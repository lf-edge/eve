// Copyright (c) 2017-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// zedAgent interfaces with zedcloud for
//   * config sync
//   * metric/info publish
// app instance config is published to zedmanager for orchestration
// baseos/certs config is published to baseosmgr for orchestration
// datastore config is published for downloader consideration
// event based baseos/app instance/device info published to ZedCloud
// periodic status/metric published to zedCloud

// zedagent handles the following configuration
//   * app instance config/status  <zedagent>   / <appimg> / <config | status>
//   * base os config/status       <zedagent>   / <baseos> / <config | status>
//   * certs config/status         <zedagent>   / certs>   / <config | status>
// <base os>
//   <zedagent>  <baseos> <config> --> <baseosmgr>  <baseos> <status>
// <certs>
//   <zedagent>  <certs> <config> --> <baseosmgr>   <certs> <status>
// <app image>
//   <zedagent>  <appimage> <config> --> <zedmanager> <appimage> <status>
// <datastore>
//   <zedagent>  <datastore> <config> --> <downloader>

package zedagent

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/api/go/attest"
	"github.com/lf-edge/eve/api/go/flowlog"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"

	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName               = "zedagent"
	restartCounterFile      = types.PersistStatusDir + "/restartcounter"
	lastDevCmdTimestampFile = types.PersistStatusDir + "/lastdevcmdtimestamp"
	// checkpointDirname - location of config checkpoint
	checkpointDirname = types.PersistDir + "/checkpoint"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
	// Maximum allowed number of flow messages enqueued and waiting to be published.
	flowlogQueueCap = 100

	// Factor by which the dormant time needs to be scaled up.
	dormantTimeScaleFactor = 3
)

// Set from Makefile
var Version = "No version specified"

// XXX move to a context? Which? Used in handleconfig and handlemetrics!
var deviceNetworkStatus = &types.DeviceNetworkStatus{}

// XXX globals filled in by subscription handlers and read by handlemetrics
// XXX could alternatively access sub object when adding them.
var clientMetrics types.MetricsMap
var loguploaderMetrics types.MetricsMap
var newlogMetrics types.NewlogMetrics
var downloaderMetrics types.MetricsMap
var networkMetrics types.NetworkMetrics
var cipherMetricsDL types.CipherMetrics
var cipherMetricsDM types.CipherMetrics
var cipherMetricsNim types.CipherMetrics
var cipherMetricsZR types.CipherMetrics
var diagMetrics types.MetricsMap
var nimMetrics types.MetricsMap
var zrouterMetrics types.MetricsMap

// Context for handleDNSModify
type DNSContext struct {
	DNSinitialized         bool // Received DeviceNetworkStatus
	subDeviceNetworkStatus pubsub.Subscription
	triggerGetConfig       bool
	triggerDeviceInfo      bool
	triggerHandleDeferred  bool
	triggerRadioPOST       bool
}

type zedagentContext struct {
	agentbase.AgentBase
	ps                        *pubsub.PubSub
	getconfigCtx              *getconfigContext // Cross link
	cipherCtx                 *cipherContext    // Cross link
	attestCtx                 *attestContext    // Cross link
	dnsCtx                    *DNSContext
	assignableAdapters        *types.AssignableAdapters
	subAssignableAdapters     pubsub.Subscription
	iteration                 int
	subNetworkInstanceStatus  pubsub.Subscription
	subCertObjConfig          pubsub.Subscription
	flowlogQueue              chan<- *flowlog.FlowMessage
	triggerDeviceInfo         chan<- destinationBitset
	triggerHwInfo             chan<- destinationBitset
	triggerLocationInfo       chan<- destinationBitset
	triggerObjectInfo         chan<- infoForObjectKey
	zbootRestarted            bool // published by baseosmgr
	subOnboardStatus          pubsub.Subscription
	subBaseOsStatus           pubsub.Subscription
	subBaseOsMgrStatus        pubsub.Subscription
	subNetworkInstanceMetrics pubsub.Subscription
	subAppFlowMonitor         pubsub.Subscription
	pubGlobalConfig           pubsub.Publication
	pubMetricsMap             pubsub.Publication
	subGlobalConfig           pubsub.Subscription
	subEdgeNodeCert           pubsub.Subscription
	subVaultStatus            pubsub.Subscription
	subAttestQuote            pubsub.Subscription
	subEncryptedKeyFromDevice pubsub.Subscription
	subNewlogMetrics          pubsub.Subscription
	subBlobStatus             pubsub.Subscription
	GCInitialized             bool // Received initial GlobalConfig
	subZbootStatus            pubsub.Subscription
	subAppContainerMetrics    pubsub.Subscription
	subDiskMetric             pubsub.Subscription
	subAppDiskMetric          pubsub.Subscription
	subCapabilities           pubsub.Subscription
	subAppInstMetaData        pubsub.Subscription
	subWwanMetrics            pubsub.Subscription
	subLocationInfo           pubsub.Subscription
	subZFSPoolStatus          pubsub.Subscription
	subZFSPoolMetrics         pubsub.Subscription
	subEdgeviewStatus         pubsub.Subscription
	subNetworkMetrics         pubsub.Subscription
	subClientMetrics          pubsub.Subscription
	subLoguploaderMetrics     pubsub.Subscription
	subDownloaderMetrics      pubsub.Subscription
	subDiagMetrics            pubsub.Subscription
	subNimMetrics             pubsub.Subscription
	subZRouterMetrics         pubsub.Subscription
	subCipherMetricsDL        pubsub.Subscription
	subCipherMetricsDM        pubsub.Subscription
	subCipherMetricsNim       pubsub.Subscription
	subCipherMetricsZR        pubsub.Subscription
	zedcloudMetrics           *zedcloud.AgentMetrics
	fatalFlag                 bool // From command line arguments
	hangFlag                  bool // From command line arguments
	rebootCmd                 bool
	rebootCmdDeferred         bool
	deviceReboot              bool // From nodeagent
	shutdownCmd               bool
	shutdownCmdDeferred       bool
	deviceShutdown            bool // From nodeagent
	poweroffCmd               bool
	poweroffCmdDeferred       bool
	devicePoweroff            bool // From nodeagent
	allDomainsHalted          bool
	requestedRebootReason     string           // Set by zedagent
	requestedBootReason       types.BootReason // Set by zedagent
	rebootReason              string           // Previous reboot from nodeagent
	bootReason                types.BootReason // Previous reboot from nodeagent
	rebootStack               string           // Previous reboot from nodeagent
	rebootTime                time.Time        // Previous reboot from nodeagent
	// restartCounter - counts number of reboots of the device by Eve
	restartCounter uint32
	// rebootConfigCounter - reboot counter sent by the cloud in its config.
	//  This is the value of counter that triggered reboot. This is sent in
	//  device info msg. Can be used to verify device is caught up on all
	// outstanding reboot commands from cloud.
	rebootConfigCounter     uint32
	shutdownConfigCounter   uint32
	subDevicePortConfigList pubsub.Subscription
	DevicePortConfigList    *types.DevicePortConfigList
	remainingTestTime       time.Duration
	physicalIoAdapterMap    map[string]types.PhysicalIOAdapter
	globalConfig            types.ConfigItemValueMap
	globalConfigPublished   bool // was last globalConfig successfully published
	specMap                 types.ConfigItemSpecMap
	globalStatus            types.GlobalStatus
	flowLogMetrics          types.FlowlogMetrics
	appContainerStatsTime   time.Time // last time the App Container stats uploaded
	// The MaintenanceMode can come from GlobalConfig and from the config
	// API. Those are merged into maintenanceMode
	// TBD will be also decide locally to go into maintenanceMode based
	// on out of disk space etc?
	maintenanceMode      bool                        //derived state, after consolidating all inputs
	maintModeReason      types.MaintenanceModeReason //reason for setting derived maintenance mode
	gcpMaintenanceMode   types.TriState
	apiMaintenanceMode   bool
	localMaintenanceMode bool                        //maintenance mode triggered by local failure
	localMaintModeReason types.MaintenanceModeReason //local failure reason for maintenance mode

	// Track the counter from force.fallback.counter to detect changes
	forceFallbackCounter int

	// Interlock with controller to ensure we get the encrypted secrets
	publishedEdgeNodeCerts bool

	attestationTryCount int
	// cli options
	versionPtr  *bool
	parsePtr    *string
	validatePtr *bool
	fatalPtr    *bool
	hangPtr     *bool

	// Netdump
	netDumper            *netdump.NetDumper // nil if netdump is disabled
	netdumpInterval      time.Duration
	lastConfigNetdumpPub time.Time // last call to publishConfigNetdump
	lastInfoNetdumpPub   time.Time // last call to publishInfoNetdump
}

// AddAgentSpecificCLIFlags adds CLI options
func (zedagentCtx *zedagentContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	zedagentCtx.versionPtr = flagSet.Bool("v", false, "Version")
	zedagentCtx.parsePtr = flagSet.String("p", "", "parse checkpoint file")
	zedagentCtx.validatePtr = flagSet.Bool("V", false, "validate UTF-8 in checkpoint")
	zedagentCtx.fatalPtr = flagSet.Bool("F", false, "Cause log.Fatal fault injection")
	zedagentCtx.hangPtr = flagSet.Bool("H", false, "Cause watchdog .touch fault injection")
}

var logger *logrus.Logger
var log *base.LogObject
var zedcloudCtx *zedcloud.ZedCloudContext

// Destination bitset as unsigned integer
type destinationBitset uint

// Destination types, where info should be sent
const (
	ControllerDest destinationBitset = 1
	LPSDest                          = 2
	LOCDest                          = 4
	AllDest                          = ControllerDest | LPSDest | LOCDest
)

// queueInfoToDest - queues "info" requests according to the specified
//
//	destination. Deferred event queue runs to a completion
//	from this context, but deferred periodic queue will
//	be executed later by timer from a separate goroutine.
//	@forcePeriodic forces all deferred requests to be added
//	to the deferred queue and errors will be ignored.
func queueInfoToDest(ctx *zedagentContext, dest destinationBitset,
	key string, buf *bytes.Buffer, size int64, bailOnHTTPErr,
	withNetTracing, forcePeriodic bool, itemType interface{}) {

	locConfig := ctx.getconfigCtx.locConfig

	if dest&ControllerDest != 0 {
		url := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API,
			devUUID, "info")
		// Ignore all errors in case of periodic
		ignoreErr := forcePeriodic
		deferredCtx := zedcloudCtx.DeferredEventCtx
		if forcePeriodic {
			deferredCtx = zedcloudCtx.DeferredPeriodicCtx
		}
		deferredCtx.SetDeferred(key, buf, size, url,
			bailOnHTTPErr, withNetTracing, ignoreErr, itemType)
	}
	if dest&LOCDest != 0 && locConfig != nil {
		url := zedcloud.URLPathString(locConfig.LocURL, zedcloudCtx.V2API,
			devUUID, "info")
		// Ignore errors for all the LOC info messages
		const ignoreErr = true
		zedcloudCtx.DeferredPeriodicCtx.SetDeferred(key, buf, size, url,
			bailOnHTTPErr, withNetTracing, ignoreErr, itemType)
	}
	if dest&ControllerDest != 0 && !forcePeriodic {
		// Run to a completion at least 1 request from this execution context
		zedcloudCtx.DeferredEventCtx.HandleDeferred(time.Now(), 0, true)
	}
	if (dest&LOCDest != 0 && locConfig != nil) || forcePeriodic {
		// Run to a completion from the goroutine
		zedcloudCtx.DeferredPeriodicCtx.KickTimer()
	}
}

// object to trigger sending of info with infoType for objectKey
type infoForObjectKey struct {
	infoType  info.ZInfoTypes
	objectKey string
	infoDest  destinationBitset
}

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	zedagentCtx := &zedagentContext{}
	agentbase.Init(zedagentCtx, logger, log, agentName,
		agentbase.WithArguments(arguments))

	var err error
	parse := *zedagentCtx.parsePtr
	validate := *zedagentCtx.validatePtr
	if *zedagentCtx.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}
	if validate && parse == "" {
		fmt.Printf("Setting -V requires -p\n")
		return 1
	}
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}

	// Initialize zedagent context.
	zedagentCtx.init()
	zedagentCtx.ps = ps
	zedagentCtx.hangFlag = *zedagentCtx.hangPtr
	zedagentCtx.fatalFlag = *zedagentCtx.fatalPtr

	flowlogQueue := make(chan *flowlog.FlowMessage, flowlogQueueCap)
	triggerDeviceInfo := make(chan destinationBitset, 1)
	triggerHwInfo := make(chan destinationBitset, 1)
	triggerLocationInfo := make(chan destinationBitset, 1)
	triggerObjectInfo := make(chan infoForObjectKey, 1)
	zedagentCtx.flowlogQueue = flowlogQueue
	zedagentCtx.triggerDeviceInfo = triggerDeviceInfo
	zedagentCtx.triggerHwInfo = triggerHwInfo
	zedagentCtx.triggerLocationInfo = triggerLocationInfo
	zedagentCtx.triggerObjectInfo = triggerObjectInfo

	// Initialize all zedagent publications.
	initPublications(zedagentCtx)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	initializeDirs()

	// Load bootstrap configuration if present.
	getconfigCtx := zedagentCtx.getconfigCtx
	maybeLoadBootstrapConfig(getconfigCtx)

	// Get GlobalConfig.
	// If not present (e.g. loading of bootstrap config failed), use default values.
	item, err := zedagentCtx.pubGlobalConfig.Get("global")
	if err == nil {
		zedagentCtx.globalConfig = item.(types.ConfigItemValueMap)
	} else {
		log.Warnf("GlobalConfig is missing, publishing default values")
		zedagentCtx.globalConfig = *types.DefaultConfigItemValueMap()
		err = zedagentCtx.pubGlobalConfig.Publish("global", zedagentCtx.globalConfig)
		if err != nil {
			// Could fail if no space left in the filesystem.
			log.Fatalf("Failed to publish default globalConfig: %s", err)
		}
	}
	// GlobalConfig is guaranteed to have been published by this point
	// (otherwise the log.Fatalf above exits zedagent).
	zedagentCtx.globalConfigPublished = true
	log.Noticef("Initialized GlobalConfig: %v", zedagentCtx.globalConfig)

	// Apply saved radio config ASAP.
	initializeRadioConfig(getconfigCtx)

	// Wait until we have been onboarded aka know our own UUID.
	// Onboarding is done by client (pillar/cmd/client).
	// Activate in the next step so that zedagentCtx.subOnboardStatus is set
	// before Modify handler is called by SubscriptionImpl.populate()
	// (only needed for persistent subs).
	zedagentCtx.subOnboardStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		MyAgentName:   agentName,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      false,
		Persistent:    true,
		Ctx:           zedagentCtx,
		CreateHandler: handleOnboardStatusCreate,
		ModifyHandler: handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subOnboardStatus.Activate()
	if parse == "" {
		waitUntilOnboarded(zedagentCtx, stillRunning)
	}
	// Netdumper uses different publish period after onboarding.
	reinitNetdumper(zedagentCtx)

	// We know our own UUID; prepare for communication with controller
	zedcloudCtx = initZedcloudContext(
		zedagentCtx.globalConfig.GlobalValueInt(types.NetworkSendTimeout),
		zedagentCtx.zedcloudMetrics)

	if parse != "" {
		res, config := readValidateConfig(
			types.DefaultConfigItemValueMap().GlobalValueInt(types.StaleConfigTime), parse)
		if !res {
			fmt.Printf("Failed to parse %s\n", parse)
			return 1
		}
		fmt.Printf("parsed proto <%v>\n", config)
		if validate {
			valid := validateConfigUTF8(config)
			if !valid {
				fmt.Printf("Found some invalid UTF-8\n")
				return 1
			}
		}
		return 0
	}

	// Timer for deferred sends of info messages
	zedcloudCtx.DeferredEventCtx = zedcloud.CreateDeferredCtx(zedcloudCtx,
		getDeferredSentHandlerFunction(zedagentCtx), getDeferredPriorityFunctions()...)
	zedcloudCtx.DeferredPeriodicCtx = zedcloud.CreateDeferredCtx(zedcloudCtx, nil)
	// XXX defer this until we have some config from cloud or saved copy
	getconfigCtx.pubAppInstanceConfig.SignalRestarted()

	// With device UUID, zedagent is ready to initialize and activate all subscriptions.
	initPostOnboardSubs(zedagentCtx)

	//initialize cipher processing block
	cipherModuleInitialize(zedagentCtx)

	//initialize remote attestation context
	attestModuleInitialize(zedagentCtx)

	// Pick up debug aka log level before we start real work
	waitUntilGCReady(zedagentCtx, stillRunning)

	// wait till, zboot status is ready
	waitUntilZbootReady(zedagentCtx, stillRunning)

	// wait until NIM reports Device Network Status
	waitUntilDNSReady(zedagentCtx, stillRunning)

	// Parse SMART data
	go parseSMARTData()

	// Handle deferred requests from periodic queue
	go handleDeferredPeriodicTask(zedagentCtx)

	// Use go routines to make sure we have wait/timeout without
	// blocking the main select loop
	log.Functionf("Creating %s at %s", "deviceInfoTask", agentlog.GetMyStack())
	go deviceInfoTask(zedagentCtx, triggerDeviceInfo)
	log.Functionf("Creating %s at %s", "objectInfoTask", agentlog.GetMyStack())
	go objectInfoTask(zedagentCtx, triggerObjectInfo)
	log.Functionf("Creating %s at %s", "flowLogTask", agentlog.GetMyStack())
	go flowlogTask(zedagentCtx, flowlogQueue)
	log.Functionf("Creating %s at %s", "hardwareInfoTask", agentlog.GetMyStack())
	go hardwareInfoTask(zedagentCtx, triggerHwInfo)

	// Publish initial device info.
	triggerPublishDevInfo(zedagentCtx)

	// Publish initial hardware info.
	triggerPublishHwInfo(zedagentCtx)

	// start the metrics reporting task
	handleChannel := make(chan interface{})
	log.Functionf("Creating %s at %s", "metricsAndInfoTimerTask", agentlog.GetMyStack())
	go metricsAndInfoTimerTask(zedagentCtx, handleChannel)
	metricsTickerHandle := <-handleChannel
	getconfigCtx.metricsTickerHandle = metricsTickerHandle

	// start the location reporting task
	log.Functionf("Creating %s at %s", "locationTimerTask", agentlog.GetMyStack())
	go locationTimerTask(zedagentCtx, handleChannel, triggerLocationInfo)
	getconfigCtx.locationCloudTickerHandle = <-handleChannel
	getconfigCtx.locationAppTickerHandle = <-handleChannel

	//trigger channel for localProfile state machine
	getconfigCtx.localProfileTrigger = make(chan Notify, 1)
	//process saved local profile
	processSavedProfile(getconfigCtx)

	// initialize localInfo
	initializeLocalAppInfo(getconfigCtx)
	go localAppInfoPOSTTask(getconfigCtx)
	initializeLocalCommands(getconfigCtx)

	initializeLocalDevCmdTimestamp(getconfigCtx)
	initializeLocalDevInfo(getconfigCtx)
	go localDevInfoPOSTTask(getconfigCtx)

	// start the config fetch tasks, when zboot status is ready
	log.Functionf("Creating %s at %s", "configTimerTask", agentlog.GetMyStack())
	go configTimerTask(getconfigCtx, handleChannel)
	configTickerHandle := <-handleChannel
	// XXX close handleChannels?
	getconfigCtx.configTickerHandle = configTickerHandle

	// start the local profile fetch tasks
	log.Functionf("Creating %s at %s", "localProfileTimerTask", agentlog.GetMyStack())
	go localProfileTimerTask(handleChannel, getconfigCtx)
	localProfileTickerHandle := <-handleChannel
	getconfigCtx.localProfileTickerHandle = localProfileTickerHandle

	// start task fetching radio config from local server
	go radioPOSTTask(getconfigCtx)

	// start cipher module tasks
	cipherModuleStart(zedagentCtx)

	// start remote attestation task
	attestModuleStart(zedagentCtx)

	// Enter main zedagent event loop.
	mainEventLoop(zedagentCtx, stillRunning) // never exits
	return 0
}

func (zedagentCtx *zedagentContext) init() {
	zedagentCtx.zedcloudMetrics = zedcloud.NewAgentMetrics()
	zedagentCtx.specMap = types.NewConfigItemSpecMap()
	zedagentCtx.globalConfig = *types.DefaultConfigItemValueMap()
	zedagentCtx.globalStatus.ConfigItems = make(
		map[string]types.ConfigItemStatus)
	zedagentCtx.globalStatus.UpdateItemValuesFromGlobalConfig(
		zedagentCtx.globalConfig)
	zedagentCtx.globalStatus.UnknownConfigItems = make(
		map[string]types.ConfigItemStatus)

	rebootConfig := readDeviceOpsCmdConfig(types.DeviceOperationReboot)
	if rebootConfig != nil {
		zedagentCtx.rebootConfigCounter = rebootConfig.Counter
		log.Functionf("Zedagent Run - rebootConfigCounter at init is %d",
			zedagentCtx.rebootConfigCounter)
	}

	shutdownConfig := readDeviceOpsCmdConfig(types.DeviceOperationShutdown)
	if shutdownConfig != nil {
		zedagentCtx.shutdownConfigCounter = shutdownConfig.Counter
		log.Functionf("Zedagent Run - shutdownConfigCounter at init is %d",
			zedagentCtx.shutdownConfigCounter)
	}

	zedagentCtx.physicalIoAdapterMap = make(map[string]types.PhysicalIOAdapter)

	// Pick up (mostly static) AssignableAdapters before we report
	// any device info
	aa := types.AssignableAdapters{}
	zedagentCtx.assignableAdapters = &aa

	// Initialize context used to get and parse device configuration.
	getconfigCtx := &getconfigContext{
		localServerMap: &localServerMap{},
		// default value of currentMetricInterval
		currentMetricInterval: zedagentCtx.globalConfig.GlobalValueInt(types.MetricInterval),
		// edge-view configure
		configEdgeview: &types.EdgeviewConfig{},
		cipherContexts: make(map[string]types.CipherContext),
	}

	cipherCtx := &cipherContext{}
	attestCtx := &attestContext{}
	dnsCtx := &DNSContext{}
	zedagentCtx.dnsCtx = dnsCtx

	// Cross links between contexts.
	getconfigCtx.zedagentCtx = zedagentCtx
	zedagentCtx.getconfigCtx = getconfigCtx

	cipherCtx.zedagentCtx = zedagentCtx
	zedagentCtx.cipherCtx = cipherCtx

	attestCtx.zedagentCtx = zedagentCtx
	zedagentCtx.attestCtx = attestCtx
}

func initializeDirs() {
	// create persistent holder directory
	if _, err := os.Stat(types.PersistDir); err != nil {
		log.Tracef("Create %s", types.PersistDir)
		if err := os.MkdirAll(types.PersistDir, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(types.CertificateDirname); err != nil {
		log.Tracef("Create %s", types.CertificateDirname)
		if err := os.MkdirAll(types.CertificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(checkpointDirname); err != nil {
		log.Tracef("Create %s", checkpointDirname)
		if err := os.MkdirAll(checkpointDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
}

func waitUntilOnboarded(zedagentCtx *zedagentContext, stillRunning *time.Ticker) {
	nilUUID := uuid.UUID{}
	for devUUID == nilUUID {
		log.Functionf("Waiting for OnboardStatus UUID")
		select {
		case change := <-zedagentCtx.subOnboardStatus.MsgChan():
			zedagentCtx.subOnboardStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		zedagentCtx.ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func waitUntilGCReady(zedagentCtx *zedagentContext, stillRunning *time.Ticker) {
	getconfigCtx := zedagentCtx.getconfigCtx
	for !zedagentCtx.GCInitialized {
		log.Functionf("Waiting for GCInitialized")
		select {
		case change := <-zedagentCtx.subOnboardStatus.MsgChan():
			zedagentCtx.subOnboardStatus.ProcessChange(change)

		case change := <-zedagentCtx.subGlobalConfig.MsgChan():
			zedagentCtx.subGlobalConfig.ProcessChange(change)

		case change := <-getconfigCtx.subNodeAgentStatus.MsgChan():
			getconfigCtx.subNodeAgentStatus.ProcessChange(change)

		case <-stillRunning.C:
		}
		zedagentCtx.ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")
}

func waitUntilZbootReady(zedagentCtx *zedagentContext, stillRunning *time.Ticker) {
	getconfigCtx := zedagentCtx.getconfigCtx
	for !zedagentCtx.zbootRestarted {
		select {
		case change := <-zedagentCtx.subOnboardStatus.MsgChan():
			zedagentCtx.subOnboardStatus.ProcessChange(change)

		case change := <-zedagentCtx.subZbootStatus.MsgChan():
			zedagentCtx.subZbootStatus.ProcessChange(change)
			if zedagentCtx.zbootRestarted {
				log.Functionf("Zboot reported restarted")
			}

		case change := <-getconfigCtx.subNodeAgentStatus.MsgChan():
			getconfigCtx.subNodeAgentStatus.ProcessChange(change)

		case <-stillRunning.C:
			// Fault injection
			if zedagentCtx.fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if zedagentCtx.hangFlag {
			log.Functionf("Requested to not touch to cause watchdog")
		} else {
			zedagentCtx.ps.StillRunning(agentName, warningTime, errorTime)
		}
	}
}

func waitUntilDNSReady(zedagentCtx *zedagentContext, stillRunning *time.Ticker) {
	getconfigCtx := zedagentCtx.getconfigCtx
	dnsCtx := zedagentCtx.dnsCtx
	log.Functionf("Waiting until we have DeviceNetworkStatus")

	for !dnsCtx.DNSinitialized {
		log.Functionf("Waiting for DeviceNetworkStatus %v",
			dnsCtx.DNSinitialized)

		select {
		case change := <-zedagentCtx.subOnboardStatus.MsgChan():
			zedagentCtx.subOnboardStatus.ProcessChange(change)

		case change := <-zedagentCtx.subGlobalConfig.MsgChan():
			zedagentCtx.subGlobalConfig.ProcessChange(change)

		case change := <-dnsCtx.subDeviceNetworkStatus.MsgChan():
			dnsCtx.subDeviceNetworkStatus.ProcessChange(change)
			if dnsCtx.triggerHandleDeferred {
				start := time.Now()
				zedcloudCtx.DeferredEventCtx.HandleDeferred(
					start, 100*time.Millisecond, false)
				zedagentCtx.ps.CheckMaxTimeTopic(agentName, "deferredEventChan",
					start, warningTime, errorTime)
				dnsCtx.triggerHandleDeferred = false
			}

		case change := <-zedagentCtx.subAssignableAdapters.MsgChan():
			zedagentCtx.subAssignableAdapters.ProcessChange(change)

		case change := <-zedagentCtx.subDevicePortConfigList.MsgChan():
			zedagentCtx.subDevicePortConfigList.ProcessChange(change)

		case change := <-getconfigCtx.subNodeAgentStatus.MsgChan():
			getconfigCtx.subNodeAgentStatus.ProcessChange(change)

		case change := <-zedagentCtx.subVaultStatus.MsgChan():
			zedagentCtx.subVaultStatus.ProcessChange(change)

		case change := <-zedagentCtx.subAttestQuote.MsgChan():
			zedagentCtx.subAttestQuote.ProcessChange(change)

		case change := <-zedagentCtx.subEncryptedKeyFromDevice.MsgChan():
			zedagentCtx.subEncryptedKeyFromDevice.ProcessChange(change)

		case change := <-getconfigCtx.subAppNetworkStatus.MsgChan():
			getconfigCtx.localServerMap.upToDate = false
			getconfigCtx.subAppNetworkStatus.ProcessChange(change)

		case change := <-zedagentCtx.subWwanMetrics.MsgChan():
			zedagentCtx.subWwanMetrics.ProcessChange(change)

		case change := <-zedagentCtx.subLocationInfo.MsgChan():
			zedagentCtx.subLocationInfo.ProcessChange(change)

		case change := <-zedcloudCtx.DeferredEventCtx.Ticker.C:
			start := time.Now()
			zedcloudCtx.DeferredEventCtx.HandleDeferred(
				change, 100*time.Millisecond, false)
			zedagentCtx.ps.CheckMaxTimeTopic(agentName, "deferredEventCtx", start,
				warningTime, errorTime)

		case <-stillRunning.C:
			// Fault injection
			if zedagentCtx.fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if zedagentCtx.hangFlag {
			log.Functionf("Requested to not touch to cause watchdog")
		} else {
			zedagentCtx.ps.StillRunning(agentName, warningTime, errorTime)
		}
	}
}

func handleDeferredPeriodicTask(zedagentCtx *zedagentContext) {
	wdName := agentName + "devinfo"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	zedagentCtx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case change := <-zedcloudCtx.DeferredPeriodicCtx.Ticker.C:
			start := time.Now()
			if !zedcloudCtx.DeferredPeriodicCtx.HandleDeferred(
				change, 100*time.Millisecond, false) {
				log.Noticef("handleDeferredPeriodicTask: some deferred items remain to be sent")
			}
			zedagentCtx.ps.CheckMaxTimeTopic(agentName, "deferredPeriodicCtx",
				start, warningTime, errorTime)
		case <-stillRunning.C:
		}
		zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func mainEventLoop(zedagentCtx *zedagentContext, stillRunning *time.Ticker) {
	getconfigCtx := zedagentCtx.getconfigCtx
	dnsCtx := zedagentCtx.dnsCtx

	hwInfoTiker := time.NewTicker(3 * time.Hour)

	for {
		select {
		case change := <-zedagentCtx.subOnboardStatus.MsgChan():
			zedagentCtx.subOnboardStatus.ProcessChange(change)

		case change := <-zedagentCtx.subZbootStatus.MsgChan():
			zedagentCtx.subZbootStatus.ProcessChange(change)

		case change := <-zedagentCtx.subGlobalConfig.MsgChan():
			zedagentCtx.subGlobalConfig.ProcessChange(change)

		case change := <-getconfigCtx.subAppInstanceStatus.MsgChan():
			getconfigCtx.subAppInstanceStatus.ProcessChange(change)

		case change := <-getconfigCtx.subContentTreeStatus.MsgChan():
			getconfigCtx.subContentTreeStatus.ProcessChange(change)

		case change := <-getconfigCtx.subVolumeStatus.MsgChan():
			getconfigCtx.subVolumeStatus.ProcessChange(change)

		case change := <-getconfigCtx.subDomainMetric.MsgChan():
			getconfigCtx.subDomainMetric.ProcessChange(change)

		case change := <-getconfigCtx.subProcessMetric.MsgChan():
			getconfigCtx.subProcessMetric.ProcessChange(change)

		case change := <-getconfigCtx.subHostMemory.MsgChan():
			getconfigCtx.subHostMemory.ProcessChange(change)

		case change := <-zedagentCtx.subBaseOsStatus.MsgChan():
			zedagentCtx.subBaseOsStatus.ProcessChange(change)

		case change := <-zedagentCtx.subBlobStatus.MsgChan():
			zedagentCtx.subBlobStatus.ProcessChange(change)

		case change := <-getconfigCtx.subNodeAgentStatus.MsgChan():
			getconfigCtx.subNodeAgentStatus.ProcessChange(change)

		case change := <-getconfigCtx.subAppNetworkStatus.MsgChan():
			getconfigCtx.localServerMap.upToDate = false
			getconfigCtx.subAppNetworkStatus.ProcessChange(change)

		case change := <-dnsCtx.subDeviceNetworkStatus.MsgChan():
			dnsCtx.subDeviceNetworkStatus.ProcessChange(change)
			if dnsCtx.triggerGetConfig {
				triggerGetConfig(getconfigCtx.configTickerHandle)
				dnsCtx.triggerGetConfig = false
			}
			if dnsCtx.triggerDeviceInfo {
				// IP/DNS in device info could have changed
				log.Functionf("NetworkStatus triggered PublishDeviceInfo")
				triggerPublishDevInfo(zedagentCtx)
				dnsCtx.triggerDeviceInfo = false
			}
			if dnsCtx.triggerHandleDeferred {
				start := time.Now()
				zedcloudCtx.DeferredEventCtx.HandleDeferred(
					start, 100*time.Millisecond, false)
				zedagentCtx.ps.CheckMaxTimeTopic(agentName,
					"deferredEventCtx", start, warningTime, errorTime)
				dnsCtx.triggerHandleDeferred = false
			}
			if dnsCtx.triggerRadioPOST {
				triggerRadioPOST(getconfigCtx)
				dnsCtx.triggerRadioPOST = false
			}

		case change := <-zedagentCtx.subAssignableAdapters.MsgChan():
			zedagentCtx.subAssignableAdapters.ProcessChange(change)

		case change := <-zedagentCtx.subNetworkMetrics.MsgChan():
			zedagentCtx.subNetworkMetrics.ProcessChange(change)
			m, err := zedagentCtx.subNetworkMetrics.Get("global")
			if err != nil {
				log.Errorf("subNetworkMetrics.Get failed: %s",
					err)
			} else {
				networkMetrics = m.(types.NetworkMetrics)
			}

		case change := <-zedagentCtx.subClientMetrics.MsgChan():
			zedagentCtx.subClientMetrics.ProcessChange(change)
			m, err := zedagentCtx.subClientMetrics.Get("global")
			if err != nil {
				log.Errorf("subClientMetrics.Get failed: %s",
					err)
			} else {
				clientMetrics = m.(types.MetricsMap)
			}

		case change := <-zedagentCtx.subLoguploaderMetrics.MsgChan():
			zedagentCtx.subLoguploaderMetrics.ProcessChange(change)
			m, err := zedagentCtx.subLoguploaderMetrics.Get("global")
			if err != nil {
				log.Errorf("subLoguploaderMetrics.Get failed: %s",
					err)
			} else {
				loguploaderMetrics = m.(types.MetricsMap)
			}

		case change := <-zedagentCtx.subDiagMetrics.MsgChan():
			zedagentCtx.subDiagMetrics.ProcessChange(change)
			m, err := zedagentCtx.subDiagMetrics.Get("global")
			if err != nil {
				log.Errorf("subDiagMetrics.Get failed: %s",
					err)
			} else {
				diagMetrics = m.(types.MetricsMap)
			}

		case change := <-zedagentCtx.subNimMetrics.MsgChan():
			zedagentCtx.subNimMetrics.ProcessChange(change)
			m, err := zedagentCtx.subNimMetrics.Get("global")
			if err != nil {
				log.Errorf("subNimMetrics.Get failed: %s",
					err)
			} else {
				nimMetrics = m.(types.MetricsMap)
			}

		case change := <-zedagentCtx.subZRouterMetrics.MsgChan():
			zedagentCtx.subZRouterMetrics.ProcessChange(change)
			m, err := zedagentCtx.subZRouterMetrics.Get("global")
			if err != nil {
				log.Errorf("subZRouterMetrics.Get failed: %s",
					err)
			} else {
				zrouterMetrics = m.(types.MetricsMap)
			}

		case change := <-zedagentCtx.subNewlogMetrics.MsgChan():
			zedagentCtx.subNewlogMetrics.ProcessChange(change)
			m, err := zedagentCtx.subNewlogMetrics.Get("global")
			if err != nil {
				log.Errorf("subNewlogMetrics.Get failed: %s",
					err)
			} else {
				newlogMetrics = m.(types.NewlogMetrics)
			}

		case change := <-zedagentCtx.subDownloaderMetrics.MsgChan():
			zedagentCtx.subDownloaderMetrics.ProcessChange(change)
			m, err := zedagentCtx.subDownloaderMetrics.Get("global")
			if err != nil {
				log.Errorf("subDownloaderMetrics.Get failed: %s",
					err)
			} else {
				downloaderMetrics = m.(types.MetricsMap)
			}

		case change := <-zedcloudCtx.DeferredEventCtx.Ticker.C:
			start := time.Now()
			zedcloudCtx.DeferredEventCtx.HandleDeferred(
				change, 100*time.Millisecond, false)
			zedagentCtx.ps.CheckMaxTimeTopic(agentName, "deferredEventCtx",
				start, warningTime, errorTime)

		case change := <-zedagentCtx.subCipherMetricsDL.MsgChan():
			zedagentCtx.subCipherMetricsDL.ProcessChange(change)
			m, err := zedagentCtx.subCipherMetricsDL.Get("global")
			if err != nil {
				log.Errorf("subCipherMetricsDL.Get failed: %s",
					err)
			} else {
				cipherMetricsDL = m.(types.CipherMetrics)
			}

		case change := <-zedagentCtx.subCipherMetricsDM.MsgChan():
			zedagentCtx.subCipherMetricsDM.ProcessChange(change)
			m, err := zedagentCtx.subCipherMetricsDM.Get("global")
			if err != nil {
				log.Errorf("subCipherMetricsDM.Get failed: %s",
					err)
			} else {
				cipherMetricsDM = m.(types.CipherMetrics)
			}

		case change := <-zedagentCtx.subCipherMetricsNim.MsgChan():
			zedagentCtx.subCipherMetricsNim.ProcessChange(change)
			m, err := zedagentCtx.subCipherMetricsNim.Get("global")
			if err != nil {
				log.Errorf("subCipherMetricsNim.Get failed: %s",
					err)
			} else {
				cipherMetricsNim = m.(types.CipherMetrics)
			}

		case change := <-zedagentCtx.subCipherMetricsZR.MsgChan():
			zedagentCtx.subCipherMetricsZR.ProcessChange(change)
			m, err := zedagentCtx.subCipherMetricsZR.Get("global")
			if err != nil {
				log.Errorf("subCipherMetricsZR.Get failed: %s",
					err)
			} else {
				cipherMetricsZR = m.(types.CipherMetrics)
			}

		case change := <-zedagentCtx.subNetworkInstanceStatus.MsgChan():
			zedagentCtx.subNetworkInstanceStatus.ProcessChange(change)

		case change := <-zedagentCtx.subNetworkInstanceMetrics.MsgChan():
			zedagentCtx.subNetworkInstanceMetrics.ProcessChange(change)

		case change := <-zedagentCtx.subDevicePortConfigList.MsgChan():
			zedagentCtx.subDevicePortConfigList.ProcessChange(change)

		case change := <-zedagentCtx.subAppFlowMonitor.MsgChan():
			log.Tracef("FlowStats: change called")
			zedagentCtx.subAppFlowMonitor.ProcessChange(change)

		case change := <-zedagentCtx.subEdgeNodeCert.MsgChan():
			zedagentCtx.subEdgeNodeCert.ProcessChange(change)

		case change := <-zedagentCtx.subVaultStatus.MsgChan():
			zedagentCtx.subVaultStatus.ProcessChange(change)

		case change := <-zedagentCtx.subAttestQuote.MsgChan():
			zedagentCtx.subAttestQuote.ProcessChange(change)

		case change := <-zedagentCtx.subEncryptedKeyFromDevice.MsgChan():
			zedagentCtx.subEncryptedKeyFromDevice.ProcessChange(change)

		case change := <-zedagentCtx.subAppContainerMetrics.MsgChan():
			zedagentCtx.subAppContainerMetrics.ProcessChange(change)

		case change := <-zedagentCtx.subDiskMetric.MsgChan():
			zedagentCtx.subDiskMetric.ProcessChange(change)

		case change := <-zedagentCtx.subAppDiskMetric.MsgChan():
			zedagentCtx.subAppDiskMetric.ProcessChange(change)

		case change := <-zedagentCtx.subCapabilities.MsgChan():
			zedagentCtx.subCapabilities.ProcessChange(change)

		case change := <-zedagentCtx.subBaseOsMgrStatus.MsgChan():
			zedagentCtx.subBaseOsMgrStatus.ProcessChange(change)

		case change := <-zedagentCtx.subAppInstMetaData.MsgChan():
			zedagentCtx.subAppInstMetaData.ProcessChange(change)

		case change := <-zedagentCtx.subWwanMetrics.MsgChan():
			zedagentCtx.subWwanMetrics.ProcessChange(change)

		case change := <-zedagentCtx.subLocationInfo.MsgChan():
			zedagentCtx.subLocationInfo.ProcessChange(change)

		case change := <-zedagentCtx.subZFSPoolStatus.MsgChan():
			zedagentCtx.subZFSPoolStatus.ProcessChange(change)
			triggerPublishDevInfo(zedagentCtx)

		case change := <-zedagentCtx.subZFSPoolMetrics.MsgChan():
			zedagentCtx.subZFSPoolMetrics.ProcessChange(change)

		case <-hwInfoTiker.C:
			triggerPublishHwInfo(zedagentCtx)

		case change := <-zedagentCtx.subEdgeviewStatus.MsgChan():
			zedagentCtx.subEdgeviewStatus.ProcessChange(change)

		case <-stillRunning.C:
			// Fault injection
			if zedagentCtx.fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if zedagentCtx.hangFlag {
			log.Functionf("Requested to not touch to cause watchdog")
		} else {
			zedagentCtx.ps.StillRunning(agentName, warningTime, errorTime)
		}
	}
}

func initPublications(zedagentCtx *zedagentContext) {
	var err error
	ps := zedagentCtx.ps

	zedagentCtx.pubGlobalConfig, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  types.ConfigItemValueMap{},
		Persistent: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Publish zedagent cloud metrics.
	zedagentCtx.pubMetricsMap, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.MetricsMap{},
		})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx := zedagentCtx.getconfigCtx

	getconfigCtx.pubZedAgentStatus, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ZedAgentStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubZedAgentStatus.ClearRestarted()

	getconfigCtx.pubPhysicalIOAdapters, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.PhysicalIOAdapterList{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubPhysicalIOAdapters.ClearRestarted()

	getconfigCtx.pubDevicePortConfig, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DevicePortConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Publish NetworkXObjectConfig and for ourselves. XXX remove
	getconfigCtx.pubNetworkXObjectConfig, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkXObjectConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}

	getconfigCtx.pubNetworkInstanceConfig, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkInstanceConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}

	getconfigCtx.pubAppInstanceConfig, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppInstanceConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubAppInstanceConfig.ClearRestarted()

	getconfigCtx.pubAppNetworkConfig, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppNetworkConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubAppNetworkConfig.ClearRestarted()

	getconfigCtx.pubBaseOsConfig, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.BaseOsConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubBaseOsConfig.ClearRestarted()

	getconfigCtx.pubDatastoreConfig, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DatastoreConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubDatastoreConfig.ClearRestarted()

	getconfigCtx.pubControllerCert, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: true,
			TopicType:  types.ControllerCert{},
		})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubControllerCert.ClearRestarted()

	// for ContentTree config Publisher
	getconfigCtx.pubContentTreeConfig, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.ContentTreeConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubContentTreeConfig.ClearRestarted()

	// for volume config Publisher
	getconfigCtx.pubVolumeConfig, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.VolumeConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubVolumeConfig.ClearRestarted()

	// for disk config Publisher
	getconfigCtx.pubDisksConfig, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.EdgeNodeDisks{},
		})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubDisksConfig.ClearRestarted()

	// for Edge Node Info Publisher
	getconfigCtx.pubEdgeNodeInfo, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.EdgeNodeInfo{},
			Persistent: true,
		})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubEdgeNodeInfo.ClearRestarted()

}

// All but one zedagent subscription (subOnboardStatus) are activated
// only after zedagent knows device UUID.
func initPostOnboardSubs(zedagentCtx *zedagentContext) {
	var err error
	ps := zedagentCtx.ps
	getconfigCtx := zedagentCtx.getconfigCtx
	dnsCtx := zedagentCtx.dnsCtx
	zedagentCtx.subAssignableAdapters, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.AssignableAdapters{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleAACreate,
		ModifyHandler: handleAAModify,
		DeleteHandler: handleAADelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for global config such as log levels
	// Note that we use these handlers to process updates from
	// the controller since the parser (in zedagent aka ourselves)
	// merely publishes the GlobalConfig
	// Activate in the next step so that zedagentCtx.subGlobalConfig is set
	// before Modify handler is called by SubscriptionImpl.populate()
	// (only needed for persistent subs).
	zedagentCtx.subGlobalConfig, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     agentName,
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           zedagentCtx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subGlobalConfig.Activate()

	zedagentCtx.subNetworkInstanceStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		MyAgentName:   agentName,
		TopicImpl:     types.NetworkInstanceStatus{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleNetworkInstanceCreate,
		ModifyHandler: handleNetworkInstanceModify,
		DeleteHandler: handleNetworkInstanceDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	getconfigCtx.subAppNetworkStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedrouter",
		MyAgentName: agentName,
		TopicImpl:   types.AppNetworkStatus{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subNetworkInstanceMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedrouter",
		MyAgentName: agentName,
		TopicImpl:   types.NetworkInstanceMetrics{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subAppFlowMonitor, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		MyAgentName:   agentName,
		TopicImpl:     types.IPFlow{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleAppFlowMonitorCreate,
		ModifyHandler: handleAppFlowMonitorModify,
		DeleteHandler: handleAppFlowMonitorDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for AppInstanceStatus from zedmanager
	getconfigCtx.subAppInstanceStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedmanager",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceStatus{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleAppInstanceStatusCreate,
		ModifyHandler: handleAppInstanceStatusModify,
		DeleteHandler: handleAppInstanceStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for ContentTreeStatus from volumemgr
	getconfigCtx.subContentTreeStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.ContentTreeStatus{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleContentTreeStatusCreate,
		ModifyHandler: handleContentTreeStatusModify,
		DeleteHandler: handleContentTreeStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for VolumeStatus from volumemgr
	getconfigCtx.subVolumeStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VolumeStatus{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleVolumeStatusCreate,
		ModifyHandler: handleVolumeStatusModify,
		DeleteHandler: handleVolumeStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for DomainMetric from domainmgr
	getconfigCtx.subDomainMetric, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.DomainMetric{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for ProcessMetric from domainmgr
	getconfigCtx.subProcessMetric, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.ProcessMetric{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	getconfigCtx.subHostMemory, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.HostMemory{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subEdgeviewStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "edgeview",
		MyAgentName:   agentName,
		TopicImpl:     types.EdgeviewStatus{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleEdgeviewStatusCreate,
		ModifyHandler: handleEdgeviewStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for zboot status
	zedagentCtx.subZbootStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "baseosmgr",
		MyAgentName:    agentName,
		TopicImpl:      types.ZbootStatus{},
		Activate:       true,
		Ctx:            zedagentCtx,
		CreateHandler:  handleZbootStatusCreate,
		ModifyHandler:  handleZbootStatusModify,
		DeleteHandler:  handleZbootStatusDelete,
		RestartHandler: handleZbootRestarted,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// sub AppContainerMetrics from zedrouter
	zedagentCtx.subAppContainerMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		MyAgentName:   agentName,
		TopicImpl:     types.AppContainerMetrics{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleAppContainerMetricsCreate,
		ModifyHandler: handleAppContainerMetricsModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subBaseOsStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "baseosmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.BaseOsStatus{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleBaseOsStatusCreate,
		ModifyHandler: handleBaseOsStatusModify,
		DeleteHandler: handleBaseOsStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Activate in the next step so that zedagentCtx.subEdgeNodeCert is set
	// before Modify handler is called by SubscriptionImpl.populate()
	// (only needed for persistent subs).
	zedagentCtx.subEdgeNodeCert, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "tpmmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.EdgeNodeCert{},
		Activate:      false,
		Persistent:    true,
		Ctx:           zedagentCtx,
		CreateHandler: handleEdgeNodeCertCreate,
		ModifyHandler: handleEdgeNodeCertModify,
		DeleteHandler: handleEdgeNodeCertDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subEdgeNodeCert.Activate()

	zedagentCtx.subVaultStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "vaultmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VaultStatus{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleVaultStatusCreate,
		ModifyHandler: handleVaultStatusModify,
		DeleteHandler: handleVaultStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subAttestQuote, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "tpmmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.AttestQuote{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleAttestQuoteCreate,
		ModifyHandler: handleAttestQuoteModify,
		DeleteHandler: handleAttestQuoteDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subEncryptedKeyFromDevice, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "vaultmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.EncryptedVaultKeyFromDevice{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleEncryptedKeyFromDeviceCreate,
		ModifyHandler: handleEncryptedKeyFromDeviceModify,
		DeleteHandler: handleEncryptedKeyFromDeviceDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for nodeagent status
	getconfigCtx.subNodeAgentStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nodeagent",
		MyAgentName:   agentName,
		TopicImpl:     types.NodeAgentStatus{},
		Activate:      true,
		Ctx:           getconfigCtx,
		CreateHandler: handleNodeAgentStatusCreate,
		ModifyHandler: handleNodeAgentStatusModify,
		DeleteHandler: handleNodeAgentStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.NodeAgentStatus = &types.NodeAgentStatus{}

	dnsCtx.subDeviceNetworkStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      true,
		Ctx:           dnsCtx,
		CreateHandler: handleDNSCreate,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subDevicePortConfigList, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		TopicImpl:     types.DevicePortConfigList{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleDPCLCreate,
		ModifyHandler: handleDPCLModify,
		DeleteHandler: handleDPCLDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.DevicePortConfigList = &types.DevicePortConfigList{}

	zedagentCtx.subBlobStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.BlobStatus{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleBlobStatusCreate,
		ModifyHandler: handleBlobStatusModify,
		DeleteHandler: handleBlobDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Subscribe to Newlog metrics from newlogd
	zedagentCtx.subNewlogMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "newlogd",
		TopicImpl: types.NewlogMetrics{},
		Activate:  true,
		Ctx:       zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subDiskMetric, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.DiskMetric{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleDiskMetricCreate,
		ModifyHandler: handleDiskMetricModify,
		DeleteHandler: handleDiskMetricDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subAppDiskMetric, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.AppDiskMetric{},
		Activate:      true,
		Ctx:           zedagentCtx,
		CreateHandler: handleAppDiskMetricCreate,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subCapabilities, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.Capabilities{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subBaseOsMgrStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "baseosmgr",
		MyAgentName: agentName,
		TopicImpl:   types.BaseOSMgrStatus{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})

	// Activate in the next step so that zedagentCtx.subAppInstMetaData is set
	// before Modify handler is called by SubscriptionImpl.populate()
	// (only needed for persistent subs).
	zedagentCtx.subAppInstMetaData, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstMetaData{},
		Activate:      false,
		Persistent:    true,
		Ctx:           zedagentCtx,
		CreateHandler: handleAppInstMetaDataCreate,
		ModifyHandler: handleAppInstMetaDataModify,
		DeleteHandler: handleAppInstMetaDataDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subAppInstMetaData.Activate()

	zedagentCtx.subWwanMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "nim",
		MyAgentName: agentName,
		TopicImpl:   types.WwanMetrics{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subLocationInfo, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "nim",
		MyAgentName: agentName,
		TopicImpl:   types.WwanLocationInfo{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Subscribe to network metrics from zedrouter
	zedagentCtx.subNetworkMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedrouter",
		MyAgentName: agentName,
		TopicImpl:   types.NetworkMetrics{},
		Activate:    true,
		Ctx:         zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Subscribe to cloud metrics from different agents
	zedagentCtx.subClientMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedclient",
		MyAgentName: agentName,
		TopicImpl:   types.MetricsMap{},
		Activate:    true,
		Ctx:         zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	// cloud metrics of loguploader
	zedagentCtx.subLoguploaderMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "loguploader",
		TopicImpl: types.MetricsMap{},
		Activate:  true,
		Ctx:       zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subDownloaderMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "downloader",
		MyAgentName: agentName,
		TopicImpl:   types.MetricsMap{},
		Activate:    true,
		Ctx:         zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	// cloud metrics of diag
	zedagentCtx.subDiagMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "diag",
		TopicImpl: types.MetricsMap{},
		Activate:  true,
		Ctx:       zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	// cloud metrics of nim
	zedagentCtx.subNimMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "nim",
		TopicImpl: types.MetricsMap{},
		Activate:  true,
		Ctx:       zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	// cloud metrics of zedrouter
	zedagentCtx.subZRouterMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "zedrouter",
		TopicImpl: types.MetricsMap{},
		Activate:  true,
		Ctx:       zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subCipherMetricsDL, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "downloader",
		MyAgentName: agentName,
		TopicImpl:   types.CipherMetrics{},
		Activate:    true,
		Ctx:         zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subCipherMetricsDM, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.CipherMetrics{},
		Activate:    true,
		Ctx:         zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subCipherMetricsNim, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "nim",
		MyAgentName: agentName,
		TopicImpl:   types.CipherMetrics{},
		Activate:    true,
		Ctx:         zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subCipherMetricsZR, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedrouter",
		MyAgentName: agentName,
		TopicImpl:   types.CipherMetrics{},
		Activate:    true,
		Ctx:         zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subZFSPoolStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zfsmanager",
		MyAgentName: agentName,
		TopicImpl:   types.ZFSPoolStatus{},
		Activate:    true,
		Ctx:         zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	zedagentCtx.subZFSPoolMetrics, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zfsmanager",
		MyAgentName: agentName,
		TopicImpl:   types.ZFSPoolMetrics{},
		Activate:    true,
		Ctx:         &zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
}

func triggerPublishHwInfoToDest(ctxPtr *zedagentContext, dest destinationBitset) {

	log.Function("Triggered PublishHardwareInfo")
	select {
	case ctxPtr.triggerHwInfo <- dest:
		// Do nothing more
	default:
		// This occurs if we are already trying to send a hardware info
		// and we get a second and third trigger before that is complete.
		log.Warnf("Failed to send on PublishHardwareInfo")
	}
}

func triggerPublishHwInfo(ctxPtr *zedagentContext) {
	triggerPublishHwInfoToDest(ctxPtr, AllDest)
}

func triggerPublishDevInfoToDest(ctxPtr *zedagentContext, dest destinationBitset) {

	log.Function("Triggered PublishDeviceInfo")
	select {
	case ctxPtr.triggerDeviceInfo <- dest:
		// Do nothing more
	default:
		// This occurs if we are already trying to send a device info
		// and we get a second and third trigger before that is complete.
		log.Warnf("Failed to send on PublishDeviceInfo")
	}
	if dest&LPSDest != 0 {
		triggerLocalDevInfoPOST(ctxPtr.getconfigCtx)
	}
}

func triggerPublishDevInfo(ctxPtr *zedagentContext) {
	triggerPublishDevInfoToDest(ctxPtr, AllDest)
}

func triggerPublishLocationToDest(ctxPtr *zedagentContext, dest destinationBitset) {
	if ctxPtr.getconfigCtx.locationCloudTickerHandle == nil {
		// Location reporting task is not yet running.
		return
	}
	log.Function("Triggered publishLocation")
	ctxPtr.triggerLocationInfo <- dest
}

func triggerPublishAllInfo(ctxPtr *zedagentContext, dest destinationBitset) {

	log.Function("Triggered PublishAllInfo")
	// we use goroutine since every publish operation can take a long time
	// and will block sending on TriggerObjectInfo channel
	go func() {
		// we need only the last one device info to publish
		triggerPublishDevInfoToDest(ctxPtr, dest)
		// trigger publish applications infos
		for _, c := range ctxPtr.getconfigCtx.subAppInstanceStatus.GetAll() {
			ctxPtr.triggerObjectInfo <- infoForObjectKey{
				info.ZInfoTypes_ZiApp,
				c.(types.AppInstanceStatus).Key(),
				dest,
			}
		}
		// trigger publish network instance infos
		for _, c := range ctxPtr.subNetworkInstanceStatus.GetAll() {
			niStatus := c.(types.NetworkInstanceStatus)
			ctxPtr.triggerObjectInfo <- infoForObjectKey{
				info.ZInfoTypes_ZiNetworkInstance,
				(&niStatus).Key(),
				dest,
			}
		}
		// trigger publish volume infos
		for _, c := range ctxPtr.getconfigCtx.subVolumeStatus.GetAll() {
			ctxPtr.triggerObjectInfo <- infoForObjectKey{
				info.ZInfoTypes_ZiVolume,
				c.(types.VolumeStatus).Key(),
				dest,
			}
		}
		// trigger publish content tree infos
		for _, c := range ctxPtr.getconfigCtx.subContentTreeStatus.GetAll() {
			ctxPtr.triggerObjectInfo <- infoForObjectKey{
				info.ZInfoTypes_ZiContentTree,
				c.(types.ContentTreeStatus).Key(),
				dest,
			}
		}
		// trigger publish blob infos
		for _, c := range ctxPtr.subBlobStatus.GetAll() {
			ctxPtr.triggerObjectInfo <- infoForObjectKey{
				info.ZInfoTypes_ZiBlobList,
				c.(types.BlobStatus).Key(),
				dest,
			}
		}
		// trigger publish appInst metadata infos
		for _, c := range ctxPtr.subAppInstMetaData.GetAll() {
			ctxPtr.triggerObjectInfo <- infoForObjectKey{
				info.ZInfoTypes_ZiAppInstMetaData,
				c.(types.AppInstMetaData).Key(),
				dest,
			}
		}
		triggerPublishHwInfoToDest(ctxPtr, dest)
		// trigger publish edgeview infos
		for _, c := range ctxPtr.subEdgeviewStatus.GetAll() {
			ctxPtr.triggerObjectInfo <- infoForObjectKey{
				info.ZInfoTypes_ZiEdgeview,
				c.(types.EdgeviewStatus).Key(),
				dest,
			}
		}
		triggerPublishLocationToDest(ctxPtr, dest)
	}()
}

// This is called when we try sending an ATTEST_REQ_QUOTE
func recordAttestationTry(ctxPtr *zedagentContext) {
	ctxPtr.attestationTryCount++
	log.Noticef("recordAttestationTry count %d", ctxPtr.attestationTryCount)
}

func handleZbootRestarted(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*zedagentContext)
	log.Functionf("handleZbootRestarted(%d)", restartCounter)
	if restartCounter != 0 {
		ctx.zbootRestarted = true
	}
}

// handleAppInstanceStatusCreate - Handle AIS create. Publish ZInfoApp
//
//	and ZInfoDevice to the cloud.
func handleAppInstanceStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.AppInstanceStatus)
	log.Functionf("handleAppInstanceStatusCreate(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishAppInfoToZedCloud(ctx, uuidStr, &status, ctx.assignableAdapters,
		ctx.iteration, AllDest)
	triggerPublishDevInfo(ctx)
	processAppCommandStatus(ctx.getconfigCtx, status)
	triggerLocalAppInfoPOST(ctx.getconfigCtx)
	ctx.iteration++
	log.Functionf("handleAppInstanceStatusCreate(%s) DONE", key)
}

// app instance event watch to capture transitions
// and publish to zedCloud
// Handles both create and modify events
func handleAppInstanceStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {

	status := statusArg.(types.AppInstanceStatus)
	log.Functionf("handleAppInstanceStatusModify(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishAppInfoToZedCloud(ctx, uuidStr, &status, ctx.assignableAdapters,
		ctx.iteration, AllDest)
	processAppCommandStatus(ctx.getconfigCtx, status)
	triggerLocalAppInfoPOST(ctx.getconfigCtx)
	ctx.iteration++
	log.Functionf("handleAppInstanceStatusModify(%s) DONE", key)
}

func handleAppInstanceStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	uuidStr := key
	log.Functionf("handleAppInstanceStatusDelete(%s)", key)
	PublishAppInfoToZedCloud(ctx, uuidStr, nil, ctx.assignableAdapters,
		ctx.iteration, AllDest)
	triggerPublishDevInfo(ctx)
	triggerLocalAppInfoPOST(ctx.getconfigCtx)
	ctx.iteration++
	log.Functionf("handleAppInstanceStatusDelete(%s) DONE", key)
}

func lookupAppInstanceStatus(ctx *zedagentContext, key string) *types.AppInstanceStatus {

	sub := ctx.getconfigCtx.subAppInstanceStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Functionf("lookupAppInstanceStatus(%s) not found", key)
		return nil
	}
	status := st.(types.AppInstanceStatus)
	return &status
}

func handleDNSCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Functionf("handleDNSImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleDNSImpl for %s", key)
	// Since we report the TestResults we compare the whole struct
	if cmp.Equal(*deviceNetworkStatus, status) {
		log.Functionf("handleDNSImpl no change")
		ctx.DNSinitialized = true
		return
	}
	// if status changed to DPCStateSuccess try to send deferred objects
	if status.State == types.DPCStateSuccess && deviceNetworkStatus.State != types.DPCStateSuccess {
		ctx.triggerHandleDeferred = true
	}
	if deviceNetworkStatus.RadioSilence.ChangeInProgress &&
		!status.RadioSilence.ChangeInProgress {
		// radio-silence state changing operation has just finalized
		ctx.triggerRadioPOST = true
	}
	log.Functionf("handleDNSImpl: changed %v",
		cmp.Diff(*deviceNetworkStatus, status))

	if dnsHasRealChange(*deviceNetworkStatus, status) {
		ctx.triggerDeviceInfo = true
		log.Functionf("handleDNSImpl: has change. hasRealChange")
	}
	*deviceNetworkStatus = status
	ctx.DNSinitialized = true

	if zedcloudCtx.V2API {
		zedcloud.UpdateTLSProxyCerts(zedcloudCtx)
	}

	log.Functionf("handleDNSImpl done for %s", key)
}

// compare two DNS records with some timestamp, etc. fields cleared
// to detect a real change in the status
func dnsHasRealChange(dnsOld, dnsNew types.DeviceNetworkStatus) bool {
	dummy1 := trimmedDNS(dnsOld)
	dummy2 := trimmedDNS(dnsNew)
	return !cmp.Equal(dummy1, dummy2)
}

// Return copy of DNS with frequently-changing fields cleared.
// Not everything is deep-copied - only those fields which are being cleared.
func trimmedDNS(dns types.DeviceNetworkStatus) types.DeviceNetworkStatus {
	dnsCopy := dns
	dnsCopy.Ports = make([]types.NetworkPortStatus, len(dns.Ports))
	for i, nps := range dns.Ports {
		npsCopy := nps
		npsCopy.LastFailed = time.Time{}
		npsCopy.LastSucceeded = time.Time{}
		npsCopy.AddrInfoList = make([]types.AddrInfo, len(nps.AddrInfoList))
		for j, naddr := range nps.AddrInfoList {
			naddr.Geo = ipinfo.IPInfo{}
			naddr.LastGeoTimestamp = time.Time{}
			npsCopy.AddrInfoList[j] = naddr
		}
		dnsCopy.Ports[i] = npsCopy
	}
	dnsCopy.Testing = false
	return dnsCopy
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleDNSDelete for %s", key)
	ctx := ctxArg.(*DNSContext)

	if key != "global" {
		log.Functionf("handleDNSDelete: ignoring %s", key)
		return
	}
	*deviceNetworkStatus = types.DeviceNetworkStatus{}
	ctx.DNSinitialized = false
	log.Functionf("handleDNSDelete done for %s", key)
}

func handleDPCLCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDPCLImpl(ctxArg, key, statusArg)
}

func handleDPCLModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDPCLImpl(ctxArg, key, statusArg)
}

func handleDPCLImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Functionf("handleDPCLImpl: ignoring %s", key)
		return
	}

	status := statusArg.(types.DevicePortConfigList)
	if dpclHasRealChange(*ctx.DevicePortConfigList, status) {
		triggerPublishDevInfo(ctx)
		log.Noticef("handleDPCLImpl: has real change.")
	}
	*ctx.DevicePortConfigList = status
}

func handleDPCLDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Functionf("handleDPCLDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleDPCLDelete for %s", key)
	triggerPublishDevInfo(ctx)
	ctx.DevicePortConfigList = &types.DevicePortConfigList{}
}

// compare two DPCL records with some timestamp, etc. fields cleared
// to detect a real change in the status
func dpclHasRealChange(dpclOld, dpclNew types.DevicePortConfigList) bool {
	dummy1 := trimmedDPCL(dpclOld)
	dummy2 := trimmedDPCL(dpclNew)
	return !cmp.Equal(dummy1, dummy2)
}

// Return copy of DPCL with frequently-changing fields cleared.
func trimmedDPCL(dpcl types.DevicePortConfigList) types.DevicePortConfigList {
	dpclCopy := dpcl
	dpclCopy.PortConfigList = make([]types.DevicePortConfig, len(dpcl.PortConfigList))
	for i, dpc := range dpcl.PortConfigList {
		dpcCopy := dpc
		dpcCopy.LastFailed = time.Time{}
		dpcCopy.LastSucceeded = time.Time{}
		dpcCopy.LastIPAndDNS = time.Time{}
		dpcCopy.Ports = make([]types.NetworkPortConfig, len(dpc.Ports))
		for j, p := range dpc.Ports {
			p.LastFailed = time.Time{}
			p.LastSucceeded = time.Time{}
			dpcCopy.Ports[j] = p
		}
		dpclCopy.PortConfigList[i] = dpcCopy
	}
	return dpclCopy
}

// vault status event handlers
// Report VaultStatus to zedcloud
func handleVaultStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVaultStatusImpl(ctxArg, key, statusArg)
}

func handleVaultStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleVaultStatusImpl(ctxArg, key, statusArg)
}

func handleVaultStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	triggerPublishDevInfo(ctx)
	log.Functionf("handleVaultStatusImpl(%s) done", key)
}

func handleVaultStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleVaultStatusDelete(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	triggerPublishDevInfo(ctx)
	log.Functionf("handleVaultStatusDelete(%s) done", key)
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.globalConfig = *gcp
		ctx.GCInitialized = true
		ctx.gcpMaintenanceMode = gcp.GlobalValueTriState(types.MaintenanceMode)
		mergeMaintenanceMode(ctx)
		reinitNetdumper(ctx)
	}

	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	ctx.globalConfig = *types.DefaultConfigItemValueMap()
	reinitNetdumper(ctx)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

func handleAACreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAAImpl(ctxArg, key, statusArg)
}

func handleAAModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAAImpl(ctxArg, key, statusArg)
}

func handleAAImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.AssignableAdapters)
	if key != "global" {
		log.Functionf("handleAAImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleAAImpl() %+v", status)
	*ctx.assignableAdapters = status
	triggerPublishDevInfo(ctx)
	log.Functionf("handleAAImpl() done")
}

func handleAADelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Functionf("handleAADelete: ignoring %s", key)
		return
	}
	log.Functionf("handleAADelete()")
	ctx.assignableAdapters.Initialized = false
	triggerPublishDevInfo(ctx)
	log.Functionf("handleAADelete() done")
}

func handleNodeAgentStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleNodeAgentStatusImpl(ctxArg, key, statusArg)
}

func handleNodeAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleNodeAgentStatusImpl(ctxArg, key, statusArg)
}

func handleNodeAgentStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	getconfigCtx := ctxArg.(*getconfigContext)
	status := statusArg.(types.NodeAgentStatus)
	log.Functionf("handleNodeAgentStatusImpl: updateInProgress %t rebootReason %s bootReason %s",
		status.UpdateInprogress, status.RebootReason,
		status.BootReason.String())
	updateInprogress := getconfigCtx.updateInprogress
	ctx := getconfigCtx.zedagentCtx
	ctx.remainingTestTime = status.RemainingTestTime
	getconfigCtx.updateInprogress = status.UpdateInprogress
	ctx.rebootTime = status.RebootTime
	ctx.rebootStack = status.RebootStack
	ctx.rebootReason = status.RebootReason
	ctx.bootReason = status.BootReason
	ctx.restartCounter = status.RestartCounter
	ctx.allDomainsHalted = status.AllDomainsHalted
	// if config reboot command was initiated and
	// was deferred, and the device is not in inprogress
	// state, initiate the reboot process
	if ctx.rebootCmdDeferred &&
		updateInprogress && !status.UpdateInprogress {
		log.Functionf("TestComplete and deferred reboot")
		ctx.rebootCmdDeferred = false
		infoStr := fmt.Sprintf("TestComplete and deferred Reboot Cmd")
		handleDeviceOperationCmd(ctx, infoStr, types.DeviceOperationReboot)
	}
	if ctx.shutdownCmdDeferred &&
		updateInprogress && !status.UpdateInprogress {
		log.Functionf("TestComplete and deferred shutdown")
		ctx.shutdownCmdDeferred = false
		infoStr := fmt.Sprintf("TestComplete and deferred Shutdown Cmd")
		handleDeviceOperationCmd(ctx, infoStr, types.DeviceOperationShutdown)
	}
	if ctx.poweroffCmdDeferred &&
		updateInprogress && !status.UpdateInprogress {
		log.Functionf("TestComplete and deferred poweroff")
		ctx.poweroffCmdDeferred = false
		infoStr := fmt.Sprintf("TestComplete and deferred Poweroff Cmd")
		handleDeviceOperationCmd(ctx, infoStr, types.DeviceOperationPoweroff)
	}
	if status.DeviceReboot {
		handleDeviceOperation(ctx, types.DeviceOperationReboot)
	}
	if status.DeviceShutdown {
		handleDeviceOperation(ctx, types.DeviceOperationShutdown)
	}
	if status.DevicePoweroff {
		handleDeviceOperation(ctx, types.DeviceOperationPoweroff)
	}
	if ctx.localMaintenanceMode != status.LocalMaintenanceMode {
		ctx.localMaintenanceMode = status.LocalMaintenanceMode
		ctx.localMaintModeReason = status.LocalMaintenanceModeReason
		mergeMaintenanceMode(ctx)
	}

	if naHasRealChange(*getconfigCtx.NodeAgentStatus, status) {
		triggerPublishDevInfo(ctx)
	}
	*getconfigCtx.NodeAgentStatus = status
	log.Functionf("handleNodeAgentStatusImpl: done.")
}

// NodeAgent status clear out the field and compare for real change
func naHasRealChange(naOld, naNew types.NodeAgentStatus) bool {
	dummy1 := naOld
	dummy2 := naNew

	return !cmp.Equal(dummy1, dummy2)
}

func handleNodeAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	getconfigCtx := ctxArg.(*getconfigContext)
	getconfigCtx.NodeAgentStatus = &types.NodeAgentStatus{}
	ctx := ctxArg.(*zedagentContext)
	log.Functionf("handleNodeAgentStatusDelete: for %s", key)
	// Nothing to do
	triggerPublishDevInfo(ctx)
}

func getDeferredSentHandlerFunction(ctx *zedagentContext) *zedcloud.SentHandlerFunction {
	var function zedcloud.SentHandlerFunction
	function = func(itemType interface{}, data *bytes.Buffer, result types.SenderStatus, traces []netdump.TracedNetRequest) {
		if el, ok := itemType.(info.ZInfoTypes); ok && len(traces) > 0 {
			for i := range traces {
				reqName := traces[i].RequestName
				traces[i].RequestName = el.String() + "-" + reqName
			}
			publishInfoNetdump(ctx, result, traces)
		}
		if result == types.SenderStatusDebug {
			// Debug stuff
			if el, ok := itemType.(info.ZInfoTypes); ok {
				log.Noticef("deferred queue has INFO: %d", el)
			}
			if el, ok := itemType.(attest.ZAttestReqType); ok {
				log.Noticef("deferred queue has ATTEST: %d", el)
			}
		} else if result == types.SenderStatusNone {
			if data == nil {
				return
			}
			if el, ok := itemType.(info.ZInfoTypes); ok && el == info.ZInfoTypes_ZiDevice {
				saveSentDeviceInfoProtoMessage(data.Bytes())
			}
			if el, ok := itemType.(info.ZInfoTypes); ok && el == info.ZInfoTypes_ZiApp {
				saveSentAppInfoProtoMessage(data.Bytes())
			}
			if el, ok := itemType.(attest.ZAttestReqType); ok && el == attest.ZAttestReqType_ATTEST_REQ_CERT {
				log.Noticef("sendAttestReqProtobuf: Sent EdgeNodeCerts")
				ctx.publishedEdgeNodeCerts = true
			}
		} else {
			if _, ok := itemType.(attest.ZAttestReqType); ok {
				switch result {
				case types.SenderStatusUpgrade:
					log.Functionf("sendAttestReqProtobuf: Controller upgrade in progress")
				case types.SenderStatusRefused:
					log.Functionf("sendAttestReqProtobuf: Controller returned ECONNREFUSED")
				case types.SenderStatusCertInvalid:
					log.Warnf("sendAttestReqProtobuf: Controller certificate invalid time")
				case types.SenderStatusCertMiss:
					log.Functionf("sendAttestReqProtobuf: Controller certificate miss")
				case types.SenderStatusNotFound:
					log.Functionf("sendAttestReqProtobuf: Controller SenderStatusNotFound")
					potentialUUIDUpdate(ctx.getconfigCtx)
				}
			}
		}
	}
	return &function
}

func getDeferredPriorityFunctions() []zedcloud.TypePriorityCheckFunction {
	var functions []zedcloud.TypePriorityCheckFunction
	functions = append(functions, func(itemType interface{}) bool {
		if _, ok := itemType.(attest.ZAttestReqType); ok {
			return true
		}
		return false
	})

	functions = append(functions, func(itemType interface{}) bool {
		if el, ok := itemType.(info.ZInfoTypes); ok && el == info.ZInfoTypes_ZiApp {
			return true
		}
		return false
	})
	return functions
}

// Track the DeviceUUID
func handleOnboardStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleOnboardStatusImpl(ctxArg, key, statusArg)
}

func handleOnboardStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleOnboardStatusImpl(ctxArg, key, statusArg)
}

func handleOnboardStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.OnboardingStatus)
	ctx := ctxArg.(*zedagentContext)
	if devUUID == status.DeviceUUID {
		return
	}
	log.Noticef("Device UUID changed from %s to %s", devUUID, status.DeviceUUID)
	oldUUID := devUUID
	devUUID = status.DeviceUUID
	if zedcloudCtx != nil {
		zedcloudCtx.DevUUID = devUUID
	}
	// Make sure trigger function isn't going to trip on a nil pointer
	if ctx.getconfigCtx != nil && ctx.getconfigCtx.zedagentCtx != nil &&
		ctx.getconfigCtx.subAppInstanceStatus != nil {
		if zedcloudCtx != nil && oldUUID != nilUUID {
			// remove old deferred attest if exists
			zedcloudCtx.DeferredEventCtx.RemoveDeferred("attest:" + oldUUID.String())
			if ctx.cipherCtx != nil && ctx.cipherCtx.triggerEdgeNodeCerts != nil {
				// Re-publish certificates with new device UUID
				triggerEdgeNodeCertEvent(ctx.getconfigCtx.zedagentCtx)
			}
		}
		// Re-publish all objects with new device UUID
		triggerPublishAllInfo(ctx.getconfigCtx.zedagentCtx, AllDest)
	}
}

func handleEdgeviewStatusCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleEdgeviewStatusImpl(ctxArg, key, statusArg)
}

func handleEdgeviewStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleEdgeviewStatusImpl(ctxArg, key, statusArg)
}

func handleEdgeviewStatusImpl(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.EdgeviewStatus)
	ctx := ctxArg.(*zedagentContext)
	PublishEdgeviewToZedCloud(ctx, &status, AllDest)
}

func reinitNetdumper(ctx *zedagentContext) {
	gcp := ctx.globalConfig
	netDumper := ctx.netDumper
	netdumpEnabled := gcp.GlobalValueBool(types.NetDumpEnable)
	if netdumpEnabled {
		if netDumper == nil {
			netDumper = &netdump.NetDumper{}
			// Determine when was the last time zedagent published netdump
			// for /config and /info.
			var err error
			ctx.lastConfigNetdumpPub, err = netDumper.LastPublishAt(
				netDumpConfigOKTopic, netDumpConfigFailTopic)
			if err != nil {
				log.Warn(err)
			}
			ctx.lastInfoNetdumpPub, err = netDumper.LastPublishAt(
				netDumpInfoOKTopic, netDumpInfoFailTopic)
			if err != nil {
				log.Warn(err)
			}
		}
		isOnboarded := devUUID != nilUUID
		if isOnboarded {
			ctx.netdumpInterval = time.Second *
				time.Duration(gcp.GlobalValueInt(types.NetDumpTopicPostOnboardInterval))
		} else {
			ctx.netdumpInterval = time.Second *
				time.Duration(gcp.GlobalValueInt(types.NetDumpTopicPreOnboardInterval))
		}
		maxCount := gcp.GlobalValueInt(types.NetDumpTopicMaxCount)
		netDumper.MaxDumpsPerTopic = int(maxCount)
	} else {
		netDumper = nil
	}
	// Assign at the end to avoid race condition with configTimerTask.
	ctx.netDumper = netDumper
}
