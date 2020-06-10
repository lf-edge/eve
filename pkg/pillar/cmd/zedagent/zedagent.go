// Copyright (c) 2017-2018 Zededa, Inc.
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
	"container/list"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"

	log "github.com/sirupsen/logrus"
)

const (
	agentName          = "zedagent"
	restartCounterFile = types.IdentityDirname + "/restartcounter"
	// checkpointDirname - location of config checkpoint
	checkpointDirname = types.PersistDir + "/checkpoint"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Set from Makefile
var Version = "No version specified"

// XXX move to a context? Which? Used in handleconfig and handlemetrics!
var deviceNetworkStatus *types.DeviceNetworkStatus = &types.DeviceNetworkStatus{}

// XXX globals filled in by subscription handlers and read by handlemetrics
// XXX could alternatively access sub object when adding them.
var clientMetrics types.MetricsMap
var logmanagerMetrics types.MetricsMap
var downloaderMetrics types.MetricsMap
var networkMetrics types.NetworkMetrics

// Context for handleDNSModify
type DNSContext struct {
	usableAddressCount     int
	DNSinitialized         bool // Received DeviceNetworkStatus
	subDeviceNetworkStatus pubsub.Subscription
	triggerGetConfig       bool
	triggerDeviceInfo      bool
}

type zedagentContext struct {
	verifierRestarted         bool              // Information from handleVerifierRestarted
	getconfigCtx              *getconfigContext // Cross link
	assignableAdapters        *types.AssignableAdapters
	subAssignableAdapters     pubsub.Subscription
	iteration                 int
	subNetworkInstanceStatus  pubsub.Subscription
	subCertObjConfig          pubsub.Subscription
	TriggerDeviceInfo         chan<- struct{}
	zbootRestarted            bool // published by baseosmgr
	subBaseOsStatus           pubsub.Subscription
	subBaseOsDownloadStatus   pubsub.Subscription
	subCertObjDownloadStatus  pubsub.Subscription
	subBaseOsVerifierStatus   pubsub.Subscription
	subAppImgDownloadStatus   pubsub.Subscription
	subAppImgVerifierStatus   pubsub.Subscription
	subNetworkInstanceMetrics pubsub.Subscription
	subAppFlowMonitor         pubsub.Subscription
	subAppVifIPTrig           pubsub.Subscription
	pubGlobalConfig           pubsub.Publication
	subGlobalConfig           pubsub.Subscription
	subAttestCert             pubsub.Subscription
	subVaultStatus            pubsub.Subscription
	subLogMetrics             pubsub.Subscription
	GCInitialized             bool // Received initial GlobalConfig
	subZbootStatus            pubsub.Subscription
	rebootCmd                 bool
	rebootCmdDeferred         bool
	deviceReboot              bool
	currentRebootReason       string    // Set by zedagent
	rebootReason              string    // Previous reboot from nodeagent
	rebootStack               string    // Previous reboot from nodeagent
	rebootTime                time.Time // Previous reboot from nodeagent
	// restartCounter - counts number of reboots of the device by Eve
	restartCounter uint32
	// rebootConfigCounter - reboot counter sent by the cloud in its config.
	//  This is the value of counter that triggered reboot. This is sent in
	//  device info msg. Can be used to verify device is caught up on all
	// outstanding reboot commands from cloud.
	rebootConfigCounter     uint32
	subDevicePortConfigList pubsub.Subscription
	devicePortConfigList    types.DevicePortConfigList
	remainingTestTime       time.Duration
	physicalIoAdapterMap    map[string]types.PhysicalIOAdapter
	globalConfig            types.ConfigItemValueMap
	specMap                 types.ConfigItemSpecMap
	globalStatus            types.GlobalStatus
	getCertsTimer           *time.Timer
}

var debug = false
var debugOverride bool // From command line arg
var flowQ *list.List

func Run(ps *pubsub.PubSub) {
	var err error
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	parsePtr := flag.String("p", "", "parse checkpoint file")
	validatePtr := flag.Bool("V", false, "validate UTF-8 in checkpoint")
	fatalPtr := flag.Bool("F", false, "Cause log.Fatal fault injection")
	hangPtr := flag.Bool("H", false, "Cause watchdog .touch fault injection")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	fatalFlag := *fatalPtr
	hangFlag := *hangPtr
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	parse := *parsePtr
	validate := *validatePtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if validate && parse == "" {
		fmt.Printf("Setting -V requires -p\n")
		os.Exit(1)
	}
	if parse != "" {
		res, config := readValidateConfig(
			types.DefaultConfigItemValueMap().GlobalValueInt(types.StaleConfigTime), parse)
		if !res {
			fmt.Printf("Failed to parse %s\n", parse)
			os.Exit(1)
		}
		fmt.Printf("parsed proto <%v>\n", config)
		if validate {
			valid := validateConfigUTF8(config)
			if !valid {
				fmt.Printf("Found some invalid UTF-8\n")
				os.Exit(1)
			}
		}
		return
	}
	agentlog.Init(agentName)
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	log.Infof("Starting %s", agentName)

	triggerDeviceInfo := make(chan struct{}, 1)
	zedagentCtx := zedagentContext{TriggerDeviceInfo: triggerDeviceInfo}
	zedagentCtx.specMap = types.NewConfigItemSpecMap()
	zedagentCtx.globalConfig = *types.DefaultConfigItemValueMap()
	zedagentCtx.globalStatus.ConfigItems = make(
		map[string]types.ConfigItemStatus)
	zedagentCtx.globalStatus.UpdateItemValuesFromGlobalConfig(
		zedagentCtx.globalConfig)
	zedagentCtx.globalStatus.UnknownConfigItems = make(
		map[string]types.ConfigItemStatus)

	rebootConfig := readRebootConfig()
	zedagentCtx.rebootConfigCounter = rebootConfig.Counter
	log.Infof("Zedagent Run - rebootConfigCounter at init is %d",
		zedagentCtx.rebootConfigCounter)

	zedagentCtx.physicalIoAdapterMap = make(map[string]types.PhysicalIOAdapter)

	zedagentCtx.pubGlobalConfig, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "",
		TopicType:  types.ConfigItemValueMap{},
		Persistent: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)
	agentlog.StillRunning(agentName+"config", warningTime, errorTime)
	agentlog.StillRunning(agentName+"metrics", warningTime, errorTime)
	agentlog.StillRunning(agentName+"devinfo", warningTime, errorTime)

	// Tell ourselves to go ahead
	// initialize the module specifig stuff
	handleInit(zedagentCtx.globalConfig.GlobalValueInt(types.NetworkSendTimeout))

	// Context to pass around
	getconfigCtx := getconfigContext{}

	// Pick up (mostly static) AssignableAdapters before we report
	// any device info
	aa := types.AssignableAdapters{}
	zedagentCtx.assignableAdapters = &aa

	// Cross link
	getconfigCtx.zedagentCtx = &zedagentCtx
	zedagentCtx.getconfigCtx = &getconfigCtx

	// Timer for deferred sends of info messages
	deferredChan := zedcloud.InitDeferred()

	// Make sure we have a GlobalConfig file with defaults
	utils.ReadAndUpdateGCFile(zedagentCtx.pubGlobalConfig)

	subAssignableAdapters, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		TopicImpl:     types.AssignableAdapters{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		CreateHandler: handleAAModify,
		ModifyHandler: handleAAModify,
		DeleteHandler: handleAADelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subAssignableAdapters = subAssignableAdapters
	subAssignableAdapters.Activate()

	pubPhysicalIOAdapters, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.PhysicalIOAdapterList{},
	})
	if err != nil {
		log.Fatal(err)
	}
	pubPhysicalIOAdapters.ClearRestarted()
	getconfigCtx.pubPhysicalIOAdapters = pubPhysicalIOAdapters

	pubDevicePortConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DevicePortConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubDevicePortConfig = pubDevicePortConfig

	// Publish NetworkXObjectConfig and for outselves. XXX remove
	pubNetworkXObjectConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkXObjectConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubNetworkXObjectConfig = pubNetworkXObjectConfig

	pubNetworkInstanceConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkInstanceConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubNetworkInstanceConfig = pubNetworkInstanceConfig

	pubAppInstanceConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppInstanceConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubAppInstanceConfig = pubAppInstanceConfig
	pubAppInstanceConfig.ClearRestarted()

	pubAppNetworkConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppNetworkConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	pubAppNetworkConfig.ClearRestarted()
	getconfigCtx.pubAppNetworkConfig = pubAppNetworkConfig

	// XXX defer this until we have some config from cloud or saved copy
	pubAppInstanceConfig.SignalRestarted()

	pubCertObjConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.CertObjConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	pubCertObjConfig.ClearRestarted()
	getconfigCtx.pubCertObjConfig = pubCertObjConfig

	pubBaseOsConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.BaseOsConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsConfig.ClearRestarted()
	getconfigCtx.pubBaseOsConfig = pubBaseOsConfig

	pubZedAgentStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ZedAgentStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	pubZedAgentStatus.ClearRestarted()
	getconfigCtx.pubZedAgentStatus = pubZedAgentStatus
	pubDatastoreConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DatastoreConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubDatastoreConfig = pubDatastoreConfig
	pubDatastoreConfig.ClearRestarted()

	pubControllerCert, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: true,
			TopicType:  types.ControllerCert{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubControllerCert.ClearRestarted()
	getconfigCtx.pubControllerCert = pubControllerCert

	// for CipherContextStatus Publisher
	pubCipherContext, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: true,
			TopicType:  types.CipherContext{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubCipherContext.ClearRestarted()
	getconfigCtx.pubCipherContext = pubCipherContext

	// for ContentTree config Publisher
	pubContentTreeConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.ContentTreeConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubContentTreeConfig.ClearRestarted()
	getconfigCtx.pubContentTreeConfig = pubContentTreeConfig

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		CreateHandler: handleGlobalConfigModify,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subNetworkInstanceStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		TopicImpl:     types.NetworkInstanceStatus{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		CreateHandler: handleNetworkInstanceModify,
		ModifyHandler: handleNetworkInstanceModify,
		DeleteHandler: handleNetworkInstanceDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subNetworkInstanceStatus = subNetworkInstanceStatus
	subNetworkInstanceStatus.Activate()

	subNetworkInstanceMetrics, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		TopicImpl:     types.NetworkInstanceMetrics{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		CreateHandler: handleNetworkInstanceMetricsModify,
		ModifyHandler: handleNetworkInstanceMetricsModify,
		DeleteHandler: handleNetworkInstanceMetricsDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subNetworkInstanceMetrics = subNetworkInstanceMetrics
	subNetworkInstanceMetrics.Activate()

	subAppFlowMonitor, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		TopicImpl:     types.IPFlow{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		CreateHandler: handleAppFlowMonitorModify,
		ModifyHandler: handleAppFlowMonitorModify,
		DeleteHandler: handleAppFlowMonitorDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	subAppFlowMonitor.Activate()
	flowQ = list.New()
	log.Infof("FlowStats: create subFlowStatus")

	subAppVifIPTrig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		TopicImpl:     types.VifIPTrig{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		CreateHandler: handleAppVifIPTrigModify,
		ModifyHandler: handleAppVifIPTrigModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	subAppVifIPTrig.Activate()

	// Look for AppInstanceStatus from zedmanager
	subAppInstanceStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedmanager",
		TopicImpl:     types.AppInstanceStatus{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		CreateHandler: handleAppInstanceStatusModify,
		ModifyHandler: handleAppInstanceStatusModify,
		DeleteHandler: handleAppInstanceStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.subAppInstanceStatus = subAppInstanceStatus
	subAppInstanceStatus.Activate()

	// Look for ContentTreeStatus from volumemgr
	subContentTreeStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		AgentScope:    types.AppImgObj,
		TopicImpl:     types.ContentTreeStatus{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		CreateHandler: handleContentTreeStatusModify,
		ModifyHandler: handleContentTreeStatusModify,
		DeleteHandler: handleContentTreeStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.subContentTreeStatus = subContentTreeStatus
	subContentTreeStatus.Activate()

	// Look for DomainMetric from domainmgr
	subDomainMetric, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		TopicImpl:   types.DomainMetric{},
		Activate:    true,
		Ctx:         &zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.subDomainMetric = subDomainMetric

	subHostMemory, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		TopicImpl:   types.HostMemory{},
		Activate:    true,
		Ctx:         &zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.subHostMemory = subHostMemory

	// Look for zboot status
	subZbootStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "baseosmgr",
		TopicImpl:      types.ZbootStatus{},
		Activate:       false,
		Ctx:            &zedagentCtx,
		CreateHandler:  handleZbootStatusModify,
		ModifyHandler:  handleZbootStatusModify,
		DeleteHandler:  handleZbootStatusDelete,
		RestartHandler: handleZbootRestarted,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subZbootStatus = subZbootStatus
	subZbootStatus.Activate()

	subBaseOsStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "baseosmgr",
		TopicImpl:     types.BaseOsStatus{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		CreateHandler: handleBaseOsStatusModify,
		ModifyHandler: handleBaseOsStatusModify,
		DeleteHandler: handleBaseOsStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subBaseOsStatus = subBaseOsStatus
	subBaseOsStatus.Activate()

	subAttestCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "tpmmgr",
		TopicImpl:     types.AttestCert{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		ModifyHandler: handleAttestCertModify,
		DeleteHandler: handleAttestCertDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subAttestCert = subAttestCert
	subAttestCert.Activate()

	subVaultStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "vaultmgr",
		TopicImpl:     types.VaultStatus{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		ModifyHandler: handleVaultStatusModify,
		DeleteHandler: handleVaultStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subVaultStatus = subVaultStatus
	subVaultStatus.Activate()

	// Look for DownloaderStatus from downloader
	// used only for downloader storage stats collection
	subBaseOsDownloadStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "downloader",
		AgentScope:  types.BaseOsObj,
		TopicImpl:   types.DownloaderStatus{},
		Activate:    false,
		Ctx:         &zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subBaseOsDownloadStatus = subBaseOsDownloadStatus
	subBaseOsDownloadStatus.Activate()

	// Look for DownloaderStatus from downloader
	// used only for downloader storage stats collection
	subCertObjDownloadStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "downloader",
		AgentScope:  types.CertObj,
		TopicImpl:   types.DownloaderStatus{},
		Activate:    false,
		Ctx:         &zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subCertObjDownloadStatus = subCertObjDownloadStatus
	subCertObjDownloadStatus.Activate()

	// Look for VerifyBaseOsImageStatus from verifier
	// used only for verifier storage stats collection
	subBaseOsVerifierStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "verifier",
		TopicImpl:      types.VerifyImageStatus{},
		Activate:       false,
		Ctx:            &zedagentCtx,
		AgentScope:     types.BaseOsObj,
		ModifyHandler:  handleVerifierStatusModify,
		DeleteHandler:  handleVerifierStatusDelete,
		RestartHandler: handleVerifierRestarted,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subBaseOsVerifierStatus = subBaseOsVerifierStatus
	subBaseOsVerifierStatus.Activate()

	// Look for VerifyImageStatus from verifier
	// used only for verifier storage stats collection
	subAppImgVerifierStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "verifier",
		AgentScope:  types.AppImgObj,
		TopicImpl:   types.VerifyImageStatus{},
		Activate:    false,
		Ctx:         &zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subAppImgVerifierStatus = subAppImgVerifierStatus
	subAppImgVerifierStatus.Activate()

	// Look for DownloaderStatus from downloader for metric reporting
	// used only for downloader storage stats collection
	subAppImgDownloadStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "downloader",
		AgentScope:  types.AppImgObj,
		TopicImpl:   types.DownloaderStatus{},
		Activate:    false,
		Ctx:         &zedagentCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subAppImgDownloadStatus = subAppImgDownloadStatus
	subAppImgDownloadStatus.Activate()

	// Look for nodeagent status
	subNodeAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nodeagent",
		TopicImpl:     types.NodeAgentStatus{},
		Activate:      false,
		Ctx:           &getconfigCtx,
		ModifyHandler: handleNodeAgentStatusModify,
		DeleteHandler: handleNodeAgentStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.subNodeAgentStatus = subNodeAgentStatus
	subNodeAgentStatus.Activate()

	DNSctx := DNSContext{}
	DNSctx.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &DNSctx,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	DNSctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	subDevicePortConfigList, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		TopicImpl:     types.DevicePortConfigList{},
		Activate:      false,
		Ctx:           &zedagentCtx,
		ModifyHandler: handleDPCLModify,
		DeleteHandler: handleDPCLDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subDevicePortConfigList = subDevicePortConfigList
	subDevicePortConfigList.Activate()

	// Subscribe to Log metrics from logmanager
	subLogMetrics, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "logmanager",
		TopicImpl: types.LogMetrics{},
		Activate:  false,
		Ctx:       &zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subLogMetrics = subLogMetrics

	// Pick up debug aka log level before we start real work

	for !zedagentCtx.GCInitialized {
		log.Infof("Waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-getconfigCtx.subNodeAgentStatus.MsgChan():
			getconfigCtx.subNodeAgentStatus.ProcessChange(change)
		}
	}
	log.Infof("processed GlobalConfig")

	// wait till, zboot status is ready
	for !zedagentCtx.zbootRestarted {
		select {
		case change := <-subZbootStatus.MsgChan():
			subZbootStatus.ProcessChange(change)
			if zedagentCtx.zbootRestarted {
				log.Infof("Zboot reported restarted")
			}

		case change := <-getconfigCtx.subNodeAgentStatus.MsgChan():
			getconfigCtx.subNodeAgentStatus.ProcessChange(change)

		case <-stillRunning.C:
			// Fault injection
			if fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if hangFlag {
			log.Infof("Requested to not touch to cause watchdog")
		} else {
			agentlog.StillRunning(agentName, warningTime, errorTime)
		}
		// Need to tickle this since the configTimerTask is not yet started
		agentlog.StillRunning(agentName+"config", warningTime, errorTime)
		agentlog.StillRunning(agentName+"metrics", warningTime, errorTime)
		agentlog.StillRunning(agentName+"devinfo", warningTime, errorTime)
	}

	log.Infof("Waiting until we have some uplinks with usable addresses")
	for !DNSctx.DNSinitialized {
		log.Infof("Waiting for DeviceNetworkStatus %v",
			DNSctx.DNSinitialized)

		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-zedagentCtx.subBaseOsVerifierStatus.MsgChan():
			zedagentCtx.subBaseOsVerifierStatus.ProcessChange(change)

		case change := <-subBaseOsDownloadStatus.MsgChan():
			subBaseOsDownloadStatus.ProcessChange(change)

		case change := <-subAppImgVerifierStatus.MsgChan():
			subAppImgVerifierStatus.ProcessChange(change)

		case change := <-subAppImgDownloadStatus.MsgChan():
			subAppImgDownloadStatus.ProcessChange(change)

		case change := <-subCertObjDownloadStatus.MsgChan():
			subCertObjDownloadStatus.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)

		case change := <-subDevicePortConfigList.MsgChan():
			subDevicePortConfigList.ProcessChange(change)

		case change := <-getconfigCtx.subNodeAgentStatus.MsgChan():
			subNodeAgentStatus.ProcessChange(change)

		case change := <-subAttestCert.MsgChan():
			subAttestCert.ProcessChange(change)

		case change := <-subVaultStatus.MsgChan():
			subVaultStatus.ProcessChange(change)

		case change := <-deferredChan:
			start := time.Now()
			zedcloud.HandleDeferred(change, 100*time.Millisecond)
			pubsub.CheckMaxTimeTopic(agentName, "deferredChan", start,
				warningTime, errorTime)

		case <-stillRunning.C:
			// Fault injection
			if fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if hangFlag {
			log.Infof("Requested to not touch to cause watchdog")
		} else {
			agentlog.StillRunning(agentName, warningTime, errorTime)
		}
		// Need to tickle this since the configTimerTask is not yet started
		agentlog.StillRunning(agentName+"config", warningTime, errorTime)
		agentlog.StillRunning(agentName+"metrics", warningTime, errorTime)
		agentlog.StillRunning(agentName+"devinfo", warningTime, errorTime)
	}

	// Subscribe to network metrics from zedrouter
	subNetworkMetrics, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "zedrouter",
		TopicImpl: types.NetworkMetrics{},
		Activate:  true,
		Ctx:       &zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	// Subscribe to cloud metrics from different agents
	cms := zedcloud.GetCloudMetrics()
	subClientMetrics, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "zedclient",
		TopicImpl: cms,
		Activate:  true,
		Ctx:       &zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	subLogmanagerMetrics, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "logmanager",
		TopicImpl: cms,
		Activate:  true,
		Ctx:       &zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	subDownloaderMetrics, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "downloader",
		TopicImpl: cms,
		Activate:  true,
		Ctx:       &zedagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Use a go routine to make sure we have wait/timeout without
	// blocking the main select loop
	go deviceInfoTask(&zedagentCtx, triggerDeviceInfo)

	// Publish initial device info.
	triggerPublishDevInfo(&zedagentCtx)

	// start the metrics reporting task
	handleChannel := make(chan interface{})
	go metricsTimerTask(&zedagentCtx, handleChannel)
	metricsTickerHandle := <-handleChannel
	getconfigCtx.metricsTickerHandle = metricsTickerHandle

	// Process the verifierStatus to avoid downloading an image we
	// already have in place
	log.Infof("Handling initial verifier Status")
	for !zedagentCtx.verifierRestarted {
		select {
		case change := <-subZbootStatus.MsgChan():
			subZbootStatus.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subBaseOsVerifierStatus.MsgChan():
			subBaseOsVerifierStatus.ProcessChange(change)
			if zedagentCtx.verifierRestarted {
				log.Infof("Verifier reported restarted")
				break
			}

		case change := <-subBaseOsDownloadStatus.MsgChan():
			zedagentCtx.subBaseOsDownloadStatus.ProcessChange(change)

		case change := <-subAppImgVerifierStatus.MsgChan():
			subAppImgVerifierStatus.ProcessChange(change)

		case change := <-subAppImgDownloadStatus.MsgChan():
			subAppImgDownloadStatus.ProcessChange(change)

		case change := <-subCertObjDownloadStatus.MsgChan():
			subCertObjDownloadStatus.ProcessChange(change)

		case change := <-getconfigCtx.subNodeAgentStatus.MsgChan():
			subNodeAgentStatus.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)
			if DNSctx.triggerDeviceInfo {
				// IP/DNS in device info could have changed
				log.Infof("NetworkStatus triggered PublishDeviceInfo")
				triggerPublishDevInfo(&zedagentCtx)
				DNSctx.triggerDeviceInfo = false
			}

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)

		case change := <-subDevicePortConfigList.MsgChan():
			subDevicePortConfigList.ProcessChange(change)

		case change := <-subAttestCert.MsgChan():
			subAttestCert.ProcessChange(change)

		case change := <-subVaultStatus.MsgChan():
			subVaultStatus.ProcessChange(change)

		case change := <-deferredChan:
			zedcloud.HandleDeferred(change, 100*time.Millisecond)

		case <-stillRunning.C:
			// Fault injection
			if fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if hangFlag {
			log.Infof("Requested to not touch to cause watchdog")
		} else {
			agentlog.StillRunning(agentName, warningTime, errorTime)
		}
		// Need to tickle this since the configTimerTask is not yet started
		agentlog.StillRunning(agentName+"config", warningTime, errorTime)
	}

	// start the config fetch tasks, when zboot status is ready
	go configTimerTask(handleChannel, &getconfigCtx)
	configTickerHandle := <-handleChannel
	// XXX close handleChannels?
	getconfigCtx.configTickerHandle = configTickerHandle

	// let zedagent get the certs for encryption/decryption at least once if V2
	zedagentCtx.getCertsTimer = time.NewTimer(1 * time.Second)
	if !zedcloud.UseV2API() {
		zedagentCtx.getCertsTimer.Stop()
	}

	for {
		select {
		case change := <-subZbootStatus.MsgChan():
			subZbootStatus.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subAppInstanceStatus.MsgChan():
			subAppInstanceStatus.ProcessChange(change)

		case change := <-subContentTreeStatus.MsgChan():
			subContentTreeStatus.ProcessChange(change)

		case change := <-subDomainMetric.MsgChan():
			subDomainMetric.ProcessChange(change)

		case change := <-subHostMemory.MsgChan():
			subHostMemory.ProcessChange(change)

		case change := <-subBaseOsStatus.MsgChan():
			subBaseOsStatus.ProcessChange(change)

		case change := <-subBaseOsVerifierStatus.MsgChan():
			subBaseOsVerifierStatus.ProcessChange(change)

		case change := <-subBaseOsDownloadStatus.MsgChan():
			subBaseOsDownloadStatus.ProcessChange(change)

		case change := <-subAppImgVerifierStatus.MsgChan():
			subAppImgVerifierStatus.ProcessChange(change)

		case change := <-subAppImgDownloadStatus.MsgChan():
			subAppImgDownloadStatus.ProcessChange(change)

		case change := <-subCertObjDownloadStatus.MsgChan():
			subCertObjDownloadStatus.ProcessChange(change)

		case change := <-getconfigCtx.subNodeAgentStatus.MsgChan():
			subNodeAgentStatus.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)
			if DNSctx.triggerGetConfig {
				triggerGetConfig(configTickerHandle)
				DNSctx.triggerGetConfig = false
			}
			if DNSctx.triggerDeviceInfo {
				// IP/DNS in device info could have changed
				log.Infof("NetworkStatus triggered PublishDeviceInfo")
				triggerPublishDevInfo(&zedagentCtx)
				DNSctx.triggerDeviceInfo = false
			}

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)

		case change := <-subNetworkMetrics.MsgChan():
			subNetworkMetrics.ProcessChange(change)
			m, err := subNetworkMetrics.Get("global")
			if err != nil {
				log.Errorf("subNetworkMetrics.Get failed: %s",
					err)
			} else {
				networkMetrics = m.(types.NetworkMetrics)
			}

		case change := <-subClientMetrics.MsgChan():
			subClientMetrics.ProcessChange(change)
			m, err := subClientMetrics.Get("global")
			if err != nil {
				log.Errorf("subClientMetrics.Get failed: %s",
					err)
			} else {
				clientMetrics = m.(types.MetricsMap)
			}

		case change := <-subLogmanagerMetrics.MsgChan():
			subLogmanagerMetrics.ProcessChange(change)
			m, err := subLogmanagerMetrics.Get("global")
			if err != nil {
				log.Errorf("subLogmanagerMetrics.Get failed: %s",
					err)
			} else {
				logmanagerMetrics = m.(types.MetricsMap)
			}

		case change := <-subDownloaderMetrics.MsgChan():
			subDownloaderMetrics.ProcessChange(change)
			m, err := subDownloaderMetrics.Get("global")
			if err != nil {
				log.Errorf("subDownloaderMetrics.Get failed: %s",
					err)
			} else {
				downloaderMetrics = m.(types.MetricsMap)
			}

		case change := <-deferredChan:
			start := time.Now()
			zedcloud.HandleDeferred(change, 100*time.Millisecond)
			pubsub.CheckMaxTimeTopic(agentName, "deferredChan", start,
				warningTime, errorTime)

		case change := <-subNetworkInstanceStatus.MsgChan():
			subNetworkInstanceStatus.ProcessChange(change)

		case change := <-subNetworkInstanceMetrics.MsgChan():
			subNetworkInstanceMetrics.ProcessChange(change)

		case change := <-subDevicePortConfigList.MsgChan():
			subDevicePortConfigList.ProcessChange(change)

		case change := <-subAppFlowMonitor.MsgChan():
			log.Debugf("FlowStats: change called")
			subAppFlowMonitor.ProcessChange(change)

		case change := <-subAppVifIPTrig.MsgChan():
			subAppVifIPTrig.ProcessChange(change)

		case change := <-subAttestCert.MsgChan():
			subAttestCert.ProcessChange(change)

		case change := <-subVaultStatus.MsgChan():
			subVaultStatus.ProcessChange(change)

		case <-zedagentCtx.getCertsTimer.C:
			start := time.Now()
			ok := getCloudCertChain(&zedagentCtx)
			log.Infof("zedagent Run: getCertsTimer get cloud cert ok %v", ok)
			pubsub.CheckMaxTimeTopic(agentName, "getCertsTimer", start,
				warningTime, errorTime)

		case <-stillRunning.C:
			// Fault injection
			if fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if hangFlag {
			log.Infof("Requested to not touch to cause watchdog")
		} else {
			agentlog.StillRunning(agentName, warningTime, errorTime)
		}
	}
}

func triggerPublishDevInfo(ctxPtr *zedagentContext) {

	log.Info("Triggered PublishDeviceInfo")
	select {
	case ctxPtr.TriggerDeviceInfo <- struct{}{}:
		// Do nothing more
	default:
		// This occurs if we are already trying to send a device info
		// and we get a second and third trigger before that is complete.
		log.Warnf("Failed to send on PublishDeviceInfo")
	}
}

func deviceInfoTask(ctxPtr *zedagentContext, triggerDeviceInfo <-chan struct{}) {

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)

	for {
		select {
		case <-triggerDeviceInfo:
			start := time.Now()
			log.Info("deviceInfoTask got message")

			PublishDeviceInfoToZedCloud(ctxPtr)
			ctxPtr.iteration++
			log.Info("deviceInfoTask done with message")
			pubsub.CheckMaxTimeTopic(agentName+"devinfo", "PublishDeviceInfo", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"devinfo", warningTime, errorTime)
	}
}

func handleVerifierRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleVerifierRestarted(%v)", done)
	if done {
		ctx.verifierRestarted = true
	}
}

// base os verifier status modify event
func handleVerifierStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VerifyImageStatus)
	log.Infof("handleVerifierStatusModify for %s", status.ImageID)
	// Nothing to do
}

// base os verifier status delete event
func handleVerifierStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VerifyImageStatus)
	log.Infof("handleVeriferStatusDelete RefCount %d for %s",
		status.RefCount, key)
	// Nothing to do
}

func handleZbootRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleZbootRestarted(%v)", done)
	if done {
		ctx.zbootRestarted = true
	}
}

func handleInit(networkSendTimeout uint32) {
	initializeDirs()
	handleConfigInit(networkSendTimeout)
}

func initializeDirs() {

	// create persistent holder directory
	if _, err := os.Stat(types.PersistDir); err != nil {
		log.Debugf("Create %s", types.PersistDir)
		if err := os.MkdirAll(types.PersistDir, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(types.CertificateDirname); err != nil {
		log.Debugf("Create %s", types.CertificateDirname)
		if err := os.MkdirAll(types.CertificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(checkpointDirname); err != nil {
		log.Debugf("Create %s", checkpointDirname)
		if err := os.MkdirAll(checkpointDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(types.DownloadDirname); err != nil {
		log.Debugf("Create %s", types.DownloadDirname)
		if err := os.MkdirAll(types.DownloadDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
}

// handleAppInstanceStatusCreate - Handle AIS create. Publish ZInfoApp
//  and ZInfoDevice to the cloud.
func handleAppInstanceStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.AppInstanceStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishAppInfoToZedCloud(ctx, uuidStr, &status, ctx.assignableAdapters,
		ctx.iteration)
	triggerPublishDevInfo(ctx)
	ctx.iteration++
}

// app instance event watch to capture transitions
// and publish to zedCloud
// Handles both create and modify events
func handleAppInstanceStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.AppInstanceStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishAppInfoToZedCloud(ctx, uuidStr, &status, ctx.assignableAdapters,
		ctx.iteration)
	ctx.iteration++
}

func handleAppInstanceStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	uuidStr := key
	PublishAppInfoToZedCloud(ctx, uuidStr, nil, ctx.assignableAdapters,
		ctx.iteration)
	triggerPublishDevInfo(ctx)
	ctx.iteration++
}

func lookupAppInstanceStatus(ctx *zedagentContext, key string) *types.AppInstanceStatus {

	sub := ctx.getconfigCtx.subAppInstanceStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupAppInstanceStatus(%s) not found", key)
		return nil
	}
	status := st.(types.AppInstanceStatus)
	return &status
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s", key)
		return
	}
	log.Infof("handleDNSModify for %s", key)
	// XXX empty is equal
	if cmp.Equal(*deviceNetworkStatus, status) {
		log.Infof("handleDNSModify no change")
		ctx.DNSinitialized = true
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(*deviceNetworkStatus, status))
	*deviceNetworkStatus = status
	// Did we (re-)gain the first usable address?
	// XXX should we also trigger if the count increases?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	if newAddrCount != 0 && ctx.usableAddressCount == 0 {
		log.Infof("DeviceNetworkStatus from %d to %d addresses",
			ctx.usableAddressCount, newAddrCount)
		ctx.triggerGetConfig = true
	}
	ctx.DNSinitialized = true
	ctx.usableAddressCount = newAddrCount
	ctx.triggerDeviceInfo = true

	if zedcloudCtx.V2API {
		zedcloud.UpdateTLSProxyCerts(&zedcloudCtx)
	}
	log.Infof("handleDNSModify done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s", key)
	ctx := ctxArg.(*DNSContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s", key)
		return
	}
	*deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.DNSinitialized = false
	ctx.usableAddressCount = newAddrCount
	log.Infof("handleDNSDelete done for %s", key)
}

func handleDPCLModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DevicePortConfigList)
	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Infof("handleDPCLModify: ignoring %s", key)
		return
	}
	if cmp.Equal(ctx.devicePortConfigList, status) {
		log.Infof("handleDPCLModify no change")
		return
	}
	// Note that lastSucceeded will increment a lot; ignore it but compare
	// lastFailed/lastError?? XXX how?
	log.Infof("handleDPCLModify: changed %v",
		cmp.Diff(ctx.devicePortConfigList, status))
	ctx.devicePortConfigList = status
	triggerPublishDevInfo(ctx)
}

func handleDPCLDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Infof("handleDPCLDelete: ignoring %s", key)
		return
	}
	log.Infof("handleDPCLDelete for %s", key)
	ctx.devicePortConfigList = types.DevicePortConfigList{}
	triggerPublishDevInfo(ctx)
}

// base os status event handlers
// Report BaseOsStatus to zedcloud
// Handles both create and modify events
func handleBaseOsStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	triggerPublishDevInfo(ctx)
	log.Infof("handleBaseOsStatusModify(%s) done", key)
}

func handleBaseOsStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleBaseOsStatusDelete(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	triggerPublishDevInfo(ctx)
	log.Infof("handleBaseOsStatusDelete(%s) done", key)
}

// vault status event handlers
// Report VaultStatus to zedcloud
func handleVaultStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	triggerPublishDevInfo(ctx)
	log.Infof("handleVaultStatusModify(%s) done", key)
}

func handleVaultStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleVaultStatusDelete(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	triggerPublishDevInfo(ctx)
	log.Infof("handleVaultStatusDelete(%s) done", key)
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil && !ctx.GCInitialized {
		ctx.globalConfig = *gcp
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Infof("handleGlobalConfigDelete done for %s", key)
}

// Handles both create and modify events
func handleAAModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.AssignableAdapters)
	if key != "global" {
		log.Infof("handleAAModify: ignoring %s", key)
		return
	}
	log.Infof("handleAAModify() %+v", status)
	*ctx.assignableAdapters = status
	triggerPublishDevInfo(ctx)
	log.Infof("handleAAModify() done")
}

func handleAADelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Infof("handleAADelete: ignoring %s", key)
		return
	}
	log.Infof("handleAADelete()")
	ctx.assignableAdapters.Initialized = false
	triggerPublishDevInfo(ctx)
	log.Infof("handleAADelete() done")
}

// Handles both create and modify events
func handleZbootStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if !isZbootValidPartitionLabel(key) {
		log.Errorf("handleZbootStatusModify: invalid key %s", key)
		return
	}
	log.Infof("handleZbootStatusModify: for %s", key)
	// nothing to do
	triggerPublishDevInfo(ctx)
}

func handleZbootStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	if !isZbootValidPartitionLabel(key) {
		log.Errorf("handleZbootStatusDelete: invalid key %s", key)
		return
	}
	log.Infof("handleZbootStatusDelete: for %s", key)
	// Nothing to do
}

func handleNodeAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	getconfigCtx := ctxArg.(*getconfigContext)
	status := statusArg.(types.NodeAgentStatus)
	log.Infof("handleNodeAgentStatusModify: updateInProgress %t rebootReason %s",
		status.UpdateInprogress, status.RebootReason)
	updateInprogress := getconfigCtx.updateInprogress
	ctx := getconfigCtx.zedagentCtx
	ctx.remainingTestTime = status.RemainingTestTime
	getconfigCtx.updateInprogress = status.UpdateInprogress
	ctx.rebootTime = status.RebootTime
	ctx.rebootStack = status.RebootStack
	ctx.rebootReason = status.RebootReason
	ctx.restartCounter = status.RestartCounter
	// if config reboot command was initiated and
	// was deferred, and the device is not in inprogress
	// state, initiate the reboot process
	if ctx.rebootCmdDeferred &&
		updateInprogress && !status.UpdateInprogress {
		log.Infof("TestComplete and deferred reboot")
		ctx.rebootCmdDeferred = false
		infoStr := fmt.Sprintf("TestComplete and deferred Reboot Cmd\n")
		handleRebootCmd(ctx, infoStr)
	}
	if status.DeviceReboot {
		handleDeviceReboot(ctx)
	}
	triggerPublishDevInfo(ctx)
	log.Infof("handleNodeAgentStatusModify: done.")
}

func handleNodeAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleNodeAgentStatusDelete: for %s", key)
	// Nothing to do
	triggerPublishDevInfo(ctx)
}
