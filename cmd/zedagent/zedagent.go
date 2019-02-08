// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// zedAgent interfaces with zedcloud for
//   * config sync
//   * metric/info publish
// app instance config is pushed to zedmanager for orchestration
// baseos/certs config is pushed to baseosmgr for orchestration
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

package zedagent

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zedcloud"
)

const (
	appImgObj = "appImg.obj"
	baseOsObj = "baseOs.obj"
	certObj   = "cert.obj"
	agentName = "zedagent"

	configDir             = "/config"
	persistDir            = "/persist"
	objectDownloadDirname = persistDir + "/downloads"
	certificateDirname    = persistDir + "/certs"
	checkpointDirname     = persistDir + "/checkpoint"

	partitionCount = 2
)

// Set from Makefile
var Version = "No version specified"

// XXX move to a context? Which? Used in handleconfig and handlemetrics!
var deviceNetworkStatus *types.DeviceNetworkStatus = &types.DeviceNetworkStatus{}

// XXX globals filled in by subscription handlers and read by handlemetrics
// XXX could alternatively access sub object when adding them.
var clientMetrics interface{}
var logmanagerMetrics interface{}
var downloaderMetrics interface{}
var networkMetrics types.NetworkMetrics

// Context for handleDNSModify
type DNSContext struct {
	usableAddressCount     int
	DNSinitialized         bool // Received DeviceNetworkStatus
	subDeviceNetworkStatus *pubsub.Subscription
	triggerGetConfig       bool
	triggerDeviceInfo      bool
}

type zedagentContext struct {
	verifierRestarted         bool              // Information from handleVerifierRestarted
	getconfigCtx              *getconfigContext // Cross link
	zbootRestarted            bool              // published by baseosmgr
	assignableAdapters        *types.AssignableAdapters
	subAssignableAdapters     *pubsub.Subscription
	iteration                 int
	subNetworkServiceStatus   *pubsub.Subscription
	subNetworkInstanceStatus  *pubsub.Subscription
	subDomainStatus           *pubsub.Subscription
	subCertObjConfig          *pubsub.Subscription
	TriggerDeviceInfo         bool
	subBaseOsStatus           *pubsub.Subscription
	subBaseOsDownloadStatus   *pubsub.Subscription
	subCertObjDownloadStatus  *pubsub.Subscription
	subBaseOsVerifierStatus   *pubsub.Subscription
	subAppImgDownloadStatus   *pubsub.Subscription
	subAppImgVerifierStatus   *pubsub.Subscription
	subNetworkServiceMetrics  *pubsub.Subscription
	subNetworkInstanceMetrics *pubsub.Subscription
	subGlobalConfig           *pubsub.Subscription
	subZbootStatus            *pubsub.Subscription
}

var debug = false
var debugOverride bool // From command line arg

func Run() {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	curpartPtr := flag.String("c", "", "Current partition")
	parsePtr := flag.String("p", "", "parse checkpoint file")
	validatePtr := flag.Bool("V", false, "validate UTF-8 in checkpoint")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	curpart := *curpartPtr
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
		res, config := readValidateConfig(parse)
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
	logf, err := agentlog.Init(agentName, curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	log.Infof("Starting %s\n", agentName)

	// If we have a reboot reason from this or the other partition
	// (assuming the other is in inprogress) then we log it
	// We assume the log makes it reliably to zedcloud hence we discard
	// the reason.
	rebootReason := agentlog.GetCurrentRebootReason()
	if rebootReason != "" {
		log.Warnf("Current partition rebooted reason: %s\n",
			rebootReason)
		agentlog.DiscardCurrentRebootReason()
	}
	rebootReason = agentlog.GetOtherRebootReason()
	if rebootReason != "" {
		log.Warnf("Other partition rebooted reason: %s\n",
			rebootReason)
		agentlog.DiscardOtherRebootReason()
	}
	rebootReason = agentlog.GetCommonRebootReason()
	if rebootReason != "" {
		log.Warnf("Common rebooted reason: %s\n",
			rebootReason)
		agentlog.DiscardCommonRebootReason()
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName)

	// Tell ourselves to go ahead
	// initialize the module specifig stuff
	handleInit()

	// Context to pass around
	getconfigCtx := getconfigContext{}

	// Pick up (mostly static) AssignableAdapters before we report
	// any device info
	aa := types.AssignableAdapters{}
	zedagentCtx := zedagentContext{assignableAdapters: &aa}

	// Cross link
	getconfigCtx.zedagentCtx = &zedagentCtx
	zedagentCtx.getconfigCtx = &getconfigCtx

	// Timer for deferred sends of info messages
	deferredChan := zedcloud.InitDeferred()

	subAssignableAdapters, err := pubsub.Subscribe("domainmgr",
		types.AssignableAdapters{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subAssignableAdapters.ModifyHandler = handleAAModify
	subAssignableAdapters.DeleteHandler = handleAADelete
	zedagentCtx.subAssignableAdapters = subAssignableAdapters
	subAssignableAdapters.Activate()

	pubDevicePortConfig, err := pubsub.Publish(agentName,
		types.DevicePortConfig{})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubDevicePortConfig = pubDevicePortConfig

	// Publish NetworkConfig and NetworkServiceConfig for zedmanager/zedrouter
	pubNetworkObjectConfig, err := pubsub.Publish(agentName,
		types.NetworkObjectConfig{})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubNetworkObjectConfig = pubNetworkObjectConfig

	pubNetworkServiceConfig, err := pubsub.Publish(agentName,
		types.NetworkServiceConfig{})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubNetworkServiceConfig = pubNetworkServiceConfig

	pubNetworkInstanceConfig, err := pubsub.Publish(agentName,
		types.NetworkInstanceConfig{})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubNetworkInstanceConfig = pubNetworkInstanceConfig

	pubAppInstanceConfig, err := pubsub.Publish(agentName,
		types.AppInstanceConfig{})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubAppInstanceConfig = pubAppInstanceConfig
	pubAppInstanceConfig.ClearRestarted()

	pubAppNetworkConfig, err := pubsub.Publish(agentName,
		types.AppNetworkConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubAppNetworkConfig.ClearRestarted()
	getconfigCtx.pubAppNetworkConfig = pubAppNetworkConfig

	// XXX defer this until we have some config from cloud or saved copy
	pubAppInstanceConfig.SignalRestarted()

	pubCertObjConfig, err := pubsub.Publish(agentName,
		types.CertObjConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubCertObjConfig.ClearRestarted()
	getconfigCtx.pubCertObjConfig = pubCertObjConfig

	pubBaseOsConfig, err := pubsub.Publish(agentName,
		types.BaseOsConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsConfig.ClearRestarted()
	getconfigCtx.pubBaseOsConfig = pubBaseOsConfig

	pubDatastoreConfig, err := pubsub.Publish(agentName,
		types.DatastoreConfig{})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubDatastoreConfig = pubDatastoreConfig
	pubDatastoreConfig.ClearRestarted()

	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	zedagentCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subNetworkServiceStatus, err := pubsub.Subscribe("zedrouter",
		types.NetworkServiceStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subNetworkServiceStatus.ModifyHandler = handleNetworkServiceModify
	subNetworkServiceStatus.DeleteHandler = handleNetworkServiceDelete
	zedagentCtx.subNetworkServiceStatus = subNetworkServiceStatus
	subNetworkServiceStatus.Activate()

	subNetworkServiceMetrics, err := pubsub.Subscribe("zedrouter",
		types.NetworkServiceMetrics{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subNetworkServiceMetrics.ModifyHandler = handleNetworkServiceMetricsModify
	subNetworkServiceMetrics.DeleteHandler = handleNetworkServiceMetricsDelete
	zedagentCtx.subNetworkServiceMetrics = subNetworkServiceMetrics
	subNetworkServiceMetrics.Activate()

	subNetworkInstanceStatus, err := pubsub.Subscribe("zedrouter",
		types.NetworkInstanceStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subNetworkInstanceStatus.ModifyHandler = handleNetworkInstanceModify
	subNetworkInstanceStatus.DeleteHandler = handleNetworkInstanceDelete
	zedagentCtx.subNetworkInstanceStatus = subNetworkInstanceStatus
	subNetworkInstanceStatus.Activate()

	subNetworkInstanceMetrics, err := pubsub.Subscribe("zedrouter",
		types.NetworkInstanceMetrics{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subNetworkInstanceMetrics.ModifyHandler = handleNetworkInstanceMetricsModify
	subNetworkInstanceMetrics.DeleteHandler = handleNetworkInstanceMetricsDelete
	zedagentCtx.subNetworkInstanceMetrics = subNetworkInstanceMetrics
	subNetworkInstanceMetrics.Activate()

	// Look for AppInstanceStatus from zedmanager
	subAppInstanceStatus, err := pubsub.Subscribe("zedmanager",
		types.AppInstanceStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subAppInstanceStatus.ModifyHandler = handleAppInstanceStatusModify
	subAppInstanceStatus.DeleteHandler = handleAppInstanceStatusDelete
	getconfigCtx.subAppInstanceStatus = subAppInstanceStatus
	subAppInstanceStatus.Activate()

	// Get DomainStatus from domainmgr
	subDomainStatus, err := pubsub.Subscribe("domainmgr",
		types.DomainStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDomainStatus.ModifyHandler = handleDomainStatusModify
	subDomainStatus.DeleteHandler = handleDomainStatusDelete
	zedagentCtx.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	// Look for zboot status
	subZbootStatus, err := pubsub.Subscribe("baseosmgr",
		types.ZbootStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subZbootStatus.ModifyHandler = handleZbootStatusModify
	subZbootStatus.DeleteHandler = handleZbootStatusDelete
	subZbootStatus.RestartHandler = handleZbootRestarted
	zedagentCtx.subZbootStatus = subZbootStatus
	subZbootStatus.Activate()

	subBaseOsStatus, err := pubsub.Subscribe("baseosmgr",
		types.BaseOsStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsStatus.ModifyHandler = handleBaseOsStatusModify
	subBaseOsStatus.DeleteHandler = handleBaseOsStatusDelete
	zedagentCtx.subBaseOsStatus = subBaseOsStatus
	subBaseOsStatus.Activate()

	// Look for DownloaderStatus from downloader
	// used only for downloader storage stats collection
	subBaseOsDownloadStatus, err := pubsub.SubscribeScope("downloader",
		baseOsObj, types.DownloaderStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subBaseOsDownloadStatus = subBaseOsDownloadStatus
	subBaseOsDownloadStatus.Activate()

	// Look for DownloaderStatus from downloader
	// used only for downloader storage stats collection
	subCertObjDownloadStatus, err := pubsub.SubscribeScope("downloader",
		certObj, types.DownloaderStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subCertObjDownloadStatus = subCertObjDownloadStatus
	subCertObjDownloadStatus.Activate()

	// Look for VerifyBaseOsImageStatus from verifier
	// used only for verifier storage stats collection
	subBaseOsVerifierStatus, err := pubsub.SubscribeScope("verifier",
		baseOsObj, types.VerifyImageStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsVerifierStatus.ModifyHandler = handleVerifierStatusModify
	subBaseOsVerifierStatus.DeleteHandler = handleVerifierStatusDelete
	subBaseOsVerifierStatus.RestartHandler = handleVerifierRestarted
	zedagentCtx.subBaseOsVerifierStatus = subBaseOsVerifierStatus
	subBaseOsVerifierStatus.Activate()

	// Look for VerifyImageStatus from verifier
	// used only for verifier storage stats collection
	subAppImgVerifierStatus, err := pubsub.SubscribeScope("verifier",
		appImgObj, types.VerifyImageStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subAppImgVerifierStatus = subAppImgVerifierStatus
	subAppImgVerifierStatus.Activate()

	// Look for DownloaderStatus from downloader for metric reporting
	// used only for downloader storage stats collection
	subAppImgDownloadStatus, err := pubsub.SubscribeScope("downloader",
		appImgObj, types.DownloaderStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	zedagentCtx.subAppImgDownloadStatus = subAppImgDownloadStatus
	subAppImgDownloadStatus.Activate()

	DNSctx := DNSContext{}
	DNSctx.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &DNSctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	DNSctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	time1 := time.Duration(globalConfig.ResetIfCloudGoneTime)
	t1 := time.NewTimer(time1 * time.Second)
	log.Infof("Started timer for reset for %d seconds\n", time1)
	time2 := time.Duration(globalConfig.FallbackIfCloudGoneTime)
	log.Infof("Started timer for fallback,  reset for %d seconds\n", time2)
	t2 := time.NewTimer(time2 * time.Second)

	// wait till, zboot status is ready
	for !zedagentCtx.zbootRestarted {
		select {
		case change := <-subZbootStatus.C:
			subZbootStatus.ProcessChange(change)
			if zedagentCtx.zbootRestarted {
				log.Infof("Zboot reported restarted\n")
			}

		case <-t1.C:
			// reboot, if not available, within a wait time
			errStr := "zboot status is still not available - rebooting"
			log.Errorf(errStr)
			agentlog.RebootReason(errStr)
			execReboot(true)

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
		}
	}

	updateInprogress := isBaseOsCurrentPartitionStateInProgress(&zedagentCtx)
	log.Infof("Current partition inProgress state is %v\n", updateInprogress)
	log.Infof("Waiting until we have some uplinks with usable addresses\n")
	waited := false
	for !DNSctx.DNSinitialized ||
		!zedagentCtx.assignableAdapters.Initialized {

		log.Infof("Waiting for DomainNetworkStatus %v and aa %v\n",
			DNSctx.DNSinitialized,
			zedagentCtx.assignableAdapters.Initialized)
		waited = true

		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-zedagentCtx.subBaseOsVerifierStatus.C:
			zedagentCtx.subBaseOsVerifierStatus.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAssignableAdapters.C:
			subAssignableAdapters.ProcessChange(change)

		case change := <-deferredChan:
			zedcloud.HandleDeferred(change, 100*time.Millisecond)

		case <-t1.C:
			errStr := "Exceeded outage for cloud connectivity - rebooting"
			log.Errorf(errStr)
			agentlog.RebootReason(errStr)
			execReboot(true)

		case <-t2.C:
			if updateInprogress {
				errStr := "Exceeded fallback outage for cloud connectivity - rebooting"
				log.Errorf(errStr)
				agentlog.RebootReason(errStr)
				execReboot(true)
			}

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
		}
	}
	t1.Stop()
	t2.Stop()
	if waited && DNSctx.usableAddressCount != 0 {
		// Inform ledmanager that we have management port addresses
		types.UpdateLedManagerConfig(2)
		getconfigCtx.ledManagerCount = 2
	}

	// Subscribe to network metrics from zedrouter
	subNetworkMetrics, err := pubsub.Subscribe("zedrouter",
		types.NetworkMetrics{}, true, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	// Subscribe to cloud metrics from different agents
	cms := zedcloud.GetCloudMetrics()
	subClientMetrics, err := pubsub.Subscribe("zedclient", cms,
		true, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subLogmanagerMetrics, err := pubsub.Subscribe("logmanager",
		cms, true, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDownloaderMetrics, err := pubsub.Subscribe("downloader",
		cms, true, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}

	// Publish initial device info.
	publishDevInfo(&zedagentCtx)

	// start the metrics reporting task
	handleChannel := make(chan interface{})
	go metricsTimerTask(&zedagentCtx, handleChannel)
	metricsTickerHandle := <-handleChannel
	getconfigCtx.metricsTickerHandle = metricsTickerHandle

	// Process the verifierStatus to avoid downloading an image we
	// already have in place
	log.Infof("Handling initial verifier Status\n")
	for !zedagentCtx.verifierRestarted {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subBaseOsVerifierStatus.C:
			subBaseOsVerifierStatus.ProcessChange(change)
			if zedagentCtx.verifierRestarted {
				log.Infof("Verifier reported restarted\n")
				break
			}

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAssignableAdapters.C:
			subAssignableAdapters.ProcessChange(change)

		case change := <-deferredChan:
			zedcloud.HandleDeferred(change, 100*time.Millisecond)

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
		}
	}

	// start the config fetch tasks, when zboot status is ready
	go configTimerTask(handleChannel, &getconfigCtx, updateInprogress)
	configTickerHandle := <-handleChannel
	// XXX close handleChannels?
	getconfigCtx.configTickerHandle = configTickerHandle

	for {
		select {
		case change := <-subZbootStatus.C:
			subZbootStatus.ProcessChange(change)

		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subAppInstanceStatus.C:
			subAppInstanceStatus.ProcessChange(change)

		case change := <-subBaseOsStatus.C:
			subBaseOsStatus.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
			if DNSctx.triggerGetConfig {
				triggerGetConfig(configTickerHandle)
				DNSctx.triggerGetConfig = false
			}
			if DNSctx.triggerDeviceInfo {
				// IP/DNS in device info could have changed
				log.Infof("NetworkStatus triggered PublishDeviceInfo\n")
				publishDevInfo(&zedagentCtx)
				DNSctx.triggerDeviceInfo = false
			}

		case change := <-subDomainStatus.C:
			subDomainStatus.ProcessChange(change)
			// UsedByUUID could have changed ...
			if zedagentCtx.TriggerDeviceInfo {
				log.Infof("UsedByUUID triggered PublishDeviceInfo\n")
				publishDevInfo(&zedagentCtx)
				zedagentCtx.TriggerDeviceInfo = false
			}

		case change := <-subAssignableAdapters.C:
			subAssignableAdapters.ProcessChange(change)

		case change := <-subNetworkMetrics.C:
			subNetworkMetrics.ProcessChange(change)
			m, err := subNetworkMetrics.Get("global")
			if err != nil {
				log.Errorf("subNetworkMetrics.Get failed: %s\n",
					err)
			} else {
				networkMetrics = types.CastNetworkMetrics(m)
			}

		case change := <-subClientMetrics.C:
			subClientMetrics.ProcessChange(change)
			m, err := subClientMetrics.Get("global")
			if err != nil {
				log.Errorf("subClientMetrics.Get failed: %s\n",
					err)
			} else {
				clientMetrics = m
			}

		case change := <-subLogmanagerMetrics.C:
			subLogmanagerMetrics.ProcessChange(change)
			m, err := subLogmanagerMetrics.Get("global")
			if err != nil {
				log.Errorf("subLogmanagerMetrics.Get failed: %s\n",
					err)
			} else {
				logmanagerMetrics = m
			}

		case change := <-subDownloaderMetrics.C:
			subDownloaderMetrics.ProcessChange(change)
			m, err := subDownloaderMetrics.Get("global")
			if err != nil {
				log.Errorf("subDownloaderMetrics.Get failed: %s\n",
					err)
			} else {
				downloaderMetrics = m
			}

		case change := <-deferredChan:
			zedcloud.HandleDeferred(change, 100*time.Millisecond)

		case change := <-subNetworkServiceStatus.C:
			subNetworkServiceStatus.ProcessChange(change)

		case change := <-subNetworkServiceMetrics.C:
			subNetworkServiceMetrics.ProcessChange(change)

		case change := <-subNetworkInstanceStatus.C:
			subNetworkInstanceStatus.ProcessChange(change)

		case change := <-subNetworkInstanceMetrics.C:
			subNetworkInstanceMetrics.ProcessChange(change)

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
		}
	}
}

func publishDevInfo(ctx *zedagentContext) {
	PublishDeviceInfoToZedCloud(ctx)
	ctx.iteration += 1
}

func handleVerifierRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleVerifierRestarted(%v)\n", done)
	if done {
		ctx.verifierRestarted = true
	}
}

// base os verifier status modify event
func handleVerifierStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleVerifierStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	log.Infof("handleVerifierStatusModify for %s\n", status.Safename)
	// Nothing to do
}

// base os verifier status delete event
func handleVerifierStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	log.Infof("handleVeriferStatusDelete RefCount %d Expired %v for %s\n",
		status.RefCount, status.Expired, key)
	// Nothing to do
}

func handleZbootRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleZbootRestarted(%v)\n", done)
	if done {
		ctx.zbootRestarted = true
	}
}

func handleInit() {
	initializeDirs()
	handleConfigInit()
}

func initializeDirs() {

	// create persistent holder directory
	if _, err := os.Stat(persistDir); err != nil {
		log.Debugf("Create %s\n", persistDir)
		if err := os.MkdirAll(persistDir, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(certificateDirname); err != nil {
		log.Debugf("Create %s\n", certificateDirname)
		if err := os.MkdirAll(certificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(checkpointDirname); err != nil {
		log.Debugf("Create %s\n", checkpointDirname)
		if err := os.MkdirAll(checkpointDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(objectDownloadDirname); err != nil {
		log.Debugf("Create %s\n", objectDownloadDirname)
		if err := os.MkdirAll(objectDownloadDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
}

// app instance event watch to capture transitions
// and publish to zedCloud

func handleAppInstanceStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := cast.CastAppInstanceStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleAppInstanceStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishAppInfoToZedCloud(ctx, uuidStr, &status, ctx.assignableAdapters,
		ctx.iteration)
	ctx.iteration += 1
}

func handleAppInstanceStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	uuidStr := key
	PublishAppInfoToZedCloud(ctx, uuidStr, nil, ctx.assignableAdapters,
		ctx.iteration)
	ctx.iteration += 1
}

func lookupAppInstanceStatus(ctx *zedagentContext, key string) *types.AppInstanceStatus {

	sub := ctx.getconfigCtx.subAppInstanceStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupAppInstanceStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastAppInstanceStatus(st)
	if status.Key() != key {
		log.Errorf("lookupAppInstanceStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(*deviceNetworkStatus, status) {
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(*deviceNetworkStatus, status))
	*deviceNetworkStatus = status
	// Did we (re-)gain the first usable address?
	// XXX should we also trigger if the count increases?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	if newAddrCount != 0 && ctx.usableAddressCount == 0 {
		log.Infof("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.usableAddressCount, newAddrCount)
		ctx.triggerGetConfig = true
	}
	ctx.DNSinitialized = true
	ctx.usableAddressCount = newAddrCount
	ctx.triggerDeviceInfo = true
	log.Infof("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*DNSContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.DNSinitialized = false
	ctx.usableAddressCount = newAddrCount
	log.Infof("handleDNSDelete done for %s\n", key)
}

// base os status event handlers
// Report BaseOsStatus to zedcloud

func handleBaseOsStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	status := cast.CastBaseOsStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleBaseOsStatusModify key/UUID mismatch %s vs %s; ignored %+v\n", key, status.Key(), status)
		return
	}
	doBaseOsZedCloudTestComplete(ctx, status)
	doBaseOsDeviceReboot(ctx, status)
	publishDevInfo(ctx)
	log.Infof("handleBaseOsStatusModify(%s) done\n", key)
}

func handleBaseOsStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleBaseOsStatusDelete(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := lookupBaseOsStatus(ctx, key)
	if status == nil {
		log.Infof("handleBaseOsStatusDelete: unknown %s\n", key)
		return
	}
	publishDevInfo(ctx)
	log.Infof("handleBaseOsStatusDelete(%s) done\n", key)
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	globalConfig = types.GlobalConfigDefaults
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

func handleAAModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := cast.CastAssignableAdapters(statusArg)
	if key != "global" {
		log.Infof("handleAAModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleAAModify() %+v\n", status)
	*ctx.assignableAdapters = status
	publishDevInfo(ctx)
	log.Infof("handleAAModify() done\n")
}

func handleAADelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	if key != "global" {
		log.Infof("handleAADelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleAADelete()\n")
	ctx.assignableAdapters.Initialized = false
	publishDevInfo(ctx)
	log.Infof("handleAADelete() done\n")
}

func handleZbootStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	if isBaseOsValidPartitionLabel(key) {
		log.Infof("handleZbootStatusModify: for %s\n", key)
	}
	// Nothing to do
}

func handleZbootStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	if isBaseOsValidPartitionLabel(key) {
		log.Infof("handleZbootStatusDelete: for %s\n", key)
	}
	// Nothing to do
}
