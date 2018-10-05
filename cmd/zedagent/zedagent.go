// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// zedAgent interfaces with zedcloud for
//   * config sync
//   * metric/info pubish
// app instance config is pushed to zedmanager for orchestration
// event based app instance/device info published to ZedCloud
// periodic status/metric published to zedCloud
// zeagent orchestrates base os/certs installation

// zedagent handles the following orchestration
//   * base os config/status          <zedagent>   / <baseos> / <config | status>
//   * certs config/status            <zedagent>   / certs>   / <config | status>
//   * base os download config/status <downloader> / <baseos> / <config | status>
//   * certs download config/status   <downloader> / <certs>  / <config | status>
//   * base os verifier config/status <verifier>   / <baseos> / <config | status>
// <base os>
//   <zedagent>   <baseos> <config> --> <zedagent>    <baseos> <status>
//				<download>...       --> <downloader>  <baseos> <config>
//   <downloader> <baseos> <config> --> <downloader>  <baseos> <status>
//				<downloaded>...     --> <downloader>  <baseos> <status>
//								    --> <zedagent>    <baseos> <status>
//								    --> <verifier>    <baseos> <config>
//				<verified>  ...     --> <verifier>    <baseos> <status>
//								    --> <zedagent>    <baseos> <status>
// <certs>
//   <zedagent>   <certs> <config> --> <zedagent>    <certs> <status>
//				<download>...      --> <downloader>  <certs> <config>
//   <downloader> <certs> <config> --> <downloader>  <certs> <status>
//				<downloaded>...    --> <downloader>  <certs> <status>
//								   --> <zedagent>    <certs> <status>

package zedagent

import (
	"flag"
	"fmt"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/adapters"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zboot"
	"github.com/zededa/go-provision/zedcloud"
	"os"
	"time"
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
)

// Set from Makefile
var Version = "No version specified"

// XXX move to a context? Which? Used in handleconfig and handlemetrics!
var deviceNetworkStatus types.DeviceNetworkStatus

// XXX globals filled in by subscription handlers and read by handlemetrics
// XXX could alternatively access sub object when adding them.
var clientMetrics interface{}
var logmanagerMetrics interface{}
var downloaderMetrics interface{}
var networkMetrics types.NetworkMetrics

// Context for handleDNSModify
type DNSContext struct {
	usableAddressCount     int
	subDeviceNetworkStatus *pubsub.Subscription
	triggerGetConfig       bool
	triggerDeviceInfo      bool
}

type zedagentContext struct {
	getconfigCtx             *getconfigContext // Cross link
	verifierRestarted        bool              // Information from handleVerifierRestarted
	assignableAdapters       *types.AssignableAdapters
	iteration                int
	subNetworkObjectStatus   *pubsub.Subscription
	subNetworkServiceStatus  *pubsub.Subscription
	subDomainStatus          *pubsub.Subscription
	subCertObjConfig         *pubsub.Subscription
	pubCertObjStatus         *pubsub.Publication
	TriggerDeviceInfo        bool
	subBaseOsConfig          *pubsub.Subscription
	subBaseOsStatus          *pubsub.Subscription
	subDatastoreConfig       *pubsub.Subscription
	pubBaseOsStatus          *pubsub.Publication
	pubBaseOsDownloadConfig  *pubsub.Publication
	subBaseOsDownloadStatus  *pubsub.Subscription
	pubCertObjDownloadConfig *pubsub.Publication
	subCertObjDownloadStatus *pubsub.Subscription
	pubBaseOsVerifierConfig  *pubsub.Publication
	subBaseOsVerifierStatus  *pubsub.Subscription
	subAppImgDownloadStatus  *pubsub.Subscription
	subAppImgVerifierStatus  *pubsub.Subscription
	subNetworkServiceMetrics *pubsub.Subscription
	subGlobalConfig          *pubsub.Subscription
}

var debug = false
var debugOverride bool // From command line arg

func Run() {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
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
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	log.Infof("Starting %s\n", agentName)

	// Tell ourselves to go ahead
	// initialize the module specifig stuff
	handleInit()

	// Context to pass around
	getconfigCtx := getconfigContext{}

	// Pick up (mostly static) AssignableAdapters before we report
	// any device info
	model := hardware.GetHardwareModel()
	log.Debugf("HardwareModel %s\n", model)
	aa := types.AssignableAdapters{}
	subAa := adapters.Subscribe(&aa, model)

	zedagentCtx := zedagentContext{assignableAdapters: &aa}
	// Cross link
	getconfigCtx.zedagentCtx = &zedagentCtx
	zedagentCtx.getconfigCtx = &getconfigCtx

	// XXX placeholder for uplink config from zedcloud
	pubDeviceUplinkConfig, err := pubsub.Publish(agentName,
		types.DeviceUplinkConfig{})
	if err != nil {
		log.Fatal(err)
	}
	getconfigCtx.pubDeviceUplinkConfig = pubDeviceUplinkConfig

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

	pubCertObjStatus, err := pubsub.Publish(agentName,
		types.CertObjStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubCertObjStatus.ClearRestarted()
	zedagentCtx.pubCertObjStatus = pubCertObjStatus

	pubBaseOsConfig, err := pubsub.Publish(agentName,
		types.BaseOsConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsConfig.ClearRestarted()
	getconfigCtx.pubBaseOsConfig = pubBaseOsConfig

	pubBaseOsStatus, err := pubsub.Publish(agentName,
		types.BaseOsStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsStatus.ClearRestarted()
	zedagentCtx.pubBaseOsStatus = pubBaseOsStatus

	pubBaseOsDownloadConfig, err := pubsub.PublishScope(agentName,
		baseOsObj, types.DownloaderConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsDownloadConfig.ClearRestarted()
	zedagentCtx.pubBaseOsDownloadConfig = pubBaseOsDownloadConfig

	pubCertObjDownloadConfig, err := pubsub.PublishScope(agentName,
		certObj, types.DownloaderConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubCertObjDownloadConfig.ClearRestarted()
	zedagentCtx.pubCertObjDownloadConfig = pubCertObjDownloadConfig

	pubBaseOsVerifierConfig, err := pubsub.PublishScope(agentName,
		baseOsObj, types.VerifyImageConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsVerifierConfig.ClearRestarted()
	zedagentCtx.pubBaseOsVerifierConfig = pubBaseOsVerifierConfig

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

	// Look for errors and status from zedrouter
	subNetworkObjectStatus, err := pubsub.Subscribe("zedrouter",
		types.NetworkObjectStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subNetworkObjectStatus.ModifyHandler = handleNetworkObjectStatusModify
	subNetworkObjectStatus.DeleteHandler = handleNetworkObjectStatusDelete
	zedagentCtx.subNetworkObjectStatus = subNetworkObjectStatus
	subNetworkObjectStatus.Activate()

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

	// Look for CertObjConfig from ourselves! XXX introduce separate
	// certmanager?
	subCertObjConfig, err := pubsub.Subscribe("zedagent",
		types.CertObjConfig{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subCertObjConfig.ModifyHandler = handleCertObjConfigModify
	subCertObjConfig.DeleteHandler = handleCertObjConfigDelete
	zedagentCtx.subCertObjConfig = subCertObjConfig
	subCertObjConfig.Activate()

	// Look for BaseOsConfig and BaseOsStatus from ourselves!
	subBaseOsConfig, err := pubsub.Subscribe("zedagent",
		types.BaseOsConfig{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsConfig.ModifyHandler = handleBaseOsConfigModify
	subBaseOsConfig.DeleteHandler = handleBaseOsConfigDelete
	zedagentCtx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()

	subBaseOsStatus, err := pubsub.Subscribe("zedagent",
		types.BaseOsStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsStatus.ModifyHandler = handleBaseOsStatusModify
	subBaseOsStatus.DeleteHandler = handleBaseOsStatusDelete
	zedagentCtx.subBaseOsStatus = subBaseOsStatus
	subBaseOsStatus.Activate()

	// Look for DatastoreConfig from ourselves!
	subDatastoreConfig, err := pubsub.Subscribe("zedagent",
		types.DatastoreConfig{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDatastoreConfig.ModifyHandler = handleDatastoreConfigModify
	subDatastoreConfig.DeleteHandler = handleDatastoreConfigDelete
	zedagentCtx.subDatastoreConfig = subDatastoreConfig
	subDatastoreConfig.Activate()

	// Look for DownloaderStatus from downloader
	subBaseOsDownloadStatus, err := pubsub.SubscribeScope("downloader",
		baseOsObj, types.DownloaderStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsDownloadStatus.ModifyHandler = handleDownloadStatusModify
	subBaseOsDownloadStatus.DeleteHandler = handleDownloadStatusDelete
	zedagentCtx.subBaseOsDownloadStatus = subBaseOsDownloadStatus
	subBaseOsDownloadStatus.Activate()

	// Look for DownloaderStatus from downloader
	subCertObjDownloadStatus, err := pubsub.SubscribeScope("downloader",
		certObj, types.DownloaderStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subCertObjDownloadStatus.ModifyHandler = handleDownloadStatusModify
	subCertObjDownloadStatus.DeleteHandler = handleDownloadStatusDelete
	zedagentCtx.subCertObjDownloadStatus = subCertObjDownloadStatus
	subCertObjDownloadStatus.Activate()

	// Look for VerifyImageStatus from verifier
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
	subAppImgVerifierStatus, err := pubsub.SubscribeScope("verifier",
		appImgObj, types.VerifyImageStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgVerifierStatus.ModifyHandler = handleVerifierStatusModify
	subAppImgVerifierStatus.DeleteHandler = handleVerifierStatusDelete
	zedagentCtx.subAppImgVerifierStatus = subAppImgVerifierStatus
	subAppImgVerifierStatus.Activate()

	// Look for DownloaderStatus from downloader for metric reporting
	subAppImgDownloadStatus, err := pubsub.SubscribeScope("downloader",
		appImgObj, types.DownloaderStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgDownloadStatus.ModifyHandler = handleDownloadStatusModify
	subAppImgDownloadStatus.DeleteHandler = handleDownloadStatusDelete
	zedagentCtx.subAppImgDownloadStatus = subAppImgDownloadStatus
	subAppImgDownloadStatus.Activate()

	// First we process the verifierStatus to avoid downloading
	// an base image we already have in place
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

		case change := <-subAa.C:
			subAa.ProcessChange(change)
		}
	}

	DNSctx := DNSContext{}
	DNSctx.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)

	subDeviceNetworkStatus, err := pubsub.Subscribe("zedrouter",
		types.DeviceNetworkStatus{}, false, &DNSctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	DNSctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	updateInprogress := zboot.IsCurrentPartitionStateInProgress()
	time1 := time.Duration(globalConfig.ResetIfCloudGoneTime)
	t1 := time.NewTimer(time1 * time.Second)
	log.Infof("Started timer for reset for %d seconds\n", time1)
	time2 := time.Duration(globalConfig.FallbackIfCloudGoneTime)
	log.Infof("Started timer for fallback (%v) reset for %d seconds\n",
		updateInprogress, time2)
	t2 := time.NewTimer(time2 * time.Second)

	// Initial settings; redone below in case some
	updateSshAccess(!globalConfig.NoSshAccess, true)

	log.Infof("Waiting until we have some uplinks with usable addresses\n")
	waited := false
	for DNSctx.usableAddressCount == 0 || !subAa.Found {
		log.Infof("Waiting - have %d addresses; subAa %v\n",
			DNSctx.usableAddressCount, subAa.Found)
		waited = true

		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAa.C:
			subAa.ProcessChange(change)

		case <-t1.C:
			log.Errorf("Exceeded outage for cloud connectivity - rebooting\n")
			execReboot(true)

		case <-t2.C:
			if updateInprogress {
				log.Errorf("Exceeded fallback outage for cloud connectivity - rebooting\n")
				execReboot(true)
			}
		}
	}
	t1.Stop()
	t2.Stop()
	log.Infof("Have %d uplinks addresses to use; subAa %v\n",
		DNSctx.usableAddressCount, subAa.Found)
	if waited {
		// Inform ledmanager that we have uplink addresses
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

	// Timer for deferred sends of info messages
	deferredChan := zedcloud.InitDeferred()

	// Publish initial device info. Retries all addresses on all uplinks.
	publishDevInfo(&zedagentCtx)

	// start the metrics/config fetch tasks
	handleChannel := make(chan interface{})
	go configTimerTask(handleChannel, &getconfigCtx)
	log.Infof("Waiting for flexticker handle\n")
	configTickerHandle := <-handleChannel
	go metricsTimerTask(&zedagentCtx, handleChannel)
	metricsTickerHandle := <-handleChannel
	// XXX close handleChannels?
	getconfigCtx.configTickerHandle = configTickerHandle
	getconfigCtx.metricsTickerHandle = metricsTickerHandle

	updateSshAccess(!globalConfig.NoSshAccess, true)

	for {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subCertObjConfig.C:
			subCertObjConfig.ProcessChange(change)

		case change := <-subAppInstanceStatus.C:
			subAppInstanceStatus.ProcessChange(change)

		case change := <-subBaseOsConfig.C:
			subBaseOsConfig.ProcessChange(change)

		case change := <-subBaseOsStatus.C:
			subBaseOsStatus.ProcessChange(change)

		case change := <-subDatastoreConfig.C:
			subDatastoreConfig.ProcessChange(change)

		case change := <-subBaseOsDownloadStatus.C:
			subBaseOsDownloadStatus.ProcessChange(change)

		case change := <-subBaseOsVerifierStatus.C:
			subBaseOsVerifierStatus.ProcessChange(change)

		case change := <-subAppImgVerifierStatus.C:
			subAppImgVerifierStatus.ProcessChange(change)

		case change := <-subAppImgDownloadStatus.C:
			subAppImgDownloadStatus.ProcessChange(change)

		case change := <-subCertObjDownloadStatus.C:
			subCertObjDownloadStatus.ProcessChange(change)

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

		case change := <-subAa.C:
			subAa.ProcessChange(change)

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
			zedcloud.HandleDeferred(change)

		case change := <-subNetworkObjectStatus.C:
			subNetworkObjectStatus.ProcessChange(change)

		case change := <-subNetworkServiceStatus.C:
			subNetworkServiceStatus.ProcessChange(change)

		case change := <-subNetworkServiceMetrics.C:
			subNetworkServiceMetrics.ProcessChange(change)
		}
	}
}

func publishDevInfo(ctx *zedagentContext) {
	PublishDeviceInfoToZedCloud(ctx.subBaseOsStatus, ctx.assignableAdapters,
		ctx.iteration)
	ctx.iteration += 1
}

func handleVerifierRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleVerifierRestarted(%v)\n", done)
	if done {
		ctx.verifierRestarted = true
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

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(deviceNetworkStatus, status) {
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(deviceNetworkStatus, status))
	deviceNetworkStatus = status
	// Did we (re-)gain the first usable address?
	// XXX should we also trigger if the count increases?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)
	if newAddrCount != 0 && ctx.usableAddressCount == 0 {
		log.Infof("DeviceNetworkStatus from %d to %d addresses\n",
			newAddrCount, ctx.usableAddressCount)
		ctx.triggerGetConfig = true
	}
	ctx.usableAddressCount = newAddrCount
	ctx.triggerDeviceInfo = true
	devicenetwork.ProxyToEnv(deviceNetworkStatus.ProxyConfig)
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
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)
	ctx.usableAddressCount = newAddrCount
	devicenetwork.ProxyToEnv(deviceNetworkStatus.ProxyConfig)
	log.Infof("handleDNSDelete done for %s\n", key)
}

// Wrappers around handleBaseOsCreate/Modify/Delete

func handleBaseOsConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	config := cast.CastBaseOsConfig(configArg)
	if config.Key() != key {
		log.Errorf("handleBaseOsConfigModify key/UUID mismatch %s vs %s; ignored %+v\n", key, config.Key(), config)
		return
	}
	status := lookupBaseOsStatus(ctx, key)
	if status == nil {
		handleBaseOsCreate(ctx, key, &config)
	} else {
		handleBaseOsModify(ctx, key, &config, status)
	}
	log.Infof("handleBaseOsConfigModify(%s) done\n", key)
}

func handleBaseOsConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleBaseOsConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := lookupBaseOsStatus(ctx, key)
	if status == nil {
		log.Infof("handleBaseOsConfigDelete: unknown %s\n", key)
		return
	}
	handleBaseOsDelete(ctx, key, status)
	log.Infof("handleBaseOsConfigDelete(%s) done\n", key)
}

// base os config/status event handlers
// base os config create event
func handleBaseOsCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	config := cast.CastBaseOsConfig(configArg)
	if config.Key() != key {
		log.Errorf("handleBaseOsCreate key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	uuidStr := config.Key()
	ctx := ctxArg.(*zedagentContext)

	log.Infof("handleBaseOsCreate for %s\n", uuidStr)
	status := types.BaseOsStatus{
		UUIDandVersion: config.UUIDandVersion,
		BaseOsVersion:  config.BaseOsVersion,
		ConfigSha256:   config.ConfigSha256,
	}

	status.StorageStatusList = make([]types.StorageStatus,
		len(config.StorageConfigList))

	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		ss.Name = sc.Name
		ss.ImageSha256 = sc.ImageSha256
		ss.Target = sc.Target
	}

	// Check total and activated counts
	err := validateBaseOsConfig(ctx, config)
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		log.Errorln(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		publishBaseOsStatus(ctx, &status)
		return
	}

	baseOsGetActivationStatus(ctx, &status)
	publishBaseOsStatus(ctx, &status)

	baseOsHandleStatusUpdate(ctx, &config, &status)
}

// base os config modify event
func handleBaseOsModify(ctxArg interface{}, key string,
	configArg interface{}, statusArg interface{}) {
	config := cast.CastBaseOsConfig(configArg)
	if config.Key() != key {
		log.Errorf("handleBaseOsModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	status := cast.CastBaseOsStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleBaseOsModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	uuidStr := config.Key()
	ctx := ctxArg.(*zedagentContext)

	log.Infof("handleBaseOsModify for %s\n", status.BaseOsVersion)
	if config.UUIDandVersion.Version == status.UUIDandVersion.Version &&
		config.Activate == status.Activated {
		log.Infof("Same version %v for %s\n",
			config.UUIDandVersion.Version, uuidStr)
		return
	}

	// Check total and activated counts
	err := validateBaseOsConfig(ctx, config)
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		log.Errorln(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		publishBaseOsStatus(ctx, &status)
		return
	}

	// update the version field, uuids being the same
	status.UUIDandVersion = config.UUIDandVersion
	publishBaseOsStatus(ctx, &status)

	baseOsHandleStatusUpdate(ctx, &config, &status)
}

// base os config delete event
func handleBaseOsDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	status := configArg.(*types.BaseOsStatus)
	if status.Key() != key {
		log.Errorf("handleBaseOsDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)

	log.Infof("handleBaseOsDelete for %s\n", status.BaseOsVersion)
	removeBaseOsConfig(ctx, status.Key())
}

// Report BaseOsStatus to zedcloud

func handleBaseOsStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	status := cast.CastBaseOsStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleBaseOsStatusModify key/UUID mismatch %s vs %s; ignored %+v\n", key, status.Key(), status)
		return
	}
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

// Wrappers around handleCertObjCreate/Modify/Delete

func handleCertObjConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	config := cast.CastCertObjConfig(configArg)
	if config.Key() != key {
		log.Errorf("handleCertObjConfigModify key/UUID mismatch %s vs %s; ignored %+v\n", key, config.Key(), config)
		return
	}
	status := lookupCertObjStatus(ctx, key)
	if status == nil {
		handleCertObjCreate(ctx, key, &config)
	} else {
		handleCertObjModify(ctx, key, &config, status)
	}
	log.Infof("handleCertObjConfigModify(%s) done\n", key)
}

func handleCertObjConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleCertObjConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := lookupCertObjStatus(ctx, key)
	if status == nil {
		log.Infof("handleCertObjConfigDelete: unknown %s\n", key)
		return
	}
	handleCertObjDelete(ctx, key, status)
	log.Infof("handleCertObjConfigDelete(%s) done\n", key)
}

// certificate config/status event handlers
// certificate config create event
func handleCertObjCreate(ctx *zedagentContext, key string, config *types.CertObjConfig) {

	log.Infof("handleCertObjCreate for %s\n", key)

	status := types.CertObjStatus{
		UUIDandVersion: config.UUIDandVersion,
		ConfigSha256:   config.ConfigSha256,
	}

	status.StorageStatusList = make([]types.StorageStatus,
		len(config.StorageConfigList))

	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		ss.Name = sc.Name
		ss.ImageSha256 = sc.ImageSha256
		ss.FinalObjDir = certificateDirname
	}

	publishCertObjStatus(ctx, &status)

	certObjHandleStatusUpdate(ctx, config, &status)
}

// certificate config modify event
func handleCertObjModify(ctx *zedagentContext, key string, config *types.CertObjConfig, status *types.CertObjStatus) {

	uuidStr := config.Key()
	log.Infof("handleCertObjModify for %s\n", uuidStr)

	// XXX:FIXME, do we
	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Infof("Same version %v for %s\n",
			config.UUIDandVersion.Version, key)
		return
	}

	status.UUIDandVersion = config.UUIDandVersion
	publishCertObjStatus(ctx, status)

	certObjHandleStatusUpdate(ctx, config, status)
}

// certificate config delete event
func handleCertObjDelete(ctx *zedagentContext, key string,
	status *types.CertObjStatus) {

	uuidStr := status.Key()
	log.Infof("handleCertObjDelete for %s\n", uuidStr)
	removeCertObjConfig(ctx, uuidStr)
}

func handleDownloadStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastDownloaderStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleDownloadStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleDownloadStatusModify for %s\n",
		status.Safename)
	updateDownloaderStatus(ctx, &status)
}

// base os download status delete event
func handleDownloadStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := cast.CastDownloaderStatus(statusArg)
	log.Infof("handleDownloadStatusDelete RefCount %d for %s\n",
		status.RefCount, key)
	switch status.ObjType {
	case baseOsObj, certObj:
		// Nothing to do
	default:
		log.Infof("handleDownloadStatusDelete skip %s for %s\n",
			status.ObjType, key)
		return
	}
	// We know there are no references to this object any more
	// so we can remove it
	config := lookupDownloaderConfig(ctx, status.ObjType, status.Key())
	if config == nil {
		log.Infof("handleDownloadStatusDelete missing config for %s\n",
			key)
		return
	}
	log.Infof("handleDownloadStatusDelete delete config for %s\n", key)
	unpublishDownloaderConfig(ctx, status.ObjType, config)
}

func handleVerifierStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleVerifierStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleVerifierStatusModify for %s\n", status.Safename)
	updateVerifierStatus(ctx, &status)
}

func handleVerifierStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleVeriferStatusDelete RefCount %d for %s\n",
		status.RefCount, key)
	if status.ObjType != baseOsObj {
		log.Infof("handleVeriferStatusDelete skip %s for %s\n",
			status.ObjType, key)
		return
	}

	config := lookupVerifierConfig(ctx, status.ObjType, status.Key())
	if config == nil {
		log.Infof("handleVerifierStatusDelete missing config for %s\n",
			key)
		return
	}
	log.Infof("handleVerifierStatusDelete delete config for %s\n", key)
	unpublishVerifierConfig(ctx, status.ObjType, config)
}

func handleDatastoreConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX empty since we look at collection when we need it
	log.Infof("handleDatastoreConfigModify for %s\n", key)
}

func handleDatastoreConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX empty since we look at collection when we need it
	log.Infof("handleDatastoreConfigDelete for %s\n", key)
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
	debug = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	c, err := ctx.subGlobalConfig.Get("global")
	if err == nil {
		gc := cast.CastGlobalConfig(c)
		if !cmp.Equal(globalConfig, gc) {
			log.Infof("handleGlobalConfigModify: diff %v\n",
				cmp.Diff(globalConfig, gc))
			applyGlobalConfig(gc)
		}
	}
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
	debug = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	globalConfig = globalConfigDefaults
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

// Check which values are set and which should come from defaults
// Zero integers means to use default
func applyGlobalConfig(newgc types.GlobalConfig) {

	if newgc.ConfigInterval == 0 {
		newgc.ConfigInterval = globalConfigDefaults.ConfigInterval
	}
	if newgc.MetricInterval == 0 {
		newgc.MetricInterval = globalConfigDefaults.MetricInterval
	}
	if newgc.ResetIfCloudGoneTime == 0 {
		newgc.ResetIfCloudGoneTime = globalConfigDefaults.ResetIfCloudGoneTime
	}
	if newgc.FallbackIfCloudGoneTime == 0 {
		newgc.FallbackIfCloudGoneTime = globalConfigDefaults.FallbackIfCloudGoneTime
	}
	if newgc.MintimeUpdateSuccess == 0 {
		newgc.MintimeUpdateSuccess = globalConfigDefaults.MintimeUpdateSuccess
	}
	if newgc.StaleConfigTime == 0 {
		newgc.StaleConfigTime = globalConfigDefaults.StaleConfigTime
	}
	globalConfig = newgc
}
