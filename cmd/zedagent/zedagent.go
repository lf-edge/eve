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
	"github.com/zededa/go-provision/adapters"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"github.com/zededa/go-provision/zboot"
	"github.com/zededa/go-provision/zedcloud"
	"log"
	"os"
	"time"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	appImgObj = "appImg.obj"
	baseOsObj = "baseOs.obj"
	certObj   = "cert.obj"
	agentName = "zedagent"

	downloaderModulename = "downloader"
	verifierModulename   = "verifier"
	zedagentModulename   = agentName
	zedmanagerModulename = "zedmanager"

	moduleName     = agentName
	zedBaseDirname = "/var/tmp"
	zedRunDirname  = "/var/run"
	baseDirname    = zedBaseDirname + "/" + moduleName
	runDirname     = zedRunDirname + "/" + moduleName

	configDir             = "/config"
	persistDir            = "/persist"
	objectDownloadDirname = persistDir + "/downloads"
	certificateDirname    = persistDir + "/certs"

	downloaderBaseDirname = zedBaseDirname + "/" + downloaderModulename
	downloaderRunDirname  = zedRunDirname + "/" + downloaderModulename

	verifierBaseDirname = zedBaseDirname + "/" + verifierModulename
	verifierRunDirname  = zedRunDirname + "/" + verifierModulename

	// base os config/status holder
	zedagentBaseOsConfigDirname = baseDirname + "/" + baseOsObj + "/config"
	zedagentBaseOsStatusDirname = runDirname + "/" + baseOsObj + "/status"

	// base os download config/status holder
	downloaderBaseOsStatusDirname  = downloaderRunDirname + "/" + baseOsObj + "/status"
	downloaderCertObjStatusDirname = downloaderRunDirname + "/" + certObj + "/status"

	// base os verifier status holder
	verifierBaseOsConfigDirname = verifierBaseDirname + "/" + baseOsObj + "/config"
	verifierBaseOsStatusDirname = verifierRunDirname + "/" + baseOsObj + "/status"
	verifierAppImgStatusDirname = verifierRunDirname + "/" + appImgObj + "/status"
)

// Set from Makefile
var Version = "No version specified"

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
}

type zedagentContext struct {
	verifierRestarted	bool // Information from handleVerifierRestarted
	assignableAdapters	*types.AssignableAdapters
	iteration          	int
	subNetworkObjectStatus  *pubsub.Subscription
	subNetworkServiceStatus *pubsub.Subscription
	subDomainStatus         *pubsub.Subscription
	subCertObjConfig        *pubsub.Subscription
	pubCertObjStatus        *pubsub.Publication
	TriggerDeviceInfo       bool
}

var debug = false

// XXX temporary hack for writeBaseOsStatus
var zedagentCtx zedagentContext

// XXX used by baseOs code to indicate that something changed
// Will not be needed once we have a separate baseosmgr since
// we'll react to baseOsStatus changes.
var publishDeviceInfo bool

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting %s\n", agentName)

	// Tell ourselves to go ahead
	// initialize the module specifig stuff
	handleInit()

	// Context to pass around
	getconfigCtx := getconfigContext{}


	// Pick up (mostly static) AssignableAdapters before we report
	// any device info
	model := hardware.GetHardwareModel()
	log.Printf("HardwareModel %s\n", model)
	aa := types.AssignableAdapters{}
	subAa := adapters.Subscribe(&aa, model)

	zedagentCtx = zedagentContext{assignableAdapters: &aa}

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

	// Look for errors and status from zedrouter
	subNetworkObjectStatus, err := pubsub.Subscribe("zedrouter",
		types.NetworkObjectStatus{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subNetworkObjectStatus.ModifyHandler = handleNetworkObjectModify
	subNetworkObjectStatus.DeleteHandler = handleNetworkObjectDelete
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

	// Look for CertObjConfig from ourselves!
	subCertObjConfig, err := pubsub.Subscribe("zedagent",
		types.CertObjConfig{}, false, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subCertObjConfig.ModifyHandler = handleCertObjConfigModify
	subCertObjConfig.DeleteHandler = handleCertObjConfigDelete
	zedagentCtx.subCertObjConfig = subCertObjConfig
	subCertObjConfig.Activate()

	baseOsConfigStatusChanges := make(chan string)
	baseOsDownloaderChanges := make(chan string)
	baseOsVerifierChanges := make(chan string)
	appImgVerifierChanges := make(chan string)
	certObjDownloaderChanges := make(chan string)

	var verifierRestartedFn watch.StatusRestartHandler = handleVerifierRestarted

	// baseOs verification status watcher
	go watch.WatchStatus(verifierBaseOsStatusDirname,
		baseOsVerifierChanges)

	go watch.WatchStatus(verifierAppImgStatusDirname,
		appImgVerifierChanges)

	// First we process the verifierStatus to avoid downloading
	// an base image we already have in place
	log.Printf("Handling initial verifier Status\n")
	for !zedagentCtx.verifierRestarted {
		select {
		case change := <-baseOsVerifierChanges:
			watch.HandleStatusEvent(change, &zedagentCtx,
				verifierBaseOsStatusDirname,
				&types.VerifyImageStatus{},
				handleBaseOsVerifierStatusModify,
				handleBaseOsVerifierStatusDelete,
				&verifierRestartedFn)
			if zedagentCtx.verifierRestarted {
				log.Printf("Verifier reported restarted\n")
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
	time1 := time.Duration(configItemCurrent.resetIfCloudGoneTime)
	t1 := time.NewTimer(time1 * time.Second)
	log.Printf("Started timer for reset for %d seconds\n", time1)
	time2 := time.Duration(configItemCurrent.fallbackIfCloudGoneTime)
	log.Printf("Started timer for fallback (%v) reset for %d seconds\n",
		updateInprogress, time2)
	t2 := time.NewTimer(time2 * time.Second)

	// Initial settings; redone below in case some
	updateSshAccess(configItemCurrent.sshAccess)

	log.Printf("Waiting until we have some uplinks with usable addresses\n")
	waited := false
	for DNSctx.usableAddressCount == 0 || !subAa.Found {
		log.Printf("Waiting - have %d addresses; subAa %v\n",
			DNSctx.usableAddressCount, subAa.Found)
		waited = true

		select {
		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAa.C:
			subAa.ProcessChange(change)

		case <-t1.C:
			log.Printf("Exceeded outage for cloud connectivity - rebooting\n")
			execReboot(true)

		case <-t2.C:
			if updateInprogress {
				log.Printf("Exceeded fallback outage for cloud connectivity - rebooting\n")
				execReboot(true)
			}
		}
	}
	t1.Stop()
	t2.Stop()
	log.Printf("Have %d uplinks addresses to use; subAa %v\n",
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
	subLogmanagerMetrics, err := pubsub.Subscribe("logmanager", cms,
		true, &zedagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDownloaderMetrics, err := pubsub.Subscribe("downloader", cms,
		true, &zedagentCtx)
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
	log.Printf("Waiting for flexticker handle\n")
	configTickerHandle := <-handleChannel
	go metricsTimerTask(handleChannel)
	metricsTickerHandle := <-handleChannel
	// XXX close handleChannels?
	getconfigCtx.configTickerHandle = configTickerHandle
	getconfigCtx.metricsTickerHandle = metricsTickerHandle

	updateSshAccess(configItemCurrent.sshAccess)

	// base os config/status event handler
	go watch.WatchConfigStatus(zedagentBaseOsConfigDirname,
		zedagentBaseOsStatusDirname, baseOsConfigStatusChanges)

	// baseOs download status watcher
	go watch.WatchStatus(downloaderBaseOsStatusDirname,
		baseOsDownloaderChanges)

	// certificate download status watcher
	go watch.WatchStatus(downloaderCertObjStatusDirname,
		certObjDownloaderChanges)

	for {
		if publishDeviceInfo {
			log.Printf("BaseOs triggered PublishDeviceInfo\n")
			publishDevInfo(&zedagentCtx)
			publishDeviceInfo = false
		}

		select {
		case change := <-subCertObjConfig.C:
			subCertObjConfig.ProcessChange(change)

		case change := <-subAppInstanceStatus.C:
			subAppInstanceStatus.ProcessChange(change)

		case change := <-baseOsConfigStatusChanges:
			watch.HandleConfigStatusEvent(change, &zedagentCtx,
				zedagentBaseOsConfigDirname,
				zedagentBaseOsStatusDirname,
				&types.BaseOsConfig{},
				&types.BaseOsStatus{},
				handleBaseOsCreate,
				handleBaseOsModify,
				handleBaseOsDelete, nil)

		case change := <-baseOsDownloaderChanges:
			watch.HandleStatusEvent(change, &zedagentCtx,
				downloaderBaseOsStatusDirname,
				&types.DownloaderStatus{},
				handleBaseOsDownloadStatusModify,
				handleBaseOsDownloadStatusDelete, nil)

		case change := <-baseOsVerifierChanges:
			watch.HandleStatusEvent(change, &zedagentCtx,
				verifierBaseOsStatusDirname,
				&types.VerifyImageStatus{},
				handleBaseOsVerifierStatusModify,
				handleBaseOsVerifierStatusDelete, nil)

				// XXX
		case change := <-appImgVerifierChanges:
			watch.HandleStatusEvent(change, &zedagentCtx,
				verifierAppImgStatusDirname,
				&types.VerifyImageStatus{},
				handleAppImgVerifierStatusModify,
				handleAppImgVerifierStatusDelete, nil)

				// XXX
		case change := <-certObjDownloaderChanges:
			watch.HandleStatusEvent(change, &zedagentCtx,
				downloaderCertObjStatusDirname,
				&types.DownloaderStatus{},
				handleCertObjDownloadStatusModify,
				handleCertObjDownloadStatusDelete, nil)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
			if DNSctx.triggerGetConfig {
				triggerGetConfig(configTickerHandle)
				DNSctx.triggerGetConfig = false
			}
			// IP/DNS in device info could have changed
			// XXX could compare in handleDNSModify as we do
			// for handleDomainStatus
			log.Printf("NetworkStatus triggered PublishDeviceInfo\n")
			publishDevInfo(&zedagentCtx)

		case change := <-subDomainStatus.C:
			subDomainStatus.ProcessChange(change)
			// UsedByUUID could have changed ...
			if zedagentCtx.TriggerDeviceInfo {
				log.Printf("UsedByUUID triggered PublishDeviceInfo\n")
				publishDevInfo(&zedagentCtx)
				zedagentCtx.TriggerDeviceInfo = false
			}

		case change := <-subAa.C:
			subAa.ProcessChange(change)

		case change := <-subNetworkMetrics.C:
			subNetworkMetrics.ProcessChange(change)
			m, err := subNetworkMetrics.Get("global")
			if err != nil {
				log.Printf("subNetworkMetrics.Get failed: %s\n",
					err)
			} else {
				networkMetrics = types.CastNetworkMetrics(m)
			}

		case change := <-subClientMetrics.C:
			subClientMetrics.ProcessChange(change)
			m, err := subClientMetrics.Get("global")
			if err != nil {
				log.Printf("subClientMetrics.Get failed: %s\n",
					err)
			} else {
				clientMetrics = m
			}

		case change := <-subLogmanagerMetrics.C:
			subLogmanagerMetrics.ProcessChange(change)
			m, err := subLogmanagerMetrics.Get("global")
			if err != nil {
				log.Printf("subLogmanagerMetrics.Get failed: %s\n",
					err)
			} else {
				logmanagerMetrics = m
			}

		case change := <-subDownloaderMetrics.C:
			subDownloaderMetrics.ProcessChange(change)
			m, err := subDownloaderMetrics.Get("global")
			if err != nil {
				log.Printf("subDownloaderMetrics.Get failed: %s\n",
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
		}
	}
}

func publishDevInfo(ctx *zedagentContext) {
	PublishDeviceInfoToZedCloud(baseOsStatusMap, ctx.assignableAdapters,
		ctx.iteration)
	ctx.iteration += 1
}

func handleVerifierRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleVerifierRestarted(%v)\n", done)
	if done {
		ctx.verifierRestarted = true
	}
}

func handleInit() {
	initializeDirs()
	initMaps()
	handleConfigInit()
}

func initializeDirs() {

	// XXX remove noObjTypes := []string{}
	zedagentObjTypes := []string{baseOsObj, certObj}
	zedagentVerifierObjTypes := []string{baseOsObj}

	// create the module object based config/status dirs
	// XXX remove
	createConfigStatusDirs(downloaderModulename, zedagentObjTypes)
	// createConfigStatusDirs(zedagentModulename, zedagentObjTypes)
	// createConfigStatusDirs(zedmanagerModulename, noObjTypes)
	createConfigStatusDirs(verifierModulename, zedagentVerifierObjTypes)

	// create persistent holder directory
	if _, err := os.Stat(persistDir); err != nil {
		log.Printf("Create %s\n", persistDir)
		if err := os.MkdirAll(persistDir, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(certificateDirname); err != nil {
		log.Printf("Create %s\n", certificateDirname)
		if err := os.MkdirAll(certificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(objectDownloadDirname); err != nil {
		log.Printf("Create %s\n", objectDownloadDirname)
		if err := os.MkdirAll(objectDownloadDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
}

// create module and object based config/status directories
func createConfigStatusDirs(moduleName string, objTypes []string) {

	jobDirs := []string{"config", "status"}
	zedBaseDirs := []string{zedBaseDirname, zedRunDirname}
	baseDirs := make([]string, len(zedBaseDirs))

	log.Printf("Creating config/status dirs for %s\n", moduleName)

	for idx, dir := range zedBaseDirs {
		baseDirs[idx] = dir + "/" + moduleName
	}

	for idx, baseDir := range baseDirs {

		dirName := baseDir + "/" + jobDirs[idx]
		if _, err := os.Stat(dirName); err != nil {
			log.Printf("Create %s\n", dirName)
			if err := os.MkdirAll(dirName, 0700); err != nil {
				log.Fatal(err)
			}
		}

		// Creating Object based holder dirs
		for _, objType := range objTypes {
			dirName := baseDir + "/" + objType + "/" + jobDirs[idx]
			if _, err := os.Stat(dirName); err != nil {
				log.Printf("Create %s\n", dirName)
				if err := os.MkdirAll(dirName, 0700); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

// app instance event watch to capture transitions
// and publish to zedCloud

func handleAppInstanceStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := cast.CastAppInstanceStatus(statusArg)
	if status.Key() != key {
		log.Printf("handleAppInstanceStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishAppInfoToZedCloud(uuidStr, &status, ctx.assignableAdapters,
		ctx.iteration)
	ctx.iteration += 1
}

func handleAppInstanceStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	uuidStr := key
	PublishAppInfoToZedCloud(uuidStr, nil, ctx.assignableAdapters,
		ctx.iteration)
	ctx.iteration += 1
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Printf("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Printf("handleDNSModify for %s\n", key)
	deviceNetworkStatus = status
	// Did we (re-)gain the first usable address?
	// XXX should we also trigger if the count increases?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)
	if newAddrCount != 0 && ctx.usableAddressCount == 0 {
		log.Printf("DeviceNetworkStatus from %d to %d addresses\n",
			newAddrCount, ctx.usableAddressCount)
		ctx.triggerGetConfig = true
	}
	ctx.usableAddressCount = newAddrCount
	log.Printf("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*DNSContext)

	if key != "global" {
		log.Printf("handleDNSDelete: ignoring %s\n", key)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)
	ctx.usableAddressCount = newAddrCount
	log.Printf("handleDNSDelete done for %s\n", key)
}

// base os config/status event handlers
// base os config create event
func handleBaseOsCreate(ctxArg interface{}, statusFilename string,
	configArg interface{}) {
	config := cast.CastBaseOsConfig(configArg)
	// XXX change once key arg
	key := config.Key()
	if config.Key() != key {
		log.Printf("handleBaseOsCreate key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	uuidStr := config.Key()
	ctx := ctxArg.(*zedagentContext)

	log.Printf("handleBaseOsCreate for %s\n", uuidStr)
	addOrUpdateBaseOsConfig(ctx, uuidStr, config)
	publishDeviceInfo = true
}

// base os config modify event
func handleBaseOsModify(ctxArg interface{}, statusFilename string,
	configArg interface{}, statusArg interface{}) {
	config := cast.CastBaseOsConfig(configArg)
	// XXX change once key arg
	key := config.Key()
	if config.Key() != key {
		log.Printf("handleBaseOsModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	status := cast.CastBaseOsStatus(statusArg)
	if status.Key() != key {
		log.Printf("handleBaseOsModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	uuidStr := config.Key()
	ctx := ctxArg.(*zedagentContext)

	log.Printf("handleBaseOsModify for %s\n", status.BaseOsVersion)
	if config.UUIDandVersion.Version == status.UUIDandVersion.Version &&
		config.Activate == status.Activated {
		log.Printf("Same version %v for %s\n",
			config.UUIDandVersion.Version, uuidStr)
		return
	}

	// update the version field, uuis being the same
	status.UUIDandVersion = config.UUIDandVersion
	baseOsStatusSet(uuidStr, &status)
	writeBaseOsStatus(&status, uuidStr)

	addOrUpdateBaseOsConfig(ctx, uuidStr, config)
	publishDeviceInfo = true
}

// base os config delete event
func handleBaseOsDelete(ctxArg interface{}, statusFilename string,
	configArg interface{}) {
	status := configArg.(*types.BaseOsStatus)
	// XXX change once key arg
	key := status.Key()
	if status.Key() != key {
		log.Printf("handleBaseOsDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)

	log.Printf("handleBaseOsDelete for %s\n", status.BaseOsVersion)
	removeBaseOsConfig(ctx, status.Key())
	publishDeviceInfo = true
}

// Wrappers around handleCertObjCreate/Modify/Delete

func handleCertObjConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	config := cast.CastCertObjConfig(configArg)
	if config.Key() != key {
		log.Printf("handleCertObjConfigModify key/UUID mismatch %s vs %s; ignored %+v\n", key, config.Key(), config)
		return
	}
	status := lookupCertObjStatus(ctx, key)
	if status == nil {
		handleCertObjCreate(ctx, key, &config)
	} else {
		handleCertObjModify(ctx, key, &config, status)
	}
	log.Printf("handleCertObjConfigModify(%s) done\n", key)
}

func handleCertObjConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Printf("handleCertObjConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := lookupCertObjStatus(ctx, key)
	if status == nil {
		log.Printf("handleCertObjConfigDelete: unknown %s\n", key)
		return
	}
	handleCertObjDelete(ctx, key, status)
	log.Printf("handleCertObjConfigDelete(%s) done\n", key)
}

// certificate config/status event handlers
// certificate config create event
func handleCertObjCreate(ctx *zedagentContext, key string, config *types.CertObjConfig) {

	uuidStr := config.Key()
	log.Printf("handleCertObjCreate for %s\n", uuidStr)
	addOrUpdateCertObjConfig(ctx, uuidStr, *config)
}

// certificate config modify event
func handleCertObjModify(ctx *zedagentContext, key string, config *types.CertObjConfig, status *types.CertObjStatus) {

	uuidStr := config.Key()
	log.Printf("handleCertObjModify for %s\n", uuidStr)

	// XXX:FIXME, do we
	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Printf("Same version %v for %s\n",
			config.UUIDandVersion.Version, key)
		return
	}

	status.UUIDandVersion = config.UUIDandVersion
	publishCertObjStatus(ctx, status, uuidStr)
	addOrUpdateCertObjConfig(ctx, uuidStr, *config)
}

// certificate config delete event
func handleCertObjDelete(ctx *zedagentContext, key string,
	status *types.CertObjStatus) {

	uuidStr := status.Key()
	log.Printf("handleCertObjDelete for %s\n", uuidStr)
	removeCertObjConfig(ctx, uuidStr)
}

func publishCertObjStatus(ctx *zedagentContext,
	config *types.CertObjStatus, uuidStr string) {

	key := uuidStr // XXX vs. config.Key()?
	log.Printf("publishCertObjStatus(%s) key %s\n", uuidStr, config.Key())
	pub := ctx.pubCertObjStatus
	pub.Publish(key, config)
}

func unpublishCertObjStatus(ctx *zedagentContext, uuidStr string) {

	key := uuidStr
	log.Printf("removeCertObjStatus(%s)\n", key)
	pub := ctx.pubCertObjStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Printf("removeCertObjStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

// base os download status change event
func handleBaseOsDownloadStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {

	status := cast.CastDownloaderStatus(statusArg)
	// XXX change once key arg
	key := status.Key()
	if status.Key() != key {
		log.Printf("handleBaseOsDownloadStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleBaseOsDownloadStatusModify for %s\n",
		status.Safename)
	updateDownloaderStatus(ctx, baseOsObj, &status)
}

// base os download status delete event
func handleBaseOsDownloadStatusDelete(ctxArg interface{}, statusFilename string) {

	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleBaseOsDownloadStatusDelete for %s\n", statusFilename)
	removeDownloaderStatus(ctx, baseOsObj, statusFilename)
}

// base os verification status change event
func handleBaseOsVerifierStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	// XXX change once key arg
	key := status.Key()
	if status.Key() != key {
		log.Printf("handleBaseOsVerifierStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleBaseOsVeriferStatusModify for %s\n",
		status.Safename)
	updateVerifierStatus(ctx, baseOsObj, &status)
}

// base os verification status delete event
func handleBaseOsVerifierStatusDelete(ctxArg interface{}, statusFilename string) {

	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleBaseOsVeriferStatusDelete for %s\n", statusFilename)
	removeVerifierStatus(ctx, baseOsObj, statusFilename)
}

// app img verification status change event; for disk usage tracking
func handleAppImgVerifierStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	// XXX change once key arg
	key := status.Key()
	if status.Key() != key {
		log.Printf("handleAppImgVerifierStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleAppImgVeriferStatusModify for %s\n",
		status.Safename)
	updateVerifierStatus(ctx, appImgObj, &status)
}

// base os verification status delete event
func handleAppImgVerifierStatusDelete(ctxArg interface{}, statusFilename string) {

	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleAppImgVeriferStatusDelete for %s\n", statusFilename)
	removeVerifierStatus(ctx, appImgObj, statusFilename)
}

// cerificate download status change event
func handleCertObjDownloadStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := cast.CastDownloaderStatus(statusArg)
	// XXX change once key arg
	key := status.Key()
	if status.Key() != key {
		log.Printf("handleCertObjDownloadStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleCertObjDownloadStatusModify for %s\n",
		status.Safename)
	updateDownloaderStatus(ctx, certObj, &status)
}

// cerificate download status delete event
func handleCertObjDownloadStatusDelete(ctxArg interface{}, statusFilename string) {

	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleCertObjDownloadStatusDelete for %s\n", statusFilename)
	removeDownloaderStatus(ctx, certObj, statusFilename)
}
