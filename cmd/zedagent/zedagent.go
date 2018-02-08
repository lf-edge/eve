// Copyright (c) 2017 Zededa, Inc.
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

package main

import (
	"flag"
	"fmt"
	"github.com/zededa/go-provision/assignableadapters"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"log"
	"os"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	appImgObj = "appImg.obj"
	baseOsObj = "baseOs.obj"
	certObj   = "cert.obj"

	downloaderModulename = "downloader"
	verifierModulename   = "verifier"
	zedagentModulename   = "zedagent"
	zedmanagerModulename = "zedmanager"

	moduleName     = "zedagent"
	zedBaseDirname = "/var/tmp"
	zedRunDirname  = "/var/run"
	baseDirname    = zedBaseDirname + "/" + moduleName
	runDirname     = zedRunDirname + "/" + moduleName

	certsDirname          = "/var/tmp/zedmanager/certs"
	persistDir            = "/persist"
	objectDownloadDirname = persistDir + "/downloads"

	downloaderBaseDirname = zedBaseDirname + "/" + downloaderModulename
	downloaderRunDirname  = zedRunDirname + "/" + downloaderModulename

	verifierBaseDirname = zedBaseDirname + "/" + verifierModulename
	verifierRunDirname  = zedRunDirname + "/" + verifierModulename

	zedagentConfigDirname = baseDirname + "/config"
	zedagentStatusDirname = runDirname + "/status"

	zedmanagerConfigDirname = zedBaseDirname + "/" + zedmanagerModulename + "/config"
	zedmanagerStatusDirname = zedRunDirname + "/" + zedmanagerModulename + "/status"

	// base os config/status holder
	zedagentBaseOsConfigDirname = baseDirname + "/" + baseOsObj + "/config"
	zedagentBaseOsStatusDirname = runDirname + "/" + baseOsObj + "/status"

	// certificate config/status holder
	zedagentCertObjConfigDirname = baseDirname + "/" + certObj + "/config"
	zedagentCertObjStatusDirname = runDirname + "/" + certObj + "/status"

	// base os download config/status holder
	downloaderBaseOsStatusDirname  = downloaderRunDirname + "/" + baseOsObj + "/status"
	downloaderCertObjStatusDirname = downloaderRunDirname + "/" + certObj + "/status"

	// base os verifier status holder
	verifierBaseOsConfigDirname = verifierBaseDirname + "/" + baseOsObj + "/config"
	verifierBaseOsStatusDirname = verifierRunDirname + "/" + baseOsObj + "/status"
	DNSDirname                  = "/var/run/zedrouter/DeviceNetworkStatus"
	domainStatusDirname         = "/var/run/domainmgr/status"
)

// Set from Makefile
var Version = "No version specified"

var deviceNetworkStatus types.DeviceNetworkStatus

// Dummy used when we don't have anything to pass
type dummyContext struct {
}

// Information from handleVerifierRestarted
type verifierContext struct {
	verifierRestarted bool
}

// Information for handleAppInstanceStatus*
type appInstanceContext struct {
	publishIteration int
}

// Information for handleBaseOsCreate/Modify/Delete
type deviceContext struct {
	assignableAdapters *types.AssignableAdapters
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	versionPtr := flag.Bool("v", false, "Version")
	flag.Parse()
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	log.Printf("Starting zedagent\n")
	watch.CleanupRestarted("zedagent")

	// Tell ourselves to go ahead
	// initialize the module specifig stuff
	handleInit()

	watch.SignalRestart("zedagent")
	var restartFn watch.StatusRestartHandler = handleRestart

	restartChanges := make(chan string)
	appInstanceStatusChanges := make(chan string)
	baseOsConfigStatusChanges := make(chan string)
	baseOsDownloaderChanges := make(chan string)
	baseOsVerifierChanges := make(chan string)
	certObjConfigStatusChanges := make(chan string)
	certObjDownloaderChanges := make(chan string)

	var verifierRestartedFn watch.StatusRestartHandler = handleVerifierRestarted

	// baseOs verification status watcher
	go watch.WatchStatus(verifierBaseOsStatusDirname,
		baseOsVerifierChanges)

	// Pick up (mostly static) AssignableAdapters before we report
	// any device info
	model := hardware.GetHardwareModel()
	aa := types.AssignableAdapters{}
	aaChanges, aaFunc, aaCtx := assignableadapters.Init(&aa, model)
	aaDone := false

	verifierCtx := verifierContext{}
	aiCtx := appInstanceContext{}
	devCtx := deviceContext{assignableAdapters: &aa}

	// First we process the verifierStatus to avoid downloading
	// an base image we already have in place
	log.Printf("Handling initial verifier Status\n")
	done := false
	for !done {
		select {
		case change := <-baseOsVerifierChanges:
			watch.HandleStatusEvent(change, &verifierCtx,
				verifierBaseOsStatusDirname,
				&types.VerifyImageStatus{},
				handleBaseOsVerifierStatusModify,
				handleBaseOsVerifierStatusDelete,
				&verifierRestartedFn)
			if verifierCtx.verifierRestarted {
				log.Printf("Verifier reported restarted\n")
				done = true
				break
			}
		case change := <-aaChanges:
			aaFunc(&aaCtx, change)
			aaDone = true
		}
	}

	deviceStatusChanges := make(chan string)
	go watch.WatchStatus(DNSDirname, deviceStatusChanges)

	waited := false
	// Wait to have some uplinks with usable addresses
	for types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus) == 0 ||
		!aaDone {
		waited = true
		select {
		case change := <-deviceStatusChanges:
			watch.HandleStatusEvent(change, dummyContext{},
				DNSDirname,
				&types.DeviceNetworkStatus{},
				handleDNSModify, handleDNSDelete,
				nil)
		case change := <-aaChanges:
			aaFunc(&aaCtx, change)
			aaDone = true
		}
	}
	fmt.Printf("Have %d uplinks addresses to use\n",
		types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus))
	if waited {
		// Inform ledmanager that we have uplink addresses
		types.UpdateLedManagerConfig(2)
	}

	// Publish initial device info. Retries all addresses on all uplinks.
	PublishDeviceInfoToZedCloud(baseOsStatusMap, devCtx.assignableAdapters)

	// start the metrics/config fetch tasks
	go metricsTimerTask()
	go configTimerTask()

	// app instance status event watcher
	go watch.WatchStatus(zedmanagerStatusDirname, appInstanceStatusChanges)

	// base os config/status event handler
	go watch.WatchConfigStatus(zedagentBaseOsConfigDirname,
		zedagentBaseOsStatusDirname, baseOsConfigStatusChanges)

	// cert object config/status event handler
	go watch.WatchConfigStatus(zedagentCertObjConfigDirname,
		zedagentCertObjStatusDirname, certObjConfigStatusChanges)

	// baseOs download status watcher
	go watch.WatchStatus(downloaderBaseOsStatusDirname,
		baseOsDownloaderChanges)

	// certificate download status watcher
	go watch.WatchStatus(downloaderCertObjStatusDirname,
		certObjDownloaderChanges)

	// for restart flag handling
	go watch.WatchStatus(zedagentStatusDirname, restartChanges)

	domainStatusChanges := make(chan string)
	go watch.WatchStatus(domainStatusDirname, domainStatusChanges)
	for {
		select {

		case change := <-restartChanges:
			// restart only, place holder
			watch.HandleStatusEvent(change, &aiCtx,
				zedagentStatusDirname,
				&types.AppInstanceStatus{},
				handleAppInstanceStatusModify,
				handleAppInstanceStatusDelete, &restartFn)

		case change := <-appInstanceStatusChanges:
			go watch.HandleStatusEvent(change, &aiCtx,
				zedmanagerStatusDirname,
				&types.AppInstanceStatus{},
				handleAppInstanceStatusModify,
				handleAppInstanceStatusDelete, nil)

		case change := <-baseOsConfigStatusChanges:
			go watch.HandleConfigStatusEvent(change, &devCtx,
				zedagentBaseOsConfigDirname,
				zedagentBaseOsStatusDirname,
				&types.BaseOsConfig{},
				&types.BaseOsStatus{},
				handleBaseOsCreate,
				handleBaseOsModify,
				handleBaseOsDelete, nil)

		case change := <-certObjConfigStatusChanges:
			go watch.HandleConfigStatusEvent(change, dummyContext{},
				zedagentCertObjConfigDirname,
				zedagentCertObjStatusDirname,
				&types.CertObjConfig{},
				&types.CertObjStatus{},
				handleCertObjCreate,
				handleCertObjModify,
				handleCertObjDelete, nil)

		case change := <-baseOsDownloaderChanges:
			go watch.HandleStatusEvent(change, dummyContext{},
				downloaderBaseOsStatusDirname,
				&types.DownloaderStatus{},
				handleBaseOsDownloadStatusModify,
				handleBaseOsDownloadStatusDelete, nil)

		case change := <-baseOsVerifierChanges:
			go watch.HandleStatusEvent(change, dummyContext{},
				verifierBaseOsStatusDirname,
				&types.VerifyImageStatus{},
				handleBaseOsVerifierStatusModify,
				handleBaseOsVerifierStatusDelete, nil)

		case change := <-certObjDownloaderChanges:
			go watch.HandleStatusEvent(change, dummyContext{},
				downloaderCertObjStatusDirname,
				&types.DownloaderStatus{},
				handleCertObjDownloadStatusModify,
				handleCertObjDownloadStatusDelete, nil)

		case change := <-deviceStatusChanges:
			watch.HandleStatusEvent(change, dummyContext{},
				DNSDirname,
				&types.DeviceNetworkStatus{},
				handleDNSModify, handleDNSDelete,
				nil)
		case change := <-domainStatusChanges:
			watch.HandleStatusEvent(change, dummyContext{},
				domainStatusDirname,
				&types.DomainStatus{},
				handleDomainStatusModify, handleDomainStatusDelete,
				nil)
		case change := <-aaChanges:
			aaFunc(&aaCtx, change)
		}
	}
}

// signal zedmanager, to restart
// it would take care of orchestrating
// all other module restart
func handleRestart(ctxArg interface{}, done bool) {
	log.Printf("handleRestart(%v)\n", done)
	if done {
		watch.SignalRestart("zedmanager")
	}
}

func handleVerifierRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*verifierContext)
	log.Printf("handleVerifierRestarted(%v)\n", done)
	if done {
		ctx.verifierRestarted = true
	}
}

func handleInit() {

	initializeDirs()
	initMaps()
	getCloudUrls()
}

func initializeDirs() {

	noObjTypes := []string{}
	zedagentObjTypes := []string{baseOsObj, certObj}
	zedagentVerifierObjTypes := []string{baseOsObj}

	// create the module object based config/status dirs
	createConfigStatusDirs(downloaderModulename, zedagentObjTypes)
	createConfigStatusDirs(zedagentModulename, zedagentObjTypes)
	createConfigStatusDirs(zedmanagerModulename, noObjTypes)
	createConfigStatusDirs(verifierModulename, zedagentVerifierObjTypes)
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

func handleAppInstanceStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.AppInstanceStatus)
	ctx := ctxArg.(*appInstanceContext)
	uuidStr := status.UUIDandVersion.UUID.String()
	PublishAppInfoToZedCloud(uuidStr, status, ctx.publishIteration)
	ctx.publishIteration += 1
}

func handleAppInstanceStatusDelete(ctxArg interface{}, statusFilename string) {
	// XXX is statusFilename == key aka UUIDstr?
	// XXX no status - need delete support
	// status := statusArg.(*types.AppInstanceStatus)
	ctx := ctxArg.(*appInstanceContext)
	uuidStr := statusFilename
	PublishAppInfoToZedCloud(uuidStr, nil, ctx.publishIteration)
	ctx.publishIteration += 1
}

func handleDNSModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.DeviceNetworkStatus)

	if statusFilename != "global" {
		fmt.Printf("handleDNSModify: ignoring %s\n", statusFilename)
		return
	}
	log.Printf("handleDNSModify for %s\n", statusFilename)
	deviceNetworkStatus = *status
	log.Printf("handleDNSModify done for %s\n", statusFilename)
}

func handleDNSDelete(ctxArg interface{}, statusFilename string) {
	log.Printf("handleDNSDelete for %s\n", statusFilename)

	if statusFilename != "global" {
		fmt.Printf("handleDNSDelete: ignoring %s\n", statusFilename)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Printf("handleDNSDelete done for %s\n", statusFilename)
}

// base os config/status event handlers
// base os config create event
func handleBaseOsCreate(ctxArg interface{}, statusFilename string,
	configArg interface{}) {
	config := configArg.(*types.BaseOsConfig)
	ctx := ctxArg.(*deviceContext)
	uuidStr := config.UUIDandVersion.UUID.String()

	log.Printf("handleBaseOsCreate for %s\n", uuidStr)
	addOrUpdateBaseOsConfig(uuidStr, *config)
	PublishDeviceInfoToZedCloud(baseOsStatusMap, ctx.assignableAdapters)
}

// base os config modify event
func handleBaseOsModify(ctxArg interface{}, statusFilename string,
	configArg interface{}, statusArg interface{}) {
	config := configArg.(*types.BaseOsConfig)
	status := statusArg.(*types.BaseOsStatus)
	ctx := ctxArg.(*deviceContext)
	uuidStr := config.UUIDandVersion.UUID.String()

	log.Printf("handleBaseOsModify for %s\n", status.BaseOsVersion)
	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, uuidStr)
		return
	}

	// update the version field, uuis being the same
	status.UUIDandVersion = config.UUIDandVersion
	writeBaseOsStatus(status, statusFilename)

	addOrUpdateBaseOsConfig(uuidStr, *config)
	PublishDeviceInfoToZedCloud(baseOsStatusMap, ctx.assignableAdapters)
}

// base os config delete event
func handleBaseOsDelete(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.BaseOsStatus)
	ctx := ctxArg.(*deviceContext)

	log.Printf("handleBaseOsDelete for %s\n", status.BaseOsVersion)
	removeBaseOsConfig(status.UUIDandVersion.UUID.String())
	PublishDeviceInfoToZedCloud(baseOsStatusMap, ctx.assignableAdapters)
}

// certificate config/status event handlers
// certificate config create event
func handleCertObjCreate(ctxArg interface{}, statusFilename string,
	configArg interface{}) {
	config := configArg.(*types.CertObjConfig)
	uuidStr := config.UUIDandVersion.UUID.String()

	log.Printf("handleCertObjCreate for %s\n", uuidStr)
	addOrUpdateCertObjConfig(uuidStr, *config)
}

// certificate config modify event
func handleCertObjModify(ctxArg interface{}, statusFilename string,
	configArg interface{}, statusArg interface{}) {
	config := configArg.(*types.CertObjConfig)
	status := statusArg.(*types.CertObjStatus)
	uuidStr := config.UUIDandVersion.UUID.String()

	log.Printf("handleCertObjModify for %s\n", uuidStr)

	// XXX:FIXME, do we
	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, statusFilename)
		return
	}

	status.UUIDandVersion = config.UUIDandVersion

	writeCertObjStatus(status, statusFilename)
	addOrUpdateCertObjConfig(uuidStr, *config)
}

// certificate config delete event
func handleCertObjDelete(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.CertObjStatus)
	uuidStr := status.UUIDandVersion.UUID.String()

	log.Printf("handleCertObjDelete for %s\n", uuidStr)

	removeCertObjConfig(uuidStr)
}

// base os download status change event
func handleBaseOsDownloadStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.DownloaderStatus)

	log.Printf("handleBaseOsDownloadStatusModify for %s\n",
		status.Safename)
	updateDownloaderStatus(baseOsObj, status)
}

// base os download status delete event
func handleBaseOsDownloadStatusDelete(ctxArg interface{}, statusFilename string) {

	log.Printf("handleBaseOsDownloadStatusDelete for %s\n",
		statusFilename)
	removeDownloaderStatus(baseOsObj, statusFilename)
}

// base os verification status change event
func handleBaseOsVerifierStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.VerifyImageStatus)

	log.Printf("handleBaseOsVeriferStatusModify for %s\n",
		status.Safename)
	updateVerifierStatus(baseOsObj, status)
}

// base os verification status delete event
func handleBaseOsVerifierStatusDelete(ctxArg interface{}, statusFilename string) {

	log.Printf("handleBaseOsVeriferStatusDelete for %s\n",
		statusFilename)
	removeVerifierStatus(baseOsObj, statusFilename)
}

// cerificate download status change event
func handleCertObjDownloadStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.DownloaderStatus)

	log.Printf("handleCertObjDownloadStatusModify for %s\n",
		status.Safename)
	updateDownloaderStatus(certObj, status)
}

// cerificate download status delete event
func handleCertObjDownloadStatusDelete(ctxArg interface{}, statusFilename string) {

	log.Printf("handleCertObjDownloadStatusDelete for %s\n",
		statusFilename)
	removeDownloaderStatus(certObj, statusFilename)
}
