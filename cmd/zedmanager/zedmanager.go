// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Get AppInstanceConfig from zedagent, drive config to Downloader, Verifier,
// IdentityMgr, and Zedrouter. Collect status from those services and make
// the combined AppInstanceStatus available to zedagent.
//
// This reads AppInstanceConfig from /var/tmp/zedmanager/config/*.json and
// produces AppInstanceStatus in /var/run/zedmanager/status/*.json.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"io/ioutil"
	"log"
	"os"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	appImgObj  = "appImg.obj"
	certObj    = "cert.obj"
	agentName  = "zedmanager"
	moduleName = agentName

	baseDirname              = "/var/tmp/" + agentName
	runDirname               = "/var/run/" + agentName
	zedmanagerConfigDirname  = baseDirname + "/config"
	zedmanagerStatusDirname  = runDirname + "/status"
	verifierConfigDirname    = "/var/tmp/verifier/config"
	downloaderConfigDirname  = "/var/tmp/downloader/config"
	domainmgrConfigDirname   = "/var/tmp/domainmgr/config"
	zedrouterConfigDirname   = "/var/tmp/zedrouter/config"
	identitymgrConfigDirname = "/var/tmp/identitymgr/config"
	DNSDirname               = "/var/run/zedrouter/DeviceNetworkStatus"
	certificateDirname       = persistDir + "/certs"

	downloaderAppImgObjConfigDirname = "/var/tmp/downloader/" + appImgObj + "/config"
	verifierAppImgObjConfigDirname   = "/var/tmp/verifier/" + appImgObj + "/config"
)

// Set from Makefile
var Version = "No version specified"

// Dummy since we don't have anything to pass to DNS
type dummyContext struct {
}

// State used by handlers
type zedmanagerContext struct {
	configRestarted   bool
	verifierRestarted bool
}

var deviceNetworkStatus types.DeviceNetworkStatus

var debug = false

func main() {
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
	watch.CleanupRestarted(agentName)
	// XXX either we don't need this, or we need it for each objType
	watch.CleanupRestart("downloader")
	// XXX either we don't need this, or we need it for each objType
	watch.CleanupRestart("verifier")
	watch.CleanupRestart("identitymgr")
	watch.CleanupRestart("zedrouter")
	watch.CleanupRestart("domainmgr")
	watch.CleanupRestart("zedagent")

	verifierStatusDirname := "/var/run/verifier/status"
	downloaderStatusDirname := "/var/run/downloader/status"
	domainmgrStatusDirname := "/var/run/domainmgr/status"
	zedrouterStatusDirname := "/var/run/zedrouter/status"
	identitymgrStatusDirname := "/var/run/identitymgr/status"

	downloaderAppImgObjStatusDirname := "/var/run/downloader/" + appImgObj + "/status"
	verifierAppImgObjStatusDirname := "/var/run/verifier/" + appImgObj + "/status"
	zedagentCertObjStatusDirname := "/var/run/zedagent/" + certObj + "/status"

	dirs := []string{
		zedmanagerConfigDirname,
		zedmanagerStatusDirname,
		identitymgrConfigDirname,
		zedrouterConfigDirname,
		domainmgrConfigDirname,
		downloaderConfigDirname,
		downloaderAppImgObjConfigDirname,
		verifierConfigDirname,
		verifierAppImgObjConfigDirname,
		identitymgrStatusDirname,
		zedrouterStatusDirname,
		domainmgrStatusDirname,
		downloaderAppImgObjStatusDirname,
		downloaderStatusDirname,
		verifierAppImgObjStatusDirname,
		verifierStatusDirname,
		zedagentCertObjStatusDirname,
	}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			if err := os.MkdirAll(dir, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}

	// Tell ourselves to go ahead
	watch.SignalRestart(agentName)

	// Any state needed by handler functions
	ctx := zedmanagerContext{}

	verifierChanges := make(chan string)
	go watch.WatchStatus(verifierAppImgObjStatusDirname, verifierChanges)
	downloaderChanges := make(chan string)
	go watch.WatchStatus(downloaderAppImgObjStatusDirname, downloaderChanges)
	identitymgrChanges := make(chan string)
	go watch.WatchStatus(identitymgrStatusDirname, identitymgrChanges)
	zedrouterChanges := make(chan string)
	go watch.WatchStatus(zedrouterStatusDirname, zedrouterChanges)
	domainmgrChanges := make(chan string)
	go watch.WatchStatus(domainmgrStatusDirname, domainmgrChanges)
	configChanges := make(chan string)
	go watch.WatchConfigStatus(zedmanagerConfigDirname,
		zedmanagerStatusDirname, configChanges)
	networkStatusChanges := make(chan string)
	go watch.WatchStatus(DNSDirname, networkStatusChanges)
	zedagentCertObjStatusChanges := make(chan string)
	go watch.WatchStatus(zedagentCertObjStatusDirname,
		zedagentCertObjStatusChanges)

	var configRestartFn watch.ConfigRestartHandler = handleConfigRestart
	var verifierRestartedFn watch.StatusRestartHandler = handleVerifierRestarted
	var identitymgrRestartedFn watch.StatusRestartHandler = handleIdentitymgrRestarted
	var zedrouterRestartedFn watch.StatusRestartHandler = handleZedrouterRestarted

	// First we process the verifierStatus to avoid downloading
	// an image we already have in place.
	log.Printf("Handling initial verifier Status\n")
	done := false
	for !done {
		select {
		case change := <-verifierChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					verifierAppImgObjStatusDirname,
					&types.VerifyImageStatus{},
					handleVerifyImageStatusModify,
					handleVerifyImageStatusDelete,
					&verifierRestartedFn)
				if ctx.verifierRestarted {
					log.Printf("Verifier reported restarted\n")
					done = true
					break
				}
			}
		}
	}

	log.Printf("Handling all inputs\n")
	for {
		select {
		// handle cert ObjectsChanges
		case change := <-zedagentCertObjStatusChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					zedagentCertObjStatusDirname,
					&types.CertObjStatus{},
					handleCertObjStatusModify,
					handleCertObjStatusDelete, nil)
			}
		case change := <-downloaderChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					downloaderAppImgObjStatusDirname,
					&types.DownloaderStatus{},
					handleDownloaderStatusModify,
					handleDownloaderStatusDelete, nil)
			}
		case change := <-verifierChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					verifierAppImgObjStatusDirname,
					&types.VerifyImageStatus{},
					handleVerifyImageStatusModify,
					handleVerifyImageStatusDelete,
					&verifierRestartedFn)
			}
		case change := <-identitymgrChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					identitymgrStatusDirname,
					&types.EIDStatus{},
					handleEIDStatusModify,
					handleEIDStatusDelete,
					&identitymgrRestartedFn)
			}
		case change := <-zedrouterChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					zedrouterStatusDirname,
					&types.AppNetworkStatus{},
					handleAppNetworkStatusModify,
					handleAppNetworkStatusDelete,
					&zedrouterRestartedFn)
			}
		case change := <-domainmgrChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					domainmgrStatusDirname,
					&types.DomainStatus{},
					handleDomainStatusModify,
					handleDomainStatusDelete, nil)
			}
		case change := <-configChanges:
			{
				watch.HandleConfigStatusEvent(change, &ctx,
					zedmanagerConfigDirname,
					zedmanagerStatusDirname,
					&types.AppInstanceConfig{},
					&types.AppInstanceStatus{},
					handleCreate, handleModify,
					handleDelete, &configRestartFn)
			}
		case change := <-networkStatusChanges:
			{
				watch.HandleStatusEvent(change, dummyContext{},
					DNSDirname,
					&types.DeviceNetworkStatus{},
					handleDNSModify, handleDNSDelete,
					nil)
			}
		}
	}
}

// Propagate a seqence of restart/restarted from the zedmanager config
// and verifier status to identitymgr, then from identitymgr to zedrouter,
// and finally from zedrouter to domainmgr.
// This removes the need for extra downloads/verifications and extra copying
// of the rootfs in domainmgr.
func handleConfigRestart(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Printf("handleConfigRestart(%v)\n", done)
	if done {
		ctx.configRestarted = true
		if ctx.verifierRestarted {
			watch.SignalRestart("identitymgr")
		}
	}
}

func handleVerifierRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Printf("handleVerifierRestarted(%v)\n", done)
	if done {
		ctx.verifierRestarted = true
		if ctx.configRestarted {
			watch.SignalRestart("identitymgr")
		}
	}
}

func handleIdentitymgrRestarted(ctxArg interface{}, done bool) {
	log.Printf("handleIdentitymgrRestarted(%v)\n", done)
	if done {
		watch.SignalRestart("zedrouter")
	}
}

func handleZedrouterRestarted(ctxArg interface{}, done bool) {
	log.Printf("handleZedrouterRestarted(%v)\n", done)
	if done {
		watch.SignalRestart("domainmgr")
	}
}

func writeAICStatus(status *types.AppInstanceStatus,
	statusFilename string) {
	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal AppInstanceStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func writeAppInstanceStatus(status *types.AppInstanceStatus,
	statusFilename string) {
	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal AppInstanceStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func handleCreate(ctxArg interface{}, statusFilename string,
	configArg interface{}) {
	config := configArg.(*types.AppInstanceConfig)

	log.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	addOrUpdateConfig(config.UUIDandVersion.UUID.String(), *config)

	// Note that the status is written as we handle updates from the
	// other services
	log.Printf("handleCreate done for %s\n", config.DisplayName)
}

func handleModify(ctxArg interface{}, statusFilename string,
	configArg interface{}, statusArg interface{}) {
	config := configArg.(*types.AppInstanceConfig)
	status := statusArg.(*types.AppInstanceStatus)
	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, statusFilename)
		return
	}

	status.UUIDandVersion = config.UUIDandVersion
	writeAppInstanceStatus(status, statusFilename)

	addOrUpdateConfig(config.UUIDandVersion.UUID.String(), *config)
	// Note that the status is written as we handle updates from the
	// other services
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.AppInstanceStatus)
	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	writeAppInstanceStatus(status, statusFilename)

	removeConfig(status.UUIDandVersion.UUID.String())
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}

func handleDNSModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.DeviceNetworkStatus)

	if statusFilename != "global" {
		if debug {
			log.Printf("handleDNSModify: ignoring %s\n",
				statusFilename)
		}
		return
	}
	log.Printf("handleDNSModify for %s\n", statusFilename)
	deviceNetworkStatus = *status
	log.Printf("handleDNSModify done for %s\n", statusFilename)
}

func handleDNSDelete(ctxArg interface{}, statusFilename string) {
	log.Printf("handleDNSDelete for %s\n", statusFilename)

	if statusFilename != "global" {
		log.Printf("handleDNSDelete: ignoring %s\n", statusFilename)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Printf("handleDNSDelete done for %s\n", statusFilename)
}
