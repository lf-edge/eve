// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Pull AppInstanceConfig from ZedCloud, drive config to Downloader, Verifier,
// IdentityMgr, and Zedrouter. Collect status from those services and push
// combined AppInstanceStatus to ZedCloud.
//
// XXX Note that this initial code reads AppInstanceConfig from
// /var/tmp/zedmanager/config/*.json and produces AppInstanceStatus in
// /var/run/zedmanager/status/*.json.
//
// XXX Should we keep the local config and status dirs and have a separate
// config downloader (which calls the Verifier), and status uploader?

package main

import (
	"encoding/json"
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"io/ioutil"
	"log"
	"os"
)

// Keeping status in /var/run to be clean after a crash/reboot
var (
	baseDirname              = "/var/tmp/zedmanager"
	runDirname               = "/var/run/zedmanager"
	zedmanagerConfigDirname  = baseDirname + "/config"
	zedmanagerStatusDirname  = runDirname + "/status"
	verifierConfigDirname    = "/var/tmp/verifier/config"
	downloaderConfigDirname  = "/var/tmp/downloader/config"
	domainmgrConfigDirname   = "/var/tmp/domainmgr/config"
	zedrouterConfigDirname   = "/var/tmp/zedrouter/config"
	identitymgrConfigDirname = "/var/tmp/identitymgr/config"
)

func main() {
	log.Printf("Starting zedmanager\n")
	watch.CleanupRestarted("zedmanager")
	watch.CleanupRestart("downloader")
	watch.CleanupRestart("verifier")
	watch.CleanupRestart("identitymgr")
	watch.CleanupRestart("zedrouter")
	watch.CleanupRestart("domainmgr")

	verifierStatusDirname := "/var/run/verifier/status"
	downloaderStatusDirname := "/var/run/downloader/status"
	domainmgrStatusDirname := "/var/run/domainmgr/status"
	zedrouterStatusDirname := "/var/run/zedrouter/status"
	identitymgrStatusDirname := "/var/run/identitymgr/status"

	dirs := []string{
		zedmanagerConfigDirname,
		zedmanagerStatusDirname,
		identitymgrConfigDirname,
		zedrouterConfigDirname,
		domainmgrConfigDirname,
		downloaderConfigDirname,
		verifierConfigDirname,
		identitymgrStatusDirname,
		zedrouterStatusDirname,
		domainmgrStatusDirname,
		downloaderStatusDirname,
		verifierStatusDirname,
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			if err := os.MkdirAll(dir, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}

	// Tell ourselves to go ahead
	watch.SignalRestart("zedmanager")
	
	verifierChanges := make(chan string)
	go watch.WatchStatus(verifierStatusDirname, verifierChanges)
	downloaderChanges := make(chan string)
	go watch.WatchStatus(downloaderStatusDirname, downloaderChanges)
	identitymgrChanges := make(chan string)
	go watch.WatchStatus(identitymgrStatusDirname, identitymgrChanges)
	zedrouterChanges := make(chan string)
	go watch.WatchStatus(zedrouterStatusDirname, zedrouterChanges)
	domainmgrChanges := make(chan string)
	go watch.WatchStatus(domainmgrStatusDirname, domainmgrChanges)
	// XXX replace this with a handleVerifierRestarted function, which
	// kicks identitymgr, which kicks zedrouter, which kicks domainmgr.
	// XXX as we process config we might start downloads; should defer
	// that until the verifier has restarted hence wait inline.
	// Wait for the verifier to report initial status to avoid downloading
	// a file which is already downloaded
	waitFile := "/var/run/verifier/status/restarted"
	log.Printf("Waiting for verifier to report in %s\n", waitFile)
	watch.WaitForFile(waitFile)
	log.Printf("Verifier reported in %s\n", waitFile)

	var configRestartFn watch.ConfigRestartHandler = handleConfigRestart
	var verifierRestartedFn watch.StatusRestartHandler = handleVerifierRestarted
	var identitymgrRestartedFn watch.StatusRestartHandler = handleIdentitymgrRestarted
	var zedrouterRestartedFn watch.StatusRestartHandler = handleZedrouterRestarted

	getCloudUrls ()
	go metricsTimerTask()
	go configTimerTask()

	configChanges := make(chan string)
	go watch.WatchConfigStatus(zedmanagerConfigDirname,
		zedmanagerStatusDirname, configChanges)
	for {
		select {
		case change := <-downloaderChanges:
			{
				watch.HandleStatusEvent(change,
					downloaderStatusDirname,
					&types.DownloaderStatus{},
					handleDownloaderStatusModify,
					handleDownloaderStatusDelete, nil)
				continue
			}
		case change := <-verifierChanges:
			{
				watch.HandleStatusEvent(change,
					verifierStatusDirname,
					&types.VerifyImageStatus{},
					handleVerifyImageStatusModify,
					handleVerifyImageStatusDelete,
					&verifierRestartedFn)
				continue
			}
		case change := <-identitymgrChanges:
			{
				watch.HandleStatusEvent(change,
					identitymgrStatusDirname,
					&types.EIDStatus{},
					handleEIDStatusModify,
					handleEIDStatusDelete,
					&identitymgrRestartedFn)
				continue
			}
		case change := <-zedrouterChanges:
			{
				watch.HandleStatusEvent(change,
					zedrouterStatusDirname,
					&types.AppNetworkStatus{},
					handleAppNetworkStatusModify,
					handleAppNetworkStatusDelete,
					&zedrouterRestartedFn)
				continue
			}
		case change := <-domainmgrChanges:
			{
				watch.HandleStatusEvent(change,
					domainmgrStatusDirname,
					&types.DomainStatus{},
					handleDomainStatusModify,
					handleDomainStatusDelete, nil)
				continue
			}
		case change := <-configChanges:
			{
				watch.HandleConfigStatusEvent(change,
					zedmanagerConfigDirname,
					zedmanagerStatusDirname,
					&types.AppInstanceConfig{},
					&types.AppInstanceStatus{},
					handleCreate, handleModify,
					handleDelete, &configRestartFn)
				continue
			}
		}
	}
}

var configRestarted = false
var verifierRestarted = false

// Propagate a seqence of restart//restarted from the zedmanager config
// and verifier status to identitymgr, then from identitymgr to zedrouter,
// and finally from zedrouter to domainmgr.
// This removes the need for extra downloads/verifications and extra copying
// of the rootfs in domainmgr.
func handleConfigRestart(done bool) {
	log.Printf("handleConfigRestart(%v)\n", done)
	if done {
		configRestarted = true
		if verifierRestarted {
			watch.SignalRestart("identitymgr")
		}
	}
}

func handleVerifierRestarted(done bool) {
	log.Printf("handleVerifierRestarted(%v)\n", done)
	if done {
		verifierRestarted = true
		if configRestarted {
			watch.SignalRestart("identitymgr")
		}
	}
}

func handleIdentitymgrRestarted(done bool) {
	log.Printf("handleIdentitymgrRestarted(%v)\n", done)
	if done {
		watch.SignalRestart("zedrouter")
	}
}

func handleZedrouterRestarted(done bool) {
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
	publishAiInfoToCloud(status)
}

func handleCreate(statusFilename string, configArg interface{}) {
	var config *types.AppInstanceConfig

	switch configArg.(type) {
	default:
		log.Fatal("Can only handle AppInstanceConfig")
	case *types.AppInstanceConfig:
		config = configArg.(*types.AppInstanceConfig)
	}
	log.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	addOrUpdateConfig(config.UUIDandVersion.UUID.String(), *config)

	// Note that the status is written as we handle updates from the
	// other services
	log.Printf("handleCreate done for %s\n", config.DisplayName)
}

func handleModify(statusFilename string, configArg interface{},
	statusArg interface{}) {
	var config *types.AppInstanceConfig
	var status *types.AppInstanceStatus

	switch configArg.(type) {
	default:
		log.Fatal("Can only handle AppInstanceConfig")
	case *types.AppInstanceConfig:
		config = configArg.(*types.AppInstanceConfig)
	}
	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle AppInstanceStatus")
	case *types.AppInstanceStatus:
		status = statusArg.(*types.AppInstanceStatus)
	}
	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		fmt.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, statusFilename)
		return
	}

	status.PendingModify = true
	status.UUIDandVersion = config.UUIDandVersion
	writeAppInstanceStatus(status, statusFilename)

	addOrUpdateConfig(config.UUIDandVersion.UUID.String(), *config)
	// Note that the status is written as we handle updates from the
	// other services
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(statusFilename string, statusArg interface{}) {
	var status *types.AppInstanceStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle AppInstanceStatus")
	case *types.AppInstanceStatus:
		status = statusArg.(*types.AppInstanceStatus)
	}
	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	status.PendingDelete = true
	writeAppInstanceStatus(status, statusFilename)

	removeConfig(status.UUIDandVersion.UUID.String())
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}
