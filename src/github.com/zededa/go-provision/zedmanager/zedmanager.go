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
	"strings"
	"time"
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
	// XXX do we need to wait for the verifier to report initial status?
	// Needed to avoid extra download
	log.Printf("Waiting for verifier to report\n")
	delay := time.Second * 5
	time.Sleep(delay)
	configChanges := make(chan string)
	go watch.WatchConfigStatus(zedmanagerConfigDirname,
		zedmanagerStatusDirname, configChanges)
	for {
		select {
		case change := <-downloaderChanges:
			{
				handleStatusEvent(change, downloaderStatusDirname,
					&types.DownloaderStatus{},
					handleDownloaderStatusModify,
					handleDownloaderStatusDelete)
				continue
			}
		case change := <-verifierChanges:
			{
				handleStatusEvent(change, verifierStatusDirname,
					&types.VerifyImageStatus{},
					handleVerifyImageStatusModify,
					handleVerifyImageStatusDelete)
				continue
			}
		case change := <-identitymgrChanges:
			{
				handleStatusEvent(change, identitymgrStatusDirname,
					&types.EIDStatus{},
					handleEIDStatusModify,
					handleEIDStatusDelete)
				continue
			}
		case change := <-zedrouterChanges:
			{
				handleStatusEvent(change, zedrouterStatusDirname,
					&types.AppNetworkStatus{},
					handleAppNetworkStatusModify,
					handleAppNetworkStatusDelete)
				continue
			}
		case change := <-domainmgrChanges:
			{
				handleStatusEvent(change, domainmgrStatusDirname,
					&types.DomainStatus{},
					handleDomainStatusModify,
					handleDomainStatusDelete)
				continue
			}
		// XXX generalize this code; struct with dirnames and comparator
		case change := <-configChanges:
			{
				handleConfigStatusEvent(change,
					zedmanagerConfigDirname,
					zedmanagerStatusDirname,
					&types.AppInstanceConfig{},
					&types.AppInstanceStatus{},
					handleCreate, handleModify,
					handleDelete)
			}
		}
	}
}

// XXX move to watch? Need watchTypes.go or sufficient to declare types
// with CAPS in watch.go?
type configCreateHandler func(statusFilename string, config interface{})
type configModifyHandler func(statusFilename string, config interface{},
	status interface{})
type configDeleteHandler func(statusFilename string, status interface{})

func handleConfigStatusEvent(change string,
	configDirname string, statusDirname string,
	config types.ZedConfig, status types.ZedStatus,
	handleCreate configCreateHandler, handleModify configModifyHandler,
	handleDelete configDeleteHandler) {

	parts := strings.Split(change, " ")
	operation := parts[0]
	fileName := parts[1]
	if !strings.HasSuffix(fileName, ".json") {
		log.Printf("Ignoring file <%s>\n", fileName)
		return
	}
	if operation == "D" {
		statusFile := statusDirname + "/" + fileName
		if _, err := os.Stat(statusFile); err != nil {
			// File just vanished!
			log.Printf("File disappeared <%s>\n", fileName)
			return
		}
		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			log.Printf("%s for %s\n", err, statusFile)
			return
		}
		if err := json.Unmarshal(sb, status); err != nil {
			log.Printf("%s AppInstanceStatus file: %s\n",
				err, statusFile)
			return
		}
		if !status.VerifyFilename(fileName) {
			return
		}
		statusName := statusDirname + "/" + fileName
		handleDelete(statusName, status)
		return
	}
	if operation != "M" {
		log.Fatal("Unknown operation from Watcher: ",
			operation)
	}
	configFile := configDirname + "/" + fileName
	cb, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Printf("%s for %s\n", err, configFile)
		return
	}
	if err := json.Unmarshal(cb, config); err != nil {
		log.Printf("%s AppInstanceConfig file: %s\n",
			err, configFile)
		return
	}
	if !config.VerifyFilename(fileName) {
		return
	}
	statusFile := statusDirname + "/" + fileName
	if _, err := os.Stat(statusFile); err != nil {
		// File does not exist in status hence new
		statusName := statusDirname + "/" + fileName
		handleCreate(statusName, config)
		return
	}
	// Read and check status
	sb, err := ioutil.ReadFile(statusFile)
	if err != nil {
		log.Printf("%s for %s\n", err, statusFile)
		return
	}
	if err := json.Unmarshal(sb, status); err != nil {
		log.Printf("%s AppInstanceStatus file: %s\n",
			err, statusFile)
		return
	}
	if !status.VerifyFilename(fileName) {
		return
	}
	// XXX make Pending* info functions... and a separate pending* boolean?
	// XXX or leave unchanged?
	// Look for pending* in status and repeat that operation.
	// XXX After that do a full ReadDir to restart ...
	if status.CheckPendingAdd() {
		statusName := statusDirname + "/" + fileName
		handleCreate(statusName, config)
		// XXX set something to rescan?
		return
	}
	if status.CheckPendingDelete() {
		statusName := statusDirname + "/" + fileName
		handleDelete(statusName, status)
		// XXX set something to rescan?
		return
	}
	if status.CheckPendingModify() {
		statusName := statusDirname + "/" + fileName
		handleModify(statusName, config, status)
		// XXX set something to rescan?
		return
	}
	statusName := statusDirname + "/" + fileName
	handleModify(statusName, config, status)
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
	log.Printf("handleUpdate done for %s\n", config.DisplayName)
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

type statusCreateHandler func(statusFilename string, status interface{})
type statusDeleteHandler func(statusFilename string)

func handleStatusEvent(change string, statusDirname string, status interface{},
	statusCreateFunc statusCreateHandler,
	statusDeleteFunc statusDeleteHandler) {
	parts := strings.Split(change, " ")
	operation := parts[0]
	fileName := parts[1]
	if !strings.HasSuffix(fileName, ".json") {
		log.Printf("Ignoring file <%s>\n", fileName)
		return
	}
	// Remove .json from name */
	name := strings.Split(fileName, ".")
	if operation == "D" {
		statusDeleteFunc(name[0])
		return
	}
	if operation != "M" {
		log.Fatal("Unknown operation from Watcher: ",
			operation)
	}
	statusFile := statusDirname + "/" + fileName
	cb, err := ioutil.ReadFile(statusFile)
	if err != nil {
		log.Printf("%s for %s\n", err, statusFile)
		return
	}
	if err := json.Unmarshal(cb, status); err != nil {
		log.Printf("%s file: %s\n",
			err, statusFile)
		return
	}
	statusCreateFunc(name[0], status)
}
