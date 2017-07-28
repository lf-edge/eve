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
)

// Keeping status in /var/run to be clean after a crash/reboot
var (
	baseDirname = "/var/tmp/zedmanager"
	runDirname  = "/var/run/zedmanager"
	zedmanagerConfigDirname = baseDirname + "/config"
	zedmanagerStatusDirname = runDirname + "/status"
	verifierConfigDirname = "/var/tmp/verifier/config"
	downloaderConfigDirname = "/var/tmp/downloader/config"
	xenmgrConfigDirname = "/var/tmp/xenmgr/config"
	zedrouterConfigDirname = "/var/tmp/zedrouter/config"
	identitymgrConfigDirname = "/var/tmp/identitymgr/config"
)

func main() {
	verifierStatusDirname := "/var/run/verifier/status"
	downloaderStatusDirname := "/var/run/downloader/status"
	xenmgrStatusDirname := "/var/run/xenmgr/status"
	zedrouterStatusDirname := "/var/run/zedrouter/status"
	identitymgrStatusDirname := "/var/run/identitymgr/status"

	dirs := []string{
		zedmanagerConfigDirname,
		zedmanagerStatusDirname,
// XXX depends on startup order
// XXX 		"/var/tmp/zedmanager/downloads",
// XXX		"/var/tmp/zedmanager/downloads/pending",
		identitymgrConfigDirname,
		zedrouterConfigDirname,
		xenmgrConfigDirname,
		downloaderConfigDirname,
		verifierConfigDirname,
		identitymgrStatusDirname,
		zedrouterStatusDirname,
		xenmgrStatusDirname,
		downloaderStatusDirname,
		verifierStatusDirname,
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			if err := os.MkdirAll(dir, 0755); err != nil {
				log.Fatal(err)
			}
		}
	}

	configChanges := make(chan string)
	go watch.WatchConfigStatus(zedmanagerConfigDirname,
		zedmanagerStatusDirname, configChanges)
	verifierChanges := make(chan string)
	go watch.WatchStatus(verifierStatusDirname, verifierChanges)
	downloaderChanges := make(chan string)
	go watch.WatchStatus(downloaderStatusDirname, downloaderChanges)
	identitymgrChanges := make(chan string)
	go watch.WatchStatus(identitymgrStatusDirname, identitymgrChanges)
	zedrouterChanges := make(chan string)
	go watch.WatchStatus(zedrouterStatusDirname, zedrouterChanges)
	xenmgrChanges := make(chan string)
	go watch.WatchStatus(xenmgrStatusDirname, xenmgrChanges)

	for {
		select {
		case change := <-downloaderChanges: {
			handleStatusEvent(change, downloaderStatusDirname,
				&types.DownloaderStatus{},
				handleDownloaderStatusModify,
				handleDownloaderStatusDelete)
			continue
		}
		case change := <-verifierChanges: {
			handleStatusEvent(change, verifierStatusDirname,
				&types.VerifyImageStatus{},
				handleVerifyImageStatusModify,
				handleVerifyImageStatusDelete)
			continue
		}
		case change := <-identitymgrChanges: {
			handleStatusEvent(change, identitymgrStatusDirname,
				&types.EIDStatus{},
				handleEIDStatusModify,
				handleEIDStatusDelete)
			continue
		}
		case change := <-zedrouterChanges: {
			handleStatusEvent(change, zedrouterStatusDirname,
				&types.AppNetworkStatus{},
				handleAppNetworkStatusModify,
				handleAppNetworkStatusDelete)
			continue
		}
		case change := <-xenmgrChanges: {
			handleStatusEvent(change, xenmgrStatusDirname,
				&types.DomainStatus{},
				handleDomainStatusModify,
				handleDomainStatusDelete)
			continue
		}
		// XXX generalize this code; struct with dirnames and comparator
		case change := <-configChanges: {
			parts := strings.Split(change, " ")
			operation := parts[0]
			fileName := parts[1]
			if !strings.HasSuffix(fileName, ".json") {
				log.Printf("Ignoring file <%s>\n", fileName)
				continue
			}
			if operation == "D" {
				statusFile := zedmanagerStatusDirname + "/" + fileName
				if _, err := os.Stat(statusFile); err != nil {
					// File just vanished!
					log.Printf("File disappeared <%s>\n", fileName)
					continue
				}
				sb, err := ioutil.ReadFile(statusFile)
				if err != nil {
					log.Printf("%s for %s\n", err, statusFile)
					continue
				}
				status := types.AppInstanceStatus{}
				if err := json.Unmarshal(sb, &status); err != nil {
					log.Printf("%s AppInstanceStatus file: %s\n",
						err, statusFile)
					continue
				}
				uuid := status.UUIDandVersion.UUID
				if uuid.String()+".json" != fileName {
					log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
						fileName, uuid.String())
					continue
				}
				statusName := zedmanagerStatusDirname + "/" + fileName
				handleDelete(statusName, status)
				continue
			}
			if operation != "M" {
				log.Fatal("Unknown operation from Watcher: ",
					operation)
			}
			configFile := zedmanagerConfigDirname + "/" + fileName
			cb, err := ioutil.ReadFile(configFile)
			if err != nil {
				log.Printf("%s for %s\n", err, configFile)
				continue
			}
			config := types.AppInstanceConfig{}
			if err := json.Unmarshal(cb, &config); err != nil {
				log.Printf("%s AppInstanceConfig file: %s\n",
					err, configFile)
				continue
			}
			uuid := config.UUIDandVersion.UUID
			if uuid.String()+".json" != fileName {
				log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
					fileName, uuid.String())
				continue
			}
			statusFile := zedmanagerStatusDirname + "/" + fileName
			if _, err := os.Stat(statusFile); err != nil {
				// File does not exist in status hence new
				statusName := zedmanagerStatusDirname + "/" + fileName
				handleCreate(statusName, config)
				continue
			}
			// Compare Version string
			sb, err := ioutil.ReadFile(statusFile)
			if err != nil {
				log.Printf("%s for %s\n", err, statusFile)
				continue
			}
			status := types.AppInstanceStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s AppInstanceStatus file: %s\n",
					err, statusFile)
				continue
			}
			uuid = status.UUIDandVersion.UUID
			if uuid.String()+".json" != fileName {
				log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
					fileName, uuid.String())
				continue
			}
			// Look for pending* in status and repeat that operation.
			// XXX After that do a full ReadDir to restart ...
			if status.PendingAdd {
				statusName := zedmanagerStatusDirname + "/" + fileName
				handleCreate(statusName, config)
				// XXX set something to rescan?
				continue
			}
			if status.PendingDelete {
				statusName := zedmanagerStatusDirname + "/" + fileName
				handleDelete(statusName, status)
				// XXX set something to rescan?
				continue
			}
			if status.PendingModify {
				statusName := zedmanagerStatusDirname + "/" + fileName
				handleModify(statusName, config, status)
				// XXX set something to rescan?
				continue
			}
				
			if config.UUIDandVersion.Version ==
				status.UUIDandVersion.Version {
				fmt.Printf("Same version %s for %s\n",
					config.UUIDandVersion.Version,
					fileName)
				continue
			}
			statusName := zedmanagerStatusDirname + "/" + fileName
			handleModify(statusName, config, status)
		}
		}
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
	// XXX which permissions?
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
	// XXX which permissions?
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func handleCreate(statusFilename string, config types.AppInstanceConfig) {
	log.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	// Start by marking with PendingAdd
	status := types.AppInstanceStatus{
		UUIDandVersion: config.UUIDandVersion,
// XXX remove field?		PendingAdd:     true,
		DisplayName:    config.DisplayName,
	}

	// First ensure the downloader is aware of the needed downloads
	for _, sc := range config.StorageConfigList {
		safename := urlToSafename(sc.DownloadURL, sc.ImageSha256)
		fmt.Printf("Found StorageConfig URL %s safename %s\n",
			sc.DownloadURL, safename)
		AddOrRefcountDownloaderConfig(safename, &sc)
		// XXX presumably need an array to track which safenames
		// this AIC has references to. To be used in delete.
	}

	addOrUpdateConfig(config.UUIDandVersion.UUID.String(), config)	
	// XXX initialize status Storage and EID here instead of in update
	addOrUpdateStatus(config.UUIDandVersion.UUID.String(), status)	

	// XXX is Pending* useful?
	// Instead delete all of zedmanagerStatusDirname on restart?
	// XXX we are never clearing PendingAdd in this code; not setting it above
	status.PendingAdd = false
	// XXX writeAppInstanceStatus(&status, statusFilename)
	log.Printf("handleCreate done for %s\n", config.DisplayName)
}

func handleModify(statusFilename string, config types.AppInstanceConfig,
	status types.AppInstanceStatus) {
	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	status.PendingModify = true
	status.UUIDandVersion = config.UUIDandVersion
	writeAppInstanceStatus(&status, statusFilename)

	// XXX do work
	
	status.PendingModify = false
	writeAppInstanceStatus(&status, statusFilename)
	log.Printf("handleUpdate done for %s\n", config.DisplayName)
}

func handleDelete(statusFilename string, status types.AppInstanceStatus) {
	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	status.PendingDelete = true
	writeAppInstanceStatus(&status, statusFilename)

	// XXX do work
	// Need to delete the other pieces
	
	// Write out what we modified to AppInstanceStatus aka delete
	// XXX defer until all children have it deleted! Avoids recreates
	if err := os.Remove(statusFilename); err != nil {
		log.Println("Failed to remove", statusFilename, err)
	}
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
