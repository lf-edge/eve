// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Pull AppInstanceConfig from ZedCloud, drive config to Downloader, Verifier,
// IdentityMgr, and Zedrouter. Collect status from those services and push
// combined AppInstanceStatus to ZedCloud.
// XXX initial code reads AppInstanceConfig from /var/tmp/zedmanager/config/*.json
// and produces AppInstanceStatus in /var/run/zedmanager/status/*.json

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
// XXX	"os/exec"
// XXX	"strconv"
	"strings"
)

func main() {
	// XXX make baseDirname and runDirname be arguments??
	// Keeping status in /var/run to be clean after a crash/reboot
	baseDirname := "/var/tmp/zedmanager"
	runDirname := "/var/run/zedmanager"
	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"
	verifierStatusDirname := "/var/run/verifier/status"
	downloaderStatusDirname := "/var/run/downloader/status"
	xenmgrStatusDirname := "/var/run/xenmgr/status"
	zedrouterStatusDirname := "/var/run/zedrouter/status"
	identitymgrStatusDirname := "/var/run/identitymgr/status"

	dirs := []string{
		configDirname,
		statusDirname,
		"/var/tmp/zedmanager/downloads",
		"/var/tmp/zedmanager/downloads/pending",
		"/var/tmp/identitymgr/status",
		"/var/tmp/zedrouter/status",
		"/var/tmp/xenmgr/status",
		"/var/tmp/downloader/status",
		"/var/tmp/verifier/status",
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

	// XXX write emtpy config
	config := types.AppInstanceConfig{}
	writeAICConfig(&config, "/tmp/foo")

	handleInit(configDirname+"/global", statusDirname+"/global", runDirname)

	configChanges := make(chan string)
	go watch.WatchConfigStatus(configDirname, statusDirname, configChanges)
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
		case change := <-verifierChanges: {
			// XXX function which takes interface which is the
			// statusDirname, Status type, and the two handle
			// functions.
			// XXX
			fmt.Printf("verifierChanges %v\n", change)
			parts := strings.Split(change, " ")
			operation := parts[0]
			fileName := parts[1]
			if !strings.HasSuffix(fileName, ".json") {
				log.Printf("Ignoring file <%s>\n", fileName)
				continue
			}
			if operation == "D" {
				// XXX Remove .json from name */
				name := strings.Split(fileName, ".")
				handleVerifyImageStatusDelete(name[0])
				continue
			} else if operation != "C" {
				log.Fatal("Unknown operation from Watcher: ",
					operation)
			}
			statusFile := verifierStatusDirname + "/" + fileName
			cb, err := ioutil.ReadFile(statusFile)
			if err != nil {
				log.Printf("%s for %s\n", err, statusFile)
				continue
			}
			status := types.VerifyImageStatus{}
			if err := json.Unmarshal(cb, &status); err != nil {
				log.Printf("%s VerifyImageStatus file: %s\n",
					err, statusFile)
				continue
			}
			handleVerifyImageStatusCreate(status)
			continue
		}
		case change := <-configChanges: {
			// XXX
			fmt.Printf("configChanges %v\n", change)
			parts := strings.Split(change, " ")
			operation := parts[0]
			fileName := parts[1]
			if !strings.HasSuffix(fileName, ".json") {
				log.Printf("Ignoring file <%s>\n", fileName)
				continue
			}
			if operation == "D" {
				statusFile := statusDirname + "/" + fileName
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
				statusName := statusDirname + "/" + fileName
				handleDelete(statusName, status)
				continue
			}
			if operation != "M" {
				log.Fatal("Unknown operation from Watcher: ",
					operation)
			}
			configFile := configDirname + "/" + fileName
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
			statusFile := statusDirname + "/" + fileName
			if _, err := os.Stat(statusFile); err != nil {
				// File does not exist in status hence new
				statusName := statusDirname + "/" + fileName
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
				statusName := statusDirname + "/" + fileName
				handleCreate(statusName, config)
				// XXX set something to rescan?
				continue
			}
			if status.PendingDelete {
				statusName := statusDirname + "/" + fileName
				handleDelete(statusName, status)
				// XXX set something to rescan?
				continue
			}
			if status.PendingModify {
				statusName := statusDirname + "/" + fileName
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
			statusName := statusDirname + "/" + fileName
			handleModify(statusName, config, status)
		}
		}
	}
}

// XXX only used for initial layout of json
func writeAICConfig(config *types.AppInstanceConfig,
	configFilename string) {
	fmt.Printf("XXX Writing empty config to %s\n", configFilename)
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal AppInstanceConfig")
	}
	err = ioutil.WriteFile(configFilename, b, 0644)
	if err != nil {
		log.Fatal(err, configFilename)
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

func handleInit(configFilename string, statusFilename string,
     runDirname string) {
	// XXX Mkdir for all the status?     
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
		PendingAdd:     true,
		DisplayName:    config.DisplayName,
	}
	writeAppInstanceStatus(&status, statusFilename)
	// XXX do work
	
	writeAppInstanceStatus(&status, statusFilename)
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
	
	// Write out what we modified to AppInstanceStatus aka delete
	// XXX defer until all children have it deleted!
	if err := os.Remove(statusFilename); err != nil {
		log.Println("Failed to remove", statusFilename, err)
	}
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}

func handleVerifyImageStatusCreate(status types.VerifyImageStatus) {
	log.Printf("handleVerifyImageStatusCreate for %s\n",
		status.Safename)

	// XXX do work
	
	log.Printf("handleVerifyImageStatusCreate done for %s\n",
		status.Safename)
}

func handleVerifyImageStatusDelete(statusFilename string) {
	log.Printf("handleVerifyImageStatusDelete for %s\n",
		statusFilename)

	// XXX do work
	
	log.Printf("handleVerifyImageStatusDelete done for %s\n",
		statusFilename)
}

