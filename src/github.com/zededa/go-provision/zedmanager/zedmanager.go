// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Pull AppInstanceConfig from ZedCloud, drive config to Downloader, Verifier,
// IdentityMgr, and Zedrouter. Collect status from those services and push
// combined AppInstanceStatus to ZedCloud.
// XXX initial code reads AppInstanceConfig from /var/tmp/zedmanager/config/*.json
// and produces AppInstanceStatus in /var/run/zedmanager/status/*.json
// XXX Downloader, Verifier and IdentityMgr interaction?

// XXX Should we keep the local config and status dirs and have a separate
// config downloader (which calls the Verifier), and uploader?

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

	if _, err := os.Stat(configDirname); err != nil {
		if err := os.Mkdir(configDirname, 0755); err != nil {
			log.Fatal("Mkdir ", configDirname, err)
		}
	}
	if _, err := os.Stat(runDirname); err != nil {
		if err := os.Mkdir(runDirname, 0755); err != nil {
			log.Fatal("Mkdir ", runDirname, err)
		}
	}
	if _, err := os.Stat(statusDirname); err != nil {
		if err := os.Mkdir(statusDirname, 0755); err != nil {
			log.Fatal("Mkdir ", statusDirname, err)
		}
	}
	// XXX Mkdir of whole list. Plus their config? Who starts last?
	// XXX 	runDirname := "/var/run/identitymgr/status"
	// XXX 	runDirname := "/var/run/zedrouter/status"
	// XXX 	runDirname := "/var/run/xenmgr/status"
	// XXX 	runDirname := "/var/run/downloader/status"
	// XXX 	runDirname := "/var/run/verifier/status"

	// XXX write emtpy config
	config := types.AppInstanceConfig{}
	writeAICConfig(&config, "/tmp/foo")

	// XXX don't we need this early? Or when activating the zedrouter?
	//	appNumAllocatorInit(statusDirname, configDirname)

	handleInit(configDirname+"/global", statusDirname+"/global", runDirname)

	// XXX need a fileChanges for each status as well + select
	// XXX do we need a shadowStatus for each sub-service to detect create
	// and delete? Thus configDirName = status, statusDirName = shadow

	fileChanges := make(chan string)
	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)
	for {
		change := <-fileChanges
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
			log.Fatal("Unknown operation from Watcher: ", operation)
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
	fmt.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	// Start by marking with PendingAdd
	status := types.AppInstanceStatus{
		UUIDandVersion: config.UUIDandVersion,
		PendingAdd:     true,
		DisplayName:    config.DisplayName,
		// XXX IsZedmanager:   config.IsZedmanager,
	}
	writeAppInstanceStatus(&status, statusFilename)
	// XXX do work

	writeAppInstanceStatus(&status, statusFilename)
	fmt.Printf("handleCreate done for %s\n", config.DisplayName)
}

// Note that modify will not touch the EID; just ACLs and NameToEidList
func handleModify(statusFilename string, config types.AppInstanceConfig,
	status types.AppInstanceStatus) {
	fmt.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	status.PendingModify = true
	status.UUIDandVersion = config.UUIDandVersion
	writeAppInstanceStatus(&status, statusFilename)

	// XXX do work
	
	status.PendingModify = false
	writeAppInstanceStatus(&status, statusFilename)
	fmt.Printf("handleUpdate done for %s\n", config.DisplayName)
}

func handleDelete(statusFilename string, status types.AppInstanceStatus) {
	fmt.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	status.PendingDelete = true
	writeAppInstanceStatus(&status, statusFilename)

	// XXX do work
	
	// Write out what we modified to AppInstanceStatus aka delete
	// XXX defer until all children have it deleted!
	if err := os.Remove(statusFilename); err != nil {
		log.Println("Failed to remove", statusFilename, err)
	}
	fmt.Printf("handleDelete done for %s\n", status.DisplayName)
}
