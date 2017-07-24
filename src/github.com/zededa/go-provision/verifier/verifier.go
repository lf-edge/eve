// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Process input changes from a config directory containing json encoded files
// with VerifyImageConfig and compare against VerifyImageStatus in the status
// dir.

// XXX TBD add support for verifying the signatures on the meta-data (the AIC)

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

var imgCatalogDirname string

func main() {
	// XXX make baseDirname and runDirname be arguments??
	// Keeping status in /var/run to be clean after a crash/reboot
	baseDirname := "/var/tmp/verifier"
	runDirname := "/var/run/verifier"
	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"
	imgCatalogDirname = "/var/tmp/zedmanager/downloads"
	pendingDirname := imgCatalogDirname + "/pending"
	
	if _, err := os.Stat(imgCatalogDirname); err != nil {
		log.Fatal("Stat ", imgCatalogDirname, err)
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
	if _, err := os.Stat(pendingDirname); err != nil {
		if err := os.Mkdir(pendingDirname, 0755); err != nil {
			log.Fatal("Mkdir ", pendingDirname, err)
		}
	}

	// XXX write emtpy config
	config := types.VerifyImageConfig{}
	writeVerifyImageConfig(&config, "/tmp/foo")

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
			status := types.VerifyImageStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s VerifyImageStatus file: %s\n",
					err, statusFile)
				continue
			}
			name := status.Safename
			if name+".json" != fileName {
				log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
					fileName, name)
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
		config := types.VerifyImageConfig{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s VerifyImageConfig file: %s\n",
				err, configFile)
			continue
		}
		name := config.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
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
		status := types.VerifyImageStatus{}
		if err = json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s VerifyImageStatus file: %s\n",
				err, statusFile)
			continue
		}
		name = status.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
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
			
		// XXX handleModify detects changes by looking at RefCount
		// Sanity check here or in handleModify?
		if config.DownloadURL !=
			status.DownloadURL {
			fmt.Printf("URL changed - not allowed %s -> %s\n",
				config.DownloadURL, status.DownloadURL)
			continue
		}
		statusName := statusDirname + "/" + fileName
		handleModify(statusName, config, status)
	}
}

// XXX Only used for initial format of config json
func writeVerifyImageConfig(config *types.VerifyImageConfig,
	configFilename string) {
	fmt.Printf("XXX Writing empty config to %s\n", configFilename)
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal VerifyImageConfig")
	}
	err = ioutil.WriteFile(configFilename, b, 0644)
	if err != nil {
		log.Fatal(err, configFilename)
	}
}

func writeVerifyImageStatus(status *types.VerifyImageStatus,
	statusFilename string) {
	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal VerifyImageStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	// XXX which permissions?
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func handleCreate(statusFilename string, config types.VerifyImageConfig) {
	log.Printf("handleCreate(%v) for %s\n",
		config.Safename, config.DownloadURL)
	// Start by marking with PendingAdd
	status := types.VerifyImageStatus{
		Safename:	config.Safename,
		DownloadURL:	config.DownloadURL,
		ImageSha256:	config.ImageSha256,
		PendingAdd:     true,
		State:		types.DOWNLOADED,
	}
	writeVerifyImageStatus(&status, statusFilename)

	// Form unique filename in /var/tmp/zedmanager/downloads/pending/
	// based on safename
	srcFilename := imgCatalogDirname + "/pending/" + config.Safename	
	log.Printf("Verifying URL %s file %s\n",
		config.DownloadURL, srcFilename)

	f, err := os.Open(srcFilename)
	if err != nil {
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.State = types.INITIAL
		writeVerifyImageStatus(&status, statusFilename)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return		
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.State = types.INITIAL
		writeVerifyImageStatus(&status, statusFilename)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return		
	}

	got := fmt.Sprintf("%x", h.Sum(nil))
	if got != config.ImageSha256 {
		fmt.Printf("got      %s\n", got)
		fmt.Printf("expected %s\n", config.ImageSha256)
		status.LastErr = fmt.Sprintf("got %s expected %s",
			got, config.ImageSha256)
		status.LastErrTime = time.Now()
		status.PendingAdd = false
		status.State = types.INITIAL
		writeVerifyImageStatus(&status, statusFilename)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return
	}
	status.PendingAdd = false
	status.State = types.DELIVERED
	writeVerifyImageStatus(&status, statusFilename)
	log.Printf("handleCreate done for %s\n", config.DownloadURL)
}

func handleModify(statusFilename string, config types.VerifyImageConfig,
	status types.VerifyImageStatus) {
	log.Printf("handleModify(%v) for %s\n",
		config.Safename, config.DownloadURL)

	// If identical we do nothing. Otherwise we do a delete and create.
	if config.Safename == status.Safename &&
	   config.DownloadURL == status.DownloadURL &&
	   config.ImageSha256 == status.ImageSha256 {
		log.Printf("handleModify: no change for %s\n",
			config.DownloadURL)
		return
	}
	   
	status.PendingModify = true
	writeVerifyImageStatus(&status, statusFilename)
	handleDelete(statusFilename, status)
	handleCreate(statusFilename, config)
	status.PendingModify = false
	writeVerifyImageStatus(&status, statusFilename)
	log.Printf("handleUpdate done for %s\n", config.DownloadURL)
}

func handleDelete(statusFilename string, status types.VerifyImageStatus) {
	log.Printf("handleDelete(%v) for %s\n",
		status.Safename, status.DownloadURL)

	// Write out what we modified to VerifyImageStatus aka delete
	if err := os.Remove(statusFilename); err != nil {
		log.Println("Failed to remove", statusFilename, err)
	}
	log.Printf("handleDelete done for %s\n", status.DownloadURL)
}
