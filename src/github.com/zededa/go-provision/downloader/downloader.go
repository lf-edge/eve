// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Process input changes from a config directory containing json encoded files
// with DownloaderConfig and compare against DownloaderStatus in the status
// dir.
// XXX NOT Tries to download the items in the config directory repeatedly until
// there is a complete download. (XXX detect eof/short file or not?)
// ZedManager can stop the download by removing from config directory.
//
// Input directory with config (URL, refcount, maxLength, dstDir)
// Output directory with status (URL, refcount, state, ModTime, lastErr, lastErrTime, retryCount)
// refCount -> 0 means delete from dstDir? Who owns dstDir? Separate mount.
// Check length against Content-Length.

// Should retrieve length somewhere first. Should that be in the catalogue?
// Content-Length is set!
// nordmark@bobo:~$ curl -I  https://cloud-images.ubuntu.com/releases/16.04/release/ubuntu-16.04-server-cloudimg-arm64-root.tar.gz
// HTTP/1.1 200 OK
// Date: Sat, 03 Jun 2017 04:28:38 GMT
// Server: Apache
// Last-Modified: Tue, 16 May 2017 15:31:53 GMT
// ETag: "b15553f-54fa5defeec40"
// Accept-Ranges: bytes
// Content-Length: 185947455
// Content-Type: application/x-gzip

package main

import (
	"encoding/json"
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"zc/libs/zedUpload"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	certFrequency	time.Duration = 30
	configFrequency	time.Duration = 10
	dCtx		*zedUpload.DronaCtx
)

func main() {

	log.Printf("Starting downloader\n")

	ctx,err := zedUpload.NewDronaCtx("zdownloader", 0)

	if ctx == nil {
		log.Printf("context create fail %s\n", err)
		log.Fatal(err)
		return
	}

	dCtx = ctx

        handleInit()

	go checkLatestCert()
	go checkLatestConfig()
	go checkImageUpdates()

	go handleLatestCertUpdates()
	go handleLatestConfigUpdates()

	go handleCertUpdates()
	go handleConfigUpdates()

	// schedule the periodic timers
	triggerLatestConfig()
	triggerLatestCert()
}

func triggerLatestCert() {

	configDirname := "/var/tmp/downloader/latest.cert/config"

	time.AfterFunc(certFrequency * time.Minute, triggerLatestCert)

        config := types.DownloaderConfig{
		Operation:		"download",
		TransportMethod:	"s3",
		Safename:		"latest.cert.json",
		DownloadURL:		"https://s3-us-west-2.amazonaws.com/zededa-cert-repo/latest.cert.json",
		MaxSize:		40,
		Bucket:			"zededa-cert-repo",
		RefCount:		1,
		}

	if err := os.MkdirAll(configDirname, 0755); err != nil {
		log.Fatal(err)
	}

	configFilename := configDirname + "/latest.cert.json.json"

        writeDownloaderConfig(&config, configFilename)
}

func triggerLatestConfig() {

	configDirname := "/var/tmp/downloader/latest.config/config"

	time.AfterFunc(configFrequency * time.Minute, triggerLatestConfig)

        config := types.DownloaderConfig{
		Operation:		"download",
		Safename:		"latest.config.json",
		DownloadURL:		"https://s3-us-west-2.amazonaws.com/zededa-config-repo/latest.config.json",
		TransportMethod:	"s3",
		MaxSize:		40,
		Bucket:			"zededa-config-repo",
		RefCount:		1,
		}

	if err := os.MkdirAll(configDirname, 0755); err != nil {
		log.Fatal(err)
	}
	configFilename := configDirname + "/latest.config.json.json"

        writeDownloaderConfig(&config, configFilename)
}

func triggerConfigObjUpdates(configObj *types.DownloaderConfig) {

	configDirname := "/var/tmp/downloader/config.obj"

	safename := urlToSafename(configObj.DownloadURL, configObj.ImageSha256)
        config := types.DownloaderConfig{
		Safename:		safename,
		Operation:		configObj.Operation,
		DownloadURL:		configObj.DownloadURL,
		ImageSha256:		configObj.ImageSha256,
		TransportMethod:	configObj.TransportMethod,
		MaxSize:		configObj.MaxSize,
		Bucket:			configObj.Bucket,
		RefCount:		1,
	}

	if err := os.MkdirAll(configDirname, 0755); err != nil {
		log.Fatal(err)
	}
	configFilename := configDirname + "/" + safename + ".json"

        writeDownloaderConfig(&config, configFilename)
}

func triggerCertObjUpdates(certObj *types.CertConfig) {

	configDirname := "/var/tmp/downloader/cert.obj"

	if err := os.MkdirAll(configDirname, 0755); err != nil {
		log.Fatal(err)
	}

	// trigger server cert
	safename := "server-cert.pem"

        config := types.DownloaderConfig{
		Safename:		safename,
		Operation:		certObj.ServerCert.Operation,
		DownloadURL:		certObj.ServerCert.DownloadURL,
		ImageSha256:		certObj.ServerCert.ImageSha256,
		TransportMethod:	certObj.ServerCert.TransportMethod,
		MaxSize:		certObj.ServerCert.MaxSize,
		Bucket:			certObj.ServerCert.Bucket,
		RefCount:		1,
	}

	configFilename := configDirname + "/" + safename + ".json"

        writeDownloaderConfig(&config, configFilename)

	// now trigger the certificate chain
	for _, cert := range certObj.CertChain {

		safename := "intermetiate-cert.pem"

                config := types.DownloaderConfig {
			Safename:		safename,
			Operation:		cert.Operation,
			DownloadURL:		cert.DownloadURL,
			ImageSha256:		cert.ImageSha256,
			TransportMethod:	cert.TransportMethod,
			MaxSize:		cert.MaxSize,
			Bucket:			cert.Bucket,
			RefCount:		1,
		}

		configFilename := configDirname + "/" + safename + ".json"

                writeDownloaderConfig(&config, configFilename)
	}
}

func checkImageUpdates() {

	baseDirname := "/var/tmp/downloader"
	runDirname  := "/var/run/downloader"
	locDirname  := "/var/tmp/zedmanager/downloads/"

	log.Printf("starting image downloader loop")
	checkObjectUpdates(baseDirname, runDirname, locDirname)
}

func checkLatestCert() {

	baseDirname := "/var/tmp/downloader/latest.cert"
	runDirname  := "/var/run/downloader/latest.cert"
	locDirname  := "/var/tmp/zedmanager/downloads/latest.cert"

	log.Printf("starting cert downloader loop")
	checkObjectUpdates(baseDirname, runDirname, locDirname)
}

func checkLatestConfig() {

	baseDirname := "/var/tmp/downloader/latest.config"
	runDirname  := "/var/run/downloader/latest.config"
	locDirname  := "/var/tmp/zedmanager/downloads/latest.config"

	log.Printf("starting config downloader loop")
	checkObjectUpdates(baseDirname, runDirname, locDirname)
}

func handleLatestCertUpdates() {

	baseDirname := "/var/tmp/downloader/latest.cert"
	runDirname  := "/var/run/downloader/latest.cert"
	locDirname  := "/var/tmp/zedmanager/downloads/latest.cert"

	processLatestCertObject (baseDirname, runDirname, locDirname)
}

func handleLatestConfigUpdates() {

	baseDirname := "/var/tmp/downloader/latest.config"
	runDirname  := "/var/run/downloader/latest.config"
	locDirname  := "/var/tmp/zedmanager/downloads/latest.config"

	processLatestConfigObject (baseDirname, runDirname, locDirname)
}

func handleCertUpdates() {

	baseDirname := "/var/tmp/downloader/cert.obj"
	runDirname  := "/var/run/downloader/cert.obj"
	locDirname  := "/var/tmp/zedmanager/downloads/cert-obj"

	checkObjectUpdates(baseDirname, runDirname, locDirname)
}

func handleConfigUpdates() {

	baseDirname := "/var/tmp/downloader/config.obj"
	runDirname  := "/var/run/downloader/config.obj"
	locDirname  := "/var/tmp/zedmanager/downloads/config-obj"

	checkObjectUpdates(baseDirname, runDirname, locDirname)
}

func processConfigUpdates() {

	baseDirname := "/var/tmp/downloader/config.obj"
	runDirname  := "/var/run/downloader/config.obj"
	locDirname  := "/var/tmp/zedmanager/downloads/config.obj"

	processConfigObject (baseDirname, runDirname, locDirname)
}

func processCertUpdates() {

	baseDirname := "/var/tmp/downloader/cert.obj"
	runDirname  := "/var/run/downloader/cert.obj"
	locDirname  := "/var/tmp/zedmanager/downloads/cert-obj"

	processCertObject (baseDirname, runDirname, locDirname)
}

func  checkObjectUpdates (baseDirname string, runDirname string, locDirname string) {

	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"

	if _, err := os.Stat(baseDirname); err != nil {

		if err := os.MkdirAll(baseDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(runDirname); err != nil {

		if err := os.MkdirAll(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(configDirname); err != nil {

		if err := os.MkdirAll(configDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(statusDirname); err != nil {

		if err := os.MkdirAll(statusDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(locDirname); err != nil {

		if err := os.MkdirAll(locDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	var fileChanges = make(chan string)

	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)

	for {
		change := <-fileChanges
		parts := strings.Split(change, " ")
		operation := parts[0]
		fileName := parts[1]

		log.Printf("Changed file <%s> %s\n", fileName, operation)
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
			status := types.DownloaderStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s DownloaderStatus file: %s\n",
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
			handleDelete(statusName, locDirname, status)
			continue
		}

		/* only consider modified files */
		if operation != "M" {
			log.Fatal("Unknown operation from Watcher: ", operation)
		}

		configFile := configDirname + "/" + fileName
		cb, err := ioutil.ReadFile(configFile)

		if err != nil {
			log.Printf("%s for %s\n", err, configFile)
			continue
		}
		log.Printf("%s %s\n", configFile, cb)

		config := types.DownloaderConfig{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s DownloaderConfig file: %s\n",
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
			statusFilename := statusDirname + "/" + fileName
			//handleCreate(statusName, config)
			handleCreate(config, statusFilename, locDirname)
			continue
		}
		// Compare Version string
		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			log.Printf("%s for %s\n", err, statusFile)
			continue
		}

		status := types.DownloaderStatus{}
		if err = json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s DownloaderStatus file: %s\n",
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
			statusFilename := statusDirname + "/" + fileName
			//handleCreate(statusFileName, config)
			// XXX set something to rescan?
			handleCreate(config, statusFilename, locDirname)
			continue
		}
		if status.PendingDelete {
			statusFileName := statusDirname + "/" + fileName
			handleDelete(statusFileName, locDirname, status)
			// XXX set something to rescan?
			continue
		}
		if status.PendingModify {
			statusFileName := statusDirname + "/" + fileName
			handleModify(statusFileName, locDirname, config, status)
			// XXX set something to rescan?
			continue
		}

		statusFilename := statusDirname + "/" + fileName
		handleModify(statusFilename, locDirname, config, status)
	}
}

func  processLatestCertObject (baseDirname string, runDirname string, locDirname string) {

	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"

	if _, err := os.Stat(baseDirname); err != nil {

		if err := os.MkdirAll(baseDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(runDirname); err != nil {

		if err := os.MkdirAll(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(configDirname); err != nil {

		if err := os.MkdirAll(configDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(statusDirname); err != nil {

		if err := os.MkdirAll(statusDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(locDirname); err != nil {

		if err := os.MkdirAll(locDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	var fileChanges = make(chan string)

	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)

	for {
		change := <-fileChanges
		parts := strings.Split(change, " ")
		operation := parts[0]
		fileName := parts[1]

		log.Printf("Changed file <%s> %s\n", fileName, operation)

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
			status := types.DownloaderStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s DownloaderStatus file: %s\n",
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
			handleDelete(statusName, locDirname, status)
			continue
		}

		/* only consider modified files */
		if operation != "M" {
			log.Fatal("Unknown operation from Watcher: ", operation)
		}

		configFile := configDirname + "/" + fileName
		cb, err := ioutil.ReadFile(configFile)

		if err != nil {
			log.Printf("%s for %s\n", err, configFile)
			continue
		}
		log.Printf("%s %s\n", configFile, cb)

		config := types.DownloaderConfig{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s DownloaderConfig file: %s\n",
				err, configFile)
			continue
		}

		name := config.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
			continue
		}

		statusFilename := statusDirname + "/" + fileName
		if _, err := os.Stat(statusFilename); err != nil {
			// File does not exist
			continue
		}

		// Compare Version string
		sb, err := ioutil.ReadFile(statusFilename)
		if err != nil {
			log.Printf("%s for %s\n", err, statusFilename)
			continue
		}

		status := types.DownloaderStatus{}
		if err = json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s DownloaderStatus file: %s\n",
				err, statusFilename)
			continue
		}

		name = status.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
			continue
		}

		// latest config has been downloaded
		if  status.State != types.DOWNLOADED {
			continue
		}

		// get the downloaded file
		locFilename := locDirname + "/pending"

		if status.ImageSha256  != "" {
			locFilename = locFilename + "/" + status.ImageSha256
		}

		locFilename = locFilename + "/" + status.Safename

		if _, err := os.Stat(locFilename); err == nil {

			sb, err := ioutil.ReadFile(locFilename)
			if err == nil {

				// XXX check if the file is already present
				// if yes, do nothing

				certHolder := types.CertConfig{}
				if err = json.Unmarshal(sb, &certHolder); err == nil {
					triggerCertObjUpdates(&certHolder)
				}
			}
		}

		// finally flush the object holder file
		handleDelete(statusFilename, locDirname, status)
	}
}

func  processLatestConfigObject (baseDirname string, runDirname string, locDirname string) {

	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"

	if _, err := os.Stat(baseDirname); err != nil {

		if err := os.MkdirAll(baseDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(runDirname); err != nil {

		if err := os.MkdirAll(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(configDirname); err != nil {

		if err := os.MkdirAll(configDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(statusDirname); err != nil {

		if err := os.MkdirAll(statusDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(locDirname); err != nil {

		if err := os.MkdirAll(locDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	var fileChanges = make(chan string)

	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)

	for {
		change := <-fileChanges
		parts := strings.Split(change, " ")
		operation := parts[0]
		fileName := parts[1]

		log.Printf("Changed file <%s> %s\n", fileName, operation)
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
			status := types.DownloaderStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s DownloaderStatus file: %s\n",
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
			handleDelete(statusName, locDirname, status)
			continue
		}

		/* only consider modified files */
		if operation != "M" {
			log.Fatal("Unknown operation from Watcher: ", operation)
		}

		configFile := configDirname + "/" + fileName
		cb, err := ioutil.ReadFile(configFile)

		if err != nil {
			log.Printf("%s for %s\n", err, configFile)
			continue
		}
		log.Printf("%s %s\n", configFile, cb)

		config := types.DownloaderConfig{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s DownloaderConfig file: %s\n",
				err, configFile)
			continue
		}

		name := config.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
			continue
		}

		statusFilename := statusDirname + "/" + fileName
		if _, err := os.Stat(statusFilename); err != nil {
			// File does not exist
			continue
		}

		// Compare Version string
		sb, err := ioutil.ReadFile(statusFilename)
		if err != nil {
			log.Printf("%s for %s\n", err, statusFilename)
			continue
		}

		status := types.DownloaderStatus{}
		if err = json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s DownloaderStatus file: %s\n",
				err, statusFilename)
			continue
		}

		name = status.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
			continue
		}

		// latest config has been downloaded
		if  status.State != types.DOWNLOADED {
			continue
		}

		locFilename := locDirname + "/pending"

		if status.ImageSha256  != "" {
			locFilename = locFilename + "/" + status.ImageSha256
		}

		locFilename = locFilename + "/" + status.Safename

		if _, err := os.Stat(locFilename); err == nil {

			sb, err = ioutil.ReadFile(locFilename)
			if err != nil {
				log.Printf("%s for %s\n", err, locFilename)
				continue
			}

			// XXX check if the file is already present
			// if yes, do nothing

			// trigger Config File Downloads
			configHolder := types.DownloaderConfig{}
			if err = json.Unmarshal(sb, &configHolder); err == nil {
				triggerConfigObjUpdates(&configHolder)
			}

		}

		// finally flush the object holder file
		handleDelete(statusFilename, locDirname, status)
	}
}

func  processCertObject (baseDirname string, runDirname string, locDirname string) {

	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"

	if _, err := os.Stat(baseDirname); err != nil {

		if err := os.MkdirAll(baseDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(runDirname); err != nil {

		if err := os.MkdirAll(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(configDirname); err != nil {

		if err := os.MkdirAll(configDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(statusDirname); err != nil {

		if err := os.MkdirAll(statusDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(locDirname); err != nil {

		if err := os.MkdirAll(locDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	var fileChanges = make(chan string)

	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)

	for {
		change := <-fileChanges
		parts := strings.Split(change, " ")
		operation := parts[0]
		fileName := parts[1]

		log.Printf("Changed file <%s> %s\n", fileName, operation)
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
			status := types.DownloaderStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s DownloaderStatus file: %s\n",
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
			handleDelete(statusName, locDirname, status)
			continue
		}

		/* only consider modified files */
		if operation != "M" {
			log.Fatal("Unknown operation from Watcher: ", operation)
		}

		configFile := configDirname + "/" + fileName
		cb, err := ioutil.ReadFile(configFile)

		if err != nil {
			log.Printf("%s for %s\n", err, configFile)
			continue
		}

		config := types.DownloaderConfig{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s DownloaderConfig file: %s\n",
				err, configFile)
			continue
		}

		name := config.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
			continue
		}

		statusFilename := statusDirname + "/" + fileName
		if _, err := os.Stat(statusFilename); err != nil {
			// File does not exist
			continue
		}

		// Compare Version string
		sb, err := ioutil.ReadFile(statusFilename)
		if err != nil {
			log.Printf("%s for %s\n", err, statusFilename)
			continue
		}

		status := types.DownloaderStatus{}
		if err = json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s DownloaderStatus file: %s\n",
				err, statusFilename)
			continue
		}

		name = status.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
			continue
		}

		// latest cert has been downloaded
		if  status.State != types.DOWNLOADED {
			continue
		}

		locFilename := locDirname + "/pending"

		if status.ImageSha256 != "" {
			locFilename = locFilename + "/" + status.ImageSha256
		}

		locFilename = locFilename + "/" + status.Safename

		// now move the file to cert dir
		if _, err := os.Stat(locFilename); err == nil {

			certDir := "/var/tmp/zedmanager/cert"
			certFilename := certDir + "/" + status.Safename

			writeFile(locFilename, certFilename)
		}

		// finally flush the object holder files
		handleDelete(statusFilename, locDirname, status)

	}

}
func  processConfigObject (baseDirname string, runDirname string, locDirname string) {

	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"

	if _, err := os.Stat(baseDirname); err != nil {

		if err := os.MkdirAll(baseDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(runDirname); err != nil {

		if err := os.MkdirAll(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(configDirname); err != nil {

		if err := os.MkdirAll(configDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(statusDirname); err != nil {

		if err := os.MkdirAll(statusDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(locDirname); err != nil {

		if err := os.MkdirAll(locDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	var fileChanges = make(chan string)

	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)

	for {
		change := <-fileChanges
		parts := strings.Split(change, " ")
		operation := parts[0]
		fileName := parts[1]

		log.Printf("Changed file <%s> %s\n", fileName, operation)
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
			status := types.DownloaderStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s DownloaderStatus file: %s\n",
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
			handleDelete(statusName, locDirname, status)
			continue
		}

		/* only consider modified files */
		if operation != "M" {
			log.Fatal("Unknown operation from Watcher: ", operation)
		}

		configFile := configDirname + "/" + fileName
		cb, err := ioutil.ReadFile(configFile)

		if err != nil {
			log.Printf("%s for %s\n", err, configFile)
			continue
		}
		log.Printf("%s %s\n", configFile, cb)

		config := types.DownloaderConfig{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s DownloaderConfig file: %s\n",
				err, configFile)
			continue
		}

		name := config.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
			continue
		}

		statusFilename := statusDirname + "/" + fileName
		if _, err := os.Stat(statusFilename); err != nil {
			// File does not exist
			continue
		}

		// Compare Version string
		sb, err := ioutil.ReadFile(statusFilename)
		if err != nil {
			log.Printf("%s for %s\n", err, statusFilename)
			continue
		}

		status := types.DownloaderStatus{}
		if err = json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s DownloaderStatus file: %s\n",
				err, statusFilename)
			continue

		}
		name = status.Safename
		if name+".json" != fileName {
			log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
				fileName, name)
			continue
		}

		// latest config has been downloaded
		if  status.State != types.DOWNLOADED {
			continue
		}

		locFilename := locDirname + "/pending"

		if status.ImageSha256 != "" {
			locFilename = locFilename + "/" + status.ImageSha256
		}

		locFilename = locFilename + "/" + status.Safename

		// now copy the file to proper config dir
		if _, err := os.Stat(locFilename); err == nil {

			configDir := "/var/tmp/zedmanager/config"
			configFilename := configDir + "/" + status.Safename

			writeFile(locFilename, configFilename)
		}

		// finally flush the object holder files
		handleDelete(statusFilename, locDirname, status)
	}

}

func urlToSafename(url string, sha string) string {
        safename := strings.Replace(url, "/", "_", -1) + "." + sha
        return safename
}

var globalConfig types.GlobalDownloadConfig
var globalStatus types.GlobalDownloadStatus
var globalStatusFilename string
var imgCatalogDirname string

func handleInit() {

	runDirname := "/var/run/downloader"
	baseDirname := "/var/tmp/downloader"

	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"

	configFilename := configDirname + "/global"
	statusFilename := statusDirname + "/global"

	locDirname := "/var/tmp/zedmanager/downloads/"

	globalStatusFilename = statusFilename

	if _, err := os.Stat(statusDirname); err != nil {

		if err := os.MkdirAll(statusDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// Read GlobalDownloadConfig to find MaxSpace
	// Then determine currently used space and remaining.
	cb, err := ioutil.ReadFile(configFilename)
	if err != nil {
		log.Printf("%s for %s\n", err, configFilename)
		log.Fatal(err)
	}
	if err := json.Unmarshal(cb, &globalConfig); err != nil {
		log.Printf("%s GlobalDownloadConfig file: %s\n",
			err, configFilename)
		log.Fatal(err)
	}
	log.Printf("MaxSpace %d\n", globalConfig.MaxSpace)

	globalStatus.UsedSpace = 0
	globalStatus.ReservedSpace = 0
	updateRemainingSpace()

	// We read /var/tmp/zedmanager/downloads/* and determine how much space
	// is used. Place in GlobalDownloadStatus. Calculate remaining space.
	totalUsed := sizeFromDir(locDirname)
	globalStatus.UsedSpace = uint((totalUsed + 1023) / 1024)
	updateRemainingSpace()
}

func sizeFromDir(dirname string) int64 {
	var totalUsed int64 = 0
	locations, err := ioutil.ReadDir(dirname)
	if err != nil {
		log.Fatalf("ReadDir(%s) %s\n",
			dirname, err)
	}
	for _, location := range locations {
		filename := dirname + "/" + location.Name()
		fmt.Printf("Looking in %s\n", filename)
		if location.IsDir() {
			size := sizeFromDir(filename)
			fmt.Printf("Dir %s size %d\n", filename, size)
			totalUsed += size
		} else {
			fmt.Printf("File %s Size %d\n", filename, location.Size())
			totalUsed += location.Size()
		}
	}
	return totalUsed
}

func updateRemainingSpace() {
	globalStatus.RemainingSpace = globalConfig.MaxSpace -
		globalStatus.UsedSpace -
		globalStatus.ReservedSpace
	log.Printf("RemaingSpace %d, maxspace %d, usedspace %d, reserved %d\n",
		globalStatus.RemainingSpace, globalConfig.MaxSpace,
		globalStatus.UsedSpace,	globalStatus.ReservedSpace)
	// Create and write
	writeGlobalStatus()
}

func writeGlobalStatus() {
	sb, err := json.Marshal(globalStatus)
	if err != nil {
		log.Fatal(err, "json Marshal GlobalDownloadStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(globalStatusFilename, sb, 0644)
	if err != nil {
		log.Fatal(err, globalStatusFilename)
	}
}

func writeDownloaderStatus(status *types.DownloaderStatus,
	statusFilename string) {
	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal DownloaderStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func writeDownloaderConfig(config *types.DownloaderConfig,
	configFilename string) {

	log.Printf("Writing the config file %s\n", configFilename)
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal DownloaderStatus")
	}
	err = ioutil.WriteFile(configFilename, b, 0644)
	if err != nil {
		log.Fatal(err, configFilename)
	}
}

func writeFile(sFilename string, dFilename string) {

	if _, err := os.Stat(sFilename); err == nil {

		sb, err := ioutil.ReadFile(sFilename)

		if err != nil {
			log.Printf("Failed to read %s: err %s\n",
				sFilename)
		} else {

			err = ioutil.WriteFile(dFilename, sb, 0644)

			if err != nil {
				log.Printf("Failed to write %s: err %s\n",
					dFilename, err)
			}
		}
	}

}

func handleCreate(config types.DownloaderConfig, statusFilename string, locDirname string) {

	var syncOp zedUpload.SyncOpType  = zedUpload.SyncOpDownload

	// Start by marking with PendingAdd
	status := types.DownloaderStatus{
		Safename:	config.Safename,
		RefCount:	config.RefCount,
		DownloadURL:	config.DownloadURL,
		ImageSha256:	config.ImageSha256,
		PendingAdd:	true,
	}
	writeDownloaderStatus(&status, statusFilename)

	// Check if we have space
	if config.MaxSize >= globalStatus.RemainingSpace {
		errString := fmt.Sprintf("Would exceed remaining space %d vs %d\n",
			config.MaxSize, globalStatus.RemainingSpace)
		log.Println(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(&status, statusFilename)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return
	}

	// Update reserved space. Keep reserved until doDelete
	// XXX RefCount -> 0 should keep it reserved.
	status.ReservedSpace = config.MaxSize
	globalStatus.ReservedSpace += status.ReservedSpace
	updateRemainingSpace()

	// If RefCount == 0 then we don't yet download.
	if config.RefCount == 0 {
		// XXX odd to treat as error.
		errString := fmt.Sprintf("RefCount==0; download deferred for %s\n",
			config.DownloadURL)
		log.Println(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(&status, statusFilename)
		log.Printf("handleCreate deferred for %s\n", config.DownloadURL)
		return
	}

	// update status to DOWNLOAD STARTED
	status.State = types.DOWNLOAD_STARTED
	writeDownloaderStatus(&status, statusFilename)

	locFilename := locDirname + "/pending"

	if config.ImageSha256 != "" {
		locFilename = locFilename + "/" + config.ImageSha256
	}

	if _, err := os.Stat(locFilename); err != nil {

		if err := os.MkdirAll(locFilename, 0755); err != nil {
			log.Fatal(err)
		}
	}

	locFilename = locFilename + "/" + config.Safename

	log.Printf("Downloading  %s to %s\n", config.DownloadURL, locFilename)

	err := handleSyncOp(syncOp, locFilename, statusFilename, config, &status)

	if err != nil {
		// Delete file
		doDelete(statusFilename, locDirname, &status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(&status, statusFilename)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return
	}

	info, err := os.Stat(locFilename)
	if err != nil {
		// Delete file
		doDelete(statusFilename, locDirname, &status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(&status, statusFilename)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return
	}
	// XXX Compare against MaxSize and reject? Already wasted the space?
	status.Size = uint((info.Size() + 1023)/1024)

	if status.Size > config.MaxSize {
		// Delete file
		doDelete(statusFilename, locDirname, &status)
		errString := fmt.Sprintf("Size exceeds MaxSize; %d vs. %d for %s\n",
			status.Size, config.MaxSize, config.DownloadURL)
		log.Println(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(&status, statusFilename)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return
	}

	globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	globalStatus.UsedSpace += status.Size
	updateRemainingSpace()

	log.Printf("handleCreate successful for %s\n", config.DownloadURL)
	// We do not clear any status.RetryCount, LastErr, etc. The caller
	// should look at State == DOWNLOADED to determine it is done.

	status.ModTime = time.Now()
	status.PendingAdd = false
	status.State = types.DOWNLOADED
	writeDownloaderStatus(&status, statusFilename)
}

// XXX Should we set        --limit-rate=100k
// XXX Can we safely try a continue?
// XXX wget seems to have no way to limit download size for single file!
// XXX temporary options since store.zededa.net not in DNS
// and wierd free.fr dns behavior with AAAA and A. Added  -4 --no-check-certificate
func doWget(url string, destFilename string) error {
	fmt.Printf("doWget %s %s\n", url, destFilename)
	cmd := "wget"
	args := []string{
		"-q",
		"-c",
		"-4",	// XXX due to getting IPv6 ULAs and not IPv4
		"--no-check-certificate",
		"--tries=3",
		"-O",
		destFilename,
		url,
	}
	_, err := exec.Command(cmd, args...).Output()
	if err != nil {
		log.Println("wget failed ", err)
		return err
	}
	fmt.Printf("wget done\n")
	return nil
}

// Allow to cancel by setting RefCount = 0. Same as delete? RefCount 0->1
// means download. Ignore other changes?
func handleModify(statusFilename string, locDirname string, config types.DownloaderConfig,
	status types.DownloaderStatus) {
	log.Printf("handleModify(%v) for %s\n",
		config.Safename, config.DownloadURL)

	if config.DownloadURL != status.DownloadURL {
		fmt.Printf("URL changed - not allowed %s -> %s\n",
			config.DownloadURL, status.DownloadURL)
		return
	}
	// If the sha changes, we treat it as a delete and recreate.
	// Ditto if we had a failure.
	if (status.ImageSha256 != "" && status.ImageSha256 != config.ImageSha256) ||
		 status.LastErr != "" {
		reason := ""
		if status.ImageSha256 != config.ImageSha256 {
			reason = "sha256 changed"
		} else {
			reason = "recovering from previous error"
		}
		log.Printf("handleModify %s for %s\n",
			reason, config.DownloadURL)
		doDelete(statusFilename, locDirname, &status)
		handleCreate(config, statusFilename, locDirname)
		log.Printf("handleModify done for %s\n", config.DownloadURL)
		return
	}

	// XXX do work; look for refcnt -> 0 and delete; cancel any running
	// download
	// If RefCount from zero to non-zero then do install
	if status.RefCount == 0 && config.RefCount != 0 {
		log.Printf("handleModify installing %s\n", config.DownloadURL)
		handleCreate(config, statusFilename, locDirname)
		status.RefCount = config.RefCount
		status.PendingModify = false
		writeDownloaderStatus(&status, statusFilename)
	} else if status.RefCount != 0 && config.RefCount == 0 {
		log.Printf("handleModify deleting %s\n", config.DownloadURL)
		doDelete(statusFilename, locDirname, &status)
	} else {
		status.RefCount = config.RefCount
		status.PendingModify = false
		writeDownloaderStatus(&status, statusFilename)
	}
	log.Printf("handleModify done for %s\n", config.DownloadURL)
}

func doDelete(statusFilename string, locDirname string, status *types.DownloaderStatus) {

	log.Printf("doDelete(%v) for %s\n",
		status.Safename, status.DownloadURL)

	locFilename := locDirname + "/pending"

	if status.ImageSha256  != "" {
		locFilename = locFilename + "/" + status.ImageSha256
	}

	if _, err := os.Stat(locFilename); err == nil {

		locFilename := locFilename + "/" + status.Safename
		log.Printf("Downloading  %s to %s\n", status.DownloadURL, locFilename)

		if _, err := os.Stat(locFilename); err == nil {

			// Remove file
			if err := os.Remove(locFilename); err != nil {
				log.Printf("Failed to remove %s: err %s\n",
					locFilename, err)
			}
		}
	}
	status.State = types.INITIAL
	// XXX Asymmetric; handleCreate reserved on RefCount 0. We unreserve
	// going back to RefCount 0. FIXed
	globalStatus.UsedSpace -= status.Size
	status.Size = 0
	updateRemainingSpace()
	writeDownloaderStatus(status, statusFilename)
}

func handleDelete(statusFilename string, locDirname string, status types.DownloaderStatus) {
	log.Printf("handleDelete(%v) for %s\n",
		status.Safename, status.DownloadURL)

	status.PendingDelete = true
	writeDownloaderStatus(&status, statusFilename)

	globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	globalStatus.UsedSpace -= status.Size
	status.Size = 0
	updateRemainingSpace()
	writeDownloaderStatus(&status, statusFilename)

	doDelete(statusFilename, locDirname, &status)

	status.PendingDelete = false
	writeDownloaderStatus(&status, statusFilename)

	// Write out what we modified to DownloaderStatus aka delete
	if err := os.Remove(statusFilename); err != nil {
		log.Println("Failed to remove", statusFilename, err)
	}
	log.Printf("handleDelete done for %s\n", status.DownloadURL)
}

func handleSyncOp(syncOp zedUpload.SyncOpType, locFilename string, statusFilename string, config types.DownloaderConfig, status *types.DownloaderStatus) (err error) {

	// Prepare the authentication Tuple
	auth := &zedUpload.AuthInput{AuthType: "s3",
			 Uname :"AKIAJMEEPPJOBQCVW3BQ",
			 Password:"nz0dXnc4Qc7z0PTsyIfIrM7bDNJWeLMvlUI2oJ2T"}
	trType:= zedUpload.SyncAwsTr
	region := "us-west-2"

	// create Endpoint
	dEndPoint,err := dCtx.NewSyncerDest(trType, region, config.Bucket, auth)

	if dEndPoint != nil {
		var resp = make(chan * zedUpload.DronaRequest);

		// create Request
		req := dEndPoint.NewRequest(syncOp, config.Safename, locFilename,
			int64(config.MaxSize * 1024), true, resp)

		if req != nil {
			err = req.Post()
		}
	}
	return err
}

