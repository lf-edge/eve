// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Wrapper around WatchConfigStatus to call handler functions

package watch

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// Common interfaces for *Status and *Config
type ZedConfig interface {
	VerifyFilename(fileName string) bool
}

type ZedStatus interface {
	VerifyFilename(fileName string) bool
	CheckPendingAdd() bool
	CheckPendingModify() bool
	CheckPendingDelete() bool
}

type configCreateHandler func(statusFilename string, config interface{})
type configModifyHandler func(statusFilename string, config interface{},
	status interface{})
type configDeleteHandler func(statusFilename string, status interface{})
type ConfigRestartHandler func(bool)

func HandleConfigStatusEvent(change string,
	configDirname string, statusDirname string,
	config ZedConfig, status ZedStatus,
	handleCreate configCreateHandler, handleModify configModifyHandler,
	handleDelete configDeleteHandler, handleRestart *ConfigRestartHandler) {
	operation := string(change[0])
	fileName := string(change[2:])
	if operation == "R" {
		log.Printf("Received restart <%s> ignored\n", fileName)
		return
	}
	// XXX implicit assumption that this is last in ReadDir?
	if fileName == "restart" && operation == "M" {
		log.Printf("Found restart file\n")
		if handleRestart != nil {
			(*handleRestart)(true)
		}
		return
	}
	if !strings.HasSuffix(fileName, ".json") {
		log.Printf("Ignoring file <%s> operation %s\n",
			fileName, operation)
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
			log.Printf("%s %T file: %s\n",
				err, status, statusFile)
			return
		}
		if !status.VerifyFilename(fileName) {
			return
		}
		statusName := statusDirname + "/" + fileName
		// Note that we might have a Pending* at this point in time
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
		log.Printf("%s %T file: %s\n",
			err, config, configFile)
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
		log.Printf("%s %T file: %s\n",
			err, status, statusFile)
		return
	}
	if !status.VerifyFilename(fileName) {
		return
	}
	// Look for pending* in status and repeat that operation.
	// Don't expect a PendingDelete since in that case we wouldn't
	// have a Config.
	if status.CheckPendingAdd() {
		statusName := statusDirname + "/" + fileName
		handleCreate(statusName, config)
		return
	}
	if status.CheckPendingDelete() {
		statusName := statusDirname + "/" + fileName
		handleDelete(statusName, status)
		return
	}
	if status.CheckPendingModify() {
		statusName := statusDirname + "/" + fileName
		handleModify(statusName, config, status)
		return
	}
	statusName := statusDirname + "/" + fileName
	handleModify(statusName, config, status)
}

type statusCreateHandler func(statusFilename string, status interface{})
type statusDeleteHandler func(statusFilename string)
type StatusRestartHandler func(bool)

func HandleStatusEvent(change string, statusDirname string, status interface{},
	statusCreateFunc statusCreateHandler,
	statusDeleteFunc statusDeleteHandler,
	handleRestart *StatusRestartHandler) {
	operation := string(change[0])
	fileName := string(change[2:])
	if operation == "R" {
		log.Printf("Received restart <%s>; ignored\n", fileName)
		return
	}
	if fileName == "restarted" && operation == "M" {
		log.Printf("Found restarted file\n")
		if handleRestart != nil {
			(*handleRestart)(true)
		}
		return
	}

	if !strings.HasSuffix(fileName, ".json") {
		log.Printf("Ignoring file <%s> operation %s\n",
			fileName, operation)
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
		log.Printf("%s %T file: %s\n",
			err, status, statusFile)
		return
	}
	statusCreateFunc(name[0], status)
}
