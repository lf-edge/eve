// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Wrapper around WatchConfigStatus to call handler functions

package watch

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"
)

// Common interfaces for *Status and *Config
type ZedConfig interface {
	Key() string
	VerifyFilename(fileName string) bool
}

type ZedStatus interface {
	Key() string
	VerifyFilename(fileName string) bool
	CheckPendingAdd() bool
	CheckPendingModify() bool
	CheckPendingDelete() bool
}

type configCreateHandler func(ctx interface{}, key string, config interface{})
type configModifyHandler func(ctx interface{}, key string, config interface{},
	status interface{})
type configDeleteHandler func(ctx interface{}, key string, status interface{})
type ConfigRestartHandler func(ctx interface{}, restarted bool)

func HandleConfigStatusEvent(change string, ctx interface{},
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
			(*handleRestart)(ctx, true)
		}
		return
	}
	if !strings.HasSuffix(fileName, ".json") {
		// log.Printf("Ignoring file <%s> operation %s\n",
		//	fileName, operation)
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
		handleDelete(ctx, statusName, status)
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
		handleCreate(ctx, statusName, config)
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
		handleCreate(ctx, statusName, config)
		return
	}
	if status.CheckPendingDelete() {
		statusName := statusDirname + "/" + fileName
		handleDelete(ctx, statusName, status)
		return
	}
	if status.CheckPendingModify() {
		statusName := statusDirname + "/" + fileName
		handleModify(ctx, statusName, config, status)
		return
	}
	statusName := statusDirname + "/" + fileName
	handleModify(ctx, statusName, config, status)
}

type statusCreateHandler func(ctx interface{}, key string, status interface{})
type statusDeleteHandler func(ctx interface{}, key string)
type StatusRestartHandler func(ctx interface{}, restarted bool)

func HandleStatusEvent(change string, ctx interface{},
	statusDirname string, status interface{},
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
		if debug {
			log.Printf("Found restarted file\n")
		}
		if handleRestart != nil {
			(*handleRestart)(ctx, true)
		}
		return
	}

	if !strings.HasSuffix(fileName, ".json") {
		// log.Printf("Ignoring file <%s> operation %s\n",
		//	fileName, operation)
		return
	}
	// Remove .json from name */
	name := strings.Split(fileName, ".json")
	if operation == "D" {
		statusDeleteFunc(ctx, name[0])
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
	statusCreateFunc(ctx, name[0], status)
}
