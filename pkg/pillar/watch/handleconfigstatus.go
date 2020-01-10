// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Wrapper around WatchConfigStatus to call handler functions

package watch

import (
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"strings"
)

type statusCreateHandler func(ctx interface{}, key string, statuscb []byte)
type statusDeleteHandler func(ctx interface{}, key string)
type StatusRestartHandler func(ctx interface{}, restarted bool)

func HandleStatusEvent(change string, ctx interface{}, statusDirname string,
	statusCreateFunc statusCreateHandler,
	statusDeleteFunc statusDeleteHandler,
	handleRestart *StatusRestartHandler,
	handleComplete *StatusRestartHandler) {

	operation := string(change[0])
	fileName := string(change[2:])
	if operation == "R" {
		log.Infof("Received restart <%s>\n", fileName)
		if handleComplete != nil {
			(*handleComplete)(ctx, true)
		}
		return
	}
	if fileName == "restarted" && operation == "M" {
		log.Debugf("Found restarted file\n")
		if handleRestart != nil {
			(*handleRestart)(ctx, true)
		}
		return
	}

	if !strings.HasSuffix(fileName, ".json") {
		// log.Debugf("Ignoring file <%s> operation %s\n",
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
		log.Errorf("%s for %s\n", err, statusFile)
		return
	}
	statusCreateFunc(ctx, name[0], cb)
}
