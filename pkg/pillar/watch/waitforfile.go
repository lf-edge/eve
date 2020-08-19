// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Wait for a named file to appear in a given directory

package watch

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
)

func WaitForFile(filename string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err, ": NewWatcher")
	}
	defer w.Close()

	done := make(chan bool)
	stop := make(chan bool)
	go func() {
		for {
			select {
			case <-stop:
				log.Debugln("WaitForFile: stopping")
				return
			case event := <-w.Events:
				log.Debugln("WaitForFile: event:", event)
				if event.Name != filename {
					log.Debugln("WaitForFile diff file:",
						event.Name)
					break
				}
				if event.Op&fsnotify.Create != 0 {
					done <- true
				}
			case err := <-w.Errors:
				log.Errorln("WaitForFile error:", err)
			}
		}
	}()

	dirname := filepath.Dir(filename)
	err = w.Add(dirname)
	if err != nil {
		log.Fatal(err, ": ", filename)
	}
	_, err = os.Stat(filename)
	if err == nil {
		log.Debugln("WaitForFile found file:", filename)
		stop <- true
		return
	}
	<-done
	stop <- true
}

func signalRestartImpl(agent string, objType string) {

	log.Infof("SignalRestart(%s, %s)\n", agent, objType)
	var restartFile string
	if objType != "" {
		restartFile = fmt.Sprintf("/var/tmp/%s/%s/config/restart",
			agent, objType)
	} else {
		restartFile = fmt.Sprintf("/var/tmp/%s/config/restart", agent)
	}
	f, err := os.OpenFile(restartFile, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()
}

func signalRestartedImpl(agent string, objType string) {

	log.Infof("SignalRestarted(%s, %s)\n", agent, objType)
	var restartedFile string
	if objType != "" {
		restartedFile = fmt.Sprintf("/var/run/%s/%s/status/restarted",
			agent, objType)
	} else {
		restartedFile = fmt.Sprintf("/var/run/%s/status/restarted",
			agent)
	}
	f, err := os.OpenFile(restartedFile, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()
}

func cleanupRestartImpl(agent string, objType string) {

	log.Infof("CleanupRestart(%s, %s)\n", agent, objType)
	var restartFile string
	if objType != "" {
		restartFile = fmt.Sprintf("/var/tmp/%s/%s/config/restart",
			agent, objType)
	} else {
		restartFile = fmt.Sprintf("/var/tmp/%s/config/restart", agent)
	}
	if _, err := os.Stat(restartFile); err == nil {
		if err = os.Remove(restartFile); err != nil {
			log.Fatal(err)
		}
	}
}

func cleanupRestartedImpl(agent string, objType string) {

	log.Infof("CleanupRestarted(%s, %s)\n", agent, objType)
	var restartedFile string
	if objType != "" {
		restartedFile = fmt.Sprintf("/var/run/%s/%s/status/restarted",
			agent, objType)
	} else {
		restartedFile = fmt.Sprintf("/var/run/%s/status/restarted",
			agent)
	}
	if _, err := os.Stat(restartedFile); err == nil {
		if err = os.Remove(restartedFile); err != nil {
			log.Fatal(err)
		}
	}
}

func SignalRestart(agent string) {
	signalRestartImpl(agent, "")
}

func SignalRestartObj(agent string, objType string) {
	signalRestartImpl(agent, objType)
}

func SignalRestarted(agent string) {
	signalRestartedImpl(agent, "")
}

func SignalRestartedObj(agent string, objType string) {
	signalRestartedImpl(agent, objType)
}

func CleanupRestart(agent string) {
	cleanupRestartImpl(agent, "")
}

func CleanupRestartObj(agent string, objType string) {
	cleanupRestartImpl(agent, objType)
}

func CleanupRestarted(agent string) {
	cleanupRestartedImpl(agent, "")
}

func CleanupRestartedObj(agent string, objType string) {
	cleanupRestartedImpl(agent, objType)
}
