// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Determine differences in terms of the set of files in the configDir
// vs. the statusDir.
// On startup report the intial files in configDir as "modified" and report any
// which exist in statusDir but not in configDir as "deleted". Then watch for
// modifications or deletions in configDir.
// Caller needs to determine whether there are actual content modifications
// in the things reported as "modified".

package watch

import (
	"github.com/fsnotify/fsnotify"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"
)

// Generates 'M' events for all existing and all creates/modify.
// Generates 'D' events for all deletes.
// Generates a 'R' event when the initial directories have been processed
func WatchConfigStatus(configDir string, statusDir string,
	fileChanges chan<- string) {
	watchConfigStatusImpl(configDir, statusDir, fileChanges, true)
}

// Like above but don't delete status just because config does not
// initially exist.
func WatchConfigStatusAllowInitialConfig(configDir string, statusDir string,
	fileChanges chan<- string) {
	watchConfigStatusImpl(configDir, statusDir, fileChanges, false)
}

func watchConfigStatusImpl(configDir string, statusDir string,
	fileChanges chan<- string, initialDelete bool) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err, ": NewWatcher")
	}
	defer w.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-w.Events:
				baseName := path.Base(event.Name)
				// log.Debugln("WatchConfigStatus event:", event)

				// We get create events when file is moved into
				// the watched directory.
				if event.Op&
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Debugln("WatchConfigStatus modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&fsnotify.Chmod != 0 {
					// log.Debugln("WatchConfigStatus chmod", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Debugln("WatchConfigStatus deleted", baseName)
					fileChanges <- "D " + baseName
				} else {
					log.Errorln("WatchConfigStatus unknown ",
						event, baseName)
				}
			case err := <-w.Errors:
				log.Errorln("WatchConfigStatus error:", err)
			}
		}
	}()

	err = w.Add(configDir)
	if err != nil {
		log.Error(err, " Inintial Add: ", configDir)
		// Check again when timer fires
	}
	// log.Debugln("WatchConfigStatus added", configDir)

	foundRestart, foundRestarted := watchReadDir(configDir, fileChanges,
		false, true)

	if initialDelete {
		statusFiles, err := ioutil.ReadDir(statusDir)
		if err != nil {
			log.Fatal(err)
		}

		for _, file := range statusFiles {
			fileName := configDir + "/" + file.Name()
			if _, err := os.Stat(fileName); err != nil {
				// File does not exist in configDir
				log.Infoln("Initial delete", file.Name())
				fileChanges <- "D " + file.Name()
			}
		}
		log.Infof("Initial deletes done for %s\n", statusDir)
	}
	// Hook to tell restart is done
	fileChanges <- "R done"
	if foundRestart {
		fileChanges <- "M " + "restart"
	}
	if foundRestarted {
		fileChanges <- "M " + "restarted"
	}

	// Watch for changes or timeout
	interval := 10 * time.Minute
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	for {
		select {
		case <-done:
			log.Errorln("WatchConfigStatus channel done; terminating")
			break
		case <-ticker.C:
			// Remove and re-add
			// XXX do we also need to re-scan?
			// log.Debugln("WatchConfigStatus remove/re-add", configDir)
			err = w.Remove(configDir)
			if err != nil {
				log.Error(err, " Remove: ", configDir)
			}
			err = w.Add(configDir)
			if err != nil {
				log.Error(err, " Add: ", configDir)
				// Check again when timer fires
				continue
			}
			foundRestart, foundRestarted := watchReadDir(configDir,
				fileChanges, true, true)
			if foundRestart {
				fileChanges <- "M " + "restart"
			}
			if foundRestarted {
				fileChanges <- "M " + "restarted"
			}
		}
	}
}

// Only reads json files if jsonOnly is set.
// Returns restart, restarted booleans if files of those names were found.
// XXX remove "restart" once no longer needed
func watchReadDir(configDir string, fileChanges chan<- string, retry bool,
	jsonOnly bool) (bool, bool) {

	foundRestart := false
	foundRestarted := false
	files, err := ioutil.ReadDir(configDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			if file.Name() == "restart" {
				foundRestart = true
			}
			if file.Name() == "restarted" {
				foundRestarted = true
			}
			if jsonOnly && file.Name() != "global" {
				continue
			}
		}
		if retry {
			log.Debugln("watchReadDir retry modified",
				configDir, file.Name())
		} else {
			log.Infoln("watchReadDir modified", file.Name())
		}
		fileChanges <- "M " + file.Name()
	}
	if !retry {
		log.Infof("watchReadDir done for %s\n", configDir)
	}
	return foundRestart, foundRestarted
}

// Generates 'M' events for all existing and all creates/modify.
// Generates 'D' events for all deletes.
// Generates a 'R' event when the initial directories have been processed
func WatchStatus(statusDir string, jsonOnly bool, fileChanges chan<- string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err, ": NewWatcher")
	}
	defer w.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-w.Events:
				baseName := path.Base(event.Name)
				// log.Debugln("WatchStatus event:", event)

				// We get create events when file is moved into
				// the watched directory.
				if event.Op&
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Debugln("WatchStatus modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&fsnotify.Chmod != 0 {
					// log.Debugln("WatchStatus chmod", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Debugln("WatchStatus deleted", baseName)
					fileChanges <- "D " + baseName
				} else {
					log.Errorln("WatchStatus unknown", event, baseName)
				}

			case err := <-w.Errors:
				log.Errorln("WatchStatus error:", err)
			}
		}
	}()

	err = w.Add(statusDir)
	if err != nil {
		log.Error(err, " Inintial Add: ", statusDir)
		// Check again when timer fires
	}
	// log.Debugln("WatchStatus added", statusDir)

	foundRestart, foundRestarted := watchReadDir(statusDir, fileChanges,
		false, jsonOnly)

	// Hook to tell restart is done
	fileChanges <- "R done"

	if foundRestart {
		fileChanges <- "M " + "restart"
	}
	if foundRestarted {
		fileChanges <- "M " + "restarted"
	}

	// Watch for changes or timeout
	interval := 10 * time.Minute
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	for {
		select {
		case <-done:
			log.Errorln("WatchStatus channel done; terminating")
			break
		case <-ticker.C:
			// Remove and re-add
			// XXX do we also need to re-scan?
			// log.Debugln("WatchStatus remove/re-add", statusDir)
			err = w.Remove(statusDir)
			if err != nil {
				log.Error(err, " Remove: ", statusDir)
			}
			err = w.Add(statusDir)
			if err != nil {
				log.Error(err, " Add: ", statusDir)
				// Try again on next timeout
				continue
			}
			foundRestart, foundRestarted := watchReadDir(statusDir,
				fileChanges, true, jsonOnly)
			if foundRestart {
				fileChanges <- "M " + "restart"
			}
			if foundRestarted {
				fileChanges <- "M " + "restarted"
			}
		}
	}
}
