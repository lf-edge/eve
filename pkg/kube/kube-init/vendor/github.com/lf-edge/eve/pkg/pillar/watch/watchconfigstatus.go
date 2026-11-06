// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Determine differences in terms of the set of files in the configDir
// vs. the statusDir.
// On startup report the initial files in configDir as "modified" and report any
// which exist in statusDir but not in configDir as "deleted". Then watch for
// modifications or deletions in configDir.
// Caller needs to determine whether there are actual content modifications
// in the things reported as "modified".

package watch

import (
	"os"
	"path"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
)

// Only reads json files if jsonOnly is set.
// Returns restart, restarted booleans if files of those names were found.
// XXX remove "restart" once no longer needed
func watchReadDir(log *base.LogObject, configDir string, fileChanges chan<- string, retry bool,
	jsonOnly bool) (bool, bool) {

	foundRestart := false
	foundRestarted := false
	files, err := os.ReadDir(configDir)
	if err != nil {
		log.Fatalf("***watchReadDir - Failed to read Directory %s . err: %s",
			configDir, err)
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
			log.Traceln("watchReadDir retry modified",
				configDir, file.Name())
		} else {
			log.Functionln("watchReadDir modified", file.Name())
		}
		fileChanges <- "M " + file.Name()
	}
	if !retry {
		log.Functionf("watchReadDir done for %s\n", configDir)
	}
	return foundRestart, foundRestarted
}

// Generates 'M' events for all existing and all creates/modify.
// Generates 'D' events for all deletes.
// Generates a 'R' event when the initial directories have been processed
// This assumes that the caller ensures that the restart and restarted files
// are handled last in a set of changes close in time, since
// the directory can see multiple modifications (content and attributes) and in
// different order.
func WatchStatus(log *base.LogObject, statusDir string, jsonOnly bool, doneChan <-chan struct{}, fileChanges chan<- string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err, ": NewWatcher")
	}
	defer w.Close()

	funcDone := make(chan struct{})
	go func() {
		done := false
		for !done {
			select {
			case _, ok := <-doneChan:
				if !ok {
					done = true
					break
				}
				log.Fatal("WatchStatus func received message on doneChan")

			case event := <-w.Events:
				baseName := path.Base(event.Name)
				// log.Traceln("WatchStatus event:", event)

				// We get create events when file is moved into
				// the watched directory.
				if event.Op&
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Traceln("WatchStatus modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&fsnotify.Chmod != 0 {
					// log.Traceln("WatchStatus chmod", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Traceln("WatchStatus deleted", baseName)
					fileChanges <- "D " + baseName
				} else {
					log.Errorln("WatchStatus unknown", event, baseName)
				}

			case err := <-w.Errors:
				log.Errorln("WatchStatus error:", err)
			}
		}
		close(funcDone)
		log.Warnf("WatchStatus func goroutine exiting")
	}()

	err = w.Add(statusDir)
	if err != nil {
		log.Error(err, " Inintial Add: ", statusDir)
		// Check again when timer fires
	}
	// log.Traceln("WatchStatus added", statusDir)

	foundRestart, foundRestarted := watchReadDir(log, statusDir, fileChanges,
		false, jsonOnly)

	// Hook to tell restart is done
	fileChanges <- "R done"

	if foundRestart {
		fileChanges <- "M " + "restart"
	}
	if foundRestarted {
		fileChanges <- "M " + "restarted"
	}

	// Watch for changes or timeout. This is to any issues where fsnotify
	// fails to deliver some notification.
	interval := 10 * time.Minute
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	done := false
	for !done {
		select {
		case _, ok := <-doneChan:
			if !ok {
				done = true
				break
			}
			log.Fatal("WatchStatus received message on doneChan")

		case <-ticker.C:
			// Remove and re-add
			// We also re-scan the directory for any changed we
			// missed.
			// log.Traceln("WatchStatus remove/re-add", statusDir)
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
			foundRestart, foundRestarted := watchReadDir(log, statusDir,
				fileChanges, true, jsonOnly)
			if foundRestart {
				fileChanges <- "M " + "restart"
			}
			if foundRestarted {
				fileChanges <- "M " + "restarted"
			}
		}
	}
	// Wait for above func to be done
	<-funcDone
	ticker.StopTicker()
	close(fileChanges)
	log.Warnf("WatchStatus goroutine exiting")
}
