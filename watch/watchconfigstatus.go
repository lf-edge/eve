// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

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
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/flextimer"
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
				// log.Println("WatchConfigStatus event:", event)

				// We get create events when file is moved into
				// the watched directory.
				if event.Op&
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Println("WatchConfigStatus modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&fsnotify.Chmod != 0 {
					// log.Println("WatchConfigStatus chmod", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Println("WatchConfigStatus deleted", baseName)
					fileChanges <- "D " + baseName
				} else {
					log.Println("WatchConfigStatus unknown ", event, baseName)
				}
			case err := <-w.Errors:
				log.Println("WatchConfigStatus error:", err)
			}
		}
	}()

	err = w.Add(configDir)
	if err != nil {
		log.Fatal(err, ": ", configDir)
	}
	// log.Println("WatchConfigStatus added", configDir)

	foundRestart, foundRestarted := watchReadDir(configDir, fileChanges,
		false)

	if initialDelete {
		statusFiles, err := ioutil.ReadDir(statusDir)
		if err != nil {
			log.Fatal(err)
		}

		for _, file := range statusFiles {
			fileName := configDir + "/" + file.Name()
			if _, err := os.Stat(fileName); err != nil {
				// File does not exist in configDir
				log.Println("Initial delete", file.Name())
				fileChanges <- "D " + file.Name()
			}
		}
		log.Printf("Initial deletes done for %s\n", statusDir)
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
			log.Println("WatchConfigStatus channel done; terminating")
			// XXX log.Fatal?
			break
		case <-ticker.C:
			// Remove and re-add
			// XXX do we also need to re-scan?
			// log.Println("WatchConfigStatus remove/re-add", configDir)
			err = w.Remove(configDir)
			if err != nil {
				log.Fatal(err, "Remove: ", configDir)
			}
			err = w.Add(configDir)
			if err != nil {
				log.Fatal(err, "Add: ", configDir)
			}
			foundRestart, foundRestarted := watchReadDir(configDir,
				fileChanges, true)
			if foundRestart {
				fileChanges <- "M " + "restart"
			}
			if foundRestarted {
				fileChanges <- "M " + "restarted"
			}
		}
	}
}

// Only reads json files. Returns restart, restarted booleans if files of those
// names were found.
// XXX remove "restart" once no longer needed
func watchReadDir(configDir string, fileChanges chan<- string, retry bool) (bool, bool) {
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
			if file.Name() != "global" {
				continue
			}
		}
		if retry {
			log.Debugln("watchReadDir retry modified",
				configDir, file.Name())
		} else {
			log.Println("watchReadDir modified", file.Name())
		}
		fileChanges <- "M " + file.Name()
	}
	if !retry {
		log.Printf("watchReadDir done for %s\n", configDir)
	}
	return foundRestart, foundRestarted
}

// Generates 'M' events for all existing and all creates/modify.
// Generates 'D' events for all deletes.
// Generates a 'R' event when the initial directories have been processed
func WatchStatus(statusDir string, fileChanges chan<- string) {
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
				// log.Println("WatchStatus event:", event)

				// We get create events when file is moved into
				// the watched directory.
				if event.Op&
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Println("WatchStatus modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&fsnotify.Chmod != 0 {
					// log.Println("WatchStatus chmod", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Println("WatchStatus deleted", baseName)
					fileChanges <- "D " + baseName
				} else {
					log.Println("WatchStatus unknown", event, baseName)
				}

			case err := <-w.Errors:
				log.Println("WatchStatus error:", err)
			}
		}
	}()

	err = w.Add(statusDir)
	if err != nil {
		log.Fatal(err, ": ", statusDir)
	}
	// log.Println("WatchStatus added", statusDir)

	foundRestart, foundRestarted := watchReadDir(statusDir, fileChanges,
		false)

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
			log.Println("WatchStatus channel done; terminating")
			// XXX log.Fatal?
			break
		case <-ticker.C:
			// Remove and re-add
			// XXX do we also need to re-scan?
			// log.Println("WatchStatus remove/re-add", statusDir)
			err = w.Remove(statusDir)
			if err != nil {
				log.Fatal(err, "Remove: ", statusDir)
			}
			err = w.Add(statusDir)
			if err != nil {
				log.Fatal(err, "Add: ", statusDir)
			}
			foundRestart, foundRestarted := watchReadDir(statusDir,
				fileChanges, true)
			if foundRestart {
				fileChanges <- "M " + "restart"
			}
			if foundRestarted {
				fileChanges <- "M " + "restarted"
			}
		}
	}
}
