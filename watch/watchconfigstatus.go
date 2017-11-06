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
	"io/ioutil"
	"log"
	"os"
	"path"
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
				log.Println("watchConfigStatus event:", event)
				// We get create events when file is moved into
				// the watched directory.
				if event.Op&
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Println("modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Println("deleted", baseName)
					fileChanges <- "D " + baseName
				}
			case err := <-w.Errors:
				log.Println("watchConfigStatus error:", err)
			}
		}
	}()

	err = w.Add(configDir)
	if err != nil {
		log.Fatal(err, ": ", configDir)
	}
	files, err := ioutil.ReadDir(configDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		log.Println("watchConfigStatus readdir modified", file.Name())
		fileChanges <- "M " + file.Name()
	}
	log.Printf("Initial ReadDir done for %s\n", configDir)

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
	// Watch for changes
	<-done
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
				log.Println("WatchStatus event:", event)
				// We get create events when file is moved into
				// the watched directory.
				if event.Op&
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Println("modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Println("deleted", baseName)
					fileChanges <- "D " + baseName
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
	files, err := ioutil.ReadDir(statusDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		log.Println("WatchStatus initial modified", file.Name())
		fileChanges <- "M " + file.Name()
	}
	log.Printf("Initial ReadDir done for %s\n", statusDir)

	// Hook to tell restart is done
	fileChanges <- "R done"

	// Watch for changes
	<-done
}
