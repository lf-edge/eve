// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Determine differences in terms of the set of files in the configDir
// vs. the statusDir.
// On startup report the intial files in configDir as "modified" and report any
// which exist in statusDir but not in configDir as "deleted". Then watch for
// modifications or deletions in configDir.
// Caller needs to determine whether there are actual content modifications
// in the things reported as "modified".

package main

import (
	"github.com/fsnotify/fsnotify"
	"io/ioutil"
	"log"
	"os"
	"path"
)

func WatchConfigStatus(configDir string, statusDir string,
	fileChanges chan<- string) {
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
				// log.Println("event:", event)
				// We get create events when file is moved into
				// the watched directory.
				if event.Op &
					(fsnotify.Write|fsnotify.Create) != 0 {
					// log.Println("modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op &
					(fsnotify.Rename|fsnotify.Remove) != 0 {
					// log.Println("deleted", baseName)
					fileChanges <- "D " + baseName
				}
			case err := <-w.Errors:
				log.Println("error:", err)
			}
		}
	}()

	err = w.Add(configDir)
	if err != nil {
		log.Fatal(err, ": ", configDir)
	}
	files, err := ioutil.ReadDir(configDir)
	if err != nil {
		log.Fatal(err, ": ", configDir)
	}

	for _, file := range files {
		// log.Println("modified", file.Name())
		fileChanges <- "M " + file.Name()
	}

	statusFiles, err := ioutil.ReadDir(statusDir)
	if err != nil {
		log.Fatal(err, ": ", statusDir)
	}

	for _, file := range statusFiles {
		fileName := configDir + "/" + file.Name()
		if _, err := os.Stat(fileName); err != nil {
			// File does not exist in configDir
			// log.Println("deleted", file.Name())
			fileChanges <- "D " + file.Name()
		}
	}
	// Watch for changes
	<-done
}

