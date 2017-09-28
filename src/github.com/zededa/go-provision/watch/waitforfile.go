// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Wait for a named file to appear in a given directory

package watch

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"log"
	"os"
	"path/filepath"
)

var debug = false

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
				if debug {
					log.Println("stopping")
				}
				return
			case event := <-w.Events:
				if debug {
					log.Println("event:", event)
				}
				if event.Name != filename {
					if debug {
						log.Println("diff file:", event.Name)
					}
					break
				}
				if event.Op & fsnotify.Create != 0 {
					done <- true
				}
			case err := <-w.Errors:
				log.Println("WaitForFile error:", err)
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
		if debug {
			log.Println("found file:", filename)
		}
		stop <- true
		return
	}
	<-done
	stop <- true
}

func SignalRestart(agent string) {
	log.Printf("SignalRestart(%v)\n", agent)
	restartFile := fmt.Sprintf("/var/tmp/%s/config/restart", agent)
	f, err := os.OpenFile(restartFile, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()
}

func SignalRestarted(agent string) {
	log.Printf("SignalRestarted(%v)\n", agent)
	restartedFile := fmt.Sprintf("/var/run/%s/status/restarted", agent)
	f, err := os.OpenFile(restartedFile, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()
}

func CleanupRestart(agent string) {
	log.Printf("CleanupRestart(%v)\n", agent)
	restartFile := fmt.Sprintf("/var/tmp/%s/config/restart", agent)
	if _, err := os.Stat(restartFile); err == nil {
		if err = os.Remove(restartFile); err != nil {
			log.Fatal(err)
		}
	}
}

func CleanupRestarted(agent string) {
	log.Printf("CleanupRestarted(%v)\n", agent)
	restartedFile := fmt.Sprintf("/var/run/%s/status/restarted", agent)
	if _, err := os.Stat(restartedFile); err == nil {
		if err = os.Remove(restartedFile); err != nil {
			log.Fatal(err)
		}
	}
}
