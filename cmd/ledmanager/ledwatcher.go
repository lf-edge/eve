package main

import (
	"github.com/fsnotify/fsnotify"
	"log"
	"path"
)

type Watcher struct {

}
func (w *Watcher) LedWatcher(ledStatusDir string, fileChanges chan<- string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("error in watch: ", err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-watcher.Events:

				//log.Println("event:", event)
				baseName := path.Base(event.Name)

				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					//log.Println("modified", baseName)
					fileChanges <- "M " + baseName
				} else if event.Op&(fsnotify.Rename|fsnotify.Remove) != 0 {
					//log.Println("deleted", baseName)
					fileChanges <- "D " + baseName
				}

			case err := <-watcher.Errors:
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add(ledStatusDir)
	if err != nil {
		log.Fatal("watch json file err: ", err)
	}
	<-done
}
