package main

import (
	"log"
	"io/ioutil"
	"encoding/json"
)

const (
	ledStatusDirName = "/home/saurabh/examples/ledmanager/status"
)
func main() {
	ledChanges := make(chan string)
	var w Watcher
	go w.LedWatcher(ledStatusDirName, ledChanges)
	log.Println("called watcher...")
	done := false
	for !done {
		select {
		case change := <-ledChanges:
			{
				log.Println("change: ", change)
				HandleLedBlink()
			}
		}
	}
}

func HandleLedBlink() {
	ledStatusFileName := ledStatusDirName+"/ledstatus.json"
	var watch = Watcher{}
	cb, err := ioutil.ReadFile(ledStatusFileName)
	if err != nil {
		log.Printf("%s for %s\n", err, ledStatusFileName)
	}
	if err := json.Unmarshal(cb, &watch); err != nil {
		log.Printf("%s %T file: %s\n",
			err, watch,ledStatusFileName)
	}
	blinkCount := watch.BlinkCounter
	log.Println("blinkCount: ",blinkCount)
}
