package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"time"
)

const (
	ledStatusDirName = "/home/saurabh/examples/ledmanager/status"
)

func main() {
	ledChanges := make(chan string)
	var w Watcher
	go w.LedWatcher(ledStatusDirName, ledChanges)
	log.Println("called watcher...")
	for {
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
	ledStatusFileName := ledStatusDirName + "/ledstatus.json"
	testFile := "/home/saurabh/examples/ledmanager/blink.json"
	var watch = Watcher{}
	cb, err := ioutil.ReadFile(ledStatusFileName)
	if err != nil {
		log.Printf("%s for %s\n", err, ledStatusFileName)
	}
	if err := json.Unmarshal(cb, &watch); err != nil {
		log.Printf("%s %T file: %s\n",
			err, watch, ledStatusFileName)
	}
	blinkCount := watch.BlinkCounter
	log.Println("blinkCount: ", blinkCount)
	b, err := json.Marshal(watch)
	if err != nil {
		log.Fatal(err, "json Marshal ledwatcher")
	}
	err = ioutil.WriteFile(testFile, b, 0644)
	if err != nil {
		log.Fatal("err: ", err, testFile)
	}
	time.Sleep(time.Second * 1)
}
