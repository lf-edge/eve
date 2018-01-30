package main

import (
	"github.com/zededa/go-provision/watch"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

const (
	ledStatusDirName = "/var/run/ledmanager/status/"
)

var count uint64
var oldBlinkCount uint64

func main() {
	ledChanges := make(chan string)
	//var w Watcher
	//go w.LedWatcher(ledStatusDirName, ledChanges)
	go watch.WatchStatus(ledStatusDirName, ledChanges)
	log.Println("called watcher...")
	for {
		select {
		case change := <-ledChanges:
			{
				log.Println("change: ", change)
				HandleLedBlink(change)
				//HandleLedManagerRestart()
				continue
			}
		}
	}
}
func HandleLedManagerRestart() {
	log.Printf("handleLedmanagerRestarted")
	done := true
	if done {
		watch.SignalRestart("zedmanager")
	}

}
func HandleLedBlink(change string) {

	log.Println("just canhge: ", change)
	ledStatusFileName := ledStatusDirName + "/ledstatus.json"
	testFile := "/var/run/ledmanager/blink.json"

	operation := string(change[0])
	fileName := string(change[2:])

	if !strings.HasSuffix(fileName, ".json") {
		log.Printf("Ignoring file <%s> operation %s\n",
			fileName, operation)
		return
	}
	if operation == "D" {
		err := os.Remove(ledStatusFileName)

		if err != nil {
			log.Println(err)
			return
		}
	}

	if operation != "M" {
		log.Fatal("Unknown operation from Watcher: ",
			operation)
	}

	log.Println("value of count: ", count)
	if count > 0 {
		log.Println("value of count: ", count)
		time.Sleep(time.Second * 1)
	}

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

	if oldBlinkCount == uint64(blinkCount) {
		log.Println("same event: ", blinkCount, oldBlinkCount)
		return
	}
	log.Println("blinkCount: ", blinkCount)
	b, err := json.Marshal(watch)
	if err != nil {
		log.Fatal(err, "json Marshal ledwatcher")
	}
	err = ioutil.WriteFile(testFile, b, 0644)
	if err != nil {
		log.Fatal("err: ", err, testFile)
	}
	oldBlinkCount = uint64(watch.BlinkCounter)
	count++
}
