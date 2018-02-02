// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

//watcher tells ledmanager about
//change in ledmanager status file,
//which contains number of times
//LED has to blink on any device
//ledmanager notify each event by
//triggering blink on device.
//number of blink is equal to
//blink counter received by status
//file...
//After each blink we will take
//pause of 200ms.
//After end of each event we will take
//pause of 1200ms...

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	ledStatusDirName = "/var/run/ledmanager/status/"
)

var count uint64
var oldBlinkCount uint64

// Set from Makefile
var Version = "No version specified"

func main() {

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	versionPtr := flag.Bool("v", false, "Version")
	flag.Parse()
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	log.Printf("Starting ledmanager\n")

	ledChanges := make(chan string)
	go watch.WatchStatus(ledStatusDirName, ledChanges)
	log.Println("called watcher...")
	for {
		select {
		case change := <-ledChanges:
			{
				log.Println("change: ", change)
				HandleLedBlink(change)
				continue
			}
		}
	}
}
func HandleLedBlink(change string) {

	ledStatusFileName := ledStatusDirName + "/ledstatus.json"

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
		time.Sleep(1200 * time.Millisecond)
	}

	var countBlink = types.LedBlinkCounter{}
	cb, err := ioutil.ReadFile(ledStatusFileName)
	if err != nil {
		log.Printf("%s for %s\n", err, ledStatusFileName)
	}
	if err := json.Unmarshal(cb, &countBlink); err != nil {
		log.Printf("%s %T file: %s\n",
			err, countBlink, ledStatusFileName)
	}
	blinkCount := countBlink.BlinkCounter

	if oldBlinkCount == uint64(blinkCount) {
		log.Println("same event: ", blinkCount, oldBlinkCount)
		return
	}
	log.Println("blinkCount: ", blinkCount)

	for i := 0; i < blinkCount; i++ {
		ExecuteDDCmd()
		time.Sleep(200 * time.Millisecond)
	}

	oldBlinkCount = uint64(countBlink.BlinkCounter)
	count++
}

func ExecuteDDCmd() {

	cmd := exec.Command("sudo", "dd", "if=/dev/sda", "of=/dev/null", "bs=4M", "count=22")
	stdout, err := cmd.Output()
	if err != nil {
		println("error: ", err.Error())
	}

	ddInfo := fmt.Sprintf("%s", stdout)
	log.Println("ddinfo: ", ddInfo)
}
