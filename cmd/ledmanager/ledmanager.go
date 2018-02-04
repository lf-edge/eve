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
	"time"
)

const (
	ledConfigDirName = "/var/tmp/ledmanager/config"
)

var blinkCount int

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
	go watch.WatchStatus(ledConfigDirName, ledChanges)
	log.Println("called watcher...")

	go TriggerBlinkOnDevice()

	for {
		select {
		case change := <-ledChanges:
			{
				log.Println("change: ", change)
				watch.HandleStatusEvent(change,
					ledConfigDirName,
					&types.LedBlinkCounter{},
					handleLedBlinkModify, handleLedBlinkDelete,
					nil)
			}
		}
	}
}

func handleLedBlinkModify(configFilename string,
	configArg interface{}) {
	var config *types.LedBlinkCounter

	if configFilename != "ledconfig" {
		fmt.Printf("handleLedBlinkModify: ignoring %s\n", configFilename)
		return
	}
	switch configArg.(type) {
	default:
		log.Fatal("Can only handle LedBlinkCounter")
	case *types.LedBlinkCounter:
		config = configArg.(*types.LedBlinkCounter)
	}

	log.Printf("handleLedBlinkModify for %s\n", configFilename)
	blinkCount = config.BlinkCounter
	log.Println("value of blinkCount: ", blinkCount)
	log.Printf("handleLedBlinkModify done for %s\n", configFilename)
}

func handleLedBlinkDelete(configFilename string) {
	log.Printf("handleLedBlinkDelete for %s\n", configFilename)

	if configFilename != "ledconfig" {
		fmt.Printf("handleLedBlinkDelete: ignoring %s\n", configFilename)
		return
	}
	UpdateLedManagerConfigFile(0)
	log.Printf("handleDNSDelete done for %s\n", configFilename)
}

func UpdateLedManagerConfigFile(count int) {
	ledConfigFileName := ledConfigDirName + "/ledconfig.json"
	blinkCounter := types.LedBlinkCounter{
		BlinkCounter: count,
	}
	b, err := json.Marshal(blinkCounter)
	if err != nil {
		log.Fatal(err, "json Marshal blinkCount")
	}
	err = ioutil.WriteFile(ledConfigFileName, b, 0644)
	if err != nil {
		log.Fatal("err: ", err, ledConfigFileName)
	}
}

func TriggerBlinkOnDevice() {
	var counter int
	for {
		counter = blinkCount
		log.Println("Number of times LED will blink: ", counter)
		for i := 0; i < counter; i++ {
			ExecuteDDCmd()
			time.Sleep(200 * time.Millisecond)
		}
		time.Sleep(1200 * time.Millisecond)
	}
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
