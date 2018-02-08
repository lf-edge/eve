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
	"flag"
	"fmt"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"log"
	"os"
	"os/exec"
	"time"
)

const (
	ledConfigDirName = "/var/tmp/ledmanager/config"
)

// State passed to handlers
type ledManagerContext struct {
	countChange chan int
}

type Blink200msFunc func()

var debug bool

// Set from Makefile
var Version = "No version specified"

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug")
	flag.Parse()
	debug = *debugPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	log.Printf("Starting ledmanager\n")

	model := hardware.HardwareModel()
	fmt.Printf("Got HardwareModel %s\n", model)

	var blinkFunc Blink200msFunc
	// XXX case insensitive matching?
	// XXX add table when we have more hardware models
	if model == "Supermicro.SYS-E100-9APP" {
		blinkFunc = ExecuteDDCmd
	} else {
		log.Printf("No blink function for %s\n", model)
		blinkFunc = DummyCmd
	}

	ledChanges := make(chan string)
	go watch.WatchStatus(ledConfigDirName, ledChanges)
	log.Println("called watcher...")

	// Any state needed by handler functions
	ctx := ledManagerContext{}
	ctx.countChange = make(chan int)
	go TriggerBlinkOnDevice(ctx.countChange, blinkFunc)

	for {
		select {
		case change := <-ledChanges:
			{
				log.Println("change: ", change)

				watch.HandleStatusEvent(change, &ctx,
					ledConfigDirName,
					&types.LedBlinkCounter{},
					handleLedBlinkModify, handleLedBlinkDelete,
					nil)
			}
		}
	}
}

func handleLedBlinkModify(ctxArg interface{}, configFilename string,
	configArg interface{}) {
	config := configArg.(*types.LedBlinkCounter)
	ctx := ctxArg.(*ledManagerContext)

	if configFilename != "ledconfig" {
		fmt.Printf("handleLedBlinkModify: ignoring %s\n", configFilename)
		return
	}

	log.Printf("handleLedBlinkModify for %s\n", configFilename)
	log.Println("value of blinkCount: ", config.BlinkCounter)
	ctx.countChange <- config.BlinkCounter
	log.Printf("handleLedBlinkModify done for %s\n", configFilename)
}

func handleLedBlinkDelete(ctxArg interface{}, configFilename string) {
	log.Printf("handleLedBlinkDelete for %s\n", configFilename)
	ctx := ctxArg.(*ledManagerContext)

	if configFilename != "ledconfig" {
		fmt.Printf("handleLedBlinkDelete: ignoring %s\n", configFilename)
		return
	}
	// XXX or should we tell the blink go routine to exit?
	ctx.countChange <- 0
	// Update our own input... XXX need something different when pubsub
	types.UpdateLedManagerConfig(0)
	log.Printf("handleLedBlinkDelete done for %s\n", configFilename)
}

func TriggerBlinkOnDevice(countChange chan int, blinkFunc Blink200msFunc) {
	var counter int
	for {
		select {
		case counter = <-countChange:
			log.Printf("Received counter update: %d\n",
				counter)
		default:
			if debug {
				log.Printf("Unchanged counter: %d\n",
					counter)
			}
		}
		if debug {
			log.Println("Number of times LED will blink: ", counter)
		}
		for i := 0; i < counter; i++ {
			blinkFunc()
			time.Sleep(200 * time.Millisecond)
		}
		time.Sleep(1200 * time.Millisecond)
	}
}

func DummyCmd() {
	time.Sleep(200 * time.Millisecond)
}

// Should be tuned so that the LED lights up for 200ms
func ExecuteDDCmd() {
	cmd := exec.Command("dd", "if=/dev/sda", "of=/dev/null", "bs=4M", "count=22")
	stdout, err := cmd.Output()
	if err != nil {
		log.Println("dd error: ", err)
		return
	}
	if debug {
		log.Printf("ddinfo: %s\n", stdout)
	}
}
