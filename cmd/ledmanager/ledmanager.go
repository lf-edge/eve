// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

//watcher tells ledmanager about
//change in ledmanager config file,
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

package ledmanager

import (
	"flag"
	"fmt"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"time"
)

const (
	agentName = "ledmanager"
	ledConfigDirName = "/var/tmp/ledmanager/config"
)

// State passed to handlers
type ledManagerContext struct {
	countChange chan int
}

type Blink200msFunc func()
type BlinkInitFunc func()

type modelToFuncs struct {
	model     string
	initFunc  BlinkInitFunc
	blinkFunc Blink200msFunc
}

var mToF = []modelToFuncs{
	modelToFuncs{
		model:     "Supermicro.SYS-E100-9APP",
		blinkFunc: ExecuteDDCmd},
	modelToFuncs{ // XXX temporary fix for old BIOS
		model:     "Supermicro.Super Server",
		blinkFunc: ExecuteDDCmd},
	modelToFuncs{
		model:     "Supermicro.SYS-E300-8D",
		blinkFunc: ExecuteDDCmd},
	modelToFuncs{
		model:     "Supermicro.SYS-5018D-FN8T",
		blinkFunc: ExecuteDDCmd},
	modelToFuncs{
		model:     "hisilicon,hikey.hisilicon,hi6220.",
		initFunc:  InitWifiLedCmd,
		blinkFunc: ExecuteWifiLedCmd},
	// Last in table as a default
	modelToFuncs{
		model:     "",
		blinkFunc: DummyCmd},
}

var debug bool

// Set from Makefile
var Version = "No version specified"

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
	       log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug")
	flag.Parse()
	debug = *debugPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)

	model := hardware.GetHardwareModel()
	log.Printf("Got HardwareModel %s\n", model)

	var blinkFunc Blink200msFunc
	var initFunc BlinkInitFunc
	for _, m := range mToF {
		if m.model == model {
			blinkFunc = m.blinkFunc
			initFunc = m.initFunc
			break
		}
		if m.model == "" {
			log.Printf("No blink function for %s\n", model)
			blinkFunc = m.blinkFunc
			initFunc = m.initFunc
			break
		}
	}

	if initFunc != nil {
		initFunc()
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
				watch.HandleStatusEvent(change, &ctx,
					ledConfigDirName,
					&types.LedBlinkCounter{},
					handleLedBlinkModify, handleLedBlinkDelete,
					nil)
			}
		}
	}
}

// Supress work and logging if no change
var oldCounter = 0

func handleLedBlinkModify(ctxArg interface{}, configFilename string,
	configArg interface{}) {
	// XXX switch to using cast?
	config := configArg.(*types.LedBlinkCounter)
	ctx := ctxArg.(*ledManagerContext)

	if configFilename != "ledconfig" {
		log.Printf("handleLedBlinkModify: ignoring %s\n", configFilename)
		return
	}
	// Supress work and logging if no change
	if config.BlinkCounter == oldCounter {
		return
	}
	oldCounter = config.BlinkCounter
	log.Printf("handleLedBlinkModify for %s\n", configFilename)
	log.Println("value of blinkCount: ", config.BlinkCounter)
	ctx.countChange <- config.BlinkCounter
	log.Printf("handleLedBlinkModify done for %s\n", configFilename)
}

func handleLedBlinkDelete(ctxArg interface{}, configFilename string) {
	log.Printf("handleLedBlinkDelete for %s\n", configFilename)
	ctx := ctxArg.(*ledManagerContext)

	if configFilename != "ledconfig" {
		log.Printf("handleLedBlinkDelete: ignoring %s\n", configFilename)
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
// Disable cache since there might be a filesystem on the device
func ExecuteDDCmd() {
	cmd := exec.Command("dd", "if=/dev/sda", "of=/dev/null", "bs=4M", "count=22", "iflag=nocache")
	stdout, err := cmd.Output()
	if err != nil {
		log.Println("dd error: ", err)
		return
	}
	if debug {
		log.Printf("ddinfo: %s\n", stdout)
	}
}

const (
	ledFilename        = "/sys/class/leds/wifi_active"
	triggerFilename    = ledFilename + "/trigger"
	brightnessFilename = ledFilename + "/brightness"
)

// Disable existimg trigger
// Write "none\n" to /sys/class/leds/wifi_active/trigger
func InitWifiLedCmd() {
	log.Printf("InitWifiLedCmd\n")
	b := []byte("none")
	err := ioutil.WriteFile(triggerFilename, b, 0644)
	if err != nil {
		log.Fatal(err, triggerFilename)
	}
}

// Enable the Wifi led for 200ms
func ExecuteWifiLedCmd() {
	b := []byte("1")
	err := ioutil.WriteFile(brightnessFilename, b, 0644)
	if err != nil {
		log.Fatal(err, brightnessFilename)
	}
	time.Sleep(200 * time.Millisecond)
	b = []byte("0")
	err = ioutil.WriteFile(brightnessFilename, b, 0644)
	if err != nil {
		log.Fatal(err, brightnessFilename)
	}
}
