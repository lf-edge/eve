// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

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
	"golang.org/x/sys/unix"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	agentName        = "ledmanager"
	ledConfigDirName = "/var/tmp/ledmanager/config"
)

// State passed to handlers
type ledManagerContext struct {
	countChange            chan int
	ledCounter             int // Supress work and logging if no change
	subGlobalConfig        pubsub.Subscription
	subLedBlinkCounter     pubsub.Subscription
	subDeviceNetworkStatus pubsub.Subscription
	deviceNetworkStatus    types.DeviceNetworkStatus
	usableAddressCount     int
	derivedLedCounter      int // Based on ledCounter + usableAddressCount
	GCInitialized          bool
}

type Blink200msFunc func(ledName string)
type BlinkInitFunc func(ledName string)

// The ledName is a string like wifi_active in /sys/class/leds
type modelToFuncs struct {
	model     string
	initFunc  BlinkInitFunc
	blinkFunc Blink200msFunc
	ledName   string
}

// XXX introduce wildcard matching on model names? Just a default at the end
var mToF = []modelToFuncs{
	{
		model:     "Supermicro.SYS-E100-9APP",
		initFunc:  InitDDCmd,
		blinkFunc: ExecuteDDCmd,
	},
	{
		model:     "Supermicro.SYS-E100-9S",
		initFunc:  InitDDCmd,
		blinkFunc: ExecuteDDCmd},
	{
		model:     "Supermicro.SYS-E50-9AP",
		initFunc:  InitDDCmd,
		blinkFunc: ExecuteDDCmd,
	},
	{ // XXX temporary fix for old BIOS
		model:     "Supermicro.Super Server",
		initFunc:  InitDDCmd,
		blinkFunc: ExecuteDDCmd,
	},
	{
		model:     "Supermicro.SYS-E300-8D",
		initFunc:  InitDDCmd,
		blinkFunc: ExecuteDDCmd,
	},
	{
		model:     "Supermicro.SYS-E300-9A-4CN10P",
		initFunc:  InitDDCmd,
		blinkFunc: ExecuteDDCmd,
	},
	{
		model:     "Supermicro.SYS-5018D-FN8T",
		initFunc:  InitDDCmd,
		blinkFunc: ExecuteDDCmd,
	},
	{
		model:     "Dell Inc..Edge Gateway 3001",
		initFunc:  InitDellCmd,
		blinkFunc: ExecuteLedCmd,
		ledName:   "/sys/class/gpio/gpio346/value",
	},
	{
		model:     "Dell Inc..Edge Gateway 3002",
		initFunc:  InitDellCmd,
		blinkFunc: ExecuteLedCmd,
		ledName:   "/sys/class/gpio/gpio346/value",
	},
	{
		model:     "Dell Inc..Edge Gateway 3003",
		initFunc:  InitDellCmd,
		blinkFunc: ExecuteLedCmd,
		ledName:   "/sys/class/gpio/gpio346/value",
	},
	{
		model:     "hisilicon,hi6220-hikey.hisilicon,hi6220.",
		initFunc:  InitLedCmd,
		blinkFunc: ExecuteLedCmd,
		ledName:   "wifi_active",
	},
	{
		model:     "hisilicon,hikey.hisilicon,hi6220.",
		initFunc:  InitLedCmd,
		blinkFunc: ExecuteLedCmd,
		ledName:   "wifi_active"},
	{
		model:     "LeMaker.HiKey-6220",
		initFunc:  InitLedCmd,
		blinkFunc: ExecuteLedCmd,
		ledName:   "wifi_active",
	},
	{
		model: "QEMU.Standard PC (i440FX + PIIX, 1996)",
		// No dd disk light blinking on QEMU
	},
	{
		model: "QEMU Standard PC (Q35 + ICH9, 2009)",
		// No dd disk light blinking on QEMU
	},
	{
		model:     "raspberrypi.rpi.raspberrypi,4-model-b.brcm,bcm2711",
		initFunc:  InitLedCmd,
		blinkFunc: ExecuteLedCmd,
		ledName:   "led0",
	},
	{
		model:     "RaspberryPi.RPi4",
		initFunc:  InitLedCmd,
		blinkFunc: ExecuteLedCmd,
		ledName:   "led0",
	},
	{
		// Last in table as a default
		model:     "",
		initFunc:  InitDDCmd,
		blinkFunc: ExecuteDDCmd,
	},
}

var debug bool
var debugOverride bool // From command line arg
var logger *logrus.Logger
var log *base.LogObject

// Set from Makefile
var Version = "No version specified"

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug")
	fatalPtr := flag.Bool("F", false, "Cause log.Fatal fault injection")
	hangPtr := flag.Bool("H", false, "Cause watchdog .touch fault injection")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	fatalFlag := *fatalPtr
	hangFlag := *hangPtr
	if debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return 0
	}
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}
	log.Functionf("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	model := hardware.GetHardwareModel(log)
	log.Functionf("Got HardwareModel %s", model)

	var blinkFunc Blink200msFunc
	var initFunc BlinkInitFunc
	var ledName string
	for _, m := range mToF {
		if m.model == model {
			blinkFunc = m.blinkFunc
			initFunc = m.initFunc
			ledName = m.ledName
			log.Functionf("Found %v led %s for model %s",
				blinkFunc, ledName, model)
			break
		}
		if m.model == "" {
			log.Functionf("No blink function for %s", model)
			blinkFunc = m.blinkFunc
			initFunc = m.initFunc
			ledName = m.ledName
			break
		}
	}

	if initFunc != nil {
		initFunc(ledName)
	}

	// Any state needed by handler functions
	ctx := ledManagerContext{}
	ctx.countChange = make(chan int)
	log.Functionf("Creating %s at %s", "triggerBinkOnDevice", agentlog.GetMyStack())
	go TriggerBlinkOnDevice(ctx.countChange, blinkFunc, ledName)

	subLedBlinkCounter, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		MyAgentName:   agentName,
		TopicImpl:     types.LedBlinkCounter{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleLedBlinkCreate,
		ModifyHandler: handleLedBlinkModify,
		DeleteHandler: handleLedBlinkDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subLedBlinkCounter = subLedBlinkCounter
	subLedBlinkCounter.Activate()

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleDNSCreate,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subLedBlinkCounter.MsgChan():
			subLedBlinkCounter.ProcessChange(change)

		case <-stillRunning.C:
			// Fault injection
			if fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if hangFlag {
			log.Functionf("Requested to not touch to cause watchdog")
		} else {
			ps.StillRunning(agentName, warningTime, errorTime)
		}
	}
}

func handleLedBlinkCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleLedBlinkImpl(ctxArg, key, configArg)
}

func handleLedBlinkModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleLedBlinkImpl(ctxArg, key, configArg)
}

func handleLedBlinkImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	config := configArg.(types.LedBlinkCounter)
	ctx := ctxArg.(*ledManagerContext)

	if key != "ledconfig" {
		log.Errorf("handleLedBlinkImpl: ignoring %s", key)
		return
	}
	// Supress work and logging if no change
	if config.BlinkCounter == ctx.ledCounter {
		return
	}
	ctx.ledCounter = config.BlinkCounter
	ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
		ctx.usableAddressCount)
	log.Functionf("counter %d usableAddr %d, derived %d",
		ctx.ledCounter, ctx.usableAddressCount, ctx.derivedLedCounter)
	ctx.countChange <- ctx.derivedLedCounter
	log.Functionf("handleLedBlinkImpl done for %s", key)
}

func handleLedBlinkDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleLedBlinkDelete for %s", key)
	ctx := ctxArg.(*ledManagerContext)

	if key != "ledconfig" {
		log.Errorf("handleLedBlinkDelete: ignoring %s", key)
		return
	}
	// XXX or should we tell the blink go routine to exit?
	ctx.ledCounter = 0
	ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
		ctx.usableAddressCount)
	log.Functionf("counter %d usableAddr %d, derived %d",
		ctx.ledCounter, ctx.usableAddressCount, ctx.derivedLedCounter)
	ctx.countChange <- ctx.derivedLedCounter
	log.Functionf("handleLedBlinkDelete done for %s", key)
}

func TriggerBlinkOnDevice(countChange chan int, blinkFunc Blink200msFunc,
	ledName string) {

	var counter int
	for {
		select {
		case counter = <-countChange:
			log.Tracef("Received counter update: %d",
				counter)
		default:
			log.Tracef("Unchanged counter: %d", counter)
		}
		log.Traceln("Number of times LED will blink: ", counter)
		for i := 0; i < counter; i++ {
			if blinkFunc != nil {
				blinkFunc(ledName)
			}
			time.Sleep(200 * time.Millisecond)
		}
		time.Sleep(1200 * time.Millisecond)
	}
}

func DummyCmd() {
	time.Sleep(200 * time.Millisecond)
}

var printOnce = true
var diskDevice string // Based on largest disk
var ddCount int       // Based on time for 200ms

// InitDellCmd prepares "Cloud LED" on Dell IoT gateways by enabling GPIO endpoint
func InitDellCmd(ledName string) {
	err := ioutil.WriteFile("/sys/class/gpio/export", []byte("346"), 0644)
	if err == nil {
		if err = ioutil.WriteFile("/sys/class/gpio/gpio346/direction", []byte("out"), 0644); err == nil {
			log.Functionf("Enabled Dell Cloud LED")
			return
		}
	}
	log.Warnf("Failed to enable Dell Cloud LED: %v", err)
}

// Keep avoid allocation and GC by keeping one buffer
var (
	bufferLength = int64(256 * 1024) //256k buffer length
	readBuffer   []byte
)

// InitDDCmd determines the disk (using the largest disk) and measures
// the repetition count to get to 200ms dd time.
func InitDDCmd(ledName string) {
	disk := diskmetrics.FindLargestDisk(log)
	if disk == "" {
		return
	}
	log.Functionf("InitDDCmd using disk %s", disk)
	readBuffer = make([]byte, bufferLength)
	diskDevice = "/dev/" + disk
	count := 100 * 16
	// Prime before measuring
	uncachedDiskRead(count)
	uncachedDiskRead(count)
	start := time.Now()
	uncachedDiskRead(count)
	elapsed := time.Since(start)
	if elapsed == 0 {
		log.Errorf("Measured 0 nanoseconds!")
		return
	}
	// Adjust count but at least one
	fl := time.Duration(count) * (200 * time.Millisecond) / elapsed
	count = int(fl)
	if count == 0 {
		count = 1
	}
	log.Noticef("Measured %v; count %d", elapsed, count)
	ddCount = count
}

// Should be tuned so that the LED lights up for 200ms
// Disable cache since there might be a filesystem on the device
func ExecuteDDCmd(ledName string) {
	if diskDevice == "" || ddCount == 0 {
		DummyCmd()
		return
	}
	uncachedDiskRead(ddCount)
}

func uncachedDiskRead(count int) {
	offset := int64(0)
	handler, err := os.Open(diskDevice)
	if err != nil {
		err = fmt.Errorf("uncachedDiskRead: Failed on open: %s", err)
		log.Error(err.Error())
		return
	}
	defer handler.Close()
	for i := 0; i < count; i++ {
		unix.Fadvise(int(handler.Fd()), offset, bufferLength, 4) // 4 == POSIX_FADV_DONTNEED
		readBytes, err := handler.Read(readBuffer)
		if err != nil {
			err = fmt.Errorf("uncachedDiskRead: Failed on read: %s", err)
			log.Error(err.Error())
		}
		syscall.Madvise(readBuffer, 4) // 4 == MADV_DONTNEED
		log.Tracef("uncachedDiskRead: size: %d", readBytes)
		if int64(readBytes) < bufferLength {
			log.Tracef("uncachedDiskRead: done")
			break
		}
		offset += bufferLength
	}
}

const (
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// InitLedCmd can use different LEDs in /sys/class/leds
// Disable existing trigger
// Write "none" to /sys/class/leds/<ledName>/trigger
func InitLedCmd(ledName string) {
	log.Functionf("InitLedCmd(%s)", ledName)
	triggerFilename := fmt.Sprintf("/sys/class/leds/%s/trigger", ledName)
	b := []byte("none")
	err := ioutil.WriteFile(triggerFilename, b, 0644)
	if err != nil {
		log.Error(err, triggerFilename)
	}
}

// ExecuteLedCmd can use different LEDs in /sys/class/leds
// Enable the led for 200ms
func ExecuteLedCmd(ledName string) {
	var brightnessFilename string
	b := []byte("1")
	if strings.HasPrefix(ledName, "/") {
		brightnessFilename = ledName
	} else {
		brightnessFilename = fmt.Sprintf("/sys/class/leds/%s/brightness", ledName)
	}
	err := ioutil.WriteFile(brightnessFilename, b, 0644)
	if err != nil {
		if printOnce {
			log.Error(err, brightnessFilename)
			printOnce = false
		} else {
			log.Trace(err, brightnessFilename)
		}
		return
	}
	time.Sleep(200 * time.Millisecond)
	b = []byte("0")
	err = ioutil.WriteFile(brightnessFilename, b, 0644)
	if err != nil {
		log.Trace(err, brightnessFilename)
	}
}

func handleDNSCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*ledManagerContext)
	status := statusArg.(types.DeviceNetworkStatus)
	if key != "global" {
		log.Functionf("handleDNSImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleDNSImpl for %s", key)
	// Ignore test status and timestamps
	if ctx.deviceNetworkStatus.MostlyEqual(status) {
		log.Functionf("handleDNSImpl no change")
		return
	}
	ctx.deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus)
	log.Functionf("handleDNSImpl %d usable addresses", newAddrCount)
	if (ctx.usableAddressCount == 0 && newAddrCount != 0) ||
		(ctx.usableAddressCount != 0 && newAddrCount == 0) {
		ctx.usableAddressCount = newAddrCount
		ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
			ctx.usableAddressCount)
		log.Functionf("counter %d usableAddr %d, derived %d",
			ctx.ledCounter, ctx.usableAddressCount, ctx.derivedLedCounter)
		ctx.countChange <- ctx.derivedLedCounter
	}
	log.Functionf("handleDNSImpl done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*ledManagerContext)
	log.Functionf("handleDNSDelete for %s", key)
	if key != "global" {
		log.Functionf("handleDNSDelete: ignoring %s", key)
		return
	}
	ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus)
	log.Functionf("handleDNSDelete %d usable addresses", newAddrCount)
	if (ctx.usableAddressCount == 0 && newAddrCount != 0) ||
		(ctx.usableAddressCount != 0 && newAddrCount == 0) {
		ctx.usableAddressCount = newAddrCount
		ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
			ctx.usableAddressCount)
		log.Functionf("counter %d usableAddr %d, derived %d",
			ctx.ledCounter, ctx.usableAddressCount, ctx.derivedLedCounter)
		ctx.countChange <- ctx.derivedLedCounter
	}
	log.Functionf("handleDNSDelete done for %s", key)
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*ledManagerContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*ledManagerContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}
