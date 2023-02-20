// Copyright (c) 2018,2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// ledmanager subscribes to LedBlinkCounter and DeviceNetworkStatus
// Based on this it determines the state of progression in the form of a
// number. The number can be output as a blinking sequence on a a LED
// which is determined based on the hardware model, or it can be sent to some
// display device.
// When blinking there is a pause of 200ms after each blink and a 1200ms pause
// after each sequence.

package ledmanager

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	agentName = "ledmanager"
)

// State passed to handlers
type ledManagerContext struct {
	agentbase.AgentBase
	countChange            chan types.LedBlinkCount
	ledCounter             types.LedBlinkCount // Suppress work and logging if no change
	subGlobalConfig        pubsub.Subscription
	subLedBlinkCounter     pubsub.Subscription
	subDeviceNetworkStatus pubsub.Subscription
	deviceNetworkStatus    types.DeviceNetworkStatus
	subAppInstanceSummary  pubsub.Subscription
	usableAddressCount     int
	radioSilence           bool
	derivedLedCounter      types.LedBlinkCount // Based on ledCounter, usableAddressCount and radioSilence
	GCInitialized          bool
	blinkSendStop          chan string // Used by sender to stop the running forever blink routine
	blinkRecvStop          chan string // Sender waits for the ack.
	// cli options
	versionPtr *bool
	fatalPtr   *bool
	hangPtr    *bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctxPtr *ledManagerContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctxPtr.versionPtr = flagSet.Bool("v", false, "Version")
	ctxPtr.fatalPtr = flagSet.Bool("F", false, "Cause log.Fatal fault injection")
	ctxPtr.hangPtr = flagSet.Bool("H", false, "Cause watchdog .touch fault injection")
}

// DisplayFunc takes an argument which can be the name of a LED or display
type DisplayFunc func(deviceNetworkStatus *types.DeviceNetworkStatus,
	arg string, blinkCount types.LedBlinkCount)

// InitFunc takes an argument which can be the name of a LED or display
// The argument could be a comma-separated list.
// Returns the one which works
type InitFunc func(arg string) string

// AppStatusDisplayFunc takes an argument to list of leds
type AppStatusDisplayFunc func(ctx *ledManagerContext, arg []string, blink bool, color string)

type modelToFuncs struct {
	model                string
	initFunc             InitFunc
	displayFunc          DisplayFunc
	arg                  string // Passed to initFunc and displayFunc
	appStatusDisplayFunc AppStatusDisplayFunc
	appStatusArgs        []string // Passed to appStatusDisplayFunc
	regexp               bool     // model string is a regex
	isDisplay            bool     // no periodic blinking/update
}

var mToF = []modelToFuncs{
	{
		model:       "Supermicro.SYS-E100-9APP",
		initFunc:    InitForceDiskCmd,
		displayFunc: ExecuteForceDiskCmd,
	},
	{
		model:       "Supermicro.SYS-E100-9S",
		initFunc:    InitForceDiskCmd,
		displayFunc: ExecuteForceDiskCmd,
	},
	{
		model:       "Supermicro.SYS-E50-9AP",
		initFunc:    InitForceDiskCmd,
		displayFunc: ExecuteForceDiskCmd,
	},
	{ // XXX temporary fix for old BIOS
		model:       "Supermicro.Super Server",
		initFunc:    InitForceDiskCmd,
		displayFunc: ExecuteForceDiskCmd,
	},
	{
		model:       "Supermicro.SYS-E300-8D",
		initFunc:    InitForceDiskCmd,
		displayFunc: ExecuteForceDiskCmd,
	},
	{
		model:       "Supermicro.SYS-E300-9A-4CN10P",
		initFunc:    InitForceDiskCmd,
		displayFunc: ExecuteForceDiskCmd,
	},
	{
		model:       "Supermicro.SYS-5018D-FN8T",
		initFunc:    InitForceDiskCmd,
		displayFunc: ExecuteForceDiskCmd,
	},
	{
		model:       "PC Engines.apu2",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "apu2:green:led3",
	},
	{
		model:       "Dell Inc..Edge Gateway 3001",
		initFunc:    InitDellCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "/sys/class/gpio/gpio346/value",
	},
	{
		model:       "Dell Inc..Edge Gateway 3002",
		initFunc:    InitDellCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "/sys/class/gpio/gpio346/value",
	},
	{
		model:       "Dell Inc..Edge Gateway 3003",
		initFunc:    InitDellCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "/sys/class/gpio/gpio346/value",
	},
	{
		model:                "SIEMENS AG.SIMATIC IPC127E",
		initFunc:             InitLedCmd,
		displayFunc:          ExecuteLedCmd,
		arg:                  "ipc127:green:1",
		appStatusDisplayFunc: executeAppStatusDisplayFunc,
		appStatusArgs:        []string{"ipc127:green:3", "ipc127:red:3"}, // For this model we use led3 to display app status
	},
	{
		model:       "hisilicon,hi6220-hikey.hisilicon,hi6220.",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "wifi_active",
	},
	{
		model:       "hisilicon,hikey.hisilicon,hi6220.",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "wifi_active",
	},
	{
		model:       "LeMaker.HiKey-6220",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "wifi_active",
	},
	{
		model:  "QEMU.*",
		regexp: true,
		// No disk light blinking on QEMU
		initFunc:    createLogfile,
		displayFunc: appendLogfile,
		// XXX set this to test output to a file:
		// arg:         "/persist/log/ledmanager-status.log",
		isDisplay: true,
	},
	{
		model:  "Red Hat.KVM",
		regexp: true,
		// No disk light blinking on Red Hat.KVM qemu
	},
	{
		model:  "Parallels.*",
		regexp: true,
		// No disk light blinking on Parallels
	},
	{
		model:  "Google.*",
		regexp: true,
		// No disk light blinking on Google
	},
	{
		model:  "VMware.*",
		regexp: true,
		// No disk light blinking on VMware
	},
	{
		model:       "raspberrypi.rpi.raspberrypi,4-model-b.brcm,bcm2711",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "ACT,led0",
	},
	{
		model:       "RaspberryPi.RPi4",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "ACT,led0",
	},
	{
		model:       "raspberrypi.uno-220.raspberrypi,4-model-b.brcm,bcm2711",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "uno",
	},
	{
		model:       "rockchip.evb_rk3399.NexCore,Q116.rockchip,rk3399",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "eve",
	},
	{
		model:       "AAEON.UP-APL01",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "upboard:blue:",
	},
	{
		model:       "Axiomtek Co., Ltd.EM320",
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "blue:status-0",
	},
	{
		model:       "advantech.imx8mp_rsb3720a1.*",
		regexp:      true,
		initFunc:    InitLedCmd,
		displayFunc: ExecuteLedCmd,
		arg:         "user",
	},
	{
		// Last in table as a default
		model:       "",
		initFunc:    InitForceDiskCmd,
		displayFunc: ExecuteForceDiskCmd,
	},
}

var logger *logrus.Logger
var log *base.LogObject

// Set from Makefile
var Version = "No version specified"

var appStatusDisplayFunc AppStatusDisplayFunc
var appStatusArgs []string

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	ctx := ledManagerContext{
		countChange: make(chan types.LedBlinkCount),
	}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithArguments(arguments))

	fatalFlag := *ctx.fatalPtr
	hangFlag := *ctx.hangPtr
	if *ctx.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
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
	log.Noticef("Got HardwareModel %s", model)

	var displayFunc DisplayFunc
	var initFunc InitFunc
	var arg string
	var isDisplay bool

	setFuncs := func(m modelToFuncs) {
		displayFunc = m.displayFunc
		initFunc = m.initFunc
		arg = m.arg
		isDisplay = m.isDisplay
		appStatusDisplayFunc = m.appStatusDisplayFunc
		appStatusArgs = m.appStatusArgs
	}

	for _, m := range mToF {
		if !m.regexp && m.model == model {
			setFuncs(m)
			log.Functionf("Found %v arg %s for model %s",
				displayFunc, arg, model)
			break
		}
		if m.regexp {
			if re, err := regexp.Compile(m.model); err != nil {
				log.Errorf("Fail in regexp parse: %s", err)
			} else if re.MatchString(model) {
				setFuncs(m)
				log.Functionf("Found %v arg %s for model %s by pattern %s",
					displayFunc, arg, model, m.model)
				break
			}
		}
		if m.model == "" {
			log.Functionf("No blink function for %s", model)
			setFuncs(m)
			break
		}
	}

	if initFunc != nil {
		arg = initFunc(arg)
	}

	if appStatusDisplayFunc != nil {
		executeAppStatusDisplayFunc(&ctx, appStatusArgs, false, "off") // turn off at the start
	}
	log.Functionf("Creating %s at %s", "handleDisplayUpdate",
		agentlog.GetMyStack())
	go handleDisplayUpdate(&ctx, displayFunc, arg, isDisplay)

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

	// Look for AppInstanceSummary from zedmanager
	subAppInstanceSummary, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedmanager",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceSummary{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleAppInstanceSummaryCreate,
		ModifyHandler: handleAppInstanceSummaryModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppInstanceSummary = subAppInstanceSummary
	subAppInstanceSummary.Activate()

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

		case change := <-subAppInstanceSummary.MsgChan():
			subAppInstanceSummary.ProcessChange(change)

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
	// Suppress work and logging if no change
	if config.BlinkCounter == ctx.ledCounter {
		return
	}
	ctx.ledCounter = config.BlinkCounter
	ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
		ctx.usableAddressCount, ctx.radioSilence)
	log.Functionf("counter %d usableAddr %d, radioSilence %t, derived %d",
		ctx.ledCounter, ctx.usableAddressCount, ctx.radioSilence, ctx.derivedLedCounter)
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
		ctx.usableAddressCount, ctx.radioSilence)
	log.Functionf("counter %d usableAddr %d, radioSilence %t, derived %d",
		ctx.ledCounter, ctx.usableAddressCount, ctx.radioSilence, ctx.derivedLedCounter)
	ctx.countChange <- ctx.derivedLedCounter
	log.Functionf("handleLedBlinkDelete done for %s", key)
}

// handleDisplayUpdate waits for changes and displays/blinks the based on
// the updated counter
func handleDisplayUpdate(ctx *ledManagerContext, displayFunc DisplayFunc,
	arg string, isDisplay bool) {

	var counter types.LedBlinkCount
	for {
		changed := false
		select {
		case counter = <-ctx.countChange:
			log.Tracef("Received counter update: %d",
				counter)
			changed = true
		default:
			log.Tracef("Unchanged counter: %d", counter)
		}
		if displayFunc != nil {
			log.Tracef("Displaying counter %d", counter)
			// Skip unchanged updates if it is a true display
			if changed || !isDisplay {
				displayFunc(&ctx.deviceNetworkStatus, arg, counter)
			}
		}
		time.Sleep(1200 * time.Millisecond)
	}
}

func DummyCmd() {
	time.Sleep(200 * time.Millisecond)
}

var printOnce = true
var diskRepeatCount int // Based on time for 200ms

// InitDellCmd prepares "Cloud LED" on Dell IoT gateways by enabling GPIO endpoint
func InitDellCmd(ledName string) string {
	err := os.WriteFile("/sys/class/gpio/export", []byte("346"), 0644)
	if err == nil {
		if err = os.WriteFile("/sys/class/gpio/gpio346/direction", []byte("out"), 0644); err == nil {
			log.Functionf("Enabled Dell Cloud LED")
			return ledName
		}
	}
	log.Warnf("Failed to enable Dell Cloud LED: %v", err)
	return ""
}

// Keep avoid allocation and GC by keeping one buffer
var (
	bufferLength = int64(256 * 1024) //256k buffer length
	readBuffer   []byte
)

// InitForceDiskCmd determines the disk (using the largest disk) and measures
// the repetition count to get to 200ms dd time.
func InitForceDiskCmd(ledName string) string {
	disk := diskmetrics.FindLargestDisk(log)
	if disk == "" {
		return ""
	}
	log.Functionf("InitForceDiskCmd using disk %s", disk)
	readBuffer = make([]byte, bufferLength)
	diskDevice := "/dev/" + disk
	count := 100 * 16
	// Prime before measuring
	uncachedDiskRead(count, diskDevice)
	uncachedDiskRead(count, diskDevice)
	start := time.Now()
	uncachedDiskRead(count, diskDevice)
	elapsed := time.Since(start)
	if elapsed == 0 {
		log.Errorf("Measured 0 nanoseconds!")
		return ""
	}
	// Adjust count but at least one
	fl := time.Duration(count) * (200 * time.Millisecond) / elapsed
	count = int(fl)
	if count == 0 {
		count = 1
	}
	log.Noticef("Measured %v; count %d", elapsed, count)
	diskRepeatCount = count
	return diskDevice
}

// ExecuteForceDiskCmd does counter number of 200ms blinks and returns
// It assumes the init function has determined a diskRepeatCount and a disk.
func ExecuteForceDiskCmd(deviceNetworkStatus *types.DeviceNetworkStatus,
	diskDevice string, blinkCount types.LedBlinkCount) {
	for i := 0; i < int(blinkCount); i++ {
		doForceDiskBlink(diskDevice)
		time.Sleep(200 * time.Millisecond)
	}
}

// doForceDiskBlink assumes the init function has determined a diskRepeatCount
// which makes the disk LED light up for 200ms
// We do this with caching disabled since there might be a filesystem on the
// device in which case the disk LED would otherwise not light up.
func doForceDiskBlink(diskDevice string) {
	if diskDevice == "" || diskRepeatCount == 0 {
		DummyCmd()
		return
	}
	uncachedDiskRead(diskRepeatCount, diskDevice)
}

func uncachedDiskRead(count int, diskDevice string) {
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
// If comma-separated list try until one is found.
// Returns the led which worked.
func InitLedCmd(ledName string) string {
	log.Functionf("InitLedCmd(%s)", ledName)
	// If there are multiple, comma-separated ones, find one which works
	leds := strings.Split(ledName, ",")
	for _, led := range leds {
		triggerFilename := fmt.Sprintf("/sys/class/leds/%s/trigger", led)
		b := []byte("none")
		err := os.WriteFile(triggerFilename, b, 0600)
		if err != nil {
			log.Error(err, triggerFilename)
			continue
		}
		return led
	}
	log.Errorf("No existing led among <%s", ledName)
	return ""
}

// ExecuteLedCmd does counter number of 200ms blinks and returns
func ExecuteLedCmd(deviceNetworkStatus *types.DeviceNetworkStatus,
	ledName string, blinkCount types.LedBlinkCount) {
	for i := 0; i < int(blinkCount); i++ {
		doLedBlink(ledName)
		time.Sleep(200 * time.Millisecond)
	}
}

// Execute blink forever until there is a message to stop
func executeBlinkLoop(ctx *ledManagerContext, color string, leds []string) {

	log.Functionf("Started blink thread for color %s", color)
	// Both of these channels are created here. This routine is considered as a receiver.
	// But closing of these channels happens as follows:
	// blinkSendStop will be closed by the sender and that signal is received by this routine to exit the loop
	// blinkRecvStop will be closed by the sender after this routine sends done message.
	ctx.blinkRecvStop = make(chan string)
	ctx.blinkSendStop = make(chan string, 1)
	var ok, valid bool
	for {

		select {
		case _, valid = <-ctx.blinkSendStop:
			ok = true
		default:
			ok = false
		}

		if ok && !valid { // This channel was closed
			ctx.blinkRecvStop <- "done"
			return
		}

		switch color {
		case "Orange":
			doLedAction(leds[0], false) // Green off
			doLedAction(leds[1], false) // Red off
			time.Sleep(200 * time.Millisecond)
			doLedAction(leds[0], true) // Green on
			doLedAction(leds[1], true) // Red on
			time.Sleep(200 * time.Millisecond)
		case "Green":
			doLedAction(leds[0], false) // Green off
			time.Sleep(200 * time.Millisecond)
			doLedAction(leds[0], true) // Green on
			time.Sleep(200 * time.Millisecond)
		default:
			log.Noticef("Unsupported Color")
			close(ctx.blinkRecvStop)
			close(ctx.blinkSendStop)
			ctx.blinkRecvStop = nil
			ctx.blinkSendStop = nil
			return
		}

	}

}

// Sets the appStatusArgs
func executeAppStatusDisplayFunc(ctx *ledManagerContext, appStatusArgs []string, blink bool, color string) {

	switch color {
	case "Red": // Solid Red
		doLedAction(appStatusArgs[0], false) // Green off
		doLedAction(appStatusArgs[1], true)  // Red on
	case "Orange": // Orange can blink or solid
		doLedAction(appStatusArgs[0], true) // Green on
		doLedAction(appStatusArgs[1], true) // Red on
		if blink == true {
			go executeBlinkLoop(ctx, "Orange", appStatusArgs)
		}

	case "Green": // Green can blink or solid
		doLedAction(appStatusArgs[1], false) // Red off
		doLedAction(appStatusArgs[0], true)  // Green on
		if blink == true {
			go executeBlinkLoop(ctx, "Green", appStatusArgs)
		}
	default: // Turn off both red and green
		doLedAction(appStatusArgs[0], false)
		doLedAction(appStatusArgs[1], false)
	}
}

// doLedAction can use different LEDs in /sys/class/leds and can turn on/off
func doLedAction(ledName string, turnon bool) {
	var brightnessFilename string
	var b []byte
	if turnon == true {
		b = []byte("1")
	} else {
		b = []byte("0")
	}

	if strings.HasPrefix(ledName, "/") {
		brightnessFilename = ledName
	} else {
		brightnessFilename = fmt.Sprintf("/sys/class/leds/%s/brightness", ledName)
	}
	err := os.WriteFile(brightnessFilename, b, 0644)
	if err != nil {
		log.Trace(err, brightnessFilename)
	}
	return
}

// doLedBlink can use different LEDs in /sys/class/leds
// Enable the led for 200ms
func doLedBlink(ledName string) {
	if ledName == "" {
		time.Sleep(200 * time.Millisecond)
		return
	}
	var brightnessFilename string
	b := []byte("1")
	if strings.HasPrefix(ledName, "/") {
		brightnessFilename = ledName
	} else {
		brightnessFilename = fmt.Sprintf("/sys/class/leds/%s/brightness", ledName)
	}
	err := os.WriteFile(brightnessFilename, b, 0644)
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
	err = os.WriteFile(brightnessFilename, b, 0644)
	if err != nil {
		log.Trace(err, brightnessFilename)
	}
}

// createLogfile will use the arg to create a file
func createLogfile(filename string) string {
	log.Functionf("createLogfile(%s)", filename)
	return filename
}

// appendLogfile
func appendLogfile(deviceNetworkStatus *types.DeviceNetworkStatus,
	filename string, counter types.LedBlinkCount) {

	if filename == "" {
		// Disabled
		return
	}
	msg := fmt.Sprintf("Progress: %d (%s)\n", counter, counter)
	for _, p := range deviceNetworkStatus.Ports {
		if p.IsMgmt {
			addrs := ""
			for _, ai := range p.AddrInfoList {
				addrs += ai.Addr.String() + " "
			}
			m1 := fmt.Sprintf("%s IP %s\n", p.IfName, addrs)
			msg = msg + m1
		}
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644)
	if err != nil {
		log.Errorf("OpenFile %s failed: %v", filename, err)
		return
	}
	defer file.Close()
	if _, err := file.WriteString(msg); err != nil {
		log.Errorf("WriteString %s failed: %v", filename, err)
		return
	}
}

func handleAppInstanceSummaryCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppInstanceSummaryImpl(ctxArg, key, statusArg)
}

func handleAppInstanceSummaryModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppInstanceSummaryImpl(ctxArg, key, statusArg)
}

func handleAppInstanceSummaryImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	summary := statusArg.(types.AppInstanceSummary)
	log.Functionf("handleAppInstanceSummaryImpl: Starting %d Running %d Stopping %d Error %d", summary.TotalStarting, summary.TotalRunning, summary.TotalStopping, summary.TotalError)

	// Nothing to do if display function is not set
	if appStatusDisplayFunc == nil {
		return
	}
	ctx := ctxArg.(*ledManagerContext)

	// Check if a previous blink loop is running.
	if ctx.blinkSendStop != nil && ctx.blinkRecvStop != nil {
		close(ctx.blinkSendStop)
		status := <-ctx.blinkRecvStop //This is blocking until blink is stopped
		if status == "done" {
			log.Functionf("Blink stopped")
		}
		close(ctx.blinkRecvStop)
		ctx.blinkRecvStop = nil
		ctx.blinkSendStop = nil
	}

	executeAppStatusDisplayFunc(ctx, appStatusArgs, false, "off") // turn off first before they get turned on

	if summary.TotalError > 0 {
		executeAppStatusDisplayFunc(ctx, appStatusArgs, false, "Red") // Error state: Solid Red
	} else if summary.TotalStopping > 0 {
		executeAppStatusDisplayFunc(ctx, appStatusArgs, true, "Orange") // Halted state: Blinking Orange
	} else if summary.TotalStarting > 0 {
		executeAppStatusDisplayFunc(ctx, appStatusArgs, true, "Green") //  Init state: Blinking Green
	} else if summary.TotalRunning > 0 && summary.TotalStarting == 0 && summary.TotalStopping == 0 {
		executeAppStatusDisplayFunc(ctx, appStatusArgs, false, "Green") // All good: Solid Green
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
		(ctx.usableAddressCount != 0 && newAddrCount == 0) ||
		updateRadioSilence(ctx, &ctx.deviceNetworkStatus) {
		ctx.usableAddressCount = newAddrCount
		ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
			ctx.usableAddressCount, ctx.radioSilence)
		log.Functionf("counter %d, usableAddr %d, radioSilence %t, derived %d",
			ctx.ledCounter, ctx.usableAddressCount, ctx.radioSilence, ctx.derivedLedCounter)
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
		(ctx.usableAddressCount != 0 && newAddrCount == 0) ||
		updateRadioSilence(ctx, &ctx.deviceNetworkStatus) {
		ctx.usableAddressCount = newAddrCount
		ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
			ctx.usableAddressCount, ctx.radioSilence)
		log.Functionf("counter %d, usableAddr %d, radioSilence %t, derived %d",
			ctx.ledCounter, ctx.usableAddressCount, ctx.radioSilence, ctx.derivedLedCounter)
		ctx.countChange <- ctx.derivedLedCounter
	}
	log.Functionf("handleDNSDelete done for %s", key)
}

func updateRadioSilence(ctx *ledManagerContext, status *types.DeviceNetworkStatus) (update bool) {
	if status == nil {
		// by default radio-silence is turned off
		update = ctx.radioSilence != false
		ctx.radioSilence = false
	} else if !status.RadioSilence.ChangeInProgress {
		update = ctx.radioSilence != status.RadioSilence.Imposed
		ctx.radioSilence = status.RadioSilence.Imposed
	}
	return
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
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
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
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}
