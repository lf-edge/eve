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
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
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
	hardware.BlinkContext
	// cli options
	fatalPtr *bool
	hangPtr  *bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctxPtr *ledManagerContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctxPtr.fatalPtr = flagSet.Bool("F", false, "Cause log.Fatal fault injection")
	ctxPtr.hangPtr = flagSet.Bool("H", false, "Cause watchdog .touch fault injection")
}

// DisplayFunc, InitFunc, AppStatusDisplayFunc types are now in hardware package

var logger *logrus.Logger
var log *base.LogObject

var appStatusDisplayFunc hardware.AppStatusDisplayFunc
var appStatusArgs []string

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	ctx := ledManagerContext{
		countChange: make(chan types.LedBlinkCount),
	}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithArguments(arguments))

	fatalFlag := *ctx.fatalPtr
	hangFlag := *ctx.hangPtr
	log.Functionf("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	model := hardware.GetHardwareModel(log)
	log.Noticef("Got HardwareModel %s", model)

	var displayFunc hardware.DisplayFunc
	var initFunc hardware.InitFunc
	var arg string
	var isDisplay bool

	setFuncs := func(m hardware.LedModel) {
		arg = m.Arg
		isDisplay = m.IsDisplay
		appStatusArgs = m.AppStatusArgs
		if m.HasAppStatus {
			appStatusDisplayFunc = hardware.ExecuteAppStatusDisplayFunc
		}

		switch m.Strategy {
		case hardware.StrategyForceDisk:
			initFunc = InitForceDiskCmd
			displayFunc = func(log *base.LogObject, dns *types.DeviceNetworkStatus, arg string, bc types.LedBlinkCount) {
				ExecuteForceDiskCmd(log, dns, arg, bc)
			}
		case hardware.StrategyLedCmd:
			initFunc = hardware.InitLedCmd
			displayFunc = hardware.ExecuteLedCmd
		case hardware.StrategyDellCmd:
			initFunc = hardware.InitDellCmd
			displayFunc = hardware.ExecuteLedCmd
		case hardware.StrategyLogfile:
			initFunc = hardware.CreateLogfile
			displayFunc = hardware.AppendLogfile
		}
	}

	for _, m := range hardware.LedModels {
		if !m.Regexp && m.Model == model {
			setFuncs(m)
			log.Functionf("Found arg %s for model %s",
				arg, model)
			break
		}
		if m.Regexp {
			if re, err := regexp.Compile(m.Model); err != nil {
				log.Errorf("Fail in regexp parse: %s", err)
			} else if re.MatchString(model) {
				setFuncs(m)
				log.Functionf("Found arg %s for model %s by pattern %s",
					arg, model, m.Model)
				break
			}
		}
		if m.Model == "" {
			log.Functionf("No blink function for %s", model)
			setFuncs(m)
			break
		}
	}

	if initFunc != nil {
		arg = initFunc(log, arg)
	}

	if appStatusDisplayFunc != nil {
		appStatusDisplayFunc(log, &ctx.BlinkContext, appStatusArgs, false, "off") // turn off at the start
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
		Persistent:    false,
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
func handleDisplayUpdate(ctx *ledManagerContext, displayFunc hardware.DisplayFunc,
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
				displayFunc(log, &ctx.deviceNetworkStatus, arg, counter)
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

// InitDellCmd removed

// Keep avoid allocation and GC by keeping one buffer
var (
	bufferLength = int64(256 * 1024) //256k buffer length
	readBuffer   []byte
)

// InitForceDiskCmd determines the disk (using the largest disk) and measures
// the repetition count to get to 200ms dd time.
func InitForceDiskCmd(log *base.LogObject, ledName string) string {
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
func ExecuteForceDiskCmd(log *base.LogObject, deviceNetworkStatus *types.DeviceNetworkStatus,
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

// Functions moved to hardware package or removed

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
	if ctx.BlinkSendStop != nil && ctx.BlinkRecvStop != nil {
		close(ctx.BlinkSendStop)
		status := <-ctx.BlinkRecvStop //This is blocking until blink is stopped
		if status == "done" {
			log.Functionf("Blink stopped")
		}
		close(ctx.BlinkRecvStop)
		ctx.BlinkRecvStop = nil
		ctx.BlinkSendStop = nil
	}

	appStatusDisplayFunc(log, &ctx.BlinkContext, appStatusArgs, false, "off") // turn off first before they get turned on

	if summary.TotalError > 0 {
		appStatusDisplayFunc(log, &ctx.BlinkContext, appStatusArgs, false, "Red") // Error state: Solid Red
	} else if summary.TotalStopping > 0 {
		appStatusDisplayFunc(log, &ctx.BlinkContext, appStatusArgs, true, "Orange") // Halted state: Blinking Orange
	} else if summary.TotalStarting > 0 {
		appStatusDisplayFunc(log, &ctx.BlinkContext, appStatusArgs, true, "Green") //  Init state: Blinking Green
	} else if summary.TotalRunning > 0 && summary.TotalStarting == 0 && summary.TotalStopping == 0 {
		appStatusDisplayFunc(log, &ctx.BlinkContext, appStatusArgs, false, "Green") // All good: Solid Green
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
