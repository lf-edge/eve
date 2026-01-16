// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// LedStrategy defines how to initialize or display LEDs
type LedStrategy string

const (
	// StrategyNone default
	StrategyNone LedStrategy = ""
	// StrategyForceDisk uses disk activity simulation
	StrategyForceDisk LedStrategy = "ForceDisk"
	// StrategyLedCmd uses sysfs LEDs
	StrategyLedCmd LedStrategy = "LedCmd"
	// StrategyDellCmd uses Dell GPIO setup
	StrategyDellCmd LedStrategy = "DellCmd"
	// StrategyLogfile writes to a log file
	StrategyLogfile LedStrategy = "Logfile"
)

// DisplayFunc takes an argument which can be the name of a LED or display
type DisplayFunc func(log *base.LogObject, deviceNetworkStatus *types.DeviceNetworkStatus,
	arg string, blinkCount types.LedBlinkCount)

// InitFunc takes an argument which can be the name of a LED or display
// The argument could be a comma-separated list.
// Returns the one which works
type InitFunc func(log *base.LogObject, arg string) string

// AppStatusDisplayFunc takes an argument to list of leds
type AppStatusDisplayFunc func(log *base.LogObject, ctx *BlinkContext, arg []string, blink bool, color string)

// BlinkContext holds channels for stopping blink routines
type BlinkContext struct {
	BlinkSendStop chan string // Used by sender to stop the running forever blink routine
	BlinkRecvStop chan string // Sender waits for the ack.
}

// LedModel describes how to handle LEDs for a specific hardware model
type LedModel struct {
	Model         string
	Strategy      LedStrategy
	Arg           string
	Regexp        bool
	IsDisplay     bool
	HasAppStatus  bool
	AppStatusArgs []string
}

// LedModels list
var LedModels = []LedModel{
	{
		Model:    "Supermicro.SYS-E100-9APP",
		Strategy: StrategyForceDisk,
	},
	{
		Model:    "Supermicro.SYS-E100-9S",
		Strategy: StrategyForceDisk,
	},
	{
		Model:    "Supermicro.SYS-E50-9AP",
		Strategy: StrategyForceDisk,
	},
	{ // XXX temporary fix for old BIOS
		Model:    "Supermicro.Super Server",
		Strategy: StrategyForceDisk,
	},
	{
		Model:    "Supermicro.SYS-E300-8D",
		Strategy: StrategyForceDisk,
	},
	{
		Model:    "Supermicro.SYS-E300-9A-4CN10P",
		Strategy: StrategyForceDisk,
	},
	{
		Model:    "Supermicro.SYS-5018D-FN8T",
		Strategy: StrategyForceDisk,
	},
	{
		Model:    "PC Engines.apu2",
		Strategy: StrategyLedCmd,
		Arg:      "apu2:green:led3",
	},
	{
		Model:    "Dell Inc..Edge Gateway 3001",
		Strategy: StrategyDellCmd,
		Arg:      "/sys/class/gpio/gpio346/value",
	},
	{
		Model:    "Dell Inc..Edge Gateway 3002",
		Strategy: StrategyDellCmd,
		Arg:      "/sys/class/gpio/gpio346/value",
	},
	{
		Model:    "Dell Inc..Edge Gateway 3003",
		Strategy: StrategyDellCmd,
		Arg:      "/sys/class/gpio/gpio346/value",
	},
	{
		Model:         "SIEMENS AG.SIMATIC IPC127E",
		Strategy:      StrategyLedCmd,
		Arg:           "ipc127:green:1",
		HasAppStatus:  true,
		AppStatusArgs: []string{"ipc127:green:3", "ipc127:red:3"},
	},
	{
		Model:    "hisilicon,hi6220-hikey.hisilicon,hi6220.",
		Strategy: StrategyLedCmd,
		Arg:      "wifi_active",
	},
	{
		Model:    "hisilicon,hikey.hisilicon,hi6220.",
		Strategy: StrategyLedCmd,
		Arg:      "wifi_active",
	},
	{
		Model:    "LeMaker.HiKey-6220",
		Strategy: StrategyLedCmd,
		Arg:      "wifi_active",
	},
	{
		Model:  "QEMU.*",
		Regexp: true,
		// No disk light blinking on QEMU
		Strategy: StrategyLogfile,
		// XXX set this to test output to a file:
		// Arg:         "/persist/log/ledmanager-status.log",
		IsDisplay: true,
	},
	{
		Model:  "Red Hat.KVM",
		Regexp: true,
		// No disk light blinking on Red Hat.KVM qemu
	},
	{
		Model:  "Parallels.*",
		Regexp: true,
		// No disk light blinking on Parallels
	},
	{
		Model:  "Google.*",
		Regexp: true,
		// No disk light blinking on Google
	},
	{
		Model:  "VMware.*",
		Regexp: true,
		// No disk light blinking on VMware
	},
	{
		Model:    "raspberrypi.rpi.raspberrypi,4-model-b.brcm,bcm2711",
		Strategy: StrategyLedCmd,
		Arg:      "ACT,led0",
	},
	{
		Model:    "RaspberryPi.RPi4",
		Strategy: StrategyLedCmd,
		Arg:      "ACT,led0",
	},
	{
		Model:    "raspberrypi,4-compute-modulebrcm,bcm2711",
		Strategy: StrategyLedCmd,
		Arg:      "ACT",
	},
	{
		Model:    "raspberrypi,5-model-bbrcm,bcm2712",
		Strategy: StrategyLedCmd,
		Arg:      "ACT",
	},
	{
		Model:    "raspberrypi.uno-220.raspberrypi,4-model-b.brcm,bcm2711",
		Strategy: StrategyLedCmd,
		Arg:      "uno",
	},
	{
		Model:    "rockchip.evb_rk3399.NexCore,Q116.rockchip,rk3399",
		Strategy: StrategyLedCmd,
		Arg:      "eve",
	},
	{
		Model:    "AAEON.UP-APL01",
		Strategy: StrategyLedCmd,
		Arg:      "upboard:blue:",
	},
	{
		Model:    "Axiomtek Co., Ltd.EM320",
		Strategy: StrategyLedCmd,
		Arg:      "blue:status-0",
	},
	{
		Model:    "advantech.imx8mp_rsb3720a1.*",
		Regexp:   true,
		Strategy: StrategyLedCmd,
		Arg:      "user",
	},
	{
		Model:    "phytec,imx8mp-phyboard-pollux-rdk.*",
		Regexp:   true,
		Strategy: StrategyLedCmd,
		Arg:      "led3", // Blue LED
	},
	{
		// Last in table as a default
		Model:    "",
		Strategy: StrategyForceDisk,
	},
}

// InitDellCmd prepares "Cloud LED" on Dell IoT gateways by enabling GPIO endpoint
func InitDellCmd(log *base.LogObject, ledName string) string {
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

// InitLedCmd can use different LEDs in /sys/class/leds
// Disable existing trigger
func InitLedCmd(log *base.LogObject, ledName string) string {
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
func ExecuteLedCmd(log *base.LogObject, deviceNetworkStatus *types.DeviceNetworkStatus,
	ledName string, blinkCount types.LedBlinkCount) {
	for i := 0; i < int(blinkCount); i++ {
		doLedBlink(log, ledName)
		time.Sleep(200 * time.Millisecond)
	}
}

// CreateLogfile will use the arg to create a file
func CreateLogfile(log *base.LogObject, filename string) string {
	log.Functionf("createLogfile(%s)", filename)
	return filename
}

// AppendLogfile
func AppendLogfile(log *base.LogObject, deviceNetworkStatus *types.DeviceNetworkStatus,
	filename string, counter types.LedBlinkCount) {

	if filename == "" {
		// Disabled
		return
	}
	msg := fmt.Sprintf("Progress: %d (%s)\n", counter, counter)
	for _, p := range deviceNetworkStatus.Ports {
		if p.IsMgmt {
			msg += fmt.Sprintf("Port %s: %s\n",
				p.IfName, p.AddrInfoList)
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
	}
}

func doLedAction(log *base.LogObject, ledName string, turnon bool) {
	var brightnessFilename string
	var b []byte
	if turnon == true {
		b = maxLEDBrightness(log, ledName)
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
}

func doLedBlink(log *base.LogObject, ledName string) {
	if ledName == "" {
		time.Sleep(200 * time.Millisecond)
		return
	}
	var brightnessFilename string
	if strings.HasPrefix(ledName, "/") {
		brightnessFilename = ledName
	} else {
		brightnessFilename = fmt.Sprintf("/sys/class/leds/%s/brightness", ledName)
	}
	b := maxLEDBrightness(log, ledName)
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

var printOnce = true

func maxLEDBrightness(log *base.LogObject, ledName string) []byte {
	log.Functionf("maxLEDBrightness(%s)", ledName)
	if !strings.HasPrefix(ledName, "/") {
		bmaxFilename := fmt.Sprintf("/sys/class/leds/%s/max_brightness", ledName)
		b, err := os.ReadFile(bmaxFilename)
		if err == nil {
			return b
		}
		log.Functionf("readFile %s failed: %s", bmaxFilename, err)
	} else {
		log.Functionf("Absolute path %s", ledName)
	}
	return []byte("1")
}

// Execute blink forever until there is a message to stop
func executeBlinkLoop(log *base.LogObject, ctx *BlinkContext, color string, leds []string) {

	log.Functionf("Started blink thread for color %s", color)
	// Both of these channels are created here. This routine is considered as a receiver.
	// But closing of these channels happens as follows:
	// blinkSendStop will be closed by the sender and that signal is received by this routine to exit the loop
	// blinkRecvStop will be closed by the sender after this routine sends done message.
	ctx.BlinkRecvStop = make(chan string)
	ctx.BlinkSendStop = make(chan string, 1)
	var ok, valid bool
	for {

		select {
		case _, valid = <-ctx.BlinkSendStop:
			ok = true
		default:
			ok = false
		}

		if ok && !valid { // This channel was closed
			ctx.BlinkRecvStop <- "done"
			return
		}

		switch color {
		case "Orange":
			doLedAction(log, leds[0], false) // Green off
			doLedAction(log, leds[1], false) // Red off
			time.Sleep(200 * time.Millisecond)
			doLedAction(log, leds[0], true) // Green on
			doLedAction(log, leds[1], true) // Red on
			time.Sleep(200 * time.Millisecond)
		case "Green":
			doLedAction(log, leds[0], false) // Green off
			time.Sleep(200 * time.Millisecond)
			doLedAction(log, leds[0], true) // Green on
			time.Sleep(200 * time.Millisecond)
		default:
			log.Noticef("Unsupported Color")
			close(ctx.BlinkRecvStop)
			close(ctx.BlinkSendStop)
			ctx.BlinkRecvStop = nil
			ctx.BlinkSendStop = nil
			return
		}

	}

}

// ExecuteAppStatusDisplayFunc sets the appStatusArgs
func ExecuteAppStatusDisplayFunc(log *base.LogObject, ctx *BlinkContext, appStatusArgs []string, blink bool, color string) {

	switch color {
	case "Red": // Solid Red
		doLedAction(log, appStatusArgs[0], false) // Green off
		doLedAction(log, appStatusArgs[1], true)  // Red on
	case "Orange": // Orange can blink or solid
		doLedAction(log, appStatusArgs[0], true) // Green on
		doLedAction(log, appStatusArgs[1], true) // Red on
		if blink == true {
			go executeBlinkLoop(log, ctx, "Orange", appStatusArgs)
		}

	case "Green": // Green can blink or solid
		doLedAction(log, appStatusArgs[1], false) // Red off
		doLedAction(log, appStatusArgs[0], true)  // Green on
		if blink == true {
			go executeBlinkLoop(log, ctx, "Green", appStatusArgs)
		}
	default: // Turn off both red and green
		doLedAction(log, appStatusArgs[0], false)
		doLedAction(log, appStatusArgs[1], false)
	}
}

// GetStatusLedPresent checks if valid status LED is present for the given model
func GetStatusLedPresent(model string) bool {
	if model == "" {
		return false
	}

	var arg string
	found := false

	// match model
	for _, m := range LedModels {
		if m.Regexp {
			matched, _ := regexp.MatchString(m.Model, model)
			if matched {
				arg = m.Arg
				found = true
				break
			}
		} else {
			if m.Model == model {
				arg = m.Arg
				found = true
				break
			}
		}
	}

	if !found {
		return false
	}

	if found && arg == "" {
		return true
	}

	// Check files
	// If arg is a comma-separated list, check if any of them exists
	parts := strings.Split(arg, ",")
	for _, p := range parts {
		path := p
		if !strings.HasPrefix(p, "/") {
			path = "/sys/class/leds/" + p
		}
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}
