// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Utility to dump diagnostic information about connectivity

package diag

import (
	"flag"
	"fmt"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"os"
)

const (
	agentName       = "diag"
	tmpDirname      = "/var/tmp/zededa"
	AADirname       = tmpDirname + "/AssignableAdapters"
	DNCDirname      = tmpDirname + "/DeviceNetworkConfig"
	identityDirname = "/config"
	selfRegFile     = identityDirname + "/self-register-failed"
)

// State passed to handlers
type diagContext struct {
	devicenetwork.DeviceNetworkContext
	forever                bool // Keep on reporting until ^C
	ledCounter             int  // Supress work and output
	subGlobalConfig        *pubsub.Subscription
	subLedBlinkCounter     *pubsub.Subscription
	subDeviceNetworkStatus *pubsub.Subscription
	deviceNetworkStatus    *types.DeviceNetworkStatus
}

// Set from Makefile
var Version = "No version specified"

var debug = false
var debugOverride bool // From command line arg

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	foreverPtr := flag.Bool("f", false, "Forever flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	ctx := diagContext{
		forever:             *foreverPtr,
		deviceNetworkStatus: &types.DeviceNetworkStatus{},
	}

	// XXX should we subscribe to and get GlobalConfig for debug??

	savedHardwareModel := hardware.GetHardwareModelOverride()
	hardwareModel := hardware.GetHardwareModelNoOverride()
	if savedHardwareModel != hardwareModel {
		fmt.Printf("INFO: dmidecode model string %s overridden as %s\n",
			hardwareModel, savedHardwareModel)
	}
	if !DNCExists(savedHardwareModel) {
		fmt.Printf("ERROR: /config/hardwaremodel %s does not exist in /var/tmp/zededa/DeviceNetworkConfig\n",
			savedHardwareModel)
		fmt.Printf("NOTE: Device is using /var/tmp/zededa/DeviceNetworkConfig/default.json\n")
	}
	if !AAExists(savedHardwareModel) {
		fmt.Printf("ERROR: /config/hardwaremodel %s does not exist in /var/tmp/zededa/AssignableAdapters\n",
			savedHardwareModel)
		fmt.Printf("NOTE: Device is using /var/tmp/zededa/AssignableAdapters/default.json\n")
	}
	if !DNCExists(hardwareModel) {
		fmt.Printf("INFO: dmidecode model %s does not exist in /var/tmp/zededa/DeviceNetworkConfig\n",
			hardwareModel)
	}
	if !AAExists(hardwareModel) {
		fmt.Printf("INFO: dmidecode model %s does not exist in /var/tmp/zededa/AssignableAdapters\n",
			hardwareModel)
	}
	// XXX certificate fingerprints? What does zedcloud use?
	if fileExists(selfRegFile) {
		fmt.Printf("INFO: selfRegister is still in progress\n")
		// XXX print onboarding cert
	}

	// XXX print any override.json; subscribe and wait for sync??
	// XXX print all DevicePortConfig's? Changes?

	subLedBlinkCounter, err := pubsub.Subscribe("", types.LedBlinkCounter{},
		false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subLedBlinkCounter.ModifyHandler = handleLedBlinkModify
	ctx.subLedBlinkCounter = subLedBlinkCounter
	subLedBlinkCounter.Activate()

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	for {
		select {
		case change := <-subLedBlinkCounter.C:
			subLedBlinkCounter.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
		}
		if !ctx.forever {
			break
		}
	}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func DNCExists(model string) bool {
	DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
	return fileExists(DNCFilename)
}

func AAExists(model string) bool {
	AAFilename := fmt.Sprintf("%s/%s.json", AADirname, model)
	return fileExists(AAFilename)
}

func handleLedBlinkModify(ctxArg interface{}, key string,
	configArg interface{}) {

	config := cast.CastLedBlinkCounter(configArg)
	ctx := ctxArg.(*diagContext)

	if key != "ledconfig" {
		log.Errorf("handleLedBlinkModify: ignoring %s\n", key)
		return
	}
	// Supress work and logging if no change
	if config.BlinkCounter == ctx.ledCounter {
		return
	}
	ctx.ledCounter = config.BlinkCounter
	printOutput(ctx)
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*diagContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(ctx.deviceNetworkStatus, status) {
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(ctx.deviceNetworkStatus, status))
	*ctx.deviceNetworkStatus = status
	// XXX can we limit to interfaces which changed?
	printOutput(ctx)
	log.Infof("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*diagContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	printOutput(ctx)
	log.Infof("handleDNSDelete done for %s\n", key)
}

// Print output for all interfaces
// XXX can we limit to interfaces which changed?
func printOutput(ctx *diagContext) {

	// XXX print old and new? Diff if LED change vs address/if change?
	switch ctx.ledCounter {
	case 0:
		fmt.Printf("ERROR: Unknown LED counter 0\n")
	case 1:
		fmt.Printf("ERROR: Running but DHCP client not yet started\n")
	case 2:
		fmt.Printf("ERROR: Waiting for DHCP IP address(es)\n")
	case 3:
		fmt.Printf("WARNING: Connected to EV Controller but not onboarded\n")
	case 4:
		fmt.Printf("INFO: Connected to EV Controller and onboarded\n")
	case 10:
		fmt.Printf("ERROR: 10 blinks XXX\n")
	default:
		fmt.Printf("ERROR: Unsupported LED counter %d\n",
			ctx.ledCounter)
	}

	fmt.Printf("INFO: Have %d ports\n", len(ctx.deviceNetworkStatus.Ports))
	for _, port := range ctx.deviceNetworkStatus.Ports {
		// XXX print usefully formatted info based on which
		// fields are set and Dhcp type; proxy info order
		fmt.Printf("Port status XXX %+v\n", port)
	}
}
