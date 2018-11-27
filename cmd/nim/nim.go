// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Manage the network interfaces based on configuration from
// different sources. Attempts to test configuration changes before applying
// them.
// Maintains old configuration as lower-priority but always tries to move to the
// most recent aka highest priority configuration.

package nim

import (
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

const (
	agentName       = "nim"
	tmpDirname      = "/var/tmp/zededa"
	DNCDirname      = tmpDirname + "/DeviceNetworkConfig"
	identityDirname = "/config"
)

type nimContext struct {
	devicenetwork.DeviceNetworkContext
	subGlobalConfig *pubsub.Subscription
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
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s\n", agentName)

	hardwaremodelFileName := identityDirname + "/hardwaremodel"
	var oldHardwaremodel string
	var model string
	b, err := ioutil.ReadFile(hardwaremodelFileName)
	if err == nil {
		oldHardwaremodel = strings.TrimSpace(string(b))
		model = oldHardwaremodel
	} else {
		model = hardware.GetHardwareModel()
	}

	// To better handle new hardware platforms log and blink if we
	// don't have a DeviceNetworkConfig
	// After some tries we fall back to default.json which is eth0, wlan0
	// and wwan0
	// XXX if we have a /config/DeviceUplinkConfig/override.json
	// we should proceed without a DNCFilename!
	tries := 0
	for {
		DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
		if _, err := os.Stat(DNCFilename); err == nil {
			break
		}
		// Tell the world that we have issues
		types.UpdateLedManagerConfig(10)
		log.Warningln(err)
		log.Warningf("You need to create this file for this hardware: %s\n",
			DNCFilename)
		time.Sleep(time.Second)
		tries += 1
		if tries == 120 { // Two minutes
			log.Infof("Falling back to using hardware model default\n")
			model = "default"
		}
	}

	pubDeviceNetworkStatus, err := pubsub.Publish(agentName,
		types.DeviceNetworkStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubDeviceNetworkStatus.ClearRestarted()

	pubDeviceUplinkConfig, err := pubsub.Publish(agentName,
		types.DeviceUplinkConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubDeviceUplinkConfig.ClearRestarted()

	nimCtx := nimContext{}
	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &nimCtx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	nimCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	nimCtx.ManufacturerModel = model
	nimCtx.DeviceNetworkConfig = &types.DeviceNetworkConfig{}
	nimCtx.DeviceUplinkConfig = &types.DeviceUplinkConfig{}
	nimCtx.DeviceNetworkStatus = &types.DeviceNetworkStatus{}
	nimCtx.PubDeviceUplinkConfig = pubDeviceUplinkConfig
	nimCtx.PubDeviceNetworkStatus = pubDeviceNetworkStatus

	// Get the initial DeviceNetworkConfig
	// Subscribe from "" means /var/tmp/zededa/
	subDeviceNetworkConfig, err := pubsub.Subscribe("",
		types.DeviceNetworkConfig{}, false,
		&nimCtx.DeviceNetworkContext)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkConfig.ModifyHandler = devicenetwork.HandleDNCModify
	subDeviceNetworkConfig.DeleteHandler = devicenetwork.HandleDNCDelete
	nimCtx.SubDeviceNetworkConfig = subDeviceNetworkConfig
	subDeviceNetworkConfig.Activate()

	// We get DeviceUplinkConfig from three sources in this priority:
	// 1. zedagent
	// 2. override file in /var/tmp/zededa/NetworkUplinkConfig/override.json
	// 3. self-generated file derived from per-platform DeviceNetworkConfig
	subDeviceUplinkConfigA, err := pubsub.Subscribe("zedagent",
		types.DeviceUplinkConfig{}, false,
		&nimCtx.DeviceNetworkContext)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceUplinkConfigA.ModifyHandler = devicenetwork.HandleDUCModify
	subDeviceUplinkConfigA.DeleteHandler = devicenetwork.HandleDUCDelete
	nimCtx.SubDeviceUplinkConfigA = subDeviceUplinkConfigA
	subDeviceUplinkConfigA.Activate()

	subDeviceUplinkConfigO, err := pubsub.Subscribe("",
		types.DeviceUplinkConfig{}, false,
		&nimCtx.DeviceNetworkContext)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceUplinkConfigO.ModifyHandler = devicenetwork.HandleDUCModify
	subDeviceUplinkConfigO.DeleteHandler = devicenetwork.HandleDUCDelete
	nimCtx.SubDeviceUplinkConfigO = subDeviceUplinkConfigO
	subDeviceUplinkConfigO.Activate()

	subDeviceUplinkConfigS, err := pubsub.Subscribe(agentName,
		types.DeviceUplinkConfig{}, false,
		&nimCtx.DeviceNetworkContext)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceUplinkConfigS.ModifyHandler = devicenetwork.HandleDUCModify
	subDeviceUplinkConfigS.DeleteHandler = devicenetwork.HandleDUCDelete
	nimCtx.SubDeviceUplinkConfigS = subDeviceUplinkConfigS
	subDeviceUplinkConfigS.Activate()

	devicenetwork.DoDNSUpdate(&nimCtx.DeviceNetworkContext)

	// Apply any changes from the uplink config to date.
	publishDeviceNetworkStatus(&nimCtx)

	// XXX should we make geoRedoTime configurable?
	// We refresh the gelocation information when the underlay
	// IP address(es) change, or once an hour.
	geoRedoTime := time.Hour

	// Timer for retries after failure etc. Should be less than geoRedoTime
	geoInterval := time.Duration(10 * time.Minute)
	geoMax := float64(geoInterval)
	geoMin := geoMax * 0.3
	geoTimer := flextimer.NewRangeTicker(time.Duration(geoMin),
		time.Duration(geoMax))

	// Look for address changes
	addrChanges := devicenetwork.AddrChangeInit(&nimCtx.DeviceNetworkContext)

	for {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkConfig.C:
			subDeviceNetworkConfig.ProcessChange(change)

		case change := <-subDeviceUplinkConfigA.C:
			subDeviceUplinkConfigA.ProcessChange(change)

		case change := <-subDeviceUplinkConfigO.C:
			subDeviceUplinkConfigO.ProcessChange(change)

		case change := <-subDeviceUplinkConfigS.C:
			subDeviceUplinkConfigS.ProcessChange(change)

		case change, ok := <-addrChanges:
			if !ok {
				log.Fatalf("addrChanges closed?\n")
			}
			if debug {
				log.Debugf("addrChanges %+v\n", change)
			}
			devicenetwork.AddrChange(&nimCtx.DeviceNetworkContext,
				change)

		case <-geoTimer.C:
			log.Debugln("geoTimer at", time.Now())
			change := devicenetwork.UpdateDeviceNetworkGeo(
				geoRedoTime, nimCtx.DeviceNetworkStatus)
			if change {
				publishDeviceNetworkStatus(&nimCtx)
			}
		}
	}
}

func publishDeviceNetworkStatus(ctx *nimContext) {
	ctx.PubDeviceNetworkStatus.Publish("global", ctx.DeviceNetworkStatus)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*nimContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*nimContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}
