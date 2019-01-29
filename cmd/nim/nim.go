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
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/iptables"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
)

const (
	agentName   = "nim"
	tmpDirname  = "/var/tmp/zededa"
	DNCDirname  = tmpDirname + "/DeviceNetworkConfig"
	DPCOverride = tmpDirname + "/DevicePortConfig/override.json"
)

type nimContext struct {
	devicenetwork.DeviceNetworkContext
	subGlobalConfig *pubsub.Subscription
	GCInitialized   bool // Received initial GlobalConfig
	sshAccess       bool

	// CLI args
	debug         bool
	debugOverride bool // From command line arg
	useStdout     bool
}

// Set from Makefile
var Version = "No version specified"

func (ctx *nimContext) processArgs() {
	versionPtr := flag.Bool("v", false, "Print Version of the agent.")
	debugPtr := flag.Bool("d", false, "Set Debug level")
	stdoutPtr := flag.Bool("s", false, "Use stdout")
	flag.Parse()

	ctx.debug = *debugPtr
	ctx.debugOverride = ctx.debug
	ctx.useStdout = *stdoutPtr
	if ctx.debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		os.Exit(0)
	}
}

func waitForDeviceNetworkConfigFile() string {
	model := hardware.GetHardwareModel()

	// To better handle new hardware platforms log and blink if we
	// don't have a DeviceNetworkConfig
	// After some tries we fall back to default.json which is eth0, wlan0
	// and wwan0
	// If we have a DevicePortConfig/override.json we proceed
	// without a DNCFilename!
	tries := 0
	if fileExists(DPCOverride) {
		model = "default"
		return model
	}
	for {
		DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
		_, err := os.Stat(DNCFilename)
		if err == nil {
			break
		}
		// Tell the world that we have issues
		types.UpdateLedManagerConfig(11)
		log.Warningln(err)
		log.Warningf("You need to create this file for this hardware: %s\n",
			DNCFilename)
		time.Sleep(time.Second)
		tries++
		if tries == 120 { // Two minutes
			log.Infof("Falling back to using hardware model default\n")
			model = "default"
		}
	}
	return model
}

// Run - Main function - invoked from zedbox.go
func Run() {
	nimCtx := nimContext{}
	nimCtx.AssignableAdapters = &types.AssignableAdapters{}
	nimCtx.sshAccess = true

	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	nimCtx.processArgs()

	if nimCtx.useStdout {
		multi := io.MultiWriter(logf, os.Stdout)
		log.SetOutput(multi)
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s\n", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName)

	model := waitForDeviceNetworkConfigFile()

	pubDeviceNetworkStatus, err := pubsub.Publish(agentName,
		types.DeviceNetworkStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubDeviceNetworkStatus.ClearRestarted()

	pubDevicePortConfig, err := pubsub.Publish(agentName,
		types.DevicePortConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubDevicePortConfig.ClearRestarted()

	pubDevicePortConfigList, err := pubsub.PublishPersistent(agentName,
		types.DevicePortConfigList{})
	if err != nil {
		log.Fatal(err)
	}
	pubDevicePortConfigList.ClearRestarted()

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
	nimCtx.DevicePortConfig = &types.DevicePortConfig{}
	nimCtx.DevicePortConfigList = &types.DevicePortConfigList{}
	nimCtx.DeviceNetworkStatus = &types.DeviceNetworkStatus{}
	nimCtx.PubDevicePortConfig = pubDevicePortConfig
	nimCtx.PubDevicePortConfigList = pubDevicePortConfigList
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

	// We get DevicePortConfig from three sources in this priority:
	// 1. zedagent publishing NetworkPortConfig
	// 2. override file in /var/tmp/zededa/NetworkPortConfig/override.json
	// 3. self-generated file derived from per-platform DeviceNetworkConfig
	subDevicePortConfigA, err := pubsub.Subscribe("zedagent",
		types.DevicePortConfig{}, false,
		&nimCtx.DeviceNetworkContext)
	if err != nil {
		log.Fatal(err)
	}
	subDevicePortConfigA.ModifyHandler = devicenetwork.HandleDPCModify
	subDevicePortConfigA.DeleteHandler = devicenetwork.HandleDPCDelete
	nimCtx.SubDevicePortConfigA = subDevicePortConfigA
	subDevicePortConfigA.Activate()

	subDevicePortConfigO, err := pubsub.Subscribe("",
		types.DevicePortConfig{}, false,
		&nimCtx.DeviceNetworkContext)
	if err != nil {
		log.Fatal(err)
	}
	subDevicePortConfigO.ModifyHandler = devicenetwork.HandleDPCModify
	subDevicePortConfigO.DeleteHandler = devicenetwork.HandleDPCDelete
	nimCtx.SubDevicePortConfigO = subDevicePortConfigO
	subDevicePortConfigO.Activate()

	subDevicePortConfigS, err := pubsub.Subscribe(agentName,
		types.DevicePortConfig{}, false,
		&nimCtx.DeviceNetworkContext)
	if err != nil {
		log.Fatal(err)
	}
	subDevicePortConfigS.ModifyHandler = devicenetwork.HandleDPCModify
	subDevicePortConfigS.DeleteHandler = devicenetwork.HandleDPCDelete
	nimCtx.SubDevicePortConfigS = subDevicePortConfigS
	subDevicePortConfigS.Activate()

	subAssignableAdapters, err := pubsub.Subscribe("domainmgr",
		types.AssignableAdapters{}, false,
		&nimCtx.DeviceNetworkContext)
	if err != nil {
		log.Fatal(err)
	}
	subAssignableAdapters.ModifyHandler = devicenetwork.HandleAssignableAdaptersModify
	subAssignableAdapters.DeleteHandler = devicenetwork.HandleAssignableAdaptersDelete
	nimCtx.SubAssignableAdapters = subAssignableAdapters
	subAssignableAdapters.Activate()

	devicenetwork.DoDNSUpdate(&nimCtx.DeviceNetworkContext)

	// Apply any changes from the port config to date.
	publishDeviceNetworkStatus(&nimCtx)

	// Wait for initial GlobalConfig
	for !nimCtx.GCInitialized {
		log.Infof("Waiting for GCInitialized\n")
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
		}
	}

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

	dnc := &nimCtx.DeviceNetworkContext
	dnc.DPCTestDuration = 30 // seconds
	// Timer for checking/verifying pending device network status
	pendTimer := time.NewTimer(dnc.DPCTestDuration * time.Second)
	// We stop this timer before using in the select loop below, because
	// we do not want the DPC list verification to start yet. We need a place
	// holder in the select loop.
	// Let the select loop have this stopped timer for now and
	// create a new timer when it's deemed required (change in DPC config).
	pendTimer.Stop()
	dnc.Pending.PendTimer = pendTimer

	// Periodic timer that tests device cloud connectivity
	dnc.NetworkTestInterval = 5 // minutes
	networkTestInterval := time.Duration(dnc.NetworkTestInterval * time.Minute)
	networkTestTimer := time.NewTimer(networkTestInterval)
	dnc.NetworkTestTimer = networkTestTimer
	// We start assuming cloud connectivity works
	dnc.CloudConnectivityWorks = true

	// Look for address changes
	addrChanges := devicenetwork.AddrChangeInit(&nimCtx.DeviceNetworkContext)

	// The handlers call UpdateLedManagerConfig with 2 and 1 as the
	// number of usable IP addresses increases from zero and drops
	// back to zero, respectively.
	for {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkConfig.C:
			subDeviceNetworkConfig.ProcessChange(change)

		case change := <-subDevicePortConfigA.C:
			subDevicePortConfigA.ProcessChange(change)

		case change := <-subDevicePortConfigO.C:
			subDevicePortConfigO.ProcessChange(change)

		case change := <-subDevicePortConfigS.C:
			subDevicePortConfigS.ProcessChange(change)

		case change := <-subAssignableAdapters.C:
			subAssignableAdapters.ProcessChange(change)

		case change, ok := <-addrChanges:
			if !ok {
				log.Fatalf("addrChanges closed?\n")
			}
			if nimCtx.debug {
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
		case _, ok := <-dnc.Pending.PendTimer.C:
			if !ok {
				log.Infof("Device port test timer stopped?")
			} else {
				log.Debugln("PendTimer at", time.Now())
				devicenetwork.VerifyDevicePortConfig(dnc)
			}
		case _, ok := <-dnc.NetworkTestTimer.C:
			if !ok {
				log.Infof("Network test timer stopped?")
			} else {
				ok := tryDeviceConnectivityToCloud(dnc)
				if ok {
					log.Infof("Device connectivity to cloud worked at %v", time.Now())
				} else {
					log.Infof("Device connectivity to cloud failed at %v", time.Now())
				}
			}

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
		}
	}
}

func tryDeviceConnectivityToCloud(ctx *devicenetwork.DeviceNetworkContext) bool {
	pass := devicenetwork.VerifyDeviceNetworkStatus(*ctx.DeviceNetworkStatus, 1)
	if pass {
		log.Infof("tryDeviceConnectivityToCloud: Device cloud connectivity test passed.")
		ctx.CloudConnectivityWorks = true
		// Restart network test timer for next slot.
		ctx.NetworkTestTimer = time.NewTimer(ctx.NetworkTestInterval * time.Minute)
		return true
	}
	if !ctx.CloudConnectivityWorks {
		// If previous cloud connectivity test also failed, it means
		// that the current DPC configuration stopped working.
		// In this case we start the process where device tries to
		// figure out a DevicePortConfig that works.
		if ctx.Pending.Inprogress {
			log.Infof("tryDeviceConnectivityToCloud: Device port configuration list " +
				"verification in progress")
			// Connectivity to cloud is already being figured out.
			// We wait till the next cloud connectivity test slot.
		} else {
			log.Infof("tryDeviceConnectivityToCloud: Triggering Device port " +
				"verification to resume cloud connectivity")
			// Start DPC verification to find a working configuration
			devicenetwork.RestartVerify(ctx, "tryDeviceConnectivityToCloud")
		}
	} else {
		// Restart network test timer for next slot.
		ctx.NetworkTestTimer = time.NewTimer(ctx.NetworkTestInterval * time.Minute)
		ctx.CloudConnectivityWorks = false
	}
	return false
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
	var gcp *types.GlobalConfig
	ctx.debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		ctx.debugOverride)
	// XXX note different polarity
	if gcp != nil && gcp.NoSshAccess == ctx.sshAccess {
		first := !ctx.GCInitialized
		ctx.sshAccess = !gcp.NoSshAccess
		iptables.UpdateSshAccess(ctx.sshAccess, first)
	}
	ctx.GCInitialized = true
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
	ctx.debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		ctx.debugOverride)
	ctx.GCInitialized = false
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
