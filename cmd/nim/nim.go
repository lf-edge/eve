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
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
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
	stdoutPtr := flag.Bool("s", false, "Use stdout instead of console")
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
	// XXX if we have a /config/DevicePortConfig/override.json
	// we should proceed without a DNCFilename!
	tries := 0
	for {
		DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
		_, err := os.Stat(DNCFilename)
		if err == nil {
			break
		}
		// Tell the world that we have issues
		types.UpdateLedManagerConfig(10)
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

	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	nimCtx.processArgs()

	// For limited output on console
	consolef := os.Stdout
	if !nimCtx.useStdout {
		consolef, err = os.OpenFile("/dev/console", os.O_RDWR|os.O_APPEND,
			0666)
		if err != nil {
			log.Fatal(err)
		}
	}
	multi := io.MultiWriter(logf, consolef)
	log.SetOutput(multi)

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s\n", agentName)

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
	nimCtx.DPCBeingUsed = &types.DevicePortConfig{}
	nimCtx.DPCBeingTested = &types.DevicePortConfig{}

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
		&nimCtx)
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

	// Timer for checking/verifying pending device network status
	dnsInterval := time.Duration(30 * time.Second)
	dnsMax := float64(dnsInterval)
	dnsMin := dnsMax * 0.9
	dnsTimer := flextimer.NewRangeTicker(time.Duration(dnsMin),
		time.Duration(dnsMax))
	parseDPCList := make(chan bool, 1)
	nimCtx.DeviceNetworkContext.ParseDPCList = parseDPCList

	// Periodic timer that tests device cloud connectivity
	// Timer for checking/verifying pending device network status
	networkTestInterval := time.Duration(5 * time.Minute)
	networkTestMax := float64(networkTestInterval)
	networkTestMin := networkTestMax * 0.9
	networkTestTimer := flextimer.NewRangeTicker(time.Duration(networkTestMin),
		time.Duration(networkTestMax))

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
		case _, ok := <-parseDPCList:
			if !ok {
				log.Infof("Parse DPC list channel closed?")
			} else {
				log.Debugln("Parsing DevicePortConfigList at", time.Now())
				dnc := &nimCtx.DeviceNetworkContext
				if dnc.NextDPCIndex >= 0 {
					log.Infof("Previous instance of Device port configuration " +
						"list verification in progress currently.")
				}
				dnc.PendDeviceNetworkStatus = nil
				dnc.NextDPCIndex = 0
				// Kick the DPC verify timer to tick now.
				dnsTimer.TickNow()
			}
		case _, ok := <-dnsTimer.C:
			if !ok {
				log.Infof("Device port test timer stopped?")
			} else {
				log.Debugln("dnsTimer at", time.Now())
				dnc := &nimCtx.DeviceNetworkContext
				ok := verifyDevicePortConfig(dnc)
				if ok == true {
					log.Debugln("Working Device port configuration available.")
				}
			}
		case _, ok := <-networkTestTimer.C:
			if !ok {
				log.Infof("Network test timer stopped?")
			} else {
				dnc := &nimCtx.DeviceNetworkContext
				ok := tryDeviceConnectivityToCloud(dnc, dnsTimer)
				if ok {
					log.Infof("Device connectivity to cloud worked at %v", time.Now())
				} else {
					log.Infof("Device connectivity to cloud failed at %v", time.Now())
				}
			}
		}
	}
}

func tryDeviceConnectivityToCloud(ctx *devicenetwork.DeviceNetworkContext,
	dnsTimer flextimer.FlexTickerHandle) bool {
	pass := devicenetwork.VerifyDeviceNetworkStatus(*ctx.DeviceNetworkStatus, 1)
	if pass {
		log.Infof("tryDeviceConnectivityToCloud: Device cloud connectivity test passed.")
		ctx.CloudConnectivityWorks = true
		return true
	} else {
		if !ctx.CloudConnectivityWorks {
			// If previous cloud connectivity test also failed, we declare
			// the device bricked. In this case we kick the process where
			// device tries to figure out a DevicePortConfig that works.
			if ctx.NextDPCIndex >= 0 {
				log.Infof("tryDeviceConnectivityToCloud: Device port configuration list " +
					"verification in progress")
				// Connectivity to cloud is already being figured out.
				// We wait till the next cloud connectivity test slot.
			} else {
				log.Infof("tryDeviceConnectivityToCloud: Triggering Device port " +
					"verification to resume cloud connectivity")
				ctx.PendDeviceNetworkStatus = nil
				ctx.NextDPCIndex = 0
				// Kick the DPC verify timer to tick now.
				dnsTimer.TickNow()
			}
		} else {
			ctx.CloudConnectivityWorks = false
		}
	}
	return false
}

func verifyDevicePortConfig(ctx *devicenetwork.DeviceNetworkContext) bool {
	if ctx.NextDPCIndex < 0 {
		return true
	}
	log.Debugln("verifyDevicePortConfig: Verifying DPC at index %d", ctx.NextDPCIndex)
	numDPCs := len(ctx.DevicePortConfigList.PortConfigList)

	dnStatus := ctx.PendDeviceNetworkStatus
	// XXX Check if there are any usable unicast ip addresses assigned.
	if dnStatus != nil && types.CountLocalAddrFreeNoLinkLocal(*dnStatus) > 0 {
		// We want connectivity to zedcloud via atleast one Management port.
		pass := devicenetwork.VerifyDeviceNetworkStatus(*dnStatus, 1)
		if pass {
			dpcBeingUsed := ctx.DPCBeingUsed.TimePriority
			dpcBeingTested := ctx.DPCBeingTested.TimePriority
			ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex].LastSucceeded = time.Now()
			if ctx.DPCBeingUsed == nil ||
				dpcBeingTested.After(dpcBeingUsed) ||
				dpcBeingTested.Equal(dpcBeingUsed) {
				log.Infof("verifyDevicePortConfig: Stopping Device Port configuration test"+
					" at index %d of Device port configuration list", ctx.NextDPCIndex)

				// XXX We should stop the network testing now.
				ctx.PendDeviceNetworkStatus = nil
				ctx.NextDPCIndex = -1

				ctx.DeviceNetworkStatus = dnStatus
				devicenetwork.DoDNSUpdate(ctx)
				ctx.DPCBeingUsed = ctx.DPCBeingTested
				*ctx.DevicePortConfig = *ctx.DPCBeingUsed
				return true
			} else {
				// Should we stop here?
				log.Infof("verifyDevicePortConfig: Tested configuration %s "+
					"has a timestamp that is earlier than timestapmp of "+
					"configuration being used %s", ctx.DPCBeingTested, ctx.DPCBeingUsed)
				ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex].LastFailed = time.Now()
				//ctx.PendDeviceNetworkStatus = nil
				//ctx.NextDPCIndex = -1
			}
		} else {
			log.Infof("verifyDevicePortConfig: DPC configuration at DPC list "+
				"index %d did not work, moving to next valid DPC (if present)",
				ctx.NextDPCIndex)
			ctx.NextDPCIndex += 1
		}
	}
	if ctx.NextDPCIndex >= numDPCs {
		log.Errorf("verifyDevicePortConfig: No working device port configuration found. " +
			"Starting Device port configuration list test again.")
		ctx.PendDeviceNetworkStatus = nil
		ctx.NextDPCIndex = 0
		return false
	}
	portConfig := ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex]
	ctx.DevicePortConfigTime = portConfig.TimePriority

	if !reflect.DeepEqual(*ctx.DevicePortConfig, portConfig) {
		log.Infof("verifyDevicePortConfig: DevicePortConfig change from %v to %v\n",
			*ctx.DevicePortConfig, portConfig)
		devicenetwork.UpdateDhcpClient(portConfig, *ctx.DevicePortConfig)
		*ctx.DevicePortConfig = portConfig
		*ctx.DPCBeingTested = portConfig
	}
	status, _ := devicenetwork.MakeDeviceNetworkStatus(portConfig,
		*ctx.DeviceNetworkStatus)
	ctx.PendDeviceNetworkStatus = &status

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
	ctx.debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		ctx.debugOverride)
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
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}
