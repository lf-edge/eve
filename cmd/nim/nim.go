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

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
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
	globalConfig    *types.GlobalConfig
	sshAccess       bool
	allowAppVnc     bool

	networkFallbackAnyEth types.TriState
	fallbackPorts         []string // All UP Ethernet ports
	fallbackPortMap       map[string]bool

	// CLI args
	debug         bool
	debugOverride bool // From command line arg
	useStdout     bool
	version       bool
	curpart       string
}

// Set from Makefile
var Version = "No version specified"

func (ctx *nimContext) processArgs() {
	versionPtr := flag.Bool("v", false, "Print Version of the agent.")
	debugPtr := flag.Bool("d", false, "Set Debug level")
	curpartPtr := flag.String("c", "", "Current partition")
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
	ctx.curpart = *curpartPtr
	ctx.version = *versionPtr
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
	nimCtx := nimContext{fallbackPortMap: make(map[string]bool)}
	nimCtx.AssignableAdapters = &types.AssignableAdapters{}
	nimCtx.sshAccess = true // Kernel default - no iptables filters
	nimCtx.globalConfig = &types.GlobalConfigDefaults

	nimCtx.processArgs()
	if nimCtx.version {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}

	logf, err := agentlog.Init(agentName, nimCtx.curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()
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
	subGlobalConfig.SynchronizedHandler = handleGlobalConfigSynchronized
	nimCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	nimCtx.ManufacturerModel = model
	nimCtx.DeviceNetworkConfig = &types.DeviceNetworkConfig{}
	nimCtx.DevicePortConfig = &types.DevicePortConfig{}
	item, _ := pubDevicePortConfigList.Get("global")
	if item != nil {
		dpcl := cast.CastDevicePortConfigList(item)
		nimCtx.DevicePortConfigList = &dpcl
		log.Infof("Initial DPCL %+v\n", nimCtx.DevicePortConfigList)
	} else {
		nimCtx.DevicePortConfigList = &types.DevicePortConfigList{}
	}
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
	// 2. override file in /var/tmp/zededa/NetworkPortConfig/*.json
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

	// We refresh the gelocation information when the underlay
	// IP address(es) change, plus periodically based on this timer
	geoRedoTime := time.Duration(nimCtx.globalConfig.NetworkGeoRedoTime) * time.Second

	// Timer for retries after failure etc. Should be less than geoRedoTime
	geoInterval := time.Duration(nimCtx.globalConfig.NetworkGeoRetryTime) * time.Second
	geoMax := float64(geoInterval)
	geoMin := geoMax * 0.3
	geoTimer := flextimer.NewRangeTicker(time.Duration(geoMin),
		time.Duration(geoMax))

	dnc := &nimCtx.DeviceNetworkContext
	// TIme we wait for DHCP to get an address before giving up
	dnc.DPCTestDuration = nimCtx.globalConfig.NetworkTestDuration

	// Timer for checking/verifying pending device network status
	// We stop this timer before using in the select loop below, because
	// we do not want the DPC list verification to start yet. We need a place
	// Holder in the select loop.
	// Let the select loop have this stopped timer for now and
	// create a new timer when it's deemed required (change in DPC config).
	pendTimer := time.NewTimer(time.Duration(dnc.DPCTestDuration) * time.Second)
	pendTimer.Stop()
	dnc.Pending.PendTimer = pendTimer

	// Periodic timer that tests device cloud connectivity
	dnc.NetworkTestInterval = nimCtx.globalConfig.NetworkTestInterval
	networkTestInterval := time.Duration(time.Duration(dnc.NetworkTestInterval) * time.Second)
	networkTestTimer := time.NewTimer(networkTestInterval)
	dnc.NetworkTestTimer = networkTestTimer
	// We start assuming cloud connectivity works
	dnc.CloudConnectivityWorks = true

	dnc.NetworkTestBetterInterval = nimCtx.globalConfig.NetworkTestBetterInterval
	if dnc.NetworkTestBetterInterval == 0 {
		log.Warnln("NOT running TestBetterTimer")
		// Dummy which is stopped needed for select loop
		networkTestBetterTimer := time.NewTimer(time.Hour)
		networkTestBetterTimer.Stop()
		dnc.NetworkTestBetterTimer = networkTestBetterTimer
	} else {
		networkTestBetterInterval := time.Duration(dnc.NetworkTestBetterInterval) * time.Second
		networkTestBetterTimer := time.NewTimer(networkTestBetterInterval)
		dnc.NetworkTestBetterTimer = networkTestBetterTimer
	}

	// Look for address and link changes
	addrChanges := devicenetwork.AddrChangeInit(&nimCtx.DeviceNetworkContext)
	linkChanges := devicenetwork.LinkChangeInit()

	// To avoid a race between domainmgr starting and moving this to pciback
	// and zedagent publishing its DevicePortConfig using those assigned-away
	// adapter(s), we first wait for domainmgr to initialize AA, then enable
	// subDevicePortConfigA.
	for !nimCtx.AssignableAdapters.Initialized {
		log.Infof("Waiting for AA to initialize")
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkConfig.C:
			subDeviceNetworkConfig.ProcessChange(change)

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
			devicenetwork.AddrChange(&nimCtx.DeviceNetworkContext,
				change)

		case change, ok := <-linkChanges:
			if !ok {
				log.Fatalf("linkChanges closed?\n")
			}
			if devicenetwork.LinkChange(change) {
				handleLinkChange(&nimCtx)
				// XXX trigger testing??
			}

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
				start := time.Now()
				log.Debugf("Starting test of Device connectivity to cloud")
				ok := tryDeviceConnectivityToCloud(dnc)
				if ok {
					log.Debugf("Device connectivity to cloud worked. Took %v",
						time.Since(start))
				} else {
					log.Infof("Device connectivity to cloud failed. Took %v",
						time.Since(start))
				}
			}

		case _, ok := <-dnc.NetworkTestBetterTimer.C:
			if !ok {
				log.Infof("Network testBetterTimer stopped?")
			} else if dnc.NextDPCIndex == 0 {
				log.Debugf("Network testBetterTimer at zero ignored")
			} else {
				start := time.Now()
				log.Infof("Network testBetterTimer at index %d",
					dnc.NextDPCIndex)
				devicenetwork.RestartVerify(dnc,
					"NetworkTestBetterTimer")
				log.Infof("Network testBetterTimer done at index %d. Took %v",
					dnc.NextDPCIndex, time.Since(start))
			}

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
		}
	}
	log.Infof("AA initialized")

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
			devicenetwork.AddrChange(&nimCtx.DeviceNetworkContext,
				change)

		case change, ok := <-linkChanges:
			if !ok {
				log.Fatalf("linkChanges closed?\n")
			}
			if devicenetwork.LinkChange(change) {
				handleLinkChange(&nimCtx)
				// XXX trigger testing??
			}

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
				start := time.Now()
				log.Debugf("Starting test of Device connectivity to cloud")
				ok := tryDeviceConnectivityToCloud(dnc)
				if ok {
					log.Debugf("Device connectivity to cloud worked. Took %v",
						time.Since(start))
				} else {
					log.Infof("Device connectivity to cloud failed. Took %v",
						time.Since(start))
				}
			}

		case _, ok := <-dnc.NetworkTestBetterTimer.C:
			if !ok {
				log.Infof("Network testBetterTimer stopped?")
			} else if dnc.NextDPCIndex == 0 {
				log.Debugf("Network testBetterTimer at zero ignored")
			} else {
				start := time.Now()
				log.Infof("Network testBetterTimer at index %d",
					dnc.NextDPCIndex)
				devicenetwork.RestartVerify(dnc,
					"NetworkTestBetterTimer")
				log.Infof("Network testBetterTimer done at index %d. Took %v",
					dnc.NextDPCIndex, time.Since(start))
			}

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
		}
	}
}

func handleLinkChange(ctx *nimContext) {
	ifs := devicenetwork.IfindexGetLastResort()
	if !cmp.Equal(ifs, ctx.fallbackPorts) {
		log.Infof("IfindexGetLastResort: updated to %v\n", ifs)
		ctx.fallbackPorts = ifs
		if ctx.networkFallbackAnyEth == types.TS_ENABLED {
			updateFallbackAnyEth(ctx)
		}
	}
	// Create superset; update to have the latest upFlag
	ifmap := devicenetwork.IfindexGetLastResortMap()
	changed := false
	for ifname, upFlag := range ifmap {
		v, ok := ctx.fallbackPortMap[ifname]
		if ok && v == upFlag {
			continue
		}
		changed = true
		if !ok {
			log.Infof("fallbackPortMap added %s %t\n", ifname, upFlag)
		} else {
			log.Infof("fallbackPortMap updated %s to %t\n", ifname, upFlag)
		}
		ctx.fallbackPortMap[ifname] = upFlag
	}
	if changed {
		log.Infof("new fallbackPortmap: %+v\n", ctx.fallbackPortMap)
	}
}

func tryDeviceConnectivityToCloud(ctx *devicenetwork.DeviceNetworkContext) bool {
	err := devicenetwork.VerifyDeviceNetworkStatus(*ctx.DeviceNetworkStatus, 1)
	if err == nil {
		log.Infof("tryDeviceConnectivityToCloud: Device cloud connectivity test passed.")
		if ctx.NextDPCIndex < len(ctx.DevicePortConfigList.PortConfigList) {
			cur := ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex]
			cur.LastSucceeded = time.Now()
		}

		ctx.CloudConnectivityWorks = true
		// Restart network test timer for next slot.
		ctx.NetworkTestTimer = time.NewTimer(time.Duration(ctx.NetworkTestInterval) * time.Second)
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
			log.Infof("tryDeviceConnectivityToCloud: Triggering Device port "+
				"verification to resume cloud connectivity after %s",
				err)
			// Start DPC verification to find a working configuration
			devicenetwork.RestartVerify(ctx, "tryDeviceConnectivityToCloud")
		}
	} else {
		// Restart network test timer for next slot.
		ctx.NetworkTestTimer = time.NewTimer(time.Duration(ctx.NetworkTestInterval) * time.Second)
		ctx.CloudConnectivityWorks = false
	}
	return false
}

func publishDeviceNetworkStatus(ctx *nimContext) {
	log.Infof("PublishDeviceNetworkStatus: %+v\n",
		ctx.DeviceNetworkStatus)
	ctx.DeviceNetworkStatus.Testing = false
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
	first := !ctx.GCInitialized
	if gcp != nil {
		if !cmp.Equal(ctx.globalConfig, *gcp) {
			log.Infof("handleGlobalConfigModify: diff %v\n",
				cmp.Diff(ctx.globalConfig, *gcp))
			updated := types.ApplyGlobalConfig(*gcp)
			log.Infof("handleGlobalConfigModify: updated with defaults %v\n",
				cmp.Diff(*gcp, updated))
			*gcp = updated
		}
		if gcp.SshAccess != ctx.sshAccess || first {
			ctx.sshAccess = gcp.SshAccess
			iptables.UpdateSshAccess(ctx.sshAccess, first)
		}
		if gcp.AllowAppVnc != ctx.allowAppVnc || first {
			ctx.allowAppVnc = gcp.AllowAppVnc
			iptables.UpdateVncAccess(ctx.allowAppVnc)
		}
		if gcp.NetworkFallbackAnyEth != ctx.networkFallbackAnyEth || first {
			ctx.networkFallbackAnyEth = gcp.NetworkFallbackAnyEth
			updateFallbackAnyEth(ctx)
		}
		ctx.globalConfig = gcp
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

// In case there is no GlobalConfig.json this will move us forward
func handleGlobalConfigSynchronized(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*nimContext)

	log.Infof("handleGlobalConfigSynchronized(%v)\n", done)
	if done {
		first := !ctx.GCInitialized
		if first {
			iptables.UpdateSshAccess(ctx.sshAccess, first)
		}
		ctx.GCInitialized = true
	}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func updateFallbackAnyEth(ctx *nimContext) {
	log.Infof("updateFallbackAnyEth: enable %v ifs %v\n",
		ctx.networkFallbackAnyEth, ctx.fallbackPorts)
	if ctx.networkFallbackAnyEth == types.TS_ENABLED {
		devicenetwork.UpdateLastResortPortConfig(&ctx.DeviceNetworkContext,
			ctx.fallbackPorts)
	} else if ctx.networkFallbackAnyEth == types.TS_DISABLED {
		devicenetwork.RemoveLastResortPortConfig(&ctx.DeviceNetworkContext)
	}
}
