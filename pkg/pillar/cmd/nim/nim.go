// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage the network interfaces based on configuration from
// different sources. Attempts to test configuration changes before applying
// them.
// Maintains old configuration as lower-priority but always tries to move to the
// most recent aka highest priority configuration.

package nim

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	pubsublegacy "github.com/lf-edge/eve/pkg/pillar/pubsub/legacy"
	"github.com/lf-edge/eve/pkg/pillar/ssh"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	agentName = "nim"
	// Time limits for event loop handlers; shorter for nim than other agents
	errorTime   = 60 * time.Second
	warningTime = 40 * time.Second
)

type nimContext struct {
	devicenetwork.DeviceNetworkContext
	subGlobalConfig   pubsub.Subscription
	GCInitialized     bool // Received initial GlobalConfig
	globalConfig      *types.GlobalConfig
	sshAccess         bool
	sshAuthorizedKeys string
	allowAppVnc       bool

	subNetworkInstanceStatus pubsub.Subscription

	networkFallbackAnyEth types.TriState
	fallbackPortMap       map[string]bool
	filteredFallback      map[string]bool

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

// Run - Main function - invoked from zedbox.go
func Run(ps *pubsub.PubSub) {
	nimCtx := nimContext{
		fallbackPortMap:  make(map[string]bool),
		filteredFallback: make(map[string]bool),
	}
	nimCtx.AssignableAdapters = &types.AssignableAdapters{}
	nimCtx.sshAccess = true // Kernel default - no iptables filters
	nimCtx.globalConfig = &types.GlobalConfigDefaults

	nimCtx.processArgs()
	if nimCtx.version {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}

	err := agentlog.Init(agentName, nimCtx.curpart)
	if err != nil {
		log.Fatal(err)
	}

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s\n", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	// Make sure we have a GlobalConfig file with defaults
	utils.EnsureGCFile()

	pubDeviceNetworkStatus, err := pubsublegacy.Publish(agentName,
		types.DeviceNetworkStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubDeviceNetworkStatus.ClearRestarted()

	pubDevicePortConfig, err := pubsublegacy.Publish(agentName,
		types.DevicePortConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubDevicePortConfig.ClearRestarted()

	pubDevicePortConfigList, err := pubsublegacy.PublishPersistent(agentName,
		types.DevicePortConfigList{})
	if err != nil {
		log.Fatal(err)
	}
	pubDevicePortConfigList.ClearRestarted()

	// Look for global config such as log levels
	subGlobalConfig, err := pubsublegacy.Subscribe("", types.GlobalConfig{},
		false, &nimCtx, &pubsub.SubscriptionOptions{
			CreateHandler: handleGlobalConfigModify,
			ModifyHandler: handleGlobalConfigModify,
			DeleteHandler: handleGlobalConfigDelete,
			SyncHandler:   handleGlobalConfigSynchronized,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	nimCtx.DevicePortConfig = &types.DevicePortConfig{}
	nimCtx.DeviceNetworkStatus = &types.DeviceNetworkStatus{}
	nimCtx.PubDevicePortConfig = pubDevicePortConfig
	nimCtx.PubDevicePortConfigList = pubDevicePortConfigList
	nimCtx.PubDeviceNetworkStatus = pubDeviceNetworkStatus
	dnc := &nimCtx.DeviceNetworkContext
	devicenetwork.IngestPortConfigList(dnc)

	// We get DevicePortConfig from three sources in this priority:
	// 1. zedagent publishing DevicePortConfig
	// 2. override file in /var/tmp/zededa/DevicePortConfig/*.json
	// 3. "lastresort" derived from the set of network interfaces
	subDevicePortConfigA, err := pubsublegacy.Subscribe("zedagent",
		types.DevicePortConfig{}, false,
		&nimCtx.DeviceNetworkContext, &pubsub.SubscriptionOptions{
			CreateHandler: devicenetwork.HandleDPCModify,
			ModifyHandler: devicenetwork.HandleDPCModify,
			DeleteHandler: devicenetwork.HandleDPCDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.SubDevicePortConfigA = subDevicePortConfigA
	subDevicePortConfigA.Activate()

	subDevicePortConfigO, err := pubsublegacy.Subscribe("",
		types.DevicePortConfig{}, false,
		&nimCtx.DeviceNetworkContext, &pubsub.SubscriptionOptions{
			CreateHandler: devicenetwork.HandleDPCModify,
			ModifyHandler: devicenetwork.HandleDPCModify,
			DeleteHandler: devicenetwork.HandleDPCDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.SubDevicePortConfigO = subDevicePortConfigO
	subDevicePortConfigO.Activate()

	subDevicePortConfigS, err := pubsublegacy.Subscribe(agentName,
		types.DevicePortConfig{}, false,
		&nimCtx.DeviceNetworkContext, &pubsub.SubscriptionOptions{
			CreateHandler: devicenetwork.HandleDPCModify,
			ModifyHandler: devicenetwork.HandleDPCModify,
			DeleteHandler: devicenetwork.HandleDPCDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.SubDevicePortConfigS = subDevicePortConfigS
	subDevicePortConfigS.Activate()

	subAssignableAdapters, err := pubsublegacy.Subscribe("domainmgr",
		types.AssignableAdapters{}, false,
		&nimCtx.DeviceNetworkContext, &pubsub.SubscriptionOptions{
			CreateHandler: devicenetwork.HandleAssignableAdaptersModify,
			ModifyHandler: devicenetwork.HandleAssignableAdaptersModify,
			DeleteHandler: devicenetwork.HandleAssignableAdaptersDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.SubAssignableAdapters = subAssignableAdapters
	subAssignableAdapters.Activate()

	subNetworkInstanceStatus, err := pubsublegacy.Subscribe("zedrouter",
		types.NetworkInstanceStatus{}, false, &nimCtx, &pubsub.SubscriptionOptions{
			CreateHandler: handleNetworkInstanceModify,
			ModifyHandler: handleNetworkInstanceModify,
			DeleteHandler: handleNetworkInstanceDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.subNetworkInstanceStatus = subNetworkInstanceStatus
	subNetworkInstanceStatus.Activate()

	devicenetwork.DoDNSUpdate(&nimCtx.DeviceNetworkContext)

	// Apply any changes from the port config to date.
	publishDeviceNetworkStatus(&nimCtx)

	// Wait for initial GlobalConfig
	for !nimCtx.GCInitialized {
		log.Infof("Waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		}
	}
	log.Infof("processed GlobalConfig")

	// We refresh the gelocation information when the underlay
	// IP address(es) change, plus periodically based on this timer
	geoRedoTime := time.Duration(nimCtx.globalConfig.NetworkGeoRedoTime) * time.Second

	// Timer for retries after failure etc. Should be less than geoRedoTime
	geoInterval := time.Duration(nimCtx.globalConfig.NetworkGeoRetryTime) * time.Second
	geoMax := float64(geoInterval)
	geoMin := geoMax * 0.3
	geoTimer := flextimer.NewRangeTicker(time.Duration(geoMin),
		time.Duration(geoMax))

	// Time we wait for DHCP to get an address before giving up
	dnc.DPCTestDuration = nimCtx.globalConfig.NetworkTestDuration

	// Timer for checking/verifying pending device network status
	// We stop this timer before using in the select loop below, because
	// we do not want the DPC list verification to start yet. We need a place
	// holder in the select loop.
	// Let the select loop have this stopped timer for now and
	// create a new timer when it's deemed required (change in DPC config).
	pendTimer := time.NewTimer(time.Duration(dnc.DPCTestDuration) * time.Second)
	pendTimer.Stop()
	dnc.Pending.PendTimer = pendTimer

	// Periodic timer that tests device cloud connectivity
	dnc.NetworkTestInterval = nimCtx.globalConfig.NetworkTestInterval
	dnc.NetworkTestTimer = time.NewTimer(time.Duration(dnc.NetworkTestInterval) * time.Second)
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
	routeChanges := devicenetwork.RouteChangeInit()
	addrChanges := devicenetwork.AddrChangeInit()
	linkChanges := devicenetwork.LinkChangeInit()

	// Build an initial lastresort by picking up initial links
	// XXX hack to pre-populate
	for idx := 0; idx < 16; idx++ {
		devicenetwork.IfindexToName(idx)
	}
	handleLinkChange(&nimCtx)
	updateFilteredFallback(&nimCtx)

	// Kick off intial configuration, which could be remembered from last boot
	// Prunes any useless entries
	devicenetwork.IngestPortConfigList(dnc)

	for nimCtx.networkFallbackAnyEth == types.TS_ENABLED &&
		len(dnc.DevicePortConfigList.PortConfigList) == 0 {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDevicePortConfigS.MsgChan():
			subDevicePortConfigS.ProcessChange(change)
			log.Infof("Got subDevicePortConfigS: len %d",
				len(dnc.DevicePortConfigList.PortConfigList))

		case <-stillRunning.C:
			// Need StillRunning when ports yet Ethernets
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}

	devicenetwork.RestartVerify(dnc, "Initial config")

	// To avoid a race between domainmgr starting and moving this to pciback
	// and zedagent publishing its DevicePortConfig using those assigned-away
	// adapter(s), we first wait for domainmgr to initialize AA, then enable
	// subDevicePortConfigA.
	// This wait can take a very long time since we first need to get
	// some usable IP addresses, or have waitforaddr time out, before we
	// even start the other agents. Punch StillRunning
	for !nimCtx.AssignableAdapters.Initialized {
		log.Infof("Waiting for AA to initialize")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDevicePortConfigO.MsgChan():
			subDevicePortConfigO.ProcessChange(change)

		case change := <-subDevicePortConfigS.MsgChan():
			subDevicePortConfigS.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)
			updateFilteredFallback(&nimCtx)

		case change := <-subNetworkInstanceStatus.MsgChan():
			subNetworkInstanceStatus.ProcessChange(change)

		case change, ok := <-addrChanges:
			start := time.Now()
			if !ok {
				log.Errorf("addrChanges closed\n")
				// XXX Need to discard all cached information?
				addrChanges = devicenetwork.AddrChangeInit()
			} else {
				ch, ifindex := devicenetwork.AddrChange(nimCtx.DeviceNetworkContext, change)
				if ch {
					handleInterfaceChange(&nimCtx, ifindex,
						"AddrChange", true)
				}
			}
			pubsub.CheckMaxTimeTopic(agentName, "addrChanges", start,
				warningTime, errorTime)

		case change, ok := <-linkChanges:
			start := time.Now()
			if !ok {
				log.Errorf("linkChanges closed\n")
				linkChanges = devicenetwork.LinkChangeInit()
				// XXX Need to discard all cached information?
			} else {
				ch, ifindex := devicenetwork.LinkChange(change)
				if ch {
					handleLinkChange(&nimCtx)
					handleInterfaceChange(&nimCtx, ifindex,
						"LinkChange", true)
				}
			}
			pubsub.CheckMaxTimeTopic(agentName, "linkChanges", start,
				warningTime, errorTime)

		case change, ok := <-routeChanges:
			start := time.Now()
			if !ok {
				log.Errorf("routeChanges closed\n")
				routeChanges = devicenetwork.RouteChangeInit()
			} else {
				ch, ifindex := devicenetwork.RouteChange(nimCtx.DeviceNetworkContext, change)
				if ch {
					handleInterfaceChange(&nimCtx, ifindex,
						"RouteChange", false)
				}
			}
			pubsub.CheckMaxTimeTopic(agentName, "linkChanges", start,
				warningTime, errorTime)

		case <-geoTimer.C:
			start := time.Now()
			log.Debugln("geoTimer at", time.Now())
			change := devicenetwork.UpdateDeviceNetworkGeo(
				geoRedoTime, nimCtx.DeviceNetworkStatus)
			if change {
				publishDeviceNetworkStatus(&nimCtx)
			}
			pubsub.CheckMaxTimeTopic(agentName, "geoTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.Pending.PendTimer.C:
			start := time.Now()
			if !ok {
				log.Infof("Device port test timer stopped?")
			} else {
				log.Debugln("PendTimer at", time.Now())
				devicenetwork.VerifyDevicePortConfig(dnc)
			}
			pubsub.CheckMaxTimeTopic(agentName, "PendTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.NetworkTestTimer.C:
			start := time.Now()
			if !ok {
				log.Infof("Network test timer stopped?")
			} else if nimCtx.DevicePortConfigList.CurrentIndex == -1 {
				log.Debugf("Starting looking for working Device connectivity to cloud")
				devicenetwork.RestartVerify(dnc,
					"Looking for working")
				log.Infof("Looking for working  done at index %d. Took %v",
					dnc.NextDPCIndex, time.Since(start))
			} else {
				log.Debugf("Starting test of Device connectivity to cloud")
				ok := tryDeviceConnectivityToCloud(dnc)
				if ok {
					log.Debugf("Device connectivity to cloud worked. Took %v",
						time.Since(start))
					// Look for DNS etc update
					devicenetwork.CheckDNSUpdate(
						&nimCtx.DeviceNetworkContext)
				} else {
					log.Infof("Device connectivity to cloud failed. Took %v",
						time.Since(start))
				}
			}
			pubsub.CheckMaxTimeTopic(agentName, "TestTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.NetworkTestBetterTimer.C:
			start := time.Now()
			if !ok {
				log.Infof("Network testBetterTimer stopped?")
			} else if dnc.NextDPCIndex == 0 {
				log.Debugf("Network testBetterTimer at zero ignored")
			} else {
				log.Infof("Network testBetterTimer at index %d",
					dnc.NextDPCIndex)
				devicenetwork.RestartVerify(dnc,
					"NetworkTestBetterTimer")
				log.Infof("Network testBetterTimer done at index %d. Took %v",
					dnc.NextDPCIndex, time.Since(start))
			}
			pubsub.CheckMaxTimeTopic(agentName, "TestTimer", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("AA initialized")

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDevicePortConfigA.MsgChan():
			subDevicePortConfigA.ProcessChange(change)

		case change := <-subDevicePortConfigO.MsgChan():
			subDevicePortConfigO.ProcessChange(change)

		case change := <-subDevicePortConfigS.MsgChan():
			subDevicePortConfigS.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)
			updateFilteredFallback(&nimCtx)

		case change := <-subNetworkInstanceStatus.MsgChan():
			subNetworkInstanceStatus.ProcessChange(change)

		case change, ok := <-addrChanges:
			start := time.Now()
			if !ok {
				log.Errorf("addrChanges closed\n")
				addrChanges = devicenetwork.AddrChangeInit()
				// XXX Need to discard all cached information?
			} else {
				ch, ifindex := devicenetwork.AddrChange(nimCtx.DeviceNetworkContext, change)
				if ch {
					handleInterfaceChange(&nimCtx, ifindex,
						"AddrChange", true)
				}
			}
			pubsub.CheckMaxTimeTopic(agentName, "addrChanges", start,
				warningTime, errorTime)

		case change, ok := <-linkChanges:
			start := time.Now()
			if !ok {
				log.Errorf("linkChanges closed\n")
				linkChanges = devicenetwork.LinkChangeInit()
				// XXX Need to discard all cached information?
			} else {
				ch, ifindex := devicenetwork.LinkChange(change)
				if ch {
					handleLinkChange(&nimCtx)
					handleInterfaceChange(&nimCtx, ifindex,
						"LinkChange", true)
				}
			}
			pubsub.CheckMaxTimeTopic(agentName, "linkChanges", start,
				warningTime, errorTime)

		case change, ok := <-routeChanges:
			start := time.Now()
			if !ok {
				log.Errorf("routeChanges closed\n")
				routeChanges = devicenetwork.RouteChangeInit()
			} else {
				ch, ifindex := devicenetwork.RouteChange(nimCtx.DeviceNetworkContext, change)
				if ch {
					handleInterfaceChange(&nimCtx, ifindex,
						"RouteChange", false)
				}
			}
			pubsub.CheckMaxTimeTopic(agentName, "routeChanges", start,
				warningTime, errorTime)

		case <-geoTimer.C:
			start := time.Now()
			log.Debugln("geoTimer at", time.Now())
			change := devicenetwork.UpdateDeviceNetworkGeo(
				geoRedoTime, nimCtx.DeviceNetworkStatus)
			if change {
				publishDeviceNetworkStatus(&nimCtx)
			}
			pubsub.CheckMaxTimeTopic(agentName, "geoTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.Pending.PendTimer.C:
			start := time.Now()
			if !ok {
				log.Infof("Device port test timer stopped?")
			} else {
				log.Debugln("PendTimer at", time.Now())
				devicenetwork.VerifyDevicePortConfig(dnc)
			}
			pubsub.CheckMaxTimeTopic(agentName, "PendTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.NetworkTestTimer.C:
			start := time.Now()
			if !ok {
				log.Infof("Network test timer stopped?")
			} else {
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
			pubsub.CheckMaxTimeTopic(agentName, "TestTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.NetworkTestBetterTimer.C:
			start := time.Now()
			if !ok {
				log.Infof("Network testBetterTimer stopped?")
			} else if dnc.NextDPCIndex == 0 {
				log.Debugf("Network testBetterTimer at zero ignored")
			} else {
				log.Infof("Network testBetterTimer at index %d",
					dnc.NextDPCIndex)
				devicenetwork.RestartVerify(dnc,
					"NetworkTestBetterTimer")
				log.Infof("Network testBetterTimer done at index %d. Took %v",
					dnc.NextDPCIndex, time.Since(start))
			}
			pubsub.CheckMaxTimeTopic(agentName, "TestBetterTimer", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleLinkChange(ctx *nimContext) {
	// Create superset; update to have the latest upFlag
	// Note that upFlag gets cleared when the device is assigned away to pciback
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
		updateFilteredFallback(ctx)
	}
}

// handleInterfaceChange deals with the fact that linkchange, addrchange, and
// routechange do not reliably indicate when a link/address comes and goes, so
// we explicitly check whether there are changes to the kernel list of IP
// address.
// Only applies to device ports.
func handleInterfaceChange(ctx *nimContext, ifindex int, logstr string, force bool) {
	// We do not see address change notifications when
	// link drops so call directly
	ifname, _, _ := devicenetwork.IfindexToName(ifindex)
	log.Infof("%s(%s) ifindex %d force %t", logstr, ifname, ifindex, force)
	if ifname != "" && !types.IsPort(*ctx.DeviceNetworkStatus, ifname) {
		log.Debugf("%s(%s): not port", logstr, ifname)
		return
	}
	if force {
		// The caller has already purged addresses from IfindexToAddrs
		addrs, err := devicenetwork.GetIPAddrs(ifindex)
		if err != nil {
			addrs = nil
		}
		log.Infof("%s(%s) force changed to %v",
			logstr, ifname, addrs)
		// Do not have a baseline to delete from
		devicenetwork.FlushRules(ifindex)
		for _, a := range addrs {
			devicenetwork.AddSourceRule(ifindex, devicenetwork.HostSubnet(a), false)
		}
		devicenetwork.HandleAddressChange(&ctx.DeviceNetworkContext)
		// XXX should we trigger restarting testing?
		return
	}

	// Compare old vs. current
	oldAddrs, _ := devicenetwork.IfindexToAddrs(ifindex)
	addrs, err := devicenetwork.GetIPAddrs(ifindex)
	if err != nil {
		log.Warnf("%s(%s %d) no addrs: %s",
			logstr, ifname, ifindex, err)
		addrs = nil
	}
	if len(oldAddrs) == 0 && len(addrs) == 0 {
		// Equal but one might be nil
	} else if reflect.DeepEqual(oldAddrs, addrs) {
		// Equal
	} else {
		log.Infof("%s(%s) changed from %v to %v",
			logstr, ifname, oldAddrs, addrs)
		for _, a := range oldAddrs {
			devicenetwork.DelSourceRule(ifindex, devicenetwork.HostSubnet(a), false)
		}
		for _, a := range addrs {
			devicenetwork.AddSourceRule(ifindex, devicenetwork.HostSubnet(a), false)
		}

		devicenetwork.HandleAddressChange(&ctx.DeviceNetworkContext)
		// XXX should we trigger restarting testing?
	}
}

func updateFilteredFallback(ctx *nimContext) {
	ctx.filteredFallback = filterIfMap(ctx, ctx.fallbackPortMap)
	log.Infof("new filteredFallback: %+v\n", ctx.filteredFallback)
	if ctx.networkFallbackAnyEth == types.TS_ENABLED {
		updateFallbackAnyEth(ctx)
	}
}

func tryDeviceConnectivityToCloud(ctx *devicenetwork.DeviceNetworkContext) bool {
	rtf, err := devicenetwork.VerifyDeviceNetworkStatus(*ctx.DeviceNetworkStatus, 1, ctx.TestSendTimeout)
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
	if !ctx.CloudConnectivityWorks && !rtf {
		// If previous cloud connectivity test also failed, it means
		// that the current DPC configuration stopped working.
		// In this case we start the process where device tries to
		// figure out a DevicePortConfig that works.
		// We avoid doing this for remoteTemporaryFailures
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
		if rtf {
			log.Warnf("tryDeviceConnectivityToCloud: remoteTemporaryFailure: %s", err)
		} else {
			log.Infof("tryDeviceConnectivityToCloud: Device cloud connectivity test restart timer due to %s", err)
		}
		// Restart network test timer for next slot.
		ctx.NetworkTestTimer = time.NewTimer(time.Duration(ctx.NetworkTestInterval) * time.Second)
		ctx.CloudConnectivityWorks = false
	}
	return false
}

func publishDeviceNetworkStatus(ctx *nimContext) {
	log.Infof("PublishDeviceNetworkStatus: %+v\n",
		ctx.DeviceNetworkStatus)
	devicenetwork.UpdateResolvConf(*ctx.DeviceNetworkStatus)
	devicenetwork.UpdatePBR(*ctx.DeviceNetworkStatus)
	ctx.DeviceNetworkStatus.Testing = false
	ctx.PubDeviceNetworkStatus.Publish("global", *ctx.DeviceNetworkStatus)
}

// Handles both create and modify events
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
			sane := types.EnforceGlobalConfigMinimums(updated)
			log.Infof("handleGlobalConfigModify: enforced minimums %v\n",
				cmp.Diff(updated, sane))
			*gcp = sane
		}
		if gcp.SshAccess != ctx.sshAccess || first {
			ctx.sshAccess = gcp.SshAccess
			iptables.UpdateSshAccess(ctx.sshAccess, first)
		}
		if gcp.SshAuthorizedKeys != ctx.sshAuthorizedKeys || first {
			ctx.sshAuthorizedKeys = gcp.SshAuthorizedKeys
			ssh.UpdateSshAuthorizedKeys(ctx.sshAuthorizedKeys)
		}
		if gcp.AllowAppVnc != ctx.allowAppVnc {
			ctx.allowAppVnc = gcp.AllowAppVnc
			iptables.UpdateVncAccess(ctx.allowAppVnc)
		}
		if gcp.NetworkFallbackAnyEth != ctx.networkFallbackAnyEth || first {
			ctx.networkFallbackAnyEth = gcp.NetworkFallbackAnyEth
			updateFallbackAnyEth(ctx)
		}
		// Check for change to NetworkTestBetterInterval
		if ctx.NetworkTestBetterInterval != gcp.NetworkTestBetterInterval {
			if gcp.NetworkTestBetterInterval == 0 {
				log.Warnln("NOT running TestBetterTimer")
				networkTestBetterTimer := time.NewTimer(time.Hour)
				networkTestBetterTimer.Stop()
				ctx.NetworkTestBetterTimer = networkTestBetterTimer
			} else {
				log.Infof("Starting TestBetterTimer: %d",
					gcp.NetworkTestBetterInterval)
				networkTestBetterInterval := time.Duration(ctx.NetworkTestBetterInterval) * time.Second
				networkTestBetterTimer := time.NewTimer(networkTestBetterInterval)
				ctx.NetworkTestBetterTimer = networkTestBetterTimer
			}
			ctx.NetworkTestBetterInterval = gcp.NetworkTestBetterInterval
		}
		ctx.globalConfig = gcp
		dnc := &ctx.DeviceNetworkContext
		dnc.NetworkTestInterval = ctx.globalConfig.NetworkTestInterval
		dnc.DPCTestDuration = ctx.globalConfig.NetworkTestDuration
		dnc.TestSendTimeout = ctx.globalConfig.NetworkTestTimeout
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
	*ctx.globalConfig = types.GlobalConfigDefaults
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

// Handles both create and modify events
func handleNetworkInstanceModify(ctxArg interface{}, key string, statusArg interface{}) {

	log.Infof("handleNetworkInstanceStatusModify(%s)\n", key)
	ctx := ctxArg.(*nimContext)
	// Hard to check if any switch NI was added, deleted, or changed
	updateFilteredFallback(ctx)
	log.Infof("handleNetworkInstanceModify(%s) done\n", key)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleNetworkInstanceDelete(%s)\n", key)
	ctx := ctxArg.(*nimContext)
	// Hard to check if any switch NI was added, deleted, or changed
	updateFilteredFallback(ctx)
	log.Infof("handleNetworkInstanceDelete(%s) done\n", key)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func updateFallbackAnyEth(ctx *nimContext) {
	log.Debugf("updateFallbackAnyEth: enable %v ifs %v\n",
		ctx.networkFallbackAnyEth, ctx.filteredFallback)
	if ctx.networkFallbackAnyEth == types.TS_ENABLED {
		ports := mapToKeys(ctx.filteredFallback)
		// sort ports to reduce churn; otherwise with two they swap
		// almost every time
		sort.Strings(ports)
		log.Debugf("updateFallbackAnyEth: ports %+v", ports)
		devicenetwork.UpdateLastResortPortConfig(&ctx.DeviceNetworkContext,
			ports)
	} else if ctx.networkFallbackAnyEth == types.TS_DISABLED {
		devicenetwork.RemoveLastResortPortConfig(&ctx.DeviceNetworkContext)
	}
}

// Return an array with the keys in the map
func mapToKeys(m map[string]bool) []string {

	keys := make([]string, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	return keys
}

// Determine which interfaces are not used exclusively by device assignment or by
// a switch network instance.
//
// Exclude those in AssignableAdapters with usedByUUID!=0
// Exclude those in NetworkInstanceStatus Type=switch
func filterIfMap(ctx *nimContext, fallbackPortMap map[string]bool) map[string]bool {
	log.Debugf("filterIfMap: len %d\n", len(fallbackPortMap))

	filteredFallback := make(map[string]bool, len(fallbackPortMap))
	for ifname, upFlag := range fallbackPortMap {
		if isAssigned(ctx, ifname) {
			continue
		}
		if isSwitch(ctx, ifname) {
			continue
		}
		filteredFallback[ifname] = upFlag
	}
	return filteredFallback
}

// Really a constant
var nilUUID uuid.UUID

// Check in AssignableAdapters with usedByUUID!=0
func isAssigned(ctx *nimContext, ifname string) bool {

	log.Debugf("isAssigned(%s) have %d bundles\n",
		ifname, len(ctx.AssignableAdapters.IoBundleList))
	ib := ctx.AssignableAdapters.LookupIoBundleNet(ifname)
	if ib == nil {
		return false
	}
	log.Debugf("isAssigned(%s): pciback %t used %s\n",
		ifname, ib.IsPCIBack, ib.UsedByUUID.String())

	if ib.UsedByUUID != nilUUID {
		return true
	}
	return false
}

// Check in NetworkInstanceStatus Type=switch
// XXX should we check for other shared usage? Static IP config?
func isSwitch(ctx *nimContext, ifname string) bool {

	sub := ctx.subNetworkInstanceStatus
	items := sub.GetAll()
	log.Debugf("isSwitch(%s) have %d items\n", ifname, len(items))

	foundExcl := false
	for _, st := range items {
		status := st.(types.NetworkInstanceStatus)

		if !status.IsUsingPort(ifname) {
			continue
		}
		log.Debugf("isSwitch(%s) found use in %s/%s\n",
			ifname, status.DisplayName, status.Key())
		if status.Type != types.NetworkInstanceTypeSwitch {
			continue
		}
		foundExcl = true
		log.Debugf("isSwitch(%s) found excl use in %s/%s\n",
			ifname, status.DisplayName, status.Key())
	}
	return foundExcl
}
