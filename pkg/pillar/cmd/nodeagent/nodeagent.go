// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// NodeAgent interfaces with baseosmgr for baseos upgrade and test validation
// we will transition through zboot for baseos upgrade validation process

// nodeagent publishes the following topic
//   * zboot config                 <nodeagent>  / <zboot> / <config>
//   * nodeagent status             <nodeagent>  / <status>

// nodeagent subscribes to the following topics
//   * global config
//   * zboot status                 <baseosmgr> / <zboot> / <status>
//   * zedagent status              <zedagent>/ <status>

package nodeagent

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	log "github.com/sirupsen/logrus"
)

const (
	agentName               = "nodeagent"
	timeTickInterval uint32 = 10
	watchdogInterval uint32 = 25
	networkUpTimeout uint32 = 300
)

// Version : module version
var Version = "No version specified"
var rebootDelay = 40 // take 40 second delay, incase zedagent fails

type nodeagentContext struct {
	GCInitialized          bool // Received initial GlobalConfig
	DNSinitialized         bool // Received DeviceNetworkStatus
	globalConfig           *types.GlobalConfig
	subGlobalConfig        *pubsub.Subscription
	subZbootStatus         *pubsub.Subscription
	subZedAgentStatus      *pubsub.Subscription
	subDeviceNetworkStatus *pubsub.Subscription
	pubZbootConfig         *pubsub.Publication
	pubNodeAgentStatus     *pubsub.Publication
	curPart                string
	upgradeTestStartTime   uint32
	remainingTestTime      time.Duration
	lastConfigReceivedTime uint32
	configGetStatus        types.ConfigGetStatus
	deviceNetworkStatus    *types.DeviceNetworkStatus
	needsReboot            bool
	rebootReason           string
	deviceRegistered       bool
	updateInprogress       bool
	updateComplete         bool
	sshAccess              bool
	testComplete           bool
	testInprogress         bool
	timeTickCount          uint32
	usableAddressCount     int
	tickerTimer            *time.Ticker
	stillRunning           *time.Ticker
}

var debug = false
var debugOverride bool // From command line arg

// Run : nodeagent run entry function
func Run() {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	curpartPtr := flag.String("c", "", "Current partition")
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
	curpart := *curpartPtr
	logf, err := agentlog.Init(agentName, curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	log.Infof("Starting %s, on %s\n", agentName, curpart)

	nodeagentCtx := nodeagentContext{}
	nodeagentCtx.curPart = strings.TrimSpace(curpart)

	nodeagentCtx.sshAccess = true // Kernel default - no iptables filters
	nodeagentCtx.globalConfig = &types.GlobalConfigDefaults

	// start the watchdog process timer tick
	duration := time.Duration(watchdogInterval) * time.Second
	nodeagentCtx.stillRunning = time.NewTicker(duration)

	// set the ticker timer
	duration = time.Duration(timeTickInterval) * time.Second
	nodeagentCtx.tickerTimer = time.NewTicker(duration)
	nodeagentCtx.configGetStatus = types.ConfigGetFail

	// Make sure we have a GlobalConfig file with defaults
	types.EnsureGCFile()

	// publisher of NodeAgent Status
	pubNodeAgentStatus, err := pubsub.Publish(agentName,
		types.NodeAgentStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubNodeAgentStatus.ClearRestarted()
	nodeagentCtx.pubNodeAgentStatus = pubNodeAgentStatus

	// publisher of Zboot Config
	pubZbootConfig, err := pubsub.Publish(agentName, types.ZbootConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubZbootConfig.ClearRestarted()
	nodeagentCtx.pubZbootConfig = pubZbootConfig

	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &nodeagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	subGlobalConfig.SynchronizedHandler = handleGlobalConfigSynchronized
	nodeagentCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// publish zboot config as of now
	publishZbootConfigAll(&nodeagentCtx)

	// access the zboot APIs directly, baseosmgr is still not ready
	nodeagentCtx.updateInprogress = zboot.IsCurrentPartitionStateInProgress()
	log.Infof("Current partition: %s, inProgress: %v\n", nodeagentCtx.curPart,
		nodeagentCtx.updateInprogress)
	publishNodeAgentStatus(&nodeagentCtx)

	// Read the GlobalConfig first
	// Wait for initial GlobalConfig
	log.Infof("Waiting for GCInitialized\n")
	for !nodeagentCtx.GCInitialized {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case <-nodeagentCtx.tickerTimer.C:
			handleDeviceTimers(&nodeagentCtx)

		case <-nodeagentCtx.stillRunning.C:
		}
		agentlog.StillRunning(agentName)
	}

	// when the partition status is inprogress state
	// check network connectivity for 300 seconds
	if nodeagentCtx.updateInprogress {
		checkNetworkConnectivity(&nodeagentCtx)
	}

	// if current partition state is not in-progress,
	// nothing much to do. Zedcloud connectivity is tracked,
	// to trigger the device to reboot, on reset timeout expiry
	//
	// if current partition state is in-progress,
	// trigger the device to reboot on
	// fallback timeout expiry
	//
	// On zedbox modules activation, nodeagent will
	// track the zedcloud connectivity events
	//
	// These timer functions will be tracked using
	// led blinker and cloud connectionnectivity status.

	log.Infof("Waiting for device registration check\n")
	for !nodeagentCtx.deviceRegistered {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case <-nodeagentCtx.tickerTimer.C:
			handleDeviceTimers(&nodeagentCtx)

		case <-nodeagentCtx.stillRunning.C:
		}
		agentlog.StillRunning(agentName)
		if isZedAgentAlive(&nodeagentCtx) {
			nodeagentCtx.deviceRegistered = true
		}
	}

	// subscribe to zboot status events
	subZbootStatus, err := pubsub.Subscribe("baseosmgr",
		types.ZbootStatus{}, false, &nodeagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subZbootStatus.ModifyHandler = handleZbootStatusModify
	subZbootStatus.DeleteHandler = handleZbootStatusDelete
	nodeagentCtx.subZbootStatus = subZbootStatus
	subZbootStatus.Activate()

	// subscribe to zedagent status events
	subZedAgentStatus, err := pubsub.Subscribe("zedagent",
		types.ZedAgentStatus{}, false, &nodeagentCtx)
	if err != nil {
		log.Fatal(err)
	}
	subZedAgentStatus.ModifyHandler = handleZedAgentStatusModify
	subZedAgentStatus.DeleteHandler = handleZedAgentStatusDelete
	nodeagentCtx.subZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	log.Infof("zedbox event loop\n")
	for {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subZbootStatus.C:
			subZbootStatus.ProcessChange(change)

		case change := <-subZedAgentStatus.C:
			subZedAgentStatus.ProcessChange(change)

		case <-nodeagentCtx.tickerTimer.C:
			handleDeviceTimers(&nodeagentCtx)

		case <-nodeagentCtx.stillRunning.C:
		}
		agentlog.StillRunning(agentName)
	}
}

// In case there is no GlobalConfig.json this will move us forward
func handleGlobalConfigSynchronized(ctxArg interface{}, done bool) {
	ctxPtr := ctxArg.(*nodeagentContext)

	log.Infof("handleGlobalConfigSynchronized(%v)\n", done)
	if done {
		first := !ctxPtr.GCInitialized
		if first {
			iptables.UpdateSshAccess(ctxPtr.sshAccess, first)
		}
		ctxPtr.GCInitialized = true
	}
}

func handleGlobalConfigModify(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.GlobalConfig
	debug, gcp = agentlog.HandleGlobalConfig(ctxPtr.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil && !ctxPtr.GCInitialized {
		updated := types.ApplyGlobalConfig(*gcp)
		log.Infof("handleGlobalConfigModify setting initials to %+v\n",
			updated)
		sane := types.EnforceGlobalConfigMinimums(updated)
		log.Infof("handleGlobalConfigModify: enforced minimums %v\n",
			cmp.Diff(updated, sane))
		ctxPtr.globalConfig = &sane
		ctxPtr.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify(%s): done\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctxPtr.subGlobalConfig, agentName,
		debugOverride)
	ctxPtr.globalConfig = &types.GlobalConfigDefaults
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

// handle zedagent status events, for cloud connectivity
func handleZedAgentStatusModify(ctxArg interface{},
	key string, statusArg interface{}) {
	ctxPtr := ctxArg.(*nodeagentContext)
	status := cast.ZedAgentStatus(statusArg)
	if status.Key() != key {
		log.Errorf("zedagentStatus key mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	updateZedagentCloudConnectStatus(ctxPtr, status)
	log.Debugf("handleZedAgentStatusModify(%s) done\n", key)
}

func handleZedAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	// do nothing
	log.Infof("handleZedAgentStatusDelete(%s) done\n", key)
}

// zboot status event handlers
func handleZbootStatusModify(ctxArg interface{},
	key string, statusArg interface{}) {
	ctxPtr := ctxArg.(*nodeagentContext)
	status := cast.ZbootStatus(statusArg)
	if status.Key() != key {
		log.Errorf("zbootStatus key mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	if status.CurrentPartition && ctxPtr.updateInprogress &&
		status.PartitionState == "active" {
		log.Infof("CurPart(%s) transitioned to \"active\" state\n",
			status.PartitionLabel)
		ctxPtr.updateInprogress = false
		ctxPtr.testComplete = false
		ctxPtr.updateComplete = false
		publishNodeAgentStatus(ctxPtr)
	}
	doZbootBaseOsInstallationComplete(ctxPtr, key, status)
	doZbootBaseOsTestValidationComplete(ctxPtr, key, status)
	log.Debugf("handleZbootStatusModify(%s) done\n", key)
}

func handleZbootStatusDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	if status := lookupZbootStatus(ctxPtr, key); status == nil {
		log.Infof("handleZbootStatusDelete: unknown %s\n", key)
		return
	}
	log.Infof("handleZbootStatusDelete(%s) done\n", key)
}

func checkNetworkConnectivity(ctxPtr *nodeagentContext) {
	// for device network status
	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, ctxPtr)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctxPtr.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	ctxPtr.deviceNetworkStatus = &types.DeviceNetworkStatus{}
	ctxPtr.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(*ctxPtr.deviceNetworkStatus)
	log.Infof("Waiting until we have some uplinks with usable addresses\n")
	for !ctxPtr.DNSinitialized {
		log.Infof("Waiting for DeviceNetworkStatus: %v\n",
			ctxPtr.DNSinitialized)
		select {
		case change := <-ctxPtr.subGlobalConfig.C:
			ctxPtr.subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case <-ctxPtr.tickerTimer.C:
			handleDeviceTimers(ctxPtr)

		case <-ctxPtr.stillRunning.C:
		}
		agentlog.StillRunning(agentName)
	}
	log.Infof("DeviceNetworkStatus: %v\n", ctxPtr.DNSinitialized)

	// reset timer tick, for all timer functions
	ctxPtr.timeTickCount = 0
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctxPtr := ctxArg.(*nodeagentContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(*ctxPtr.deviceNetworkStatus, status) {
		log.Infof("handleDNSModify no change\n")
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(*ctxPtr.deviceNetworkStatus, status))
	*ctxPtr.deviceNetworkStatus = status
	// Did we (re-)gain the first usable address?
	// XXX should we also trigger if the count increases?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctxPtr.deviceNetworkStatus)
	if newAddrCount != 0 && ctxPtr.usableAddressCount == 0 {
		log.Infof("DeviceNetworkStatus from %d to %d addresses\n",
			ctxPtr.usableAddressCount, newAddrCount)
	}
	ctxPtr.DNSinitialized = true
	ctxPtr.usableAddressCount = newAddrCount
	log.Infof("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s\n", key)
	ctxPtr := ctxArg.(*nodeagentContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*ctxPtr.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctxPtr.deviceNetworkStatus)
	ctxPtr.DNSinitialized = false
	ctxPtr.usableAddressCount = newAddrCount
	log.Infof("handleDNSDelete done for %s\n", key)
}

// check whether zedagent module is alive
func isZedAgentAlive(ctxPtr *nodeagentContext) bool {
	pgrepCmd := exec.Command("pgrep", "zedagent")
	stdout, err := pgrepCmd.Output()
	output := string(stdout)
	if err == nil && output != "" {
		return true
	}
	return false
}

// publish nodeagent status for consumption by zedagent
func publishNodeAgentStatus(ctxPtr *nodeagentContext) {
	pub := ctxPtr.pubNodeAgentStatus
	status := types.NodeAgentStatus{
		Name:              agentName,
		CurPart:           ctxPtr.curPart,
		RemainingTestTime: ctxPtr.remainingTestTime,
		UpdateInprogress:  ctxPtr.updateInprogress,
		NeedsReboot:       ctxPtr.needsReboot,
		RebootReason:      ctxPtr.rebootReason,
	}
	pub.Publish(agentName, status)
}
