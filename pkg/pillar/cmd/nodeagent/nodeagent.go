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
//   * zedagent status              <zedagent>  / <status>

package nodeagent

import (
	"bytes"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	log "github.com/sirupsen/logrus"
)

const (
	agentName                   = "nodeagent"
	timeTickInterval     uint32 = 10
	watchdogInterval     uint32 = 25
	networkUpTimeout     uint32 = 300
	maxRebootStackSize          = 1600
	maxJSONAttributeSize        = maxRebootStackSize + 100
	configDir                   = "/config"
	tmpDirname                  = "/var/tmp/zededa"
	firstbootFile               = tmpDirname + "/first-boot"
	restartCounterFile          = configDir + "/restartcounter"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	// Timer values ( in sec ) to handle reboot
	minRebootDelay          uint32 = 30
	maxDomainHaltTime       uint32 = 300
	domainHaltWaitIncrement uint32 = 5
)

// Version : module version
var Version = "No version specified"

type nodeagentContext struct {
	agentBaseContext       agentbase.Context
	GCInitialized          bool // Received initial GlobalConfig
	DNSinitialized         bool // Received DeviceNetworkStatus
	globalConfig           *types.ConfigItemValueMap
	subGlobalConfig        pubsub.Subscription
	subZbootStatus         pubsub.Subscription
	subZedAgentStatus      pubsub.Subscription
	subDeviceNetworkStatus pubsub.Subscription
	subDomainStatus        pubsub.Subscription
	pubZbootConfig         pubsub.Publication
	pubNodeAgentStatus     pubsub.Publication
	curPart                string
	upgradeTestStartTime   uint32
	tickerTimer            *time.Ticker
	stillRunning           *time.Ticker
	remainingTestTime      time.Duration
	lastConfigReceivedTime uint32
	configGetStatus        types.ConfigGetStatus
	deviceNetworkStatus    *types.DeviceNetworkStatus
	deviceRegistered       bool
	updateInprogress       bool
	updateComplete         bool
	sshAccess              bool
	testComplete           bool
	testInprogress         bool
	timeTickCount          uint32
	usableAddressCount     int
	rebootCmd              bool // Are we rebooting?
	deviceReboot           bool
	currentRebootReason    string    // Reason we are rebooting
	rebootReason           string    // From last reboot
	rebootImage            string    // Image from which the last reboot happened
	rebootStack            string    // From last reboot
	rebootTime             time.Time // From last reboot
	restartCounter         uint32

	// Some contants.. Declared here as variables to enable unit tests
	minRebootDelay          uint32
	maxDomainHaltTime       uint32
	domainHaltWaitIncrement uint32
}

var debug = false
var debugOverride bool // From command line arg

func newNodeagentContext() nodeagentContext {
	nodeagentCtx := nodeagentContext{}
	nodeagentCtx.minRebootDelay = minRebootDelay
	nodeagentCtx.maxDomainHaltTime = maxDomainHaltTime
	nodeagentCtx.domainHaltWaitIncrement = domainHaltWaitIncrement

	nodeagentCtx.sshAccess = true // Kernel default - no iptables filters
	nodeagentCtx.globalConfig = types.DefaultConfigItemValueMap()

	// start the watchdog process timer tick
	duration := time.Duration(watchdogInterval) * time.Second
	nodeagentCtx.stillRunning = time.NewTicker(duration)

	// set the ticker timer
	duration = time.Duration(timeTickInterval) * time.Second
	nodeagentCtx.tickerTimer = time.NewTicker(duration)
	nodeagentCtx.configGetStatus = types.ConfigGetFail

	nodeagentCtx.agentBaseContext.ErrorTime = errorTime
	nodeagentCtx.agentBaseContext.AgentName = agentName
	nodeagentCtx.agentBaseContext.WarningTime = warningTime

	curpart := agentlog.EveCurrentPartition()
	nodeagentCtx.curPart = strings.TrimSpace(curpart)
	nodeagentCtx.agentBaseContext.NeedWatchdog = true
	return nodeagentCtx
}

func (ctxPtr *nodeagentContext) AgentBaseContext() *agentbase.Context {
	return &ctxPtr.agentBaseContext
}

func (ctxPtr *nodeagentContext) AddAgentSpecificCLIFlags() {
	return
}

func (ctxPtr *nodeagentContext) ProcessAgentSpecificCLIFlags() {
	return
}

// Run : nodeagent run entry function
func Run(ps *pubsub.PubSub) {
	nodeagentCtx := newNodeagentContext()

	agentbase.Run(&nodeagentCtx)

	// Make sure we have a GlobalConfig file with defaults
	utils.EnsureGCFile()

	// get the last reboot reason
	handleLastRebootReason(&nodeagentCtx)

	// publisher of NodeAgent Status
	pubNodeAgentStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.NodeAgentStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubNodeAgentStatus.ClearRestarted()
	nodeagentCtx.pubNodeAgentStatus = pubNodeAgentStatus

	// publisher of Zboot Config
	pubZbootConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.ZbootConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubZbootConfig.ClearRestarted()
	nodeagentCtx.pubZbootConfig = pubZbootConfig

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           &nodeagentCtx,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		SyncHandler:   handleGlobalConfigSynchronized,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nodeagentCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// publish zboot config as of now
	publishZbootConfigAll(&nodeagentCtx)

	// access the zboot APIs directly, baseosmgr is still not ready
	nodeagentCtx.updateInprogress = zboot.IsCurrentPartitionStateInProgress()
	log.Infof("Current partition: %s, inProgress: %v", nodeagentCtx.curPart,
		nodeagentCtx.updateInprogress)
	publishNodeAgentStatus(&nodeagentCtx)

	// Get DomainStatus from domainmgr
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "domainmgr",
		TopicImpl: types.DomainStatus{},
		Activate:  false,
		Ctx:       &nodeagentCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	nodeagentCtx.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	// Pick up debug aka log level before we start real work
	log.Infof("Waiting for GCInitialized")
	for !nodeagentCtx.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-nodeagentCtx.tickerTimer.C:
			handleDeviceTimers(&nodeagentCtx)

		case <-nodeagentCtx.stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

	// when the partition status is inprogress state
	// check network connectivity for 300 seconds
	if nodeagentCtx.updateInprogress {
		checkNetworkConnectivity(ps, &nodeagentCtx)
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
	// cloud connectionnectivity status.

	log.Infof("Waiting for device registration check")
	for !nodeagentCtx.deviceRegistered {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-nodeagentCtx.tickerTimer.C:
			handleDeviceTimers(&nodeagentCtx)

		case <-nodeagentCtx.stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
		if isZedAgentAlive(&nodeagentCtx) {
			nodeagentCtx.deviceRegistered = true
		}
	}

	// subscribe to zboot status events
	subZbootStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "baseosmgr",
		TopicImpl:     types.ZbootStatus{},
		Activate:      false,
		Ctx:           &nodeagentCtx,
		ModifyHandler: handleZbootStatusModify,
		DeleteHandler: handleZbootStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nodeagentCtx.subZbootStatus = subZbootStatus
	subZbootStatus.Activate()

	// subscribe to zedagent status events
	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           &nodeagentCtx,
		ModifyHandler: handleZedAgentStatusModify,
		DeleteHandler: handleZedAgentStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nodeagentCtx.subZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	log.Infof("zedbox event loop")
	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDomainStatus.MsgChan():
			subDomainStatus.ProcessChange(change)

		case change := <-subZbootStatus.MsgChan():
			subZbootStatus.ProcessChange(change)

		case change := <-subZedAgentStatus.MsgChan():
			subZedAgentStatus.ProcessChange(change)

		case <-nodeagentCtx.tickerTimer.C:
			handleDeviceTimers(&nodeagentCtx)

		case <-nodeagentCtx.stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

// In case there is no GlobalConfig.json this will move us forward
func handleGlobalConfigSynchronized(ctxArg interface{}, done bool) {
	ctxPtr := ctxArg.(*nodeagentContext)

	log.Infof("handleGlobalConfigSynchronized(%v)", done)
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
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(ctxPtr.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil && !ctxPtr.GCInitialized {
		ctxPtr.globalConfig = gcp
		ctxPtr.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify(%s): done", key)
}

func handleGlobalConfigDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(ctxPtr.subGlobalConfig, agentName,
		debugOverride)
	ctxPtr.globalConfig = types.DefaultConfigItemValueMap()
	log.Infof("handleGlobalConfigDelete done for %s", key)
}

// handle zedagent status events, for cloud connectivity
func handleZedAgentStatusModify(ctxArg interface{},
	key string, statusArg interface{}) {
	ctxPtr := ctxArg.(*nodeagentContext)
	status := statusArg.(types.ZedAgentStatus)
	handleRebootCmd(ctxPtr, status)
	updateZedagentCloudConnectStatus(ctxPtr, status)
	log.Debugf("handleZedAgentStatusModify(%s) done", key)
}

func handleZedAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	// do nothing
	log.Infof("handleZedAgentStatusDelete(%s) done", key)
}

// zboot status event handlers
func handleZbootStatusModify(ctxArg interface{},
	key string, statusArg interface{}) {
	ctxPtr := ctxArg.(*nodeagentContext)
	status := statusArg.(types.ZbootStatus)
	if status.CurrentPartition && ctxPtr.updateInprogress &&
		status.PartitionState == "active" {
		log.Infof("CurPart(%s) transitioned to \"active\" state",
			status.PartitionLabel)
		ctxPtr.updateInprogress = false
		ctxPtr.testComplete = false
		ctxPtr.updateComplete = false
		publishNodeAgentStatus(ctxPtr)
	}
	doZbootBaseOsInstallationComplete(ctxPtr, key, status)
	doZbootBaseOsTestValidationComplete(ctxPtr, key, status)
	log.Debugf("handleZbootStatusModify(%s) done", key)
}

func handleZbootStatusDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	if status := lookupZbootStatus(ctxPtr, key); status == nil {
		log.Infof("handleZbootStatusDelete: unknown %s", key)
		return
	}
	log.Infof("handleZbootStatusDelete(%s) done", key)
}

func checkNetworkConnectivity(ps *pubsub.PubSub, ctxPtr *nodeagentContext) {
	// for device network status
	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           ctxPtr,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	ctxPtr.deviceNetworkStatus = &types.DeviceNetworkStatus{}
	ctxPtr.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(*ctxPtr.deviceNetworkStatus)
	log.Infof("Waiting until we have some uplinks with usable addresses")

	for !ctxPtr.DNSinitialized {
		log.Infof("Waiting for DeviceNetworkStatus: %v",
			ctxPtr.DNSinitialized)
		select {
		case change := <-ctxPtr.subGlobalConfig.MsgChan():
			ctxPtr.subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case <-ctxPtr.tickerTimer.C:
			handleDeviceTimers(ctxPtr)

		case <-ctxPtr.stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("DeviceNetworkStatus: %v", ctxPtr.DNSinitialized)

	// reset timer tick, for all timer functions
	ctxPtr.timeTickCount = 0
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctxPtr := ctxArg.(*nodeagentContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s", key)
		return
	}
	log.Infof("handleDNSModify for %s", key)
	if cmp.Equal(*ctxPtr.deviceNetworkStatus, status) {
		log.Infof("handleDNSModify no change")
		ctxPtr.DNSinitialized = true
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(*ctxPtr.deviceNetworkStatus, status))
	*ctxPtr.deviceNetworkStatus = status
	// Did we (re-)gain the first usable address?
	// XXX should we also trigger if the count increases?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctxPtr.deviceNetworkStatus)
	if newAddrCount != 0 && ctxPtr.usableAddressCount == 0 {
		log.Infof("DeviceNetworkStatus from %d to %d addresses",
			ctxPtr.usableAddressCount, newAddrCount)
	}
	ctxPtr.DNSinitialized = true
	ctxPtr.usableAddressCount = newAddrCount
	log.Infof("handleDNSModify done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s", key)
	ctxPtr := ctxArg.(*nodeagentContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s", key)
		return
	}
	*ctxPtr.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctxPtr.deviceNetworkStatus)
	ctxPtr.DNSinitialized = false
	ctxPtr.usableAddressCount = newAddrCount
	log.Infof("handleDNSDelete done for %s", key)
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

// If we have a reboot reason from this or the other partition
// (assuming the other is in inprogress) then we log it
// we will push this as part of baseos status
func handleLastRebootReason(ctx *nodeagentContext) {

	// ctx.rebootStack is sent by timer hence don't set it
	// until after truncation.
	var rebootStack = ""
	ctx.rebootReason, ctx.rebootTime, rebootStack =
		agentlog.GetCommonRebootReason()
	if ctx.rebootReason != "" {
		log.Warnf("Current partition RebootReason: %s",
			ctx.rebootReason)
		agentlog.DiscardCommonRebootReason()
	}
	// XXX We'll retain this block of code for some time to support having older
	// versions of code in the other partition.
	otherRebootReason, otherRebootTime, otherRebootStack := agentlog.GetOtherRebootReason()
	if otherRebootReason != "" {
		log.Warnf("Other partition RebootReason: %s",
			otherRebootReason)
		// if other partition state is "inprogress"
		// do not erase the reboot reason, going to
		// be used for baseos error status, across reboot
		if !zboot.IsOtherPartitionStateInProgress() {
			agentlog.DiscardOtherRebootReason()
		}
	}
	// first, pick up from other partition
	if ctx.rebootReason == "" {
		ctx.rebootReason = otherRebootReason
		ctx.rebootTime = otherRebootTime
		rebootStack = otherRebootStack
	}

	// still nothing, fillup the default
	if ctx.rebootReason == "" {
		ctx.rebootTime = time.Now()
		dateStr := ctx.rebootTime.Format(time.RFC3339Nano)
		var reason string
		if fileExists(firstbootFile) {
			reason = fmt.Sprintf("NORMAL: First boot of device - at %s\n",
				dateStr)
		} else {
			reason = fmt.Sprintf("Unknown reboot reason - power failure or crash - at %s\n",
				dateStr)
		}
		log.Warnf("Default RebootReason: %s", reason)
		ctx.rebootReason = reason
		ctx.rebootTime = time.Now()
		rebootStack = ""
	}
	// remove the first boot file, if it is present
	if fileExists(firstbootFile) {
		os.Remove(firstbootFile)
	}

	// if reboot stack size crosses max size, truncate
	if len(rebootStack) > maxJSONAttributeSize {
		runes := bytes.Runes([]byte(rebootStack))
		if len(runes) > maxJSONAttributeSize {
			runes = runes[:maxRebootStackSize]
		}
		rebootStack = fmt.Sprintf("Truncated stack: %v", string(runes))
	}
	ctx.rebootStack = rebootStack
	rebootImage := agentlog.GetRebootImage()
	if rebootImage != "" {
		ctx.rebootImage = rebootImage
		agentlog.DiscardRebootImage()
	}
	// Read and increment restartCounter
	ctx.restartCounter = incrementRestartCounter()
}

// If the file doesn't exist we pick zero.
// Return value before increment; write new value to file
func incrementRestartCounter() uint32 {
	var restartCounter uint32

	if _, err := os.Stat(restartCounterFile); err == nil {
		b, err := ioutil.ReadFile(restartCounterFile)
		if err != nil {
			log.Errorf("incrementRestartCounter: %s", err)
		} else {
			c, err := strconv.Atoi(string(b))
			if err != nil {
				log.Errorf("incrementRestartCounter: %s", err)
			} else {
				restartCounter = uint32(c)
				log.Infof("incrementRestartCounter: read %d", restartCounter)
			}
		}
	}
	b := []byte(fmt.Sprintf("%d", restartCounter+1))
	err := ioutil.WriteFile(restartCounterFile, b, 0644)
	if err != nil {
		log.Errorf("incrementRestartCounter write: %s", err)
	}
	return restartCounter
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// publish nodeagent status
func publishNodeAgentStatus(ctxPtr *nodeagentContext) {
	pub := ctxPtr.pubNodeAgentStatus
	status := types.NodeAgentStatus{
		Name:              agentName,
		CurPart:           ctxPtr.curPart,
		RemainingTestTime: ctxPtr.remainingTestTime,
		UpdateInprogress:  ctxPtr.updateInprogress,
		DeviceReboot:      ctxPtr.deviceReboot,
		RebootReason:      ctxPtr.rebootReason,
		RebootStack:       ctxPtr.rebootStack,
		RebootTime:        ctxPtr.rebootTime,
		RebootImage:       ctxPtr.rebootImage,
		RestartCounter:    ctxPtr.restartCounter,
	}
	pub.Publish(agentName, status)
}
