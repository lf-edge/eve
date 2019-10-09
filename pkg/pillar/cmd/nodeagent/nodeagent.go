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
	agentName        = "nodeagent"
	timeTickInterval = 10
)

// Version : module version
var Version = "No version specified"
var rebootDelay = 30 // take a 30 second delay

type nodeagentContext struct {
	GCInitialized          bool // Received initial GlobalConfig
	globalConfig           *types.GlobalConfig
	subGlobalConfig        *pubsub.Subscription
	subZbootStatus         *pubsub.Subscription
	subZedAgentStatus      *pubsub.Subscription
	pubZbootConfig         *pubsub.Publication
	pubNodeAgentStatus     *pubsub.Publication
	curPart                string
	upgradeTestStartTime   uint32
	remainingTestTime      time.Duration
	lastConfigReceivedTime uint32
	configGetStatus        types.ConfigGetStatus
	needsReboot            bool
	rebootReason           string
	deviceRegistered       bool
	updateInprogress       bool
	updateComplete         bool
	sshAccess              bool
	testComplete           bool
	testInprogress         bool
	timeTickCount          uint32
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
	stillRunning := time.NewTicker(25 * time.Second)
	tickerTimer := time.NewTicker(time.Duration(timeTickInterval) * time.Second)
	nodeagentCtx.configGetStatus = types.CONFIG_GET_FAIL

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

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)

		case <-tickerTimer.C:
			handleDeviceTimers(&nodeagentCtx)
		}
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

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)

		case <-tickerTimer.C:
			handleDeviceTimers(&nodeagentCtx)
		}
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

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)

		case <-tickerTimer.C:
			handleDeviceTimers(&nodeagentCtx)
		}
	}
}

// In case there is no GlobalConfig.json this will move us forward
func handleGlobalConfigSynchronized(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*nodeagentContext)

	log.Infof("handleGlobalConfigSynchronized(%v)\n", done)
	if done {
		first := !ctx.GCInitialized
		if first {
			iptables.UpdateSshAccess(ctx.sshAccess, first)
		}
		ctx.GCInitialized = true
	}
}

func handleGlobalConfigModify(ctxArg interface{},
	key string, statusArg interface{}) {

	ctx := ctxArg.(*nodeagentContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.GlobalConfig
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil && !ctx.GCInitialized {
		updated := types.ApplyGlobalConfig(*gcp)
		log.Infof("handleGlobalConfigModify setting initials to %+v\n",
			updated)
		sane := types.EnforceGlobalConfigMinimums(updated)
		log.Infof("handleGlobalConfigModify: enforced minimums %v\n",
			cmp.Diff(updated, sane))
		ctx.globalConfig = &sane
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify(%s): done\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctx := ctxArg.(*nodeagentContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	ctx.globalConfig = &types.GlobalConfigDefaults
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

// handle zedagent status events, for cloud connectivity
func handleZedAgentStatusModify(ctxArg interface{},
	key string, statusArg interface{}) {
	ctx := ctxArg.(*nodeagentContext)
	status := cast.ZedAgentStatus(statusArg)
	if status.Key() != key {
		log.Errorf("zedagentStatus key mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	updateZedagentCloudConnectStatus(ctx, status)
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
	ctx := ctxArg.(*nodeagentContext)
	status := cast.ZbootStatus(statusArg)
	if status.Key() != key {
		log.Errorf("zbootStatus key mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	if status.CurrentPartition && ctx.updateInprogress &&
		status.PartitionState == "active" {
		log.Infof("CurPart(%s) transitioned to \"active\" state\n",
			status.PartitionLabel)
		ctx.updateInprogress = false
		publishNodeAgentStatus(ctx)
	}
	doZbootBaseOsInstallationComplete(ctx, key, status)
	doZbootBaseOsTestValidationComplete(ctx, key, status)
	log.Debugf("handleZbootStatusModify(%s) done\n", key)
}

func handleZbootStatusDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctx := ctxArg.(*nodeagentContext)
	if status := lookupZbootStatus(ctx, key); status == nil {
		log.Infof("handleZbootStatusDelete: unknown %s\n", key)
		return
	}
	log.Infof("handleZbootStatusDelete(%s) done\n", key)
}

// check whether zedagent module is alive
func isZedAgentAlive(ctx *nodeagentContext) bool {
	pgrepCmd := exec.Command("pgrep", "zedagent")
	stdout, err := pgrepCmd.Output()
	output := string(stdout)
	if err == nil && output != "" {
		return true
	}
	return false
}

// publish this status for consumption by zedagent
func publishNodeAgentStatus(ctx *nodeagentContext) {
	pub := ctx.pubNodeAgentStatus
	status := types.NodeAgentStatus{
		Name:              agentName,
		CurPart:           ctx.curPart,
		TestInprogress:    ctx.testInprogress,
		TestComplete:      ctx.updateComplete,
		RemainingTestTime: ctx.remainingTestTime,
		UpdateInprogress:  ctx.updateInprogress,
		NeedsReboot:       ctx.needsReboot,
		RebootReason:      ctx.rebootReason,
	}
	pub.Publish(agentName, status)
}
