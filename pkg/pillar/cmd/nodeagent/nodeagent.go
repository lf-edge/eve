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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	info "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	"github.com/sirupsen/logrus"
)

const (
	agentName                   = "nodeagent"
	timeTickInterval     uint32 = 10
	watchdogInterval     uint32 = 25 // For StillRunning
	maxRebootStackSize          = 1600
	maxJSONAttributeSize        = maxRebootStackSize + 100
	configDir                   = "/config"
	tmpDirname                  = "/run/global"
	firstbootFile               = tmpDirname + "/first-boot"
	installLog                  = types.PersistInstallerDir + "/installer.log"
	installLogSendReq           = types.PersistInstallerDir + "/send-require" //indicates that we should send logs
	restartCounterFile          = types.PersistStatusDir + "/restartcounter"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	// Timer values ( in sec ) to handle reboot
	minRebootDelay          uint32 = 30
	maxDomainHaltTime       uint32 = 300
	domainHaltWaitIncrement uint32 = 5
	maxReadSize                    = 16384 // From files in /persist
	maxSmartCtlSize                = 65536 // Limit size of smartctl output files read
)

var (
	smartData         = types.NewSmartDataWithDefaults()
	previousSmartData = types.NewSmartDataWithDefaults()
)

type nodeagentContext struct {
	agentbase.AgentBase
	GCInitialized               bool // Received initial GlobalConfig
	globalConfig                *types.ConfigItemValueMap
	subGlobalConfig             pubsub.Subscription
	subZbootStatus              pubsub.Subscription
	subZedAgentStatus           pubsub.Subscription
	subDomainStatus             pubsub.Subscription
	subVaultStatus              pubsub.Subscription
	subVolumeMgrStatus          pubsub.Subscription
	subNodeDrainStatus          pubsub.Subscription
	subTpmStatus                pubsub.Subscription
	pubZbootConfig              pubsub.Publication
	pubNodeAgentStatus          pubsub.Publication
	curPart                     string
	upgradeTestStartTime        uint32
	tickerTimer                 *time.Ticker
	stillRunning                *time.Ticker
	remainingTestTime           time.Duration
	lastControllerReachableTime uint32 // Got a config or some error but can reach controller
	configGetStatus             types.ConfigGetStatus
	deviceRegistered            bool
	updateInprogress            bool
	updateComplete              bool
	testComplete                bool
	testInprogress              bool
	timeTickCount               uint32 // Don't get confused by NTP making time jump by tracking our own progression
	rebootCmd                   bool   // Are we rebooting?
	shutdownCmd                 bool   // Are we shutting down all apps?
	poweroffCmd                 bool   // Shutting down all apps plus poweroff?
	deviceReboot                bool
	deviceShutdown              bool
	devicePoweroff              bool
	allDomainsHalted            bool   // Progression of reboot, shutdown, etc
	requestedRebootReason       string // Reason we will be rebooting
	requestedBootReason         types.BootReason
	lastLock                    sync.Mutex       // Ensure publish gets consistent data
	rebootReason                string           // From last reboot
	bootReason                  types.BootReason // From last reboot
	rebootImage                 string           // Image from which the last reboot happened
	rebootStack                 string           // From last reboot
	rebootTime                  time.Time        // From last reboot
	restartCounter              uint32
	vaultOperational            types.TriState                   // Is the vault fully operational?
	vaultMismatchingPCRs        []int                            // PCR indexes that probably blocked unsealing the vault key
	vaultTestStartTime          uint32                           // Time at which we should start waiting for vault to be operational
	maintMode                   bool                             // whether Maintenance mode should be triggered
	maintModeReasons            types.MaintenanceModeMultiReason // reasons for entering Maintenance mode
	configGetSuccess            bool                             // got config from controller success
	vaultmgrReported            bool                             // got reports from vaultmgr
	hvTypeKube                  bool                             // image is kubernetes cluster type
	waitDrainInProgress         bool

	// Some constants.. Declared here as variables to enable unit tests
	minRebootDelay          uint32
	maxDomainHaltTime       uint32
	domainHaltWaitIncrement uint32

	// startNodeOperation spawns the reboot/shutdown/poweroff goroutine.
	// Defaulted in newNodeagentContext to handleNodeOperation; overridden
	// by tests so they don't actually call zboot.Reset / zboot.Poweroff.
	startNodeOperation func(types.DeviceOperation)

	// Test seams. Defaulted to real implementations in
	// newNodeagentContext; overridden by tests.
	zboot       Zboot
	rebootStore RebootStore
	paths       pathConfig
}

func newNodeagentContext(ps *pubsub.PubSub, _ *logrus.Logger, logArg *base.LogObject) *nodeagentContext {
	nodeagentCtx := nodeagentContext{}
	nodeagentCtx.minRebootDelay = minRebootDelay
	nodeagentCtx.maxDomainHaltTime = maxDomainHaltTime
	nodeagentCtx.domainHaltWaitIncrement = domainHaltWaitIncrement

	nodeagentCtx.globalConfig = types.DefaultConfigItemValueMap()

	// start the watchdog process timer tick
	duration := time.Duration(watchdogInterval) * time.Second
	nodeagentCtx.stillRunning = time.NewTicker(duration)
	ps.StillRunning(agentName, warningTime, errorTime)

	// set the ticker timer
	duration = time.Duration(timeTickInterval) * time.Second
	nodeagentCtx.tickerTimer = time.NewTicker(duration)
	nodeagentCtx.configGetStatus = types.ConfigGetFail

	nodeagentCtx.zboot = realZboot{}
	nodeagentCtx.rebootStore = realRebootStore{log: logArg}
	nodeagentCtx.paths = defaultPathConfig()

	curpart := nodeagentCtx.zboot.EveCurrentPartition()
	nodeagentCtx.curPart = strings.TrimSpace(curpart)
	nodeagentCtx.vaultOperational = types.TS_NONE
	nodeagentCtx.hvTypeKube = base.IsHVTypeKube()
	nodeagentCtx.startNodeOperation = func(op types.DeviceOperation) {
		go handleNodeOperation(&nodeagentCtx, op)
	}
	return &nodeagentCtx
}

// Global to make log calls easier
var log *base.LogObject

// Run : nodeagent run entry function
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	log = logArg

	ctxPtr := newNodeagentContext(ps, loggerArg, logArg)
	agentbase.Init(ctxPtr, loggerArg, logArg, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    false,
		Activate:      false,
		Ctx:           ctxPtr,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		SyncHandler:   handleGlobalConfigSynchronized,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Pick up debug aka log level before we start real work
	for !ctxPtr.GCInitialized {
		log.Functionf("Waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-ctxPtr.tickerTimer.C:
			handleDeviceTimers(ctxPtr)

		case <-ctxPtr.stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	//Parse SMART data
	parseSMARTData(ctxPtr)
	// get the last reboot reason
	handleLastRebootReason(ctxPtr)
	// send Installation log and remove first-boot from installation
	handleInstallationLog(ctxPtr)

	// Fault injection; if /persist/fault-injection/readfile exists we read it
	// which will use memory
	fileToRead := ctxPtr.paths.faultInjectionFile
	if _, err := os.Stat(fileToRead); err == nil {
		log.Warnf("Reading %s", fileToRead)
		content, err := os.ReadFile(fileToRead)
		if err != nil {
			log.Error(err)
		} else {
			log.Noticef("Read %d bytes from %s",
				len(content), fileToRead)
		}
	}

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
	ctxPtr.pubNodeAgentStatus = pubNodeAgentStatus

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
	ctxPtr.pubZbootConfig = pubZbootConfig

	// Look for vault status
	subVaultStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "vaultmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VaultStatus{},
		Activate:      false,
		Ctx:           ctxPtr,
		CreateHandler: handleVaultStatusCreate,
		ModifyHandler: handleVaultStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subVaultStatus = subVaultStatus
	subVaultStatus.Activate()

	// Look for VolumeMgrStatus
	subVolumeMgrStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VolumeMgrStatus{},
		Activate:      false,
		Ctx:           ctxPtr,
		CreateHandler: handleVolumeMgrStatusCreate,
		ModifyHandler: handleVolumeMgrStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subVolumeMgrStatus = subVolumeMgrStatus
	subVolumeMgrStatus.Activate()

	// Look for Tpm status
	subTpmStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "tpmmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.TpmSanityStatus{},
		Activate:      false,
		Ctx:           ctxPtr,
		CreateHandler: handleTpmStatusCreate,
		ModifyHandler: handleTpmStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subTpmStatus = subTpmStatus
	subTpmStatus.Activate()

	// publish zboot config as of now
	publishZbootConfigAll(ctxPtr)

	// access the zboot APIs directly, baseosmgr is still not ready
	ctxPtr.updateInprogress = ctxPtr.zboot.IsCurrentPartitionStateInProgress()
	log.Functionf("Current partition: %s, inProgress: %v", ctxPtr.curPart,
		ctxPtr.updateInprogress)
	publishNodeAgentStatus(ctxPtr)

	// Get DomainStatus from domainmgr
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.DomainStatus{},
		Activate:    false,
		Ctx:         ctxPtr,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	// Wait until we have been onboarded aka know our own UUID however we do not use the UUID
	if _, err := wait.WaitForOnboarded(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("Device is onboarded")

	// if current partition state is not in-progress,
	// nothing much to do. Controller connectivity is tracked,
	// to trigger the device to reboot, on reset timeout expiry
	//
	// if current partition state is in-progress,
	// trigger the device to reboot on
	// fallback timeout expiry
	//
	// On zedbox modules activation, nodeagent will
	// track the controller connectivity events
	//
	// These timer functions will be tracked using
	// controller connectivity status.

	// Start waiting for controller connectivity
	ctxPtr.lastControllerReachableTime = ctxPtr.timeTickCount
	setTestStartTime(ctxPtr)

	// subscribe to zboot status events
	subZbootStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "baseosmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.ZbootStatus{},
		Activate:      false,
		Ctx:           ctxPtr,
		CreateHandler: handleZbootStatusCreate,
		ModifyHandler: handleZbootStatusModify,
		DeleteHandler: handleZbootStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subZbootStatus = subZbootStatus
	subZbootStatus.Activate()

	// subscribe to zedagent status events
	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           ctxPtr,
		CreateHandler: handleZedAgentStatusCreate,
		ModifyHandler: handleZedAgentStatusModify,
		DeleteHandler: handleZedAgentStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	initNodeDrainPubSub(ps, ctxPtr)

	log.Functionf("zedbox event loop")
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

		case <-ctxPtr.tickerTimer.C:
			handleDeviceTimers(ctxPtr)

		case change := <-subVaultStatus.MsgChan():
			subVaultStatus.ProcessChange(change)

		case change := <-subVolumeMgrStatus.MsgChan():
			subVolumeMgrStatus.ProcessChange(change)

		case change := <-ctxPtr.subNodeDrainStatus.MsgChan():
			ctxPtr.subNodeDrainStatus.ProcessChange(change)

		case change := <-subTpmStatus.MsgChan():
			subTpmStatus.ProcessChange(change)

		case <-ctxPtr.stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

// In case there is no GlobalConfig.json this will move us forward
func handleGlobalConfigSynchronized(ctxArg interface{}, done bool) {
	ctxPtr := ctxArg.(*nodeagentContext)

	log.Functionf("handleGlobalConfigSynchronized(%v)", done)
	if done {
		ctxPtr.GCInitialized = true
	}
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctxPtr.subGlobalConfig, agentName,
		ctxPtr.CLIParams().DebugOverride, ctxPtr.Logger())
	if gcp != nil {
		ctxPtr.globalConfig = gcp
		ctxPtr.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl(%s): done", key)
}

func handleGlobalConfigDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctxPtr.subGlobalConfig, agentName,
		ctxPtr.CLIParams().DebugOverride, ctxPtr.Logger())
	ctxPtr.globalConfig = types.DefaultConfigItemValueMap()
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

// handle zedagent status events, for controller connectivity
func handleZedAgentStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	status := statusArg.(types.ZedAgentStatus)
	if status.RebootCmd {
		handleDeviceCmd(ctxPtr, status, types.DeviceOperationReboot)
	}
	if status.ShutdownCmd {
		handleDeviceCmd(ctxPtr, status, types.DeviceOperationShutdown)
	}
	if status.PoweroffCmd {
		handleDeviceCmd(ctxPtr, status, types.DeviceOperationPoweroff)
	}
	updateZedagentCloudConnectStatus(ctxPtr, status)
	if status.EdgeNodeCertsRefused {
		addMaintenanceModeReason(ctxPtr,
			types.MaintenanceModeReasonEdgeNodeCertsRefused,
			"handleZedAgentStatusImpl")
		publishNodeAgentStatus(ctxPtr)
	} else {
		removeMaintenanceModeReason(ctxPtr,
			types.MaintenanceModeReasonEdgeNodeCertsRefused,
			"handleZedAgentStatusImpl")
		publishNodeAgentStatus(ctxPtr)
	}
	log.Functionf("handleZedAgentStatusImpl(%s) done", key)
}

func handleZedAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	// do nothing
	log.Functionf("handleZedAgentStatusDelete(%s) done", key)
}

// zboot status event handlers
func handleZbootStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleZbootStatusImpl(ctxArg, key, statusArg)
}

func handleZbootStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleZbootStatusImpl(ctxArg, key, statusArg)
}

func handleZbootStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	status := statusArg.(types.ZbootStatus)
	if status.CurrentPartition && ctxPtr.updateInprogress &&
		status.PartitionState == "active" {
		log.Functionf("CurPart(%s) transitioned to \"active\" state",
			status.PartitionLabel)
		ctxPtr.updateInprogress = false
		ctxPtr.testComplete = false
		ctxPtr.updateComplete = false
		publishNodeAgentStatus(ctxPtr)
	}
	doZbootBaseOsInstallationComplete(ctxPtr, key, status)
	doZbootBaseOsTestValidationComplete(ctxPtr, key, status)
	log.Tracef("handleZbootStatusImpl(%s) done", key)
}

func handleZbootStatusDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(*nodeagentContext)
	if status := lookupZbootStatus(ctxPtr, key); status == nil {
		log.Functionf("handleZbootStatusDelete: unknown %s", key)
		return
	}
	log.Functionf("handleZbootStatusDelete(%s) done", key)
}

// If we have a reboot reason from this or the other partition
// (assuming the other is in inprogress) then we log it
// we will push this as part of baseos status
func handleLastRebootReason(ctx *nodeagentContext) {

	// Wait to update ctx until the end since the timer publishes these
	// values and don't want partial or changing data.
	// until after truncation.
	rebootReason, rebootTime, rebootStack := ctx.rebootStore.GetRebootReason()
	if rebootReason != "" {
		log.Warnf("Current partition RebootReason: %s",
			rebootReason)
		ctx.rebootStore.DiscardRebootReason()
	}
	// We override the above rebootTime since if bootReason is known this is when things
	// started going down
	bootReason, ts := ctx.rebootStore.GetBootReason()
	if bootReason != types.BootReasonNone {
		rebootTime = ts
		log.Noticef("found bootReason %s", bootReason)
	}

	ctx.rebootStore.DiscardBootReason()
	// Make sure we log the reboot stack or dmesg
	if len(rebootStack) > 0 {
		lines := strings.Split(rebootStack, "\n")

		// Tag each line for easy grep
		var tag string
		if bootReason == types.BootReasonKernel {
			tag = "dmesg"
		} else {
			tag = "stack"
		}
		log.Warnf("[%s] found reboot-stack content: %d bytes %d lines",
			tag, len(rebootStack), len(lines))
		for i, l := range lines {
			log.Warnf("[%s #%d]: %s", tag, i, l)
		}
	}
	// still no rebootReason? set based on other info
	if rebootReason == "" {
		rebootTime = time.Now()
		rebootReason, bootReason = synthesizeRebootReason(
			fileutils.FileExists(log, ctx.paths.firstbootFile),
			bootReason, previousSmartData, smartData, rebootTime)
		log.Warnf("Default RebootReason: %s", rebootReason)
		rebootStack = ""
	}
	// remove the first boot file, if it is present
	if fileutils.FileExists(log, ctx.paths.firstbootFile) {
		os.Remove(ctx.paths.firstbootFile)
	}

	rebootStack = truncateRebootStack(rebootStack)
	rebootImage := ctx.rebootStore.GetRebootImage()
	if rebootImage != "" {
		ctx.rebootStore.DiscardRebootImage()
	}
	// Update context
	ctx.lastLock.Lock()
	ctx.bootReason = bootReason
	ctx.rebootImage = rebootImage
	ctx.rebootReason = rebootReason
	ctx.rebootTime = rebootTime
	ctx.rebootStack = rebootStack
	// Read and increment restartCounter
	ctx.restartCounter = incrementRestartCounter(ctx)
	ctx.lastLock.Unlock()
}

// synthesizeRebootReason produces a default RebootReason and BootReason
// when nothing was persisted from the previous boot. Pure: no I/O,
// no globals.
func synthesizeRebootReason(firstBoot bool, storedBootReason types.BootReason,
	prevSmart, currSmart *types.DeviceSmartInfo, now time.Time) (string, types.BootReason) {

	bootReason := storedBootReason
	// The hardware watchdog latches WDIOF_CARDRESET when it reset the
	// device. Recorded at boot by pkg/watchdog; used to disambiguate the
	// reboots that SMART power-cycle counters and EVE's own bookkeeping
	// cannot otherwise explain.
	hwWatchdogReset := hwWatchdogCardReset()
	dateStr := now.Format(time.RFC3339Nano)
	var reason string
	switch {
	case firstBoot:
		reason = fmt.Sprintf("NORMAL: First boot of device - at %s",
			dateStr)
		if bootReason == types.BootReasonNone {
			bootReason = types.BootReasonFirst
		}
	case hwWatchdogReset:
		reason = fmt.Sprintf("Reboot reason - hardware watchdog reset the device - at %s",
			dateStr)
		bootReason = types.BootReasonHWWatchdog
	case prevSmart != nil && currSmart != nil &&
		prevSmart.PowerCycleCount > -1 && currSmart.PowerCycleCount > -1 &&
		bootReason == types.BootReasonNone:
		if prevSmart.PowerCycleCount < currSmart.PowerCycleCount {
			reason = fmt.Sprintf("Reboot reason - device powered off. Restarted at %s",
				dateStr)
			bootReason = types.BootReasonPowerFail
		} else {
			reason = fmt.Sprintf("Reboot reason - system reset, reboot or kernel panic due to watchdog or kernel bug (no kdump) - at %s",
				dateStr)
			bootReason = types.BootReasonKernel
		}
	default:
		reason = fmt.Sprintf("Unknown reboot reason - power failure or crash - at %s",
			dateStr)
		if bootReason == types.BootReasonNone {
			bootReason = types.BootReasonUnknown
		}
	}
	return reason, bootReason
}

// truncateRebootStack tail-truncates the reboot stack to fit in pubsub.
// The tail is preserved (rather than the head) because the stack grows
// down and the bottom frames are more interesting after truncation.
// Pure: no I/O.
func truncateRebootStack(stack string) string {
	if len(stack) <= maxJSONAttributeSize {
		return stack
	}
	runes := bytes.Runes([]byte(stack))
	sz := len(runes)
	if sz <= maxJSONAttributeSize {
		// Bytes too long but runes fit; not worth truncating.
		return stack
	}
	return fmt.Sprintf("...\n%v", string(runes[sz-maxRebootStackSize:sz]))
}

// handleInstallationLog checks if we should send installer logs
// send log from installation to the controller
// and remove file after small timeout to not send them after reboot
func handleInstallationLog(ctx *nodeagentContext) {
	if fileutils.FileExists(log, ctx.paths.installLogSendReq) {
		f, err := os.Open(ctx.paths.installLog)
		if err != nil {
			log.Errorf("cannot open installation log: %s", err)
			return
		}
		scanner := bufio.NewScanner(f)
		buf := make([]byte, 0, maxReadSize)
		scanner.Buffer(buf, maxReadSize)
		// installerLog is logger with modified source and zeroed pid
		installerLog := base.NewSourceLogObject(ctx.Logger(), "installer", 0)
		for scanner.Scan() {
			installerLog.Noticeln(scanner.Text())
		}
		if scanner.Err() != nil {
			log.Errorf("cannot read installation log: %s", scanner.Err())
		}
		_ = f.Close()
		// schedule remove of installLogSendReq file after small timeout
		// to not re-send log after reboot
		removePath := ctx.paths.installLogSendReq
		time.AfterFunc(warningTime, func() {
			err := os.Remove(removePath)
			if err != nil {
				log.Errorf("cannot remove installation log sending request file: %s", err)
			}
		})
	}
}

// If the file doesn't exist we pick zero.
// Return value before increment; write new value to file
func incrementRestartCounter(ctx *nodeagentContext) uint32 {
	return incrementRestartCounterIn(ctx.paths.restartCounterFile)
}

// incrementRestartCounterIn is the path-parameterised core of
// incrementRestartCounter, used by unit tests.
func incrementRestartCounterIn(path string) uint32 {
	var restartCounter uint32

	if _, err := os.Stat(path); err == nil {
		b, err := fileutils.ReadWithMaxSize(log, path,
			maxReadSize)
		if err != nil {
			log.Errorf("incrementRestartCounter: %s", err)
		} else {
			c, err := strconv.ParseUint(string(b), 10, 32)
			if err != nil {
				log.Errorf("incrementRestartCounter: %s", err)
			} else {
				restartCounter = uint32(c)
				log.Functionf("incrementRestartCounter: read %d", restartCounter)
			}
		}
	}
	b := []byte(fmt.Sprintf("%d", restartCounter+1))
	err := os.WriteFile(path, b, 0644)
	if err != nil {
		log.Errorf("incrementRestartCounter write: %s", err)
	}
	return restartCounter
}

// publish nodeagent status
// Can be called from a timer hence we use a mutex to avoid issues
// with changing last* fields.
func publishNodeAgentStatus(ctxPtr *nodeagentContext) {
	pub := ctxPtr.pubNodeAgentStatus
	ctxPtr.lastLock.Lock()
	status := types.NodeAgentStatus{
		Name:                        agentName,
		CurPart:                     ctxPtr.curPart,
		RemainingTestTime:           ctxPtr.remainingTestTime,
		UpdateInprogress:            ctxPtr.updateInprogress,
		DeviceReboot:                ctxPtr.deviceReboot,
		DeviceShutdown:              ctxPtr.deviceShutdown,
		DevicePoweroff:              ctxPtr.devicePoweroff,
		AllDomainsHalted:            ctxPtr.allDomainsHalted,
		RebootReason:                ctxPtr.rebootReason,
		BootReason:                  ctxPtr.bootReason,
		RebootStack:                 ctxPtr.rebootStack,
		RebootTime:                  ctxPtr.rebootTime,
		RebootImage:                 ctxPtr.rebootImage,
		RestartCounter:              ctxPtr.restartCounter,
		LocalMaintenanceMode:        ctxPtr.maintMode,
		LocalMaintenanceModeReasons: ctxPtr.maintModeReasons,
		HVTypeKube:                  ctxPtr.hvTypeKube,
		WaitDrainInProgress:         ctxPtr.waitDrainInProgress,
	}
	ctxPtr.lastLock.Unlock()
	pub.Publish(agentName, status)
}

func handleVaultStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVaultStatusImpl(ctxArg, key, statusArg)
}

func handleVaultStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleVaultStatusImpl(ctxArg, key, statusArg)
}

func handleVaultStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*nodeagentContext)
	vault := statusArg.(types.VaultStatus)

	ctx.vaultmgrReported = true
	if ctx.vaultTestStartTime == 0 {
		//First update from vaultmgr, record it as test start time
		log.Notice("handleVaultStatusImpl: Recording vault test start time")
		ctx.vaultTestStartTime = ctx.timeTickCount
	}

	//Filter out other irrelevant vaults' status
	if vault.Name != types.DefaultVaultName {
		return
	}
	if vault.Status != info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR {
		ctx.vaultMismatchingPCRs = nil
		if vault.ConversionComplete {
			ctx.vaultOperational = types.TS_ENABLED
			// Do we need to clear maintenance?
			removeMaintenanceModeReason(ctx, types.MaintenanceModeReasonVaultLockedUp, "handleVaultStatusImpl")
			publishNodeAgentStatus(ctx)
		} else {
			ctx.vaultOperational = types.TS_NONE
		}
	} else {
		ctx.vaultOperational = types.TS_DISABLED
		// Remember why the vault could not be unlocked so we can record it in
		// the reboot reason if the vault never becomes operational.
		ctx.vaultMismatchingPCRs = vault.MismatchingPCRs
	}
}

func handleVolumeMgrStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVolumeMgrStatusImpl(ctxArg, key, statusArg)
}

func handleVolumeMgrStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleVolumeMgrStatusImpl(ctxArg, key, statusArg)
}

func handleVolumeMgrStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*nodeagentContext)
	vms := statusArg.(types.VolumeMgrStatus)
	// This RemainingSpace takes into account the space reserved for
	// /persist/newlog plus the percentage/minimum reserved for the rest
	// of EVE-OS. Thus it can never go negative, but zero means that
	// we neiether have space to download new images nor space to deploy
	// a tiny app instance.
	if vms.RemainingSpace == 0 {
		log.Warnf("MaintenanceMode due to no remaining diskspace")
		// Add to maintenance mode reasons
		addMaintenanceModeReason(ctx, types.MaintenanceModeReasonNoDiskSpace, "handleVolumeMgrStatusImpl")
		publishNodeAgentStatus(ctx)
	} else {
		// Do we need to clear maintenance?
		removeMaintenanceModeReason(ctx, types.MaintenanceModeReasonNoDiskSpace, "handleVolumeMgrStatusImpl")
		publishNodeAgentStatus(ctx)
	}
}

func parseSMARTData(ctx *nodeagentContext) {
	parseSMARTDataFiles(
		ctx.paths.smartCurrent,
		ctx.paths.smartPrevious,
		smartData, previousSmartData)
}

// parseSMARTDataFiles is the path-parameterised core of parseSMARTData,
// used by unit tests. Missing or malformed files leave the destination
// unchanged.
func parseSMARTDataFiles(currPath, prevPath string,
	curr, prev *types.DeviceSmartInfo) {
	parseOne := func(filePath string, dst *types.DeviceSmartInfo) {
		data, err := fileutils.ReadWithMaxSize(log, filePath,
			maxSmartCtlSize)
		if err != nil {
			log.Errorf("parseSMARTData: exception while opening %s. %s", filePath, err.Error())
			return
		}
		if err := json.Unmarshal(data, &dst); err != nil {
			log.Errorf("parseSMARTData: exception while parsing SMART data. %s", err.Error())
			return
		}
	}
	parseOne(currPath, curr)
	parseOne(prevPath, prev)
}

// hwWatchdogCardReset reports whether the hardware watchdog reset the device
// on the previous boot. It reads the boot status recorded by pkg/watchdog,
// which lists the WDIOF_* flag names that were set; CARDRESET is the flag the
// kernel sets when the watchdog timer expired and reset the board. Platforms
// whose watchdog driver does not report this flag never produce the entry, so
// a missing or absent file simply yields false.
func hwWatchdogCardReset() bool {
	data, err := fileutils.ReadWithMaxSize(log, types.HWWatchdogBootStatusFile,
		maxReadSize)
	if err != nil {
		// Expected on platforms with no hardware watchdog or none that
		// reports a boot status; not an error worth flagging.
		log.Functionf("hwWatchdogCardReset: %s not readable: %v",
			types.HWWatchdogBootStatusFile, err)
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "CARDRESET" {
			return true
		}
	}
	return false
}

func handleTpmStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleTpmStatusImpl(ctxArg, key, statusArg)
}

func handleTpmStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleTpmStatusImpl(ctxArg, key, statusArg)
}

func handleTpmStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*nodeagentContext)
	tpm := statusArg.(types.TpmSanityStatus)

	if tpm.Status == types.MaintenanceModeReasonTpmEncFailure {
		log.Errorf("handleTpmStatusImpl: TPM manager reported TPM error : %s", tpm.Error)
		addMaintenanceModeReason(ctx, types.MaintenanceModeReasonTpmEncFailure, "handleTpmStatusImpl")
		publishNodeAgentStatus(ctx)
	} else {
		removeMaintenanceModeReason(ctx, types.MaintenanceModeReasonTpmEncFailure, "handleTpmStatusImpl")
		publishNodeAgentStatus(ctx)
	}
}

func addMaintenanceModeReason(ctx *nodeagentContext, reason types.MaintenanceModeReason, caller string) {
	log.Noticef("%s setting %s", caller, reason)
	ctx.maintMode = true
	// don't add duplicate reasons
	for _, r := range ctx.maintModeReasons {
		if r == reason {
			return
		}
	}

	ctx.maintModeReasons = append(ctx.maintModeReasons, reason)
}

func removeMaintenanceModeReason(ctx *nodeagentContext, reason types.MaintenanceModeReason, caller string) {
	log.Noticef("%s clearing %s", caller, reason)
	for i, r := range ctx.maintModeReasons {
		if r == reason {
			ctx.maintModeReasons = append(ctx.maintModeReasons[:i], ctx.maintModeReasons[i+1:]...)
		}
	}

	if len(ctx.maintModeReasons) == 0 && ctx.maintMode {
		ctx.maintMode = false
		log.Noticef("%s : No reason to be in maintenance mode, clearing maintenance mode", caller)
	}
}
