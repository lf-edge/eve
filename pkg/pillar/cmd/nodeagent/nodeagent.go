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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	info "github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
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
	// Version : module version
	Version           = "No version specified"
	smartData         = types.NewSmartDataWithDefaults()
	previousSmartData = types.NewSmartDataWithDefaults()
)

type nodeagentContext struct {
	agentBaseContext            agentbase.Context
	GCInitialized               bool // Received initial GlobalConfig
	globalConfig                *types.ConfigItemValueMap
	subGlobalConfig             pubsub.Subscription
	subZbootStatus              pubsub.Subscription
	subZedAgentStatus           pubsub.Subscription
	subDomainStatus             pubsub.Subscription
	subVaultStatus              pubsub.Subscription
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
	deviceReboot                bool
	currentRebootReason         string // Reason we are rebooting
	currentBootReason           types.BootReason
	lastLock                    sync.Mutex       // Ensure publish gets consistent data
	rebootReason                string           // From last reboot
	bootReason                  types.BootReason // From last reboot
	rebootImage                 string           // Image from which the last reboot happened
	rebootStack                 string           // From last reboot
	rebootTime                  time.Time        // From last reboot
	restartCounter              uint32
	vaultOperational            types.TriState              // Is the vault fully operational?
	vaultTestStartTime          uint32                      // Time at which we should start waiting for vault to be operational
	maintMode                   bool                        // whether Maintenance mode should be triggered
	maintModeReason             types.MaintenanceModeReason //reason for entering Maintenance mode
	configGetSuccess            bool                        // got config from controller success
	vaultmgrReported            bool                        // got reports from vaultmgr

	// Some contants.. Declared here as variables to enable unit tests
	minRebootDelay          uint32
	maxDomainHaltTime       uint32
	domainHaltWaitIncrement uint32
}

var debug = false
var debugOverride bool // From command line arg

func newNodeagentContext(ps *pubsub.PubSub, logger *logrus.Logger, log *base.LogObject) *nodeagentContext {
	nodeagentCtx := nodeagentContext{}
	nodeagentCtx.minRebootDelay = minRebootDelay
	nodeagentCtx.maxDomainHaltTime = maxDomainHaltTime
	nodeagentCtx.domainHaltWaitIncrement = domainHaltWaitIncrement

	nodeagentCtx.globalConfig = types.DefaultConfigItemValueMap()

	// start the watchdog process timer tick
	duration := time.Duration(watchdogInterval) * time.Second
	nodeagentCtx.stillRunning = time.NewTicker(duration)

	// set the ticker timer
	duration = time.Duration(timeTickInterval) * time.Second
	nodeagentCtx.tickerTimer = time.NewTicker(duration)
	nodeagentCtx.configGetStatus = types.ConfigGetFail

	nodeagentCtx.agentBaseContext.PubSub = ps
	nodeagentCtx.agentBaseContext.Logger = logger
	nodeagentCtx.agentBaseContext.Log = log
	nodeagentCtx.agentBaseContext.ErrorTime = errorTime
	nodeagentCtx.agentBaseContext.AgentName = agentName
	nodeagentCtx.agentBaseContext.WarningTime = warningTime

	curpart := agentlog.EveCurrentPartition()
	nodeagentCtx.curPart = strings.TrimSpace(curpart)
	nodeagentCtx.agentBaseContext.NeedWatchdog = true
	nodeagentCtx.vaultOperational = types.TS_NONE
	return &nodeagentCtx
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

// Global to make log calls easier
var log *base.LogObject

// Run : nodeagent run entry function
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	log = logArg
	ctxPtr := newNodeagentContext(ps, loggerArg, logArg)

	agentbase.Run(ctxPtr)

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
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
	parseSMARTData()
	// get the last reboot reason
	handleLastRebootReason(ctxPtr)

	// Fault injection; if /persist/fault-injection/readfile exists we read it
	// which will use memory
	fileToRead := "/persist/fault-injection/readfile"
	if _, err := os.Stat(fileToRead); err == nil {
		log.Warnf("Reading %s", fileToRead)
		content, err := ioutil.ReadFile(fileToRead)
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

	// publish zboot config as of now
	publishZbootConfigAll(ctxPtr)

	// access the zboot APIs directly, baseosmgr is still not ready
	ctxPtr.updateInprogress = zboot.IsCurrentPartitionStateInProgress()
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
	if err := utils.WaitForOnboarded(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("Device is onboarded")

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
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctxPtr.subGlobalConfig, agentName,
		debugOverride, ctxPtr.agentBaseContext.Logger)
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
	debug, _ = agentlog.HandleGlobalConfig(log, ctxPtr.subGlobalConfig, agentName,
		debugOverride, ctxPtr.agentBaseContext.Logger)
	ctxPtr.globalConfig = types.DefaultConfigItemValueMap()
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

// handle zedagent status events, for cloud connectivity
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
	handleRebootCmd(ctxPtr, status)
	updateZedagentCloudConnectStatus(ctxPtr, status)
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
	rebootReason, rebootTime, rebootStack := agentlog.GetRebootReason(log)
	if rebootReason != "" {
		log.Warnf("Current partition RebootReason: %s",
			rebootReason)
		agentlog.DiscardRebootReason(log)
	}
	// We override the above rebootTime since if bootReason is known this is when things
	// started going down
	bootReason, ts := agentlog.GetBootReason(log)
	if bootReason != types.BootReasonNone {
		rebootTime = ts
		log.Noticef("found bootReason %s", bootReason)
	}

	agentlog.DiscardBootReason(log)
	// still nothing, fillup the default
	if rebootReason == "" {
		rebootTime = time.Now()
		dateStr := rebootTime.Format(time.RFC3339Nano)
		var reason string
		if fileExists(firstbootFile) {
			reason = fmt.Sprintf("NORMAL: First boot of device - at %s",
				dateStr)
			if bootReason == types.BootReasonNone {
				bootReason = types.BootReasonFirst
			}
		} else if previousSmartData.PowerCycleCount > -1 && smartData.PowerCycleCount > -1 &&
			bootReason == types.BootReasonNone {
			log.Noticef("previous power cycle count %d current %d",
				previousSmartData.PowerCycleCount,
				smartData.PowerCycleCount)
			if previousSmartData.PowerCycleCount < smartData.PowerCycleCount {
				reason = fmt.Sprintf("Reboot reason - device powered off. Restarted at %s",
					dateStr)
				bootReason = types.BootReasonPowerFail
			} else {
				reason = fmt.Sprintf("Reboot reason - kernel crash - at %s",
					dateStr)
				bootReason = types.BootReasonKernel
			}
		} else {
			reason = fmt.Sprintf("Unknown reboot reason - power failure or crash - at %s",
				dateStr)
			if bootReason == types.BootReasonNone {
				bootReason = types.BootReasonUnknown
			}
		}
		log.Warnf("Default RebootReason: %s", reason)
		rebootReason = reason
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
	rebootImage := agentlog.GetRebootImage(log)
	if rebootImage != "" {
		agentlog.DiscardRebootImage(log)
	}
	// Update context
	ctx.lastLock.Lock()
	ctx.bootReason = bootReason
	ctx.rebootImage = rebootImage
	ctx.rebootReason = rebootReason
	ctx.rebootTime = rebootTime
	ctx.rebootStack = rebootStack
	// Read and increment restartCounter
	ctx.restartCounter = incrementRestartCounter()
	ctx.lastLock.Unlock()
}

// If the file doesn't exist we pick zero.
// Return value before increment; write new value to file
func incrementRestartCounter() uint32 {
	var restartCounter uint32

	if _, err := os.Stat(restartCounterFile); err == nil {
		b, err := fileutils.ReadWithMaxSize(log, restartCounterFile,
			maxReadSize)
		if err != nil {
			log.Errorf("incrementRestartCounter: %s", err)
		} else {
			c, err := strconv.Atoi(string(b))
			if err != nil {
				log.Errorf("incrementRestartCounter: %s", err)
			} else {
				restartCounter = uint32(c)
				log.Functionf("incrementRestartCounter: read %d", restartCounter)
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
// Can be called from a timer hence we use a mutex to avoid issues
// with changing last* fields.
func publishNodeAgentStatus(ctxPtr *nodeagentContext) {
	pub := ctxPtr.pubNodeAgentStatus
	ctxPtr.lastLock.Lock()
	status := types.NodeAgentStatus{
		Name:                       agentName,
		CurPart:                    ctxPtr.curPart,
		RemainingTestTime:          ctxPtr.remainingTestTime,
		UpdateInprogress:           ctxPtr.updateInprogress,
		DeviceReboot:               ctxPtr.deviceReboot,
		RebootReason:               ctxPtr.rebootReason,
		BootReason:                 ctxPtr.bootReason,
		RebootStack:                ctxPtr.rebootStack,
		RebootTime:                 ctxPtr.rebootTime,
		RebootImage:                ctxPtr.rebootImage,
		RestartCounter:             ctxPtr.restartCounter,
		LocalMaintenanceMode:       ctxPtr.maintMode,
		LocalMaintenanceModeReason: ctxPtr.maintModeReason,
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
	if vault.ConversionComplete && vault.Status != info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR {
		ctx.vaultOperational = types.TS_ENABLED
		// Do we need to clear maintenance?
		if ctx.maintMode &&
			ctx.maintModeReason == types.MaintenanceModeReasonVaultLockedUp {
			log.Noticef("Clearing %s",
				types.MaintenanceModeReasonVaultLockedUp)
			ctx.maintMode = false
			ctx.maintModeReason = types.MaintenanceModeReasonNone
			publishNodeAgentStatus(ctx)
		}
	} else {
		ctx.vaultOperational = types.TS_DISABLED
	}
}

func parseSMARTData() {
	currentSMARTfilename := "/persist/SMART_details.json"
	previousSMARTfilename := "/persist/SMART_details_previous.json"
	parseData := func(filePath string, SMARTDataObj *types.SmartData) {
		data, err := fileutils.ReadWithMaxSize(log, filePath,
			maxSmartCtlSize)
		if err != nil {
			log.Errorf("parseSMARTData: exception while opening %s. %s", filePath, err.Error())
			return
		}
		if err := json.Unmarshal(data, &SMARTDataObj); err != nil {
			log.Errorf("parseSMARTData: exception while parsing SMART data. %s", err.Error())
			return
		}
		SMARTDataObj.RawData = string(data)
	}

	parseData(currentSMARTfilename, smartData)
	parseData(previousSMARTfilename, previousSmartData)
}
