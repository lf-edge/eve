// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Get AppInstanceConfig from zedagent, drive config to VolumeMgr,
// IdentityMgr, and Zedrouter. Collect status from those services and make
// the combined AppInstanceStatus available to zedagent.

package zedmanager

import (
	"flag"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/uuidtonum"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "zedmanager"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Version can be set from Makefile
var Version = "No version specified"

// State used by handlers
type zedmanagerContext struct {
	subAppInstanceConfig  pubsub.Subscription
	subAppInstanceStatus  pubsub.Subscription // zedmanager both publishes and subscribes to AppInstanceStatus
	pubAppInstanceStatus  pubsub.Publication
	pubAppInstanceSummary pubsub.Publication
	pubVolumeRefConfig    pubsub.Publication
	subVolumeRefStatus    pubsub.Subscription
	pubAppNetworkConfig   pubsub.Publication
	subAppNetworkStatus   pubsub.Subscription
	pubDomainConfig       pubsub.Publication
	subDomainStatus       pubsub.Subscription
	subGlobalConfig       pubsub.Subscription
	subHostMemory         pubsub.Subscription
	subZedAgentStatus     pubsub.Subscription
	globalConfig          *types.ConfigItemValueMap
	pubUuidToNum          pubsub.Publication
	GCInitialized         bool
	checkFreedResources   bool // Set when app instance has !Activated
	currentProfile        string
	currentTotalMemoryMB  uint64
	// The time from which the configured applications delays should be counted
	delayBaseTime time.Time
}

var debug = false
var debugOverride bool // From command line arg
var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg
	flagSet := flag.NewFlagSet(agentName, flag.ExitOnError)
	versionPtr := flagSet.Bool("v", false, "Version")
	debugPtr := flagSet.Bool("d", false, "Debug flag")
	if err := flagSet.Parse(arguments); err != nil {
		log.Fatal(err)
	}
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}
	log.Functionf("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Any state needed by handler functions
	ctx := zedmanagerContext{
		globalConfig: types.DefaultConfigItemValueMap(),
	}
	// Create publish before subscribing and activating subscriptions
	pubAppInstanceStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppInstanceStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppInstanceStatus = pubAppInstanceStatus
	pubAppInstanceStatus.ClearRestarted()

	pubAppInstanceSummary, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppInstanceSummary{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppInstanceSummary = pubAppInstanceSummary
	pubAppInstanceSummary.ClearRestarted()

	pubVolumeRefConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		AgentScope: types.AppImgObj,
		TopicType:  types.VolumeRefConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumeRefConfig = pubVolumeRefConfig

	pubAppNetworkConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppNetworkConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppNetworkConfig = pubAppNetworkConfig
	pubAppNetworkConfig.ClearRestarted()

	pubDomainConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DomainConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubDomainConfig = pubDomainConfig
	pubDomainConfig.ClearRestarted()

	pubUuidToNum, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		Persistent: true,
		TopicType:  types.UuidToNum{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubUuidToNum = pubUuidToNum
	pubUuidToNum.ClearRestarted()

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Get AppInstanceConfig from zedagent
	subAppInstanceConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "zedagent",
		MyAgentName:    agentName,
		TopicImpl:      types.AppInstanceConfig{},
		Activate:       false,
		Ctx:            &ctx,
		CreateHandler:  handleCreate,
		ModifyHandler:  handleModify,
		DeleteHandler:  handleAppInstanceConfigDelete,
		RestartHandler: handleConfigRestart,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppInstanceConfig = subAppInstanceConfig
	subAppInstanceConfig.Activate()

	// Look for VolumeRefStatus from volumemgr
	subVolumeRefStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		AgentScope:    types.AppImgObj,
		TopicImpl:     types.VolumeRefStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleVolumeRefStatusCreate,
		ModifyHandler: handleVolumeRefStatusModify,
		DeleteHandler: handleVolumeRefStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVolumeRefStatus = subVolumeRefStatus
	subVolumeRefStatus.Activate()

	// Get AppNetworkStatus from zedrouter
	subAppNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "zedrouter",
		MyAgentName:    agentName,
		TopicImpl:      types.AppNetworkStatus{},
		Activate:       false,
		Ctx:            &ctx,
		CreateHandler:  handleAppNetworkStatusCreate,
		ModifyHandler:  handleAppNetworkStatusModify,
		DeleteHandler:  handleAppNetworkStatusDelete,
		RestartHandler: handleZedrouterRestarted,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppNetworkStatus = subAppNetworkStatus
	subAppNetworkStatus.Activate()

	// Get DomainStatus from domainmgr
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.DomainStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleDomainStatusCreate,
		ModifyHandler: handleDomainStatusModify,
		DeleteHandler: handleDomainStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	subHostMemory, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.HostMemory{},
		Activate:      true,
		Ctx:           &ctx,
		CreateHandler: handleHostMemoryCreate,
		ModifyHandler: handleHostMemoryModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subHostMemory = subHostMemory

	// subscribe to zedagent status events
	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleZedAgentStatusCreate,
		ModifyHandler: handleZedAgentStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	// subscribe to zedmanager(myself) to get AppInstancestatus events
	subAppInstanceStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedmanager",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleAppInstanceStatusCreate,
		ModifyHandler: handleAppInstanceStatusModify,
		DeleteHandler: handleAppInstanceStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppInstanceStatus = subAppInstanceStatus
	subAppInstanceStatus.Activate()

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}

	//use timer for free resource checker to run it after stabilising of other changes
	freeResourceChecker := flextimer.NewRangeTicker(5*time.Second, 10*time.Second)

	// The ticker that triggers a check for the applications in the START_DELAYED state
	delayedStartTicker := time.NewTicker(1 * time.Second)

	log.Functionf("Handling all inputs")
	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subVolumeRefStatus.MsgChan():
			subVolumeRefStatus.ProcessChange(change)

		case change := <-subAppNetworkStatus.MsgChan():
			subAppNetworkStatus.ProcessChange(change)

		case change := <-subDomainStatus.MsgChan():
			subDomainStatus.ProcessChange(change)

		case change := <-subHostMemory.MsgChan():
			subHostMemory.ProcessChange(change)

		case change := <-subAppInstanceConfig.MsgChan():
			subAppInstanceConfig.ProcessChange(change)

		case change := <-subZedAgentStatus.MsgChan():
			subZedAgentStatus.ProcessChange(change)

		case change := <-subAppInstanceStatus.MsgChan():
			subAppInstanceStatus.ProcessChange(change)

		case <-freeResourceChecker.C:
			// Did any update above make more resources available for
			// other app instances?
			if ctx.checkFreedResources {
				start := time.Now()
				checkRetry(&ctx)
				ps.CheckMaxTimeTopic(agentName, "checkRetry", start,
					warningTime, errorTime)
				ctx.checkFreedResources = false
			}

		case <-delayedStartTicker.C:
			checkDelayedStartApps(&ctx)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func checkRetry(ctxPtr *zedmanagerContext) {
	log.Noticef("checkRetry")
	items := ctxPtr.pubAppInstanceStatus.GetAll()
	for _, st := range items {
		status := st.(types.AppInstanceStatus)
		if !status.MissingMemory {
			continue
		}
		config := lookupAppInstanceConfig(ctxPtr, status.Key())
		if config == nil {
			log.Noticef("checkRetry: %s waiting for memory but no config",
				status.Key())
			continue
		}
		if !status.IsErrorSource(types.AppInstanceConfig{}) {
			log.Noticef("checkRetry: %s waiting for memory but no error",
				status.Key())
			continue
		}
		status.ClearErrorWithSource()
		status.MissingMemory = false

		log.Noticef("checkRetry: %s waiting for memory", status.Key())
		handleModify(ctxPtr, status.Key(), *config, *config)
	}
}

// Handle the applications in the START_DELAY state ready to be started.
func checkDelayedStartApps(ctx *zedmanagerContext) {
	configs := ctx.subAppInstanceConfig.GetAll()
	for _, c := range configs {
		config := c.(types.AppInstanceConfig)
		status := lookupAppInstanceStatus(ctx, config.Key())
		// Is the application in the delayed state and ready to be started?
		if status != nil && status.State == types.START_DELAYED && status.StartTime.Before(time.Now()) {
			// Change the state immediately, so we do not enter here twice
			status.State = types.INSTALLED
			doUpdate(ctx, config, status)
			publishAppInstanceStatus(ctx, status)
		}
	}
}

// After zedagent has waited for its config and set restarted for
// AppInstanceConfig (which triggers this callback) we propagate a sequence of
// restarts so that the agents don't do extra work.
// We propagate a sequence of restarted from the zedmanager config
// to identitymgr, then from identitymgr to zedrouter,
// and finally from zedrouter to domainmgr.
// XXX is that sequence still needed with volumemgr in place?
// Need EIDs before zedrouter ...
func handleConfigRestart(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*zedmanagerContext)
	log.Functionf("handleConfigRestart(%d)", restartCounter)
	if restartCounter != 0 {
		ctx.pubAppNetworkConfig.SignalRestarted()
	}
}

func handleIdentitymgrRestarted(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Functionf("handleIdentitymgrRestarted(%d)", restartCounter)
	if restartCounter != 0 {
		ctx.pubAppNetworkConfig.SignalRestarted()
	}
}

func handleZedrouterRestarted(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Functionf("handleZedrouterRestarted(%d)", restartCounter)
	if restartCounter != 0 {
		ctx.pubDomainConfig.SignalRestarted()
	}
}

// handleAppInstanceStatusCreate - Handle AIS create. Publish AppStatusSummary to ledmanager
func handleAppInstanceStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	publishAppInstanceSummary(ctx)
}

// handleAppInstanceStatusModify - Handle AIS modify. Publish AppStatusSummary to ledmanager
func handleAppInstanceStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	publishAppInstanceSummary(ctx)
}

// handleAppInstanceStatusDelete - Handle AIS delete. Publish AppStatusSummary to ledmanager
func handleAppInstanceStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	publishAppInstanceSummary(ctx)
}

func publishAppInstanceSummary(ctxPtr *zedmanagerContext) {

	summary := types.AppInstanceSummary{
		TotalStarting: 0,
		TotalRunning:  0,
		TotalStopping: 0,
		TotalError:    0,
	}
	items := ctxPtr.pubAppInstanceStatus.GetAll()
	for _, st := range items {
		status := st.(types.AppInstanceStatus)
		effectiveActivate := false
		config := lookupAppInstanceConfig(ctxPtr, status.Key())
		if config != nil {
			effectiveActivate = effectiveActivateCurrentProfile(*config, ctxPtr.currentProfile)
		}
		// Only condition we did not count is EffectiveActive = true and Activated = false.
		// That means customer either halted his app or did not activate it yet.
		if effectiveActivate && status.Activated {
			summary.TotalRunning++
		} else if len(status.Error) > 0 {
			summary.TotalError++
		} else if status.Activated {
			summary.TotalStopping++
		} else if effectiveActivate {
			summary.TotalStarting++
		}

	}

	log.Functionf("publishAppInstanceSummary TotalStarting: %d TotalRunning: %d TotalStopping: %d TotalError: %d",
		summary.TotalStarting, summary.TotalRunning, summary.TotalStopping, summary.TotalError)

	pub := ctxPtr.pubAppInstanceSummary

	pub.Publish(summary.Key(), summary)
}

func publishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Tracef("publishAppInstanceStatus(%s)", key)
	pub := ctx.pubAppInstanceStatus
	pub.Publish(key, *status)
}

func unpublishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Tracef("unpublishAppInstanceStatus(%s)", key)
	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishAppInstanceStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleAppInstanceConfigDelete(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := lookupAppInstanceStatus(ctx, key)
	if status == nil {
		log.Functionf("handleAppInstanceConfigDelete: unknown %s", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Functionf("handleAppInstanceConfigDelete(%s) done", key)
}

// Callers must be careful to publish any changes to AppInstanceStatus
func lookupAppInstanceStatus(ctx *zedmanagerContext, key string) *types.AppInstanceStatus {

	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Tracef("lookupAppInstanceStatus(%s) not found", key)
		return nil
	}
	status := st.(types.AppInstanceStatus)
	return &status
}

func lookupAppInstanceConfig(ctx *zedmanagerContext, key string) *types.AppInstanceConfig {

	sub := ctx.subAppInstanceConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupAppInstanceConfig(%s) not found", key)
		return nil
	}
	config := c.(types.AppInstanceConfig)
	return &config
}

func handleCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	config := configArg.(types.AppInstanceConfig)

	log.Functionf("handleCreate(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	status := types.AppInstanceStatus{
		UUIDandVersion: config.UUIDandVersion,
		DisplayName:    config.DisplayName,
		FixedResources: config.FixedResources,
		State:          types.INITIAL,
	}

	// Calculate the moment when the application should start, taking into account the configured delay
	status.StartTime = ctx.delayBaseTime.Add(config.Delay)

	// Do we have a PurgeCmd counter from before the reboot?
	// Note that purgeCmdCounter is a sum of the remote and the local purge counter.
	persistedCounter, err := uuidtonum.UuidToNumGet(log, ctx.pubUuidToNum,
		config.UUIDandVersion.UUID, "purgeCmdCounter")
	configCounter := int(config.PurgeCmd.Counter + config.LocalPurgeCmd.Counter)
	if err == nil {
		if persistedCounter == configCounter {
			log.Functionf("handleCreate(%v) for %s found matching purge counter %d",
				config.UUIDandVersion, config.DisplayName, persistedCounter)
		} else {
			log.Warnf("handleCreate(%v) for %s found different purge counter %d vs. %d",
				config.UUIDandVersion, config.DisplayName, persistedCounter, configCounter)
			status.PurgeInprogress = types.DownloadAndVerify
			status.State = types.PURGING
			status.PurgeStartedAt = time.Now()
			// We persist the PurgeCmd Counter when
			// PurgeInprogress is done
		}
	} else {
		// Save this PurgeCmd.Counter as the baseline
		log.Functionf("handleCreate(%v) for %s saving purge counter %d",
			config.UUIDandVersion, config.DisplayName, configCounter)
		uuidtonum.UuidToNumAllocate(log, ctx.pubUuidToNum,
			config.UUIDandVersion.UUID, configCounter,
			true, "purgeCmdCounter")
	}

	status.VolumeRefStatusList = make([]types.VolumeRefStatus,
		len(config.VolumeRefConfigList))
	for i, vrc := range config.VolumeRefConfigList {
		vrs := &status.VolumeRefStatusList[i]
		vrs.VolumeID = vrc.VolumeID
		vrs.GenerationCounter = vrc.GenerationCounter
		vrs.LocalGenerationCounter = vrc.LocalGenerationCounter
		vrs.RefCount = vrc.RefCount
		vrs.MountDir = vrc.MountDir
		vrs.PendingAdd = true
		vrs.State = types.INITIAL
		vrs.VerifyOnly = true
	}

	allErrors := ""
	if len(config.Errors) > 0 {
		// Combine all errors from Config parsing state and send them in Status
		for i, errStr := range config.Errors {
			allErrors += errStr
			log.Errorf("App Instance %s-%s: Error(%d): %s",
				config.DisplayName, config.UUIDandVersion.UUID, i, errStr)
		}
		log.Errorf("App Instance %s-%s: Errors in App Instance Create.",
			config.DisplayName, config.UUIDandVersion.UUID)
	}

	// Do some basic sanity checks.
	if config.FixedResources.Memory == 0 {
		errStr := "Invalid Memory Size - 0\n"
		allErrors += errStr
	}
	if config.FixedResources.VCpus == 0 {
		errStr := "Invalid Cpu count - 0\n"
		allErrors += errStr
	}

	// if some error, return
	if allErrors != "" {
		log.Errorf("AppInstance(Name:%s, UUID:%s): Errors in App Instance "+
			"Create. Error: %s",
			config.DisplayName, config.UUIDandVersion.UUID, allErrors)
		status.SetErrorWithSource(allErrors, types.AppInstanceStatus{},
			time.Now())
		publishAppInstanceStatus(ctx, &status)
		return
	}

	// If there are no errors, go ahead with Instance creation.
	changed := doUpdate(ctx, config, &status)
	if changed {
		log.Functionf("AppInstance(Name:%s, UUID:%s): handleCreate status change.",
			config.DisplayName, config.UUIDandVersion.UUID)
		publishAppInstanceStatus(ctx, &status)
	}
	log.Functionf("handleCreate done for %s", config.DisplayName)
}

func handleModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	config := configArg.(types.AppInstanceConfig)
	oldConfig := oldConfigArg.(types.AppInstanceConfig)
	status := lookupAppInstanceStatus(ctx, key)
	log.Functionf("handleModify(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	status.StartTime = ctx.delayBaseTime.Add(config.Delay)

	effectiveActivate := effectiveActivateCurrentProfile(config, ctx.currentProfile)

	publishAppInstanceStatus(ctx, status)

	// We handle at least ACL and activate changes. XXX What else?
	// Not checking the version here; assume the microservices can handle
	// some updates.

	// We detect significant changes which require a reboot and/or
	// purge of disk changes, so we can generate errors if it is
	// not a PurgeCmd and RestartCmd, respectively
	// If we are purging then restart is redundant.
	needPurge, needRestart, purgeReason, restartReason := quantifyChanges(config, oldConfig, *status)
	if needPurge {
		needRestart = false
	}

	if config.RestartCmd.Counter != oldConfig.RestartCmd.Counter ||
		config.LocalRestartCmd.Counter != oldConfig.LocalRestartCmd.Counter {

		log.Functionf("handleModify(%v) for %s restartcmd from %d/%d to %d/%d "+
			"needRestart: %v",
			config.UUIDandVersion, config.DisplayName,
			oldConfig.RestartCmd.Counter, oldConfig.LocalRestartCmd.Counter,
			config.RestartCmd.Counter, config.LocalRestartCmd.Counter,
			needRestart)
		if effectiveActivate {
			// Will restart even if we crash/power cycle since that
			// would also restart the app. Hence we can update
			// the status counter here.
			status.RestartInprogress = types.BringDown
			status.State = types.RESTARTING
			status.RestartStartedAt = time.Now()
		} else {
			log.Functionf("handleModify(%v) for %s restartcmd ignored config !Activate",
				config.UUIDandVersion, config.DisplayName)
			oldConfig.RestartCmd.Counter = config.RestartCmd.Counter
			oldConfig.LocalRestartCmd.Counter = config.LocalRestartCmd.Counter
		}
	} else if needRestart {
		errStr := fmt.Sprintf("Need restart due to %s but not a restartCmd",
			restartReason)
		log.Errorf("handleModify(%s) failed: %s", status.Key(), errStr)
		status.SetError(errStr, time.Now())
		publishAppInstanceStatus(ctx, status)
		return
	}

	if config.PurgeCmd.Counter != oldConfig.PurgeCmd.Counter ||
		config.LocalPurgeCmd.Counter != oldConfig.LocalPurgeCmd.Counter {
		log.Functionf("handleModify(%v) for %s purgecmd from %d/%d to %d/%d "+
			"needPurge: %v",
			config.UUIDandVersion, config.DisplayName,
			oldConfig.PurgeCmd.Counter, oldConfig.LocalPurgeCmd.Counter,
			config.PurgeCmd.Counter, config.LocalPurgeCmd.Counter,
			needPurge)
		if status.IsErrorSource(types.AppInstanceStatus{}) {
			log.Functionf("Removing error %s", status.Error)
			status.ClearErrorWithSource()
		}
		status.PurgeInprogress = types.DownloadAndVerify
		status.State = types.PURGING
		status.PurgeStartedAt = time.Now()
		// We persist the PurgeCmd Counter when PurgeInprogress is done
	} else if needPurge {
		errStr := fmt.Sprintf("Need purge due to %s but not a purgeCmd",
			purgeReason)
		log.Errorf("handleModify(%s) failed: %s", status.Key(), errStr)
		status.SetError(errStr, time.Now())
		publishAppInstanceStatus(ctx, status)
		return
	}

	status.UUIDandVersion = config.UUIDandVersion
	publishAppInstanceStatus(ctx, status)

	changed := doUpdate(ctx, config, status)
	if changed {
		log.Functionf("handleModify status change for %s", status.Key())
		publishAppInstanceStatus(ctx, status)
	}
	publishAppInstanceStatus(ctx, status)
	log.Functionf("handleModify done for %s", config.DisplayName)
}

func handleDelete(ctx *zedmanagerContext, key string,
	status *types.AppInstanceStatus) {

	log.Functionf("handleDelete(%v) for %s",
		status.UUIDandVersion, status.DisplayName)

	removeAIStatus(ctx, status)
	// Remove the recorded PurgeCmd Counter
	uuidtonum.UuidToNumDelete(log, ctx.pubUuidToNum, status.UUIDandVersion.UUID)
	log.Functionf("handleDelete done for %s", status.DisplayName)
}

// Returns needRestart, needPurge, plus a string for each.
// If there is a change to the disks, adapters, or network interfaces
// it returns needPurge.
// If there is a change to the CPU etc resources it returns needRestart
// Changes to ACLs don't result in either being returned.
func quantifyChanges(config types.AppInstanceConfig, oldConfig types.AppInstanceConfig,
	status types.AppInstanceStatus) (bool, bool, string, string) {

	needPurge := false
	needRestart := false
	var purgeReason, restartReason string
	log.Functionf("quantifyChanges for %s %s",
		config.Key(), config.DisplayName)
	if len(oldConfig.VolumeRefConfigList) != len(config.VolumeRefConfigList) {
		str := fmt.Sprintf("number of volume ref changed from %d to %d",
			len(oldConfig.VolumeRefConfigList),
			len(config.VolumeRefConfigList))
		log.Functionf(str)
		needPurge = true
		purgeReason += str + "\n"
	} else {
		for _, vrc := range config.VolumeRefConfigList {
			vrs := getVolumeRefStatusFromAIStatus(&status, vrc)
			if vrs == nil {
				str := fmt.Sprintf("Missing VolumeRefStatus for "+
					"(VolumeID: %s, GenerationCounter: %d, LocalGenerationCounter: %d)",
					vrc.VolumeID, vrc.GenerationCounter, vrc.LocalGenerationCounter)
				log.Errorf(str)
				needPurge = true
				purgeReason += str + "\n"
				continue
			}
		}
	}
	if len(oldConfig.UnderlayNetworkList) != len(config.UnderlayNetworkList) {
		str := fmt.Sprintf("number of underlay interfaces changed from %d to %d",
			len(oldConfig.UnderlayNetworkList),
			len(config.UnderlayNetworkList))
		log.Functionf(str)
		needPurge = true
		purgeReason += str + "\n"
	} else {
		for i, uc := range config.UnderlayNetworkList {
			old := oldConfig.UnderlayNetworkList[i]
			if old.AppMacAddr.String() != uc.AppMacAddr.String() {
				str := fmt.Sprintf("AppMacAddr changed from %v to %v",
					old.AppMacAddr, uc.AppMacAddr)
				log.Functionf(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if !old.AppIPAddr.Equal(uc.AppIPAddr) {
				str := fmt.Sprintf("AppIPAddr changed from %v to %v",
					old.AppIPAddr, uc.AppIPAddr)
				log.Functionf(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if old.Network != uc.Network {
				str := fmt.Sprintf("Network changed from %v to %v",
					old.Network, uc.Network)
				log.Functionf(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if !cmp.Equal(old.ACLs, uc.ACLs) {
				log.Functionf("FYI ACLs changed: %v",
					cmp.Diff(old.ACLs, uc.ACLs))
			}
		}
	}
	if !cmp.Equal(config.IoAdapterList, oldConfig.IoAdapterList) {
		str := fmt.Sprintf("IoAdapterList changed: %v",
			cmp.Diff(oldConfig.IoAdapterList, config.IoAdapterList))
		log.Functionf(str)
		needPurge = true
		purgeReason += str + "\n"
	}
	if !cmp.Equal(config.FixedResources, oldConfig.FixedResources) {
		str := fmt.Sprintf("FixedResources changed: %v",
			cmp.Diff(oldConfig.FixedResources, config.FixedResources))
		log.Functionf(str)
		needRestart = true
		restartReason += str + "\n"
	}
	log.Functionf("quantifyChanges for %s %s returns %v, %v",
		config.Key(), config.DisplayName, needPurge, needRestart)
	return needPurge, needRestart, purgeReason, restartReason
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

	ctx := ctxArg.(*zedmanagerContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	if gcp != nil {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

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
	ctxPtr := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.ZedAgentStatus)
	// When getting the config successfully for the first time (get from the controller or read from the file), consider
	// the device as ready to start apps. Hence, count the app delay timeout from now.
	if status.ConfigGetStatus == types.ConfigGetSuccess || status.ConfigGetStatus == types.ConfigGetReadSaved {
		if ctxPtr.delayBaseTime.IsZero() {
			ctxPtr.delayBaseTime = time.Now()
		}
	}

	if ctxPtr.currentProfile != status.CurrentProfile {
		log.Noticef("handleZedAgentStatusImpl: CurrentProfile changed from %s to %s",
			ctxPtr.currentProfile, status.CurrentProfile)
		oldProfile := ctxPtr.currentProfile
		ctxPtr.currentProfile = status.CurrentProfile
		updateBasedOnProfile(ctxPtr, oldProfile)
	}
	log.Functionf("handleZedAgentStatusImpl(%s) done", key)
}

func handleHostMemoryCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleHostMemoryImpl(ctxArg, key, statusArg)
}

func handleHostMemoryModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleHostMemoryImpl(ctxArg, key, statusArg)
}

func handleHostMemoryImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctxPtr := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.HostMemory)
	if ctxPtr.currentTotalMemoryMB != 0 && status.TotalMemoryMB > ctxPtr.currentTotalMemoryMB {
		// re-check available resources again in case of TotalMemory changed from non-zero to larger values
		ctxPtr.checkFreedResources = true
	}
	if ctxPtr.currentTotalMemoryMB != status.TotalMemoryMB {
		ctxPtr.currentTotalMemoryMB = status.TotalMemoryMB
		log.Functionf("handleHostMemoryImpl(%s) currentTotalMemoryMB changed from %d to %d",
			key, ctxPtr.currentTotalMemoryMB, status.TotalMemoryMB)
	}
	log.Functionf("handleHostMemoryImpl(%s) done", key)
}

// updateBasedOnProfile check all app instances with ctx.currentProfile and oldProfile
// update AppInstance if change in effective activate detected
func updateBasedOnProfile(ctx *zedmanagerContext, oldProfile string) {
	pub := ctx.subAppInstanceConfig
	items := pub.GetAll()
	for _, c := range items {
		config := c.(types.AppInstanceConfig)
		effectiveActivate := effectiveActivateCurrentProfile(config, ctx.currentProfile)
		effectiveActivateOld := effectiveActivateCurrentProfile(config, oldProfile)
		if effectiveActivateOld == effectiveActivate {
			// no changes in effective activate
			continue
		}
		status := lookupAppInstanceStatus(ctx, config.Key())
		if status != nil {
			log.Functionf("updateBasedOnProfile: change activate state for %s from %t to %t",
				config.Key(), effectiveActivateOld, effectiveActivate)
			if doUpdate(ctx, config, status) {
				publishAppInstanceStatus(ctx, status)
			}
		}
	}
}

// returns effective Activate status based on Activate from app instance config and current profile
func effectiveActivateCurrentProfile(config types.AppInstanceConfig, currentProfile string) bool {
	if currentProfile == "" {
		log.Functionf("effectiveActivateCurrentProfile(%s): empty current", config.Key())
		// if currentProfile is empty set activate state from controller
		return config.Activate
	}
	if len(config.ProfileList) == 0 {
		log.Functionf("effectiveActivateCurrentProfile(%s): empty ProfileList", config.Key())
		//we have no profile in list so we should use activate state from the controller
		return config.Activate
	}
	for _, p := range config.ProfileList {
		if p == currentProfile {
			log.Functionf("effectiveActivateCurrentProfile(%s): profile form list (%s) match current (%s)",
				config.Key(), p, currentProfile)
			// pass config.Activate from controller if currentProfile is inside ProfileList
			return config.Activate
		}
	}
	log.Functionf("effectiveActivateCurrentProfile(%s): no match with current (%s)",
		config.Key(), currentProfile)
	return false
}
