// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Get AppInstanceConfig from zedagent, drive config to VolumeMgr,
// IdentityMgr, and Zedrouter. Collect status from those services and make
// the combined AppInstanceStatus available to zedagent.

package zedmanager

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
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
	subAppInstanceConfig pubsub.Subscription
	pubAppInstanceStatus pubsub.Publication
	pubVolumeRefConfig   pubsub.Publication
	subVolumeRefStatus   pubsub.Subscription
	pubAppNetworkConfig  pubsub.Publication
	subAppNetworkStatus  pubsub.Subscription
	pubDomainConfig      pubsub.Publication
	subDomainStatus      pubsub.Subscription
	subGlobalConfig      pubsub.Subscription
	globalConfig         *types.ConfigItemValueMap
	pubUuidToNum         pubsub.Publication
	GCInitialized        bool
}

var debug = false
var debugOverride bool // From command line arg
var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
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

		case change := <-subAppInstanceConfig.MsgChan():
			subAppInstanceConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

// After zedagent has waited for its config and set restarted for
// AppInstanceConfig (which triggers this callback) we propagate a sequence of
// restarts so that the agents don't do extra work.
// We propagate a seqence of restarted from the zedmanager config
// to identitymgr, then from identitymgr to zedrouter,
// and finally from zedrouter to domainmgr.
// XXX is that sequence still needed with volumemgr in place?
// Need EIDs before zedrouter ...
func handleConfigRestart(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)
	log.Functionf("handleConfigRestart(%v)", done)
	if done {
		ctx.pubAppNetworkConfig.SignalRestarted()
	}
}

func handleIdentitymgrRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Functionf("handleIdentitymgrRestarted(%v)", done)
	if done {
		ctx.pubAppNetworkConfig.SignalRestarted()
	}
}

func handleZedrouterRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Functionf("handleZedrouterRestarted(%v)", done)
	if done {
		ctx.pubDomainConfig.SignalRestarted()
	}
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
		State:          types.INITIAL,
	}

	// Do we have a PurgeCmd counter from before the reboot?
	c, err := uuidtonum.UuidToNumGet(log, ctx.pubUuidToNum,
		config.UUIDandVersion.UUID, "purgeCmdCounter")
	if err == nil {
		if uint32(c) == config.PurgeCmd.Counter {
			log.Functionf("handleCreate(%v) for %s found matching purge counter %d",
				config.UUIDandVersion, config.DisplayName, c)
		} else {
			log.Warnf("handleCreate(%v) for %s found different purge counter %d vs. %d",
				config.UUIDandVersion, config.DisplayName, c,
				config.PurgeCmd.Counter)
			status.PurgeInprogress = types.RecreateVolumes
			status.State = types.PURGING
			// We persist the PurgeCmd Counter when
			// PurgeInprogress is done
		}
	} else {
		// Save this PurgeCmd.Counter as the baseline
		log.Functionf("handleCreate(%v) for %s saving purge counter %d",
			config.UUIDandVersion, config.DisplayName,
			config.PurgeCmd.Counter)
		uuidtonum.UuidToNumAllocate(log, ctx.pubUuidToNum,
			config.UUIDandVersion.UUID, int(config.PurgeCmd.Counter),
			true, "purgeCmdCounter")
	}

	status.VolumeRefStatusList = make([]types.VolumeRefStatus,
		len(config.VolumeRefConfigList))
	for i, vrc := range config.VolumeRefConfigList {
		vrs := &status.VolumeRefStatusList[i]
		vrs.VolumeID = vrc.VolumeID
		vrs.GenerationCounter = vrc.GenerationCounter
		vrs.RefCount = vrc.RefCount
		vrs.MountDir = vrc.MountDir
		vrs.PendingAdd = true
		vrs.State = types.INITIAL
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

	if config.RestartCmd.Counter != oldConfig.RestartCmd.Counter {

		log.Functionf("handleModify(%v) for %s restartcmd from %d to %d "+
			"needRestart: %v",
			config.UUIDandVersion, config.DisplayName,
			oldConfig.RestartCmd.Counter, config.RestartCmd.Counter,
			needRestart)
		if config.Activate {
			// Will restart even if we crash/power cycle since that
			// would also restart the app. Hence we can update
			// the status counter here.
			status.RestartInprogress = types.BringDown
			status.State = types.RESTARTING
		} else {
			log.Functionf("handleModify(%v) for %s restartcmd ignored config !Activate",
				config.UUIDandVersion, config.DisplayName)
			oldConfig.RestartCmd.Counter = config.RestartCmd.Counter
		}
	} else if needRestart {
		errStr := fmt.Sprintf("Need restart due to %s but not a restartCmd",
			restartReason)
		log.Errorf("handleModify(%s) failed: %s", status.Key(), errStr)
		status.SetError(errStr, time.Now())
		publishAppInstanceStatus(ctx, status)
		return
	}

	if config.PurgeCmd.Counter != oldConfig.PurgeCmd.Counter {
		log.Functionf("handleModify(%v) for %s purgecmd from %d to %d "+
			"needPurge: %v",
			config.UUIDandVersion, config.DisplayName,
			oldConfig.PurgeCmd.Counter, config.PurgeCmd.Counter,
			needPurge)
		if status.IsErrorSource(types.AppInstanceStatus{}) {
			log.Functionf("Removing error %s", status.Error)
			status.ClearErrorWithSource()
		}
		status.PurgeInprogress = types.RecreateVolumes
		status.State = types.PURGING
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
				str := fmt.Sprintf("Missing VolumeRefStatus for (VolumeID: %s, GenerationCounter: %d)",
					vrc.VolumeID, vrc.GenerationCounter)
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
