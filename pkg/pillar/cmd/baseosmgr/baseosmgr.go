// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// baseosmgr orchestrates base os installation
// interfaces with zedagent for configuration update
// interfaces with volumemgr to get the images/blobs as volumes

package baseosmgr

import (
	"flag"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	"github.com/sirupsen/logrus"
)

const (
	agentName      = "baseosmgr"
	partitionCount = 2
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	// last value of baseOsMgrContext.currentUpdateRetry for persistence
	currentRetryUpdateCounterFile = types.PersistStatusDir + "/current_retry_update_counter"
	// last value of baseOsMgrContext.configUpdateRetry for persistence
	configRetryUpdateCounterFile = types.PersistStatusDir + "/config_retry_update_counter"
)

// Set from Makefile
var Version = "No version specified"

type baseOsMgrContext struct {
	agentbase.AgentBase
	pubBaseOsStatus    pubsub.Publication
	pubZbootStatus     pubsub.Publication
	pubBaseOsMgrStatus pubsub.Publication

	subGlobalConfig      pubsub.Subscription
	globalConfig         *types.ConfigItemValueMap
	GCInitialized        bool
	subBaseOsConfig      pubsub.Subscription
	subZbootConfig       pubsub.Subscription
	subContentTreeStatus pubsub.Subscription
	subNodeAgentStatus   pubsub.Subscription
	subZedAgentStatus    pubsub.Subscription
	rebootReason         string    // From last reboot
	rebootTime           time.Time // From last reboot
	rebootImage          string    // Image from which the last reboot happened
	currentUpdateRetry   uint32    // UpdateRetryCounter from last retry; it will be sent for info
	configUpdateRetry    uint32    // UpdateRetryCounter from config; to avoid loop after reboot with failed testing

	worker worker.Worker // For background work
	// cli options
	versionPtr *bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctxPtr *baseOsMgrContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctxPtr.versionPtr = flagSet.Bool("v", false, "Version")
}

var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	// Context to pass around
	ctx := baseOsMgrContext{
		globalConfig: types.DefaultConfigItemValueMap(),
	}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithArguments(arguments))

	if *ctx.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait until we have been onboarded aka know our own UUID, but we don't use the UUID
	err := wait.WaitForOnboarded(ps, log, agentName, warningTime, errorTime)
	if err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed onboarded")

	// initialize publishing handles
	initializeSelfPublishHandles(ps, &ctx)

	// load saved values or fill with 0
	ctx.currentUpdateRetry = readSavedCurrentRetryUpdateCounter()
	ctx.configUpdateRetry = readSavedConfigRetryUpdateCounter()
	publishBaseOSMgrStatus(&ctx)

	// initialize module specific subscriber handles
	initializeGlobalConfigHandles(ps, &ctx)
	initializeNodeAgentHandles(ps, &ctx)
	initializeZedagentHandles(ps, &ctx)
	initializeVolumemgrHandles(ps, &ctx)

	// publish initial zboot partition status
	updateAndPublishZbootStatusAll(&ctx)

	ctx.worker = worker.NewPool(log, &ctx, 20, map[string]worker.Handler{
		workInstall: {Request: installWorker, Response: processInstallWorkResult},
	})

	// report other agents, about, zboot status availability
	ctx.pubZbootStatus.SignalRestarted()

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	if err := wait.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed Vault Status")

	if err := wait.WaitForUserContainerd(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("user containerd ready")

	// start the forever loop for event handling
	for {
		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)

		case change := <-ctx.subBaseOsConfig.MsgChan():
			ctx.subBaseOsConfig.ProcessChange(change)

		case change := <-ctx.subZbootConfig.MsgChan():
			ctx.subZbootConfig.ProcessChange(change)

		case change := <-ctx.subContentTreeStatus.MsgChan():
			ctx.subContentTreeStatus.ProcessChange(change)

		case change := <-ctx.subNodeAgentStatus.MsgChan():
			ctx.subNodeAgentStatus.ProcessChange(change)

		case change := <-ctx.subZedAgentStatus.MsgChan():
			ctx.subZedAgentStatus.ProcessChange(change)

		case res := <-ctx.worker.MsgChan():
			res.Process(&ctx, true)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleBaseOsConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleBaseOsConfigDelete(%s)", key)
	ctx := ctxArg.(*baseOsMgrContext)
	status := lookupBaseOsStatus(ctx, key)
	if status == nil {
		log.Functionf("handleBaseOsConfigDelete: unknown %s", key)
		return
	}
	handleBaseOsConfigDeleteByStatus(ctx, key, status)
	log.Functionf("handleBaseOsConfigDelete(%s) done", key)
}

// base os config modify event
func handleBaseOsConfigCreate(ctxArg interface{}, key string, configArg interface{}) {

	log.Functionf("handleBaseOsConfigCreate(%s)", key)
	ctx := ctxArg.(*baseOsMgrContext)
	config := configArg.(types.BaseOsConfig)
	status := types.BaseOsStatus{
		BaseOsVersion:   config.BaseOsVersion,
		ContentTreeUUID: config.ContentTreeUUID,
	}

	// Check content tree provided
	err := validateBaseOsConfig(ctx, config)
	if err != nil {
		log.Error(err)
		status.SetErrorNow(err.Error())
		publishBaseOsStatus(ctx, &status)
		return
	}
	publishBaseOsStatus(ctx, &status)
	baseOsHandleStatusUpdate(ctx, &config, &status)
	handleUpdateRetryCounter(ctx, config.RetryUpdateCounter)
}

func handleBaseOsConfigModify(ctxArg interface{}, key string, configArg interface{},
	oldConfigArg interface{}) {

	log.Functionf("handleBaseOsConfigModify(%s)", key)
	ctx := ctxArg.(*baseOsMgrContext)
	config := configArg.(types.BaseOsConfig)
	status := lookupBaseOsStatus(ctx, key)
	if status == nil {
		log.Errorf("handleBaseOsConfigModify status not found, ignored %+v", key)
		return
	}

	log.Functionf("handleBaseOsConfigModify(%s) Activate %v",
		config.Key(), config.Activate)

	// Check content tree provided
	err := validateBaseOsConfig(ctx, config)
	if err != nil {
		log.Error(err)
		status.SetErrorNow(err.Error())
		publishBaseOsStatus(ctx, status)
		return
	}

	publishBaseOsStatus(ctx, status)
	baseOsHandleStatusUpdate(ctx, &config, status)
	handleUpdateRetryCounter(ctx, config.RetryUpdateCounter)
}

// base os config delete event
func handleBaseOsConfigDeleteByStatus(ctx *baseOsMgrContext, key string,
	status *types.BaseOsStatus) {

	log.Functionf("handleBaseOsConfigDeleteByStatus for %s", status.BaseOsVersion)
	removeBaseOsConfig(ctx, status.Key())
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
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

	ctx := ctxArg.(*baseOsMgrContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*baseOsMgrContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

func initializeSelfPublishHandles(ps *pubsub.PubSub, ctx *baseOsMgrContext) {
	pubBaseOsStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.BaseOsStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsStatus.ClearRestarted()
	ctx.pubBaseOsStatus = pubBaseOsStatus

	pubZbootStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.ZbootStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubZbootStatus.ClearRestarted()
	ctx.pubZbootStatus = pubZbootStatus

	pubBaseOsMgrStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.BaseOSMgrStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsMgrStatus.ClearRestarted()
	ctx.pubBaseOsMgrStatus = pubBaseOsMgrStatus
}

func initializeGlobalConfigHandles(ps *pubsub.PubSub, ctx *baseOsMgrContext) {

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "zedagent",
			MyAgentName:   agentName,
			TopicImpl:     types.ConfigItemValueMap{},
			Persistent:    true,
			Activate:      false,
			Ctx:           ctx,
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
}

func initializeNodeAgentHandles(ps *pubsub.PubSub, ctx *baseOsMgrContext) {
	// Look for NodeAgentStatus, from zedagent
	subNodeAgentStatus, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "nodeagent",
			MyAgentName:   agentName,
			TopicImpl:     types.NodeAgentStatus{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleNodeAgentStatusCreate,
			ModifyHandler: handleNodeAgentStatusModify,
			DeleteHandler: handleNodeAgentStatusDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subNodeAgentStatus = subNodeAgentStatus
	subNodeAgentStatus.Activate()

	// subscribe to zedagent status events
	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleZedAgentStatusCreate,
		ModifyHandler: handleZedAgentStatusModify,
		DeleteHandler: handleZedAgentStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	// Look for ZbootConfig, from nodeagent
	subZbootConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "nodeagent",
			MyAgentName:   agentName,
			TopicImpl:     types.ZbootConfig{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleZbootConfigCreate,
			ModifyHandler: handleZbootConfigModify,
			DeleteHandler: handleZbootConfigDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subZbootConfig = subZbootConfig
	subZbootConfig.Activate()
}

func initializeZedagentHandles(ps *pubsub.PubSub, ctx *baseOsMgrContext) {
	// Look for BaseOsConfig , from zedagent
	subBaseOsConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "zedagent",
			MyAgentName:   agentName,
			TopicImpl:     types.BaseOsConfig{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleBaseOsConfigCreate,
			ModifyHandler: handleBaseOsConfigModify,
			DeleteHandler: handleBaseOsConfigDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()
}

func initializeVolumemgrHandles(ps *pubsub.PubSub, ctx *baseOsMgrContext) {
	// Look for BaseOs OldVolumeStatus from volumemgr
	subContentTreeStatus, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "volumemgr",
			MyAgentName:   agentName,
			TopicImpl:     types.ContentTreeStatus{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleContentTreeStatusCreate,
			ModifyHandler: handleContentTreeStatusModify,
			DeleteHandler: handleContentTreeStatusDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subContentTreeStatus = subContentTreeStatus
	subContentTreeStatus.Activate()
}

func handleNodeAgentStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleNodeAgentStatusImpl(ctxArg, key, statusArg)
}

func handleNodeAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleNodeAgentStatusImpl(ctxArg, key, statusArg)
}

func handleNodeAgentStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*baseOsMgrContext)
	status := statusArg.(types.NodeAgentStatus)
	ctx.rebootTime = status.RebootTime
	ctx.rebootReason = status.RebootReason
	ctx.rebootImage = status.RebootImage
	updateBaseOsStatusOnReboot(ctx)
	log.Functionf("handleNodeAgentStatusImpl(%s) done", key)
}

func handleNodeAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	// do nothing
	log.Functionf("handleNodeAgentStatusDelete(%s) done", key)
}

func handleZbootConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleZbootConfigImpl(ctxArg, key, configArg)
}

func handleZbootConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleZbootConfigImpl(ctxArg, key, configArg)
}

func handleZbootConfigImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*baseOsMgrContext)
	config := configArg.(types.ZbootConfig)
	status := getZbootStatus(ctx, key)
	if status == nil {
		log.Functionf("handleZbootConfigImpl: unknown %s", key)
		return
	}
	log.Functionf("handleZbootImpl for %s TestComplete %v",
		config.Key(), config.TestComplete)

	if config.TestComplete != status.TestComplete {
		handleZbootTestComplete(ctx, config, *status)
	}

	log.Functionf("handleZbootConfigImpl(%s) done", key)
}

func handleZbootConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleZbootConfigDelete(%s)", key)
	ctx := ctxArg.(*baseOsMgrContext)
	status := getZbootStatus(ctx, key)
	if status == nil {
		log.Functionf("handleZbootConfigDelete: unknown %s", key)
		return
	}
	// Nothing to do. We report ZbootStatus for the IMG* partitions
	// in any case
	log.Functionf("handleZbootConfigDelete(%s) done", key)
}

func publishBaseOSMgrStatus(ctx *baseOsMgrContext) {
	log.Function("publish BaseOSMgrStatus")
	ctx.pubBaseOsMgrStatus.Publish("global",
		types.BaseOSMgrStatus{
			CurrentRetryUpdateCounter: ctx.currentUpdateRetry,
		})
}
