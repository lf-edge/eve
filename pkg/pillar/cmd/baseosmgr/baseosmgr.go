// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// baseosmgr orchestrates base os installation
// interfaces with zedagent for configuration update
// interfaces with volumemgr to get the images/blobs as volumes

package baseosmgr

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

const (
	agentName      = "baseosmgr"
	partitionCount = 2
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Set from Makefile
var Version = "No version specified"

type baseOsMgrContext struct {
	pubBaseOsStatus pubsub.Publication
	pubContentTreeConfig pubsub.Publication
	pubZbootStatus  pubsub.Publication

	subGlobalConfig    pubsub.Subscription
	globalConfig       *types.ConfigItemValueMap
	GCInitialized      bool
	subBaseOsConfig    pubsub.Subscription
	subZbootConfig     pubsub.Subscription
	subContentTreeStatus    pubsub.Subscription
	subNodeAgentStatus pubsub.Subscription
	rebootReason       string    // From last reboot
	rebootTime         time.Time // From last reboot
	rebootImage        string    // Image from which the last reboot happened
}

var debug = false
var debugOverride bool // From command line arg

func Run(ps *pubsub.PubSub) {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
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
	agentlog.Init(agentName)
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	log.Infof("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	// Context to pass around
	ctx := baseOsMgrContext{
		globalConfig: types.DefaultConfigItemValueMap(),
	}

	// initialize publishing handles
	initializeSelfPublishHandles(ps, &ctx)

	// initialize module specific subscriber handles
	initializeGlobalConfigHandles(ps, &ctx)
	initializeNodeAgentHandles(ps, &ctx)
	initializeZedagentHandles(ps, &ctx)
	initializeVolumemgrHandles(ps, &ctx)

	// publish zboot partition status
	publishZbootPartitionStatusAll(&ctx)

	// report other agents, about, zboot status availability
	ctx.pubZbootStatus.SignalRestarted()

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

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

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleBaseOsConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleBaseOsConfigDelete(%s)", key)
	ctx := ctxArg.(*baseOsMgrContext)
	status := lookupBaseOsStatus(ctx, key)
	if status == nil {
		log.Infof("handleBaseOsConfigDelete: unknown %s", key)
		return
	}
	handleBaseOsDelete(ctx, key, status)
	log.Infof("handleBaseOsConfigDelete(%s) done", key)
}

// base os config modify event
func handleBaseOsCreate(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("handleBaseOsCreate(%s)", key)
	ctx := ctxArg.(*baseOsMgrContext)
	config := configArg.(types.BaseOsConfig)
	status := types.BaseOsStatus{
		UUIDandVersion: config.UUIDandVersion,
		BaseOsVersion:  config.BaseOsVersion,
		ConfigSha256:   config.ConfigSha256,
	}

	status.StorageStatusList = make([]types.StorageStatus,
		len(config.StorageConfigList))

	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		ss.UpdateFromStorageConfig(sc)
	}
	// Check image count
	err := validateBaseOsConfig(ctx, config)
	if err != nil {
		log.Error(err)
		status.SetErrorNow(err.Error())
		publishBaseOsStatus(ctx, &status)
		return
	}
	publishBaseOsStatus(ctx, &status)
	baseOsHandleStatusUpdate(ctx, &config, &status)
}

func handleBaseOsModify(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("handleBaseOsModify(%s)", key)
	ctx := ctxArg.(*baseOsMgrContext)
	config := configArg.(types.BaseOsConfig)
	status := lookupBaseOsStatus(ctx, key)
	if status == nil {
		log.Errorf("handleBaseOsModify status not found, ignored %+v", key)
		return
	}

	log.Infof("handleBaseOsModify(%s) for %s Activate %v",
		config.Key(), config.BaseOsVersion, config.Activate)

	// Check image count
	err := validateBaseOsConfig(ctx, config)
	if err != nil {
		log.Error(err)
		status.SetErrorNow(err.Error())
		publishBaseOsStatus(ctx, status)
		return
	}

	// update the version field, uuids being the same
	status.UUIDandVersion = config.UUIDandVersion
	publishBaseOsStatus(ctx, status)
	baseOsHandleStatusUpdate(ctx, &config, status)
}

// base os config delete event
func handleBaseOsDelete(ctx *baseOsMgrContext, key string,
	status *types.BaseOsStatus) {

	log.Infof("handleBaseOsDelete for %s", status.BaseOsVersion)
	removeBaseOsConfig(ctx, status.Key())
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

// This handles both the create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*baseOsMgrContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*baseOsMgrContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Infof("handleGlobalConfigDelete done for %s", key)
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

	pubContentTreeConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			AgentScope: types.BaseOsObj,
			TopicType:  types.ContentTreeConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubContentTreeConfig = pubContentTreeConfig

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
}

func initializeGlobalConfigHandles(ps *pubsub.PubSub, ctx *baseOsMgrContext) {

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "",
			TopicImpl:     types.ConfigItemValueMap{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleGlobalConfigModify,
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
			TopicImpl:     types.NodeAgentStatus{},
			Activate:      false,
			Ctx:           ctx,
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

	// Look for ZbootConfig, from nodeagent
	subZbootConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "nodeagent",
			TopicImpl:     types.ZbootConfig{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleZbootConfigModify,
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
			TopicImpl:     types.BaseOsConfig{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleBaseOsCreate,
			ModifyHandler: handleBaseOsModify,
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
			AgentScope:    types.BaseOsObj,
			TopicImpl:     types.ContentTreeStatus{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleContentTreeStatusModify,
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

// This handles both the create and modify events
func handleNodeAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*baseOsMgrContext)
	status := statusArg.(types.NodeAgentStatus)
	ctx.rebootTime = status.RebootTime
	ctx.rebootReason = status.RebootReason
	ctx.rebootImage = status.RebootImage
	updateBaseOsStatusOnReboot(ctx)
	log.Infof("handleNodeAgentStatusModify(%s) done", key)
}

func handleNodeAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	// do nothing
	log.Infof("handleNodeAgentStatusDelete(%s) done", key)
}

// This handles both the create and modify events
func handleZbootConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*baseOsMgrContext)
	config := configArg.(types.ZbootConfig)
	status := getZbootStatus(ctx, key)
	if status == nil {
		log.Infof("handleZbootConfigModify: unknown %s", key)
		return
	}
	log.Infof("handleZbootModify for %s TestComplete %v",
		config.Key(), config.TestComplete)

	if config.TestComplete != status.TestComplete {
		handleZbootTestComplete(ctx, config, *status)
	}

	log.Infof("handleZbootConfigModify(%s) done", key)
}

func handleZbootConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleZbootConfigDelete(%s)", key)
	ctx := ctxArg.(*baseOsMgrContext)
	status := getZbootStatus(ctx, key)
	if status == nil {
		log.Infof("handleZbootConfigDelete: unknown %s", key)
		return
	}
	// Nothing to do. We report ZbootStatus for the IMG* partitions
	// in any case
	log.Infof("handleZbootConfigDelete(%s) done", key)
}
