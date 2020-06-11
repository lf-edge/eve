// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// baseosmgr orchestrates base os installation
// interfaces with zedagent for configuration update
// interfaces with volumemgr to get the images/blobs as volumes

package baseosmgr

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
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

type baseOsMgrContext struct {
	agentBaseContext agentbase.Context
	pubBaseOsStatus  pubsub.Publication
	pubVolumeConfig  pubsub.Publication
	pubZbootStatus   pubsub.Publication

	subBaseOsConfig    pubsub.Subscription
	subZbootConfig     pubsub.Subscription
	subVolumeStatus    pubsub.Subscription
	subNodeAgentStatus pubsub.Subscription
	rebootReason       string    // From last reboot
	rebootTime         time.Time // From last reboot
	rebootImage        string    // Image from which the last reboot happened
}

func newBaseOsMgrContext() *baseOsMgrContext {
	baseOsMgrContext := baseOsMgrContext{}
	baseOsMgrContext.agentBaseContext = agentbase.DefaultContext(agentName)
	// Once all the agents are converted, SubscribeToGlobalConfig would be set to true in agentbase.DefaultContext itself.
	baseOsMgrContext.agentBaseContext.AgentOptions.SubscribeToGlobalConfig = true
	return &baseOsMgrContext
}

func (ctxPtr *baseOsMgrContext) AgentBaseContext() *agentbase.Context {
	return &ctxPtr.agentBaseContext
}

func Run(ps *pubsub.PubSub) {
	ctxPtr := newBaseOsMgrContext()

	agentbase.Run(ps, ctxPtr)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	// initialize publishing handles
	initializeSelfPublishHandles(ps, ctxPtr)

	// initialize module specific subscriber handles
	initializeNodeAgentHandles(ps, ctxPtr)
	initializeZedagentHandles(ps, ctxPtr)
	initializeVolumemgrHandles(ps, ctxPtr)

	// publish zboot partition status
	publishZbootPartitionStatusAll(ctxPtr)

	// report other agents, about, zboot status availability
	ctxPtr.pubZbootStatus.SignalRestarted()

	// Pick up debug aka log level before we start real work
	for !ctxPtr.agentBaseContext.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-ctxPtr.agentBaseContext.SubGlobalConfig.MsgChan():
			ctxPtr.agentBaseContext.SubGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

	// start the forever loop for event handling
	for {
		select {
		case change := <-ctxPtr.agentBaseContext.SubGlobalConfig.MsgChan():
			ctxPtr.agentBaseContext.SubGlobalConfig.ProcessChange(change)

		case change := <-ctxPtr.subBaseOsConfig.MsgChan():
			ctxPtr.subBaseOsConfig.ProcessChange(change)

		case change := <-ctxPtr.subZbootConfig.MsgChan():
			ctxPtr.subZbootConfig.ProcessChange(change)

		case change := <-ctxPtr.subVolumeStatus.MsgChan():
			ctxPtr.subVolumeStatus.ProcessChange(change)

		case change := <-ctxPtr.subNodeAgentStatus.MsgChan():
			ctxPtr.subNodeAgentStatus.ProcessChange(change)

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
	return fmt.Sprintf("%s%s: %s", allErrors, prefix, lasterr)
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

	pubVolumeConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			AgentScope: types.BaseOsObj,
			TopicType:  types.OldVolumeConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumeConfig = pubVolumeConfig

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
	// Look for BaseOs VolumeStatus from volumemgr
	subVolumeStatus, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "volumemgr",
			AgentScope:    types.BaseOsObj,
			TopicImpl:     types.OldVolumeStatus{},
			Activate:      false,
			Ctx:           ctx,
			CreateHandler: handleVolumeStatusModify,
			ModifyHandler: handleVolumeStatusModify,
			DeleteHandler: handleVolumeStatusDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVolumeStatus = subVolumeStatus
	subVolumeStatus.Activate()
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
