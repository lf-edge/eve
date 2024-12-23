// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleNodeDrainStatusCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleNodeDrainStatusImpl(ctxArg, key, configArg, nil)
}

func handleNodeDrainStatusModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleNodeDrainStatusImpl(ctxArg, key, configArg, oldConfigArg)
}

func handleNodeDrainStatusImpl(ctxArg interface{}, _ string,
	configArg interface{}, _ interface{}) {
	newStatus, ok := configArg.(kubeapi.NodeDrainStatus)
	if !ok {
		log.Errorf("handleNodeDrainStatusImpl invalid type in configArg: %v", configArg)
		return
	}
	ctx, ok := ctxArg.(*baseOsMgrContext)
	if !ok {
		log.Errorf("handleNodeDrainStatusImpl invalid type in ctxArg: %v", ctxArg)
		return
	}

	if newStatus.RequestedBy != kubeapi.UPDATE {
		return
	}

	log.Functionf("handleNodeDrainStatusImpl to:%v", newStatus)
	if (newStatus.Status == kubeapi.FAILEDCORDON) ||
		(newStatus.Status == kubeapi.FAILEDDRAIN) {
		log.Errorf("handleNodeDrainStatusImpl nodedrain-step:drain-failed-handler unpublish NodeDrainRequest due to NodeDrainStatus:%v", newStatus)
		if err := ctx.pubNodeDrainRequest.Unpublish("global"); err != nil {
			log.Errorf("Unable to remove NodeDrainRequest object:%v", err)
		}
	}
	if newStatus.Status == kubeapi.COMPLETE {
		id := ctx.deferredBaseOsID
		if id != "" {
			log.Noticef("handleNodeDrainStatusImpl nodedrain-step:drain-complete-handler, continuing baseosstatus update id:%s", id)
			baseOsHandleStatusUpdateUUID(ctx, id)
		}
	}
}

func handleNodeDrainStatusDelete(_ interface{}, _ string,
	_ interface{}) {
	log.Function("handleNodeDrainStatusDelete")
}

func initializeNodeDrainHandles(ps *pubsub.PubSub, ctx *baseOsMgrContext) {
	subNodeDrainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedkube",
		MyAgentName:   agentName,
		TopicImpl:     kubeapi.NodeDrainStatus{},
		Persistent:    false,
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleNodeDrainStatusCreate,
		ModifyHandler: handleNodeDrainStatusModify,
		DeleteHandler: handleNodeDrainStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatalf("initNodeDrainPubSub subNodeDrainStatus err:%v", err)
		return
	}
	if err := subNodeDrainStatus.Activate(); err != nil {
		log.Fatalf("initNodeDrainPubSub can't activate sub:%v", err)
	}

	pubNodeDrainRequest, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: kubeapi.NodeDrainRequest{},
		})
	if err != nil {
		log.Fatalf("initNodeDrainPubSub pubNodeDrainRequest err:%v", err)
	}
	ctx.subNodeDrainStatus = subNodeDrainStatus
	ctx.pubNodeDrainRequest = pubNodeDrainRequest
}

// shouldDeferForNodeDrain will return true if this BaseOsStatus update will be handled later
func shouldDeferForNodeDrain(ctx *baseOsMgrContext, id string, config *types.BaseOsConfig, status *types.BaseOsStatus) bool {
	drainStatus := kubeapi.GetNodeDrainStatus(ctx.subNodeDrainStatus, log)
	if drainStatus.Status == kubeapi.NOTSUPPORTED {
		return false
	}
	if drainStatus.Status == kubeapi.UNKNOWN {
		log.Error("shouldDeferForNodeDrain EARLY boot request, zedkube not up yet")
		return false
	}

	log.Noticef("shouldDeferForNodeDrain drainCheck id:%s state:%d baseOsConfig:%v baseOsStatus:%v drainStatus:%d",
		id, status.State, config, status, drainStatus.Status)
	// To allow switching baseos version mid-drain, keep this general to all
	// cases of: restarting-failed-drain, starting-fresh-drain
	ctx.deferredBaseOsID = id

	if drainStatus.Status == kubeapi.NOTREQUESTED ||
		drainStatus.Status == kubeapi.FAILEDCORDON ||
		drainStatus.Status == kubeapi.FAILEDDRAIN {
		log.Noticef("shouldDeferForNodeDrain nodedrain-step:request requester:eve-os-update ctx:%s", id)
		err := kubeapi.RequestNodeDrain(ctx.pubNodeDrainRequest, kubeapi.UPDATE, id)
		if err != nil {
			log.Errorf("shouldDeferForNodeDrain: can't request node drain: %v", err)
		}
		return true
	}
	if drainStatus.Status == kubeapi.REQUESTED ||
		drainStatus.Status == kubeapi.STARTING ||
		drainStatus.Status == kubeapi.CORDONED ||
		drainStatus.Status == kubeapi.DRAINRETRYING {
		log.Functionf("shouldDeferForNodeDrain drain in-progress or in error, still defer")
		return true
	}

	if drainStatus.Status != kubeapi.COMPLETE {
		log.Errorf("shouldDeferForNodeDrain unhanded NodeDrainStatus:%v", drainStatus)
	}

	log.Noticef("shouldDeferForNodeDrain nodedrain-step:handle-complete requester:eve-os-update ctx:%s", id)
	return false
}
