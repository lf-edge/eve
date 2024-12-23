// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
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
	ctx, ok := ctxArg.(*nodeagentContext)
	if !ok {
		log.Errorf("handleNodeDrainStatusImpl invalid type in ctxArg:%v", ctxArg)
	}
	newStatus, ok := configArg.(kubeapi.NodeDrainStatus)
	if !ok {
		log.Errorf("handleNodeDrainStatusImpl invalid type in configArg:%v", configArg)
	}

	if newStatus.RequestedBy != kubeapi.DEVICEOP {
		return
	}

	log.Noticef("handleNodeDrainStatusImpl to:%v", newStatus)
	// NodeDrainStatus Failures here should keep drainInProgress set.
	//      As this will set DrainInProgress on NodeAgentStatus and keep zedagent from allowing
	//  the deferred operation to continue.
	if (newStatus.Status >= kubeapi.REQUESTED) && (newStatus.Status < kubeapi.COMPLETE) {
		log.Noticef("handleNodeDrainStatusImpl nodedrain-step:drain-inprogress-handler NodeDrainStatus:%v", newStatus)
		ctx.waitDrainInProgress = true
		publishNodeAgentStatus(ctx)
	}
	if newStatus.Status == kubeapi.COMPLETE {
		log.Notice("handleNodeDrainStatusImpl nodedrain-step:drain-complete-handler notify zedagent")
		ctx.waitDrainInProgress = false
		publishNodeAgentStatus(ctx)
	}
}

func handleNodeDrainStatusDelete(_ interface{}, _ string,
	_ interface{}) {
	log.Functionf("handleNodeDrainStatusDelete")
}

func initNodeDrainPubSub(ps *pubsub.PubSub, ctx *nodeagentContext) {
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
		log.Fatalf("initNodeDrainPubSub activate err:%v", err)
	}
	ctx.subNodeDrainStatus = subNodeDrainStatus
}
