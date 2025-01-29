// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

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

func handleNodeDrainStatusImpl(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	newStatus, ok := configArg.(kubeapi.NodeDrainStatus)
	if !ok {
		log.Errorf("handleNodeDrainStatusImpl invalid type in configArg: %v", configArg)
		return
	}

	if newStatus.RequestedBy != kubeapi.DEVICEOP {
		return
	}

	log.Functionf("handleNodeDrainStatusImpl to:%v", newStatus)
	if (newStatus.Status == kubeapi.FAILEDCORDON) ||
		(newStatus.Status == kubeapi.FAILEDDRAIN) {
		log.Errorf("handleNodeDrainStatusImpl nodedrain-step:drain-failed-handler unpublish request")
		ctx := ctxArg.(*zedagentContext)
		ctx.pubNodeDrainRequest.Unpublish("global")
	}

}

func handleNodeDrainStatusDelete(_ interface{}, _ string,
	_ interface{}) {
	log.Notice("handleNodeDrainStatusDelete")
}

func initNodeDrainPubSub(ctx *zedagentContext) {
	// Sub the Status
	subNodeDrainStatus, err := ctx.ps.NewSubscription(pubsub.SubscriptionOptions{
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
	subNodeDrainStatus.Activate()

	// Pub the request
	pubNodeDrainRequest, err := ctx.ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: kubeapi.NodeDrainRequest{},
		})
	if err != nil {
		log.Fatalf("initNodeDrainPubSub pubNodeDrainRequest err:%v", err)
		return
	}
	ctx.subNodeDrainStatus = subNodeDrainStatus
	ctx.pubNodeDrainRequest = pubNodeDrainRequest
}

func shouldDeferForNodeDrain(ctx *zedagentContext, op types.DeviceOperation) bool {
	drainStatus := kubeapi.GetNodeDrainStatus(ctx.subNodeDrainStatus, log)
	switch drainStatus.Status {
	case kubeapi.UNKNOWN:
		log.Error("scheduleDeviceOperation EARLY boot request, zedkube not up yet")
		return false
	case kubeapi.NOTSUPPORTED:
		log.Function("scheduleDeviceOperation drain not supported, skipping")
		return false
	case kubeapi.NOTREQUESTED:
		fallthrough
	case kubeapi.FAILEDCORDON:
		fallthrough
	case kubeapi.FAILEDDRAIN:
		err := kubeapi.RequestNodeDrain(ctx.pubNodeDrainRequest, kubeapi.DEVICEOP, op.String())
		if err != nil {
			log.Errorf("scheduleDeviceOperation: can't request node drain: %v", err)
		}
		// Wait until drained
		log.Notice("scheduleDeviceOperation drain requested defer")
		return true
	case kubeapi.REQUESTED:
		fallthrough
	case kubeapi.STARTING:
		fallthrough
	case kubeapi.DRAINRETRYING:
		// Wait until drained
		log.Function("scheduleDeviceOperation drain in-progress still defer")
		return true
	case kubeapi.COMPLETE:
		//Finally...
		log.Notice("scheduleDeviceOperation drain complete, goodbye")
		return false
	}
	return false
}
