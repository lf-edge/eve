// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

func initDrainSub(ps *pubsub.PubSub, ctx *diagContext) {
	subNodeDrainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedkube",
		MyAgentName:   agentName,
		TopicImpl:     kubeapi.NodeDrainStatus{},
		Persistent:    false,
		Activate:      true,
		Ctx:           ctx,
		CreateHandler: handleNodeDrainStatusCreate,
		ModifyHandler: handleNodeDrainStatusModify,
		DeleteHandler: handleNodeDrainStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subNodeDrainStatus = subNodeDrainStatus
	ctx.subNodeDrainStatus.Activate()
}

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
	ctx := ctxArg.(*diagContext)
	newStatus := configArg.(kubeapi.NodeDrainStatus)
	printNodeDrainStatus(ctx, newStatus)
}

func printNodeDrainStatus(ctx *diagContext, newStatus kubeapi.NodeDrainStatus) {
	ts := time.Now().Format(time.RFC3339Nano)
	if newStatus.Status < kubeapi.REQUESTED {
		// Just print the transitions which are linked to lengthy operations or errors
		return
	}
	ctx.ph.Print("INFO: Node Drain -> %s at %v\n", newStatus.Status.String(), ts)
	ctx.ph.Flush()
}

func handleNodeDrainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
}
