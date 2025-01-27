// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diag

import (
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

func handleNodeDrainStatusImpl(ctxArg interface{}, _ string,
	_ interface{}, _ interface{}) {
	ctx := ctxArg.(*diagContext)
	triggerPrintOutput(ctx, "NodeDrain")
}

func printNodeDrainStatus(ctx *diagContext) {
	items := ctx.subNodeDrainStatus.GetAll()
	for _, item := range items {
		nds := item.(kubeapi.NodeDrainStatus)

		sev := ""
		switch nds.Status {
		case kubeapi.UNKNOWN:
		case kubeapi.NOTSUPPORTED:
			// not kubevirt-EVE or not clustered, skipping unnecessary logging
		case kubeapi.NOTREQUESTED:
			fallthrough
		case kubeapi.REQUESTED:
			fallthrough
		case kubeapi.STARTING:
			fallthrough
		case kubeapi.CORDONED:
			sev = "INFO"
			break
		case kubeapi.FAILEDCORDON:
			sev = "ERROR"
		case kubeapi.DRAINRETRYING:
			sev = "WARNING"
		case kubeapi.FAILEDDRAIN:
			sev = "ERROR"
		case kubeapi.COMPLETE:
			sev = "INFO"
		}
		ctx.ph.Print("%s: Node Drain -> %s\n", sev, nds.Status.String())
	}
}

func handleNodeDrainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
}
