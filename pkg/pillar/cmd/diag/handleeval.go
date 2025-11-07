// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// initEvalSub initializes subscription to EvalStatus from evalmgr
func initEvalSub(ps *pubsub.PubSub, ctx *diagContext) {
	agentName := "diag"
	warningTime := warningTime
	errorTime := errorTime

	// Subscribe to evaluation status from evalmgr (if available)
	subEvalStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "evalmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.EvalStatus{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleEvalStatusCreate,
		ModifyHandler: handleEvalStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subEvalStatus = subEvalStatus
	subEvalStatus.Activate()
}

func handleEvalStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleEvalStatusImpl(ctxArg, key, statusArg)
}

func handleEvalStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleEvalStatusImpl(ctxArg, key, statusArg)
}

func handleEvalStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*diagContext)
	ctx.evalStatus = statusArg.(types.EvalStatus)
	log.Functionf("handleEvalStatusImpl: key %s, IsEvaluationPlatform %t",
		key, ctx.evalStatus.IsEvaluationPlatform)
	triggerPrintOutput(ctx, "EvalStatus")
}
