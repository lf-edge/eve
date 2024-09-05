package nodeagent

import (
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

func handleNodeDrainStatusCreateNA(ctxArg interface{}, key string,
	configArg interface{}) {
	handleNodeDrainStatusImplNA(ctxArg, key, configArg, nil)
}

func handleNodeDrainStatusModifyNA(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleNodeDrainStatusImplNA(ctxArg, key, configArg, oldConfigArg)
}

func handleNodeDrainStatusImplNA(ctxArg interface{}, _ string,
	configArg interface{}, _ interface{}) {
	ctx, ok := ctxArg.(*nodeagentContext)
	if !ok {
		log.Fatalf("handleNodeDrainStatusImplNA invalid type in ctxArg:%v", ctxArg)
	}
	newStatus, ok := configArg.(kubeapi.NodeDrainStatus)
	if !ok {
		log.Fatalf("handleNodeDrainStatusImplNA invalid type in configArg:%v", configArg)
	}

	if newStatus.RequestedBy != kubeapi.DEVICEOP {
		return
	}

	log.Noticef("handleNodeDrainStatusImplNA to:%v", newStatus)
	// NodeDrainStatus Failures here should keep drainInProgress set.
	//      As this will set DrainInProgress on NodeAgentStatus and keep zedagent from allowing
	//  the deferred operation to continue.
	if (newStatus.Status >= kubeapi.REQUESTED) && (newStatus.Status <= kubeapi.COMPLETE) {
		log.Noticef("handleNodeDrainStatusImplNA nodedrain-step:drain-inprogress-handler NodeDrainStatus:%v", newStatus)
		ctx.drainInProgress = true
		publishNodeAgentStatus(ctx)
	}
	if newStatus.Status == kubeapi.COMPLETE {
		log.Notice("handleNodeDrainStatusImplNA nodedrain-step:drain-complete-handler notify zedagent")
		ctx.drainInProgress = false
		publishNodeAgentStatus(ctx)
	}
}

func handleNodeDrainStatusDeleteNA(_ interface{}, _ string,
	_ interface{}) {
	log.Functionf("handleNodeDrainStatusDeleteNA")
}

func initNodeDrainPubSub(ps *pubsub.PubSub, ctx *nodeagentContext) {
	subNodeDrainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedkube",
		MyAgentName:   agentName,
		TopicImpl:     kubeapi.NodeDrainStatus{},
		Persistent:    false,
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleNodeDrainStatusCreateNA,
		ModifyHandler: handleNodeDrainStatusModifyNA,
		DeleteHandler: handleNodeDrainStatusDeleteNA,
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
