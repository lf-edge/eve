package zedagent

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

func handleNodeDrainStatusImpl(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	newStatus, ok := configArg.(kubeapi.NodeDrainStatus)
	if !ok {
		log.Fatalf("handleNodeDrainStatusImpl invalid type in configArg: %v", configArg)
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
