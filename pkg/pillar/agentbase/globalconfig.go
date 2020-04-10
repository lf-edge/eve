package agentbase

import (
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"

	log "github.com/sirupsen/logrus"
)

func NewGlobalConfigSub(ps *pubsub.PubSub, ctx interface{}) (pubsub.Subscription, error) {
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           ctx,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   DefaultWarningTime,
		ErrorTime:     DefaultErrorTime,
	})
	return subGlobalConfig, err
}

func handleGlobalConfigModify(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(*Context)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.ConfigItemValueMap
	ctxPtr.CLIParams.Debug, gcp = agentlog.HandleGlobalConfig(ctxPtr.subGlobalConfig, ctxPtr.AgentName,
		ctxPtr.CLIParams.DebugOverride)
	if gcp != nil && !ctxPtr.GCInitialized {
		ctxPtr.globalConfig = gcp
		ctxPtr.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify(%s): done\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(*Context)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	ctxPtr.CLIParams.Debug, _ = agentlog.HandleGlobalConfig(ctxPtr.subGlobalConfig, ctxPtr.AgentName,
		ctxPtr.CLIParams.DebugOverride)
	ctxPtr.globalConfig = types.DefaultConfigItemValueMap()
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}
