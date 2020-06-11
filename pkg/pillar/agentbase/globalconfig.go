package agentbase

import (
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"

	log "github.com/sirupsen/logrus"
)

// SubscribeToGlobalConfig - subscribes an agent to global config
func SubscribeToGlobalConfig(ps *pubsub.PubSub, ctx interface{}) (pubsub.Subscription, error) {
	ctxPtr := ctx.(AgentBase).AgentBaseContext()
	options := ctxPtr.AgentOptions.GlobalConfigSubscriptionOptions
	options.Ctx = ctx
	options.ModifyHandler = handleGlobalConfigModify
	options.DeleteHandler = handleGlobalConfigDelete
	subGlobalConfig, err := ps.NewSubscription(options)
	return subGlobalConfig, err
}

func handleGlobalConfigModify(ctxArg interface{},
	key string, statusArg interface{}) {

	ctxPtr := ctxArg.(AgentBase).AgentBaseContext()
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.ConfigItemValueMap
	ctxPtr.CLIParams.Debug, gcp = agentlog.HandleGlobalConfig(ctxPtr.SubGlobalConfig, ctxPtr.AgentName,
		ctxPtr.CLIParams.DebugOverride)
	if gcp != nil {
		if ctxPtr.GlobalConfigHandler != nil {
			ctxPtr.GlobalConfigHandler(gcp)
		} else {
			ctxPtr.GlobalConfig = gcp
		}
		ctxPtr.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify(%s): done\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{},
	key string, statusArg interface{}) {
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("GlobalConfig unexpectedly deleted for %s\n", key)
}
