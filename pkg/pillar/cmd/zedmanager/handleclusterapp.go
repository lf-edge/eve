package zedmanager

import "github.com/lf-edge/eve/pkg/pillar/types"

func handleENClusterAppStatusCreate(ctxArg interface{}, key string, configArg interface{}) {
	log.Noticef("handleENClusterAppStatusCreate(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := configArg.(types.ENClusterAppStatus)
	handleENClusterAppStatusImpl(ctx, key, &status)
}

func handleENClusterAppStatusModify(ctxArg interface{}, key string, configArg interface{}, oldConfigArg interface{}) {
	log.Noticef("handleENClusterAppStatusModify(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := configArg.(types.ENClusterAppStatus)
	handleENClusterAppStatusImpl(ctx, key, &status)
}

func handleENClusterAppStatusDelete(ctxArg interface{}, key string, configArg interface{}) {
	log.Noticef("handleENClusterAppStatusDelete(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	//status := configArg.(types.ENClusterAppStatus)
	handleENClusterAppStatusImpl(ctx, key, nil)
}

func handleENClusterAppStatusImpl(ctx *zedmanagerContext, key string, status *types.ENClusterAppStatus) {

	log.Noticef("handleENClusterAppStatusImpl(%s) for app-status %v", key, status)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		aiStatus := st.(types.AppInstanceStatus)
		if aiStatus.UUIDandVersion.UUID.String() == key {
			log.Noticef("handleENClusterAppStatusImpl(%s) found ai status, update", key)

			updateAIStatusUUID(ctx, aiStatus.UUIDandVersion.UUID.String())
			break
		}
	}
}
