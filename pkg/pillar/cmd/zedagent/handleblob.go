package zedagent

import "github.com/lf-edge/eve/pkg/pillar/types"

func blobStatusGetAll(ctx *zedagentContext) map[string]*types.BlobStatus {
	sub := ctx.subBlobStatus
	blobShaAndBlobStatus := make(map[string]*types.BlobStatus)
	for blobSha, blobStatusInt := range sub.GetAll() {
		blobStatus := blobStatusInt.(types.BlobStatus)
		blobShaAndBlobStatus[blobSha] = &blobStatus
	}
	return blobShaAndBlobStatus
}

func handleBlobStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleBlobStatusImpl(ctxArg, key, statusArg)
}

func handleBlobStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleBlobStatusImpl(ctxArg, key, statusArg)
}

func handleBlobStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.BlobStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishBlobInfoToZedCloud(ctx, uuidStr, &status, ctx.iteration, AllDest)
	ctx.iteration++
}

func handleBlobDelete(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.BlobStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishBlobInfoToZedCloud(ctx, uuidStr, nil, ctx.iteration, AllDest)
	ctx.iteration++
}
