package zedagent

import (
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

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
	ctx := ctxArg.(*zedagentContext)
	triggerPublishObjectInfo(ctx, info.ZInfoTypes_ZiBlobList, key)
}

func handleBlobDelete(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.BlobStatus)
	ctx := ctxArg.(*zedagentContext)
	triggerPublishDeletedObjectInfo(ctx, info.ZInfoTypes_ZiBlobList, key, status)
}
