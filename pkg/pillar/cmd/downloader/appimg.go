package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleAppImgModify(ctxArg interface{}, key string,
	configArg interface{}) {

	dHandler.modify(ctxArg, types.AppImgObj, key, configArg)
}

func handleAppImgCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	dHandler.create(ctxArg, types.AppImgObj, key, configArg)
}

func handleAppImgDelete(ctxArg interface{}, key string, configArg interface{}) {
	dHandler.delete(ctxArg, key, configArg)
}
