package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleBaseOsModify(ctxArg interface{}, key string,
	configArg interface{}) {

	dHandler.modify(ctxArg, types.BaseOsObj, key, configArg)
}

func handleBaseOsCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	dHandler.create(ctxArg, types.BaseOsObj, key, configArg)
}

func handleBaseOsDelete(ctxArg interface{}, key string, configArg interface{}) {
	dHandler.delete(ctxArg, key, configArg)
}
