package verifier

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleBaseOsModify(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.modify(ctxArg, types.BaseOsObj, key, configArg)
}

func handleBaseOsCreate(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.create(ctxArg, types.BaseOsObj, key, configArg)
}

func handleBaseOsDelete(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.delete(ctxArg, key, configArg)
}
