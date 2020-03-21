package verifier

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// wrappers to add objType for create. The Delete wrappers are merely
// for function name consistency
func handleAppImgModify(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.modify(ctxArg, types.AppImgObj, key, configArg)
}

func handleAppImgCreate(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.create(ctxArg, types.AppImgObj, key, configArg)
}

func handleAppImgDelete(ctxArg interface{}, key string, configArg interface{}) {
	vHandler.delete(ctxArg, key, configArg)
}
