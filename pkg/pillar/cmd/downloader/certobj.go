package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleCertObjModify(ctxArg interface{}, key string,
	configArg interface{}) {

	dHandler.modify(ctxArg, types.CertObj, key, configArg)
}
func handleCertObjCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	dHandler.create(ctxArg, types.CertObj, key, configArg)
}

func handleCertObjDelete(ctxArg interface{}, key string, configArg interface{}) {
	dHandler.delete(ctxArg, key, configArg)
}
