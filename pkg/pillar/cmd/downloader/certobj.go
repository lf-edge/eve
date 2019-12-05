package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleCertObjModify(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderModify(ctxArg, types.CertObj, key, configArg)
}
func handleCertObjCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderCreate(ctxArg, types.CertObj, key, configArg)
}

func handleCertObjDelete(ctxArg interface{}, key string, configArg interface{}) {
	handleDownloaderDelete(ctxArg, key, configArg)
}
