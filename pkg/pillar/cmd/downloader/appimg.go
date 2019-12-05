package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// for function name consistency
func handleAppImgModify(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderModify(ctxArg, types.AppImgObj, key, configArg)
}

func handleAppImgCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderCreate(ctxArg, types.AppImgObj, key, configArg)
}

func handleAppImgDelete(ctxArg interface{}, key string, configArg interface{}) {
	handleDownloaderDelete(ctxArg, key, configArg)
}
