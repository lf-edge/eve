package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleBaseOsModify(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderModify(ctxArg, types.BaseOsObj, key, configArg)
}

func handleBaseOsCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderCreate(ctxArg, types.BaseOsObj, key, configArg)
}

func handleBaseOsDelete(ctxArg interface{}, key string, configArg interface{}) {
	handleDownloaderDelete(ctxArg, key, configArg)
}
