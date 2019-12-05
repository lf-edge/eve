package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/cast"
	log "github.com/sirupsen/logrus"
)

// Handles both create and modify events
func handleGlobalDownloadConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := cast.CastGlobalDownloadConfig(configArg)
	if key != "global" {
		log.Errorf("handleGlobalDownloadConfigModify: unexpected key %s\n", key)
		return
	}
	log.Infof("handleGlobalDownloadConfigModify for %s\n", key)
	ctx.globalConfig = config
	log.Infof("handleGlobalDownloadConfigModify done for %s\n", key)
}
