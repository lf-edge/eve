package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/cast"
	log "github.com/sirupsen/logrus"
)

// Handles both create and modify events
func handleDatastoreConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := cast.CastDatastoreConfig(configArg)
	log.Infof("handleDatastoreConfigModify for %s\n", key)
	checkAndUpdateDownloadableObjects(ctx, config.UUID)
	log.Infof("handleDatastoreConfigModify for %s, done\n", key)
}

func handleDatastoreConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleDatastoreConfigDelete for %s\n", key)
}
