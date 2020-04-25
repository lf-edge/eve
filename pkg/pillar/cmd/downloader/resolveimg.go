package downloader

import (
	log "github.com/sirupsen/logrus"
)

// for function name consistency
func handleAppImgResolveModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleAppImgResolveModify for %s", key)
	resHandler.modify(ctxArg, key, configArg)
	log.Infof("handleAppImgResolveModify for %s, done", key)
}

func handleAppImgResolveDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("handleAppImgResolveDelete for %s", key)
	resHandler.delete(ctxArg, key, configArg)
	log.Infof("handleAppImgResolveDelete for %s, done", key)
}
