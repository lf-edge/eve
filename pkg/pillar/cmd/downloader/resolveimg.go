// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	log "github.com/sirupsen/logrus"
)

// for function name consistency
func handleAppImgResolveModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleAppImgResolveModify for %s", key)
	resHandler.modify(ctxArg, key, configArg, false)
	log.Infof("handleAppImgResolveModify for %s, done", key)
}

func handleAppImgResolveDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleAppImgResolveDelete for %s", key)
	resHandler.delete(ctxArg, key, configArg, false)
	log.Infof("handleAppImgResolveDelete for %s, done", key)
}

func handleContentTreeResolveModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeResolveModify for %s", key)
	resHandler.modify(ctxArg, key, configArg, true)
	log.Infof("handleContentTreeResolveModify for %s, done", key)
}

func handleContentTreeResolveDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeResolveDelete for %s", key)
	resHandler.delete(ctxArg, key, configArg, true)
	log.Infof("handleContentTreeResolveDelete for %s, done", key)
}
