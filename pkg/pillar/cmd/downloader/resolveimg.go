// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	log "github.com/sirupsen/logrus"
)

// for function name consistency
func handleContentTreeResolveModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeResolveModify for %s", key)
	resHandler.modify(ctxArg, key, configArg)
	log.Infof("handleContentTreeResolveModify for %s, done", key)
}

func handleContentTreeResolveDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeResolveDelete for %s", key)
	resHandler.delete(ctxArg, key, configArg)
	log.Infof("handleContentTreeResolveDelete for %s, done", key)
}
