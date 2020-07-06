// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	log "github.com/sirupsen/logrus"
)

// for function name consistency
func handleResolveModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleResolveModify for %s", key)
	resHandler.modify(ctxArg, key, configArg)
	log.Infof("handleResolveModify for %s, done", key)
}

func handleResolveDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleResolveDelete for %s", key)
	resHandler.delete(ctxArg, key, configArg)
	log.Infof("handleResolveDelete for %s, done", key)
}
