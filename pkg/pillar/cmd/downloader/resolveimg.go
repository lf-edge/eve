// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

// for function name consistency
func handleResolveCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleResolveCreate for %s", key)
	resHandler.create(ctxArg, key, configArg)
	log.Infof("handleResolveCreate for %s, done", key)
}

func handleResolveModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	log.Infof("handleResolveModify for %s", key)
	resHandler.modify(ctxArg, key, configArg, oldConfigArg)
	log.Infof("handleResolveModify for %s, done", key)
}

func handleResolveDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleResolveDelete for %s", key)
	resHandler.delete(ctxArg, key, configArg)
	log.Infof("handleResolveDelete for %s, done", key)
}
