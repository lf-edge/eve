// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

// for function name consistency
func handleResolveCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleResolveCreate for %s", key)
	resHandler.create(ctxArg, key, configArg)
	log.Functionf("handleResolveCreate for %s, done", key)
}

func handleResolveModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	log.Functionf("handleResolveModify for %s", key)
	resHandler.modify(ctxArg, key, configArg, oldConfigArg)
	log.Functionf("handleResolveModify for %s, done", key)
}

func handleResolveDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleResolveDelete for %s", key)
	resHandler.delete(ctxArg, key, configArg)
	log.Functionf("handleResolveDelete for %s, done", key)
}
