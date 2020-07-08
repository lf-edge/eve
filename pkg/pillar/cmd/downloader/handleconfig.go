// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

func handleDownloaderConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	dHandler.modify(ctxArg, key, configArg)
}

func handleDownloaderConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	dHandler.create(ctxArg, key, configArg)
}

func handleDownloaderConfigDelete(ctxArg interface{}, key string, configArg interface{}) {
	dHandler.delete(ctxArg, key, configArg)
}
