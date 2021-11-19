// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleDatastoreConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleDatastoreConfigImpl(ctxArg, key, configArg)
}

func handleDatastoreConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleDatastoreConfigImpl(ctxArg, key, configArg)
}

func handleDatastoreConfigImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := configArg.(types.DatastoreConfig)
	log.Functionf("handleDatastoreConfigImpl for %s", key)
	checkAndUpdateDownloadableObjects(ctx, config.UUID)
	checkAndUpdateResolveConfig(ctx, config.UUID)
	log.Noticef("handleDatastoreConfigImpl for %s, done", key)
}

func handleDatastoreConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*downloaderContext)
	config := configArg.(types.DatastoreConfig)
	cipherBlock := config.CipherBlockStatus
	ctx.pubCipherBlockStatus.Unpublish(cipherBlock.Key())
	log.Noticef("handleDatastoreConfigDelete for %s", key)
}
