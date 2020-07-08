// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Handles both create and modify events
func handleDatastoreConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := configArg.(types.DatastoreConfig)
	log.Infof("handleDatastoreConfigModify for %s", key)
	checkAndUpdateDownloadableObjects(ctx, config.UUID)
	log.Infof("handleDatastoreConfigModify for %s, done", key)
}

func handleDatastoreConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*downloaderContext)
	config := configArg.(types.DatastoreConfig)
	cipherBlock := config.CipherBlockStatus
	ctx.pubCipherBlockStatus.Unpublish(cipherBlock.Key())
	log.Infof("handleDatastoreConfigDelete for %s", key)
}
