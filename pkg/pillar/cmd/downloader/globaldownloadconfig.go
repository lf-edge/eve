// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Handles both create and modify events
func handleGlobalDownloadConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := configArg.(types.GlobalDownloadConfig)
	if key != "global" {
		log.Errorf("handleGlobalDownloadConfigModify: unexpected key %s", key)
		return
	}
	log.Infof("handleGlobalDownloadConfigModify for %s", key)
	ctx.globalConfig = config
	log.Infof("handleGlobalDownloadConfigModify done for %s", key)
}
