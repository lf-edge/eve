// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// content info specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"strings"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
)

var contentInfoHash []byte

// content info parsing routine
func parseContentInfoConfig(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Tracef("Started parsing content info config")
	cfgContentTreeList := config.GetContentInfo()
	h := sha256.New()
	for _, cfgContentTree := range cfgContentTreeList {
		computeConfigElementSha(h, cfgContentTree)
	}
	newHash := h.Sum(nil)
	if bytes.Equal(newHash, contentInfoHash) {
		return
	}
	log.Functionf("parseContentInfo: Applying updated config "+
		"Last Sha: % x, "+
		"New  Sha: % x, "+
		"Num of cfgContentInfo: %d",
		contentInfoHash, newHash, len(cfgContentTreeList))

	contentInfoHash = newHash

	// First look for deleted ones
	items := ctx.pubContentTreeConfig.GetAll()
	for idStr := range items {
		found := false
		for _, cfgContentTree := range cfgContentTreeList {
			if cfgContentTree.GetUuid() == idStr {
				found = true
				break
			}
		}
		// content tree not found, delete
		if !found {
			log.Functionf("parseContentInfo: deleting %s\n", idStr)
			unpublishContentTreeConfig(ctx, idStr)
		}
	}

	for _, cfgContentTree := range cfgContentTreeList {
		contentConfig := new(types.ContentTreeConfig)
		contentConfig.ContentID, _ = uuid.FromString(cfgContentTree.GetUuid())
		contentConfig.DatastoreID, _ = uuid.FromString(cfgContentTree.GetDsId())
		contentConfig.RelativeURL = cfgContentTree.GetURL()
		contentConfig.Format = cfgContentTree.GetIformat()
		contentConfig.ContentSha256 = strings.ToLower(cfgContentTree.GetSha256())
		contentConfig.MaxDownloadSize = cfgContentTree.GetMaxSizeBytes()
		contentConfig.DisplayName = cfgContentTree.GetDisplayName()
		publishContentTreeConfig(ctx, *contentConfig)
	}
	ctx.pubContentTreeConfig.SignalRestarted()
	log.Functionf("parsing content info config done\n")
}

func publishContentTreeConfig(ctx *getconfigContext,
	config types.ContentTreeConfig) {
	key := config.Key()
	log.Tracef("publishContentTreeConfig(%s)\n", key)
	pub := ctx.pubContentTreeConfig
	pub.Publish(key, config)
	log.Tracef("publishContentTreeConfig(%s) done\n", key)
}

func unpublishContentTreeConfig(ctx *getconfigContext, key string) {
	log.Tracef("unpublishContentTreeConfig(%s)\n", key)
	pub := ctx.pubContentTreeConfig
	config, _ := pub.Get(key)
	if config == nil {
		log.Errorf("unpublishContentTreeConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishContentTreeConfig(%s) done\n", key)
}

// content tree event watch to capture transitions
// and publish to zedCloud
func handleContentTreeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleContentTreeStatusImpl(ctxArg, key, statusArg)
}

func handleContentTreeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleContentTreeStatusImpl(ctxArg, key, statusArg)
}

func handleContentTreeStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	triggerPublishObjectInfo(ctx, info.ZInfoTypes_ZiContentTree, key)
}

func handleContentTreeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.ContentTreeStatus)
	ctx := ctxArg.(*zedagentContext)
	triggerPublishDeletedObjectInfo(ctx, info.ZInfoTypes_ZiContentTree, key, status)
}
