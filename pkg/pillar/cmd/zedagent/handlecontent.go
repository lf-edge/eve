// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// content info specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

var contentInfoHash []byte

// content info parsing routine
func parseContentInfoConfig(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Debugf("Started parsing content info config")
	cfgContentTreeList := config.GetContentInfo()
	h := sha256.New()
	for _, cfgContentTree := range cfgContentTreeList {
		computeConfigElementSha(h, cfgContentTree)
	}
	newHash := h.Sum(nil)
	if bytes.Equal(newHash, contentInfoHash) {
		return
	}
	log.Infof("parseContentInfo: Applying updated config "+
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
			log.Infof("parseContentInfo: deleting %s\n", idStr)
			unpublishContentTreeConfig(ctx, idStr)
		}
	}

	for _, cfgContentTree := range cfgContentTreeList {
		contentConfig := new(types.ContentTreeConfig)
		contentConfig.ContentID, _ = uuid.FromString(cfgContentTree.GetUuid())
		contentConfig.DatastoreID, _ = uuid.FromString(cfgContentTree.GetDsId())
		contentConfig.RelativeURL = cfgContentTree.GetURL()
		contentConfig.Format = cfgContentTree.GetIformat()
		contentConfig.ContentSha256 = cfgContentTree.GetSha256()
		contentConfig.MaxDownloadSize = cfgContentTree.GetMaxSizeBytes()
		contentConfig.DisplayName = cfgContentTree.GetDisplayName()
		contentConfig.ImageSignature = cfgContentTree.Siginfo.Signature
		contentConfig.SignatureKey = cfgContentTree.Siginfo.Signercerturl

		// XXX:FIXME certificates can be many
		// this list, currently contains the certUrls
		// should be the sha/uuid of cert filenames
		// as proper DataStore Entries
		if cfgContentTree.Siginfo.Intercertsurl != "" {
			contentConfig.CertificateChain = make([]string, 1)
			contentConfig.CertificateChain[0] = cfgContentTree.Siginfo.Intercertsurl
		}
		publishContentTreeConfig(ctx, *contentConfig)
	}
	log.Infof("parsing content info config done\n")
}

func publishContentTreeConfig(ctx *getconfigContext,
	config types.ContentTreeConfig) {
	key := config.Key()
	log.Debugf("publishContentTreeConfig(%s)\n", key)
	pub := ctx.pubContentTreeConfig
	pub.Publish(key, config)
	log.Debugf("publishContentTreeConfig(%s) done\n", key)
}

func unpublishContentTreeConfig(ctx *getconfigContext, key string) {
	log.Debugf("unpublishContentTreeConfig(%s)\n", key)
	pub := ctx.pubContentTreeConfig
	config, _ := pub.Get(key)
	if config == nil {
		log.Errorf("unpublishContentTreeConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishContentTreeConfig(%s) done\n", key)
}

// content tree event watch to capture transitions
// and publish to zedCloud
// Handles both create and modify events
func handleContentTreeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.ContentTreeStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishContentInfoToZedCloud(ctx, uuidStr, &status, ctx.iteration)
	ctx.iteration++
}

func handleContentTreeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	uuidStr := key
	PublishContentInfoToZedCloud(ctx, uuidStr, nil, ctx.iteration)
	ctx.iteration++
}
