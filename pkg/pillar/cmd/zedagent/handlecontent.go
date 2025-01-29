// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// content info specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"strings"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

var contentInfoHash []byte

// stringsToUuids() - converts list of strings to a list of uuids,
//
//	returns a list with a nil uuid and a last error if
//	conversion fails
func stringsToUuids(strings []string) ([]uuid.UUID, error) {
	list := make([]uuid.UUID, len(strings))
	for i, str := range strings {
		var err error
		list[i], err = uuid.FromString(str)
		if err != nil {
			log.Errorf("stringsToUuids(): error parsing UUID '%s' index %d, %v\n",
				str, i, err)
			return []uuid.UUID{nilUUID}, err
		}
	}

	return list, nil
}

// getDatastoreIDList() - returns list of datastores UUIDs
func getDatastoreIDList(contentTree *zconfig.ContentTree) ([]uuid.UUID, error) {
	idsStrList := contentTree.GetDsIdsList()
	if len(idsStrList) == 0 {
		// Compatibility with the old controller, which does not support
		// list of datastores
		idsStrList = []string{contentTree.GetDsId()}
	}
	return stringsToUuids(idsStrList)
}

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
		contentConfig.DatastoreIDList, _ = getDatastoreIDList(cfgContentTree)
		contentConfig.RelativeURL = cfgContentTree.GetURL()
		contentConfig.Format = cfgContentTree.GetIformat()
		contentConfig.ContentSha256 = strings.ToLower(cfgContentTree.GetSha256())
		contentConfig.MaxDownloadSize = cfgContentTree.GetMaxSizeBytes()
		contentConfig.DisplayName = cfgContentTree.GetDisplayName()
		contentConfig.CustomMeta = cfgContentTree.GetCustomMetaData()
		contentConfig.IsLocal = true
		controllerDNID := cfgContentTree.GetDesignatedNodeId()
		// If this node is not designated node id set IsLocal to false.
		// Content will be downloaded to only to the designated node id of that content tree.
		// So on other nodes in the cluster mark the content tree as non-local.
		// On single node eve either kvm or kubevirt based, this node will always be designated node.
		// But if this is the contenttree of a container, we download it to all nodes of the cluster,
		// so set IsLocal true in such case.
		if controllerDNID != "" && controllerDNID != devUUID.String() {
			if contentConfig.Format == zconfig.Format_CONTAINER {
				contentConfig.IsLocal = true
			} else {
				contentConfig.IsLocal = false
			}
		}

		log.Noticef("parseContentInfo designated ID copy from volume config: %v, contentid %v, url %s", controllerDNID, contentConfig.ContentID, contentConfig.RelativeURL)

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

	status := statusArg.(types.ContentTreeStatus)
	ctx := ctxArg.(*zedagentContext)
	uuidStr := status.Key()
	PublishContentInfoToZedCloud(ctx, uuidStr, &status, ctx.iteration, AllDest)
	ctx.iteration++
}

func handleContentTreeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	uuidStr := key
	PublishContentInfoToZedCloud(ctx, uuidStr, nil, ctx.iteration, AllDest)
	ctx.iteration++
}
