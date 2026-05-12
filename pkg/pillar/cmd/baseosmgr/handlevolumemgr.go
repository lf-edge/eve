// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

// Code for the interface with VolumeMgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func lookupContentTreeStatus(ctx *baseOsMgrContext, key string) *types.ContentTreeStatus {

	sub := ctx.subContentTreeStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Functionf("lookupContentTreeStatus(%s) not found", key)
		return nil
	}
	status := st.(types.ContentTreeStatus)
	return &status
}

func handleContentTreeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleContentTreeStatusImpl(ctxArg, key, statusArg)
}

func handleContentTreeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleContentTreeStatusImpl(ctxArg, key, statusArg)
}

func handleContentTreeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleContentTreeStatusImpl(ctxArg, key, statusArg)

	// If the BaseOsConfig for a BaseOsStatus referencing this content
	// tree has already been deleted, doBaseOsUninstall ran at
	// BaseOsConfig-delete time but returned del=false because
	// ContentTreeStatus was still present. Retry the uninstall now so
	// the orphan BaseOsStatus is unpublished instead of lingering until
	// the next reboot.
	status := statusArg.(types.ContentTreeStatus)
	ctx := ctxArg.(*baseOsMgrContext)
	for _, el := range lookupBaseOsStatusesByContentID(ctx, status.ContentID.String()) {
		if lookupBaseOsConfig(ctx, el.Key()) != nil {
			continue
		}
		log.Functionf("handleContentTreeStatusDelete: retrying removeBaseOsStatus for %s",
			el.Key())
		removeBaseOsStatus(ctx, el.Key())
	}
}

func handleContentTreeStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.ContentTreeStatus)
	ctx := ctxArg.(*baseOsMgrContext)
	log.Functionf("handleContentTreeStatusImpl: key:%s, name:%s",
		key, status.DisplayName)
	baseOSStatuses := lookupBaseOsStatusesByContentID(ctx, status.ContentID.String())
	for _, el := range baseOSStatuses {
		baseOsHandleStatusUpdateUUID(ctx, el.Key())
	}
	log.Functionf("handleContentTreeStatusImpl done for %s", key)
}
