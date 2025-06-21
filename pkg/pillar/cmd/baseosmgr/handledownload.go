// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"errors"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

func checkContentTreeStatus(ctx *baseOsMgrContext,
	currentState types.SwState, contentID string) *types.RetStatus {

	ret := &types.RetStatus{}
	log.Functionf("checkContentTreeStatus for %s", contentID)

	ret.Changed = false
	ret.AllErrors = ""
	ret.MinState = types.MAXSTATE

	contentStatus := lookupContentTreeStatus(ctx, contentID)
	if contentStatus != nil {

		log.Functionf("checkContentTreeStatus %s, content status %v",
			contentID, contentStatus.State)

		if ret.MinState > contentStatus.State {
			ret.MinState = contentStatus.State
		}
		if contentStatus.HasError() {
			log.Errorf("checkContentTreeStatus %s, volumemgr error, %s", contentID, contentStatus.Error)
			ret.AllErrors = appendError(ret.AllErrors, "volumemgr", contentStatus.Error)
			ret.ErrorTime = contentStatus.ErrorTime
			ret.Changed = true
		}
	} else {
		ret.MinState = types.DOWNLOADING
		ret.Changed = true
	}

	if ret.MinState == types.MAXSTATE {
		// No StorageStatus
		ret.MinState = types.INITIAL
		ret.Changed = true
	}
	if currentState != ret.MinState {
		ret.Changed = true
	}

	return ret
}

// Note: can not do this in volumemgr since it is triggered by Activate=true
func installDownloadedObjects(ctx *baseOsMgrContext, uuidStr, finalObjDir string,
	contentID string) (bool, bool, error) {

	var (
		changed bool
		proceed bool
		err     error
	)
	log.Functionf("installDownloadedObjects(%s)", uuidStr)

	status := lookupContentTreeStatus(ctx, contentID)

	if status == nil {
		return changed, proceed, fmt.Errorf("installDownloadedObjects(%s) cannot found contentTree %s",
			uuidStr, contentID)
	}

	if status.State == types.LOADED {
		changed, proceed, err = installDownloadedObject(ctx, status.ContentID,
			finalObjDir, status)
		if err != nil {
			log.Error(err)
			return changed, proceed, err
		}
	}
	log.Functionf("installDownloadedObjects(%s) done %v", uuidStr, proceed)
	return changed, proceed, nil
}

// If the final installation directory is known, move the object there
// returns an error, and if ready
func installDownloadedObject(ctx *baseOsMgrContext, contentID uuid.UUID, finalObjDir string,
	ctsPtr *types.ContentTreeStatus) (bool, bool, error) {

	var (
		refID   string
		changed bool
		proceed bool
	)

	log.Functionf("installDownloadedObject(%s, %v)",
		contentID, ctsPtr.State)

	if ctsPtr.State != types.LOADED {
		return changed, proceed, nil
	}
	refID = ctsPtr.ReferenceID()
	if refID == "" {
		log.Fatalf("Content tree status is LOADED but missing required image ID for content %s",
			contentID)
	}
	log.Functionf("For %s reference ID for LOADED: %s",
		contentID, refID)

	// make sure we have a proper final destination point
	if finalObjDir == "" {
		changed = true
		errStr := fmt.Sprintf("installDownloadedObject %s, final dir not set",
			contentID)
		log.Errorln(errStr)
		ctsPtr.SetErrorWithSource(errStr, types.ContentTreeStatus{}, time.Now())
		return changed, proceed, errors.New(errStr)
	}

	// check if we have a result
	wres := ctx.worker.Pop(contentID.String())
	if wres != nil {
		log.Functionf("installDownloadedObject(%s): InstallWorkResult found", contentID)
		if wres.Error != nil {
			err := fmt.Errorf("installDownloadedObject(%s): InstallWorkResult error, exception while installing: %v", contentID, wres.Error)
			log.Error(err.Error())
			return changed, proceed, err
		}
		changed = true
		proceed = true
		return changed, proceed, nil
	}

	// if we made it here, there was no work result, so try to add it

	// Move to final installation point
	// do this as a background task
	// XXX called twice!
	AddWorkInstall(ctx, contentID.String(), refID, finalObjDir)
	log.Functionf("installDownloadedObject(%s) worker started", contentID)
	return changed, proceed, nil
}
