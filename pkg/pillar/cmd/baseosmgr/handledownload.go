// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Really a constant
var nilUUID uuid.UUID

func checkContentTreeStatus(ctx *baseOsMgrContext,
	baseOsUUID uuid.UUID, config []types.ContentTreeConfig,
	status []types.ContentTreeStatus) *types.RetStatus {

	uuidStr := baseOsUUID.String()
	ret := &types.RetStatus{}
	log.Functionf("checkContentTreeStatus for %s", uuidStr)

	ret.Changed = false
	ret.AllErrors = ""
	ret.MinState = types.MAXSTATE

	for i, ctc := range config {

		cts := &status[i]

		contentID := ctc.ContentID

		log.Functionf("checkContentTreeStatus %s, content status %v",
			contentID, cts.State)
		if cts.State == types.INSTALLED {
			ret.MinState = cts.State
			cts.Progress = 100
			// XXX TotalSize and CurrentSize?
			ret.Changed = true
			log.Functionf("checkContentTreeStatus %s is already installed",
				contentID)
			continue
		}

		c := MaybeAddContentTreeConfig(ctx, &ctc)
		if c {
			ret.Changed = true
		}
		contentStatus := lookupContentTreeStatus(ctx, ctc.Key())
		if contentStatus == nil {
			log.Functionf("Content tree status not found. name: %s", ctc.RelativeURL)
			ret.MinState = types.DOWNLOADING
			cts.State = types.DOWNLOADING
			ret.Changed = true
			continue
		}

		if contentStatus.FileLocation != cts.FileLocation {
			cts.FileLocation = contentStatus.FileLocation
			ret.Changed = true
			log.Functionf("checkContentTreeStatus(%s) from contentStatus set FileLocation to %s",
				contentID, contentStatus.FileLocation)
		}
		if ret.MinState > contentStatus.State {
			ret.MinState = contentStatus.State
		}
		if contentStatus.State != cts.State {
			log.Functionf("checkContentTreeStatus(%s) from ds set cts.State %d",
				contentID, contentStatus.State)
			cts.State = contentStatus.State
			ret.Changed = true
		}

		if contentStatus.Progress != cts.Progress {
			cts.Progress = contentStatus.Progress
			ret.Changed = true
		}
		if contentStatus.TotalSize != cts.TotalSize {
			if (cts.TotalSize != 0) && (cts.TotalSize != contentStatus.TotalSize) {
				log.Warnf("checkContentTreeStatus(%s) from ds set cts.TotalSize %d, was %d", contentID, contentStatus.TotalSize, cts.TotalSize)
			}
			cts.TotalSize = contentStatus.TotalSize
			ret.Changed = true
		}
		if contentStatus.CurrentSize != cts.CurrentSize {
			cts.CurrentSize = contentStatus.CurrentSize
			ret.Changed = true
		}
		if contentStatus.HasError() {
			log.Errorf("checkContentTreeStatus %s, volumemgr error, %s", uuidStr, contentStatus.Error)
			description := contentStatus.ErrorDescription
			description.ErrorEntities = []*types.ErrorEntity{{EntityID: contentStatus.ContentID.String(), EntityType: types.ErrorEntityContentTree}}
			cts.SetErrorWithSourceAndDescription(description, types.ContentTreeStatus{})
			ret.AllErrors = appendError(ret.AllErrors, "volumemgr", contentStatus.Error)
			ret.ErrorTime = cts.ErrorTime
			ret.Changed = true
		}
	}

	if ret.MinState == types.MAXSTATE {
		// No StorageStatus
		ret.MinState = types.INITIAL
		ret.Changed = true
	}

	return ret
}

// Note: can not do this in volumemgr since it is triggered by Activate=true
func installDownloadedObjects(ctx *baseOsMgrContext, uuidStr, finalObjDir string,
	status *[]types.ContentTreeStatus) (bool, bool, error) {

	var (
		changed bool
		proceed bool
		err     error
	)
	log.Functionf("installDownloadedObjects(%s)", uuidStr)

	for i := range *status {
		ctsPtr := &(*status)[i]

		if ctsPtr.State == types.LOADED {
			changed, proceed, err = installDownloadedObject(ctx, ctsPtr.ContentID,
				finalObjDir, ctsPtr)
			if err != nil {
				log.Error(err)
				return changed, proceed, err
			}
		}
		if ctsPtr.State == types.INSTALLED {
			proceed = true
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
		log.Fatalf("XXX no image ID for LOADED %s",
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
		return changed, proceed, fmt.Errorf(errStr)
	}

	// check if we have a result
	wres := ctx.worker.Pop(contentID.String())
	if wres != nil {
		log.Functionf("installDownloadedObject(%s): InstallWorkResult found", contentID)
		if wres.Error != nil {
			err := fmt.Errorf("installDownloadedObject(%s): InstallWorkResult error, exception while installing: %v", contentID, wres.Error)
			log.Errorf(err.Error())
			return changed, proceed, err
		}
		changed = true
		proceed = true
		// if we made it here, we successfully completed the job
		ctsPtr.State = types.INSTALLED
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
