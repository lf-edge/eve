// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Really a constant
var nilUUID uuid.UUID

func checkContentTreeStatus(ctx *baseOsMgrContext,
	baseOsUUID uuid.UUID, config []types.ContentTreeConfig,
	status []types.ContentTreeStatus) *types.RetStatus {

	uuidStr := baseOsUUID.String()
	ret := &types.RetStatus{}
	log.Infof("checkContentTreeStatus for %s", uuidStr)

	ret.Changed = false
	ret.AllErrors = ""
	ret.MinState = types.MAXSTATE

	for i, ctc := range config {

		cts := &status[i]

		contentID := ctc.ContentID

		log.Infof("checkContentTreeStatus %s, content status %v",
			contentID, cts.State)
		if cts.State == types.INSTALLED {
			ret.MinState = cts.State
			cts.Progress = 100
			ret.Changed = true
			log.Infof("checkContentTreeStatus %s is already installed",
				contentID)
			continue
		}

		publishContentTreeConfig(ctx, &ctc)
		ret.Changed = true
		contentStatus := lookupContentTreeStatus(ctx, ctc.Key())
		if contentStatus == nil {
			log.Infof("Content tree status not found. name: %s", ctc.RelativeURL)
			ret.MinState = types.DOWNLOADING
			cts.State = types.DOWNLOADING
			ret.Changed = true
			continue
		}

		if contentStatus.FileLocation != cts.FileLocation {
			cts.FileLocation = contentStatus.FileLocation
			ret.Changed = true
			log.Infof("checkContentTreeStatus(%s) from contentStatus set FileLocation to %s",
				contentID, contentStatus.FileLocation)
		}
		if ret.MinState > contentStatus.State {
			ret.MinState = contentStatus.State
		}
		if contentStatus.State != cts.State {
			log.Infof("checkContentTreeStatus(%s) from ds set cts.State %d",
				contentID, contentStatus.State)
			cts.State = contentStatus.State
			ret.Changed = true
		}

		if contentStatus.Progress != cts.Progress {
			cts.Progress = contentStatus.Progress
			ret.Changed = true
		}
		if contentStatus.HasError() {
			log.Errorf("checkContentTreeStatus %s, volumemgr error, %s",
				uuidStr, contentStatus.Error)
			cts.SetErrorWithSource(contentStatus.Error, types.ContentTreeStatus{},
				contentStatus.ErrorTime)
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
func installDownloadedObjects(uuidStr, FinalObjDir string,
	status *[]types.ContentTreeStatus) bool {

	ret := true
	log.Infof("installDownloadedObjects(%s)", uuidStr)

	for i := range *status {
		ctsPtr := &(*status)[i]

		if ctsPtr.State == types.VERIFIED {
			err := installDownloadedObject(ctsPtr.ContentID, FinalObjDir, ctsPtr)
			if err != nil {
				log.Error(err)
			}
		}
		// if something is still not installed, mark accordingly
		if ctsPtr.State != types.INSTALLED {
			ret = false
		}
	}

	log.Infof("installDownloadedObjects(%s) done %v", uuidStr, ret)
	return ret
}

// If the final installation directory is known, move the object there
func installDownloadedObject(contentID uuid.UUID, FinalObjDir string,
	ctsPtr *types.ContentTreeStatus) error {

	var ret error
	var srcFilename string

	log.Infof("installDownloadedObject(%s, %v)",
		contentID, ctsPtr.State)

	if ctsPtr.State != types.VERIFIED {
		return nil
	}
	srcFilename = ctsPtr.FileLocation
	if srcFilename == "" {
		log.Fatalf("XXX no FileLocation for VERIFIED %s",
			contentID)
	}
	log.Infof("For %s FileLocation for VERIFIED: %s",
		contentID, srcFilename)

	// ensure the file is present
	if _, err := os.Stat(srcFilename); err != nil {
		log.Fatal(err)
	}

	// Move to final installation point
	if FinalObjDir != "" {
		var dstFilename string = FinalObjDir
		ret = installBaseOsObject(srcFilename, dstFilename)
	} else {
		errStr := fmt.Sprintf("installDownloadedObject %s, final dir not set",
			contentID)
		log.Errorln(errStr)
		ret = errors.New(errStr)
	}

	if ret == nil {
		ctsPtr.State = types.INSTALLED
		log.Infof("installDownloadedObject(%s) done", contentID)
	} else {
		errStr := fmt.Sprintf("installDownloadedObject: %s", ret)
		ctsPtr.SetErrorWithSource(errStr, types.ContentTreeStatus{}, time.Now())
	}
	return ret
}
