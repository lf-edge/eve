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

func checkVolumeStatus(ctx *baseOsMgrContext,
	baseOsUUID uuid.UUID, config []types.StorageConfig,
	status []types.StorageStatus) *types.RetStatus {

	uuidStr := baseOsUUID.String()
	ret := &types.RetStatus{}
	log.Infof("checkVolumeStatus for %s", uuidStr)

	ret.Changed = false
	ret.AllErrors = ""
	ret.MinState = types.MAXSTATE

	for i, sc := range config {

		ss := &status[i]

		imageID := sc.ImageID

		log.Infof("checkVolumeStatus %s, image status %v",
			imageID, ss.State)
		if ss.State == types.INSTALLED {
			ret.MinState = ss.State
			ss.Progress = 100
			ret.Changed = true
			log.Infof("checkVolumeStatus %s is already installed",
				imageID)
			continue
		}

		if !ss.HasVolumemgrRef {
			log.Infof("checkVolumeStatus %s, !HasVolumemgrRef", sc.ImageID)
			// We use the baseos object UUID as appInstID here
			// XXX note that we use the ImageID for the VolumeID
			// argument since we do not have a VolumeID
			AddOrRefcountVolumeConfig(ctx, ss.ImageSha256,
				baseOsUUID, ss.ImageID, *ss)
			ss.HasVolumemgrRef = true
			ret.Changed = true
		}
		// We use the baseos object UUID as appInstID here
		vs := lookupVolumeStatus(ctx, ss.ImageSha256, baseOsUUID, ss.ImageID)
		if vs == nil || vs.RefCount == 0 {
			if vs == nil {
				log.Infof("VolumeStatus not found. name: %s",
					ss.Name)
			} else {
				log.Infof("VolumeStatus RefCount zero. name: %s",
					ss.Name)
			}
			ret.MinState = types.DOWNLOADING
			ss.State = types.DOWNLOADING
			ret.Changed = true
			continue
		}

		if vs.FileLocation != ss.ActiveFileLocation {
			ss.ActiveFileLocation = vs.FileLocation
			ret.Changed = true
			log.Infof("checkVolumeStatus(%s) from vs set ActiveFileLocation to %s",
				imageID, vs.FileLocation)
		}
		if ret.MinState > vs.State {
			ret.MinState = vs.State
		}
		if vs.State != ss.State {
			log.Infof("checkVolumeStatus(%s) from ds set ss.State %d",
				imageID, vs.State)
			ss.State = vs.State
			ret.Changed = true
		}

		if vs.Progress != ss.Progress {
			ss.Progress = vs.Progress
			ret.Changed = true
		}
		if vs.Pending() {
			log.Infof("checkVolumeStatus(%s) Pending",
				imageID)
			continue
		}
		if vs.HasError() {
			log.Errorf("checkVolumeStatus %s, volumemgr error, %s",
				uuidStr, vs.Error)
			ss.SetErrorWithSource(vs.Error, types.VolumeStatus{},
				vs.ErrorTime)
			ret.AllErrors = appendError(ret.AllErrors, "volumemgr", vs.Error)
			ret.ErrorTime = ss.ErrorTime
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
func installDownloadedObjects(uuidStr string,
	status *[]types.StorageStatus) bool {

	ret := true
	log.Infof("installDownloadedObjects(%s)", uuidStr)

	for i := range *status {
		ssPtr := &(*status)[i]

		if ssPtr.State == types.CREATED_VOLUME {
			err := installDownloadedObject(ssPtr.ImageID, ssPtr)
			if err != nil {
				log.Error(err)
			}
		}
		// if something is still not installed, mark accordingly
		if ssPtr.State != types.INSTALLED {
			ret = false
		}
	}

	log.Infof("installDownloadedObjects(%s) done %v", uuidStr, ret)
	return ret
}

// If the final installation directory is known, move the object there
func installDownloadedObject(imageID uuid.UUID,
	ssPtr *types.StorageStatus) error {

	var ret error
	var srcFilename string

	log.Infof("installDownloadedObject(%s, %v)",
		imageID, ssPtr.State)

	if ssPtr.State != types.CREATED_VOLUME {
		return nil
	}
	srcFilename = ssPtr.ActiveFileLocation
	if srcFilename == "" {
		log.Fatalf("XXX no ActiveFileLocation for CREATED_VOLUME %s",
			imageID)
	}
	log.Infof("For %s ActiveFileLocation for CREATED_VOLUME: %s",
		imageID, srcFilename)

	// ensure the file is present
	if _, err := os.Stat(srcFilename); err != nil {
		log.Fatal(err)
	}

	// Move to final installation point
	if ssPtr.FinalObjDir != "" {

		var dstFilename string = ssPtr.FinalObjDir
		ret = installBaseOsObject(srcFilename, dstFilename)
	} else {
		errStr := fmt.Sprintf("installDownloadedObject %s, final dir not set",
			imageID)
		log.Errorln(errStr)
		ret = errors.New(errStr)
	}

	if ret == nil {
		ssPtr.State = types.INSTALLED
		log.Infof("installDownloadedObject(%s) done", imageID)
	} else {
		errStr := fmt.Sprintf("installDownloadedObject: %s", ret)
		ssPtr.SetErrorWithSource(errStr, types.VolumeStatus{}, time.Now())
	}
	return ret
}
