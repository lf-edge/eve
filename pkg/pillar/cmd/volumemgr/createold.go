// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"fmt"
	"os"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	log "github.com/sirupsen/logrus"
)

// createOldVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createOldVolume(ctx *volumemgrContext, status types.OldVolumeStatus) (bool, string, error) {

	srcLocation := status.FileLocation
	log.Infof("createOldVolume(%s) from %s", status.Key(), srcLocation)
	switch status.Origin {
	case types.OriginTypeDownload:
		if status.Format == zconfig.Format_CONTAINER {
			return createOldContainerVolume(ctx, status, srcLocation)
		} else {
			return createOldVdiskVolume(ctx, status, srcLocation)
		}
	default:
		log.Fatalf("XXX unsupported origin %v", status.Origin)
	}
	return false, "", nil
}

// createOldVdiskVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createOldVdiskVolume(ctx *volumemgrContext, status types.OldVolumeStatus, srcLocation string) (bool, string, error) {

	created := false
	if status.ReadOnly {
		log.Infof("createOldVdiskVolume(%s) ReadOnly", status.Key())
		created = true // To make doUpdate proceed
		return created, srcLocation, nil
	}

	filelocation := appRwOldVolumeName(status.BlobSha256, status.AppInstID.String(),
		// XXX in general status.VolumeID,
		status.PurgeCounter, status.Format, status.Origin, false)

	if _, err := os.Stat(filelocation); err == nil {
		errStr := fmt.Sprintf("Can not create %s for %s: exists",
			filelocation, status.Key())
		log.Error(errStr)
		return created, srcLocation, errors.New(errStr)
	}
	log.Infof("Copy from %s to %s", srcLocation, filelocation)
	created = true // So we will delete later even if partial failure
	if err := cp(filelocation, srcLocation); err != nil {
		errStr := fmt.Sprintf("Copy failed from %s to %s: %s\n",
			srcLocation, filelocation, err)
		log.Error(errStr)
		return created, filelocation, errors.New(errStr)
	}
	// Do we need to expand disk?
	err := maybeResizeDisk(filelocation, status.MaxVolSize)
	if err != nil {
		log.Error(err)
		return created, filelocation, err
	}
	log.Infof("Copy DONE from %s to %s", srcLocation, status.FileLocation)
	log.Infof("createOldVdiskVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// createOldContainerVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createOldContainerVolume(ctx *volumemgrContext, status types.OldVolumeStatus, srcLocation string) (bool, string, error) {

	created := false
	dirName := appRwOldVolumeName(status.BlobSha256, status.AppInstID.String(),
		// XXX in general status.VolumeID,
		status.PurgeCounter, status.Format, status.Origin, true)

	filelocation := containerd.GetContainerPath(dirName)

	ociFilename, err := utils.VerifiedImageFileLocation(status.BlobSha256)
	if err != nil {
		errStr := fmt.Sprintf("failed to get Image File Location. err: %+s",
			err)
		log.Error(errStr)
		return created, filelocation, errors.New(errStr)
	}
	log.Infof("ociFilename %s sha %s", ociFilename, status.BlobSha256)
	created = true
	if err := prepareContainerVolume(filelocation, ociFilename); err != nil {
		log.Errorf("Failed to create ctr bundle. Error %s", err)
		return created, filelocation, err
	}
	log.Infof("createOldContainerVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// destroyOldVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyOldVolume(ctx *volumemgrContext, status types.OldVolumeStatus) (bool, string, error) {

	log.Infof("destroyOldVolume(%s)", status.Key())
	if !status.VolumeCreated {
		log.Infof("destroyOldVolume(%s) nothing was created", status.Key())
		return false, status.FileLocation, nil
	}

	if status.ReadOnly {
		log.Infof("destroyOldVolume(%s) ReadOnly", status.Key())
		return false, "", nil
	}

	if status.FileLocation == "" {
		log.Errorf("destroyOldVolume(%s) no FileLocation", status.Key())
		return false, "", nil
	}

	switch status.Origin {
	case types.OriginTypeDownload:
		if status.Format == zconfig.Format_CONTAINER {
			return destroyOldContainerVolume(ctx, status)
		} else {
			return destroyOldVdiskVolume(ctx, status)
		}
	default:
		log.Fatalf("XXX unsupported origin %v", status.Origin)
	}
	return false, "", nil
}

// destroyOldVdiskVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyOldVdiskVolume(ctx *volumemgrContext, status types.OldVolumeStatus) (bool, string, error) {

	created := status.VolumeCreated
	filelocation := status.FileLocation
	log.Infof("Delete copy at %s", filelocation)
	if err := os.Remove(filelocation); err != nil {
		log.Error(err)
		filelocation = ""
		return created, filelocation, err
	}
	filelocation = ""
	created = false
	log.Infof("destroyOldVdiskVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// destroyOldContainerVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyOldContainerVolume(ctx *volumemgrContext, status types.OldVolumeStatus) (bool, string, error) {

	created := status.VolumeCreated
	filelocation := status.FileLocation
	log.Infof("Removing container volume %s", filelocation)
	if err := removeContainerVolume(filelocation, true); err != nil {
		return created, filelocation, err
	}
	filelocation = ""
	created = false
	log.Infof("destroyOldContainerVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}
