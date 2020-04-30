// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	log "github.com/sirupsen/logrus"
)

// createVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	srcLocation := status.FileLocation
	log.Infof("createVolume(%s) from %s", status.Key(), srcLocation)
	switch status.Origin {
	case types.OriginTypeDownload:
		if status.Format == zconfig.Format_CONTAINER {
			return createContainerVolume(ctx, status, srcLocation)
		} else {
			return createVdiskVolume(ctx, status, srcLocation)
		}
	default:
		log.Fatalf("XXX unsupported origin %v", status.Origin)
	}
	return false, "", nil
}

// createVdiskVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createVdiskVolume(ctx *volumemgrContext, status types.VolumeStatus, srcLocation string) (bool, string, error) {

	created := false
	if status.ReadOnly {
		log.Infof("createVolume(%s) ReadOnly", status.Key())
		created = true // To make doUpdate proceed
		return created, srcLocation, nil
	}

	filelocation := appRwVolumeName(status.BlobSha256, status.AppInstID.String(),
		// XXX in general status.VolumeID,
		status.PurgeCounter, status.Format, status.Origin)

	if _, err := os.Stat(filelocation); err == nil {
		errStr := fmt.Sprintf("Can not create %s for %s: exists",
			filelocation, status.Key())
		log.Error(errStr)
		return created, srcLocation, errors.New(errStr)
	}
	log.Infof("Copy from %s to %s\n", srcLocation, filelocation)
	created = true // So we will delete later even if partial failure
	if err := cp(filelocation, srcLocation); err != nil {
		errStr := fmt.Sprintf("Copy failed from %s to %s: %s\n",
			srcLocation, filelocation, err)
		log.Error(errStr)
		return created, filelocation, errors.New(errStr)
	}
	// Do we need to expand disk?
	err := maybeResizeDisk(filelocation, status.TargetSizeBytes)
	if err != nil {
		log.Error(err)
		return created, filelocation, err
	}
	log.Infof("Copy DONE from %s to %s\n", srcLocation, status.FileLocation)
	log.Infof("createVdiskVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// createContainerVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createContainerVolume(ctx *volumemgrContext, status types.VolumeStatus, srcLocation string) (bool, string, error) {

	created := false
	filelocation := containerd.GetContainerPath(status.AppInstID.String())

	ociFilename, err := utils.VerifiedImageFileLocation(status.ContainerSha256)
	if err != nil {
		errStr := fmt.Sprintf("failed to get Image File Location. err: %+s",
			err)
		log.Error(errStr)
		return created, filelocation, errors.New(errStr)
	}
	log.Infof("ociFilename %s sha %s", ociFilename, status.ContainerSha256)
	created = true
	if err := containerd.SnapshotPrepare(filelocation, ociFilename); err != nil {
		log.Errorf("Failed to create ctr bundle. Error %s", err)
		return created, filelocation, err
	}
	log.Infof("createContainerVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// destroyVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	log.Infof("destroyVolume(%s)", status.Key())
	if !status.VolumeCreated {
		log.Infof("destroyVolume(%s) nothing was created", status.Key())
		return false, status.FileLocation, nil
	}

	if status.ReadOnly {
		log.Infof("destroyVolume(%s) ReadOnly", status.Key())
		return false, "", nil
	}

	if status.FileLocation == "" {
		log.Errorf("destroyVolume(%s) no FileLocation", status.Key())
		return false, "", nil
	}

	switch status.Origin {
	case types.OriginTypeDownload:
		if status.Format == zconfig.Format_CONTAINER {
			return destroyContainerVolume(ctx, status)
		} else {
			return destroyVdiskVolume(ctx, status)
		}
	default:
		log.Fatalf("XXX unsupported origin %v", status.Origin)
	}
	return false, "", nil
}

// destroyVdiskVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyVdiskVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	created := status.VolumeCreated
	filelocation := status.FileLocation
	log.Infof("Delete copy at %s\n", filelocation)
	if err := os.Remove(filelocation); err != nil {
		log.Error(err)
		filelocation = ""
		return created, filelocation, err
	}
	filelocation = ""
	created = false
	log.Infof("destroyVdiskVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// destroyContainerVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyContainerVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	created := status.VolumeCreated
	filelocation := status.FileLocation
	log.Infof("Removing container volume %s", filelocation)
	if err := containerd.SnapshotRm(filelocation, false); err != nil {
		return created, filelocation, err
	}
	filelocation = ""
	created = false
	log.Infof("destroyContainerVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

func cp(dst, src string) error {
	if strings.Compare(dst, src) == 0 {
		log.Fatalf("Same src and dst: %s", src)
	}
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	// no need to check errors on read only file, we already got everything
	// we need from the filesystem, so nothing can go wrong now.
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(d, s); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// Make sure the (virtual) size of the disk is at least maxsizebytes
func maybeResizeDisk(diskfile string, maxsizebytes uint64) error {
	if maxsizebytes == 0 {
		return nil
	}
	currentSize, err := diskmetrics.GetDiskVirtualSize(diskfile)
	if err != nil {
		return err
	}
	log.Infof("maybeResizeDisk(%s) current %d to %d",
		diskfile, currentSize, maxsizebytes)
	if maxsizebytes < currentSize {
		log.Warnf("maybeResizeDisk(%s) already above maxsize  %d vs. %d",
			diskfile, maxsizebytes, currentSize)
		return nil
	}
	err = diskmetrics.ResizeImg(diskfile, maxsizebytes)
	return err
}
