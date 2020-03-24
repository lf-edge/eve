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
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	log "github.com/sirupsen/logrus"
)

// Returns changed if VolumeStatus changed
func createVolume(ctx *volumemgrContext, status *types.VolumeStatus, srcLocation string) (bool, error) {

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
	return false, nil
}

func createVdiskVolume(ctx *volumemgrContext, status *types.VolumeStatus, srcLocation string) (bool, error) {

	changed := false
	if status.ReadOnly {
		log.Infof("createVolume(%s) ReadOnly", status.Key())
		status.FileLocation = srcLocation
		changed = true
		return changed, nil
	}

	filelocation := appRwVolumeName(status.BlobSha256, status.AppInstID.String(),
		// XXX in general status.VolumeID,
		status.PurgeCounter, status.Format, status.Origin)

	if _, err := os.Stat(filelocation); err == nil {
		errStr := fmt.Sprintf("Can not create %s for %s: exists",
			filelocation, status.Key())
		log.Error(errStr)
		return false, errors.New(errStr)
	}
	log.Infof("Copy from %s to %s\n", srcLocation, filelocation)
	status.VolumeCreated = true
	changed = true
	if err := cp(filelocation, srcLocation); err != nil {
		errStr := fmt.Sprintf("Copy failed from %s to %s: %s\n",
			srcLocation, filelocation, err)
		log.Error(errStr)
		return changed, errors.New(errStr)
	}
	status.FileLocation = filelocation

	// Do we need to expand disk?
	err := maybeResizeDisk(status.FileLocation, status.TargetSizeBytes)
	if err != nil {
		log.Error(err)
		return changed, err
	}
	log.Infof("Copy DONE from %s to %s\n", srcLocation, status.FileLocation)
	log.Infof("createVdiskVolume(%s) DONE", status.Key())
	return changed, nil
}

func createContainerVolume(ctx *volumemgrContext, status *types.VolumeStatus, srcLocation string) (bool, error) {

	changed := false
	filelocation := getContainerPath(status.AppInstID.String())
	status.FileLocation = filelocation
	changed = true

	ociFilename, err := utils.VerifiedImageFileLocation(status.ContainerSha256)
	if err != nil {
		errStr := fmt.Sprintf("failed to get Image File Location. err: %+s",
			err)
		log.Error(errStr)
		return changed, errors.New(errStr)
	}
	log.Infof("ociFilename %s sha %s", ociFilename, status.ContainerSha256)
	if err := ctrPrepare(filelocation, ociFilename); err != nil {
		log.Errorf("Failed to create ctr bundle. Error %s", err)
		return changed, err
	}
	log.Infof("createContainerVolume(%s) DONE", status.Key())
	return changed, nil
}

// Returns changed if VolumeStatus changed
func destroyVolume(ctx *volumemgrContext, status *types.VolumeStatus) (bool, error) {
	changed := false

	log.Infof("destroyVolume(%s)", status.Key())
	if !status.VolumeCreated {
		log.Infof("destroyVolume(%s) nothing was created", status.Key())
		return changed, nil
	}

	if status.ReadOnly {
		log.Infof("destroyVolume(%s) ReadOnly", status.Key())
		status.FileLocation = ""
		changed = true
		return changed, nil
	}

	if status.FileLocation == "" {
		log.Errorf("destroyVolume(%s) no FileLocation", status.Key())
		return changed, nil
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
	return false, nil
}

func destroyVdiskVolume(ctx *volumemgrContext, status *types.VolumeStatus) (bool, error) {

	changed := false
	log.Infof("Delete copy at %s\n", status.FileLocation)
	if err := os.Remove(status.FileLocation); err != nil {
		log.Error(err)
		status.FileLocation = ""
		changed = true
		return changed, err
	}
	status.FileLocation = ""
	changed = true
	log.Infof("destroyVdiskVolume(%s) DONE", status.Key())
	return changed, nil
}

func destroyContainerVolume(ctx *volumemgrContext, status *types.VolumeStatus) (bool, error) {

	changed := false
	log.Infof("Removing container volume %s", status.FileLocation)
	if err := ctrRm(status.FileLocation, false); err != nil {
		return changed, err
	}
	status.FileLocation = ""
	changed = true
	log.Infof("destroyContainerVolume(%s) DONE", status.Key())
	return changed, nil
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
