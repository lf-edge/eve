// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// createVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	srcLocation := status.FileLocation
	log.Infof("createVolume(%s) from %s", status.Key(), srcLocation)
	if status.IsContainer() {
		return createContainerVolume(ctx, status, srcLocation)
	} else {
		return createVdiskVolume(ctx, status, srcLocation)
	}
}

// createVdiskVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createVdiskVolume(ctx *volumemgrContext, status types.VolumeStatus,
	srcLocation string) (bool, string, error) {

	created := false
	if status.ReadOnly {
		log.Infof("createVolume(%s) ReadOnly", status.Key())
		created = true // To make doUpdate proceed
		return created, srcLocation, nil
	}

	filelocation := status.PathName()
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
	log.Infof("createVdiskVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// createContainerVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createContainerVolume(ctx *volumemgrContext, status types.VolumeStatus,
	srcLocation string) (bool, string, error) {

	created := false
	filelocation := status.PathName()
	if err := prepareContainerVolume(filelocation, srcLocation); err != nil {
		log.Errorf("Failed to create ctr bundle. Error %s", err)
		return created, filelocation, err
	}
	created = true
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

	if status.IsContainer() {
		return destroyContainerVolume(ctx, status)
	} else {
		return destroyVdiskVolume(ctx, status)
	}
}

// destroyVdiskVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyVdiskVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

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
	log.Infof("destroyVdiskVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// destroyContainerVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyContainerVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	created := status.VolumeCreated
	filelocation := status.FileLocation
	log.Infof("Removing container volume %s", filelocation)
	if err := removeContainerVolume(filelocation, true); err != nil {
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
