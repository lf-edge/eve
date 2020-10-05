// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"fmt"
	"os"

	"github.com/lf-edge/edge-containers/pkg/registry"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// createVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	if status.IsContainer() {
		log.Infof("createVolume(%s) from container %s", status.Key(), status.ReferenceName)
		return createContainerVolume(ctx, status, status.ReferenceName)
	}
	log.Infof("createVolume(%s) from disk %s", status.Key(), status.ReferenceName)
	return createVdiskVolume(ctx, status, status.ReferenceName)
}

// createVdiskVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createVdiskVolume(ctx *volumemgrContext, status types.VolumeStatus,
	ref string) (bool, string, error) {

	created := false

	// this is the target location, where we expect the volume to be
	filelocation := status.PathName()
	if _, err := os.Stat(filelocation); err == nil {
		errStr := fmt.Sprintf("Can not create %s for %s: exists",
			filelocation, status.Key())
		log.Error(errStr)
		return created, "", errors.New(errStr)
	}

	// use the edge-containers library to extract the data we need
	puller := registry.Puller{
		Image: ref,
	}
	resolver, err := ctx.casClient.Resolver()
	if err != nil {
		errStr := fmt.Sprintf("error getting CAS resolver: %v", err)
		log.Error(errStr)
		return created, "", errors.New(errStr)
	}

	// create a writer for the file where we want
	f, err := os.Create(filelocation)
	if err != nil {
		errStr := fmt.Sprintf("error creating target file at %s: %v", filelocation, err)
		log.Error(errStr)
		return created, "", errors.New(errStr)
	}
	defer f.Close()

	if _, _, err := puller.Pull(registry.FilesTarget{Root: f}, false, os.Stderr, resolver); err != nil {
		errStr := fmt.Sprintf("error pulling %s from containerd: %v", ref, err)
		log.Error(errStr)
		return created, "", errors.New(errStr)
	}

	// Do we need to expand disk?
	if err := maybeResizeDisk(filelocation, status.MaxVolSize); err != nil {
		log.Error(err)
		return created, "", err
	}

	log.Infof("Extract DONE from %s to %s", ref, filelocation)

	log.Infof("createVdiskVolume(%s) DONE", status.Key())
	return true, filelocation, nil
}

// createContainerVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createContainerVolume(ctx *volumemgrContext, status types.VolumeStatus,
	ref string) (bool, string, error) {

	created := false

	filelocation := status.PathName()
	ctStatus := lookupContentTreeStatusAny(ctx, status.ContentID.String())
	if ctStatus == nil {
		err := fmt.Errorf("createContainerVolume: Unable to find contentTreeStatus %s for Volume %s",
			status.ContentID.String(), status.VolumeID)
		log.Errorf(err.Error())
		return created, filelocation, err
	}
	//First blob in the list will be a root Blob
	rootBlobStatus := lookupBlobStatus(ctx, ctStatus.Blobs[0])
	if rootBlobStatus == nil {
		err := fmt.Errorf("createContainerVolume: Unable to find root BlobStatus %s for Volume %s",
			ctStatus.Blobs[0], status.VolumeID)
		log.Errorf(err.Error())
		return created, filelocation, err
	}
	if err := ctx.casClient.PrepareContainerRootDir(filelocation, ref, checkAndCorrectBlobHash(rootBlobStatus.Sha256)); err != nil {
		log.Errorf("Failed to create ctr bundle. Error %s", err)
		return created, filelocation, err
	}
	log.Infof("createContainerVolume(%s) DONE", status.Key())
	return true, filelocation, nil
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
	if err := os.RemoveAll(filelocation); err != nil {
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
	if err := ctx.casClient.RemoveContainerRootDir(filelocation); err != nil {
		return created, filelocation, err
	}
	filelocation = ""
	created = false
	log.Infof("destroyContainerVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// Make sure the (virtual) size of the disk is at least maxsizebytes
func maybeResizeDisk(diskfile string, maxsizebytes uint64) error {
	if maxsizebytes == 0 {
		return nil
	}
	currentSize, err := diskmetrics.GetDiskVirtualSize(log, diskfile)
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
	err = diskmetrics.ResizeImg(log, diskfile, maxsizebytes)
	return err
}
