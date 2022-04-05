// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/edge-containers/pkg/registry"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/tgt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

// createVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	if status.IsContainer() {
		log.Functionf("createVolume(%s) from container %s", status.Key(), status.ReferenceName)
		return createContainerVolume(ctx, status, status.ReferenceName)
	}
	log.Functionf("createVolume(%s) from disk %s", status.Key(), status.ReferenceName)
	return createVdiskVolume(ctx, status, status.ReferenceName)
}

// createVdiskVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func createVdiskVolume(ctx *volumemgrContext, status types.VolumeStatus,
	ref string) (bool, string, error) {

	created := false

	persistFsType := ctx.persistType

	// this is the target location, where we expect the volume to be
	filelocation := status.PathName()

	createContext := context.Background()

	//we call createCancel to break volume creation process
	//removing of partially created objects must be done inside caller
	createContext, createCancel := context.WithCancel(createContext)

	done := make(chan bool, 1)

	defer func() {
		done <- true
	}()

	go func() {
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				st := lookupVolumeStatus(ctx, status.Key())
				//it disappears in case of deleting of volume config
				if st == nil {
					log.Warnf("createVdiskVolume: VolumeStatus(%s) disappear during creation", status.Key())
					createCancel()
					return
				}
			case <-done:
				createCancel()
				return
			}
		}
	}()

	if persistFsType != types.PersistZFS {
		if _, err := os.Stat(filelocation); err == nil {
			errStr := fmt.Sprintf("Can not create %s for %s: exists",
				filelocation, status.Key())
			log.Error(errStr)
			return created, "", errors.New(errStr)
		}
	}

	switch persistFsType {
	case types.PersistZFS:
		zVolName := status.ZVolName()
		zVolDevice := zfs.GetZVolDeviceByDataset(zVolName)
		if zVolDevice == "" {
			errStr := fmt.Sprintf("Error finding zfs zvol %s", zVolName)
			log.Error(errStr)
			return created, "", errors.New(errStr)
		}
		if ref != "" {
			pathToFile, err := getVolumeFilePath(ctx, status)
			if err != nil {
				errStr := fmt.Sprintf("Error obtaining file for zvol at volume %s, error=%v",
					status.Key(), err)
				log.Error(errStr)
				return created, "", errors.New(errStr)
			}
			if err := diskmetrics.ConvertImg(createContext, log, pathToFile, zVolDevice, "raw"); err != nil {
				errStr := fmt.Sprintf("Error converting %s to zfs zvol %s: %v",
					pathToFile, zVolDevice, err)
				log.Error(errStr)
				return created, zVolDevice, errors.New(errStr)
			}
		}
		filelocation = zVolDevice
	default:
		if ref != "" {
			// use the edge-containers library to extract the data we need
			puller := registry.Puller{
				Image: ref,
			}

			casClient, err := cas.NewCAS(casClientType)
			if err != nil {
				err = fmt.Errorf("Run: exception while initializing CAS client: %s", err.Error())
				return created, "", err
			}
			defer casClient.CloseClient()

			//redefine createContext and createCancel with values received from cas
			//we call createCancel to cancel creating process
			createContext, createCancel = casClient.CtrNewUserServicesCtx()

			resolver, err := casClient.Resolver(createContext)
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
			if _, _, err := puller.Pull(&registry.FilesTarget{Root: f, AcceptHash: true}, 0, false, os.Stderr, resolver); err != nil {
				errStr := fmt.Sprintf("error pulling %s from containerd: %v", ref, err)
				log.Error(errStr)
				return created, filelocation, errors.New(errStr)
			}
			// Do we need to expand disk?
			if err := maybeResizeDisk(createContext, filelocation, status.MaxVolSize); err != nil {
				log.Error(err)
				return created, filelocation, err
			}
		} else {
			if err := diskmetrics.CreateImg(createContext, log, filelocation, strings.ToLower(status.ContentFormat.String()), status.MaxVolSize); err != nil {
				log.Error(err)
				return created, filelocation, err
			}
		}
	}

	log.Functionf("Extract DONE from %s to %s", ref, filelocation)

	log.Functionf("createVdiskVolume(%s) DONE", status.Key())
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
			status.ContentID.String(), status.Key())
		log.Errorf(err.Error())
		return created, filelocation, err
	}
	//First blob in the list will be a root Blob
	rootBlobStatus := lookupBlobStatus(ctx, ctStatus.Blobs[0])
	if rootBlobStatus == nil {
		err := fmt.Errorf("createContainerVolume: Unable to find root BlobStatus %s for Volume %s",
			ctStatus.Blobs[0], status.Key())
		log.Errorf(err.Error())
		return created, filelocation, err
	}
	if err := ctx.casClient.PrepareContainerRootDir(filelocation, ref, checkAndCorrectBlobHash(rootBlobStatus.Sha256)); err != nil {
		log.Errorf("Failed to create ctr bundle. Error %s", err)
		return created, filelocation, err
	}
	log.Functionf("createContainerVolume(%s) DONE", status.Key())
	return true, filelocation, nil
}

// destroyVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	log.Functionf("destroyVolume(%s)", status.Key())
	// we have no explicit un-prepare action for now, so it works with prepared or created volumes
	if status.SubState != types.VolumeSubStateCreated && status.SubState != types.VolumeSubStatePrepareDone {
		log.Functionf("destroyVolume(%s) nothing was created/prepared", status.Key())
		return false, status.FileLocation, nil
	}

	if status.ReadOnly {
		log.Functionf("destroyVolume(%s) ReadOnly", status.Key())
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

	created := status.SubState == types.VolumeSubStateCreated
	filelocation := status.FileLocation
	log.Functionf("Delete copy at %s", filelocation)

	info, err := os.Stat(filelocation)
	if err != nil {
		errStr := fmt.Sprintf("Error get stat of file %s: %v",
			filelocation, err)
		return created, "", errors.New(errStr)
	}
	if info.Mode()&os.ModeDevice != 0 {
		if err := tgt.VHostDeleteIBlock(status.WWN); err != nil {
			errStr := fmt.Sprintf("Error deleting vhost for %s, error=%v",
				status.Key(), err)
			log.Error(errStr)
		}
		if err := tgt.TargetDeleteIBlock(status.Key()); err != nil {
			errStr := fmt.Sprintf("Error deleting target for %s, error=%v",
				status.Key(), err)
			log.Error(errStr)
		}
		//Assume this is zfs device
		zVolName := status.ZVolName()
		if stdoutStderr, err := zfs.DestroyDataset(log, zVolName); err != nil {
			errStr := fmt.Sprintf("Error destroying zfs zvol at %s, error=%v, output=%s",
				zVolName, err, stdoutStderr)
			log.Error(errStr)
			return created, "", errors.New(errStr)
		}
	} else {
		if err := os.RemoveAll(filelocation); err != nil {
			log.Error(err)
			return created, "", err
		}
	}
	filelocation = ""
	created = false
	log.Functionf("destroyVdiskVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// destroyContainerVolume does not update status but returns
// new values for VolumeCreated, FileLocation, and error
func destroyContainerVolume(ctx *volumemgrContext, status types.VolumeStatus) (bool, string, error) {

	created := status.SubState == types.VolumeSubStateCreated
	filelocation := status.FileLocation
	log.Functionf("Removing container volume %s", filelocation)
	if err := ctx.casClient.RemoveContainerRootDir(filelocation); err != nil {
		return created, filelocation, err
	}
	filelocation = ""
	created = false
	log.Functionf("destroyContainerVolume(%s) DONE", status.Key())
	return created, filelocation, nil
}

// returns size and indicates do we need to resize disk to be at least maxsizebytes
func checkResizeDisk(diskfile string, maxsizebytes uint64) (uint64, bool, error) {
	vSize, err := diskmetrics.GetDiskVirtualSize(log, diskfile)
	if err != nil {
		return 0, false, err
	}
	if vSize > maxsizebytes {
		log.Warnf("Virtual size (%d) of provided volume(%s) is larger than provided MaxVolSize (%d). "+
			"Will use virtual size.", vSize, diskfile, maxsizebytes)
		return vSize, false, nil
	}
	return maxsizebytes, vSize != maxsizebytes, nil
}

// Make sure the (virtual) size of the disk is at least maxsizebytes
func maybeResizeDisk(ctx context.Context, diskfile string, maxsizebytes uint64) error {
	if maxsizebytes == 0 {
		return nil
	}
	log.Functionf("maybeResizeDisk(%s) current to %d",
		diskfile, maxsizebytes)
	size, resize, err := checkResizeDisk(diskfile, maxsizebytes)
	if err != nil {
		return fmt.Errorf("maybeResizeDisk checkResizeDisk error: %s", err)
	}
	if resize {
		log.Functionf("maybeResizeDisk(%s) resize to %d",
			diskfile, size)
		return diskmetrics.ResizeImg(ctx, log, diskfile, size)
	}
	return nil
}

//createTargetVhost creates target and vhost for device using information from VolumeStatus
//and returns wwn to use for mounting
func createTargetVhost(device string, status *types.VolumeStatus) (string, error) {
	defer func(start time.Time) {
		log.Functionf("createTargetVhost ended after %s", time.Since(start))
	}(time.Now())
	serial := tgt.GenerateNaaSerial()
	wwn := fmt.Sprintf("naa.%s", serial)
	err := tgt.TargetCreateIBlock(device, status.Key(), serial)
	if err != nil {
		return "", fmt.Errorf("TargetCreateFileIODev(%s, %s, %s): %v",
			device, status.Key(), serial, err)
	}
	if !tgt.CheckVHostIBlock(status.Key()) {
		err = tgt.VHostCreateIBlock(status.Key(), wwn)
		if err != nil {
			errString := fmt.Sprintf("VHostCreateIBlock: %v", err)
			err = tgt.VHostDeleteIBlock(wwn)
			if err != nil {
				errString = fmt.Sprintf("%s; VHostDeleteIBlock: %v",
					errString, err)
			}
			return "", fmt.Errorf("VHostCreateIBlock(%s, %s): %s",
				status.Key(), wwn, errString)
		}
	}
	return wwn, nil
}
