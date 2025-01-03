// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package volumehandlers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lf-edge/edge-containers/pkg/registry"
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

const imageToQcowScript = "/opt/zededa/bin/copy-image-to-qcow.sh"

type volumeHandlerCSI struct {
	commonVolumeHandler
	useVHost bool
	config   *rest.Config
}

// NewCSIHandler is a constructor for the kubernetes CSI handler.
func NewCSIHandler(common commonVolumeHandler, useVHost bool) VolumeHandler {
	return &volumeHandlerCSI{
		commonVolumeHandler: common,
		useVHost:            useVHost,
	}
}

func (handler *volumeHandlerCSI) GetVolumeDetails() (uint64, uint64, string, bool, error) {
	pvcName := handler.status.GetPVCName()
	handler.log.Noticef("GetVolumeDetails called for PVC %s", pvcName)
	imgInfo, err := kubeapi.GetPVCInfo(pvcName, handler.log)
	if err != nil {
		return 0, 0, "", false, fmt.Errorf("GetPVCInfo failed for %s: %v", pvcName, err)
	}
	return imgInfo.ActualSize, imgInfo.VirtualSize, imgInfo.Format,
		imgInfo.DirtyFlag, nil
}

func (handler *volumeHandlerCSI) UsageFromStatus() uint64 {
	// use MaxVolSize for PVC
	handler.log.Noticef("UsageFromStatus: Use MaxVolSize for PVC %s",
		handler.status.GetPVCName())
	return handler.status.MaxVolSize
}

func (handler *volumeHandlerCSI) PrepareVolume() error {
	handler.log.Noticef("PrepareVolume called for PVC %s", handler.status.GetPVCName())
	return nil
}

func (handler *volumeHandlerCSI) HandlePrepared() (bool, error) {
	handler.log.Noticef("HandlePrepared called for PVC %s", handler.status.GetPVCName())
	return true, nil
}

func (handler *volumeHandlerCSI) HandleCreated() (bool, error) {
	handler.log.Noticef("HandleCreated called for PVC %s", handler.status.GetPVCName())
	// Though we convert container image to PVC, we need to keep the image format to tell domainmgr
	// that we are launching a container as VM.
	if !handler.status.IsContainer() {
		handler.status.ContentFormat = zconfig.Format_PVC
	}
	updateVolumeSizes(handler.log, handler, handler.status)
	return true, nil
}

func (handler *volumeHandlerCSI) CreateVolume() (string, error) {

	createContext := context.Background()

	// we call createCancel to break volume creation process
	// removing of partially created objects must be done inside caller
	createContext, createCancel := context.WithCancel(createContext)

	done := make(chan struct{}, 1)

	defer func() {
		done <- struct{}{}
	}()

	go func() {
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				st := handler.volumeManager.LookupVolumeStatus(handler.status.Key())
				// it disappears in case of deleting of volume config
				if st == nil {
					handler.log.Warnf("CreateVolume: VolumeStatus(%s) disappear during creation", handler.status.Key())
					createCancel()
					return
				}
			case <-done:
				createCancel()
				return
			}
		}
	}()

	pvcName := handler.status.GetPVCName()
	pvcSize := handler.status.MaxVolSize

	// We cannot create a PVC with size 0. MaxVolSize could be set to 0 for a DOWNLOADED volume.
	// So use the totalsize of downloaded volume.
	if pvcSize == 0 {
		pvcSize = uint64(handler.status.TotalSize)
	}
	handler.log.Noticef("CreateVolume called for PVC %s size %v", pvcName, pvcSize)

	// Reference Name is set for downloaded volumes. virtctl in RolloutImgToPVC can create PVC if not exists
	// so we need not explicitly create the PVC here.
	if handler.status.ReferenceName != "" {

		// If this is an image in container format, then convert it to qcow2
		// Some app images are already in qcow2 format, then just proceed to next step
		// Downloaded volumes are almost always in qcow2 format
		if handler.status.IsContainer() {

			// This is a multistep process.
			// 1) Use container volume handler to Prepare a containerimage rootdir
			// 2) Call CopyImgDirToRawImg to convert the rootdir to a qcow2 file
			// NOTE: This qcow2 will be converted to PVC in later steps.
			// For container images we convert to qcow2 file under /persist/vault/volumes/pvcName.qcow2

			rawImgFile := "/persist/vault/volumes/" + pvcName + ".img"

			chandler := &volumeHandlerContainer{handler.commonVolumeHandler}

			// This lays out container rootfs directory and creates all bootloader files for kubevirt eve.
			imgDirLocation, err := chandler.CreateVolume()

			handler.log.Noticef("After CreateVolume fileloc %s err %v", imgDirLocation, err)

			if err != nil {
				errStr := fmt.Sprintf("Error CreateVolume %s err: %v",
					imgDirLocation, err)
				handler.log.Error(errStr)
				return "", errors.New(errStr)
			}

			err = handler.CopyImgDirToRawImg(createContext, handler.log, imgDirLocation, rawImgFile)
			if err != nil {
				errStr := fmt.Sprintf("Error copying container image to raw image %s err: %v",
					imgDirLocation, err)
				handler.log.Error(errStr)
				return "", errors.New(errStr)
			}

			chandler.status.FileLocation = imgDirLocation
			// If we are here, we converted container image to rawImgFile, no reason to keep the containerdir
			// So delete the container image mount we created as part of CreateVolume() above
			// DestroyVolume() just umounts rootfs and deletes the container directory in /persist/vault/volumes.
			// It does not delete the image, which is what we want.
			imgDirLocation, err = chandler.DestroyVolume()
			if err != nil {
				errStr := fmt.Sprintf("Error DestroyVolume %s err: %v",
					imgDirLocation, err)
				handler.log.Error(errStr)
				return "", errors.New(errStr)
			}

			// Convert to PVC
			pvcerr := kubeapi.RolloutDiskToPVC(createContext, handler.log, false, rawImgFile, pvcName, false, pvcSize)

			// Since we succeeded or failed to create PVC above, no point in keeping the rawImgFile.
			// Delete it to save space.
			if err = os.RemoveAll(rawImgFile); err != nil {
				errStr := fmt.Sprintf("CreateVolume: exception while deleting: %v. %v", rawImgFile, err)
				handler.log.Error(errStr)
				return pvcName, errors.New(errStr)
			}

			if pvcerr != nil {
				errStr := fmt.Sprintf("Error converting %s to PVC %s: %v",
					rawImgFile, pvcName, pvcerr)
				handler.log.Error(errStr)
				return pvcName, errors.New(errStr)
			}
		} else {
			qcowFile, err := handler.getVolumeFilePath()
			if err != nil {
				errStr := fmt.Sprintf("Error obtaining file for PVC at volume %s, error=%v",
					pvcName, err)
				handler.log.Error(errStr)
				return pvcName, errors.New(errStr)
			}
			// Convert qcow2 to PVC
			err = kubeapi.RolloutDiskToPVC(createContext, handler.log, false, qcowFile, pvcName, false, pvcSize)

			if err != nil {
				errStr := fmt.Sprintf("Error converting %s to PVC %s: %v",
					qcowFile, pvcName, err)
				handler.log.Error(errStr)
				return pvcName, errors.New(errStr)
			}
		}
	} else {
		err := kubeapi.CreatePVC(pvcName, pvcSize, handler.log)
		if err != nil {
			errStr := fmt.Sprintf("Error creating PVC %s", pvcName)
			handler.log.Error(errStr)
			return "", errors.New(errStr)
		}
	}

	handler.log.Functionf("CreateVolume(%s) DONE", pvcName)
	return pvcName, nil
}

func (handler *volumeHandlerCSI) DestroyVolume() (string, error) {
	pvcName := handler.status.GetPVCName()
	handler.log.Noticef("DestroyVolume called for PVC %s", pvcName)
	err := kubeapi.DeletePVC(pvcName, handler.log)
	if err != nil {
		// Its OK if not found since PVC might have been deleted already
		if kerr.IsNotFound(err) {
			handler.log.Noticef("PVC %s not found, might have been deleted", pvcName)
			return pvcName, nil
		} else {
			return pvcName, err
		}
	}
	return pvcName, nil
}

func (handler *volumeHandlerCSI) Populate() (bool, error) {
	pvcName := handler.status.GetPVCName()
	handler.status.FileLocation = pvcName
	handler.log.Noticef("Populate called for PVC %s", pvcName)
	_, err := kubeapi.FindPVC(pvcName, handler.log)
	if err != nil {
		// Its OK if not found since PVC might not be created yet.
		if kerr.IsNotFound(err) {
			handler.log.Noticef("PVC %s not found", pvcName)
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}

// Copied from zvolhandler.go
func (handler *volumeHandlerCSI) getVolumeFilePath() (string, error) {
	puller := registry.Puller{
		Image: handler.status.ReferenceName,
	}
	ctrdCtx, done := handler.volumeManager.GetCasClient().CtrNewUserServicesCtx()
	defer done()

	resolver, err := handler.volumeManager.GetCasClient().Resolver(ctrdCtx)
	if err != nil {
		errStr := fmt.Sprintf("error getting CAS resolver: %v", err)
		handler.log.Error(errStr)
		return "", errors.New(errStr)
	}
	pathToFile := ""
	_, i, err := puller.Config(true, os.Stderr, resolver)
	if err != nil {
		errStr := fmt.Sprintf("error Config for ref %s: %v", handler.status.ReferenceName, err)
		handler.log.Error(errStr)
		return "", errors.New(errStr)
	}
	if len(i.RootFS.DiffIDs) > 0 {
		// FIXME we expects root in the first layer for now
		b := i.RootFS.DiffIDs[0]
		// FIXME we need the proper way to extract file from content dir of containerd
		pathToFile = filepath.Join(types.ContainerdContentDir, "blobs", b.Algorithm().String(), b.Encoded())
	}

	if pathToFile == "" {
		errStr := fmt.Sprintf("no blobs to convert found for ref %s", handler.status.ReferenceName)
		handler.log.Error(errStr)
		return "", errors.New(errStr)
	}
	return pathToFile, nil
}

// Creates a dest qcow2 file from the srcLocation
func (handler *volumeHandlerCSI) CopyImgDirToRawImg(ctx context.Context, log *base.LogObject, srcLocation string, destFile string) error {

	args := []string{srcLocation, destFile}

	log.Noticef("%s args %v", imageToQcowScript, args)

	output, err := base.Exec(log, imageToQcowScript, args...).WithContext(ctx).WithUnlimitedTimeout(120 * time.Hour).CombinedOutput()

	if err != nil {
		return fmt.Errorf("CopyImgDirToRawImg: Failed to create raw image file  %s: %w", output, err)
	}

	return nil
}

func (handler *volumeHandlerCSI) CreateSnapshot() (interface{}, time.Time, error) {
	//TODO implement me
	errStr := fmt.Sprintf("CreateSnapshot not implemented for CSI")
	handler.log.Error(errStr)
	err := errors.New(errStr)
	timeCreated := time.Time{}
	return "", timeCreated, err
}

func (handler *volumeHandlerCSI) RollbackToSnapshot(snapshotMeta interface{}) error {
	//TODO implement me
	errStr := fmt.Sprintf("RollbackToSnapshot not implemented for CSI")
	handler.log.Error(errStr)
	err := errors.New(errStr)
	return err
}

func (handler *volumeHandlerCSI) DeleteSnapshot(snapshotMeta interface{}) error {
	//TODO implement me
	errStr := fmt.Sprintf("DeleteSnapshot not implemented for CSI")
	handler.log.Error(errStr)
	err := errors.New(errStr)
	return err
}

func (handler *volumeHandlerCSI) GetAllDataSets() ([]types.ImgInfo, error) {
	errStr := fmt.Sprintf("GetAllDataSets not implemented for container volumes")
	handler.log.Errorf(errStr)
	return nil, fmt.Errorf(errStr)
}
