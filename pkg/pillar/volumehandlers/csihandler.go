// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

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
	cfg := handler.volumeManager.LookupVolumeConfig(handler.status.Key())
	if handler.status.ReadOnly || cfg == nil || cfg.HasNoAppReferences {
		handler.log.Noticef("UsageFromStatus: Volume %s use CurrentSize (ReadOnly=%v cfg==nil:%v)",
			handler.status.GetPVCName(), handler.status.ReadOnly, cfg == nil)
		return uint64(handler.status.CurrentSize)
	}
	handler.log.Noticef("UsageFromStatus: Use MaxVolSize for PVC %s",
		handler.status.GetPVCName())
	return handler.status.MaxVolSize
}

func (handler *volumeHandlerCSI) PrepareVolume() error {
	pvcName := handler.status.GetPVCName()
	handler.log.Noticef("PrepareVolume: waiting for Longhorn before creating PVC %s", pvcName)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 1)
	defer func() {
		done <- struct{}{}
	}()

	// Cancel the Longhorn wait if VolumeStatus disappears (volume config deleted while waiting).
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if handler.volumeManager.LookupVolumeStatus(handler.status.Key()) == nil {
					handler.log.Warnf("PrepareVolume: VolumeStatus(%s) disappeared, cancelling Longhorn wait", pvcName)
					cancel()
					return
				}
			case <-done:
				cancel()
				return
			}
		}
	}()

	return kubeapi.WaitForLonghornReady(ctx, handler.log, handler.volumeManager.GetNodeName())
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

	// Guard against re-creation on reboot: if the PVC already exists (created in a
	// prior boot where VolumeStatus was not persisted as CREATED_VOLUME) the
	// content is normally already in place. The exception is a prior attempt that
	// created the PVC but did not finish the CDI image upload (e.g. the cluster
	// was still coming up): fall through and re-drive the upload against the
	// existing PVC rather than declaring the volume done with no data.
	pvcExists := false
	if found, err := kubeapi.FindPVC(pvcName, handler.log); err == nil && found {
		pvcExists = true
		if handler.status.ReferenceName == "" {
			handler.log.Noticef("CreateVolume: PVC %s already exists, skipping creation", pvcName)
			return pvcName, nil
		}
		if uploaded, uerr := kubeapi.IsPVCUploadComplete(pvcName, handler.log); uerr == nil && uploaded {
			handler.log.Noticef("CreateVolume: PVC %s already exists and upload complete, skipping creation", pvcName)
			return pvcName, nil
		}
		handler.log.Noticef("CreateVolume: PVC %s exists but upload not complete, re-driving upload", pvcName)
	}

	repCount, err := kubeapi.GetSupportedReplicaCountForCluster()
	if err != nil {
		handler.log.Errorf("Can't determine dynamic replica count, defaulting to: %d due to: %v", repCount, err)
	}
	storageClassName := kubeapi.GetStorageClassForReplicaCount(repCount)

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

			// This lays out container rootfs directory and creates all bootloader files for EVE 'k'.
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
			pvcerr := kubeapi.RolloutDiskToPVC(createContext, handler.log, pvcExists, rawImgFile, pvcName, false, pvcSize, storageClassName)

			// Since we succeeded or failed to create PVC above, no point in keeping the rawImgFile.
			// Delete it to save space.
			if err = os.RemoveAll(rawImgFile); err != nil {
				errStr := fmt.Sprintf("CreateVolume: exception while deleting: %v. %v", rawImgFile, err)
				handler.log.Error(errStr)
				return pvcName, errors.New(errStr)
			}

			if pvcerr != nil {
				err := fmt.Errorf("Error converting %s to PVC %s: %w",
					rawImgFile, pvcName, pvcerr)
				handler.log.Error(err)
				return pvcName, err
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
			err = kubeapi.RolloutDiskToPVC(createContext, handler.log, pvcExists, qcowFile, pvcName, false, pvcSize, storageClassName)

			if err != nil {
				err = fmt.Errorf("Error converting %s to PVC %s: %w",
					qcowFile, pvcName, err)
				handler.log.Error(err)
				return pvcName, err
			}
		}
	} else {
		err := kubeapi.CreatePVC(pvcName, pvcSize, handler.log, storageClassName)
		if err != nil {
			err = fmt.Errorf("Error creating PVC %s: %w", pvcName, err)
			handler.log.Error(err)
			return "", err
		}
	}

	handler.log.Functionf("CreateVolume(%s) DONE", pvcName)
	return pvcName, nil
}

func (handler *volumeHandlerCSI) DestroyVolume() (string, error) {
	pvcName := handler.status.GetPVCName()
	handler.log.Noticef("DestroyVolume called for PVC %s", pvcName)
	// if this is a replicated volume, do not delete PVC on this node.
	if !handler.status.IsReplicated {
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
	} else {
		// Lets log this to see that PVC delete was skipped because its a replicated PVC.
		handler.log.Noticef("DestroyVolume skip delete PVC %s", pvcName)
	}
	return pvcName, nil
}

// Populate reports whether the PVC for this volume already exists.
// It never returns a non-nil error: all failure cases are treated as
// "not yet created" ((false, nil)) so that handleDeferredVolumeCreate
// routes the volume through the normal create path (PrepareVolume →
// CreateVolume) rather than setting a hard error on VolumeStatus with
// no retry mechanism. Specifically:
//   - Non-replicated, PVC found:            (true,  nil)
//   - Non-replicated, PVC not found (404):  (false, nil)
//   - Non-replicated, any other error:      (false, nil) — transient (kubeconfig
//     unavailable, API server not ready, etc.); CreateVolume guards against
//     double-creation with its own FindPVC check.
//   - Replicated, WaitForPVCReady succeeds: (true,  nil)
//   - Replicated, WaitForPVCReady error:    (false, nil) — loops or returns nil
func (handler *volumeHandlerCSI) Populate() (bool, error) {
	pvcName := handler.status.GetPVCName()
	isReplicated := handler.status.IsReplicated
	// Kubevirt eve volumes have no location on /persist, they are PVCs
	handler.status.FileLocation = pvcName
	// Though we convert container image to PVC, we need to keep the image format to tell domainmgr
	// that we are launching a container as VM.
	if !handler.status.IsContainer() {
		handler.status.ContentFormat = zconfig.Format_PVC
	} else {
		handler.status.ContentFormat = zconfig.Format_CONTAINER
	}
	handler.log.Noticef("Populate called for PVC %s", pvcName)
	// A replicated volume is created on designated node, this node is supposed to be a replica volume.
	// so wait until the replica is created. It could happen that the designated node did not even receive
	// the configuration. This wait can be for long long time.
	if isReplicated {
		for {
			// waitForPVCReady sleeps for 60 secs, so no need to sleep here.
			err := kubeapi.WaitForPVCReady(pvcName, handler.log)
			if err != nil {
				if kerr.IsNotFound(err) {
					handler.log.Noticef("PVC %s not found", pvcName)
					continue
				} else {
					return false, nil
				}
			}
			return true, nil
		}
	} else {
		_, err := kubeapi.FindPVC(pvcName, handler.log)
		if err != nil {
			// Its OK if not found since PVC might not be created yet.
			if kerr.IsNotFound(err) {
				handler.log.Noticef("PVC %s not found", pvcName)
				return false, nil
			}
			// Any other error (kubeconfig unavailable, API server not ready, etc.)
			// is transient — return (false, nil) so handleDeferredVolumeCreate
			// routes this through the normal create path (which waits in PrepareVolume)
			// rather than setting a hard error on VolumeStatus with no retry.
			handler.log.Noticef("Populate: FindPVC(%s) transient error, treating as not-yet-created: %v", pvcName, err)
			return false, nil
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
	handler.log.Error(errStr)
	return nil, errors.New(errStr)
}
