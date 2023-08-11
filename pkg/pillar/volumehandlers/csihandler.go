// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

type volumeHandlerCSI struct {
	commonVolumeHandler
	useVHost bool
	config   *rest.Config
}

type csiContext struct {
	globalConfig *types.ConfigItemValueMap
	config       *rest.Config
}

func (handler *volumeHandlerCSI) GetVolumeDetails() (uint64, uint64, string, bool, error) {
	pvcName := handler.status.Key()
	handler.log.Noticef("GetVolumeDetails called for PVC %s", pvcName)
	imgInfo, err := kubeapi.GetPVCInfo(pvcName)
	if err != nil {
		return 0, 0, "", false, fmt.Errorf("GetPVCInfo failed for %s: %v", pvcName, err)
	}
	return imgInfo.ActualSize, imgInfo.VirtualSize, imgInfo.Format,
		imgInfo.DirtyFlag, nil
}

func (handler *volumeHandlerCSI) UsageFromStatus() uint64 {
	// use MaxVolSize for PVC
	handler.log.Noticef("UsageFromStatus: Use MaxVolSize for PVC %s",
		handler.status.Key())
	return handler.status.MaxVolSize
}

func (handler *volumeHandlerCSI) PrepareVolume() error {
	handler.log.Noticef("PrepareVolume called for PVC %s", handler.status.Key())
	return nil
}

func (handler *volumeHandlerCSI) HandlePrepared() (bool, error) {
	handler.log.Noticef("HandlePrepared called for PVC %s", handler.status.Key())
	return true, nil
}

func (handler *volumeHandlerCSI) HandleCreated() (bool, error) {
	handler.log.Noticef("HandleCreated called for PVC %s", handler.status.Key())
	//handler.status.ContentFormat = zconfig.Format_PVC
	handler.status.ContentFormat = zconfig.Format_RAW
	updateVolumeSizes(handler.log, handler, handler.status)
	return true, nil
}

func (handler *volumeHandlerCSI) CreateVolume() (string, error) {
	// this is the target location, where we expect the volume to be
	// fileLocation := handler.status.PathName()

	createContext := context.Background()

	// we call createCancel to break volume creation process
	// removing of partially created objects must be done inside caller
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

	pvcName := handler.status.Key()
	pvcSize := handler.status.MaxVolSize

	// We cannot create a PVC with size 0. MaxVolSize could be set to 0 for a DOWNLOADED volume.
	// So use the totalsize of downloaded volume.
	if pvcSize == 0 {
		pvcSize = uint64(handler.status.TotalSize)
	}
	handler.log.Noticef("CreateVolume called for PVC %s size %v", pvcName, pvcSize)
	err := kubeapi.CreatePVC(pvcName, pvcSize)
	if err != nil {
		errStr := fmt.Sprintf("Error creating PVC %s", pvcName)
		handler.log.Error(errStr)
		return "", errors.New(errStr)
	}

	if handler.status.ReferenceName != "" {
		pathToFile, err := handler.getVolumeFilePath()
		if err != nil {
			errStr := fmt.Sprintf("Error obtaining file for PVC at volume %s, error=%v",
				pvcName, err)
			handler.log.Error(errStr)
			return "", errors.New(errStr)
		}
		if err := diskmetrics.RolloutImgToPVC(createContext, handler.log, pathToFile, pvcName, "pvc"); err != nil {
			errStr := fmt.Sprintf("Error converting %s to PVC %s: %v",
				pathToFile, pvcName, err)
			handler.log.Error(errStr)
			return pvcName, errors.New(errStr)
		}
	}

	handler.log.Functionf("CreateVolume(%s) DONE", pvcName)
	return pvcName, nil
}

func (handler *volumeHandlerCSI) DestroyVolume() (string, error) {
	pvcName := handler.status.Key()
	handler.log.Noticef("DestroyVolume called for PVC %s", pvcName)
	err := kubeapi.DeletePVC(pvcName)
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
	handler.log.Noticef("Populate called for PVC %s", handler.status.Key())
	_, err := kubeapi.FindPVC(handler.status.Key())
	if err != nil {
		// Its OK if not found since PVC might not be created yet.
		if kerr.IsNotFound(err) {
			handler.log.Noticef("PVC %s not found", handler.status.Key())
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
