// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumehandlers

import (
	//	"context"
	"errors"
	"fmt"

	//	"os"
	//	"path/filepath"
	"time"

	//	"github.com/lf-edge/edge-containers/pkg/registry"
	zconfig "github.com/lf-edge/eve-api/go/config"
	//	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	//	"github.com/lf-edge/eve/pkg/pillar/tgt"
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
	handler.status.ContentFormat = zconfig.Format_RAW // For now, should be PVC
	updateVolumeSizes(handler.log, handler, handler.status)
	return true, nil
}

func (handler *volumeHandlerCSI) CreateVolume() (string, error) {
	pvcName := handler.status.Key()
	pvcSize := handler.status.MaxVolSize
	handler.log.Noticef("CreateVolume called for PVC %s size %v", pvcName, pvcSize)
	err := kubeapi.CreatePVC(pvcName, pvcSize)
	if err != nil {
		return pvcName, err
	}

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

func (handler *volumeHandlerCSI) getVolumeFilePath() (string, error) {
	// PVC has no filepath, so just return the name
	handler.log.Noticef("getVolumeFilePath called for PVC %s", handler.status.Key())
	return handler.status.Key(), nil
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
