// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumehandlers

import (
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

type volumeHandlerContainer struct {
	commonVolumeHandler
}

func (handler *volumeHandlerContainer) HandleCreated() (bool, error) {
	updateVolumeSizes(handler.log, handler, handler.status)
	return true, nil
}

func (handler *volumeHandlerContainer) GetVolumeDetails() (uint64, uint64, string, bool, error) {
	_, err := os.Stat(handler.status.FileLocation)
	if err != nil {
		return 0, 0, "", false, fmt.Errorf("GetVolumeSize failed for %s: %v",
			handler.status.FileLocation, err)
	}
	var size uint64
	snapshotID := containerd.GetSnapshotID(handler.status.FileLocation)
	su, err := handler.volumeManager.GetCasClient().SnapshotUsage(snapshotID, true)
	if err == nil {
		size = uint64(su)
	} else {
		// we did not create snapshot yet
		handler.log.Warnf("GetVolumeSize: Failed get snapshot usage: %s for %s. Error %s",
			snapshotID, handler.status.FileLocation, err)
		size, err = diskmetrics.SizeFromDir(handler.log, handler.status.FileLocation)
	}
	return size, size, "CONTAINER", false, err
}

func (handler *volumeHandlerContainer) CreateVolume() (string, error) {
	handler.log.Functionf("CreateVolume(%s) from container %s", handler.status.Key(), handler.status.ReferenceName)
	fileLocation := handler.status.PathName()
	ctStatus := handler.volumeManager.LookupContentTreeStatus(handler.status.ContentID.String())
	if ctStatus == nil {
		err := fmt.Errorf("createContainerVolume: Unable to find contentTreeStatus %s for Volume %s",
			handler.status.ContentID.String(), handler.status.Key())
		handler.log.Errorf(err.Error())
		return fileLocation, err
	}
	// First blob in the list will be a root Blob
	rootBlobStatus := handler.volumeManager.LookupBlobStatus(ctStatus.Blobs[0])
	if rootBlobStatus == nil {
		err := fmt.Errorf("createContainerVolume: Unable to find root BlobStatus %s for Volume %s",
			ctStatus.Blobs[0], handler.status.Key())
		handler.log.Errorf(err.Error())
		return fileLocation, err
	}
	if err := handler.volumeManager.GetCasClient().PrepareContainerRootDir(fileLocation, handler.status.ReferenceName, cas.CheckAndCorrectBlobHash(rootBlobStatus.Sha256)); err != nil {
		handler.log.Errorf("Failed to create ctr bundle. Error %s", err)
		return fileLocation, err
	}
	if err := utils.DirSync(fileLocation); err != nil {
		handler.log.Errorf("Failed to sync directory. Error %s", err)
		return fileLocation, err
	}
	handler.log.Functionf("createContainerVolume(%s) DONE", handler.status.Key())
	return fileLocation, nil
}

func (handler *volumeHandlerContainer) DestroyVolume() (string, error) {
	fileLocation := handler.status.FileLocation
	handler.log.Functionf("Removing container volume %s", fileLocation)
	if err := handler.volumeManager.GetCasClient().RemoveContainerRootDir(fileLocation); err != nil {
		return fileLocation, err
	}
	handler.log.Functionf("destroyVolume(%s) DONE", handler.status.Key())
	return "", nil
}

func (handler *volumeHandlerContainer) Populate() (bool, error) {
	if _, err := os.Stat(handler.status.PathName()); err == nil {
		handler.status.FileLocation = handler.status.PathName()
		return true, nil
	}
	return false, nil
}

func (handler *volumeHandlerContainer) CreateSnapshot() (interface{}, time.Time, error) {
	//TODO implement me
	errStr := fmt.Sprintf("CreateSnapshot not implemented for container volumes")
	handler.log.Errorf(errStr)
	timeCreated := time.Time{}
	return "", timeCreated, fmt.Errorf(errStr)
}

func (handler *volumeHandlerContainer) RollbackToSnapshot(snapshotMeta interface{}) error {
	//TODO implement me
	errStr := fmt.Sprintf("RollbackToSnapshot not implemented for container volumes")
	handler.log.Errorf(errStr)
	return fmt.Errorf(errStr)
}

func (handler *volumeHandlerContainer) DeleteSnapshot(snapshotMeta interface{}) error {
	//TODO implement me
	errStr := fmt.Sprintf("DeleteSnapshot not implemented for container volumes")
	handler.log.Errorf(errStr)
	return fmt.Errorf(errStr)
}
