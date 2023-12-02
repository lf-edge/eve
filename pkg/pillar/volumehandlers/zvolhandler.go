// Copyright (c) 2022 Zededa, Inc.
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
	"github.com/lf-edge/eve/pkg/pillar/tgt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

type volumeHandlerZVol struct {
	commonVolumeHandler
	useVHost bool
}

func (handler *volumeHandlerZVol) GetVolumeDetails() (uint64, uint64, string, bool, error) {
	_, err := os.Stat(handler.status.FileLocation)
	if err != nil {
		return 0, 0, "", false, fmt.Errorf("GetVolumeSize failed for %s: %v",
			handler.status.FileLocation, err)
	}
	//Assume this is zfs device
	imgInfo, err := zfs.GetZFSVolumeInfo(handler.status.FileLocation)
	if err != nil {
		return 0, 0, "", false, fmt.Errorf("GetVolumeSize/GetZFSInfo failed for %s: %v",
			handler.status.FileLocation, err)
	}
	return imgInfo.ActualSize, imgInfo.VirtualSize, imgInfo.Format,
		imgInfo.DirtyFlag, nil
}

func (handler *volumeHandlerZVol) UsageFromStatus() uint64 {
	// use MaxVolSize for zvol
	handler.log.Noticef("UsageFromStatus: Use MaxVolSize for Volume %s",
		handler.status.Key())
	return handler.status.MaxVolSize
}

func (handler *volumeHandlerZVol) PrepareVolume() error {
	size := handler.status.MaxVolSize
	if handler.status.ReferenceName != "" {
		pathToFile, err := handler.getVolumeFilePath()
		if err != nil {
			errStr := fmt.Sprintf("Error obtaining file for zvol at volume %s, error=%v",
				handler.status.Key(), err)
			handler.log.Error(errStr)
			return errors.New(errStr)
		}
		size, _, err = diskmetrics.CheckResizeDisk(handler.log, pathToFile, handler.status.MaxVolSize)
		if err != nil {
			errStr := fmt.Sprintf("Error creating zfs zvol at checkResizeDisk %s, error=%v",
				pathToFile, err)
			handler.log.Error(errStr)
			return errors.New(errStr)
		}
	}
	zVolName := handler.status.ZVolName()
	if err := zfs.CreateVolumeDataset(handler.log, zVolName, size, "zstd", zfs.VolBlockSize); err != nil {
		errStr := fmt.Sprintf("Error creating zfs zvol at %s, error=%v",
			zVolName, err)
		handler.log.Error(errStr)
		return errors.New(errStr)
	}
	return nil
}

func (handler *volumeHandlerZVol) HandlePrepared() (bool, error) {
	zVolStatus := handler.volumeManager.LookupZVolStatusByDataset(handler.status.ZVolName())
	if zVolStatus == nil {
		// wait for ZVolStatus from zfsmanager
		return false, nil
	}
	if handler.useVHost {
		wwn, err := tgt.CreateTargetVhost(zVolStatus.Device, handler.status.Key())
		if err != nil {
			return true, fmt.Errorf("createTargetVhost for volume %s: %v",
				handler.status.DisplayName, err)
		}
		handler.status.WWN = wwn
	}
	return true, nil
}

func (handler *volumeHandlerZVol) HandleCreated() (bool, error) {
	handler.status.ContentFormat = zconfig.Format_RAW
	updateVolumeSizes(handler.log, handler, handler.status)
	return true, nil
}

func (handler *volumeHandlerZVol) CreateVolume() (string, error) {
	// this is the target location, where we expect the volume to be
	fileLocation := handler.status.PathName()

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

	zVolName := handler.status.ZVolName()
	zVolDevice := zfs.GetZVolDeviceByDataset(zVolName)
	if zVolDevice == "" {
		errStr := fmt.Sprintf("Error finding zfs zvol %s", zVolName)
		handler.log.Error(errStr)
		return "", errors.New(errStr)
	}
	if handler.status.ReferenceName != "" {
		pathToFile, err := handler.getVolumeFilePath()
		if err != nil {
			errStr := fmt.Sprintf("Error obtaining file for zvol at volume %s, error=%v",
				handler.status.Key(), err)
			handler.log.Error(errStr)
			return "", errors.New(errStr)
		}
		if err := diskmetrics.RolloutImgToBlock(createContext, handler.log, pathToFile, zVolDevice, "raw"); err != nil {
			errStr := fmt.Sprintf("Error converting %s to zfs zvol %s: %v",
				pathToFile, zVolDevice, err)
			handler.log.Error(errStr)
			return zVolDevice, errors.New(errStr)
		}
		f, err := os.Open(zVolDevice)
		if err != nil {
			errStr := fmt.Sprintf("Error opening zfs zvol %s: %v",
				zVolDevice, err)
			handler.log.Error(errStr)
			return zVolDevice, errors.New(errStr)
		}
		defer func() {
			if err := f.Close(); err != nil {
				handler.log.Errorf("error closing zfs zvol: %s: %v", zVolDevice, err)
			}
		}()
		if err := f.Sync(); err != nil {
			errStr := fmt.Sprintf("Error syncing zfs zvol %s: %v", zVolDevice, err)
			handler.log.Error(errStr)
			return zVolDevice, errors.New(errStr)
		}
	}
	fileLocation = zVolDevice

	handler.log.Functionf("Extract DONE from %s to %s", handler.status.ReferenceName, fileLocation)

	handler.log.Functionf("CreateVolume(%s) DONE", handler.status.Key())
	return fileLocation, nil
}

func (handler *volumeHandlerZVol) DestroyVolume() (string, error) {
	if handler.useVHost {
		serial, err := tgt.GetSerialTarget(handler.status.Key())
		if err != nil {
			handler.log.Warnf("Error obtaining serial from target for %s, error=%v",
				handler.status.Key(), err)
		} else {
			if err := tgt.VHostDeleteIBlock(tgt.GetNaaSerial(serial)); err != nil {
				errStr := fmt.Sprintf("Error deleting vhost for %s, error=%v",
					handler.status.Key(), err)
				handler.log.Warnf(errStr)
			}
		}
		if err := tgt.TargetDeleteIBlock(handler.status.Key()); err != nil {
			errStr := fmt.Sprintf("Error deleting target for %s, error=%v",
				handler.status.Key(), err)
			handler.log.Warnf(errStr)
		}
	}
	zVolName := handler.status.ZVolName()
	if err := zfs.DestroyDataset(zVolName); err != nil {
		errStr := fmt.Sprintf("Error destroying zfs zvol at %s, error=%v",
			zVolName, err)
		handler.log.Error(errStr)
		return "", errors.New(errStr)
	}
	handler.log.Functionf("destroyVolume(%s) DONE", handler.status.Key())
	return "", nil
}

func (handler *volumeHandlerZVol) Populate() (bool, error) {
	zvolName := handler.status.ZVolName()
	if zfs.DatasetExist(handler.log, zvolName) {
		zVolDevice := zfs.GetZVolDeviceByDataset(zvolName)
		if zVolDevice == "" {
			return false, fmt.Errorf("cannot find device for zvol %s of %s", zvolName, handler.status.Key())
		}
		handler.status.FileLocation = zVolDevice
		handler.status.ContentFormat = zconfig.Format_RAW
		if handler.useVHost && !tgt.CheckTargetIBlock(handler.status.Key()) {
			handler.log.Functionf("generating target and vhost for %s", handler.status.Key())
			wwn, err := tgt.CreateTargetVhost(zVolDevice, handler.status.Key())
			if err != nil {
				return true, fmt.Errorf("createTargetVhost volume %s: %v",
					handler.status.DisplayName, err)
			}
			handler.status.WWN = wwn
		}
		return true, nil
	}
	return false, nil
}

func (handler *volumeHandlerZVol) getVolumeFilePath() (string, error) {
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

func (handler *volumeHandlerZVol) CreateSnapshot() (interface{}, time.Time, error) {
	//TODO implement me
	errStr := fmt.Sprintf("CreateSnapshot not implemented for zvol")
	handler.log.Error(errStr)
	err := errors.New(errStr)
	timeCreated := time.Time{}
	return "", timeCreated, err
}

func (handler *volumeHandlerZVol) RollbackToSnapshot(snapshotMeta interface{}) error {
	//TODO implement me
	errStr := fmt.Sprintf("RollbackToSnapshot not implemented for zvol")
	handler.log.Error(errStr)
	err := errors.New(errStr)
	return err
}

func (handler *volumeHandlerZVol) DeleteSnapshot(snapshotMeta interface{}) error {
	//TODO implement me
	errStr := fmt.Sprintf("DeleteSnapshot not implemented for zvol")
	handler.log.Error(errStr)
	err := errors.New(errStr)
	return err
}
