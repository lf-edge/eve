// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumehandlers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/edge-containers/pkg/registry"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
)

type volumeHandlerFile struct {
	commonVolumeHandler
}

func (handler *volumeHandlerFile) HandlePrepared() (bool, error) { return true, nil }

func (handler *volumeHandlerFile) HandleCreated() (bool, error) {
	updateVolumeSizes(handler.log, handler, handler.status)
	return true, nil
}

func (handler *volumeHandlerFile) GetVolumeDetails() (uint64, uint64, string, bool, error) {
	_, err := os.Stat(handler.status.FileLocation)
	if err != nil {
		return 0, 0, "", false, fmt.Errorf("GetVolumeSize failed for %s: %v",
			handler.status.FileLocation, err)
	}
	imgInfo, err := diskmetrics.GetImgInfo(handler.log, handler.status.FileLocation)
	if err != nil {
		errStr := fmt.Sprintf("GetVolumeSize/GetImgInfo failed for %s: %v",
			handler.status.FileLocation, err)
		return 0, 0, "", false, errors.New(errStr)
	}
	return imgInfo.ActualSize, imgInfo.VirtualSize, imgInfo.Format,
		imgInfo.DirtyFlag, nil
}

func (handler *volumeHandlerFile) CreateVolume() (string, error) {
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
				//it disappears in case of deleting of volume config
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

	if _, err := os.Stat(fileLocation); err == nil {
		errStr := fmt.Sprintf("Can not create %s for %s: exists",
			fileLocation, handler.status.Key())
		handler.log.Error(errStr)
		return "", errors.New(errStr)
	}
	if handler.status.ReferenceName != "" {
		// use the edge-containers library to extract the data we need
		puller := registry.Puller{
			Image: handler.status.ReferenceName,
		}

		// redefine createContext and createCancel with values received from cas
		// we call createCancel to cancel creating process
		createContext, createCancel = handler.volumeManager.GetCasClient().CtrNewUserServicesCtx()

		resolver, err := handler.volumeManager.GetCasClient().Resolver(createContext)
		if err != nil {
			errStr := fmt.Sprintf("error getting CAS resolver: %v", err)
			handler.log.Error(errStr)
			return "", errors.New(errStr)
		}
		// create a writer for the file where we want
		f, err := os.Create(fileLocation)
		if err != nil {
			errStr := fmt.Sprintf("error creating target file at %s: %v", fileLocation, err)
			handler.log.Error(errStr)
			return "", errors.New(errStr)
		}
		defer f.Close()
		if _, _, err := puller.Pull(&registry.FilesTarget{Root: f, AcceptHash: true}, 0, false, os.Stderr, resolver); err != nil {
			errStr := fmt.Sprintf("error pulling %s from containerd: %v", handler.status.ReferenceName, err)
			handler.log.Error(errStr)
			return fileLocation, errors.New(errStr)
		}
		if handler.expandableDisk() {
			// Do we need to expand disk?
			if err := handler.maybeResizeDisk(createContext, fileLocation, handler.status.MaxVolSize); err != nil {
				handler.log.Error(err)
				return fileLocation, err
			}
		}
		if err := f.Sync(); err != nil {
			handler.log.Error(err)
			return fileLocation, err
		}
	} else {
		if err := diskmetrics.CreateImg(createContext, handler.log, fileLocation, strings.ToLower(handler.status.ContentFormat.String()), handler.status.MaxVolSize); err != nil {
			handler.log.Error(err)
			return fileLocation, err
		}
		f, err := os.Open(fileLocation)
		if err != nil {
			errStr := fmt.Sprintf("Error opening volume %s: %v",
				fileLocation, err)
			handler.log.Error(errStr)
			return fileLocation, errors.New(errStr)
		}
		defer func() {
			if err := f.Close(); err != nil {
				handler.log.Errorf("error closing volume: %s: %v", fileLocation, err)
			}
		}()
		if err := f.Sync(); err != nil {
			errStr := fmt.Sprintf("Error syncing volume %s: %v", fileLocation, err)
			handler.log.Error(errStr)
			return fileLocation, errors.New(errStr)
		}
	}

	handler.log.Functionf("Extract DONE from %s to %s", handler.status.ReferenceName, fileLocation)

	handler.log.Functionf("CreateVolume(%s) DONE", handler.status.Key())
	return fileLocation, nil
}

func (handler *volumeHandlerFile) DestroyVolume() (string, error) {
	if err := os.RemoveAll(handler.status.FileLocation); err != nil {
		handler.log.Error(err)
		return "", err
	}
	handler.log.Functionf("destroyVolume(%s) DONE", handler.status.Key())
	return "", nil
}

func (handler *volumeHandlerFile) Populate() (bool, error) {
	if _, err := os.Stat(handler.status.PathName()); err == nil {
		handler.status.FileLocation = handler.status.PathName()
		return true, nil
	}
	return false, nil
}

// expandableDisk returns true if we should try to expand disk to the provided max volume size
func (handler *volumeHandlerFile) expandableDisk() bool {
	if handler.status.ContentFormat == zconfig.Format_ISO {
		return false
	}
	return true
}

// Make sure the (virtual) size of the disk is at least maxsizebytes
func (handler *volumeHandlerFile) maybeResizeDisk(ctx context.Context, diskfile string, maxsizebytes uint64) error {
	if maxsizebytes == 0 {
		return nil
	}
	handler.log.Functionf("maybeResizeDisk(%s) current to %d",
		diskfile, maxsizebytes)
	size, resize, err := diskmetrics.CheckResizeDisk(handler.log, diskfile, maxsizebytes)
	if err != nil {
		return fmt.Errorf("maybeResizeDisk checkResizeDisk error: %s", err)
	}
	if resize {
		handler.log.Functionf("maybeResizeDisk(%s) resize to %d",
			diskfile, size)
		return diskmetrics.ResizeImg(ctx, handler.log, diskfile, size)
	}
	return nil
}
