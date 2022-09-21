// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle publishing the existing-at-boot VolumeStatus
// Published under "unknown" objType with refcount=0. Moved to
// other objType when there is a reference.

package volumemgr

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/tgt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

// populateExistingVolumesFormat iterates over the directory and takes format
// from the name of the volume and prepares map of it
func populateExistingVolumesFormat(dirName string) {

	log.Functionf("populateExistingVolumesFormat(%s)", dirName)
	locations, err := ioutil.ReadDir(dirName)
	if err != nil {
		log.Errorf("populateExistingVolumesFormat: read directory '%s' failed: %v",
			dirName, err)
		return
	}
	for _, location := range locations {
		key, format, _, err := getVolumeKeyAndFormat(dirName, location.Name())
		if err != nil {
			log.Error(err)
			continue
		}
		volumeFormat[key] = zconfig.Format(zconfig.Format_value[format])
	}
	log.Functionf("populateExistingVolumesFormat(%s) Done", dirName)
}

// Periodic garbage collection looking at RefCount=0 files in the unknown
// Others have their delete handler.
func gcObjects(ctx *volumemgrContext, dirName string) {

	log.Tracef("gcObjects(%s)", dirName)
	locations, err := ioutil.ReadDir(dirName)
	if err != nil {
		log.Errorf("gcObjects: read directory '%s' failed: %v",
			dirName, err)
		return
	}
	for _, location := range locations {
		filelocation := path.Join(dirName, location.Name())
		key, format, _, err := getVolumeKeyAndFormat(dirName, location.Name())
		if err != nil {
			log.Error(err)
			deleteFile(filelocation)
			continue
		}
		vs := lookupVolumeStatus(ctx, key)
		if vs == nil {
			log.Functionf("gcObjects: Found unused volume %s. Deleting it.",
				filelocation)
			if format == "CONTAINER" {
				_ = ctx.casClient.RemoveContainerRootDir(filelocation)
			} else {
				deleteFile(filelocation)
			}
		}
	}
	log.Tracef("gcObjects(%s) Done", dirName)
}

// Periodic garbage collection of children datasets in provided zfs dataset
func gcDatasets(ctx *volumemgrContext, dataset string) {
	if ctx.persistType != types.PersistZFS {
		return
	}
	log.Tracef("gcDatasets(%s)", dataset)
	locations, err := zfs.GetVolumesFromDataset(dataset)
	if err != nil {
		log.Errorf("gcDatasets: GetVolumesFromDataset '%s' failed: %v",
			dataset, err)
		return
	}
	for _, location := range locations {
		key := types.ZVolNameToKey(location)
		vs := lookupVolumeStatus(ctx, key)
		if vs == nil {
			log.Functionf("gcDatasets: Found unused volume %s. Deleting it.",
				location)
			serial, err := tgt.GetSerialTarget(key)
			if err != nil {
				log.Warnf("gcDatasets: Error obtaining serial from target for %s, error=%v",
					key, err)
			} else {
				if err := tgt.VHostDeleteIBlock(fmt.Sprintf("naa.%s", serial)); err != nil {
					log.Warnf("gcDatasets: Error deleting vhost for %s, error=%v",
						key, err)
				}
			}
			if err := tgt.TargetDeleteIBlock(key); err != nil {
				log.Warnf("gcDatasets: Error deleting target for %s, error=%v",
					key, err)
			}
			if err := zfs.DestroyDataset(location); err != nil {
				log.Errorf("gcDatasets: DestroyDataset '%s' failed: %v",
					location, err)
			}
		}
	}
	log.Tracef("gcDatasets(%s) Done", dataset)
}

func getVolumeKeyAndFormat(dirName, name string) (key string, format string, tmp bool, err error) {
	filelocation := path.Join(dirName, name)
	keyAndFormat := strings.Split(name, ".")
	switch {
	case len(keyAndFormat) == 2:
		key, format, tmp, err = keyAndFormat[0], strings.ToUpper(keyAndFormat[1]), false, nil
	case len(keyAndFormat) == 3 && keyAndFormat[2] == "tmp":
		key, format, tmp, err = keyAndFormat[0], strings.ToUpper(keyAndFormat[1]), true, nil
	default:
		errStr := fmt.Sprintf("getVolumeKeyAndFormat: Found unknown format volume %s.",
			filelocation)
		key, format, tmp, err = "", "", false, errors.New(errStr)
	}
	return key, format, tmp, err
}

func deleteFile(filelocation string) {
	log.Functionf("deleteFile: Deleting %s", filelocation)
	if err := os.RemoveAll(filelocation); err != nil {
		log.Errorf("Failed to delete file %s. Error: %s",
			filelocation, err.Error())
	}
}

// gcPendingCreateVolume remove volumes not created on previous boot
func gcPendingCreateVolume(ctx *volumemgrContext) {
	log.Trace("gcPendingCreateVolume")
	for _, obj := range ctx.pubVolumeCreatePending.GetAll() {
		vcp := obj.(types.VolumeCreatePending)
		if vcp.IsContainer() {
			// check if directory accessible
			// assume that we should remove it as not created completely
			if _, err := os.Stat(vcp.PathName()); err == nil {
				if err := ctx.casClient.RemoveContainerRootDir(vcp.PathName()); err != nil {
					log.Errorf("gcPendingCreateVolume: error removing container root dir: %s", err)
					continue
				}
			}
		} else {
			switch ctx.persistType {
			case types.PersistZFS:
				zVolName := vcp.ZVolName()
				// check if dataset exists
				// assume that we should remove it as not created completely
				if zfs.DatasetExist(log, zVolName) {
					if err := zfs.DestroyDataset(zVolName); err != nil {
						log.Errorf("gcPendingCreateVolume: error destroying zfs zvol at %s, error=%s",
							zVolName, err)
						continue
					}
				}
			default:
				// check if file accessible
				// assume that we should remove it as not created completely
				if _, err := os.Stat(vcp.PathName()); err == nil {
					if err := os.Remove(vcp.PathName()); err != nil {
						log.Errorf("gcPendingCreateVolume: error deleting volume: %s", err)
						continue
					}
				}
			}
		}
		if err := ctx.pubVolumeCreatePending.Unpublish(vcp.Key()); err != nil {
			log.Errorf("gcPendingCreateVolume: cannot unpublish %s: %s", vcp.Key(), err)
		}
	}
	log.Trace("gcPendingCreateVolume done")
}
