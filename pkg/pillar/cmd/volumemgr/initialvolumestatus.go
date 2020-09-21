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
)

// populateExistingVolumesFormat iterates over the directory and takes format
// from the name of the volume and prepares map of it
func populateExistingVolumesFormat(dirName string) {

	log.Infof("populateExistingVolumesFormat(%s)", dirName)
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
	log.Infof("populateExistingVolumesFormat(%s) Done", dirName)
}

// Periodic garbage collection looking at RefCount=0 files in the unknown
// Others have their delete handler.
func gcObjects(ctx *volumemgrContext, dirName string) {

	log.Debugf("gcObjects(%s)", dirName)
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
			log.Infof("gcObjects: Found unused volume %s. Deleting it.",
				filelocation)
			if format == "CONTAINER" {
				_ = ctx.casClient.RemoveContainerRootDir(filelocation)
			}
			deleteFile(filelocation)
		}
	}
	log.Debugf("gcObjects(%s) Done", dirName)
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
	log.Infof("deleteFile: Deleting %s", filelocation)
	if err := os.RemoveAll(filelocation); err != nil {
		log.Errorf("Failed to delete file %s. Error: %s",
			filelocation, err.Error())
	}
}
