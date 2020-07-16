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
	log "github.com/sirupsen/logrus"
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
		key, format, err := getVolumeKeyAndFormat(dirName, location.Name())
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
		key, format, err := getVolumeKeyAndFormat(dirName, location.Name())
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

func getVolumeKeyAndFormat(dirName, name string) (string, string, error) {
	filelocation := path.Join(dirName, name)
	keyAndFormat := strings.Split(name, ".")
	if len(keyAndFormat) != 2 {
		errStr := fmt.Sprintf("getVolumeKeyAndFormat: Found unknown format volume %s.",
			filelocation)
		return "", "", errors.New(errStr)
	}
	return keyAndFormat[0], strings.ToUpper(keyAndFormat[1]), nil
}

func deleteFile(filelocation string) {
	log.Infof("deleteFile: Deleting %s", filelocation)
	if err := os.RemoveAll(filelocation); err != nil {
		log.Errorf("Failed to delete file %s. Error: %s",
			filelocation, err.Error())
	}
}
