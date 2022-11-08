// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

func moveConfigItemValueMap(ctxPtr *ucContext) error {
	createConfigItemMapDir(ctxPtr.newConfigItemValueMapDir())
	newFile := ctxPtr.newConfigItemValueMapFile()
	oldFile := ctxPtr.oldConfigItemValueMapFile()
	newExists := fileutils.FileExists(log, newFile)
	oldExists := fileutils.FileExists(log, oldFile)

	if oldExists {
		if newExists {
			newTime, _ := fileTimeStamp(newFile)
			oldTime, _ := fileTimeStamp(oldFile)
			log.Tracef("moveConfigItemValueMap: newTime:%+v, oldTime: %+v",
				newTime, oldTime)
			if oldTime.After(newTime) {
				log.Functionf("oldFile more recent than newFile. Copy")
			} else {
				log.Functionf("newFile more recent than oldFile. Discard old")
				err := os.RemoveAll(ctxPtr.oldConfigItemValueMapDir())
				if err != nil {
					log.Error(err)
				}
				return nil
			}
		} else {
			log.Functionf("Old Config Exists. No New Config. Copy")
		}
	} else if newExists {
		log.Functionf("No Old Config. Only new Config Exists. No copy needed")
		return nil
	} else {
		log.Functionf("Neither new nor old configs exist. Bail")
		return nil
	}

	log.Functionf("Copy from %s to %s", oldFile, newFile)
	err := fileutils.CopyFile(oldFile, newFile)
	if err != nil {
		log.Error(err)
		return err
	}
	err = os.RemoveAll(ctxPtr.oldConfigItemValueMapDir())
	if err != nil {
		log.Error(err)
	}
	log.Tracef("upgradeconverter.moveConfigItemValueMap done")
	return nil
}
