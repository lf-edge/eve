// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
)

func moveConfigItemValueMap(ctxPtr *ucContext) error {
	createConfigItemMapDir(ctxPtr.newConfigItemValueMapDir())
	newFile := ctxPtr.newConfigItemValueMapFile()
	oldFile := ctxPtr.oldConfigItemValueMapFile()
	newExists := fileExists(newFile)
	oldExists := fileExists(oldFile)

	if oldExists {
		if newExists {
			newTime, _ := fileTimeStamp(newFile)
			oldTime, _ := fileTimeStamp(oldFile)
			log.Debugf("moveConfigItemValueMap: newTime:%+v, oldTime: %+v",
				newTime, oldTime)
			if oldTime.After(newTime) {
				log.Infof("oldFile more recent than newFile. Copy")
			} else {
				log.Infof("newFile more recent than oldFile. Discard old")
				err := os.RemoveAll(ctxPtr.oldConfigItemValueMapDir())
				if err != nil {
					log.Error(err)
				}
				return nil
			}
		} else {
			log.Infof("Old Config Exists. No New Config. Copy")
		}
	} else if newExists {
		log.Infof("No Old Config. Only new Config Exists. No copy needed")
		return nil
	} else {
		log.Infof("Neither new nor old configs exist. Bail")
		return nil
	}

	log.Infof("Copy from %s to %s", oldFile, newFile)
	err := CopyFile(oldFile, newFile)
	if err != nil {
		log.Error(err)
		return err
	}
	err = os.RemoveAll(ctxPtr.oldConfigItemValueMapDir())
	if err != nil {
		log.Error(err)
	}
	log.Debugf("upgradeconverter.moveConfigItemValueMap done")
	return nil
}
