// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	log "github.com/sirupsen/logrus"
)

const (
	configItemMapDir    = types.PersistConfigDir + "/ConfigItemValueMap/"
	newGlobalConfigFile = configItemMapDir + "global.json"
	globalConfigDir     = types.PersistConfigDir + "/GlobalConfig"
	oldGlobalConfigFile = globalConfigDir + "/global.json"
)

func createConfigItemMapDir(configItemMapDir string) {
	info, err := os.Stat(configItemMapDir)
	if err == nil {
		// Dir Exists.. Make sure it is a Dir
		if info.IsDir() {
			log.Debugf("createConfigItemMapDir: Dir %s Exists", configItemMapDir)
			return
		}
		log.Errorf("***createConfigItemMapDir: %s not a directory. Info: %+v\n"+
			"Deleting it and recreating the Directory", configItemMapDir, info)
		err = deleteFile(configItemMapDir)
		if err != nil {
			log.Fatalf("***createConfigItemMapDir: Failed to delete file %s. Err: %s",
				configItemMapDir, err)
		}
	} else if os.IsNotExist(err) {
		log.Debugf("createConfigItemMapDir: Dir %s Doesn't Exist. Creating it.",
			configItemMapDir)
	} else {
		log.Fatalf("***createConfigItemMapDir: Failed to get Info for file %s. Err: %s",
			configItemMapDir, err)
	}
	err = os.MkdirAll(configItemMapDir, 0700)
	if err != nil {
		log.Fatalf("***createConfigItemMapDir: Failed to create Dir (%s). Err %s",
			configItemMapDir, err)
	}
	return
}

func delOldGlobalConfigDir(ctxPtr *ucContext) error {
	// Old Global Config is the only one to be cleaned up currently.
	globalConfigDir := ctxPtr.globalConfigDir()
	err := os.RemoveAll(globalConfigDir)
	if err == nil {
		log.Debugf("delOldGlobalConfigDir: Removed %s", globalConfigDir)
		return nil
	}
	log.Errorf("delOldGlobalConfigDir: Failed to remove %s", globalConfigDir)
	return err
}

func convertGlobalConfig(ctxPtr *ucContext) error {
	createConfigItemMapDir(ctxPtr.configItemValueMapDir())
	newGlobalConfigFile := ctxPtr.configItemValueMapFile()
	oldGlobalConfigFile := ctxPtr.globalConfigFile()
	newExists := fileExists(newGlobalConfigFile)
	oldExists := fileExists(oldGlobalConfigFile)

	var newConfigPtr *types.ConfigItemValueMap

	if oldExists {
		if newExists {
			newTime, _ := fileTimeStamp(newGlobalConfigFile)
			oldTime, _ := fileTimeStamp(oldGlobalConfigFile)
			log.Debugf("convertGlobalConfig: newTime:%+v, oldTime: %+v",
				newTime, oldTime)
			if oldTime.After(newTime) {
				log.Infof("OldConfig Newer than NewConfig. Need Conversion")
			} else {
				log.Infof("convertGlobalConfig: NewConfig Newer than OldConfig")
				delOldGlobalConfigDir(ctxPtr)
				return nil
			}
		} else {
			log.Infof("OldConfig Exists. NO NewConfig. Need Conversion")
		}
		newConfigPtr = newConfigFromOld(oldGlobalConfigFile)
	} else if newExists {
		log.Infof("No Old Config. Only new Config Exists. No conversion needed")
		delOldGlobalConfigDir(ctxPtr)
		return nil
	} else {
		log.Infof("Neither New Nor Old Configs Exist. Creating Default new Config")
		newConfigPtr = types.DefaultConfigItemValueMap()
	}

	// Save New config to file.
	var data []byte
	data, err := json.Marshal(newConfigPtr)
	if err != nil {
		log.Fatalf("Failed to marshall new global config err %s", err)
	}
	err = ioutil.WriteFile(newGlobalConfigFile, data, 0644)
	if err != nil {
		log.Fatalf("Failed to Save NewConfig. err %s", err)
	}
	log.Infof("Saved NewConfig. data: %s", data)

	// Create a symlink of one doesn't currently exist
	symLinkPath := ctxPtr.varTmpDir + "/ConfigItemValueMap"
	utils.CreateSymlink(symLinkPath, ctxPtr.configItemValueMapDir())
	log.Debugf("Created symlink %s -> %s",
		symLinkPath, ctxPtr.configItemValueMapDir())

	// Delete the OldGlobalConfig
	delOldGlobalConfigDir(ctxPtr)
	log.Debugf("upgradeconverter.convertGlobalConfig done")
	return nil
}

func newConfigFromOld(globalConfigFile string) *types.ConfigItemValueMap {
	file, err := os.Open(globalConfigFile)
	if err != nil {
		log.Errorf("Failed to open file %s. Err: %s", globalConfigFile, err)
		return types.DefaultConfigItemValueMap()
	}

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		log.Errorf("***Failed to read file %s. Err: %s",
			globalConfigFile, err)
		return types.DefaultConfigItemValueMap()
	}

	var oldGlobalConfig types.OldGlobalConfig
	err = json.Unmarshal([]byte(byteValue), &oldGlobalConfig)
	if err != nil {
		log.Errorf("Could not unmarshall data in file %s. err: %s",
			globalConfigFile, err)
		return types.DefaultConfigItemValueMap()
	}
	return oldGlobalConfig.MoveBetweenConfigs()
}

func convert(ctxPtr *ucContext) error {
	// Any any conversions we need here.
	err := convertGlobalConfig(ctxPtr)
	log.Debugf("upgradeconverter.convert done")
	return err
}
