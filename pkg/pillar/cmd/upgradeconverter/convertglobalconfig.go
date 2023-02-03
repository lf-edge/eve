// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"encoding/json"
	"io"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

func createConfigItemMapDir(configItemMapDir string) {
	info, err := os.Stat(configItemMapDir)
	if err == nil {
		// Dir Exists.. Make sure it is a Dir
		if info.IsDir() {
			log.Tracef("createConfigItemMapDir: Dir %s Exists", configItemMapDir)
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
		log.Tracef("createConfigItemMapDir: Dir %s Doesn't Exist. Creating it.",
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
		log.Tracef("delOldGlobalConfigDir: Removed %s", globalConfigDir)
		return nil
	}
	log.Errorf("delOldGlobalConfigDir: Failed to remove %s", globalConfigDir)
	return err
}

func convertGlobalConfig(ctxPtr *ucContext) error {
	oldGlobalConfigFile := ctxPtr.globalConfigFile()
	oldExists := fileutils.FileExists(log, oldGlobalConfigFile)
	if oldExists {
		createConfigItemMapDir(ctxPtr.oldConfigItemValueMapDir())
	}
	newGlobalConfigFile := ctxPtr.oldConfigItemValueMapFile()
	newExists := fileutils.FileExists(log, newGlobalConfigFile)

	var newConfigPtr *types.ConfigItemValueMap

	if oldExists {
		if newExists {
			newTime, _ := fileTimeStamp(newGlobalConfigFile)
			oldTime, _ := fileTimeStamp(oldGlobalConfigFile)
			log.Tracef("convertGlobalConfig: newTime:%+v, oldTime: %+v",
				newTime, oldTime)
			if oldTime.After(newTime) {
				log.Functionf("OldConfig Newer than NewConfig. Need Conversion")
			} else {
				log.Functionf("convertGlobalConfig: NewConfig Newer than OldConfig")
				delOldGlobalConfigDir(ctxPtr)
				return nil
			}
		} else {
			log.Functionf("OldConfig Exists. NO NewConfig. Need Conversion")
		}
		newConfigPtr = newConfigFromOld(oldGlobalConfigFile)
	} else if newExists {
		log.Functionf("No Old Config. Only new Config Exists. No conversion needed")
		delOldGlobalConfigDir(ctxPtr)
		return nil
	} else {
		log.Functionf("Neither New Nor Old Configs Exist. Do nothing")
		return nil
	}

	// Save New config to file.
	var data []byte
	data, err := json.Marshal(newConfigPtr)
	if err != nil {
		log.Fatalf("Failed to marshall new global config err %s", err)
	}
	err = os.WriteFile(newGlobalConfigFile, data, 0644)
	if err != nil {
		log.Fatalf("Failed to Save NewConfig. err %s", err)
	}
	// Delete the OldGlobalConfig
	delOldGlobalConfigDir(ctxPtr)
	log.Tracef("upgradeconverter.convertGlobalConfig done")
	return nil
}

func newConfigFromOld(globalConfigFile string) *types.ConfigItemValueMap {
	file, err := os.Open(globalConfigFile)
	if err != nil {
		log.Errorf("Failed to open file %s. Err: %s", globalConfigFile, err)
		return types.DefaultConfigItemValueMap()
	}

	byteValue, err := io.ReadAll(file)
	if err != nil {
		log.Errorf("***Failed to read file %s. Err: %s",
			globalConfigFile, err)
		return types.DefaultConfigItemValueMap()
	}

	var oldGlobalConfig types.OldGlobalConfig
	err = json.Unmarshal(byteValue, &oldGlobalConfig)
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
	log.Tracef("upgradeconverter.convert done")
	return err
}
