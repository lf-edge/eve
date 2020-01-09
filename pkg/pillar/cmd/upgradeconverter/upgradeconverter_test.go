// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

type testEntry struct {
	oldVersionExists bool
	newVersionExists bool
	oldVersionOlder  bool
	// newConfigPtr - If nil, verifies no NewCfgDir. If not, expect contents
	//  to match.
	newConfigPtr *types.ConfigItemValueMap
	// expectNoOldCfgDir - Verified oldConfigDir to be deleted.
	expectNoOldCfgDir bool
}

func oldGlobalConfig() types.OldGlobalConfig {
	config := types.OldGlobalConfig{}
	config = types.ApplyDefaults(config)
	// Set Some values
	config.ConfigInterval = 300
	config.AllowAppVnc = true
	config.AllowNonFreeBaseImages = types.TS_NONE
	config.DefaultLogLevel = "debug"
	config.AgentSettings["zedagent"] = types.PerAgentSettings{
		LogLevel: "info", RemoteLogLevel: "fatal"}
	return config
}

func newConfigItemValueMap() types.ConfigItemValueMap {
	config := types.DefaultConfigItemValueMap()
	config.SetGlobalValueInt(types.ConfigInterval, 400)
	config.SetGlobalValueBool(types.AllowAppVnc, false)
	config.SetGlobalValueTriState(types.AllowNonFreeBaseImages,
		types.TS_ENABLED)
	config.SetGlobalValueString(types.DefaultLogLevel, "warn")
	config.SetAgentSettingStringValue("zedagent", types.LogLevel, "debug")
	config.SetAgentSettingStringValue("zedagent", types.RemoteLogLevel, "crit")
	return *config
}

func createJSONFile(config interface{}, file string) {

	parentDir := filepath.Dir(file)
	if !fileExists(parentDir) {
		err := os.MkdirAll(parentDir, 0700)
		if err != nil {
			log.Fatalf("Failed to create Dir: %s", parentDir)
		}
		log.Debugf("Created Dir: %s", parentDir)
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		log.Fatalf("createJSONFile: failed to marshall. err %s\n config: %+v",
			err, config)
	}
	err = ioutil.WriteFile(file, configJSON, 0644)
	if err != nil {
		log.Fatalf("createJSONFile: failed to write file err %s", err)
	}
	return
}

func configItemValueMapFromFile(file string) *types.ConfigItemValueMap {
	var newConfig types.ConfigItemValueMap
	cfgJSON, err := ioutil.ReadFile(file)
	if err != nil {
		log.Errorf("***configItemValueMapFromFile - Failed to read from %s. "+
			"Err: %s", file, err)
		return nil
	}
	err = json.Unmarshal(cfgJSON, &newConfig)
	if err == nil {
		return &newConfig
	}
	log.Errorf("***configItemValueMapFromFile - Failed to unmarshall data: %+v",
		cfgJSON)
	return nil
}

func checkNoDir(t *testing.T, dir string) {
	if fileExists(dir) {
		t.Fatalf("***Dir %s Still Present. Expected it to be deleted.", dir)
	}
}

func ucContextForTest() *ucContext {
	//log.SetLevel(log.DebugLevel)
	var err error
	ctxPtr := &ucContext{}
	ctxPtr.persistConfigDir, err = ioutil.TempDir(".", "Converter")
	if err != nil {
		log.Fatalf("Failed to create persistConfigDir. err: %s", err)
	}
	ctxPtr.varTmpDir, err = ioutil.TempDir(".", "ConvertvarTmp")
	if err != nil {
		log.Fatalf("Failed to create varTmpDir. err: %s", err)
	}
	return ctxPtr
}

func ucContextCleanupDirs(ctxPtr *ucContext) {
	os.RemoveAll(ctxPtr.persistConfigDir)
	ctxPtr.persistConfigDir = ""
	os.RemoveAll(ctxPtr.varTmpDir)
	ctxPtr.varTmpDir = ""
}

func runTestMatrix(t *testing.T, testMatrix map[string]testEntry) {
	oldConfig := oldGlobalConfig()
	newConfig := newConfigItemValueMap()

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		ctxPtr := ucContextForTest()
		if test.oldVersionExists && test.oldVersionOlder {
			createJSONFile(oldConfig, ctxPtr.globalConfigFile())
		}
		if test.newVersionExists {
			createJSONFile(newConfig, ctxPtr.configItemValueMapFile())
		}
		if test.oldVersionExists && !test.oldVersionOlder {
			time.Sleep(2 * time.Second)
			createJSONFile(oldConfig, ctxPtr.globalConfigFile())
		}
		err := convertGlobalConfig(ctxPtr)
		if err != nil {
			t.Fatalf("Unexpected Failure in GlobalConfigHandler. err: %s", err)
		}
		if test.newConfigPtr == nil {
			checkNoDir(t, ctxPtr.configItemValueMapDir())
		} else {
			newCfgFromFile := configItemValueMapFromFile(
				ctxPtr.configItemValueMapFile())
			if !cmp.Equal(test.newConfigPtr, newCfgFromFile) {
				msg := ""
				for key, value := range test.newConfigPtr.GlobalSettings {
					newVal, ok := newCfgFromFile.GlobalSettings[key]
					if !ok {
						msg += fmt.Sprintf("Key %s not present in newCfgFromFile",
							key)
						continue
					} else if value != newVal {
						msg += fmt.Sprintf("Key %s value != newVal\n"+
							"Value: %+v\nnewVal: %+v\n", key, value, newVal)
					}
				}
				t.Fatalf("Expected newConfig !=  Actual newConfig.\nDIFF: %s",
					msg)
			}
		}
		if test.expectNoOldCfgDir {
			checkNoDir(t, ctxPtr.globalConfigDir())
		}
		ucContextCleanupDirs(ctxPtr)
	}

}

func Test_UpgradeConverter_Convert(t *testing.T) {
	oldConfig := oldGlobalConfig()
	newConfig := newConfigItemValueMap()
	convertedConfig := oldConfig.MoveBetweenConfigs()

	testMatrix := map[string]testEntry{
		"Convert: Neither Old Version Nor New Version exist.": {
			// Default ConfigItemValueMap gets creates
			oldVersionExists: false,
			newVersionExists: false,
			newConfigPtr:     types.DefaultConfigItemValueMap(),
		},
		"Convert: Old Version Exists, No New Version - Normal Upgrade case": {
			// Old Converted to New
			oldVersionExists: true,
			newConfigPtr:     convertedConfig,
		},
		"Convert: Old Version Older than New Version": {
			// oldVersion Ignored. New version used.
			oldVersionExists: true,
			newVersionExists: true,
			oldVersionOlder:  true,
			newConfigPtr:     &newConfig,
		},
		"Convert: Old Version Newer than New Version": {
			// New Version Regenerated ( Convert Old to New)
			oldVersionExists: true,
			newVersionExists: true,
			oldVersionOlder:  false,
			newConfigPtr:     convertedConfig,
		},
		"Convert: Only New Version exists. Upgrade from one new version to another": {
			// New Version untouched
			newVersionExists: true,
			newConfigPtr:     &newConfig,
		},
	}
	runTestMatrix(t, testMatrix)
}
