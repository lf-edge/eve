// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

func applyDefaultConfigItem(ctxPtr *ucContext) error {
	createConfigItemMapDir(ctxPtr.newConfigItemValueMapDir())
	newConfigItemFile := ctxPtr.newConfigItemValueMapFile()
	newExists := fileExists(newConfigItemFile)

	newConfigPtr := types.DefaultConfigItemValueMap()
	if newExists {
		oldConfigPtr, err := parseFile(newConfigItemFile)
		if err != nil {
			log.Error(err)
		} else {
			// Apply defaults
			newConfigPtr.UpdateItemValues(oldConfigPtr)
			if !cmp.Equal(oldConfigPtr, newConfigPtr) {
				log.Noticef("Updated ConfigItemValueMap with new defaults. Diff: %+v",
					cmp.Diff(oldConfigPtr, newConfigPtr))
			} else {
				log.Tracef("upgradeconverter.applyDefaultConfigItem done with no change")
				return nil
			}
		}
	} else {
		log.Noticef("No existing ConfigItemValueMap; creating %s with defaults",
			newConfigItemFile)
	}

	// Save New config to file.
	var data []byte
	data, err := json.Marshal(newConfigPtr)
	if err != nil {
		log.Fatalf("Failed to marshall new global config err %s", err)
	}
	// Do a write plus rename so we don't leave a zero-length file if
	// there is no space left; leave old file content instead
	err = fileutils.WriteRename(newConfigItemFile, data)
	if err != nil {
		// Could be low on disk space
		log.Errorf("Failed to Save NewConfig: %s", err)
		return err
	}
	log.Tracef("upgradeconverter.applyDefaultConfigItem done")
	return nil
}

func parseFile(filename string) (*types.ConfigItemValueMap, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to open file %s. Err: %s", filename, err)
	}

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("***Failed to read file %s. Err: %s",
			filename, err)
	}

	var config types.ConfigItemValueMap
	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshall data in file %s. err: %s",
			filename, err)
	}
	return &config, nil
}
