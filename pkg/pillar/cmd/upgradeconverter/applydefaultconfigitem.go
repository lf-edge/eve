// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

const (
	baseAuthorizedKeysFile    = types.IdentityDirname + "/authorized_keys"
	importGlobalConfigFile    = types.IdentityDirname + "/GlobalConfig/global.json"
	ingestedAuthorizedKeysSha = types.IngestedDirname + "/authorized_keys.sha"
	ingestedGlobalConfigSha   = types.IngestedDirname + "/GlobalConfig/global.sha"
)

func applyDefaultConfigItem(ctxPtr *ucContext) error {
	createConfigItemMapDir(ctxPtr.newConfigItemValueMapDir())
	newConfigItemFile := ctxPtr.newConfigItemValueMapFile()
	newExists := fileutils.FileExists(log, newConfigItemFile)
	bootstrapExists := fileutils.FileExists(log, types.BootstrapConfFileName)

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
		if bootstrapExists {
			log.Warnf("Not creating default %s: "+
				"bootstrap config is present", newConfigItemFile)
			return nil
		}
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

// If we have a /config/ importGlobalConfigFile then we compare its sha against
// ingestedGlobalConfigSha and only import if different. This ensures that we only
// apply it once.
func importFromConfigPartition(ctxPtr *ucContext) error {
	var err error
	var globalConfigPtr *types.ConfigItemValueMap
	var configSha, authorizedKeysSha []byte

	persistStatusFile := ctxPtr.newConfigItemValueMapFile()
	globalConfigExists := fileutils.FileExists(log, importGlobalConfigFile)
	persistedConfigExists := fileutils.FileExists(log, persistStatusFile)
	bootstrapExists := fileutils.FileExists(log, types.BootstrapConfFileName)
	authKeysExists := fileutils.FileExists(log, baseAuthorizedKeysFile)

	doImport := globalConfigExists

	// Skip the legacy global.json if there is bootstrap config.
	if bootstrapExists {
		if doImport {
			log.Warnf("Skipping import of %s: "+
				"bootstrap config is present", importGlobalConfigFile)
		}
		if authKeysExists {
			log.Warnf("Skipping import of %s: "+
				"bootstrap config is present", baseAuthorizedKeysFile)
		}
		return nil
	}

	if doImport {
		doImport, configSha, err = fileutils.CompareSha(importGlobalConfigFile,
			ingestedGlobalConfigSha)
		if err != nil {
			log.Errorf("CompareSha failed: %s", err)
		} else if !doImport {
			log.Noticef("No change to %s", importGlobalConfigFile)
		}
	}
	if doImport {
		log.Noticef("Importing config items from %s", importGlobalConfigFile)
		globalConfigPtr, err = parseFile(importGlobalConfigFile)
		if err != nil {
			log.Errorf("Error parsing configuration from file: %s, %s", importGlobalConfigFile, err)
			return err
		}
	} else if persistedConfigExists {
		log.Noticef("Reusing persisted config items from the previous run")
		globalConfigPtr, err = parseFile(persistStatusFile)
		if err != nil {
			log.Errorf("Error parsing configuration from file: %s, %s", persistStatusFile, err)
			return err
		}
	} else {
		log.Noticef("No existing ConfigItemValueMap; creating new %s",
			persistStatusFile)
		globalConfigPtr = types.NewConfigItemValueMap()
	}

	keyData, keyDataValid := readAuthorizedKeys(baseAuthorizedKeysFile)
	doAuthorizedKeys := (len(keyData) != 0 && keyDataValid)
	if doAuthorizedKeys {
		doAuthorizedKeys, authorizedKeysSha, err = fileutils.CompareSha(baseAuthorizedKeysFile,
			ingestedAuthorizedKeysSha)
		if err != nil {
			log.Errorf("CompareSha failed: %s", err)
		} else if !doAuthorizedKeys {
			log.Noticef("No change to the key data in %s",
				baseAuthorizedKeysFile)
		}
	}
	if doAuthorizedKeys {
		log.Noticef("Found the key data in %s", baseAuthorizedKeysFile)
		globalConfigPtr.SetGlobalValueString(types.SSHAuthorizedKeys, keyData)
	}

	// Save Global config to file.
	var data []byte
	data, err = json.Marshal(globalConfigPtr)
	if err != nil {
		log.Fatalf("Failed to marshall global config err %s", err)
	}
	err = fileutils.WriteRename(persistStatusFile, data)
	if err != nil {
		// Could be low on disk space
		log.Errorf("Failed to Save global config in: %s, %s", persistStatusFile, err)
		return err
	}
	if doAuthorizedKeys {
		// Save sha of what we ingested
		err := fileutils.SaveShaInFile(ingestedAuthorizedKeysSha, authorizedKeysSha)
		if err != nil {
			log.Errorf("SaveShaInFile %s failed: %s", ingestedAuthorizedKeysSha, err)
		} else {
			log.Noticef("Saved new sha for %s in %s",
				baseAuthorizedKeysFile, ingestedAuthorizedKeysSha)
		}
	}

	if doImport {
		// Save sha of what we ingested
		err := fileutils.SaveShaInFile(ingestedGlobalConfigSha, configSha)
		if err != nil {
			log.Errorf("SaveShaInFile %s failed: %s", ingestedGlobalConfigSha, err)
		} else {
			log.Noticef("Saved new sha for %s in %s",
				importGlobalConfigFile, ingestedGlobalConfigSha)
		}
	}
	log.Tracef("upgradeconverter.importFromConfigPartition done")
	return nil
}

func parseFile(filename string) (*types.ConfigItemValueMap, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to open file %s. Err: %s", filename, err)
	}

	byteValue, err := io.ReadAll(file)
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

func readAuthorizedKeys(filename string) (string, bool) {
	if !fileutils.FileExists(log, filename) {
		return "", false
	}

	fileDesc, err := os.Open(filename)
	if err != nil {
		log.Warnf("readAuthorizedKeys: File (%s) open error: %s", filename, err)
		return "", false
	}
	defer fileDesc.Close()

	// Collect keys and join them with newlines. sshd requires one key
	// per line, so the separator must be preserved: concatenating the
	// keys directly would mash them into a single invalid line.
	var keys []string
	scanner := bufio.NewScanner(fileDesc)
	for scanner.Scan() {
		// bufio.Scanner strips the trailing newline (and a trailing
		// "\r"), and yields the final line even without a trailing
		// newline.
		line := scanner.Text()

		// Skip comments and blank lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys = append(keys, line)
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("readAuthorizedKeys: scan (%s) error: %s", filename, err)
		return "", false
	}
	keyData := strings.Join(keys, "\n")
	if len(keyData) != 0 {
		return keyData, true
	}
	return keyData, false
}
