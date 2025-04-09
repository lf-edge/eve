// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package activeapp

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// CreateLocalAppActiveFile creates the local file that indicates the app instance is active
func CreateLocalAppActiveFile(log *base.LogObject, appUUID string) {
	// Construct the file path as "<LocalActiveAppConfigDir>/<appUUID>.json".
	filePath := filepath.Join(types.LocalActiveAppConfigDir, appUUID+".json")

	// Ensure that the base directory exists.
	if err := os.MkdirAll(types.LocalActiveAppConfigDir, 0700); err != nil {
		log.Errorf("Failed to create directory %s: %v", types.LocalActiveAppConfigDir, err)
		return
	}

	// Create (or truncate) an empty file.
	f, err := os.Create(filePath)
	if err != nil {
		log.Errorf("Failed to create active file %s: %v", filePath, err)
		return
	}
	defer f.Close()

	log.Noticef("Created empty JSON file: %s", filePath)
}

// DelLocalAppActiveFile deletes the local file that indicates the app instance is active
func DelLocalAppActiveFile(log *base.LogObject, appUUID string) {
	filePath := filepath.Join(types.LocalActiveAppConfigDir, appUUID+".json")
	if err := os.Remove(filePath); err != nil {
		log.Errorf("Failed to remove a file %s: %v", filePath, err)
	}
}

// LoadActiveAppInstanceUUIDs reads all JSON files from the specified directory,
// extracts the UUID from each filename (by removing the ".json" extension),
// and returns a slice of UUIDs.
func LoadActiveAppInstanceUUIDs(log *base.LogObject) ([]string, error) {
	// Read all directory entries using os.ReadDir.
	entries, err := os.ReadDir(types.LocalActiveAppConfigDir)
	if err != nil {
		return nil, err
	}

	var uuids []string
	// Iterate over all entries found.
	for _, entry := range entries {
		// We only care about files (not subdirectories) with a .json extension.
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			// Remove the .json extension to get the UUID.
			uuid := strings.TrimSuffix(entry.Name(), ".json")
			log.Noticef("Found active app instance UUID: %s", uuid)
			uuids = append(uuids, uuid)
		}
	}

	return uuids, nil
}
