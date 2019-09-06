// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types which feed in and out of the verifier

package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func locationFromDir(locationDir string) (string, error) {
	if _, err := os.Stat(locationDir); err != nil {
		log.Errorf("Missing directory: %s, %s\n", locationDir, err)
		return "", err
	}
	// locationDir is a directory. Need to find single file inside
	// which the verifier ensures.
	locations, err := ioutil.ReadDir(locationDir)
	if err != nil {
		log.Errorln(err)
		return "", err
	}
	if len(locations) != 1 {
		log.Errorf("Multiple files in %s\n", locationDir)
		return "", fmt.Errorf("Multiple files in %s\n",
			locationDir)
	}
	if len(locations) == 0 {
		log.Errorf("No files in %s\n", locationDir)
		return "", fmt.Errorf("No files in %s\n",
			locationDir)
	}
	return locationDir + "/" + locations[0].Name(), nil
}

// VerifiedImageFileLocation - Gives the file location for a verified image.
func VerifiedImageFileLocation(isContainer bool, containerImageID string,
	imageSha256 string) (string, error) {
	var location string
	if isContainer {
		// Check if statusPtr.ContainerImageID has "sha512-" substring at the beginning
		if strings.Index(containerImageID, "sha512-") != 0 {
			err := fmt.Errorf("status.ContainerImageID should start with "+
				" sha512-, but is %s", containerImageID)
			return "", err
		}
		location = filepath.Join(types.PersistRktDataDir,
			"cas", "blob", "sha512",
			string(containerImageID[7:9]), containerImageID)
	} else {
		locationDir := types.VerifiedDirname + "/" + imageSha256
		var err error
		location, err = locationFromDir(locationDir)
		if err != nil {
			return "", err
		}
	}
	return location, nil
}
