// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types which feed in and out of the verifier

package utils

import (
	"fmt"
	"io/ioutil"
	"os"

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
		return "", err
	}
	if len(locations) > 1 {
		return "", fmt.Errorf("Multiple files in %s\n",
			locationDir)
	}
	if len(locations) == 0 {
		return "", fmt.Errorf("No files in %s\n",
			locationDir)
	}
	return locationDir + "/" + locations[0].Name(), nil
}

// VerifiedImageDirLocation - Gives the directory for a verified image, but not
// the file itself, which is subject to possible algorithms
func VerifiedImageDirLocation(sha256 string) string {
	return types.VerifiedAppImgDirname + "/" + sha256
}

// VerifiedImageFileLocation - Gives the file location for a verified image.
func VerifiedImageFileLocation(sha256 string) (string, error) {
	locationDir := VerifiedImageDirLocation(sha256)
	location, err := locationFromDir(locationDir)
	// logging the error here kind of violates functional principles,
	// since it would be legitimate to ask, "where is the verified image file,
	// and let me decide if the returned error really is an error". Similar to,
	// sometimes an err isn't an error, e.g. io.EOF, where the caller decides
	// but this minimizes the changes
	if err != nil {
		log.Errorln(err)
	}
	return location, err
}
