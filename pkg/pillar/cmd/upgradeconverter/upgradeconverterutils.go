// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
	"time"
)

func fileTimeStamp(filename string) (time.Time, error) {
	file, err := os.Stat(filename)
	if err != nil {
		log.Functionf("failed to get a timestamp for file %s err %s", filename, err)
		return time.Time{}, err
	}
	return file.ModTime(), nil
}

func deleteFile(filename string) error {
	var err = os.Remove(filename)
	if err == nil {
		log.Functionf("Removed file %s", filename)
		return nil
	}
	return err
}
