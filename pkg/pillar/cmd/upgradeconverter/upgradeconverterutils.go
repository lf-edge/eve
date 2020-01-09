// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	log.Errorf("***File %s May or May Not exist. Err: %s", filename, err)
	return false
}

func fileTimeStamp(filename string) (time.Time, error) {
	file, err := os.Stat(filename)
	if err != nil {
		log.Infof("failed to get a timestamp for file %s err %s", filename, err)
		return time.Time{}, err
	}
	return file.ModTime(), nil
}

func deleteFile(filename string) error {
	var err = os.Remove(filename)
	if err == nil {
		log.Infof("Removed file %s", filename)
		return nil
	}
	return err
}
