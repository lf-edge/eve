// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package persist

import (
	"os"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// ReadSavedConfig reads the contents of a saved config file from the checkpoint directory
// and returns its data along with the last modification time.
func ReadSavedConfig(log *base.LogObject, filename string) ([]byte, time.Time, error) {
	filename = filepath.Join(types.CheckpointDirname, filename)
	info, err := os.Stat(filename)
	if err != nil {
		return nil, time.Time{}, err
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		log.Errorln("ReadSavedConfig", err)
		return nil, info.ModTime(), err
	}
	return contents, info.ModTime(), nil
}

// SaveConfig writes the given config data to the checkpoint directory, replacing any
// existing file. Logs an error if the write fails (e.g., due to lack of disk space).
func SaveConfig(log *base.LogObject, filename string, contents []byte) {
	filename = filepath.Join(types.CheckpointDirname, filename)
	err := fileutils.WriteRename(filename, contents)
	if err != nil {
		// Can occur if no space in filesystem
		log.Errorf("SaveConfig failed: %s", err)
		return
	}
}

// CleanSavedConfig removes the specified saved config file from the checkpoint directory,
// if it exists. Logs a message if removal fails.
func CleanSavedConfig(log *base.LogObject, filename string) {
	filename = filepath.Join(types.CheckpointDirname, filename)
	if err := os.Remove(filename); err != nil {
		log.Functionf("CleanSavedConfig failed: %s", err)
	}
}

// TouchSavedConfig updates the modification timestamp of the specified saved config file
// to the current time. Logs a warning if the file does not exist and an error if the
// timestamp update fails.
func TouchSavedConfig(log *base.LogObject, filename string) {
	filename = filepath.Join(types.CheckpointDirname, filename)
	_, err := os.Stat(filename)
	if err != nil {
		log.Warnf("TouchSavedConfig stat failed: %s", err)
	}
	currentTime := time.Now()
	err = os.Chtimes(filename, currentTime, currentTime)
	if err != nil {
		// Can occur if no space in filesystem?
		log.Errorf("TouchSavedConfig failed: %s", err)
	}
}

// ExistsSavedConfig checks if the specified saved config file exists in the checkpoint
// directory. Logs an error if the existence check fails for a reason other than
// "file not found".
func ExistsSavedConfig(log *base.LogObject, filename string) bool {
	filename = filepath.Join(types.CheckpointDirname, filename)
	_, err := os.Stat(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("ExistsSavedConfig: cannot stat %s: %s", filename, err)
		}
		return false
	}
	return true
}
