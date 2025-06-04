// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	maxToSendMbytes uint32 = 2048 // default 2 Gbytes for log files remains on disk
)

var (
	limitGzipFilesMbyts = maxToSendMbytes // maximum Mbytes for gzip files remain to be sent up
)

type gfileStats struct {
	isSent   bool
	logDir   string
	filename string
	filesize int64
}

func checkDirGZFiles(sfiles map[string]gfileStats, logDir string) ([]string, int64, error) {
	var sizes int64
	dir, err := os.Open(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, sizes, err
	}
	defer func() {
		if err := dir.Close(); err != nil {
			log.Errorf("cannot close dir %s: %s", logDir, err)
		}
	}()

	var alreadySent bool
	if logDir == keepSentDir {
		alreadySent = true
	}

	var keys []string

	for {
		files, err := dir.Readdir(10)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, sizes, err
		}
		for _, fi := range files {
			fname := fi.Name()
			fsize := fi.Size()
			fs := gfileStats{
				filename: fname,
				filesize: fsize,
				isSent:   alreadySent,
				logDir:   logDir,
			}
			sizes += fsize
			fname2 := strings.TrimSuffix(fname, ".gz")
			fname3 := strings.Split(fname2, ".log.")
			if len(fname3) != 2 {
				continue
			}
			keys = append(keys, fname3[1])
			sfiles[fname3[1]] = fs
		}
	}

	return keys, sizes, nil
}

// checkKeepQuota - keep gzip file sizes below the default or user defined quota limit
func checkKeepQuota() {
	maxSize := int64(limitGzipFilesMbyts * 1000000)
	sfiles := make(map[string]gfileStats)

	filesKeepSent, sizeKeepSent, err := checkDirGZFiles(sfiles, keepSentDir)
	if err != nil {
		log.Errorf("checkKeepQuota: keepSentDir %v", err)
	}
	filesAppUpload, sizeAppUpload, err := checkDirGZFiles(sfiles, uploadAppDir)
	if err != nil {
		log.Errorf("checkKeepQuota: AppDir %v", err)
	}
	filesDevUpload, sizeDevUpload, err := checkDirGZFiles(sfiles, uploadDevDir)
	if err != nil {
		log.Errorf("checkKeepQuota: DevDir %v", err)
	}
	fileFailSend, sizeFailSend, err := checkDirGZFiles(sfiles, failSendDir)
	if err != nil && !os.IsNotExist(err) {
		log.Errorf("checkKeepQuota: FailToSendDir %v", err)
	}

	totalsize := sizeKeepSent + sizeAppUpload + sizeDevUpload + sizeFailSend
	totalCount := len(filesKeepSent) + len(filesAppUpload) + len(filesDevUpload) + len(fileFailSend)
	removed := 0
	// limit file count to not as they can have less size than expected
	// we can have enormous number of files
	maxCount := int(maxSize / maxGzipFileSize)
	if totalsize > maxSize || totalCount > maxCount {
		removalPriority := [][]string{filesKeepSent, fileFailSend, filesAppUpload, filesDevUpload}

		for _, dirFiles := range removalPriority {
			// sort the files in alphabetical order: this way the files with the oldest (smallest) timestamps will be removed first
			// side effect: in keepSentQueue, app logs will be removed before device logs, which is okay since those are always synced with the controller
			sort.Strings(dirFiles)

			for _, filename := range dirFiles {
				if _, ok := sfiles[filename]; !ok {
					continue
				}
				fs := sfiles[filename]
				filePath := filepath.Join(fs.logDir, fs.filename)
				if _, err := os.Stat(filePath); err != nil {
					continue
				}
				if err := os.Remove(filePath); err != nil {
					log.Errorf("checkKeepQuota: remove failed %s, %v", filePath, err)
					continue
				}
				if fs.logDir == keepSentDir {
					// since the files are sorted by name and we delete the oldest files first,
					// we can assume that the latest available log (from the file that is next in line to be deleted)
					// has the timestamp of the file that was just deleted
					oldestSavedDeviceLog, err := types.GetTimestampFromGzipName(fs.filename)
					if err != nil {
						log.Errorf("checkKeepQuota: %v", err)
					} else {
						logmetrics.OldestSavedDeviceLog = oldestSavedDeviceLog
					}
				}
				if !fs.isSent {
					logmetrics.NumGZipFileRemoved++
				}
				removed++
				totalsize -= fs.filesize
				totalCount--
				if totalsize < maxSize && totalCount < maxCount {
					break
				}
			}
		}
		log.Tracef("checkKeepQuota: %d gzip files removed", removed)
	}
	logmetrics.TotalSizeLogs = uint64(totalsize)
}
