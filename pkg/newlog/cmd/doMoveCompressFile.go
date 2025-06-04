// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/ring"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/lf-edge/eve-api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	maxGzipFileSize int64 = 50000 // maximum gzipped file size for upload in bytes
	gzipFileFooter  int64 = 12    // size of gzip footer to use in calculations
)

var (
	gzipFilesCnt int64 // total gzip files written
	lastLogNum   int   // last number used for file name generation
)

func doMoveCompressFile(ps *pubsub.PubSub, tmplogfileInfo fileChanInfo) []string {
	var writtenFiles []string

	isApp := tmplogfileInfo.isApp
	dirName, appuuid := getFileInfo(tmplogfileInfo)

	now := time.Now()
	timeNowNum := int(now.UnixNano() / int64(time.Millisecond)) // in msec
	if timeNowNum < lastLogNum {
		// adjust variable for file name generation to not overlap with the old one
		timeNowNum = lastLogNum + 1
	}
	outfile := gzipFileNameGet(isApp, timeNowNum, dirName, appuuid, tmplogfileInfo.notUpload)
	log.Function("Moving ", tmplogfileInfo.tmpfile, " to ", outfile)

	// open input file
	iFile, err := os.Open(tmplogfileInfo.tmpfile)
	if err != nil {
		log.Fatal(err)
	}
	defer iFile.Close()

	// first we go through the file and count the number of occurrences of the selected log entries
	var logCounter map[string]int
	var seen map[string]uint64
	var queue *ring.Ring
	if dirName == uploadDevDir {
		if len(logsToCount.Load().([]string)) != 0 {
			logCounter = countLogsInFile(iFile)
			log.Functionf("Counted log occurrences while compressing %s to %s: %v", tmplogfileInfo.tmpfile, outfile, logCounter)
		}

		// for deduplicator
		// 'seen' counts occurrences of each file in the current window.
		seen = make(map[string]uint64)
		// 'queue' holds the file fields of the last bufferSize logs.
		queue = ring.New(int(dedupWindowSize.Load()))
	}

	scanner := bufio.NewScanner(iFile)
	// check if we cannot scan
	// check valid json header for device log we will use later
	if !scanner.Scan() || (!isApp && !json.Valid(scanner.Bytes())) {
		log.Errorf("doMoveCompressFile: can't get metadata on first line, remove %s", tmplogfileInfo.tmpfile)
		if scanner.Err() != nil {
			log.Error(scanner.Err())
		}
		return nil
	}

	// assign the metadata in the first line of the logfile
	tmplogfileInfo.header = scanner.Text()

	// prepare writers to save gzipped logs
	gw, underlayWriter, oTmpFile := prepareGzipToOutTempFile(filepath.Dir(outfile), tmplogfileInfo, now)

	fileID := 0
	wdTime := time.Now()
	var newSize int64
	for scanner.Scan() {
		if time.Since(wdTime) >= (15 * time.Second) {
			ps.StillRunning(agentName, warningTime, errorTime)
			wdTime = time.Now()
		}
		newLine := scanner.Bytes()
		//trim non-graphic symbols
		newLine = bytes.TrimFunc(newLine, func(r rune) bool {
			return !unicode.IsGraphic(r)
		})
		if len(newLine) == 0 {
			continue
		}
		if !json.Valid(newLine) {
			log.Errorf("doMoveCompressFile: found broken line: %s", string(newLine))
			continue
		}

		if dirName == uploadDevDir {
			if len(filenameFilter.Load().(map[string]struct{})) != 0 || len(logCounter) != 0 || dedupWindowSize.Load() != 0 {
				var logEntry logs.LogEntry
				if err := json.Unmarshal(newLine, &logEntry); err != nil {
					continue // we don't care about the error here
				}
				var useEntry bool
				if useEntry = !filterOut(&logEntry); !useEntry {
					continue
				}
				if useEntry = addLogCount(&logEntry, logCounter); !useEntry {
					continue
				}
				if useEntry, queue = dedupLogEntry(&logEntry, seen, queue); !useEntry {
					continue
				}
				newLine, err = json.Marshal(&logEntry)
				if err != nil {
					log.Errorf("doMoveCompressFile: failed to marshal logEntry: %v", err)
					continue
				}
			}
		}

		// assume that next line is incompressible to be safe
		// note: bytesWritten may be updated eventually because of gzip implementation
		// potentially we cannot account maxGzipFileSize less than windowsize of gzip 32768
		if underlayWriter.bytesWritten+gzipFileFooter+int64(len(newLine)) >= maxGzipFileSize {
			newSize += finalizeGzipToOutTempFile(gw, oTmpFile, outfile)
			writtenFiles = append(writtenFiles, outfile)
			logmetrics.NumBreakGZipFile++
			fileID++
			outfile = gzipFileNameGet(isApp, timeNowNum+fileID, dirName, appuuid, tmplogfileInfo.notUpload)
			gw, underlayWriter, oTmpFile = prepareGzipToOutTempFile(filepath.Dir(outfile), tmplogfileInfo, now)
		}
		_, err := gw.Write(append(newLine, '\n'))
		if err != nil {
			log.Fatal("doMoveCompressFile: cannot write file", err)
		}
	}
	if scanner.Err() != nil {
		log.Fatal("doMoveCompressFile: reading file failed", scanner.Err())
	}
	newSize += finalizeGzipToOutTempFile(gw, oTmpFile, outfile)
	writtenFiles = append(writtenFiles, outfile)
	fileID++

	// store variable to check for the new file name generator
	lastLogNum = timeNowNum + fileID

	if isApp {
		logmetrics.AppMetrics.NumGZipBytesWrite += uint64(newSize)
		if tmplogfileInfo.notUpload {
			logmetrics.NumSkipUploadAppFile += uint32(fileID)
		}
	} else {
		logmetrics.DevMetrics.NumGZipBytesWrite += uint64(newSize)
	}

	return writtenFiles
}

func getFileInfo(tmplogfileInfo fileChanInfo) (string, string) {
	var dirName, appuuid string
	if tmplogfileInfo.isApp {
		if tmplogfileInfo.notUpload {
			dirName = keepSentDir
		} else {
			dirName = uploadAppDir
		}
		appuuid = getAppuuidFromLogfile(tmplogfileInfo)
	} else {
		if tmplogfileInfo.notUpload {
			dirName = keepSentDir
		} else {
			dirName = uploadDevDir
		}
	}
	return dirName, appuuid
}

func getAppuuidFromLogfile(tmplogfileInfo fileChanInfo) string {
	tmpStr1 := strings.TrimPrefix(path.Base(tmplogfileInfo.tmpfile), appPrefix)
	tmpStr2 := strings.SplitN(tmpStr1, ".log", 2)
	return tmpStr2[0]
}

func gzipFileNameGet(isApp bool, timeNum int, dirName, appUUID string, notUpload bool) string {
	var outfileName string
	if isApp {
		appPref := appPrefix
		if notUpload {
			appPref = appPref + skipUpload
		}
		outfileName = appPref + appUUID + types.AppSuffix + strconv.Itoa(timeNum) + ".gz"
	} else {
		outfileName = devPrefix + strconv.Itoa(timeNum) + ".gz"
	}
	return dirName + "/" + outfileName
}

func finalizeGzipToOutTempFile(gw *gzip.Writer, oTmpFile *os.File, outfile string) int64 {
	err := gw.Close()
	if err != nil {
		log.Fatal("finalizeGzipToOutTempFile: cannot close file", err)
	}
	tmpFileName := oTmpFile.Name()
	err = oTmpFile.Sync()
	if err != nil {
		log.Error(err)
	}
	err = oTmpFile.Close()
	if err != nil {
		log.Error(err)
	}
	f2, err := os.Stat(tmpFileName)
	if err != nil {
		log.Fatal("finalizeGzipToOutTempFile: file stat error", err)
	}
	newSize := f2.Size()
	err = os.Rename(tmpFileName, outfile)
	if err != nil {
		log.Fatal("finalizeGzipToOutTempFile: rename tmp file failed ", err)
	}
	calculateGzipSizes(newSize)
	return newSize
}

func calculateGzipSizes(size int64) {
	if uint32(size) > logmetrics.MaxGzipSize {
		logmetrics.MaxGzipSize = uint32(size)
	}
	oldtotal := int64(logmetrics.AvgGzipSize) * gzipFilesCnt
	gzipFilesCnt++
	logmetrics.AvgGzipSize = uint32((oldtotal + size) / gzipFilesCnt)
}

// countingWriter implements io.Writer and store count of bytesWritten
type countingWriter struct {
	writer       io.Writer
	bytesWritten int64
}

// Write implementation for countingWriter
func (w *countingWriter) Write(p []byte) (n int, err error) {
	n, err = w.writer.Write(p)
	w.bytesWritten += int64(n)
	return n, err
}

func prepareGzipToOutTempFile(gzipDirName string, fHdr fileChanInfo, now time.Time) (*gzip.Writer, *countingWriter, *os.File) {
	// open output file
	oTmpFile, err := os.CreateTemp(gzipDirName, tmpPrefix)
	if err != nil {
		log.Fatal("prepareGzipToOutTempFile: create tmp file failed: ", err)
	}

	writer := &countingWriter{
		writer: oTmpFile,
	}

	gw, _ := gzip.NewWriterLevel(writer, gzip.BestCompression)

	// for app upload, use gzip header 'Name' for appName string to simplify cloud side implementation
	// for now, the gw.Comment has the metadata for device log, and gw.Name for appName for app log
	if fHdr.isApp {
		gw.Name = fHdr.header
	} else {
		gw.Comment = fHdr.header
	}
	gw.ModTime = now

	return gw, writer, oTmpFile
}
