// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/lf-edge/eve-api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"

	nestedapp "github.com/lf-edge/eve-api/go/nestedappinstancemetrics"
)

const (
	maxLogFileSize int32 = 550000 // maximum collect file size in bytes
)

var (
	msgIDDevCnt uint64 = 1 // every log message increments the msg-id by 1

	// per app writelog stats
	appStatsMap map[string]statsLogFile
)

// collection time device/app temp file stats for file size and time limit
type statsLogFile struct {
	index     int
	file      *os.File
	size      int32
	starttime time.Time
	notUpload bool
}

// writelogFile - a goroutine to format and write log entries into dev/app logfiles
func writelogFile(logChan <-chan inputEntry, moveChan chan fileChanInfo) {
	// get EVE version and partition, UUID may not be available yet
	getEveInfo()

	// move and gzip the existing logfiles first
	findMovePrevLogFiles(moveChan)

	// new file to collect device logs for upload
	devStatsUpload := initNewLogfile(collectDir, devPrefixUpload, "")
	defer devStatsUpload.file.Close()
	devStatsUpload.notUpload = false

	// new file to collect device logs to keep on device
	devStatsKeep := initNewLogfile(collectDir, devPrefixKeep, "")
	defer devStatsKeep.file.Close()
	devStatsKeep.notUpload = true

	oldestLogEntry, err := getOldestLog()
	if err != nil {
		log.Errorf("could not set OldestSavedDeviceLog metric due to getLatestLog error: %v", err)
	} else {
		if oldestLogEntry == nil {
			// no log entry found, set the oldest log time to now
			logmetrics.OldestSavedDeviceLog = time.Now()
		} else {
			logmetrics.OldestSavedDeviceLog = time.Unix(oldestLogEntry.Timestamp.Seconds, int64(oldestLogEntry.Timestamp.Nanos))
		}
	}

	devSourceBytes = base.NewLockedStringMap()
	appStatsMap = make(map[string]statsLogFile)
	checklogTimer := time.NewTimer(5 * time.Second)

	timeIdx := 0
	for {
		select {
		case <-checklogTimer.C:
			timeIdx++
			checkLogTimeExpire(&devStatsUpload, moveChan)  // only check the upload log file, there is no need to hurry moving the keep log file
			checklogTimer = time.NewTimer(5 * time.Second) // check the file time limit every 5 seconds

		case entry := <-logChan:
			appuuid := checkAppEntry(&entry)
			var appM statsLogFile
			if appuuid != "" {
				appM = getAppStatsMap(appuuid)
			}
			timeS, _ := getPtypeTimestamp(entry.timestamp)
			mapLog := logs.LogEntry{
				Severity:  entry.severity,
				Source:    entry.source,
				Content:   entry.content,
				Iid:       entry.pid,
				Filename:  entry.filename,
				Msgid:     updateLogMsgID(appuuid),
				Function:  entry.function,
				Timestamp: timeS,
			}
			mapJentry, _ := json.Marshal(&mapLog)
			logline := string(mapJentry) + "\n"
			if appuuid != "" {
				bytesWritten := writelogEntry(&appM, logline)

				logmetrics.AppMetrics.NumBytesWrite += uint64(bytesWritten)
				appStatsMap[appuuid] = appM

				trigMoveToGzip(&appM, appuuid, moveChan, false)

			} else {
				if entry.sendToRemote {
					writelogEntry(&devStatsUpload, logline)

					trigMoveToGzip(&devStatsUpload, "", moveChan, false)
				}

				// write all log entries to the log file to keep
				n := writelogEntry(&devStatsKeep, logline)
				updateDevInputlogStats(entry.source, uint64(n))

				trigMoveToGzip(&devStatsKeep, "", moveChan, false)
			}
		}
	}
}

func checkLogTimeExpire(devStats *statsLogFile, moveChan chan fileChanInfo) {
	// check device log file
	if devStats.file != nil && devStats.size > 0 && uint32(time.Since(devStats.starttime).Seconds()) > logmetrics.LogfileTimeoutSec {
		trigMoveToGzip(devStats, "", moveChan, true)
	}

	// check app log files
	for appuuid, appM := range appStatsMap {
		if val, ok := domainUUID.Load(appuuid); ok { // if app disable-upload status changes, move file to gzip now
			d := val.(appDomain)
			if d.trigMove && appM.file != nil {
				d.trigMove = false
				domainUUID.Store(appuuid, d)
				trigMoveToGzip(&appM, appuuid, moveChan, true)
				continue
			}
		}
		if appM.file != nil && appM.size > 0 && uint32(time.Since(appM.starttime).Seconds()) > logmetrics.LogfileTimeoutSec {
			trigMoveToGzip(&appM, appuuid, moveChan, true)
		}
	}
}
func checkAppEntry(entry *inputEntry) string {
	appuuid := ""
	var appVMlog bool
	var appSplitArr []string
	if entry.appUUID != "" {
		appuuid = entry.appUUID
		entry.content = "{\"container\":\"" + entry.acName + "\",\"time\":\"" + entry.acLogTime + "\",\"msg\":\"" + entry.content + "\"}"
	} else if strings.HasPrefix(entry.source, "guest_vm-") {
		appSplitArr = strings.SplitN(entry.source, "guest_vm-", 2)
		appVMlog = true
	} else if strings.HasPrefix(entry.source, "guest_vm_err-") {
		appSplitArr = strings.SplitN(entry.source, "guest_vm_err-", 2)
		appVMlog = true
	}
	if appVMlog {
		if len(appSplitArr) == 2 {
			if appSplitArr[0] == "" && appSplitArr[1] != "" {
				// entry.source is the 'domainName' in the format
				// of app-uuid.restart-num.app-num
				entry.source = appSplitArr[1]
				appsource := strings.Split(entry.source, ".")

				// Check the nested app log message of docker runtime app
				vmAppUUID := appsource[0]
				appuuid = processNestedAppLogMessage(entry, vmAppUUID)
				if appuuid == "" {
					if val, ok := domainUUID.Load(vmAppUUID); ok {
						du := val.(appDomain)
						appuuid = du.appUUID
					} else {
						log.Tracef("entry.source not in right format %s", entry.source)
					}
				}
			}
		}
	}
	return appuuid
}

func getAppStatsMap(appuuid string) statsLogFile {
	if _, ok := appStatsMap[appuuid]; !ok {
		applogname := appPrefix + appuuid + ".log"
		appM := initNewLogfile(collectDir, applogname, appuuid)

		val, found := domainUUID.Load(appuuid)
		if found {
			appD := val.(appDomain)
			appM.notUpload = appD.disableLogs
			if appD.trigMove {
				appD.trigMove = false // reset this since we start a new file
				domainUUID.Store(appuuid, appD)
			}
		}

		appStatsMap[appuuid] = appM

	}
	return appStatsMap[appuuid]
}
func getPtypeTimestamp(timeStr string) (*timestamp.Timestamp, error) {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		t = time.Unix(0, 0)
	}
	tt := &timestamp.Timestamp{Seconds: t.Unix(), Nanos: int32(t.Nanosecond())}
	return tt, err
}

// updateLogMsgID - handles the msgID for log for both dev and apps
// dev log does not have app-uuid, thus domainName passed in is ""
func updateLogMsgID(appUUID string) uint64 {
	var msgid uint64
	if appUUID == "" {
		msgid = msgIDDevCnt
		msgIDDevCnt++
	} else {
		if val, ok := domainUUID.Load(appUUID); ok {
			appD := val.(appDomain)
			msgid = appD.msgIDAppCnt
			appD.msgIDAppCnt++
			domainUUID.Store(appUUID, appD)
		}
	}

	return msgid
}

// write log entry, update size and index, sync file if needed
func writelogEntry(stats *statsLogFile, logline string) int {
	n, err := stats.file.WriteString(logline)
	if err != nil {
		log.Fatal("writelogEntry: write logline ", err)
	}
	stats.size += int32(n)

	if stats.index%syncToFileCnt == 0 {
		err = stats.file.Sync()
		if err != nil {
			log.Error(err)
		}
	}
	stats.index++
	return n
}

// at boot-up, move the collected log files from previous life
func findMovePrevLogFiles(movefile chan fileChanInfo) {
	files, err := os.ReadDir(collectDir)
	if err != nil {
		log.Fatal("findMovePrevLogFiles: read dir ", err)
	}

	// remove any gzip file the name starts them 'Tempfile', it crashed before finished rename in dev/app dir
	cleanGzipTempfiles(uploadDevDir)
	cleanGzipTempfiles(uploadAppDir)

	// on prev life's dev-log and app-log
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		isDev := strings.HasPrefix(f.Name(), devPrefix)
		isApp := strings.HasPrefix(f.Name(), appPrefix)

		if (isDev && len(f.Name()) > len(devPrefix)) || (isApp && len(f.Name()) > len(appPrefix)) {
			fileinfo := fileChanInfo{
				tmpfile: path.Join(collectDir, f.Name()),
				isApp:   isApp,
			}
			if isDev {
				fileinfo.notUpload = strings.HasPrefix(f.Name(), devPrefixKeep)
			} else {
				// this is going to be executed right after boot-up, so the availability of config for this app is subject to race condition
				// furthermore the config might not contain the appUUID anymore, so we are better off uploading the logs as default
				appuuid := getAppuuidFromLogfile(fileinfo)
				if val, found := domainUUID.Load(appuuid); found {
					appD := val.(appDomain)
					fileinfo.notUpload = appD.disableLogs
				} else {
					fileinfo.notUpload = false // default to upload
				}
			}

			if info, err := f.Info(); err == nil {
				fileinfo.inputSize = int32(info.Size())
			}
			movefile <- fileinfo
		}
	}
}

func trigMoveToGzip(stats *statsLogFile, appUUID string, moveChan chan fileChanInfo, timerTrig bool) {
	// check filesize over limit if not triggered by timeout
	if !timerTrig && stats.size < maxLogFileSize {
		return
	}

	if err := stats.file.Close(); err != nil {
		log.Fatal(err)
	}

	fileinfo := fileChanInfo{
		isApp:     appUUID != "",
		inputSize: stats.size,
		tmpfile:   stats.file.Name(),
		notUpload: stats.notUpload,
	}

	if timerTrig {
		log.Function("Move log file ", stats.file.Name(), " to gzip. Size: ", stats.size, " Reason timer")
	} else {
		log.Function("Move log file ", stats.file.Name(), " to gzip. Size: ", stats.size, " Reason size")
	}
	moveChan <- fileinfo

	if fileinfo.isApp { // appM stats and logfile is created when needed
		delete(appStatsMap, appUUID)
		return
	}

	// reset stats data and create new logfile for device
	var newStats statsLogFile
	if fileinfo.notUpload {
		newStats = initNewLogfile(collectDir, devPrefixKeep, "")
	} else {
		newStats = initNewLogfile(collectDir, devPrefixUpload, "")
	}
	newStats.index = stats.index // keep the index from the old file
	*stats = newStats
}

func initNewLogfile(dir, name, appuuid string) statsLogFile {
	// new file to collect device logs for upload
	stats := statsLogFile{
		file:      createLogTmpfile(dir, name),
		size:      0,
		starttime: time.Now(),
	}

	if name == devPrefixKeep {
		stats.notUpload = true
	}
	if name == devPrefixUpload {
		stats.notUpload = false
	}

	// write the first log metadata to the first line of the logfile, will be extracted when
	// doing gzip conversion. further log file's metadata is handled inside 'trigMoveToGzip()'
	_, err := stats.file.WriteString(formatAndGetMeta(appuuid) + "\n")
	if err != nil {
		log.Fatal("initNewLogfile: write metadata line ", err)
	}

	return stats
}

func getEveInfo() {
	for devMetaData.curPart = agentlog.EveCurrentPartition(); devMetaData.curPart == "Unknown"; devMetaData.curPart = agentlog.EveCurrentPartition() {
		log.Errorln("currPart unknown")
		time.Sleep(time.Second)
	}
	for devMetaData.imageVer = agentlog.EveVersion(); devMetaData.imageVer == "Unknown"; devMetaData.imageVer = agentlog.EveVersion() {
		log.Errorln("imageVer unknown")
		time.Sleep(time.Second)
	}
}

func cleanGzipTempfiles(dir string) {
	gfiles, err := os.ReadDir(dir)
	if err == nil {
		for _, f := range gfiles {
			if !f.IsDir() && strings.HasPrefix(f.Name(), tmpPrefix) && len(f.Name()) > len(tmpPrefix) {
				err = os.Remove(dir + "/" + f.Name())
				if err != nil {
					log.Error(err)
				}
			}
		}
	}
}

func getOldestLog() (*logs.LogEntry, error) {
	// Read the directory and filter log files
	files, err := os.ReadDir(keepSentDir)
	if err != nil {
		return nil, fmt.Errorf("error reading directory: %w", err)
	}

	oldestLogFileName := ""
	oldestLogFileTimestamp := time.Now()

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		timestamp, err := types.GetTimestampFromGzipName(file.Name())
		if err != nil {
			continue
		}
		if timestamp.Before(oldestLogFileTimestamp) {
			oldestLogFileTimestamp = timestamp
			oldestLogFileName = file.Name()
		}
	}

	if oldestLogFileName == "" {
		log.Function("getLatestLog: no log files found.")
		return nil, nil
	}

	// Open the oldest log file
	oldestFile := filepath.Join(keepSentDir, oldestLogFileName)
	file, err := os.Open(oldestFile)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Create a gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("error creating gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Read lines from the gzip file
	scanner := bufio.NewScanner(gzReader)
	scanner.Scan()
	firstLine := scanner.Text() // we assume the first line to be the oldest log entry

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading gzip file: %w", err)
	}

	if firstLine == "" {
		log.Functionf("gzip log file %s is empty", oldestFile)
		return nil, nil
	}

	var entry logs.LogEntry
	if err = json.Unmarshal([]byte(firstLine), &entry); err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	return &entry, nil
}

// update device log source map for metrics64
func updateDevInputlogStats(source string, size uint64) {
	var b uint64
	val, ok := devSourceBytes.Load(source)
	if ok {
		b = val.(uint64)
	}
	b += size
	devSourceBytes.Store(source, b)

	logmetrics.DevMetrics.NumBytesWrite += size
}

// Check the nested app log message of docker runtime app
func processNestedAppLogMessage(entry *inputEntry, vmAppUUID string) string {
	var appUUID string
	if vmApp, ok := domainUUID.Load(vmAppUUID); !ok {
		return appUUID // Exit early if the app domain does not exist
	} else if vm, ok := vmApp.(appDomain); !ok {
		return appUUID // Exit early if the app domain is not of type appDomain
	} else {
		if !vm.nestedAppVM {
			return appUUID // Exit early if the app is not a nested app VM
		}
	}

	var nestedAppLogMsg nestedapp.NestedAppInstanceLogMsg
	if err := json.Unmarshal([]byte(entry.content), &nestedAppLogMsg); err != nil {
		return appUUID // Exit early if JSON unmarshalling fails
	}

	if nestedAppLogMsg.NestedAppId == "" {
		return appUUID // Exit early if no NestedAppId exists
	}

	if _, ok := domainUUID.Load(nestedAppLogMsg.NestedAppId); ok {
		// Nested app domain status exists, return the nestedApp appUUID
		appUUID = nestedAppLogMsg.NestedAppId
		entry.content = formatNestedAppLogContent(nestedAppLogMsg.ContainerName, nestedAppLogMsg.Msg)
	} else {
		// Nested app domain status not set up yet
		entry.content = formatParentRuntimeLogContent(nestedAppLogMsg.NestedAppId, nestedAppLogMsg.ContainerName, nestedAppLogMsg.Msg)
	}

	return appUUID
}

func formatNestedAppLogContent(containerName, msg string) string {
	return "{\"container-name\":\"" + containerName + "\",\"msg\":\"" + msg + "\"}"
}

// formatParentRuntimeLogContent expects it's parameters already be sanitized for use in json
func formatParentRuntimeLogContent(nestedAppId, containerName, msg string) string {
	return "{\"nested-app-uuid\":\"" + nestedAppId + "\",\"container-name\":\"" + containerName + "\",\"msg\":\"" + msg + "\"}"
}

func createLogTmpfile(dirname, filename string) *os.File {
	tmpFile, err := os.CreateTemp(dirname, filename)
	if err != nil {
		log.Fatal(err)
	}
	err = tmpFile.Chmod(0600)
	if err != nil {
		log.Fatal(err)
	}
	log.Function("Created new temp log file: ", tmpFile.Name())
	// make symbolic link for device log file to keep
	if filename == devPrefixKeep {
		if err := os.Remove(tmpSymlink); err != nil && !os.IsNotExist(err) { // remove a stale one
			log.Error(err)
		}
		err = os.Symlink(path.Base(tmpFile.Name()), tmpSymlink)
		if err != nil {
			log.Error(err)
		}
		err = os.Rename(tmpSymlink, symlinkFile)
		if err != nil {
			log.Error(err)
		}
		log.Function("Pointed symlink ", symlinkFile, " to ", tmpFile.Name())
	}
	return tmpFile
}
