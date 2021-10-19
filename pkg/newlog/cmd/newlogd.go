// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/euank/go-kmsg-parser/kmsgparser"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	agentName              = "newlogd"
	errorTime              = 3 * time.Minute
	warningTime            = 40 * time.Second
	metricsPublishInterval = 300 * time.Second
	logfileDelay           = 300 // maximum delay 5 minutes for log file collection
	fastlogfileDelay       = 10  // faster to close log file if fastUpload is enabled
	stillRunningInerval    = 25 * time.Second

	collectDir   = types.NewlogCollectDir
	uploadDevDir = types.NewlogUploadDevDir
	uploadAppDir = types.NewlogUploadAppDir
	keepSentDir  = types.NewlogKeepSentQueueDir
	failSendDIr  = types.NewlogDir + "/failedUpload"
	panicFileDir = types.NewlogDir + "/panicStacks"
	symlinkFile  = collectDir + "/current.device.log"
	tmpSymlink   = collectDir + "/tmp-sym.dev.log"
	devPrefix    = types.DevPrefix
	appPrefix    = types.AppPrefix
	tmpPrefix    = "TempFile"
	skipUpload   = "skipTx."

	maxLogFileSize   int32 = 550000 // maximum collect file size in bytes
	maxGzipFileSize  int64 = 50000  // maximum gzipped file size for upload in bytes
	defaultSyncCount       = 30     // default log events flush/sync to disk file

	maxToSendMbytes uint32 = 2048 // default 2 Gbytes for log files remains on disk

	ansi = "[\u0009\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
)

var (
	logger *logrus.Logger
	log    *base.LogObject

	msgIDDevCnt   uint64              = 1 // every log message increments the msg-id by 1
	logmetrics    types.NewlogMetrics     // the log metric, publishes to zedagent
	devMetaData   devMeta
	logmetaData   string
	syncToFileCnt int    // every 'N' log event count flush to log file
	persistMbytes uint64 // '/persist' disk space total in Mbytes
	gzipFilesCnt  int64  // total gzip files written
	panicBuf      []byte // buffer to save panic crash stack

	limitGzipFilesMbyts uint32 // maximum Mbytes for gzip files remain to be sent up

	enableFastUpload bool // enable fast upload to controller similar to previous log operation

	subGlobalConfig  pubsub.Subscription

	schedResetTimer *time.Timer // after detect log has watchdog going down message, reset the file flush count
	panicWriteTimer *time.Timer // after detect pillar panic, in case no other log comes in, write the panic files

	// per app writelog stats
	appStatsMap map[string]statsLogFile

	// device source input bytes written to log file
	devSourceBytes map[string]uint64

	//domainUUID
	domainUUID map[string]appDomain // App log, from domain-id to app-UUID and app-Name
	// syslog/kmsg priority string definition
	priorityStr = [8]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
)

// for app Domain-ID mapping into UUID and DisplayName
type appDomain struct {
	appUUID     string
	appName     string
	msgIDAppCnt uint64
	disableLogs bool
	trigMove    bool
}

type inputEntry struct {
	severity  string
	source    string
	content   string // One line
	pid       string
	filename  string // file name that generated the logmsg
	function  string // function name that generated the log msg
	timestamp string
	appUUID   string // App UUID
	acName    string // App Container Name
	acLogTime string // App Container log time
}

// collection time device/app temp file stats for file size and time limit
type statsLogFile struct {
	index      int
	file       *os.File
	size       int32
	starttime  time.Time
	notUpload  bool
}

// file info passing from collection to compression threads
type fileChanInfo struct {
	tmpfile   string
	header    string
	inputSize int32
	isApp     bool
	notUpload bool   // app log is configured not to upload
}

// device Meta Data
type devMeta struct {
	uuid     string
	imageVer string
	curPart  string
}

// newlogd program
func main() {
	restartPtr := flag.Bool("r", false, "Restart")
	flag.Parse()
	restarted := *restartPtr

	logger, log = agentlog.Init(agentName)

	if !restarted {
		if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
			log.Fatal(err)
		}
		syncToFileCnt = defaultSyncCount
	} else {
		// sync every log event in restart mode, going down in less than 5 min
		syncToFileCnt = 1
	}

	persistMbytes = getPersistSpace()
	limitGzipFilesMbyts = maxToSendMbytes

	log.Functionf("newlogd: starting... restarted %v", restarted)

	loggerChan := make(chan inputEntry, 10)
	movefileChan := make(chan fileChanInfo, 5)
	panicFileChan := make(chan []byte, 2)

	ps := *pubsub.New(&socketdriver.SocketDriver{Logger: logger, Log: log}, logger, log)

	// handle the write log messages to /persist/newlog/collect/ logfiles
	go writelogFile(loggerChan, movefileChan)

	// handle the kernel messages
	go getKmessages(loggerChan)

	// handle collect other container log messages from memlogd
	go getMemlogMsg(loggerChan, panicFileChan)

	// handle linux Syslog /dev/log messages
	go getSyslogMsg(loggerChan)

	stillRunning := time.NewTicker(stillRunningInerval)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Publish newlog metrics
	metricsPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.NewlogMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}
	err = metricsPub.ClearRestarted()
	if err != nil {
		log.Fatal(err)
	}

	// domain-name to UUID and App-name mapping
	domainUUID = make(map[string]appDomain)
	// Get DomainStatus from domainmgr
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		TopicImpl:     types.DomainStatus{},
		Activate:      true,
		CreateHandler: handleDomainStatusCreate,
		ModifyHandler: handleDomainStatusModify,
		DeleteHandler: handleDomainStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		CreateHandler: handleOnboardStatusCreate,
		ModifyHandler: handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      true,
		Persistent:    true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for global config such as log levels
	subGlobalConfig, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	err = subGlobalConfig.Activate()
	if err != nil {
		log.Fatal(err)
	}

	subUploadMetrics, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "loguploader",
		CreateHandler: handleUploadMetricsCreate,
		ModifyHandler: handleUploadMetricsModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.NewlogMetrics{},
		Activate:      true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// newlog Metrics publish timer. Publish log metrics every 5 minutes.
	interval := time.Duration(metricsPublishInterval)
	max := float64(interval)
	min := max * 0.3
	metricsPublishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	schedResetTimer = time.NewTimer(1 * time.Second)
	schedResetTimer.Stop()
	panicWriteTimer = time.NewTimer(1 * time.Second)
	panicWriteTimer.Stop()

	// set default timeout of logfile delay
	if enableFastUpload {
		logmetrics.LogfileTimeoutSec = uint32(fastlogfileDelay)
	} else {
		logmetrics.LogfileTimeoutSec = uint32(logfileDelay)
	}

	for {
		select {
		case <-metricsPublishTimer.C:
			getDevTop10Inputs()
			err = metricsPub.Publish("global", logmetrics)
			if err != nil {
				log.Error(err)
			}
			log.Tracef("newlodg main: Published newlog metrics at %s", time.Now().String())
			// check and handle if logfile quota exceeded
			checkKeepQuota()

		case change := <-subDomainStatus.MsgChan():
			subDomainStatus.ProcessChange(change)

		case change := <-subUploadMetrics.MsgChan():
			subUploadMetrics.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case tmpLogfileInfo := <-movefileChan:
			// handle logfile to gzip conversion work
			doMoveCompressFile(tmpLogfileInfo)

		case panicBuf := <- panicFileChan:
			// save panic stack into files
			savePanicFiles(panicBuf)

		case <- panicWriteTimer.C:
			if len(panicBuf) > 0 {
				savePanicFiles(panicBuf)
				panicBuf = nil
			}

		case <-schedResetTimer.C:
			syncToFileCnt = defaultSyncCount

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

// Handles upload side of Newlog metrics
func handleUploadMetricsCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleUploadMetricsImp(ctxArg, key, statusArg)
}

// Handles upload side of Newlog metrics
func handleUploadMetricsModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleUploadMetricsImp(ctxArg, key, statusArg)
}

// Handles and combine loguploader side of Newlog metrics
func handleUploadMetricsImp(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.NewlogMetrics)
	logmetrics.TotalBytesUpload = status.TotalBytesUpload
	logmetrics.Num4xxResponses = status.Num4xxResponses
	logmetrics.NumTooManyRequest = status.NumTooManyRequest
	logmetrics.Latency.MinUploadMsec = status.Latency.MinUploadMsec
	logmetrics.Latency.MaxUploadMsec = status.Latency.MaxUploadMsec
	logmetrics.Latency.AvgUploadMsec = status.Latency.AvgUploadMsec
	logmetrics.Latency.CurrUploadMsec = status.Latency.CurrUploadMsec

	logmetrics.CurrUploadIntvSec = status.CurrUploadIntvSec

	logmetrics.ServerStats.CurrCPULoadPCT = status.ServerStats.CurrCPULoadPCT
	logmetrics.ServerStats.AvgCPULoadPCT = status.ServerStats.AvgCPULoadPCT
	logmetrics.ServerStats.CurrProcessMsec = status.ServerStats.CurrProcessMsec
	logmetrics.ServerStats.AvgProcessMsec = status.ServerStats.AvgProcessMsec

	// loguplader signal to newlogd on upload fail status
	logmetrics.FailedToSend = status.FailedToSend
	logmetrics.FailSentStartTime = status.FailSentStartTime
	logmetrics.LastTooManyReqTime = status.LastTooManyReqTime

	logmetrics.DevMetrics.NumGZipFilesSent = status.DevMetrics.NumGZipFilesSent
	logmetrics.DevMetrics.NumGzipFileInDir = status.DevMetrics.NumGzipFileInDir
	logmetrics.DevMetrics.NumGZipFileRetry = status.DevMetrics.NumGZipFileRetry
	logmetrics.DevMetrics.RecentUploadTimestamp = status.DevMetrics.RecentUploadTimestamp
	logmetrics.DevMetrics.LastGZipFileSendTime = status.DevMetrics.LastGZipFileSendTime
	logmetrics.DevMetrics.NumGZipFileKeptLocal = status.DevMetrics.NumGZipFileKeptLocal

	logmetrics.AppMetrics.NumGZipFilesSent = status.AppMetrics.NumGZipFilesSent
	logmetrics.AppMetrics.NumGzipFileInDir = status.AppMetrics.NumGzipFileInDir
	logmetrics.AppMetrics.NumGZipFileRetry = status.AppMetrics.NumGZipFileRetry
	logmetrics.AppMetrics.RecentUploadTimestamp = status.AppMetrics.RecentUploadTimestamp
	logmetrics.AppMetrics.LastGZipFileSendTime = status.AppMetrics.LastGZipFileSendTime
	logmetrics.AppMetrics.NumGZipFileKeptLocal = status.AppMetrics.NumGZipFileKeptLocal

	log.Tracef("newlogd handleUploadMetricsModify changed to %+v", status)
}

// Handles UUID change from process client
func handleOnboardStatusCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleOnboardStatusImp(ctxArg, key, statusArg)
}

// Handles UUID change from process client
func handleOnboardStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleOnboardStatusImp(ctxArg, key, statusArg)
}

// Handles UUID change from process client
func handleOnboardStatusImp(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.OnboardingStatus)
	if cmp.Equal(devMetaData.uuid, status.DeviceUUID.String()) {
		log.Tracef("newlogd handleOnboardStatusModify no change to %s", devMetaData.uuid)
		return
	}
	devMetaData.uuid = status.DeviceUUID.String()
	logmetaData = formatAndGetMeta("")
	log.Functionf("newlogd handleOnboardStatusModify changed to %+v", devMetaData)
}

func handleDomainStatusCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleDomainStatusImp(ctxArg, key, statusArg)
}

func handleDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDomainStatusImp(ctxArg, key, statusArg)
}

func handleDomainStatusImp(ctxArg interface{}, key string, statusArg interface{}) {

	log.Tracef("handleDomainStatusModify: for %s", key)
	status := statusArg.(types.DomainStatus)
	// Record the domainName even if Pending* is set
	log.Tracef("handleDomainStatusModify: add %s to %s",
		status.DomainName, status.UUIDandVersion.UUID.String())
	appD := appDomain{
		appUUID:     status.UUIDandVersion.UUID.String(),
		appName:     status.DisplayName,
		disableLogs: status.DisableLogs,
		msgIDAppCnt: 1,
	}

	// close the app log file if already opened due to app log policy change
	if d, ok := domainUUID[appD.appUUID]; ok {
		if d.disableLogs != appD.disableLogs {
			appD.trigMove = true
		} else {
			appD.trigMove = d.trigMove
		}
		appD.msgIDAppCnt = d.msgIDAppCnt // inherit the counter for the app
	}
	domainUUID[appD.appUUID] = appD
	log.Tracef("handleDomainStatusModify: done for %s", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string, statusArg interface{}) {

	log.Tracef("handleDomainStatusDelete: for %s", key)
	status := statusArg.(types.DomainStatus)
	appUUID := status.UUIDandVersion.UUID.String()
	if _, ok := domainUUID[appUUID]; !ok {
		return
	}
	log.Tracef("handleDomainStatusDelete: remove %s", appUUID)
	delete(domainUUID, appUUID)
	log.Tracef("handleDomainStatusDelete: done for %s", key)
}

// Handles create events
func handleGlobalConfigCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleGlobalConfigImp(ctxArg, key, statusArg)
}

// Handles modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImp(ctxArg, key, statusArg)
}

func handleGlobalConfigImp(ctxArg interface{}, key string, statusArg interface{}) {
	if key != "global" {
		log.Tracef("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	debug, gcp := agentlog.HandleGlobalConfig(log, subGlobalConfig, agentName, false, logger)

	if gcp != nil {
		enabled := gcp.GlobalValueBool(types.AllowLogFastupload)
		if enableFastUpload != enabled {
			if enabled {
				logmetrics.LogfileTimeoutSec = uint32(fastlogfileDelay)
			} else {
				logmetrics.LogfileTimeoutSec = uint32(logfileDelay)
			}
		}
		enableFastUpload = enabled

		// get user specified disk quota for logs and cap at 10% of /persist space
		limitGzipFilesMbyts = gcp.GlobalValueInt(types.LogRemainToSendMBytes)
		if limitGzipFilesMbyts > uint32(persistMbytes / 10) {
			limitGzipFilesMbyts = uint32(persistMbytes / 10)
		}
	}
	log.Tracef("handleGlobalConfigModify done for %s, debug set %v, fastupload enabled %v", key, debug, enableFastUpload)
}

// getKmessages - goroutine to get from /dev/kmsg
func getKmessages(loggerChan chan inputEntry) {
	parser, err := kmsgparser.NewParser()
	if err != nil {
		log.Fatalf("unable to create kmsg parser: %v", err)
	}
	defer parser.Close()

	kmsg := parser.Parse()
	for msg := range kmsg {
		entry := inputEntry{
			source:    "kernel",
			severity:  "info",
			content:   msg.Message,
			timestamp: msg.Timestamp.Format(time.RFC3339Nano),
		}
		if msg.Priority >= 0 {
			entry.severity = priorityStr[msg.Priority % 8]
		}

		logmetrics.NumKmessages++
		logmetrics.DevMetrics.NumInputEvent++
		log.Tracef("getKmessages (%d) entry msg %s", logmetrics.NumKmessages, entry.content)

		loggerChan <- entry
	}
}

// getMemlogMsg - goroutine to get messages from memlogd queue
func getMemlogMsg(logChan chan inputEntry, panicFileChan chan []byte) {
	sockName := fmt.Sprintf("/run/%s.sock", "memlogdq")
	s, err := net.Dial("unix", sockName)
	if err != nil {
		log.Fatal("getMemlogMsg: Dial:", err)
	}
	defer s.Close()
	log.Functionf("getMemlogMsg: got socket for memlogdq")

	var writeByte byte = 2
	readTimeout := 30 * time.Second

	// have to write byte value 2 to trigger memlogd queue streaming
	_, err = s.Write([]byte{writeByte})
	if err != nil {
		log.Fatal("getMemlogMsg: write to memlogd failed:", err)
	}

	var panicStackCount int
	bufReader := bufio.NewReader(s)
	for {
		if err = s.SetDeadline(time.Now().Add(readTimeout)); err != nil {
			log.Fatal("getMemlogMsg: SetDeadline:", err)
		}

		bytes, err := bufReader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF && !strings.HasSuffix(err.Error(), "i/o timeout") {
				log.Fatal("getMemlogMsg: bufRead Read:", err)
			}
		}
		if len(bytes) == 0 {
			time.Sleep(5 * time.Second)
			continue
		}
		sourceName, msgTime, origMsg := getSourceFromMsg(string(bytes))
		logInfo, ok := agentlog.ParseLoginfo(origMsg)

		var pidStr string
		var isApp bool

		if strings.Contains(string(bytes), "guest_vm") {
			logmetrics.AppMetrics.NumInputEvent++
			logInfo.Source = sourceName
			logInfo.Msg = origMsg
			isApp = true
		} else if logInfo.Containername != "" {
			logmetrics.AppMetrics.NumInputEvent++
			isApp = true
		} else {
			logInfo.Msg = origMsg
			logmetrics.DevMetrics.NumInputEvent++
		}
		if !ok {
			// not in json or right json format, try to reformat
			logInfo = repaireMsg(origMsg, msgTime, sourceName)
		}
		if logInfo.Msg == "" {
			logInfo.Msg = origMsg
		}
		if !isApp && logInfo.Source == "" {
			logInfo.Source = sourceName
		}
		if logInfo.Time == "" && strings.HasSuffix(msgTime, "Z") {
			logInfo.Time = msgTime
		}
		if logInfo.Pid != 0 {
			pidStr = strconv.Itoa(logInfo.Pid)
		}
		entry := inputEntry{
			source:    logInfo.Source,
			content:   logInfo.Msg,
			pid:       pidStr,
			timestamp: logInfo.Time,
			function:  logInfo.Function,
			filename:  logInfo.Filename,
			severity:  logInfo.Level,
			appUUID:   logInfo.Appuuid,
			acName:    logInfo.Containername,
			acLogTime: logInfo.Eventtime,
		}

		// if we are in watchdog going down. fsync often
		checkWatchdogRestart(&entry, &panicStackCount, string(bytes), panicFileChan)

		logChan <- entry
	}
}

func repaireMsg(content, savedTimestamp, sourceName string) agentlog.Loginfo {
	// repair oversized json msg
	myStr := remNonPrintable(content)
	myStr1 := strings.Split(myStr, ",\"msg\":")
	var loginfo agentlog.Loginfo
	var ok bool
	if loginfo.Time == "" {
		loginfo.Time = savedTimestamp
	}
	if loginfo.Source == "" {
		loginfo.Source = sourceName
	}
	if len(myStr1) == 1 { // no msg:
		var nsev, nmsg string
		level := strings.SplitN(content, "level=", 2)
		if len(level) == 2 {
			level2 := strings.Split(level[1], " ")
			nsev = level2[0]
		}
		msg := strings.SplitN(content, "msg=", 2)
		if len(msg) == 2 {
			msg2 := strings.Split(msg[1], "\"")
			if len(msg2) == 3 {
				nmsg = msg2[1]
			}
		}
		if nsev != "" || nmsg != "" {
			loginfo.Level = nsev
			loginfo.Msg = nmsg
			ok = true
		}
	} else {
		msgStr := myStr1[0]
		if string(msgStr[len(msgStr)-1]) != "}" {
			msgStr += "}"
		}
		loginfo, ok = agentlog.ParseLoginfo(msgStr)
		if ok {
			loginfo.Msg = myStr1[1]
		}
	}
	if !ok {
		loginfo.Level = "info"
		loginfo.Msg = content
	}
	return loginfo
}

func getSourceFromMsg(msg string) (string, string, string) {
	var source, content string
	lines := strings.SplitN(msg, ";", 2)
	if len(lines) != 2 {
		return source, "", content
	}
	content = lines[1]
	lines2 := strings.Split(lines[0], ",")
	n := len(lines2)
	if n < 2 {
		return source, "", content
	}
	return lines2[n-1], lines2[n-2], content
}

func startTmpfile(dirname, filename string, isApp bool) *os.File {
	tmpFile, err := ioutil.TempFile(dirname, filename)
	if err != nil {
		log.Fatal(err)
	}
	err = tmpFile.Chmod(0600)
	if err != nil {
		log.Fatal(err)
	}
	// make symbolic link for device temp logfiles
	if !isApp {
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
	}
	return tmpFile
}

func remNonPrintable(str string) string {
	var re = regexp.MustCompile(ansi)
	myStr := re.ReplaceAllString(str, "")
	myStr = strings.Trim(myStr, "\r")
	return strings.Trim(myStr, "\n")
}

// writelogFile - a goroutine to format and write log entries into dev/app logfiles
func writelogFile(logChan <-chan inputEntry, moveChan chan fileChanInfo) {

	if _, err := os.Stat(collectDir); os.IsNotExist(err) {
		if err := os.MkdirAll(collectDir, 0755); err != nil {
			log.Fatal(err)
		}
	}

	// move and gzip the existing logfiles first
	logmetaData = findMovePrevLogFiles(moveChan)

	// new logfile
	devlogFile := startTmpfile(collectDir, devPrefix, false)
	defer devlogFile.Close()

	var fileinfo fileChanInfo
	var devStats statsLogFile

	devSourceBytes = make(map[string]uint64)
	appStatsMap = make(map[string]statsLogFile)
	checklogTimer := time.NewTimer(5 * time.Second)
	devStats.file = devlogFile

	// write the first log metadata to the first line of the logfile, will be extracted when
	// doing gzip conversion. further log file's metadata is handled inside 'trigMoveToGzip()'
	_, err := devStats.file.WriteString(logmetaData + "\n")
	if err != nil {
		log.Fatal(err)
	}

	timeIdx := 0
	for {
		select {
		case <-checklogTimer.C:
			timeIdx++
			checkLogTimeExpire(fileinfo, &devStats, moveChan)
			checklogTimer = time.NewTimer(5 * time.Second)  // check the file time limit every 5 seconds

		case entry := <-logChan:
			appuuid := checkAppEntry(&entry)
			var appM statsLogFile
			if appuuid != "" {
				appM = getAppStatsMap(appuuid)
			}
			timeS := getPtypeTimestamp(entry.timestamp)
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
				len := writelogEntry(&appM, logline)

				logmetrics.AppMetrics.NumBytesWrite += uint64(len)
				appStatsMap[appuuid] = appM

				trigMoveToGzip(fileinfo, &appM, appuuid, moveChan, false)

			} else {
				len := writelogEntry(&devStats, logline)
				updateDevInputlogStats(entry.source, uint64(len))

				trigMoveToGzip(fileinfo, &devStats, "", moveChan, false)
			}
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
				if du, ok := domainUUID[appsource[0]]; ok {
					appuuid = du.appUUID
				} else {
					log.Tracef("entry.source not in right format %s", entry.source)
				}
			}
		}
	}
	return appuuid
}

// updateLogMsgID - handles the msgID for log for both dev and apps
// dev log does not have app-uuid, thus domainName passed in is ""
func updateLogMsgID(appUUID string) uint64 {
	var msgid uint64
	if appUUID == "" {
		msgid = msgIDDevCnt
		msgIDDevCnt++
	} else {
		if _, ok := domainUUID[appUUID]; ok {
			appD := domainUUID[appUUID]
			msgid = appD.msgIDAppCnt
			appD.msgIDAppCnt++
			domainUUID[appUUID] = appD
		}
	}

	return msgid
}

func getAppStatsMap(appuuid string) statsLogFile {
	if _, ok := appStatsMap[appuuid]; !ok {
		applogname := appPrefix + appuuid + ".log"
		applogfile := startTmpfile(collectDir, applogname, true)

		var notUpload bool
		for _, appD := range domainUUID {
			if appD.appUUID == appuuid {
				notUpload = appD.disableLogs
				if appD.trigMove {
					appD.trigMove = false // reset this since we start a new file
					domainUUID[appuuid] = appD
				}
				break
			}
		}

		appM := statsLogFile{
			file:       applogfile,
			starttime:  time.Now(),
			notUpload:  notUpload,
		}
		appStatsMap[appuuid] = appM

		// write the metadata to the first line of app logfile, for App, just the appName info
		_, err := appM.file.WriteString(formatAndGetMeta(appuuid) + "\n")
		if err != nil {
			log.Fatal("getAppStatsMap: write appName ", err)
		}
	}
	return appStatsMap[appuuid]
}

// update device log source map for metrics64
func updateDevInputlogStats(source string, size uint64) {
	b, ok := devSourceBytes[source]
	if !ok {
		b = 0
	}
	b += size
	devSourceBytes[source] = b

	logmetrics.DevMetrics.NumBytesWrite += size
}

// write log entry, update size and index, sync file if needed
func writelogEntry(stats *statsLogFile, logline string) int {
	len, err := stats.file.WriteString(logline)
	if err != nil {
		log.Fatal("writelogEntry: write logline ", err)
	}
	stats.size += int32(len)

	if stats.index%syncToFileCnt == 0 {
		err = stats.file.Sync()
		if err != nil {
			log.Error(err)
		}
	}
	stats.index++
	return len
}

type gfileStats struct {
	isSent   bool
	filename string
	filesize int64
}

func checkDirGzfiles(sfiles map[string]gfileStats, logdir string) ([]string, int64, error) {
	var sizes int64

	if _, err := os.Stat(logdir); err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, sizes, err
	}

	files, err := ioutil.ReadDir(logdir)
	if err != nil {
		return nil, sizes, err
	}

	var alreadySent bool
	if logdir == keepSentDir {
		alreadySent = true
	}

	keys := make([]string, 0, len(files))
	for _, f := range files {
		fname := f.Name()
		fsize := f.Size()
		fs := gfileStats{
			filename: logdir + "/" + fname,
			filesize: fsize,
			isSent: alreadySent,
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

	return keys, sizes, nil
}

// checkKeepQuota - keep gzip file sizes below the default or user defined quota limit
func checkKeepQuota() {
	maxSize := int64(limitGzipFilesMbyts * 1000000)
	sfiles := make(map[string]gfileStats)

	key0, size0, err := checkDirGzfiles(sfiles, keepSentDir)
	if err != nil {
		log.Errorf("checkKeepQuota: keepSentDir %v", err)
	}
	key1, size1, err := checkDirGzfiles(sfiles, uploadAppDir)
	if err != nil {
		log.Errorf("checkKeepQuota: AppDir %v", err)
	}
	key2, size2, err := checkDirGzfiles(sfiles, uploadDevDir)
	if err != nil {
		log.Errorf("checkKeepQuota: DevDir %v", err)
	}
	key3, size3, err := checkDirGzfiles(sfiles, failSendDIr)
	if err != nil && !os.IsNotExist(err) {
		log.Errorf("checkKeepQuota: FailToSendDir %v", err)
	}

	totalsize := size0 + size1 + size2 + size3
	removed := 0
	if totalsize > maxSize {
		keys := key0
		keys = append(keys, key1...)
		keys = append(keys, key2...)
		keys = append(keys, key3...)
		sort.Strings(keys)

		for _, key := range keys {
			if _, ok := sfiles[key]; !ok {
				continue
			}
			fs := sfiles[key]
			if _, err := os.Stat(fs.filename); err != nil {
				continue
			}
			if err := os.Remove(fs.filename); err != nil {
				log.Errorf("checkKeepQuota: remove failed %s, %v", fs.filename, err)
				continue
			}
			if !fs.isSent {
				logmetrics.NumGZipFileRemoved++
			}
			removed++
			totalsize -= fs.filesize
			if totalsize < maxSize {
				break
			}
		}
		log.Tracef("checkKeepQuota: %d gzip files removed", removed)
	}
}

func doMoveCompressFile(tmplogfileInfo fileChanInfo) {
	isApp := tmplogfileInfo.isApp
	dirName, appuuid := getFileInfo(tmplogfileInfo)

	now := time.Now()
	timenowNum := int(now.UnixNano() / int64(time.Millisecond)) // in msec
	outfile := gzipFileNameGet(isApp, timenowNum, dirName, appuuid, tmplogfileInfo.notUpload)

	// read input file
	ifile, err := os.Open(tmplogfileInfo.tmpfile)
	if err != nil {
		log.Fatal(err)
	}
	reader := bufio.NewReader(ifile)
	content, _ := ioutil.ReadAll(reader)

	c2 := bytes.SplitN(content, []byte("\n"), 2)
	if len(c2) != 2 { // most likely the file is created before any write on it
		err = fmt.Errorf("doMoveCompressFile: can't get metadata on first line, remove %s", tmplogfileInfo.tmpfile)
		log.Error(err)
		ifile.Close()
		err = os.Remove(tmplogfileInfo.tmpfile)
		if err != nil {
			log.Fatal("doMoveCompressFile: remove file failed", err)
		}
		return
	}

	// assign the metadata in the first line of the logfile
	tmplogfileInfo.header = string(c2[0])
	content = c2[1]
	newSize := gzipToOutFile(content, outfile, tmplogfileInfo, now)
	ifile.Close()

	// if the newSize exceeding the limit, split into multiple segments and redo the gzip on them
	var ratio int
	if newSize > maxGzipFileSize {
		// remove this new oversied gzip file
		os.Remove(outfile)

		ratio = int(newSize / maxGzipFileSize + 2) // minimum to 3 segments
		newSize = doGzipSplitContent(content, ratio, now, tmplogfileInfo)
		logmetrics.NumBreakGZipFile += uint32(ratio)
	} else {
		calculateGzipSizes(newSize)
	}

	if isApp {
		logmetrics.AppMetrics.NumGZipBytesWrite += uint64(newSize)
		if tmplogfileInfo.notUpload {
			if ratio > 0 {
				logmetrics.NumSkipUploadAppFile += uint32(ratio)
			} else {
				logmetrics.NumSkipUploadAppFile++
			}
		}
	} else {
		logmetrics.DevMetrics.NumGZipBytesWrite += uint64(newSize)
	}

	// done gzip conversion, get rid of the temp log file in collect directory
	err = os.Remove(tmplogfileInfo.tmpfile)
	if err != nil {
		log.Fatal("doMoveCompressFile: remove file failed", err)
	}
}

func calculateGzipSizes(size int64) {
	if uint32(size) > logmetrics.MaxGzipSize {
		logmetrics.MaxGzipSize = uint32(size)
	}
	oldtotal := int64(logmetrics.AvgGzipSize) * gzipFilesCnt
	gzipFilesCnt++
	logmetrics.AvgGzipSize = uint32((oldtotal + size) / gzipFilesCnt)
}

func doGzipSplitContent(content []byte, ratio int, now time.Time, info fileChanInfo) int64 {
	segments := breakGzipSegments(content, ratio)
	timenowNum := int(now.UnixNano() / int64(time.Millisecond)) // in msec
	dirName, appuuid := getFileInfo(info)
	var totalNewSize int64
	for idx, seg := range segments {
		outfile := gzipFileNameGet(info.isApp, timenowNum + idx, dirName, appuuid, info.notUpload)
		newSize := gzipToOutFile(seg, outfile, info, now)
		calculateGzipSizes(newSize)
		totalNewSize += newSize
	}
	return totalNewSize
}

func gzipToOutFile(content []byte, fName string, fHdr fileChanInfo, now time.Time) int64 {
	// open output file
	files := strings.Split(fName, "/")
	gzipfileName := files[len(files)-1]
	gzipDirName := strings.TrimSuffix(fName, "/"+gzipfileName)
	oTmpFile, err := ioutil.TempFile(gzipDirName, tmpPrefix)
	if err != nil {
		log.Fatal("gzipToOutFile: create tmp file failed ", err)
	}

	gw, _ := gzip.NewWriterLevel(oTmpFile, gzip.BestCompression)

	// for app upload, use gzip header 'Name' for appName string to simplify cloud side implementation
	// for now, the gw.Comment has the metadata for device log, and gw.Name for appName for app log
	if fHdr.isApp {
		gw.Name = fHdr.header
	} else {
		gw.Comment = fHdr.header
	}
	gw.ModTime = now

	_, err = gw.Write(content)
	if err != nil {
		log.Error(err)
	}
	err = gw.Close()
	if err != nil {
		log.Error(err)
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
		log.Fatal("gzipToOutFile: ofile stat error", err)
	}
	newSize := f2.Size()
	err = os.Rename(tmpFileName, fName)
	if err != nil {
		log.Fatal("gzipToOutFile: os.Rename error: ", err)
	}
	return newSize
}

func breakGzipSegments(content []byte, ratio int) [][]byte {
	contents := make([][]byte, ratio)
	fsize := len(content)
	blocksize := fsize / ratio
	s := 0
	presize := 0
	for {
		pos := 0
		for {
			size := blocksize * (s + 1) + pos
			pos++
			if size > fsize {
				err := fmt.Errorf("can't break the log file")
				log.Fatal(err)
			}
			if content[size] == '\n' { // find the newline to break
				size++
				contents[s] = content[presize:size]
				presize = size
				break
			}
		}
		s++
		if s + 1 == ratio { // done, assign the last segment
			contents[s] = content[presize:fsize]
			break
		}
	}
	return contents
}

func getFileInfo(tmplogfileInfo fileChanInfo) (string, string) {
	var dirName, appuuid string
	if tmplogfileInfo.isApp {
		if tmplogfileInfo.notUpload {
			dirName = types.NewlogKeepSentQueueDir
		} else {
			dirName = uploadAppDir
		}
		appuuid = getAppuuidFromLogfile(tmplogfileInfo)
	} else {
		if _, err := os.Stat(uploadDevDir); os.IsNotExist(err) {
			if err := os.Mkdir(uploadDevDir, 0755); err != nil {
				log.Fatal(err)
			}
		}
		dirName = uploadDevDir
	}
	return dirName, appuuid
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

func getAppuuidFromLogfile(tmplogfileInfo fileChanInfo) string {
	if _, err := os.Stat(uploadAppDir); os.IsNotExist(err) {
		if err := os.Mkdir(uploadAppDir, 0755); err != nil {
			log.Fatal(err)
		}
	}
	prefix := collectDir + "/" + appPrefix
	tmpStr1 := strings.TrimPrefix(tmplogfileInfo.tmpfile, prefix)
	tmpStr2 := strings.SplitN(tmpStr1, ".log", 2)
	return tmpStr2[0]
}

// at bootup, move the collected log files from previous life
func findMovePrevLogFiles(movefile chan fileChanInfo) string {
	files, err := ioutil.ReadDir(collectDir)
	if err != nil {
		log.Fatal("findMovePrevLogFiles: read dir ", err)
	}

	// get EVE version and partition, UUID may not be available yet
	getEveInfo()

	// remove any gzip file the name starts them 'Tempfile', it crashed before finished rename in dev/app dir
	cleanGzipTempfiles(uploadDevDir)
	cleanGzipTempfiles(uploadAppDir)

	// on prev life's dev-log and app-log
	for _, f := range files {
		isDev := strings.HasPrefix(f.Name(), devPrefix)
		isApp := strings.HasPrefix(f.Name(), appPrefix)
		if !f.IsDir() && (isDev && len(f.Name()) > len(devPrefix) || isApp && len(f.Name()) > len(appPrefix)) {
			var fileinfo fileChanInfo
			prevLogFile := collectDir + "/" + f.Name()
			fileinfo.tmpfile = prevLogFile
			fileinfo.isApp = isApp
			fileinfo.inputSize = int32(f.Size())

			movefile <- fileinfo
		}
	}

	return formatAndGetMeta("")
}

func trigMoveToGzip(fileinfo fileChanInfo, stats *statsLogFile, appUUID string, moveChan chan fileChanInfo, timerTrig bool) {
	// check filesize over limit if not triggered by timeout
	if !timerTrig && stats.size < maxLogFileSize {
		return
	}

	if err := stats.file.Close(); err != nil {
		log.Fatal(err)
	}

	isApp := appUUID != ""
	fileinfo.isApp = isApp
	fileinfo.inputSize = stats.size
	fileinfo.tmpfile = stats.file.Name()
	fileinfo.notUpload = stats.notUpload

	moveChan <- fileinfo

	if isApp { // appM stats and logfile is created when needed
		delete(appStatsMap, appUUID)
		return
	}

	// reset stats data and create new logfile for device
	stats.size = 0
	stats.file = startTmpfile(collectDir, devPrefix, isApp)
	stats.starttime = time.Now()

	_, err := stats.file.WriteString(logmetaData + "\n") // write the metadata in the first line of logfile
	if err != nil {
		log.Fatal("trigMoveToGzip: write metadata line ", err)
	}
}

func checkLogTimeExpire(fileinfo fileChanInfo, devStats *statsLogFile, moveChan chan fileChanInfo) {
	// check device log file
	if devStats.file != nil && devStats.size > 0 && uint32(time.Since(devStats.starttime).Seconds()) > logmetrics.LogfileTimeoutSec {
		trigMoveToGzip(fileinfo, devStats, "", moveChan, true)
	}

	// check app log files
	for appuuid, appM := range appStatsMap {
		if d, ok := domainUUID[appuuid]; ok { // if app disable-upload status changes, move file to gzip now
			if d.trigMove && appM.file != nil {
				d.trigMove = false
				domainUUID[appuuid] = d
				trigMoveToGzip(fileinfo, &appM, appuuid, moveChan, true)
				continue
			}
		}
		if appM.file != nil && appM.size > 0 && uint32(time.Since(appM.starttime).Seconds()) > logmetrics.LogfileTimeoutSec {
			trigMoveToGzip(fileinfo, &appM, appuuid, moveChan, true)
		}
	}
}

// for dev, returns the meta data, and for app, return the appName
func formatAndGetMeta(appuuid string) string {
	var appName string
	if appuuid != "" {
		for _, appD := range domainUUID { // cycle through the domainUUID map and find the UUID and appName
			if appD.appUUID == appuuid {
				appName = appD.appName
				return appName
			}
		}
	}
	metaStr := logs.LogBundle{
		DevID:      devMetaData.uuid,
		Image:      devMetaData.curPart,
		EveVersion: devMetaData.imageVer,
	}
	mapJmeta, _ := json.Marshal(&metaStr)
	return string(mapJmeta)
}

func getEveInfo() {
	for {
		devMetaData.curPart = agentlog.EveCurrentPartition()
		if devMetaData.curPart == "Unknown" {
			log.Errorln("currPart unknown")
			time.Sleep(time.Second)
			continue
		} else {
			break
		}
	}
	for {
		devMetaData.imageVer = agentlog.EveVersion()
		if devMetaData.imageVer == "Unknown" {
			log.Errorln("imageVer unknown")
			time.Sleep(time.Second)
			continue
		} else {
			break
		}
	}
}

func cleanGzipTempfiles(dir string) {
	gfiles, err := ioutil.ReadDir(dir)
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

// flush more often when we are going down by reading from watchdog log message itself
func checkWatchdogRestart(entry *inputEntry, panicStackCount *int, origMsg string, panicFileChan chan []byte) {
	// source can be watchdog or watchdog.err
	if strings.HasPrefix(entry.source, "watchdog") {
		if strings.Contains(entry.content, "Retry timed-out at") {
			entry.severity = "emerg"
			syncToFileCnt = 1

			// in case if the system does not go down, fire a timer to reset it to normal sync count
			schedResetTimer = time.NewTimer(300 * time.Second)
		}
		return
	}

	if entry.source == "pillar" && strings.Contains(origMsg, "pillar;panic") && !strings.Contains(entry.content, "rebootReason") {
		*panicStackCount = 1
		panicBuf = append(panicBuf, []byte(origMsg)...)
		// in case there is only few log messages after this, kick off a timer to write the panic files
		panicWriteTimer = time.NewTimer(10 * time.Second)
	} else if *panicStackCount > 0 {
		var done bool
		if entry.source == "pillar" {
			panicBuf = append(panicBuf, []byte(origMsg)...)
		} else {
			// conclude the capture when log source is not 'pillar'
			done = true
		}

		*panicStackCount++

		if *panicStackCount > 15 || done {
			panicWriteTimer.Stop()
			*panicStackCount = 0
			panicFileChan <- panicBuf
			panicBuf = nil
		}
	}
}

func savePanicFiles(panicbuf []byte) {
	var reason string
	panicStr := string(panicbuf)
	strs := strings.Split(panicStr, "\n")
	if len(strs) > 1 {
		reason = strs[0]
		f1, err := os.OpenFile("/persist/reboot-reason", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error(err)
			return
		}
		defer f1.Close()
		if _, err := f1.WriteString(reason); err != nil {
			log.Error(err)
		}
	}

	f2, err := os.OpenFile("/persist/reboot-stack", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error(err)
		return
	}
	defer f2.Close()
	if _, err := f2.WriteString(panicStr); err != nil {
		log.Error(err)
	}

	// save to /persist/newlog/panicStacks directory for maximum of 100 files
	if _, err := os.Stat(panicFileDir); os.IsNotExist(err) {
		if err := os.MkdirAll(panicFileDir, 0755); err != nil {
			log.Error(err)
			return
		}
	}

	now := time.Now()
	timeStr := strconv.Itoa(int(now.Unix()))
	fileName := panicFileDir + "/pillar-panic-stack." + timeStr
	pfile, err := os.Create(fileName)
	if err != nil {
		log.Error(err)
		return
	}
	defer pfile.Close()

	_, err = pfile.WriteString(logmetaData + "\n")
	if err != nil {
		log.Error(err)
	}
	_, err = pfile.WriteString(panicStr)
	if err != nil {
		log.Error(err)
	}

	cleanPanicFileDir()
}

// clean up the old panic files if the directory has more than 100 files
func cleanPanicFileDir() {
	if _, err := os.Stat(panicFileDir); err != nil {
		return
	}

	files, err := ioutil.ReadDir(panicFileDir)
	if err != nil {
		log.Error(err)
		return
	}

	if len(files) <= 100 {
		return
	}

	var minNum int
	var getFileName string
	for _, f := range files {
		p := strings.Split(f.Name(), ".")
		if len(p) != 2 {
			continue
		}
		fnumber, err := strconv.Atoi(p[1])
		if err != nil {
			continue
		}
		if minNum == 0 || fnumber < minNum {
			minNum = fnumber
			getFileName = f.Name()
		}
	}

	if getFileName != "" {
		err := os.Remove(panicFileDir + "/" + getFileName)
		if err != nil {
			log.Error(err)
			return
		}
	}
}

func rankByInputCount(Frequencies map[string]uint64) pairList {
	pl := make(pairList, len(Frequencies))
	i := 0
	for k, v := range Frequencies {
		pl[i] = pair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(pl))
	return pl
}

type pair struct {
	Key   string
	Value uint64
}

type pairList []pair

func (p pairList) Len() int           { return len(p) }
func (p pairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p pairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// generate top 10 contributor in total bytes from services
func getDevTop10Inputs() {
	if logmetrics.DevMetrics.NumBytesWrite == 0 {
		return
	}

	top10 := make(map[string]uint32)
	pl := rankByInputCount(devSourceBytes)
	for i, p := range pl {
		if i >= 10 {
			break
		}
		top10[p.Key] = uint32(p.Value * 100 / logmetrics.DevMetrics.NumBytesWrite)
	}
	logmetrics.DevTop10InputBytesPCT = top10
}

func getPtypeTimestamp(timeStr string) *timestamp.Timestamp {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		log.Fatal(err)
	}
	tt := &timestamp.Timestamp{Seconds: t.Unix(), Nanos: int32(t.Nanosecond())}
	return tt
}

// get total MBytes in '/persist' partition on device
func getPersistSpace() uint64 {
	var stat syscall.Statfs_t
	err := syscall.Statfs(types.PersistDir, &stat)
	if err != nil {
		log.Fatal(err)
	}
	return stat.Blocks * uint64(stat.Bsize) / uint64(1000000)
}

// getSyslogMsg - go routine to handle syslog input
func getSyslogMsg(loggerChan chan inputEntry) {

	sysfmt := regexp.MustCompile("<([0-9]+)>(.{15}|.{25}) (.*?): (.*)")
	conn, err := listenUnix()
	if err != nil {
		log.Error(err)
		return
	}

	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			log.Error(err)
			return
		}

		entry, err := newMessage(buf, n, sysfmt)
		if err != nil {
			log.Error(err)
			continue
		}

		logmetrics.NumSyslogMessages++
		logmetrics.DevMetrics.NumInputEvent++
		log.Tracef("getSyslogMsg (%d) entry msg %s", logmetrics.NumSyslogMessages, entry.content)

		loggerChan <- entry
	}
}

//func listenUnix() (net.PacketConn, error) {
func listenUnix() (*net.UnixConn, error) {
	UnixPath := "/dev/log"
	os.Remove(UnixPath)
	a, err := net.ResolveUnixAddr("unixgram", UnixPath)
	if err != nil {
		return nil, err
	}
	unix, err := net.ListenUnixgram("unixgram", a)
	if err != nil {
		return nil, err
	}
	err = os.Chmod(UnixPath, 0666)
	if err != nil {
		return nil, err
	}

	return unix, nil
}

func newMessage(pkt []byte, size int, sysfmt *regexp.Regexp) (inputEntry, error) {
	entry := inputEntry{}
	res := sysfmt.FindSubmatch(pkt)
	if len(res) != 5 {
		return entry, fmt.Errorf("can't parse: %d %s", len(res), string(pkt))
	}

	var msgPid int
	var tagpid, msgTag, msgPriority string
	var msgRaw []byte

	msgReceived := time.Now()
	p, _ := strconv.ParseInt(string(res[1]), 10, 64)
	msgPriority = priorityStr[p % 8]
	misc := res[3]
	// Check for either "hostname tagpid" or "tagpid"
	a := bytes.SplitN(misc, []byte(" "), 2)
	if len(a) == 2 {
		tagpid = string(a[1])
	} else {
		//msg.Hostname = hostname
		tagpid = string(a[0])
	}

	// tagpid is either "tag[pid]" or "[pid]" or just "tag".
	if n := strings.Index(tagpid, "["); n > 0 || strings.HasPrefix(tagpid, "[") && strings.HasSuffix(tagpid, "]") {
		p, _ = strconv.ParseInt(tagpid[n+1:(len(tagpid)-1)], 10, 64)
		msgPid = int(p)
		msgTag = tagpid[:n]
	} else {
		msgTag = tagpid
	}

	// Raw message string excluding priority, timestamp, tag and pid.
	n := bytes.Index(pkt, []byte("]: "))
	if n > 0 {
		if size > n + 2 {
			msgRaw = bytes.TrimSpace(pkt[n+2 : size])
		} else {
			msgRaw = bytes.TrimSpace(pkt[n+2:])
		}
	} else {
		n = bytes.Index(pkt, []byte(": "))
		if n > 0 {
			if size > n + 1 {
				msgRaw = bytes.TrimSpace(pkt[n+1 : size])
			} else {
				msgRaw = bytes.TrimSpace(pkt[n+1:])
			}
		} else {
			msgRaw = bytes.TrimSpace(pkt)
		}
	}

	entry = inputEntry{
		source:     msgTag,
		severity:   msgPriority,
		content:    string(msgRaw),
		pid:        strconv.Itoa(msgPid),
		timestamp:  msgReceived.Format(time.RFC3339Nano),
	}

	return entry, nil
}
