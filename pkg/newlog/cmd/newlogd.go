// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/go-cmp/cmp"
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

	devPrefix       = types.DevPrefix
	devPrefixKeep   = types.DevPrefixKeep
	devPrefixUpload = types.DevPrefixUpload
	appPrefix       = types.AppPrefix
	tmpPrefix       = "TempFile"
	skipUpload      = "skipTx."

	defaultSyncCount = 30 // default log events flush/sync to disk file
)

var (
	logger *logrus.Logger
	log    *base.LogObject

	collectDir   = types.NewlogCollectDir
	uploadDevDir = types.NewlogUploadDevDir
	uploadAppDir = types.NewlogUploadAppDir
	keepSentDir  = types.NewlogKeepSentQueueDir
	failSendDir  = types.NewlogDir + "/failedUpload"
	panicFileDir = types.NewlogDir + "/panicStacks"
	symlinkFile  = collectDir + "/current.device.log"
	tmpSymlink   = collectDir + "/tmp-sym.dev.log"

	logmetrics    types.NewlogMetrics // the log metric, publishes to zedagent
	devMetaData   devMeta
	syncToFileCnt int    // every 'N' log event count flush to log file
	persistMbytes uint64 // '/persist' disk space total in Mbytes
	panicBuf      []byte // buffer to save panic crash stack

	enableFastUpload bool // enable fast upload to controller similar to previous log operation

	subGlobalConfig pubsub.Subscription

	schedResetTimer *time.Timer // after detect log has watchdog going down message, reset the file flush count
	panicWriteTimer *time.Timer // after detect pillar panic, in case no other log comes in, write the panic files

	//domainUUID
	domainUUID *base.LockedStringMap // App log, from domain-id to appDomain
	// subNestedAppDomainStatus
	subNestedAppDomainStatus pubsub.Subscription

	// Default log levels for some subsystems. Variables are updated and used
	// from different goroutines, so in order to push the changes out of the
	// goroutines local caches and correctly observe changed values in another
	// goroutine sync/atomic synchronization is used. You've been warned.
	syslogPrio                 = types.SyslogKernelLogLevelNum[types.SyslogKernelDefaultLogLevel]
	kernelPrio                 = types.SyslogKernelLogLevelNum[types.SyslogKernelDefaultLogLevel]
	syslogRemotePrio           = types.SyslogKernelLogLevelNum[types.SyslogKernelDefaultLogLevel]
	kernelRemotePrio           = types.SyslogKernelLogLevelNum[types.SyslogKernelDefaultLogLevel]
	agentDefaultRemoteLogLevel atomic.Value // logrus.Level
	agentsRemoteLogLevel       sync.Map     // map of agentName to logrus.Level
)

func init() {
	// domain-name to UUID and App-name mapping
	domainUUID = base.NewLockedStringMap()
	agentDefaultRemoteLogLevel.Store(logrus.InfoLevel)
}

// for app Domain-ID mapping into UUID and DisplayName
type appDomain struct {
	appUUID     string
	appName     string
	msgIDAppCnt uint64
	disableLogs bool
	trigMove    bool
	nestedAppVM bool
}

type inputEntry struct {
	severity     string
	source       string
	content      string // One line
	pid          string
	filename     string // file name that generated the logmsg
	function     string // function name that generated the log msg
	timestamp    string
	appUUID      string // App UUID
	acName       string // App Container Name
	acLogTime    string // App Container log time
	sendToRemote bool   // this log entry needs to be sent to remote
}

// file info passing from collection to compression threads
type fileChanInfo struct {
	tmpfile   string
	header    string
	inputSize int32
	isApp     bool
	notUpload bool // app log is configured not to upload
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

	log.Functionf("newlogd: starting... restarted %v", restarted)

	loggerChan := make(chan inputEntry, 10)
	movefileChan := make(chan fileChanInfo, 5)
	panicFileChan := make(chan []byte, 2)

	ps := *pubsub.New(&socketdriver.SocketDriver{Logger: logger, Log: log}, logger, log)

	// create the necessary directories upfront
	for _, dir := range []string{collectDir, uploadDevDir, uploadAppDir, keepSentDir, panicFileDir} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				log.Fatal(err)
			}
		}
	}

	// handle the write log messages to /persist/newlog/collect/ logfiles
	go writelogFile(loggerChan, movefileChan)

	// handle the kernel messages
	go getKernelMsg(loggerChan)

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

	// Get NestedAppDomainStatus from zedrouter
	subNestedAppDomainStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		TopicImpl:     types.NestedAppDomainStatus{},
		Activate:      true,
		CreateHandler: handleNestedAppDomainStatusCreate,
		ModifyHandler: handleNestedAppDomainStatusModify,
		DeleteHandler: handleNestedAppDomainStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// newlog Metrics publish timer. Publish log metrics every 5 minutes.
	interval := time.Duration(metricsPublishInterval)
	maxInterval := float64(interval)
	minInterval := maxInterval * 0.3
	metricsPublishTimer := flextimer.NewRangeTicker(time.Duration(minInterval),
		time.Duration(maxInterval))

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
			doMoveCompressFile(&ps, tmpLogfileInfo)
			// done gzip conversion, get rid of the temp log file in collect directory
			err = os.Remove(tmpLogfileInfo.tmpfile)
			if err != nil {
				log.Fatal("doMoveCompressFile: remove file failed", err)
			}

		case panicBuf := <-panicFileChan:
			// save panic stack into files
			savePanicFiles(panicBuf)

		case change := <-subNestedAppDomainStatus.MsgChan():
			subNestedAppDomainStatus.ProcessChange(change)

		case <-panicWriteTimer.C:
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
		nestedAppVM: status.DeploymentType == types.AppRuntimeTypeDocker,
	}

	// close the app log file if already opened due to app log policy change
	if val, ok := domainUUID.Load(appD.appUUID); ok {
		d := val.(appDomain)
		if d.disableLogs != appD.disableLogs {
			appD.trigMove = true
		} else {
			appD.trigMove = d.trigMove
		}
		appD.msgIDAppCnt = d.msgIDAppCnt // inherit the counter for the app
	}
	domainUUID.Store(appD.appUUID, appD)

	log.Tracef("handleDomainStatusModify: done for %s", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string, statusArg interface{}) {

	log.Tracef("handleDomainStatusDelete: for %s", key)
	status := statusArg.(types.DomainStatus)
	appUUID := status.UUIDandVersion.UUID.String()
	if _, ok := domainUUID.Load(appUUID); !ok {
		return
	}
	log.Tracef("handleDomainStatusDelete: remove %s", appUUID)
	domainUUID.Delete(appUUID)
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
	gcp := agentlog.HandleGlobalConfig(log, subGlobalConfig, agentName, false, logger)

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
		if limitGzipFilesMbyts > uint32(persistMbytes/10) {
			limitGzipFilesMbyts = uint32(persistMbytes / 10)
		}

		// parse agent's individual remote log levels
		for agentName := range gcp.AgentSettings {
			loglevel := getRemoteLogLevelImpl(gcp, agentName)
			agentsRemoteLogLevel.Store(agentName, parseAgentLogLevel(loglevel))
		}

		// parse agent's default remote log level
		loglevel := gcp.GlobalValueString(types.DefaultRemoteLogLevel)
		agentDefaultRemoteLogLevel.Store(parseAgentLogLevel(loglevel))

		// parse syslog log level
		syslogPrioStr := gcp.GlobalValueString(types.SyslogLogLevel)
		atomic.StoreUint32(&syslogPrio, parseSyslogLogLevel(syslogPrioStr))

		// parse kernel log level
		kernelPrioStr := gcp.GlobalValueString(types.KernelLogLevel)
		atomic.StoreUint32(&kernelPrio, parseSyslogLogLevel(kernelPrioStr))

		// parse syslog remote log level
		syslogRemotePrioStr := gcp.GlobalValueString(types.SyslogRemoteLogLevel)
		atomic.StoreUint32(&syslogRemotePrio, parseSyslogLogLevel(syslogRemotePrioStr))

		// parse kernel remote log level
		kernelRemotePrioStr := gcp.GlobalValueString(types.KernelRemoteLogLevel)
		atomic.StoreUint32(&kernelRemotePrio, parseSyslogLogLevel(kernelRemotePrioStr))

		// set log deduplication and filtering settings
		dedupWindowSize.Store(gcp.GlobalValueInt(types.LogDedupWindowSize))
		log.Functionf("handleGlobalConfigModify: set dedupWindowSize to %d", dedupWindowSize.Load())

		// parse a comma separated list of log filenames to count
		var filenamesToCount []string
		if gcp.GlobalValueString(types.LogFilenamesToCount) != "" {
			filenamesToCount = strings.Split(gcp.GlobalValueString(types.LogFilenamesToCount), ",")
		}
		logsToCount.Store(filenamesToCount)
		log.Functionf("handleGlobalConfigModify: gonna count the logs from the following lines %v", filenamesToCount)

		// parse a comma separated list of log filenames to filter
		newFilenameFilter := make(map[string]struct{})
		if gcp.GlobalValueString(types.LogFilenamesToFilter) != "" {
			for filename := range strings.SplitSeq(gcp.GlobalValueString(types.LogFilenamesToFilter), ",") {
				newFilenameFilter[filename] = struct{}{}
			}
		}
		filenameFilter.Store(newFilenameFilter)
		log.Functionf("handleGlobalConfigModify: gonna filter out the logs from the following lines %v", newFilenameFilter)

	}
	log.Tracef("handleGlobalConfigModify done for %s, fastupload enabled %v", key, enableFastUpload)
}

func getRemoteLogLevelImpl(gc *types.ConfigItemValueMap, agentName string) string {
	// Do we have an entry for this agent?
	loglevel := gc.AgentSettingStringValue(agentName, types.RemoteLogLevel)
	if loglevel != "" {
		log.Tracef("getRemoteLogLevelImpl: loglevel=%s", loglevel)
		return loglevel
	}

	// Agent specific setting  not available. Get it from Global Setting
	loglevel = gc.GlobalValueString(types.DefaultRemoteLogLevel)
	if loglevel != "" {
		log.Tracef("getRemoteLogLevelImpl: returning DefaultRemoteLogLevel (%s)",
			loglevel)
		return loglevel
	}

	log.Errorf("***getRemoteLogLevelImpl: DefaultRemoteLogLevel not found. " +
		"returning info")
	return "info"
}

func handleNestedAppDomainStatusCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleNestedAppDomainStatusImp(ctxArg, key, statusArg)
}

func handleNestedAppDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleNestedAppDomainStatusImp(ctxArg, key, statusArg)
}

func handleNestedAppDomainStatusImp(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.NestedAppDomainStatus)
	// Record the domainName even if Pending* is set
	log.Functionf("handleNestedAppDomainStatusImp: add %s to %s",
		status.DisplayName, status.UUIDandVersion.UUID.String())
	appD := appDomain{
		appUUID:     status.UUIDandVersion.UUID.String(),
		appName:     status.DisplayName,
		disableLogs: status.DisableLogs,
		msgIDAppCnt: 1,
	}

	// close the app log file if already opened due to app log policy change
	if val, ok := domainUUID.Load(appD.appUUID); ok {
		d := val.(appDomain)
		if d.disableLogs != appD.disableLogs {
			appD.trigMove = true
		} else {
			appD.trigMove = d.trigMove
		}
		appD.msgIDAppCnt = d.msgIDAppCnt // inherit the counter for the app
	}
	domainUUID.Store(appD.appUUID, appD)
}

func handleNestedAppDomainStatusDelete(ctxArg interface{}, key string, statusArg interface{}) {

	log.Tracef("handleNestedAppDomainStatusDelete: for %s", key)
	status := statusArg.(types.NestedAppDomainStatus)
	appUUID := status.UUIDandVersion.UUID.String()
	if _, ok := domainUUID.Load(appUUID); !ok {
		return
	}
	log.Tracef("handleNestedAppDomainStatusDelete: remove %s", appUUID)
	domainUUID.Delete(appUUID)
	log.Tracef("handleNestedAppDomainStatusDelete: done for %s", key)
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
