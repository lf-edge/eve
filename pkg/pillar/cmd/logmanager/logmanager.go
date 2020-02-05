// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logmanager

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	dbg "runtime/debug"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	pubsublegacy "github.com/lf-edge/eve/pkg/pillar/pubsub/legacy"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/watch"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"gopkg.in/mcuadros/go-syslog.v2"
)

const (
	agentName        = "logmanager"
	commonLogdir     = types.PersistDir + "/log"
	xenLogDirname    = "/var/log/xen"
	lastSentDirname  = "lastlogsent"  // Directory in /persist/
	lastDeferDirname = "lastlogdefer" // Directory in /persist/
	logsApi          = "api/v1/edgedevice/logs"
	logMaxMessages   = 100
	logMaxBytes      = 32768 // Approximate - no headers counted
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

var (
	devUUID             uuid.UUID
	deviceNetworkStatus *types.DeviceNetworkStatus = &types.DeviceNetworkStatus{}
	debug               bool
	debugOverride       bool // From command line arg
	serverName          string
	logsUrl             string
	zedcloudCtx         zedcloud.ZedCloudContext

	globalDeferInprogress bool
)

// global stuff
type logDirModifyHandler func(ctx interface{}, logFileName string, source string)
type logDirDeleteHandler func(ctx interface{}, logFileName string, source string)

type logmanagerContext struct {
	subGlobalConfig pubsub.Subscription
	globalConfig    *types.GlobalConfig
	subDomainStatus pubsub.Subscription
	GCInitialized   bool
}

// Set from Makefile
var Version = "No version specified"

// Based on the proto file
type logEntry struct {
	severity  string
	source    string // basename of filename?
	iid       string // XXX e.g. PID - where do we get it from?
	content   string // One line
	filename  string // file name that generated the logmsg
	function  string // function name that generated the log msg
	timestamp time.Time
}

// List of log files we watch
type loggerContext struct {
	logfileReaders []logfileReader
	image          string
	logChan        chan<- logEntry
}

type logfileReader struct {
	filename string
	source   string
	fileDesc *os.File
	reader   *bufio.Reader
}

// These are for the case when we have a separate channel/image
// per file.
type imageLogfileReader struct {
	logfileReader
	image   string
	logChan chan logEntry
}

// List of log files we watch where channel/image is per file
type imageLoggerContext struct {
	logfileReaders []imageLogfileReader
}

// Context for handleDNSModify
type DNSContext struct {
	usableAddressCount     int
	subDeviceNetworkStatus pubsub.Subscription
	doDeferred             bool
}

type zedcloudLogs struct {
	FailureCount uint64
	SuccessCount uint64
	LastFailure  time.Time
	LastSuccess  time.Time
}

func Run() {
	defaultLogdirname := agentlog.GetCurrentLogdir()
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug")
	curpartPtr := flag.String("c", "", "Current partition")
	forcePtr := flag.Bool("f", false, "Force")
	logdirPtr := flag.String("l", defaultLogdirname, "Log file directory")
	fatalPtr := flag.Bool("F", false, "Cause log.Fatal fault injection")
	hangPtr := flag.Bool("H", false, "Cause watchdog .touch fault injection")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	fatalFlag := *fatalPtr
	hangFlag := *hangPtr
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	curpart := *curpartPtr
	logDirName := *logdirPtr
	force := *forcePtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	logf, err := agentlog.InitWithDirText(agentName, commonLogdir,
		curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s watching %s\n", agentName, logDirName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	// Make sure we have the last sent directory
	dirname := fmt.Sprintf("%s/%s", types.PersistDir, lastSentDirname)
	if _, err := os.Stat(dirname); err != nil {
		if err := os.MkdirAll(dirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	dirname = fmt.Sprintf("%s/%s", types.PersistDir, lastDeferDirname)
	if _, err := os.Stat(dirname); err != nil {
		if err := os.MkdirAll(dirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	cms := zedcloud.GetCloudMetrics() // Need type of data
	pub, err := pubsublegacy.Publish(agentName, cms)
	if err != nil {
		log.Fatal(err)
	}

	logmanagerCtx := logmanagerContext{
		globalConfig: &types.GlobalConfigDefaults,
	}
	// Look for global config such as log levels
	subGlobalConfig, err := pubsublegacy.Subscribe("", types.GlobalConfig{},
		false, &logmanagerCtx, &pubsub.SubscriptionOptions{
			CreateHandler: handleGlobalConfigModify,
			ModifyHandler: handleGlobalConfigModify,
			DeleteHandler: handleGlobalConfigDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	logmanagerCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Get DomainStatus from domainmgr
	subDomainStatus, err := pubsublegacy.Subscribe("domainmgr",
		types.DomainStatus{}, false, &logmanagerCtx, &pubsub.SubscriptionOptions{
			CreateHandler: handleDomainStatusModify,
			ModifyHandler: handleDomainStatusModify,
			DeleteHandler: handleDomainStatusDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	logmanagerCtx.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	// Wait until we have at least one useable address?
	DNSctx := DNSContext{}
	DNSctx.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)

	subDeviceNetworkStatus, err := pubsublegacy.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &DNSctx, &pubsub.SubscriptionOptions{
			CreateHandler: handleDNSModify,
			ModifyHandler: handleDNSModify,
			DeleteHandler: handleDNSDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	DNSctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Pick up debug aka log level before we start real work
	for !logmanagerCtx.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

	log.Infof("Waiting until we have some management ports with usable addresses\n")
	for DNSctx.usableAddressCount == 0 && !force {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		// This wait can take an unbounded time since we wait for IP
		// addresses. Punch StillRunning
		case <-stillRunning.C:
			// Fault injection
			if fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if hangFlag {
			log.Infof("Requested to not touch to cause watchdog")
		} else {
			agentlog.StillRunning(agentName, warningTime, errorTime)
		}
	}
	log.Infof("Have %d management ports with usable addresses\n",
		DNSctx.usableAddressCount)

	// Timer for deferred sends of info messages
	deferredChan := zedcloud.InitDeferred()
	DNSctx.doDeferred = true

	//Get servername, set logUrl, get device id and initialize zedcloudCtx
	sendCtxInit(&logmanagerCtx)

	// Publish send metrics for zedagent every 10 seconds
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	currentPartition := zboot.GetCurrentPartition()
	loggerChan := make(chan logEntry)
	ctx := loggerContext{logChan: loggerChan, image: currentPartition}
	xenCtx := imageLoggerContext{}
	lastSent := readLast(lastSentDirname, currentPartition)
	lastSentStr, _ := lastSent.MarshalText()
	log.Debugf("Current partition logs were last sent at %s\n",
		string(lastSentStr))

	// Start sender of log events
	go processEvents(currentPartition, lastSent, loggerChan)

	// If we have a logdir from a failed update, then set that up
	// as well.
	// XXX we can close this down once we've reached EOF for all the
	// files in otherLogdirname. This is TBD
	// Closing otherLoggerChan would the effect of terminating the
	// processEvents go routine but we need to tell when all the files
	// have reached the end.
	otherLogDirname := agentlog.GetOtherLogdir()
	otherLogDirChanges := make(chan string)
	var otherCtx = loggerContext{}

	if otherLogDirname != "" {
		log.Infof("Have logs from failed upgrade in %s\n",
			otherLogDirname)
		otherLoggerChan := make(chan logEntry)
		otherPartition := zboot.GetOtherPartition()
		lastSent := readLast(lastSentDirname, otherPartition)
		lastSentStr, _ := lastSent.MarshalText()
		log.Debugf("Other partition logs were last sent at %s\n",
			string(lastSentStr))

		go processEvents(otherPartition, lastSent, otherLoggerChan)

		go watch.WatchStatus(otherLogDirname, false, otherLogDirChanges)
		otherCtx = loggerContext{logChan: otherLoggerChan,
			image: otherPartition}
	}

	logDirChanges := make(chan string)
	go watch.WatchStatus(logDirName, false, logDirChanges)

	xenLogDirChanges := make(chan string)
	go watch.WatchStatus(xenLogDirname, false, xenLogDirChanges)

	// Run these dir -> event as goroutines since they will block
	// when there is backpressure
	// XXX state sharing with HandleDeferred?
	go handleLogDir(logDirChanges, logDirName, &ctx)
	go handleLogDir(otherLogDirChanges, otherLogDirname, &otherCtx)
	go handleXenLogDir(xenLogDirChanges, xenLogDirname, &xenCtx)

	go parseAndSendSyslogEntries(&ctx)

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDomainStatus.MsgChan():
			subDomainStatus.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case <-publishTimer.C:
			start := time.Now()
			log.Debugln("publishTimer at", time.Now())
			err := pub.Publish("global", zedcloud.GetCloudMetrics())
			if err != nil {
				log.Errorln(err)
			}
			pubsub.CheckMaxTimeTopic(agentName, "publishTimer", start,
				warningTime, errorTime)

		case change := <-deferredChan:
			start := time.Now()
			done := zedcloud.HandleDeferred(change, 1*time.Second)
			dbg.FreeOSMemory()
			globalDeferInprogress = !done
			if globalDeferInprogress {
				log.Warnf("logmanager: globalDeferInprogress")
			}
			pubsub.CheckMaxTimeTopic(agentName, "deferredChan", start,
				warningTime, errorTime)

		case <-stillRunning.C:
			// Fault injection
			if fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if hangFlag {
			log.Infof("Requested to not touch to cause watchdog")
		} else {
			agentlog.StillRunning(agentName, warningTime, errorTime)
		}
	}
}

func parseAndSendSyslogEntries(ctx *loggerContext) {
	logChannel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(logChannel)
	server := syslog.NewServer()
	server.SetFormat(syslog.RFC3164)
	server.SetHandler(handler)
	server.ListenTCP("localhost:5140")
	server.Boot()
	for logParts := range logChannel {
		logInfo, ok := agentlog.ParseLoginfo(logParts["content"].(string))
		if !ok {
			continue
		}
		level, err := log.ParseLevel(logInfo.Level)
		if err != nil {
			log.Errorf("ParseLevel failed: %s\n", err)
			level = log.InfoLevel
		}
		if dropEvent(logInfo.Source, level) {
			log.Debugf("Dropping source %s level %v\n",
				logInfo.Source, level)
			continue
		}
		timestamp := logParts["timestamp"].(time.Time)
		logMsg := logEntry{
			source:    logInfo.Source,
			content:   timestamp.String() + ": " + logParts["content"].(string),
			severity:  logInfo.Level,
			timestamp: timestamp,
			function:  logInfo.Function,
			filename:  logInfo.Filename,
		}
		ctx.logChan <- logMsg
	}
}

func handleLogDir(logDirChanges chan string, logDirName string,
	ctx *loggerContext) {

	for {
		select {
		case change := <-logDirChanges:
			HandleLogDirEvent(change, logDirName, ctx,
				handleLogDirModify, handleLogDirDelete)
		}
	}
}

func handleXenLogDir(logDirChanges chan string, logDirName string,
	ctx *imageLoggerContext) {

	for {
		select {
		case change := <-logDirChanges:
			HandleLogDirEvent(change, logDirName, ctx,
				handleXenLogDirModify, handleXenLogDirDelete)
		}
	}
}

// Handles both create and modify events
func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(deviceNetworkStatus, status) {
		log.Infof("handleDNSModify no change\n")
		return
	}
	*deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	cameOnline := (ctx.usableAddressCount == 0) && (newAddrCount != 0)
	ctx.usableAddressCount = newAddrCount
	if cameOnline && ctx.doDeferred {
		change := time.Now()
		done := zedcloud.HandleDeferred(change, 1*time.Second)
		globalDeferInprogress = !done
		if globalDeferInprogress {
			log.Warnf("handleDNSModify: globalDeferInprogress")
		}
	}
	log.Infof("handleDNSModify done for %s; %d usable\n",
		key, newAddrCount)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	log.Infof("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*DNSContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.usableAddressCount = newAddrCount
	log.Infof("handleDNSDelete done for %s\n", key)
}

// This runs as a separate go routine sending out data
// Compares and drops events which have already been sent to the cloud
func processEvents(image string, prevLastSent time.Time,
	logChan <-chan logEntry) {

	log.Infof("processEvents(%s, %s)\n", image, prevLastSent.String())

	reportLogs := new(logs.LogBundle)
	// XXX should we make the log interval configurable?
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	flushTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	messageCount := 0
	dropped := 0
	deferInprogress := false
	for {
		// If we had a defer wait until it has been taken care of
		// Note that globalDeferInprogress might not yet be set
		// but if the condition persists it will be set in a bit
		if deferInprogress {
			log.Warnf("processEvents(%s) deferInprogress", image)
			time.Sleep(2 * time.Minute)
			if globalDeferInprogress {
				log.Warnf("processEvents(%s) globalDeferInprogress",
					image)
				continue
			}
			log.Infof("processEvents(%s) deferInprogress done",
				image)
			deferInprogress = false
		}

		select {
		case event, more := <-logChan:
			sent := false
			if !more {
				log.Infof("processEvents(%s) end\n",
					image)
				if messageCount == 0 {
					return
				}
				sent = sendProtoStrForLogs(reportLogs, image,
					iteration)
				if sent {
					recordLast(lastSentDirname, image)
				} else {
					recordLast(lastDeferDirname, image)
				}
				return
			}
			if event.timestamp.Before(prevLastSent) {
				dropped++
				break
			}
			HandleLogEvent(event, reportLogs, messageCount)
			messageCount++
			// Bytes before appending this one
			byteCount := proto.Size(reportLogs)

			if messageCount < logMaxMessages &&
				byteCount < logMaxBytes {

				break
			}

			log.Debugf("processEvents(%s): sending at messageCount %d, byteCount %d\n",
				image, messageCount, byteCount)
			sent = sendProtoStrForLogs(reportLogs, image,
				iteration)
			messageCount = 0
			iteration += 1
			if sent {
				recordLast(lastSentDirname, image)
			} else {
				recordLast(lastDeferDirname, image)
				deferInprogress = true
			}

		case <-flushTimer.C:
			if messageCount == 0 {
				break
			}
			log.Debugf("processEvents(%s) flush at %s dropped %d messageCount %d bytecount %d\n",
				image, time.Now().String(),
				dropped, messageCount,
				proto.Size(reportLogs))
			sent := sendProtoStrForLogs(reportLogs, image,
				iteration)
			messageCount = 0
			iteration += 1
			if sent {
				recordLast(lastSentDirname, image)
			} else {
				recordLast(lastDeferDirname, image)
				deferInprogress = true
			}
		}
	}
}

// Touch/create a file to keep track of when things where sent before a reboot
func recordLast(dirname string, image string) {
	log.Debugf("recordLast(%s, %s)\n", dirname, image)
	filename := fmt.Sprintf("%s/%s/%s", types.PersistDir, dirname, image)
	_, err := os.Stat(filename)
	if err != nil {
		file, err := os.Create(filename)
		if err != nil {
			log.Infof("recordLast: %s\n", err)
			return
		}
		file.Close()
	}
	_, err = os.Stat(filename)
	if err != nil {
		log.Errorf("recordLast: %s\n", err)
		return
	}
	now := time.Now()
	err = os.Chtimes(filename, now, now)
	if err != nil {
		log.Errorf("recordLast: %s\n", err)
		return
	}
}

func readLast(dirname string, image string) time.Time {
	filename := fmt.Sprintf("%s/%s/%s", types.PersistDir, dirname, image)
	st, err := os.Stat(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("readLast: %s\n", err)
		}
		return time.Time{}
	}
	return st.ModTime()
}

var msgIdCounter = 1
var iteration = 0

func HandleLogEvent(event logEntry, reportLogs *logs.LogBundle, counter int) {
	// Assign a unique msgId for each message
	msgId := msgIdCounter
	msgIdCounter += 1
	log.Debugf("Read event from %s time %v id %d: %s\n",
		event.source, event.timestamp, msgId, event.content)
	// Have to discard if too large since service doesn't
	// handle above 64k; we limit payload at 32k
	strLen := len(event.content)
	if strLen > logMaxBytes {
		log.Errorf("HandleLogEvent: dropping source %s %d bytes: %s\n",
			event.source, strLen, event.content)
		return
	}

	logDetails := &logs.LogEntry{}
	logDetails.Content = event.content
	logDetails.Severity = event.severity
	logDetails.Timestamp, _ = ptypes.TimestampProto(event.timestamp)
	logDetails.Source = event.source
	logDetails.Iid = event.iid
	logDetails.Msgid = uint64(msgId)
	logDetails.Filename = event.filename
	logDetails.Function = event.function
	oldLen := int64(proto.Size(reportLogs))
	reportLogs.Log = append(reportLogs.Log, logDetails)
	newLen := int64(proto.Size(reportLogs))
	if newLen > logMaxBytes {
		log.Warnf("HandleLogEvent: source %s from %d to %d bytes: %s\n",
			event.source, oldLen, newLen, event.content)
	}
}

// Returns true if a message was successfully sent
func sendProtoStrForLogs(reportLogs *logs.LogBundle, image string,
	iteration int) bool {
	reportLogs.Timestamp = ptypes.TimestampNow()
	reportLogs.DevID = *proto.String(devUUID.String())
	reportLogs.Image = image

	log.Debugln("sendProtoStrForLogs called...", iteration)
	data, err := proto.Marshal(reportLogs)
	if err != nil {
		log.Fatal("sendProtoStrForLogs proto marshaling error: ", err)
	}
	size := int64(proto.Size(reportLogs))
	if size > logMaxBytes {
		log.Warnf("sendProtoStrForLogs: %d bytes: %s\n",
			size, reportLogs)
	} else {
		log.Debugf("sendProtoStrForLogs %d bytes: %s\n",
			size, reportLogs)
	}
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("sendProtoStrForLogs malloc error:")
	}

	// For any 400 error we abandon
	const return400 = true
	if zedcloud.HasDeferred(image) {
		log.Infof("SendProtoStrForLogs queued after existing for %s\n",
			image)
		zedcloud.AddDeferred(image, buf, size, logsUrl, zedcloudCtx,
			return400)
		reportLogs.Log = []*logs.LogEntry{}
		return false
	}
	resp, _, _, err := zedcloud.SendOnAllIntf(zedcloudCtx, logsUrl,
		size, buf, iteration, return400)
	// XXX We seem to still get large or bad messages which are rejected
	// by the server. Ignore them to make sure we can log subsequent ones.
	// XXX Should we inject a separate log entry to record that we dropped
	// this one?
	if resp != nil && resp.StatusCode == 400 {
		log.Errorf("Failed sending %d bytes image %s to %s; code 400; ignored error\n",
			size, image, logsUrl)
		reportLogs.Log = []*logs.LogEntry{}
		return true
	}
	if err != nil {
		log.Errorf("SendProtoStrForLogs %d bytes image %s failed: %s\n",
			size, image, err)
		// Try sending later. The deferred state means processEvents
		// will sleep until the timer takes care of sending this
		// hence we'll keep things in order for a given image
		// The buf might have been consumed
		buf := bytes.NewBuffer(data)
		if buf == nil {
			log.Fatal("sendProtoStrForLogs malloc error:")
		}
		zedcloud.AddDeferred(image, buf, size, logsUrl, zedcloudCtx,
			return400)
		reportLogs.Log = []*logs.LogEntry{}
		return false
	}
	log.Debugf("Sent %d bytes image %s to %s\n", size, image, logsUrl)
	reportLogs.Log = []*logs.LogEntry{}
	return true
}

func sendCtxInit(ctx *logmanagerContext) {
	//get server name
	bytes, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
	}
	// Preserve port
	serverNameAndPort := strings.TrimSpace(string(bytes))
	serverName = strings.Split(serverName, ":")[0]

	//set log url
	logsUrl = serverNameAndPort + "/" + logsApi

	v2api := false // XXX set
	zedcloudCtx.DeviceNetworkStatus = deviceNetworkStatus
	zedcloudCtx.FailureFunc = zedcloud.ZedCloudFailure
	zedcloudCtx.SuccessFunc = zedcloud.ZedCloudSuccess
	zedcloudCtx.NetworkSendTimeout = ctx.globalConfig.NetworkSendTimeout
	zedcloudCtx.V2API = v2api

	// get the edge box serial number
	zedcloudCtx.DevSerial = hardware.GetProductSerial()
	zedcloudCtx.DevSoftSerial = hardware.GetSoftSerial()
	log.Infof("Log Get Device Serial %s, Soft Serial %s\n", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial)

	// XXX need to redo this since the root certificates can change when DeviceNetworkStatus changes
	err = zedcloud.UpdateTLSConfig(&zedcloudCtx, serverName, nil)
	if err != nil {
		log.Fatal(err)
	}

	// In case we run early, wait for UUID file to appear
	for {
		b, err := ioutil.ReadFile(types.UUIDFileName)
		if err != nil {
			log.Errorln("ReadFile", err, types.UUIDFileName)
			time.Sleep(time.Second)
			continue
		}
		uuidStr := strings.TrimSpace(string(b))
		devUUID, err = uuid.FromString(uuidStr)
		if err != nil {
			log.Errorln("uuid.FromString", err, string(b))
			time.Sleep(time.Second)
			continue
		}
		zedcloudCtx.DevUUID = devUUID
		break
	}
	log.Infof("Read UUID %s\n", devUUID)
}

func HandleLogDirEvent(change string, logDirName string, ctx interface{},
	handleLogDirModifyFunc logDirModifyHandler,
	handleLogDirDeleteFunc logDirDeleteHandler) {

	operation := string(change[0])
	fileName := string(change[2:])
	if !strings.HasSuffix(fileName, ".log") {
		log.Debugf("Ignoring file <%s> operation %s\n",
			fileName, operation)
		return
	}
	logFilePath := logDirName + "/" + fileName
	// Remove .log from name
	name := strings.Split(fileName, ".log")
	source := name[0]
	if operation == "D" {
		handleLogDirDeleteFunc(ctx, logFilePath, source)
		return
	}
	if operation != "M" {
		log.Fatal("Unknown operation from Watcher: ",
			operation)
	}
	handleLogDirModifyFunc(ctx, logFilePath, source)
}

func handleXenLogDirModify(context interface{},
	filename string, source string) {

	if strings.Compare(source, "hypervisor") == 0 {
		log.Debugln("Ignoring hypervisor log while sending domU log")
		return
	}
	ctx := context.(*imageLoggerContext)
	for i, r := range ctx.logfileReaders {
		if r.filename == filename {
			readLineToEvent(&ctx.logfileReaders[i].logfileReader,
				r.logChan)
			return
		}
	}
	// Look for guest-domainName.log and look it up to find app UUID
	// change source to app UUID
	if strings.HasPrefix(source, "guest-") {
		domainName := strings.TrimPrefix(source, "guest-")
		uuidStr := lookupDomainName(domainName)
		if uuidStr != "" {
			log.Infof("Changing %s to %s\n", source, uuidStr)
			source = uuidStr
		} else {
			log.Infof("DomainName %s not found\n", domainName)
		}
	}
	createXenLogger(ctx, filename, source)
}

func createXenLogger(ctx *imageLoggerContext, filename string, source string) {

	log.Infof("createXenLogger: add %s, source %s\n", filename, source)

	fileDesc, err := os.Open(filename)
	if err != nil {
		log.Errorf("Log file ignored due to %s\n", err)
		return
	}
	// Start reading from the file with a reader.
	reader := bufio.NewReader(fileDesc)
	if reader == nil {
		log.Errorf("Log file ignored due to %s\n", err)
		return
	}

	r0 := logfileReader{filename: filename,
		source:   source,
		fileDesc: fileDesc,
		reader:   reader,
	}
	r := imageLogfileReader{logfileReader: r0,
		image:   source,
		logChan: make(chan logEntry),
	}

	lastSent := readLast(lastSentDirname, source)
	lastSentStr, _ := lastSent.MarshalText()
	log.Debugf("createXenLogger: source %s last sent at %s\n",
		source, string(lastSentStr))

	// process associated channel
	go processEvents(source, lastSent, r.logChan)

	// Write start event to ensure log is not empty
	now := time.Now()
	nowStr, _ := now.MarshalText()
	line := fmt.Sprintf("%s logmanager starting to log %s\n",
		nowStr, r.source)
	r.logChan <- logEntry{source: r.source, content: line,
		timestamp: now}
	// read initial entries until EOF
	readLineToEvent(&r.logfileReader, r.logChan)
	ctx.logfileReaders = append(ctx.logfileReaders, r)
}

func handleXenLogDirDelete(context interface{},
	filename string, source string) {
	ctx := context.(*imageLoggerContext)

	log.Infof("handleLogDirDelete: delete %s, source %s\n", filename, source)
	for _, logger := range ctx.logfileReaders {
		if logger.logfileReader.filename == filename {
			// XXX:FIXME, delete the entry
		}
	}
}

func handleLogDirModify(context interface{}, filename string, source string) {
	ctx := context.(*loggerContext)

	for i, r := range ctx.logfileReaders {
		if r.filename == filename {
			readLineToEvent(&ctx.logfileReaders[i], ctx.logChan)
			return
		}
	}
	createLogger(ctx, filename, source)
}

func createLogger(ctx *loggerContext, filename, source string) {

	log.Infof("createLogger: add %s, source %s\n", filename, source)

	fileDesc, err := os.Open(filename)
	if err != nil {
		log.Errorf("Log file ignored due to %s\n", err)
		return
	}
	// Start reading from the file with a reader.
	reader := bufio.NewReader(fileDesc)
	if reader == nil {
		log.Errorf("Log file ignored due to %s\n", err)
		return
	}
	r := logfileReader{filename: filename,
		source:   source,
		fileDesc: fileDesc,
		reader:   reader,
	}
	// Write start event to ensure log is not empty
	now := time.Now()
	nowStr, _ := now.MarshalText()
	line := fmt.Sprintf("%s logmanager starting to log %s\n",
		nowStr, r.source)
	ctx.logChan <- logEntry{source: r.source, content: line,
		timestamp: now}
	// read initial entries until EOF
	readLineToEvent(&r, ctx.logChan)
	ctx.logfileReaders = append(ctx.logfileReaders, r)
}

// XXX TBD should we stop the go routine?
func handleLogDirDelete(ctx interface{}, filename string, source string) {
	// ctx := context.(*loggerContext)
}

// Read until EOF or error
// When we get backpressure the writes to logChan will block hence
// we will stop reading and using more memory
func readLineToEvent(r *logfileReader, logChan chan<- logEntry) {
	// Check if shrunk aka truncated
	offset, err := r.fileDesc.Seek(0, os.SEEK_CUR)
	if err != nil {
		log.Errorf("Seek failed %s\n", err)
		offset = 0
	}
	fi, err := r.fileDesc.Stat()
	if err != nil {
		log.Errorf("Stat failed %s\n", err)
		return
	}
	if offset != 0 && offset > fi.Size() {
		log.Infof("File %s shrunk from %d to %d\n",
			r.filename, offset, fi.Size())
		_, err = r.fileDesc.Seek(0, os.SEEK_SET)
		if err != nil {
			log.Errorf("Seek failed %s\n", err)
			return
		}
	}
	// Remember last time and level. Start with now in case the file
	// has no date.
	lastTime := time.Now()
	var lastLevel int
	for {
		line, err := r.reader.ReadString('\n')
		if err != nil {
			log.Debugln(err)
			if err != io.EOF {
				log.Errorf(" > Failed!: %v\n", err)
			}
			break
		}
		if !utf8.ValidString(line) {
			log.Errorf("Invalid UTF-8 - dropping line: %v",
				line)
			continue
		}
		// remove trailing "/n" from line
		line = line[0 : len(line)-1]
		// Check if the line is json output from logrus
		loginfo, ok := agentlog.ParseLoginfo(line)
		if ok {
			log.Debugf("Parsed json %+v\n", loginfo)
			timestamp, ok := parseTime(loginfo.Time)
			if !ok {
				timestamp = time.Now()
			} else {
				lastTime = timestamp
			}
			level, err := log.ParseLevel(loginfo.Level)
			if err != nil {
				log.Errorf("ParseLevel failed: %s\n", err)
				level = log.InfoLevel
			}
			if dropEvent(r.source, level) {
				log.Debugf("Dropping source %s level %v\n",
					r.source, level)
				continue
			}
			// XXX set iid to PID? From where?
			// We add time to front of msg.
			logSource := r.source
			if loginfo.Source != "" {
				logSource = loginfo.Source
			}
			logChan <- logEntry{source: logSource,
				content:   loginfo.Time + ": " + loginfo.Msg,
				severity:  loginfo.Level,
				timestamp: timestamp,
				function:  loginfo.Function,
				filename:  loginfo.Filename,
			}
			lastLevel = int(level)
		} else {
			// Reformat/add timestamp to front of line
			line, lastTime, lastLevel = parseDateTime(line, lastTime,
				lastLevel)
			level := log.InfoLevel
			if dropEvent(r.source, level) {
				log.Debugf("Dropping source %s level %v\n",
					r.source, level)
				continue
			}
			// XXX set iid to PID? From where?
			logChan <- logEntry{source: r.source,
				content:   line,
				severity:  level.String(),
				timestamp: lastTime,
			}
		}
	}
}

// Read unchanging files until EOF
// Used for the otherpartition files!
func logReader(logFile string, source string, logChan chan<- logEntry) {
	fileDesc, err := os.Open(logFile)
	if err != nil {
		log.Errorf("Log file ignored due to %s\n", err)
		return
	}
	// Start reading from the file with a reader.
	reader := bufio.NewReader(fileDesc)
	if reader == nil {
		log.Errorf("Log file ignored due to %s\n", err)
		return
	}
	r := logfileReader{filename: logFile,
		source:   source,
		fileDesc: fileDesc,
		reader:   reader,
	}
	// read entries until EOF
	readLineToEvent(&r, logChan)
	log.Infof("logReader done for %s\n", logFile)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*logmanagerContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	status := statusArg.(types.GlobalConfig)
	var gcp *types.GlobalConfig
	debug, gcp = agentlog.HandleGlobalConfigNoDefault(ctx.subGlobalConfig,
		agentName, debugOverride)
	if gcp != nil {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	foundAgents := make(map[string]bool)
	if status.DefaultRemoteLogLevel != "" {
		foundAgents["default"] = true
		addRemoteMap("default", status.DefaultRemoteLogLevel)
	}
	for agentName, perAgentSetting := range status.AgentSettings {
		log.Debugf("Processing agentName %s\n", agentName)
		foundAgents[agentName] = true
		if perAgentSetting.RemoteLogLevel != "" {
			addRemoteMap(agentName, perAgentSetting.RemoteLogLevel)
		}
	}
	// Any deletes?
	delRemoteMapAgents(foundAgents)
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*logmanagerContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	*ctx.globalConfig = types.GlobalConfigDefaults
	delRemoteMapAll()
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

// Cache of loglevels per agent. Protected by mutex since accessed by
// multiple goroutines
var remoteMapLock sync.Mutex
var remoteMap map[string]log.Level = make(map[string]log.Level)

func addRemoteMap(agentName string, logLevel string) {
	log.Infof("addRemoteMap(%s, %s)\n", agentName, logLevel)
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Errorf("addRemoteMap: ParseLevel failed: %s\n", err)
		return
	}
	remoteMapLock.Lock()
	defer remoteMapLock.Unlock()
	remoteMap[agentName] = level
	log.Infof("addRemoteMap after %v\n", remoteMap)
}

// Delete everything not in foundAgents
func delRemoteMapAgents(foundAgents map[string]bool) {
	log.Infof("delRemoteMapAgents(%v)\n", foundAgents)
	remoteMapLock.Lock()
	defer remoteMapLock.Unlock()
	for agentName := range remoteMap {
		log.Debugf("delRemoteMapAgents: processing %s\n", agentName)
		if _, ok := foundAgents[agentName]; !ok {
			delete(remoteMap, agentName)
		}
	}
	log.Infof("delRemoteMapAgents after %v\n", remoteMap)
}

func delRemoteMap(agentName string) {
	log.Infof("delRemoteMap(%s)\n", agentName)
	remoteMapLock.Lock()
	defer remoteMapLock.Unlock()
	delete(remoteMap, agentName)
}

func delRemoteMapAll() {
	log.Infof("delRemoteMapAll()\n")
	remoteMapLock.Lock()
	defer remoteMapLock.Unlock()
	remoteMap = make(map[string]log.Level)
}

// If source exists in GlobalConfig and has a remoteLogLevel, then
// we compare. If not we accept all
func dropEvent(source string, level log.Level) bool {
	remoteMapLock.Lock()
	defer remoteMapLock.Unlock()
	if l, ok := remoteMap[source]; ok {
		return level > l
	}
	// Any default setting?
	if l, ok := remoteMap["default"]; ok {
		return level > l
	}
	return false
}
