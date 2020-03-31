// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logmanager

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
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
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"gopkg.in/mcuadros/go-syslog.v2"
)

const (
	agentName      = "logmanager"
	commonLogdir   = types.PersistDir + "/log"
	logMaxMessages = 100
	logMaxBytes    = 32768 // Approximate - no headers counted
	// Time limits for event loop handlers
	errorTime              = 3 * time.Minute
	warningTime            = 40 * time.Second
	metricsPublishInterval = 300 * time.Second
)

var logContextPtr *logmanagerContext

// global stuff
type logDirModifyHandler func(ctx interface{}, logFileName string, source string)
type logDirDeleteHandler func(ctx interface{}, logFileName string, source string)

type logmanagerContext struct {
	agentBaseContext agentbase.Context
	subGlobalConfig  pubsub.Subscription
	globalConfig     *types.ConfigItemValueMap
	subDomainStatus  pubsub.Subscription
	GCInitialized    bool
	metricsPub       pubsub.Publication
	inputMetrics     *inputLogMetrics
	sync.RWMutex

	devUUID             uuid.UUID
	deviceNetworkStatus *types.DeviceNetworkStatus
	serverName          string
	logsURL             string
	zedcloudCtx         zedcloud.ZedCloudContext

	globalDeferInprogress bool
	eveVersion            string
	// Really a constant
	nilUUID    uuid.UUID
	domainUUID map[string]string

	// CLI Args
	fatalFlag bool
	hangFlag  bool
	force     bool
}

// Based on the proto file
type logEntry struct {
	severity  string
	source    string // basename of filename?
	iid       string // XXX e.g. PID - where do we get it from?
	content   string // One line
	filename  string // file name that generated the logmsg
	function  string // function name that generated the log msg
	timestamp time.Time
	isAppLog  bool
}

// List of log files we watch
type loggerContext struct {
	image        string
	logChan      chan<- logEntry
	inputMetrics *inputLogMetrics
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
}

// DNSContext holds context for handleDNSModify
type DNSContext struct {
	usableAddressCount     int
	subDeviceNetworkStatus pubsub.Subscription
	doDeferred             bool
	zedcloudCtx            *zedcloud.ZedCloudContext
}

type zedcloudLogs struct {
	FailureCount uint64
	SuccessCount uint64
	LastFailure  time.Time
	LastSuccess  time.Time
}

type inputLogMetrics struct {
	totalDeviceLogInput uint64
	totalAppLogInput    uint64
}

func newLogManagerContext() *logmanagerContext {
	ctx := logmanagerContext{}

	ctx.agentBaseContext = agentbase.DefaultContext(agentName)
	ctx.agentBaseContext.AddAgentCLIFlagsFnPtr = addAgentSpecificCLIFlags

	ctx.deviceNetworkStatus = &types.DeviceNetworkStatus{}
	ctx.eveVersion = agentlog.EveVersion()

	return &ctx
}

func (ctxPtr *logmanagerContext) AgentBaseContext() *agentbase.Context {
	return &ctxPtr.agentBaseContext
}

func addAgentSpecificCLIFlags() {
	flag.BoolVar(&logContextPtr.force, "f", false, "Force")
	flag.BoolVar(&logContextPtr.fatalFlag, "F", false, "Cause log.Fatal fault injection")
	flag.BoolVar(&logContextPtr.hangFlag, "H", false, "Cause watchdog .touch fault injection")
}

// Run is an entry point into running logmanager
func Run(ps *pubsub.PubSub) {

	logContextPtr = newLogManagerContext()

	agentbase.Run(logContextPtr)

	stillRunning := time.NewTicker(25 * time.Second)

	cms := zedcloud.GetCloudMetrics() // Need type of data
	pub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: cms,
		})
	if err != nil {
		log.Fatal(err)
	}

	var inputMetrics inputLogMetrics
	metricsPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.LogMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}

	logmanagerCtx := logmanagerContext{
		globalConfig: types.DefaultConfigItemValueMap(),
		metricsPub:   metricsPub,
		inputMetrics: &inputMetrics,
	}

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           &logmanagerCtx,
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
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		TopicImpl:     types.DomainStatus{},
		Activate:      false,
		Ctx:           &logmanagerCtx,
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
	DNSctx.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(*logContextPtr.deviceNetworkStatus)

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &DNSctx,
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
	for DNSctx.usableAddressCount == 0 && !logContextPtr.force {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		// This wait can take an unbounded time since we wait for IP
		// addresses. Punch StillRunning
		case <-stillRunning.C:
			// Fault injection
			if logContextPtr.fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if logContextPtr.hangFlag {
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
	sendCtxInit(&logmanagerCtx, &DNSctx)

	// Publish send metrics for zedagent every 10 seconds
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	currentPartition := zboot.GetCurrentPartition()
	loggerChan := make(chan logEntry)
	ctx := loggerContext{
		logChan:      loggerChan,
		image:        currentPartition,
		inputMetrics: &inputMetrics}

	// Start sender of log events
	go processEvents(currentPartition, loggerChan, logContextPtr.eveVersion, &logmanagerCtx)

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
			_, err := devicenetwork.VerifyDeviceNetworkStatus(*logContextPtr.deviceNetworkStatus, 1, 15)
			if err != nil {
				log.Errorf("logmanager(Run): log message processing still in "+
					"deferred state. err: %s", err)
				continue
			}
			start := time.Now()
			done := zedcloud.HandleDeferred(change, 1*time.Second)
			dbg.FreeOSMemory()
			logContextPtr.globalDeferInprogress = !done
			if logContextPtr.globalDeferInprogress {
				log.Warnf("logmanager: globalDeferInprogress")
			}
			pubsub.CheckMaxTimeTopic(agentName, "deferredChan", start,
				warningTime, errorTime)

		case <-stillRunning.C:
			// Fault injection
			if logContextPtr.fatalFlag {
				log.Fatal("Requested fault injection to cause watchdog")
			}
		}
		if logContextPtr.hangFlag {
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
		level := parseLogLevel(logInfo.Level)
		if dropEvent(logInfo.Source, level) {
			log.Debugf("Dropping source %s level %v\n",
				logInfo.Source, level)
			continue
		}
		timestamp := logParts["timestamp"].(time.Time)
		logSource := logInfo.Source
		appLog := false
		if strings.HasPrefix(logSource, "guest_vm-") {
			splitArr := strings.SplitN(logSource, "guest_vm-", 2)
			if len(splitArr) == 2 {
				if splitArr[0] == "" && splitArr[1] != "" {
					appLog = true
					logSource = splitArr[1]
				}
			}
		}
		logMsg := logEntry{
			source:    logSource,
			content:   timestamp.String() + ": " + logParts["content"].(string),
			severity:  logInfo.Level,
			timestamp: timestamp,
			function:  logInfo.Function,
			filename:  logInfo.Filename,
			isAppLog:  appLog,
		}
		ctx.logChan <- logMsg

		if appLog {
			ctx.inputMetrics.totalAppLogInput++
		} else {
			ctx.inputMetrics.totalDeviceLogInput++
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
	if cmp.Equal(logContextPtr.deviceNetworkStatus, status) {
		log.Infof("handleDNSModify no change\n")
		return
	}
	*logContextPtr.deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*logContextPtr.deviceNetworkStatus)
	cameOnline := (ctx.usableAddressCount == 0) && (newAddrCount != 0)
	ctx.usableAddressCount = newAddrCount
	if cameOnline && ctx.doDeferred {
		change := time.Now()
		done := zedcloud.HandleDeferred(change, 1*time.Second)
		logContextPtr.globalDeferInprogress = !done
		if logContextPtr.globalDeferInprogress {
			log.Warnf("handleDNSModify: globalDeferInprogress")
		}
	}

	// update proxy certs if configured
	if ctx.zedcloudCtx != nil && ctx.zedcloudCtx.V2API {
		zedcloud.UpdateTLSProxyCerts(ctx.zedcloudCtx)
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
	*logContextPtr.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*logContextPtr.deviceNetworkStatus)
	ctx.usableAddressCount = newAddrCount
	log.Infof("handleDNSDelete done for %s\n", key)
}

// This runs as a separate go routine sending out data
// Compares and drops events which have already been sent to the cloud
func processEvents(image string, logChan <-chan logEntry,
	eveVersion string, ctx *logmanagerContext) {

	reportLogs := new(logs.LogBundle)
	appLogBundles := make(map[string]*logs.AppInstanceLogBundle)
	// XXX should we make the log interval configurable?
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	flushTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	// Metrics publish timer. Publish log metrics every 5 minutes.
	interval = time.Duration(metricsPublishInterval)
	max = float64(interval)
	min = max * 0.3
	metricsPublishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	messageCount := 0
	byteCount := 0
	dropped := 0
	deferInprogress := false
	appUUID := ""
	var appLogBundle *logs.AppInstanceLogBundle
	var logMetrics types.LogMetrics
	for {
		// If we had a defer wait until it has been taken care of
		// Note that globalDeferInprogress might not yet be set
		// but if the condition persists it will be set in a bit
		if deferInprogress {
			log.Warnf("processEvents(%s) deferInprogress", image)
			time.Sleep(30 * time.Second)
			if logContextPtr.globalDeferInprogress {
				log.Warnf("processEvents(%s) globalDeferInprogress",
					image)
				continue
			}
			_, err := devicenetwork.VerifyDeviceNetworkStatus(*logContextPtr.deviceNetworkStatus, 1, 15)
			if err != nil {
				log.Warnf("processEvents:(%s) log message processing still"+
					" in deferred state", image)
				continue
			}
			log.Infof("processEvents(%s) deferInprogress done",
				image)
			deferInprogress = false
			logMetrics.IsLogProcessingDeferred = false
			// Publish LogMetrics
			publishLogMetrics(ctx, &logMetrics)
		}

		select {
		case event, more := <-logChan:
			sent := false
			is4xx := false
			if !more {
				log.Infof("processEvents(%s) end\n",
					image)
				flushAllLogBundles(image, iteration, eveVersion,
					reportLogs, appLogBundles, &logMetrics)
				return
			}
			if event.isAppLog {
				appUUID = lookupDomainName(ctx, event.source)
				if appUUID == "" {
					log.Errorf("processEvents(%s): UUID for App instance %s not found",
						image, event.source)
					break
				}
				var ok bool
				appLogBundle, ok = appLogBundles[appUUID]
				if !ok {
					log.Debugf("processEvents: Creating new Bundle for app %s with UUID %s",
						event.source, appUUID)
					appLogBundle = &logs.AppInstanceLogBundle{}
					appLogBundles[appUUID] = appLogBundle
				} else {
					log.Debugf("processEvents: Bundle found for app %s with UUID %s",
						event.source, appUUID)
				}

				ok = handleAppLogEvent(event, appLogBundle)
				if !ok {
					logMetrics.NumAppEventErrors++
				}
				messageCount = len(appLogBundle.Log)
				byteCount = proto.Size(appLogBundle)
			} else {
				ok := handleLogEvent(event, reportLogs)
				if !ok {
					logMetrics.NumDeviceEventErrors++
				}
				messageCount = len(reportLogs.Log)
				byteCount = proto.Size(reportLogs)
			}

			if messageCount < logMaxMessages &&
				byteCount < logMaxBytes {

				break
			}

			log.Debugf("processEvents(%s): sending at messageCount %d, byteCount %d\n",
				image, messageCount, byteCount)
			if event.isAppLog {
				sent, is4xx = sendProtoStrForAppLogs(appUUID, appLogBundle, iteration, image)
				if is4xx {
					logMetrics.Num4xxResponses += uint64(messageCount)
				} else {
					logMetrics.NumAppEventsSent += uint64(messageCount)
					logMetrics.NumAppBundleProtoBytesSent += uint64(byteCount)
					logMetrics.NumAppBundlesSent++
					logMetrics.LastAppBundleSendTime = time.Now()
				}
				delete(appLogBundles, appUUID)
			} else {
				sent = sendProtoStrForLogs(reportLogs, image, iteration, eveVersion)
				logMetrics.NumDeviceEventsSent += uint64(messageCount)
				logMetrics.NumDeviceBundleProtoBytesSent += uint64(byteCount)
				logMetrics.NumDeviceBundlesSent++
				logMetrics.LastDeviceBundleSendTime = time.Now()
			}

			iteration++
			if !sent {
				deferInprogress = true
				logMetrics.IsLogProcessingDeferred = true
				logMetrics.NumTimesDeferred++
				logMetrics.LastLogDeferTime = time.Now()
				// Publish LogMetrics
				publishLogMetrics(ctx, &logMetrics)
			}

		case <-flushTimer.C:
			log.Debugf("processEvents(%s) flush at %s dropped %d messageCount %d bytecount %d\n",
				image, time.Now().String(),
				dropped, messageCount,
				proto.Size(reportLogs))
			// Iterate the app/device log bundle map and send out all app logs
			sent := flushAllLogBundles(image, iteration, eveVersion,
				reportLogs, appLogBundles, &logMetrics)
			iteration++
			if !sent {
				deferInprogress = true
				logMetrics.IsLogProcessingDeferred = true
				logMetrics.NumTimesDeferred++
				logMetrics.LastLogDeferTime = time.Now()
				// Publish LogMetrics
				publishLogMetrics(ctx, &logMetrics)
			}
		case <-metricsPublishTimer.C:
			publishLogMetrics(ctx, &logMetrics)
			log.Debugf("processEvents(%s): Published log metrics at %s",
				image, time.Now().String())
		}
	}
}

func publishLogMetrics(ctx *logmanagerContext, outMetrics *types.LogMetrics) {
	outMetrics.TotalDeviceLogInput = ctx.inputMetrics.totalDeviceLogInput
	outMetrics.TotalAppLogInput = ctx.inputMetrics.totalAppLogInput
	ctx.metricsPub.Publish("global", *outMetrics)
}

func flushAllLogBundles(image string, iteration int, eveVersion string,
	reportLogs *logs.LogBundle, appLogBundles map[string]*logs.AppInstanceLogBundle,
	logMetrics *types.LogMetrics) bool {
	messageCount := len(reportLogs.Log)
	byteCount := proto.Size(reportLogs)
	sent := sendProtoStrForLogs(reportLogs, image, iteration, eveVersion)
	// Take care of metrics
	logMetrics.NumDeviceEventsSent += uint64(messageCount)
	logMetrics.NumDeviceBundleProtoBytesSent += uint64(byteCount)
	logMetrics.NumDeviceBundlesSent++
	logMetrics.LastDeviceBundleSendTime = time.Now()

	if !sent {
		return false
	}

	var is4xx bool
	appBundlesToDelete := []string{}
	for appUUID, appLogBundle := range appLogBundles {
		log.Debugf("flushAllLogBundles: Trying to flush App bundle with UUID %s and %d logs",
			appUUID, len(appLogBundle.Log))
		messageCount := len(appLogBundle.Log)
		byteCount := proto.Size(appLogBundle)
		sent, is4xx = sendProtoStrForAppLogs(appUUID, appLogBundle, iteration, image)

		// Take care of metrics
		if is4xx {
			logMetrics.Num4xxResponses += uint64(messageCount)
		} else {
			logMetrics.NumAppEventsSent += uint64(messageCount)
			logMetrics.NumAppBundleProtoBytesSent += uint64(byteCount)
			logMetrics.NumAppBundlesSent++
			logMetrics.LastAppBundleSendTime = time.Now()
		}

		log.Debugf("flushAllLogBundles: Flushed App bundle with UUID %s", appUUID)
		appBundlesToDelete = append(appBundlesToDelete, appUUID)
		if !sent {
			break
		}
	}
	for _, appUUID := range appBundlesToDelete {
		delete(appLogBundles, appUUID)
	}
	return sent
}

var msgIDCounter = 1
var iteration = 0

// returns false when app log event is dropped
func handleAppLogEvent(event logEntry, appLogs *logs.AppInstanceLogBundle) bool {
	log.Debugf("Read event from %s time %v",
		event.source, event.timestamp)
	// Have to discard if too large since service doesn't
	// handle above 64k; we limit payload at 32k
	strLen := len(event.content)
	if strLen > logMaxBytes {
		log.Errorf("handleLogEvent: dropping source %s %d bytes",
			event.source, strLen)
		return false
	}

	logDetails := &logs.LogEntry{}
	// XXX Is this still required. rsyslogd is now configured to do the same
	logDetails.Content = strings.Map(func(r rune) rune {
		if r == utf8.RuneError {
			return -1
		}
		return r
	}, event.content)
	logDetails.Severity = event.severity
	logDetails.Timestamp, _ = ptypes.TimestampProto(event.timestamp)
	logDetails.Source = event.source
	logDetails.Iid = event.iid
	logDetails.Filename = event.filename
	logDetails.Function = event.function
	oldLen := int64(proto.Size(appLogs))
	appLogs.Log = append(appLogs.Log, logDetails)
	newLen := int64(proto.Size(appLogs))
	if newLen > logMaxBytes {
		log.Warnf("handleLogEvent: source %s from %d to %d bytes",
			event.source, oldLen, newLen)
	}
	return true
}

// returns false when the device log event is dropped
func handleLogEvent(event logEntry, reportLogs *logs.LogBundle) bool {
	// Assign a unique msgID for each message
	msgID := msgIDCounter
	msgIDCounter++
	log.Debugf("Read event from %s time %v id %d",
		event.source, event.timestamp, msgID)
	// Have to discard if too large since service doesn't
	// handle above 64k; we limit payload at 32k
	strLen := len(event.content)
	if strLen > logMaxBytes {
		log.Errorf("handleLogEvent: dropping source %s %d bytes",
			event.source, strLen)
		return false
	}

	logDetails := &logs.LogEntry{}
	logDetails.Content = strings.Map(func(r rune) rune {
		if r == utf8.RuneError {
			return -1
		}
		return r
	}, event.content)
	logDetails.Severity = event.severity
	logDetails.Timestamp, _ = ptypes.TimestampProto(event.timestamp)
	logDetails.Source = event.source
	logDetails.Iid = event.iid
	logDetails.Msgid = uint64(msgID)
	logDetails.Filename = event.filename
	logDetails.Function = event.function
	oldLen := int64(proto.Size(reportLogs))
	reportLogs.Log = append(reportLogs.Log, logDetails)
	newLen := int64(proto.Size(reportLogs))
	if newLen > logMaxBytes {
		log.Warnf("handleLogEvent: source %s from %d to %d bytes",
			event.source, oldLen, newLen)
	}
	return true
}

// Returns true if a message was successfully sent
func sendProtoStrForLogs(reportLogs *logs.LogBundle, image string,
	iteration int, eveVersion string) bool {
	if len(reportLogs.Log) == 0 {
		return true
	}
	reportLogs.Timestamp = ptypes.TimestampNow()
	reportLogs.DevID = *proto.String(logContextPtr.devUUID.String())
	reportLogs.Image = image
	reportLogs.EveVersion = eveVersion

	log.Debugln("sendProtoStrForLogs called...", iteration)
	data, err := proto.Marshal(reportLogs)
	if err != nil {
		log.Fatal("sendProtoStrForLogs proto marshaling error: ", err)
	}
	size := int64(proto.Size(reportLogs))
	if size > logMaxBytes {
		log.Warnf("LogBundle: DevID %s, Image %s, EveVersion %s, %d log entries",
			reportLogs.DevID, reportLogs.Image, reportLogs.EveVersion, len(reportLogs.Log))
	} else {
		log.Debugf("sendProtoStrForLogs %d bytes: %s\n",
			size, reportLogs)
		log.Debugf("LogBundle: DevID %s, Image %s, EveVersion %s",
			reportLogs.DevID, reportLogs.Image, reportLogs.EveVersion)
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
		zedcloud.AddDeferred(image, buf, size, logContextPtr.logsURL, logContextPtr.zedcloudCtx,
			return400)
		reportLogs.Log = []*logs.LogEntry{}
		return false
	}
	resp, _, _, err := zedcloud.SendOnAllIntf(&logContextPtr.zedcloudCtx, logContextPtr.logsURL,
		size, buf, iteration, return400)
	// XXX We seem to still get large or bad messages which are rejected
	// by the server. Ignore them to make sure we can log subsequent ones.
	// XXX Should we inject a separate log entry to record that we dropped
	// this one?
	if resp != nil && resp.StatusCode == 400 {
		log.Errorf("Failed sending %d bytes image %s to %s; code 400; ignored error\n",
			size, image, logContextPtr.logsURL)
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
		zedcloud.AddDeferred(image, buf, size, logContextPtr.logsURL, logContextPtr.zedcloudCtx,
			return400)
		reportLogs.Log = []*logs.LogEntry{}
		return false
	}
	log.Debugf("Sent %d bytes image %s to %s\n", size, image, logContextPtr.logsURL)
	reportLogs.Log = []*logs.LogEntry{}
	return true
}

// Returns true if a message was successfully sent
func sendProtoStrForAppLogs(appUUID string, appLogs *logs.AppInstanceLogBundle,
	iteration int, image string) (sent, is4xx bool) {
	if len(appLogs.Log) == 0 {
		return true, false
	}
	log.Debugln("sendProtoStrForAppLogs called...", iteration)
	data, err := proto.Marshal(appLogs)
	if err != nil {
		log.Fatal("sendProtoStrForAppLogs proto marshaling error: ", err)
	}
	size := int64(proto.Size(appLogs))
	if size > logMaxBytes {
		log.Warnf("AppLogBundle: App with UUID %s, %d log entries", appUUID, len(appLogs.Log))
	} else {
		log.Debugf("sendProtoStrForAppLogs %d bytes: %s", size, appLogs)
		log.Debugf("AppLogBundle: App with UUID %s", appUUID)
	}
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("sendProtoStrForAppLogs malloc error:")
	}

	// api/v1/edgeDevice/apps/instances/id/<app-instance-uuid>/logs
	appLogURL := fmt.Sprintf("apps/instances/id/%s/logs", appUUID)
	//get server name
	serverBytes, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatalf("Failed to read ServerFileName (%s). Err: %s",
			types.ServerFileName, err)
	}
	// Preserve port
	serverNameAndPort := strings.TrimSpace(string(serverBytes))
	appLogsURL := zedcloud.URLPathString(serverNameAndPort, logContextPtr.zedcloudCtx.V2API, false,
		logContextPtr.nilUUID, appLogURL)

	// For any 400 error we abandon
	const return400 = true
	if zedcloud.HasDeferred(image) {
		log.Infof("SendProtoStrForAppLogs queued after existing for %s\n",
			image)
		zedcloud.AddDeferred(image, buf, size, appLogsURL, logContextPtr.zedcloudCtx,
			return400)
		appLogs.Log = []*logs.LogEntry{}
		return false, false
	}
	resp, _, _, err := zedcloud.SendOnAllIntf(&logContextPtr.zedcloudCtx, appLogsURL,
		size, buf, iteration, return400)
	// XXX We seem to still get large or bad messages which are rejected
	// by the server. Ignore them to make sure we can log subsequent ones.
	// XXX Should we inject a separate log entry to record that we dropped
	// this one?
	// Response code 404 is sent back where device tries to send log entries,
	// corresponding to an app/container instance that has already been deleted.
	if resp != nil {
		is4xx := isResp4xx(resp.StatusCode)
		if is4xx {
			log.Errorf("Failed sending %d bytes image %s to %s; code %v; ignored error\n",
				size, image, appLogsURL, resp.StatusCode)
			appLogs.Log = []*logs.LogEntry{}
			return true, true
		}
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
		zedcloud.AddDeferred(image, buf, size, appLogsURL, logContextPtr.zedcloudCtx,
			return400)
		appLogs.Log = []*logs.LogEntry{}
		return false, false
	}
	log.Debugf("Sent %d bytes image %s to %s\n", size, image, appLogsURL)
	appLogs.Log = []*logs.LogEntry{}
	return true, false
}

func isResp4xx(code int) bool {
	remainder := code - 400
	if remainder >= 0 && remainder <= 99 {
		return true
	}
	return false
}

func sendCtxInit(ctx *logmanagerContext, dnsCtx *DNSContext) {
	//get server name
	bytes, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatalf("sendCtxInit: Failed to read ServerFileName(%s). Err: %s",
			types.ServerFileName, err)
	}
	// Preserve port
	serverNameAndPort := strings.TrimSpace(string(bytes))
	logContextPtr.serverName = strings.Split(logContextPtr.serverName, ":")[0]

	//set log url
	logContextPtr.zedcloudCtx = zedcloud.NewContext(zedcloud.ContextOptions{
		DevNetworkStatus: logContextPtr.deviceNetworkStatus,
		Timeout:          ctx.globalConfig.GlobalValueInt(types.NetworkSendTimeout),
		NeedStatsFunc:    true,
		Serial:           hardware.GetProductSerial(),
		SoftSerial:       hardware.GetSoftSerial(),
	})
	log.Infof("sendCtxInit: Use V2 API %v\n", zedcloud.UseV2API())

	dnsCtx.zedcloudCtx = &logContextPtr.zedcloudCtx
	log.Infof("Log Get Device Serial %s, Soft Serial %s\n", logContextPtr.zedcloudCtx.DevSerial,
		logContextPtr.zedcloudCtx.DevSoftSerial)

	// XXX need to redo this since the root certificates can change when DeviceNetworkStatus changes
	err = zedcloud.UpdateTLSConfig(&logContextPtr.zedcloudCtx, logContextPtr.serverName, nil)
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
		logContextPtr.devUUID, err = uuid.FromString(uuidStr)
		if err != nil {
			log.Errorln("uuid.FromString", err, string(b))
			time.Sleep(time.Second)
			continue
		}
		logContextPtr.zedcloudCtx.DevUUID = logContextPtr.devUUID
		break
	}
	// wait for uuid of logs V2 URL string
	logContextPtr.logsURL = zedcloud.URLPathString(serverNameAndPort, logContextPtr.zedcloudCtx.V2API, false, logContextPtr.devUUID, "logs")
	log.Infof("Read UUID %s\n", logContextPtr.devUUID)
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
	status := statusArg.(types.ConfigItemValueMap)
	var gcp *types.ConfigItemValueMap
	ctx.agentBaseContext.CLIParams.Debug, gcp = agentlog.HandleGlobalConfigNoDefault(ctx.subGlobalConfig,
		agentName, ctx.agentBaseContext.CLIParams.DebugOverride)
	if gcp != nil {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	foundAgents := make(map[string]bool)
	defaultRemoteLogLevel := types.DefaultConfigItemValueMap().GlobalValueString(types.DefaultRemoteLogLevel)
	if defaultRemoteLogLevel != "" {
		foundAgents["default"] = true
		addRemoteMap("default", defaultRemoteLogLevel)
	}
	for agentName := range status.AgentSettings {
		log.Debugf("Processing agentName %s\n", agentName)
		foundAgents[agentName] = true
		remoteLogLevel := status.AgentSettingStringValue(agentName, types.RemoteLogLevel)
		if remoteLogLevel != "" {
			addRemoteMap(agentName, remoteLogLevel)
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
	ctx.agentBaseContext.CLIParams.Debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		ctx.agentBaseContext.CLIParams.DebugOverride)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
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

func parseLogLevel(logLevel string) log.Level {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		// XXX Some of the log sources send logs with
		// severity set to err, emerg & notice.
		// Logrus log level parse does not recognize the above severities.
		// Map err, emerg to error and notice to info.
		if logLevel == "err" || logLevel == "emerg" {
			level = log.ErrorLevel
		} else if logLevel == "notice" {
			level = log.InfoLevel
		} else {
			log.Errorf("ParseLevel failed: %s, defaulting log level to Info\n", err)
			level = log.InfoLevel
		}
	}
	return level
}
