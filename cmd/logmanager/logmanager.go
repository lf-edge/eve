// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package logmanager

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"github.com/zededa/go-provision/zboot"
	"github.com/zededa/go-provision/zedcloud"
	"io"
	"io/ioutil"
	"os"
	dbg "runtime/debug"
	"strings"
	"sync"
	"time"
)

const (
	agentName       = "logmanager"
	identityDirname = "/config"
	serverFilename  = identityDirname + "/server"
	uuidFileName    = identityDirname + "/uuid"
	xenLogDirname   = "/var/log/xen"
	lastSentDirname = "lastlogsent" // Directory in /persist/
	logsApi         = "api/v1/edgedevice/logs"
	logMaxMessages  = 100
	logMaxBytes     = 32768 // Approximate - no headers counted
)

var (
	devUUID             uuid.UUID
	deviceNetworkStatus *types.DeviceNetworkStatus = &types.DeviceNetworkStatus{}
	debug               bool
	debugOverride       bool // From command line arg
	serverName          string
	logsUrl             string
	zedcloudCtx         zedcloud.ZedCloudContext
	logs                map[string]zedcloudLogs // Key is ifname string
)

// global stuff
type logDirModifyHandler func(ctx interface{}, logFileName string, source string)
type logDirDeleteHandler func(ctx interface{}, logFileName string, source string)

type logmanagerContext struct {
	subGlobalConfig *pubsub.Subscription
	subDomainStatus *pubsub.Subscription
}

// Set from Makefile
var Version = "No version specified"

// Based on the proto file
type logEntry struct {
	severity  string
	source    string // basename of filename?
	iid       string // XXX e.g. PID - where do we get it from?
	content   string // One line
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
	subDeviceNetworkStatus *pubsub.Subscription
}

type zedcloudLogs struct {
	FailureCount uint64
	SuccessCount uint64
	LastFailure  time.Time
	LastSuccess  time.Time
}

func Run() {
	logf, err := agentlog.InitWithDirText(agentName, "/persist/log")
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	defaultLogdirname := agentlog.GetCurrentLogdir()
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug")
	forcePtr := flag.Bool("f", false, "Force")
	logdirPtr := flag.String("l", defaultLogdirname, "Log file directory")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	logDirName := *logdirPtr
	force := *forcePtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}

	// Note that LISP needs a separate directory since it moves
	// old content to a subdir when it (re)starts
	lispLogDirName := fmt.Sprintf("%s/%s", logDirName, "lisp")
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s watching %s\n", agentName, logDirName)
	log.Infof("watching %s\n", lispLogDirName)

	// Make sure we have the last sent directory
	dirname := fmt.Sprintf("/persist/%s", lastSentDirname)
	if _, err := os.Stat(dirname); err != nil {
		if err := os.MkdirAll(dirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	cms := zedcloud.GetCloudMetrics() // Need type of data
	pub, err := pubsub.Publish(agentName, cms)
	if err != nil {
		log.Fatal(err)
	}

	logmanagerCtx := logmanagerContext{}
	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &logmanagerCtx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	logmanagerCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Get DomainStatus from domainmgr
	subDomainStatus, err := pubsub.Subscribe("domainmgr",
		types.DomainStatus{}, false, &logmanagerCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDomainStatus.ModifyHandler = handleDomainStatusModify
	subDomainStatus.DeleteHandler = handleDomainStatusDelete
	logmanagerCtx.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	// Wait until we have at least one useable address?
	DNSctx := DNSContext{}
	DNSctx.usableAddressCount = types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &DNSctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	DNSctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	log.Infof("Waiting until we have some uplinks with usable addresses\n")
	for DNSctx.usableAddressCount == 0 && !force {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
		}
	}
	log.Infof("Have %d uplinks with usable addresses\n",
		DNSctx.usableAddressCount)

	// Timer for deferred sends of info messages
	deferredChan := zedcloud.InitDeferred()

	//Get servername, set logUrl, get device id and initialize zedcloudCtx
	sendCtxInit()

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
	lastSent := readLastSent(currentPartition)
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
		lastSent := readLastSent(otherPartition)
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

	lispLogDirChanges := make(chan string)
	go watch.WatchStatus(lispLogDirName, false, lispLogDirChanges)

	xenLogDirChanges := make(chan string)
	go watch.WatchStatus(xenLogDirname, false, xenLogDirChanges)

	log.Debugln("called watcher...")
	for {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDomainStatus.C:
			subDomainStatus.ProcessChange(change)

		case change := <-logDirChanges:
			HandleLogDirEvent(change, logDirName, &ctx,
				handleLogDirModify, handleLogDirDelete)

		case change := <-otherLogDirChanges:
			HandleLogDirEvent(change, otherLogDirname, &otherCtx,
				handleLogDirModify, handleLogDirDelete)

		case change := <-lispLogDirChanges:
			HandleLogDirEvent(change, lispLogDirName, &ctx,
				handleLogDirModify, handleLogDirDelete)

		case change := <-xenLogDirChanges:
			HandleLogDirEvent(change, xenLogDirname, &xenCtx,
				handleXenLogDirModify, handleXenLogDirDelete)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case <-publishTimer.C:
			log.Debugln("publishTimer at", time.Now())
			err := pub.Publish("global", zedcloud.GetCloudMetrics())
			if err != nil {
				log.Errorln(err)
			}
		case change := <-deferredChan:
			zedcloud.HandleDeferred(change, 1*time.Second)
			dbg.FreeOSMemory()
		}
	}
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	*deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.usableAddressCount = newAddrCount
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

	reportLogs := new(zmet.LogBundle)
	// XXX should we make the log interval configurable?
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	flushTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	messageCount := 0
	dropped := 0
	for {
		select {
		case event, more := <-logChan:
			sent := false
			if !more {
				log.Infof("processEvents(%s) end\n",
					image)
				if messageCount > 0 {
					sent = sendProtoStrForLogs(reportLogs, image,
						iteration)
				}
				if sent {
					recordLastSent(image)
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

			if messageCount >= logMaxMessages ||
				byteCount >= logMaxBytes {

				log.Debugf("processEvents(%s): sending at messageCount %d, byteCount %d\n",
					image, messageCount, byteCount)
				sent = sendProtoStrForLogs(reportLogs, image,
					iteration)
				messageCount = 0
				iteration += 1
			}
			if sent {
				recordLastSent(image)
			}

		case <-flushTimer.C:
			if messageCount > 0 {
				log.Debugf("processEvents(%s) flush at %s dropped %d messageCount %d bytecount %d\n",
					image, time.Now().String(),
					dropped, messageCount,
					proto.Size(reportLogs))
				sent := sendProtoStrForLogs(reportLogs, image,
					iteration)
				messageCount = 0
				iteration += 1
				if sent {
					recordLastSent(image)
				}
			}
		}
	}
}

// Touch/create a file to keep track of when things where sent before a reboot
func recordLastSent(image string) {
	log.Debugf("recordLastSent(%s)\n", image)
	filename := fmt.Sprintf("/persist/%s/%s", lastSentDirname, image)
	_, err := os.Stat(filename)
	if err != nil {
		file, err := os.Create(filename)
		if err != nil {
			log.Infof("recordLastSent: %s\n", err)
			return
		}
		file.Close()
	}
	_, err = os.Stat(filename)
	if err != nil {
		log.Errorf("recordLastSent: %s\n", err)
		return
	}
	now := time.Now()
	err = os.Chtimes(filename, now, now)
	if err != nil {
		log.Errorf("recordLastSent: %s\n", err)
		return
	}
}

func readLastSent(image string) time.Time {
	filename := fmt.Sprintf("/persist/%s/%s", lastSentDirname, image)
	st, err := os.Stat(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("readLastSent: %s\n", err)
		}
		return time.Time{}
	}
	return st.ModTime()
}

var msgIdCounter = 1
var iteration = 0

func HandleLogEvent(event logEntry, reportLogs *zmet.LogBundle, counter int) {
	// Assign a unique msgId for each message
	msgId := msgIdCounter
	msgIdCounter += 1
	log.Debugf("Read event from %s time %v id %d: %s\n",
		event.source, event.timestamp, msgId, event.content)
	logDetails := &zmet.LogEntry{}
	logDetails.Content = event.content
	logDetails.Severity = event.severity
	logDetails.Timestamp, _ = ptypes.TimestampProto(event.timestamp)
	logDetails.Source = event.source
	logDetails.Iid = event.iid
	logDetails.Msgid = uint64(msgId)
	reportLogs.Log = append(reportLogs.Log, logDetails)
}

// Returns true if a message was successfully sent
func sendProtoStrForLogs(reportLogs *zmet.LogBundle, image string,
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
	log.Debugf("Log Details (size %d): %s\n", size, reportLogs)
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("sendProtoStrForLogs malloc error:")
	}

	if zedcloud.HasDeferred(image) {
		log.Infof("SendProtoStrForLogs queued after existing for %s\n",
			image)
		zedcloud.AddDeferred(image, buf, size, logsUrl, zedcloudCtx, false)
		reportLogs.Log = []*zmet.LogEntry{}
		return false
	}
	_, _, err = zedcloud.SendOnAllIntf(zedcloudCtx, logsUrl,
		size, buf, iteration, false)
	if err != nil {
		log.Errorf("SendProtoStrForLogs %d bytes image %s failed: %s\n",
			size, image, err)
		// Try sending later. The deferred state means processEvents
		// will sleep until the timer takes care of sending this
		// hence we'll keep things in order for a given image
		zedcloud.AddDeferred(image, buf, size, logsUrl, zedcloudCtx,
			false)
		reportLogs.Log = []*zmet.LogEntry{}
		return false
	}
	log.Debugf("Sent %d bytes image %s to %s\n", size, image, logsUrl)
	reportLogs.Log = []*zmet.LogEntry{}
	return true
}

func sendCtxInit() {
	//get server name
	bytes, err := ioutil.ReadFile(serverFilename)
	if err != nil {
		log.Fatal(err)
	}
	strTrim := strings.TrimSpace(string(bytes))
	serverName = strings.Split(strTrim, ":")[0]

	//set log url
	logsUrl = serverName + "/" + logsApi

	tlsConfig, err := zedcloud.GetTlsConfig(serverName, nil)
	if err != nil {
		log.Fatal(err)
	}
	zedcloudCtx.DeviceNetworkStatus = deviceNetworkStatus
	zedcloudCtx.TlsConfig = tlsConfig
	zedcloudCtx.FailureFunc = zedcloud.ZedCloudFailure
	zedcloudCtx.SuccessFunc = zedcloud.ZedCloudSuccess

	// In case we run early, wait for UUID file to appear
	for {
		b, err := ioutil.ReadFile(uuidFileName)
		if err != nil {
			log.Errorln("ReadFile", err, uuidFileName)
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

	lastSent := readLastSent(source)
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
				level = log.DebugLevel
			}
			if dropEvent(r.source, level) {
				log.Debugf("Dropping source %s level %v\n",
					r.source, level)
				continue
			}
			// XXX set iid to PID? From where?
			// We add time to front of msg.
			logChan <- logEntry{source: r.source,
				content:   loginfo.Time + ": " + loginfo.Msg,
				severity:  loginfo.Level,
				timestamp: timestamp,
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

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*logmanagerContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	status := cast.CastGlobalConfig(statusArg)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	foundAgents := make(map[string]bool)
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
	for agentName, _ := range remoteMap {
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
