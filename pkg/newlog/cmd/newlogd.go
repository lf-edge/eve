// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/google/go-cmp/cmp"
	"github.com/euank/go-kmsg-parser/kmsgparser"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"flag"
	"os"
	"time"
)

const (
	agentName           = "newlogd"
	errorTime           = 3 * time.Minute
	warningTime         = 40 * time.Second // XXX was 40 sec
	metricsPublishInterval       = 300 * time.Second
	logfileDelay                 = 300 * time.Second // maxinum delay 5 minutes for log file collection
	stillRunningInerval = 25 * time.Second // XXX was 25 sec

	newlogDir    = "/persist/newlog"
	collectDir   = newlogDir + "/collect"
	uploadDevDir = newlogDir + "/devUpload"
	uploadAppDir = newlogDir + "/appUpload"
	devPrefix    = "dev."
	appPrefix    = "app."
	metaInfoName = "log_meta_info"

	maxLogFileSize         int32 = 420000            // maxinum collect file size in bytes
	maxGzipFileSize        int32 = 46000             // maxinum gzipped file size for upload in bytes
	defaultSyncCount             = 15 // default log events flush/sync to disk file
)

var (
	savedPid = 0
	devUUID  string
	logmetrics  types.NewlogMetrics
	syncToFileCnt       int // every 'N' log event count flush to log file
	domainUUID map[string]appDomain // App log, from domain-id to app-UUID and app-Name
	// syslog/kmsg priority string definition
	priorityStr = [8]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
)

// for app Domain-ID mapping into UUID and DisplayName
type appDomain struct {
	appUUID string
	appName string
}

type logEntry struct {
	severity  string
	source    string // basename of filename?
	content   string // One line
	filename  string // file name that generated the logmsg
	function  string // function name that generated the log msg
	timestamp string
	appUUID   string // App UUID
	acName    string // App Container Name
	acLogTime string // App Container log time
}

func main() {
	restartPtr := flag.Bool("r", false, "Restart")
	flag.Parse()
	restarted := *restartPtr

	logInit()

	if !restarted {
		if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
			log.Fatal(err)
		}
		syncToFileCnt = defaultSyncCount
	} else {
		// sync every log event in restart mode, going down in less than 5 min
		syncToFileCnt = 1
	}

	stillRunning := time.NewTicker(stillRunningInerval)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	log.Infof("newlogd: starting... restarted %v", restarted)

	// XXX Start a number of go routines for collect, process, compress log events
	loggerChan := make(chan logEntry, 10)

	// handle the kernal messages
	go getKmessages(loggerChan)

	ps := *pubsub.New(&socketdriver.SocketDriver{})
	// Publish newlog metrics
	metricsPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.NewlogMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}

	// domain-name to UUID and App-name mapping
	domainUUID = make(map[string]appDomain)
	// Get DomainStatus from domainmgr
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		TopicImpl:     types.DomainStatus{},
		Activate:      false,
		CreateHandler: handleDomainStatusModify,
		ModifyHandler: handleDomainStatusModify,
		DeleteHandler: handleDomainStatusDelete,
	})
	if err != nil {
		log.Fatal(err)
	}
	subDomainStatus.Activate()

	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		CreateHandler: handleOnboardStatusModify,
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

	// newlog Metrics publish timer. Publish log metrics every 5 minutes.
	interval := time.Duration(metricsPublishInterval)
	max := float64(interval)
	min := max * 0.3
	metricsPublishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	for {
		select {
		case <-metricsPublishTimer.C:
			metricsPub.Publish("global", logmetrics)
			log.Debugf("newlodg main: Published newlog metrics at %s", time.Now().String())

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

// Handles UUID change from process client
func handleOnboardStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.OnboardingStatus)
	if cmp.Equal(devUUID, status.DeviceUUID) {
		log.Infof("newlogd handleOnboardStatusModify no change to %v", devUUID)
		return
	}
	devUUID = status.DeviceUUID.String()
	log.Infof("newlogd handleOnboardStatusModify changed to %v", devUUID)
}

func handleDomainStatusModify(ctxArg interface{}, key string, statusArg interface{}) {

	log.Infof("handleDomainStatusModify: for %s", key)
	status := statusArg.(types.DomainStatus)
	// Record the domainName even if Pending* is set
	log.Infof("handleDomainStatusModify: add %s to %s",
		status.DomainName, status.UUIDandVersion.UUID.String())
	appD := appDomain{
		appUUID: status.UUIDandVersion.UUID.String(),
		appName: status.DisplayName,
	}
	domainUUID[status.DomainName] = appD
	log.Infof("handleDomainStatusModify: done for %s", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string, statusArg interface{}) {

	log.Infof("handleDomainStatusDelete: for %s", key)
	status := statusArg.(types.DomainStatus)
	if _, ok := domainUUID[status.DomainName]; !ok {
		return
	}
	log.Infof("handleDomainStatusDelete: remove %s", status.DomainName)
	delete(domainUUID, status.DomainName)
	log.Infof("handleDomainStatusDelete: done for %s", key)
}

func logInit() {
	savedPid = os.Getpid()
	hook := new(SourceHook)
	log.AddHook(hook)
	formatter := log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
	log.SetFormatter(&formatter)
	log.SetReportCaller(true)
	log.RegisterExitHandler(agentlog.PrintStacks)
}

// SourceHook is used to add source=agentName
type SourceHook struct {
}

// Fire adds source=agentName
func (hook *SourceHook) Fire(entry *log.Entry) error {
	entry.Data["source"] = agentName
	entry.Data["pid"] = savedPid
	return nil
}

// Levels installs the SourceHook for all levels
func (hook *SourceHook) Levels() []log.Level {
	return log.AllLevels
}

// getKmessages - goroutine to get from /dev/kmsg
func getKmessages(loggerChan chan logEntry) {
	parser, err := kmsgparser.NewParser()
	if err != nil {
		log.Fatalf("unable to create kmsg parser: %v", err)
	}
	defer parser.Close()

	kmsg := parser.Parse()
	for msg := range kmsg {
		entry := logEntry{
			source:    "kernel",
			severity:  "info",
			content:   msg.Message,
			timestamp: msg.Timestamp.Format(time.RFC3339Nano),
		}
		if msg.Priority >= 0 && msg.Priority < len(priorityStr) {
			entry.severity = priorityStr[msg.Priority]
		}

		//loggerChan <- entry
	}
}
