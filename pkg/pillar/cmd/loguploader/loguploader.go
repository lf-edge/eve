// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package loguploader

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve-api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "loguploader"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	failSendDir = types.NewlogDir + "/failedUpload"
	keepSentDir = types.NewlogKeepSentQueueDir

	backoffMaxUploadIntv   = 300
	backoffTimeout         = 3600 // backoff timeout in one hour, within that duration, not to use the normal upload interval calculation
	defaultUploadIntv      = 90
	metricsPublishInterval = 300 * time.Second
	cloudMetricInterval    = 10 * time.Second
	stillRunningInerval    = 25 * time.Second
	max4xxdropFiles        = 1000  // leave maximum of 1000 gzip failed to upload files on device, 50M max disk space
	max4xxRetries          = 10    // move on if the same gzip file failed for 4xx
	warnGzipFileSize       = 50000 // maximum expected gzipped file size for upload in bytes
	errorGzipFileSize      = 65536 // hard limit of gzipped file size for upload in bytes
)

var (
	deviceNetworkStatus = &types.DeviceNetworkStatus{}
	backoffEnabled      bool // when received 429 code, before backoffTimeout expires, not use the normal upload scheduling
	logger              *logrus.Logger
	log                 *base.LogObject
	contSentSuccess     int64
	contSentFailure     int64
	dev4xxfile          resp4xxlogfile
	app4xxfile          resp4xxlogfile
	appGzipMap          map[string]bool // current app gzip files counts with app-uuid as key
)

type resp4xxlogfile struct {
	logfileName string
	failureCnt  int
}

type loguploaderContext struct {
	agentbase.AgentBase
	devUUID                uuid.UUID
	globalConfig           *types.ConfigItemValueMap
	ctrlClient             *controllerconn.Client
	subDeviceNetworkStatus pubsub.Subscription
	subGlobalConfig        pubsub.Subscription
	subAppInstConfig       pubsub.Subscription
	subCachedResolvedIPs   pubsub.Subscription
	subZedAgentStatus      pubsub.Subscription
	usableAddrCount        int
	metrics                types.NewlogMetrics
	agentMetrics           *controllerconn.AgentMetrics
	serverNameAndPort      string
	metricsPub             pubsub.Publication
	enableFastUpload       bool
	airgapMode             bool
	scheduleTimer          *time.Timer
	backoffExprTimer       *time.Timer
}

func (ctx *loguploaderContext) getCachedResolvedIPs(hostname string) []types.CachedIP {
	if ctx.subCachedResolvedIPs == nil {
		return nil
	}
	if item, err := ctx.subCachedResolvedIPs.Get(hostname); err == nil {
		return item.(types.CachedResolvedIPs).CachedIPs
	}
	return nil
}

// Run - an loguploader run
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	loguploaderCtx := loguploaderContext{
		globalConfig: types.DefaultConfigItemValueMap(),
		agentMetrics: controllerconn.NewAgentMetrics(),
	}
	agentbase.Init(&loguploaderCtx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningInerval)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait until we have been onboarded aka know our own UUID
	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		MyAgentName:   agentName,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      true,
		Persistent:    true,
		Ctx:           &loguploaderCtx,
		CreateHandler: handleOnboardStatusCreate,
		ModifyHandler: handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	// Wait for Onboarding to be done by client
	nilUUID := uuid.UUID{}
	for loguploaderCtx.devUUID == nilUUID {
		log.Functionf("Waiting for OnboardStatus UUID")
		select {
		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	sendCtxInit(ps, &loguploaderCtx)

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &loguploaderCtx,
		CreateHandler: handleDNSCreate,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	loguploaderCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &loguploaderCtx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	loguploaderCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// get the AppInstanceConfig, will use for maintaining the current
	// log MetricsMap http URL sets
	subAppInstConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.AppInstanceConfig{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	loguploaderCtx.subAppInstConfig = subAppInstConfig
	subAppInstConfig.Activate()

	// To check if Air-gap mode is enabled, in which case lack of cloud connectivity
	// is expected.
	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           &loguploaderCtx,
		CreateHandler: handleZedAgentStatusCreate,
		ModifyHandler: handleZedAgentStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	loguploaderCtx.subZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	sendCtxInit(ps, &loguploaderCtx)

	for loguploaderCtx.usableAddrCount == 0 {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		// This wait can take an unbounded time since we wait for IP
		// addresses. Punch StillRunning
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("Have %d management ports with usable addresses", loguploaderCtx.usableAddrCount)

	subCachedResolvedIPs, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "nim",
		MyAgentName: agentName,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		TopicImpl:   types.CachedResolvedIPs{},
		Activate:    true,
	})
	if err != nil {
		log.Fatal(err)
	}
	loguploaderCtx.subCachedResolvedIPs = subCachedResolvedIPs

	// Publish cloud metrics
	pubCloud, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.MetricsMap{},
		})
	if err != nil {
		log.Fatal(err)
	}

	interval := time.Duration(cloudMetricInterval) // every 10 sec
	max := float64(interval)
	min := max * 0.3
	publishCloudTimer := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	// Publish newlog metrics
	metricsPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.NewlogMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}
	loguploaderCtx.metricsPub = metricsPub

	// assume we can not send to cloud first, fail-to-send status to 'newlogd'
	loguploaderCtx.metrics.FailedToSend = true
	loguploaderCtx.metrics.FailSentStartTime = time.Now()

	// newlog Metrics publish timer. Publish log metrics every 5 minutes.
	interval = time.Duration(metricsPublishInterval)
	max = float64(interval)
	min = max * 0.3
	metricsPublishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	var numLeftFiles, iteration, prevIntv int
	var initSched time.Duration
	if loguploaderCtx.enableFastUpload {
		initSched = 1
	} else {
		initSched = 1200
	}
	loguploaderCtx.scheduleTimer = time.NewTimer(initSched * time.Second)

	loguploaderCtx.backoffExprTimer = time.NewTimer(backoffTimeout * time.Second)
	loguploaderCtx.backoffExprTimer.Stop()

	// init the upload interface to 2 min
	loguploaderCtx.metrics.CurrUploadIntvSec = defaultUploadIntv
	uploadTimer := time.NewTimer(time.Duration(loguploaderCtx.metrics.CurrUploadIntvSec) * time.Second)

	// create the necceary directories upfront
	if _, err := os.Stat(keepSentDir); os.IsNotExist(err) {
		if err := os.MkdirAll(keepSentDir, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(failSendDir); os.IsNotExist(err) {
		if err := os.MkdirAll(failSendDir, 0755); err != nil {
			log.Fatal(err)
		}
	}

	pubidx := 0
	for {
		select {
		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case change := <-subAppInstConfig.MsgChan():
			subAppInstConfig.ProcessChange(change)

		case change := <-subZedAgentStatus.MsgChan():
			subZedAgentStatus.ProcessChange(change)

		case change := <-subCachedResolvedIPs.MsgChan():
			subCachedResolvedIPs.ProcessChange(change)

		case <-publishCloudTimer.C:
			start := time.Now()
			log.Tracef("publishCloudTimer cloud metrics at at %s", time.Now().String())
			err := loguploaderCtx.agentMetrics.Publish(log, pubCloud, "global")
			if err != nil {
				log.Errorln(err)
			}
			ps.CheckMaxTimeTopic(agentName, "publishCloudTimer", start, warningTime, errorTime)
			pubidx++
			if pubidx%360 == 0 { // reuse the timer, do check hourly for MetricMap
				checkAppLogMetrics(&loguploaderCtx)
			}

		case <-metricsPublishTimer.C:
			metricsPub.Publish("global", loguploaderCtx.metrics)
			log.Tracef("Published newlog upload metrics at %s", time.Now().String())

		case <-loguploaderCtx.backoffExprTimer.C:
			// backoff timer expired. resume the normal upload schedule
			backoffEnabled = false
			if loguploaderCtx.scheduleTimer != nil {
				loguploaderCtx.scheduleTimer.Stop()
			}
			log.Tracef("upload backoff expired. resume normal")
			loguploaderCtx.scheduleTimer = time.NewTimer(1 * time.Second)

		case <-loguploaderCtx.scheduleTimer.C:

			// upload interval stays for 20 min once it calculates
			// - if the device is disconnected from cloud for over 20 min, then when use random
			//   interval between 3-15 min to retry, avoid overwhelming the cloud server once it is up
			// - in normal uploading case, set interval depends on the number of gzip files left in
			//   both dev/app directories, from 15 seconds up to to 2 minutes
			// - if Configure Item has enabled fastUpload, check/upload every 3 sec
			//
			// at device starts, more logging activities, and slower timer. will see longer delays,
			// as the device moves on, the log upload should catchup quickly
			var interval int
			prevBackoff := time.Since(loguploaderCtx.metrics.LastTooManyReqTime) / time.Second
			if backoffEnabled {
				// skip evaluation, it's now controlled by backoff
			} else if loguploaderCtx.enableFastUpload {
				loguploaderCtx.metrics.CurrUploadIntvSec = 3
				uploadTimer.Stop()
				uploadTimer = time.NewTimer(time.Duration(loguploaderCtx.metrics.CurrUploadIntvSec) * time.Second)
			} else if loguploaderCtx.metrics.FailedToSend &&
				time.Since(loguploaderCtx.metrics.FailSentStartTime).Nanoseconds()/int64(time.Second) > 1200 {
				loguploaderCtx.metrics.CurrUploadIntvSec = uint32(rand.Intn(720) + 180)
			} else {
				if numLeftFiles < 5 {
					interval = defaultUploadIntv
				} else if numLeftFiles >= 5 && numLeftFiles < 25 {
					interval = 45
				} else if numLeftFiles >= 25 && numLeftFiles < 50 {
					interval = 30
				} else if numLeftFiles >= 50 && numLeftFiles < 200 {
					interval = 15
				} else if numLeftFiles >= 200 && numLeftFiles < 1000 {
					interval = 8
				} else {
					interval = 3
				}

				// If the too-many request code 429 has been seen recently, slow it down and
				// keep the fastest at 10 second for upload interval
				if prevBackoff < 7200 {
					interval *= 2
					if interval < 10 {
						interval = 10
					}
				}

				// if there is more than 4 files left, and new interval calculated is longer than previous
				// interval, keep the previous one instead
				if numLeftFiles >= 5 && prevIntv != 0 && prevIntv < interval {
					interval = prevIntv
				}
				prevIntv = interval
				// give 20% of randomness
				intvBase := (interval * 80) / 100
				intvRan := (interval - intvBase) * 2
				if intvRan > 0 {
					loguploaderCtx.metrics.CurrUploadIntvSec = uint32(rand.Intn(intvRan) + intvBase)
				}
			}
			log.Tracef("loguploader Run: upload interval sec %d", loguploaderCtx.metrics.CurrUploadIntvSec)
			loguploaderCtx.scheduleTimer = time.NewTimer(1800 * time.Second)

		case <-uploadTimer.C:
			// Main upload
			origIter := iteration
			numDevFile := doFetchSend(&loguploaderCtx, types.NewlogUploadDevDir, &iteration)
			loguploaderCtx.metrics.DevMetrics.NumGzipFileInDir = uint32(numDevFile)

			// App upload
			numAppFile := doFetchSend(&loguploaderCtx, types.NewlogUploadAppDir, &iteration)
			loguploaderCtx.metrics.AppMetrics.NumGzipFileInDir = uint32(numAppFile)

			numLeftFiles = numDevFile + numAppFile
			uploadTimer = time.NewTimer(time.Duration(loguploaderCtx.metrics.CurrUploadIntvSec) * time.Second)
			log.Tracef("loguploader Run: time %v, timer fired, Dev/App files left in directories %d/%d",
				time.Now(), numDevFile, numAppFile)
			if iteration > origIter {
				metricsPub.Publish("global", loguploaderCtx.metrics)
			}

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func sendCtxInit(ps *pubsub.PubSub, ctx *loguploaderContext) {
	//get server name
	var bytes []byte
	var err error
	for len(bytes) == 0 {
		bytes, err = os.ReadFile(types.ServerFileName)
		if err != nil {
			log.Errorf("sendCtxInit: Failed to read ServerFileName(%s). Err: %s",
				types.ServerFileName, err)
			time.Sleep(10 * time.Second)
			ps.StillRunning(agentName, warningTime, errorTime)
		} else if len(bytes) == 0 {
			log.Warnf("Empty %s file - waiting for it",
				types.ServerFileName)
			time.Sleep(10 * time.Second)
			ps.StillRunning(agentName, warningTime, errorTime)
		}
	}
	// Preserve port
	ctx.serverNameAndPort = strings.TrimSpace(string(bytes))

	SendTimeoutSecs := ctx.globalConfig.GlobalValueInt(types.NetworkSendTimeout)
	DialTimeoutSecs := ctx.globalConfig.GlobalValueInt(types.NetworkDialTimeout)
	ctrlClient := controllerconn.NewClient(log, controllerconn.ClientOptions{
		DeviceNetworkStatus: deviceNetworkStatus,
		NetworkSendTimeout:  time.Duration(SendTimeoutSecs) * time.Second,
		NetworkDialTimeout:  time.Duration(DialTimeoutSecs) * time.Second,
		AgentMetrics:        ctx.agentMetrics,
		ResolverCacheFunc:   ctx.getCachedResolvedIPs,
		DevSerial:           hardware.GetProductSerial(log),
		DevSoftSerial:       hardware.GetSoftSerial(log),
		DevUUID:             ctx.devUUID,
		AgentName:           agentName,
	})

	ctx.ctrlClient = ctrlClient
	log.Functionf("sendCtxInit: Get Device Serial %s, Soft Serial %s", ctrlClient.DevSerial,
		ctrlClient.DevSoftSerial)

	// XXX need to redo this since the root certificates can change when DeviceNetworkStatus changes
	err = ctrlClient.UpdateTLSConfig(nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Functionf("sendCtxInit: Using UUID %s", ctx.devUUID)
}

func handleDNSCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleDNSImp(ctxArg, key, statusArg)
}

func handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDNSImp(ctxArg, key, statusArg)
}

func handleDNSImp(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*loguploaderContext)
	if key != "global" {
		log.Tracef("handleDNSModify: ignoring %s", key)
		return
	}
	log.Tracef("handleDNSModify for %s", key)
	if cmp.Equal(*deviceNetworkStatus, status) {
		log.Tracef("handleDNSModify no change")
		return
	}
	*deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.usableAddrCount = newAddrCount // inc both ipv4 and ipv6 of mgmt intfs

	// update proxy certs if configured
	if ctx.ctrlClient != nil && ctx.ctrlClient.UsingV2API() {
		ctx.ctrlClient.UpdateTLSProxyCerts()
	}
	log.Tracef("handleDNSModify done for %s; %d usable",
		key, newAddrCount)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {
	log.Tracef("handleDNSDelete for %s", key)
	ctx := ctxArg.(*loguploaderContext)

	if key != "global" {
		log.Tracef("handleDNSDelete: ignoring %s", key)
		return
	}
	*deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.usableAddrCount = newAddrCount
	log.Tracef("handleDNSDelete done for %s", key)
}

// periodically check if the log for current app metric-map url list
// is still valid. if we don't have this domain anymore, remove them.
// using subAppInstConfig deletion won't work since the entries of those
// app can still wait for upload on the device, the action of uploading
// to the url can happen after the app is deleted.
func checkAppLogMetrics(ctx *loguploaderContext) {
	var ai, rmlist []string

	// get current configured apps
	sub := ctx.subAppInstConfig
	items := sub.GetAll()
	for _, c := range items {
		config := c.(types.AppInstanceConfig)
		ai = append(ai, config.UUIDandVersion.UUID.String())
	}

	// get the url set in the log metric-map
	urlstats := ctx.agentMetrics.GetURLsWithSubstr(log, "apps/instanceid")
	log.Tracef("checkAppLogMetrics: app config len %d, log metrics url length %d", len(ai), len(urlstats))

	// get a removal set
	for _, stats := range urlstats {
		foundit := false
		for _, n := range ai {
			if strings.Contains(stats, n) {
				foundit = true
			}
		}
		if foundit {
			continue
		}
		if isInAppUUIDMap(stats) {
			continue
		}
		rmlist = append(rmlist, stats)
	}
	log.Tracef("checkAppLogMetrics: list of remove urls %v", rmlist)
	for _, url := range rmlist {
		ctx.agentMetrics.RemoveURLMetrics(log, url)
	}
}

func handleGlobalConfigCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleGlobalConfigImp(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImp(ctxArg, key, statusArg)
}

// Handles both create and modify events
func handleGlobalConfigImp(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*loguploaderContext)
	if key != "global" {
		log.Tracef("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Tracef("handleGlobalConfigModify for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.globalConfig = gcp
		enabled := gcp.GlobalValueBool(types.AllowLogFastupload)
		if enabled != ctx.enableFastUpload {
			// reset the schedule for next 30 minutes
			if ctx.scheduleTimer != nil {
				ctx.scheduleTimer.Stop()
			}
			ctx.scheduleTimer = time.NewTimer(1 * time.Second)
		}
		ctx.enableFastUpload = enabled
	}
	log.Tracef("handleGlobalConfigModify done for %s, fastupload enabled %v", key, ctx.enableFastUpload)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*loguploaderContext)
	if key != "global" {
		log.Tracef("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Tracef("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	ctx.globalConfig = types.DefaultConfigItemValueMap()
	log.Tracef("handleGlobalConfigDelete done for %s", key)
}

func handleZedAgentStatusCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusImpl(ctxArg interface{}, _ string, statusArg interface{}) {
	zedagentStatus := statusArg.(types.ZedAgentStatus)
	ctx := ctxArg.(*loguploaderContext)
	ctx.airgapMode = zedagentStatus.AirgapMode
}

func doFetchSend(ctx *loguploaderContext, zipDir string, iter *int) int {
	if _, err := os.Stat(zipDir); err != nil {
		log.Tracef("doFetchSend: can't stats %s", zipDir)
		return 0
	}
	files, err := os.ReadDir(zipDir)
	if err != nil {
		log.Fatal("doFetchSend: read dir failed", err)
	}

	numFiles := len(files)
	if numFiles == 0 {
		log.Tracef("doFetchSend: no gzip file found in %s", zipDir)
		return 0
	}

	var fileTime int
	var gotFileName string
	var numGzipfiles int
	var isApp bool
	if zipDir == types.NewlogUploadAppDir {
		isApp = true
		appGzipMap = make(map[string]bool)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		if !strings.HasSuffix(f.Name(), ".gz") {
			continue
		}
		timestamp, err := types.GetTimestampFromGzipName(f.Name())
		if err != nil {
			continue
		}
		fTime := int(timestamp.Unix() * 1000) // convert to milliseconds

		numGzipfiles++
		if fileTime == 0 || fileTime > fTime {
			fileTime = fTime
			gotFileName = f.Name()
		}
		if isApp {
			buildAppUUIDMap(f.Name())
		}
	}

	if fileTime > 0 && gotFileName != "" {
		gziplogfile := zipDir + "/" + gotFileName
		content, err := utils.ReadWithMaxSize(log, gziplogfile, errorGzipFileSize)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Errorf("doFetchSend: error reading file %s, removing: %s", gziplogfile, err)
				// remove broken file
				_ = os.Remove(gziplogfile)
			}
			return numFiles
		}
		if len(content) > warnGzipFileSize {
			logFunc := log.Warnf
			if ctx.airgapMode {
				logFunc = log.Functionf
			}
			logFunc("doFetchSend: log file size %d more than expected %d",
				len(content), warnGzipFileSize)
		}
		unavailable, err := sendToCloud(ctx, content, *iter, gotFileName, fileTime, isApp)
		if err != nil {
			if unavailable {
				contSentFailure++
				contSentSuccess = 0
			}
			// if resp code is 503, or continuously 3 times unavailable failed, start to set the 'FailedToSend' status
			// 'newlogd' gzip directory space management and random spaced out uploading schedule is
			// based on the 'FailedToSend' status
			if (contSentFailure >= 3) && !ctx.metrics.FailedToSend {
				ctx.metrics.FailSentStartTime = time.Now()
				ctx.metrics.FailedToSend = true
				log.Functionf("doFetchSend: fail. set fail to send time %v", ctx.metrics.FailSentStartTime.String())
				ctx.metricsPub.Publish("global", ctx.metrics)
			}
			logFunc := log.Errorf
			if ctx.airgapMode {
				logFunc = log.Functionf
			}
			logFunc("doFetchSend: %v got error sending http: %v",
				ctx.metrics.FailSentStartTime.String(), err)
		} else {
			if isApp {
				// keep the sent out app log files on device
				if _, err := os.Stat(gziplogfile); err == nil {
					moveToFile := keepSentDir + "/" + gotFileName
					if err := os.Rename(gziplogfile, moveToFile); err != nil {
						log.Errorf("doFetchSend: can not move gziplogfile, %v", err)
					}
				}
			} else {
				// remove the sent out dev log files, since there is a different mechanism to keep them handled by newlogd
				if _, err := os.Stat(gziplogfile); err == nil {
					if err := os.Remove(gziplogfile); err != nil {
						log.Errorf("doFetchSend: can not remove gziplogfile, %v", err)
					}
				}
			}

			contSentSuccess++
			contSentFailure = 0
			if contSentSuccess >= 3 && ctx.metrics.FailedToSend {
				log.Functionf("doFetchSend: Reset failedToSend, at %v, gzip file %s is sent out ok",
					time.Now().String(), gotFileName)
				ctx.metrics.FailedToSend = false
				ctx.metricsPub.Publish("global", ctx.metrics)
			}
			log.Tracef("doFetchSend: gzip file %s is sent out ok", gotFileName)
		}
		*iter++
		return numGzipfiles - 1
	}
	log.Tracef("doFetchSend: does not find gz log file")
	return 0
}

func buildAppUUIDMap(fName string) {
	var appUUID string
	if strings.HasPrefix(fName, types.AppPrefix) && strings.HasSuffix(fName, ".gz") {
		fStr1 := strings.TrimPrefix(fName, types.AppPrefix)
		fStr := strings.Split(fStr1, types.AppSuffix)
		if len(fStr) != 2 {
			err := fmt.Errorf("app split is not 2")
			log.Error(err)
			return
		}
		appUUID = fStr[0]
	}

	if len(appUUID) > 0 {
		if _, ok := appGzipMap[appUUID]; !ok {
			appGzipMap[appUUID] = true
		}
	}
}

func isInAppUUIDMap(urlStr string) bool {
	str1 := strings.Split(urlStr, "apps/instanceid/")
	if len(str1) < 2 {
		return false
	}
	str2 := strings.Split(str1[1], "/newlogs")
	if len(str2) < 2 {
		return false
	}
	uuid := str2[0]
	if _, ok := appGzipMap[uuid]; !ok {
		return false
	}
	return true
}

func sendToCloud(ctx *loguploaderContext, data []byte, iter int, fName string, fTime int, isApp bool) (bool, error) {
	size := int64(len(data))
	log.Tracef("sendToCloud: size %d, isApp %v, iter %d", size, isApp, iter)

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("sendToCloud malloc error:")
	}

	var logsURL, appLogURL string
	var sentFailed, serviceUnavailable bool
	if isApp {
		fStr1 := strings.TrimPrefix(fName, types.AppPrefix)
		fStr := strings.Split(fStr1, types.AppSuffix)
		if len(fStr) != 2 {
			err := fmt.Errorf("app split is not 2")
			log.Fatal(err)
		}
		appUUID := fStr[0]
		if ctx.ctrlClient.UsingV2API() {
			appLogURL = fmt.Sprintf("apps/instanceid/%s/newlogs", appUUID)
		} else {
			// XXX temp support for adam controller
			appLogURL = fmt.Sprintf("apps/instanceid/id/%s/newlogs", appUUID)
		}
		logsURL = controllerconn.URLPathString(ctx.serverNameAndPort, ctx.ctrlClient.UsingV2API(),
			ctx.devUUID, appLogURL)
	} else {
		logsURL = controllerconn.URLPathString(ctx.serverNameAndPort, ctx.ctrlClient.UsingV2API(),
			ctx.devUUID, "newlogs")
	}
	startTime := time.Now()

	ctxWork, cancel := ctx.ctrlClient.GetContextForAllIntfFunctions()
	defer cancel()
	// if resp statusOK, then sent success
	// otherwise have to retry the same file later:
	//  - if resp is nil, or it's 'StatusServiceUnavailable', mark as serviceUnavailabe
	//  - if resp is 4xx, the file maybe moved to 'failtosend' directory later
	rv, err := ctx.ctrlClient.SendOnAllIntf(ctxWork, logsURL, buf, controllerconn.RequestOptions{
		WithNetTracing: false,
		BailOnHTTPErr:  false,
		Iteration:      iter,
		SuppressLogs:   ctx.airgapMode,
	})
	if rv.HTTPResp != nil {
		if rv.HTTPResp.StatusCode == http.StatusOK ||
			rv.HTTPResp.StatusCode == http.StatusCreated {
			latency := time.Since(startTime).Nanoseconds() / int64(time.Millisecond)
			if ctx.metrics.Latency.MinUploadMsec == 0 || ctx.metrics.Latency.MinUploadMsec > uint32(latency) {
				ctx.metrics.Latency.MinUploadMsec = uint32(latency)
			}
			if uint32(latency) > ctx.metrics.Latency.MaxUploadMsec {
				ctx.metrics.Latency.MaxUploadMsec = uint32(latency)
			}
			totalLatency := int64(ctx.metrics.Latency.AvgUploadMsec) *
				int64(ctx.metrics.AppMetrics.NumGZipFilesSent+ctx.metrics.DevMetrics.NumGZipFilesSent)
			filetime := time.Unix(int64(fTime/1000), 0) // convert msec to unix sec
			// Note that contents does not have an AuthContainer
			// FIXME: documentation or code needs to change
			if isApp {
				ctx.metrics.AppMetrics.RecentUploadTimestamp = filetime
				ctx.metrics.AppMetrics.NumGZipFilesSent++
				ctx.metrics.AppMetrics.LastGZipFileSendTime = startTime
			} else {
				updateserverload(ctx, rv.RespContents)
				ctx.metrics.DevMetrics.RecentUploadTimestamp = filetime
				ctx.metrics.DevMetrics.NumGZipFilesSent++
				ctx.metrics.DevMetrics.LastGZipFileSendTime = startTime
			}
			ctx.metrics.Latency.AvgUploadMsec = uint32((totalLatency + latency) /
				int64(ctx.metrics.AppMetrics.NumGZipFilesSent+ctx.metrics.DevMetrics.NumGZipFilesSent))
			ctx.metrics.Latency.CurrUploadMsec = uint32(latency)

			ctx.metrics.TotalBytesUpload += uint64(size)
			log.Tracef("sendToCloud: sent ok, file time %v, latency %d, content %s",
				filetime, latency, string(rv.RespContents))
		} else {
			if rv.HTTPResp.StatusCode == http.StatusServiceUnavailable { // status code 503
				serviceUnavailable = true
			} else if isResp4xx(rv.HTTPResp.StatusCode) {
				// status code 429
				if rv.HTTPResp.StatusCode == http.StatusTooManyRequests {
					lastBackOff := ctx.metrics.LastTooManyReqTime
					ctx.metrics.LastTooManyReqTime = time.Now()
					ctx.metrics.NumTooManyRequest++
					backoffEnabled = true
					if ctx.backoffExprTimer != nil {
						ctx.backoffExprTimer.Stop()
					}
					ctx.backoffExprTimer = time.NewTimer(backoffTimeout * time.Second)

					// we could have received several 429 in a row due to the
					// cloud side may take some time for rate-limit behavior change in a short time
					// do not readjust too soon.
					// otherwise, double the upload interval up to a max
					if time.Since(lastBackOff)/time.Second > 300 {
						currentIntv := ctx.metrics.CurrUploadIntvSec * 2
						log.Tracef("sendToCloud: backoff num %d, uploadintv was %d sec",
							ctx.metrics.NumTooManyRequest, ctx.metrics.CurrUploadIntvSec)
						if currentIntv > backoffMaxUploadIntv {
							ctx.metrics.CurrUploadIntvSec = backoffMaxUploadIntv
						} else {
							ctx.metrics.CurrUploadIntvSec = currentIntv
						}
					}
				}
				handle4xxlogfile(ctx, fName, isApp)
			}
			sentFailed = true
			log.Tracef("sendToCloud: sent failed, content %s", string(rv.RespContents))
		}
	} else {
		serviceUnavailable = true
		sentFailed = true
		log.Tracef("sendToCloud: sent failed no resp, content %s", string(rv.RespContents))
	}
	if sentFailed {
		if isApp {
			ctx.metrics.AppMetrics.NumGZipFileRetry++
		} else {
			ctx.metrics.DevMetrics.NumGZipFileRetry++
		}
	}
	if err != nil {
		logFunc := log.Errorf
		if ctx.airgapMode {
			logFunc = log.Functionf
		}
		logFunc("sendToCloud: %d bytes, file %s failed: %v", size, fName, err)
		return serviceUnavailable, fmt.Errorf("sendToCloud: failed to send")
	}
	log.Tracef("sendToCloud: Sent %d bytes, file %s to %s", size, fName, logsURL)
	return serviceUnavailable, nil
}

func updateserverload(ctx *loguploaderContext, contents []byte) {
	size := len(contents)
	if size == 0 {
		return
	}
	var serverM logs.ServerMetrics
	contents = bytes.TrimRight(contents, "\n")
	err := json.Unmarshal(contents, &serverM)
	if err == nil {
		ctx.metrics.ServerStats.CurrCPULoadPCT = serverM.CpuPercentage
		ctx.metrics.ServerStats.CurrProcessMsec = serverM.LogProcessDelayMsec

		totalAvg := ctx.metrics.ServerStats.AvgProcessMsec * uint32(ctx.metrics.DevMetrics.NumGZipFilesSent)
		ctx.metrics.ServerStats.AvgProcessMsec = (totalAvg + ctx.metrics.ServerStats.CurrProcessMsec) /
			uint32(ctx.metrics.DevMetrics.NumGZipFilesSent+1)
		totalLoad := ctx.metrics.ServerStats.AvgCPULoadPCT * float32(ctx.metrics.DevMetrics.NumGZipFilesSent)
		ctx.metrics.ServerStats.AvgCPULoadPCT = (totalLoad + ctx.metrics.ServerStats.CurrCPULoadPCT) /
			float32(ctx.metrics.DevMetrics.NumGZipFilesSent+1)
	} else {
		log.Errorf("updateserverload: size %d, contents %s, data unmarshal error %v", size, string(contents), err)
	}
	log.Tracef("updateserverload: size %d, contents %s, pct %f, avg-pct %f, duration-msec %d",
		size, contents, ctx.metrics.ServerStats.CurrCPULoadPCT, ctx.metrics.ServerStats.AvgCPULoadPCT, ctx.metrics.ServerStats.CurrProcessMsec)
}

func isResp4xx(code int) bool {
	remainder := code - 400
	if remainder >= 0 && remainder <= 99 {
		return true
	}
	return false
}

// if we failed to send the same gzip file and get 4xx too many times, move it
// to the 'failedtosend' dir, so we don't get blocked forever, keep maximum of 100 there
func handle4xxlogfile(ctx *loguploaderContext, fName string, isApp bool) {
	var relocate bool
	ctx.metrics.Num4xxResponses++
	if isApp {
		if app4xxfile.logfileName == "" || app4xxfile.logfileName != fName {
			app4xxfile.logfileName = fName
			app4xxfile.failureCnt = 1
		} else if app4xxfile.failureCnt < max4xxRetries {
			app4xxfile.failureCnt++
		} else {
			app4xxfile.logfileName = ""
			app4xxfile.failureCnt = 0
			ctx.metrics.AppMetrics.NumGZipFileKeptLocal++
			relocate = true
		}
	} else {
		if dev4xxfile.logfileName == "" || dev4xxfile.logfileName != fName {
			dev4xxfile.logfileName = fName
			dev4xxfile.failureCnt = 1
		} else if dev4xxfile.failureCnt < max4xxRetries {
			dev4xxfile.failureCnt++
		} else {
			dev4xxfile.logfileName = ""
			dev4xxfile.failureCnt = 0
			ctx.metrics.DevMetrics.NumGZipFileKeptLocal++
			relocate = true
		}
	}

	if relocate {
		var srcFile, dstFile string

		if isApp {
			srcFile = types.NewlogUploadAppDir + "/" + fName
		} else {
			srcFile = types.NewlogUploadDevDir + "/" + fName
		}
		dstFile = failSendDir + "/" + fName

		files, err := os.ReadDir(failSendDir)
		if err != nil {
			log.Fatal("handle4xxlogfile: read dir ", err)
		}
		if len(files) >= max4xxdropFiles {
			for _, f := range files { // ordered by filename
				log.Functionf("handle4xxlogfile: remove 4xx gzip file %s", f.Name())
				os.Remove(failSendDir + "/" + f.Name())
				break
			}
		}

		log.Functionf("handle4xxlogfile: relocate src %s to dst %s", srcFile, dstFile)
		os.Rename(srcFile, dstFile)
	}
}

// Track the DeviceUUID
func handleOnboardStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleOnboardStatusImpl(ctxArg, key, statusArg)
}

func handleOnboardStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleOnboardStatusImpl(ctxArg, key, statusArg)
}

func handleOnboardStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.OnboardingStatus)
	ctx := ctxArg.(*loguploaderContext)

	ctx.devUUID = status.DeviceUUID
}
