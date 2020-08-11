// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package newlogmgr

import (
	"flag"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"strings"
	"time"
)

const (
	agentName = "newlogmgr"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	newlogDir    = "/persist/newlog"
	collectDir   = newlogDir + "/collect"
	uploadDevDir = newlogDir + "/devUpload"
	uploadAppDir = newlogDir + "/appUpload"
	devPrefix    = "dev."
	appPrefix    = "app."
	metaInfoName = "log_meta_info"

	maxLogFileSize         int32 = 420000            // maxinum collect file size in bytes
	maxGzipFileSize        int32 = 46000             // maxinum gzipped file size for upload in bytes
	logfileDelay                 = 300 * time.Second // maxinum delay 5 minutes for log file collection
	metricsPublishInterval       = 300 * time.Second
	cloudMetricInterval          = 10 * time.Second
	stillRunningInerval          = 25 * time.Second
	defaultSyncCount             = 15 // default log events flush/sync to disk file
)

var (
	devUUID             uuid.UUID
	deviceNetworkStatus = &types.DeviceNetworkStatus{}
	zedcloudCtx         zedcloud.ZedCloudContext
	nilUUID             uuid.UUID
	debug               bool
	debugOverride       bool
	restart             bool
	syncToFileCnt       int // every 'N' log event count flush to log file
	//appMap          map[string]statsLogFile
	uploadIntv time.Duration = 120
	newlogsURL string
	domainUUID map[string]appDomain // App log, from domain-id to app-UUID and app-Name
)

type newlogmgrContext struct {
	globalConfig           *types.ConfigItemValueMap
	zedcloudCtx            *zedcloud.ZedCloudContext
	subDeviceNetworkStatus pubsub.Subscription
	subGlobalConfig        pubsub.Subscription
	usableAddrCount        int
	GCInitialized          bool
	metrics                types.NewlogMetrics
	serverNameAndPort      string
}

// for app Domain-ID mapping into UUID and DisplayName
type appDomain struct {
	appUUID string
	appName string
}

// Run - an newlogmgr run
func Run(ps *pubsub.PubSub) {
	debugPtr := flag.Bool("d", false, "Debug flag")
	restartPtr := flag.Bool("r", false, "Restart flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	// restart is the newlogmgr launched from the 'monitor-newlogmgr'
	// the flag can be used for example to change 'N' count for flush/sync to logfile
	restart = *restartPtr
	if restart {
		log.Infof("Run: is restart")
		syncToFileCnt = 1
	} else {
		syncToFileCnt = defaultSyncCount
	}

	agentlog.Init(agentName)

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningInerval)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	newlogmgrCtx := newlogmgrContext{
		globalConfig: types.DefaultConfigItemValueMap(),
	}

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &newlogmgrCtx,
		CreateHandler: handleDNSModify,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	newlogmgrCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	domainUUID = make(map[string]appDomain)
	// Get DomainStatus from domainmgr
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		TopicImpl:     types.DomainStatus{},
		Activate:      false,
		Ctx:           &newlogmgrCtx,
		CreateHandler: handleDomainStatusModify,
		ModifyHandler: handleDomainStatusModify,
		DeleteHandler: handleDomainStatusDelete,
	})
	if err != nil {
		log.Fatal(err)
	}
	subDomainStatus.Activate()

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           &newlogmgrCtx,
		CreateHandler: handleGlobalConfigModify,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	newlogmgrCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		CreateHandler: handleOnboardStatusModify,
		ModifyHandler: handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      true,
		Persistent:    true,
		Ctx:           &newlogmgrCtx,
	})
	if err != nil {
		log.Fatal(err)
	}

	sendCtxInit(&newlogmgrCtx)

	// XXX launch collect-log/transfer-gzip newlogmgr goroutines here
	// which don't need network connection

	for newlogmgrCtx.usableAddrCount == 0 {
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
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("Have %d management ports with usable addresses", newlogmgrCtx.usableAddrCount)

	// Publish cloud metrics
	cms := zedcloud.GetCloudMetrics() // Need type of data
	pub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: cms,
		})
	if err != nil {
		log.Fatal(err)
	}

	interval := time.Duration(cloudMetricInterval) // every 10 sec
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	// Publish newlog metrics
	metricsPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.NewlogMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}

	// newlog Metrics publish timer. Publish log metrics every 5 minutes.
	interval = time.Duration(metricsPublishInterval)
	max = float64(interval)
	min = max * 0.3
	metricsPublishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	for {
		select {
		case change := <-subDomainStatus.MsgChan():
			subDomainStatus.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case <-publishTimer.C:
			start := time.Now()
			log.Debugf("publishTimer cloud metrics at at %s", time.Now().String())
			err := pub.Publish("global", zedcloud.GetCloudMetrics())
			if err != nil {
				log.Errorln(err)
			}
			pubsub.CheckMaxTimeTopic(agentName, "publishTimer", start, warningTime, errorTime)

		case <-metricsPublishTimer.C:
			metricsPub.Publish("global", newlogmgrCtx.metrics)
			log.Debugf("Published newlog metrics at %s", time.Now().String())

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

func sendCtxInit(ctx *newlogmgrContext) {
	//get server name
	bytes, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatalf("sendCtxInit: Failed to read ServerFileName(%s). Err: %s",
			types.ServerFileName, err)
	}
	// Preserve port
	ctx.serverNameAndPort = strings.TrimSpace(string(bytes))
	serverName := strings.Split(ctx.serverNameAndPort, ":")[0]

	//set newlog url
	zedcloudCtx = zedcloud.NewContext(zedcloud.ContextOptions{
		DevNetworkStatus: deviceNetworkStatus,
		Timeout:          ctx.globalConfig.GlobalValueInt(types.NetworkSendTimeout),
		NeedStatsFunc:    true,
		Serial:           hardware.GetProductSerial(),
		SoftSerial:       hardware.GetSoftSerial(),
		AgentName:        agentName,
	})
	log.Infof("sendCtxInit: Use V2 API %v", zedcloud.UseV2API())

	ctx.zedcloudCtx = &zedcloudCtx
	log.Infof("newLog Get Device Serial %s, Soft Serial %s", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial)

	// XXX need to redo this since the root certificates can change when DeviceNetworkStatus changes
	err = zedcloud.UpdateTLSConfig(&zedcloudCtx, serverName, nil)
	if err != nil {
		log.Fatal(err)
	}

	// if there exists the uuid file, read it and move on
	b, err := ioutil.ReadFile(types.UUIDFileName)
	if err == nil {
		uuidStr := strings.TrimSpace(string(b))
		devUUID, err = uuid.FromString(uuidStr)
		if err != nil {
			log.Errorf("sendCtxInit: can't format UUID string %s", err)
		}
	}

	newlogsURL = zedcloud.URLPathString(ctx.serverNameAndPort, zedcloudCtx.V2API, devUUID, "newlogs")
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*newlogmgrContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s", key)
		return
	}
	log.Infof("handleDNSModify for %s", key)
	if cmp.Equal(*deviceNetworkStatus, status) {
		log.Infof("handleDNSModify no change")
		return
	}
	*deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.usableAddrCount = newAddrCount // inc both ipv4 and ipv6 of mgmt intfs

	// update proxy certs if configured
	if ctx.zedcloudCtx != nil && ctx.zedcloudCtx.V2API {
		zedcloud.UpdateTLSProxyCerts(ctx.zedcloudCtx)
	}
	log.Infof("handleDNSModify done for %s; %d usable",
		key, newAddrCount)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	log.Infof("handleDNSDelete for %s", key)
	ctx := ctxArg.(*newlogmgrContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s", key)
		return
	}
	*deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.usableAddrCount = newAddrCount
	log.Infof("handleDNSDelete done for %s", key)
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

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*newlogmgrContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil && !ctx.GCInitialized {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*newlogmgrContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	ctx.globalConfig = types.DefaultConfigItemValueMap()
	log.Infof("handleGlobalConfigDelete done for %s", key)
}

// Handles UUID change from process client
func handleOnboardStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.OnboardingStatus)
	ctx := ctxArg.(*newlogmgrContext)
	if cmp.Equal(devUUID, status.DeviceUUID) {
		log.Infof("handleOnboardStatusModify no change to %v", devUUID)
		return
	}
	devUUID = status.DeviceUUID
	log.Infof("handleOnboardStatusModify changed to %v", devUUID)

	newlogsURL = zedcloud.URLPathString(ctx.serverNameAndPort, zedcloudCtx.V2API, devUUID, "newlogs")
}
