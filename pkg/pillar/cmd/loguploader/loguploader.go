// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package loguploader

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
	agentName = "loguploader"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	metricsPublishInterval = 300 * time.Second
	cloudMetricInterval    = 10 * time.Second
	stillRunningInerval    = 25 * time.Second
)

var (
	devUUID             uuid.UUID
	deviceNetworkStatus = &types.DeviceNetworkStatus{}
	zedcloudCtx         zedcloud.ZedCloudContext
	nilUUID             uuid.UUID
	debug               bool
	debugOverride       bool
	uploadIntv          time.Duration = 120
	newlogsURL          string
)

type loguploaderContext struct {
	globalConfig           *types.ConfigItemValueMap
	zedcloudCtx            *zedcloud.ZedCloudContext
	subDeviceNetworkStatus pubsub.Subscription
	subGlobalConfig        pubsub.Subscription
	usableAddrCount        int
	GCInitialized          bool
	metrics                types.NewlogMetrics
	serverNameAndPort      string
}

// Run - an loguploader run
func Run(ps *pubsub.PubSub) {
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	agentlog.Init(agentName)

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningInerval)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	loguploaderCtx := loguploaderContext{
		globalConfig: types.DefaultConfigItemValueMap(),
	}

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &loguploaderCtx,
		CreateHandler: handleDNSModify,
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
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           &loguploaderCtx,
		CreateHandler: handleGlobalConfigModify,
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

	sendCtxInit(&loguploaderCtx)

	for loguploaderCtx.usableAddrCount == 0 {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		// This wait can take an unbounded time since we wait for IP
		// addresses. Punch StillRunning
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("Have %d management ports with usable addresses", loguploaderCtx.usableAddrCount)

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
		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-publishTimer.C:
			start := time.Now()
			log.Debugf("publishTimer cloud metrics at at %s", time.Now().String())
			err := pub.Publish("global", zedcloud.GetCloudMetrics())
			if err != nil {
				log.Errorln(err)
			}
			pubsub.CheckMaxTimeTopic(agentName, "publishTimer", start, warningTime, errorTime)

		case <-metricsPublishTimer.C:
			metricsPub.Publish("global", loguploaderCtx.metrics)
			log.Debugf("Published newlog upload metrics at %s", time.Now().String())

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

func sendCtxInit(ctx *loguploaderContext) {
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
	// wait for uuid of logs V2 URL string
	newlogsURL = zedcloud.URLPathString(ctx.serverNameAndPort, zedcloudCtx.V2API, devUUID, "newlogs")
	log.Infof("Read UUID %s", devUUID)
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*loguploaderContext)
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
	ctx := ctxArg.(*loguploaderContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s", key)
		return
	}
	*deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.usableAddrCount = newAddrCount
	log.Infof("handleDNSDelete done for %s", key)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*loguploaderContext)
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

	ctx := ctxArg.(*loguploaderContext)
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
