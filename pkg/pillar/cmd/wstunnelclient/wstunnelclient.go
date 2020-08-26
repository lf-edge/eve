// Copyright (c) 2018,2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package wstunnelclient

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"os"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "wstunnelclient"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Set from Makefile
var Version = "No version specified"

// Context for handleDNSModify
type DNSContext struct {
	usableAddressCount     int
	DNSinitialized         bool // Received initial DeviceNetworkStatus
	subDeviceNetworkStatus pubsub.Subscription
	deviceNetworkStatus    *types.DeviceNetworkStatus
}

type wstunnelclientContext struct {
	subGlobalConfig      pubsub.Subscription
	GCInitialized        bool
	subAppInstanceConfig pubsub.Subscription
	serverNameAndPort    string
	wstunnelclient       *zedcloud.WSTunnelClient
	dnsContext           *DNSContext
	devUUID              uuid.UUID
	// XXX add any output from scanAIConfigs()?
}

var debug = false
var debugOverride bool // From command line arg
var log *base.LogObject

func Run(ps *pubsub.PubSub) int {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return 0
	}
	// XXX Make logrus record a noticable global source
	agentlog.Init("xyzzy-" + agentName)

	log = agentlog.Init(agentName)
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}

	log.Infof("Starting %s\n", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	DNSctx := DNSContext{
		deviceNetworkStatus: &types.DeviceNetworkStatus{},
	}

	wscCtx := wstunnelclientContext{}

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           &wscCtx,
		CreateHandler: handleGlobalConfigModify,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	wscCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

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

	// Look for AppInstanceConfig from zedagent
	// XXX is it better to look for AppInstanceStatus from zedmanager?
	subAppInstanceConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		TopicImpl:     types.AppInstanceConfig{},
		Activate:      false,
		Ctx:           &wscCtx,
		CreateHandler: handleAppInstanceConfigModify,
		ModifyHandler: handleAppInstanceConfigModify,
		DeleteHandler: handleAppInstanceConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	wscCtx.subAppInstanceConfig = subAppInstanceConfig

	//get server name
	bytes, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
	}
	wscCtx.serverNameAndPort = strings.TrimSpace(string(bytes))

	subAppInstanceConfig.Activate()

	if zedcloud.UseV2API() {
		b, err := ioutil.ReadFile(types.UUIDFileName)
		if err != nil {
			log.Fatal(err)
		}
		uuidStr := strings.TrimSpace(string(b))
		wscCtx.devUUID, err = uuid.FromString(uuidStr)
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("Read devUUID %s\n", wscCtx.devUUID.String())
	}

	// Pick up debug aka log level before we start real work
	for !wscCtx.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

	wscCtx.dnsContext = &DNSctx
	// Wait for knowledge about IP addresses. XXX needed?
	for !DNSctx.DNSinitialized {
		log.Infof("Waiting for DeviceNetworkStatus\n")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)
		}
	}

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAppInstanceConfig.MsgChan():
			subAppInstanceConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*wstunnelclientContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*wstunnelclientContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
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
	// Ignore test status and timestamps
	if ctx.deviceNetworkStatus.Equal(status) {
		log.Infof("handleDNSModify no change\n")
		ctx.DNSinitialized = true
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(*ctx.deviceNetworkStatus, status))
	*ctx.deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)
	if newAddrCount != 0 && ctx.usableAddressCount == 0 {
		log.Infof("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.usableAddressCount, newAddrCount)
		// XXX do we need to trigger something like a reconnect?
	}
	ctx.DNSinitialized = true
	ctx.usableAddressCount = newAddrCount
	log.Infof("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)
	ctx.DNSinitialized = false
	ctx.usableAddressCount = newAddrCount
	log.Infof("handleDNSDelete done for %s\n", key)
}

// Handles both create and modify events
func handleAppInstanceConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleAppInstanceConfigModify for %s\n", key)
	// XXX config := configArg.(types.AppInstanceConfig)
	ctx := ctxArg.(*wstunnelclientContext)
	scanAIConfigs(ctx)
	log.Infof("handleAppInstanceConfigModify done for %s\n", key)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleAppInstanceConfigDelete for %s\n", key)
	// XXX config := configArg).(types.AppInstanceConfig)
	ctx := ctxArg.(*wstunnelclientContext)
	scanAIConfigs(ctx)
	log.Infof("handleAppInstanceConfigDelete done for %s\n", key)
}

// walk over all instances to determine new value
func scanAIConfigs(ctx *wstunnelclientContext) {

	isTunnelRequired := false
	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	for _, c := range items {
		config := c.(types.AppInstanceConfig)
		log.Debugf("Remote console status for app-instance: %s: %t\n",
			config.DisplayName, config.RemoteConsole)
		isTunnelRequired = config.RemoteConsole || isTunnelRequired
	}
	log.Infof("Tunnel check status after checking app-instance configs: %t\n",
		isTunnelRequired)

	if !isTunnelRequired {
		if ctx.wstunnelclient != nil {
			ctx.wstunnelclient.Stop()
			ctx.wstunnelclient = nil
		}
		return
	}
	if ctx.wstunnelclient != nil {
		return
	}
	deviceNetworkStatus := ctx.dnsContext.deviceNetworkStatus
	for _, port := range deviceNetworkStatus.Ports {
		ifname := port.IfName
		if !types.IsMgmtPort(*deviceNetworkStatus, ifname) {
			log.Debugf("Skipping connection using non-mangement intf %s\n",
				ifname)
			continue
		}
		wstunnelclient := zedcloud.InitializeTunnelClient(log, ctx.serverNameAndPort, "localhost:4822")
		destURL := wstunnelclient.Tunnel

		addrCount := types.CountLocalAddrAnyNoLinkLocalIf(*deviceNetworkStatus, ifname)
		log.Infof("Connecting to %s using intf %s #sources %d\n",
			destURL, ifname, addrCount)

		if addrCount == 0 {
			errStr := fmt.Sprintf("No IP addresses to connect to %s using intf %s",
				destURL, ifname)
			log.Infoln(errStr)
			continue
		}

		var connected bool
		for retryCount := 0; retryCount < addrCount; retryCount++ {
			localAddr, err := types.GetLocalAddrAnyNoLinkLocal(*deviceNetworkStatus,
				retryCount, ifname)
			if err != nil {
				log.Info(err)
				continue
			}

			proxyURL, _ := zedcloud.LookupProxy(log, deviceNetworkStatus,
				ifname, destURL)
			if err := wstunnelclient.TestConnection(deviceNetworkStatus, proxyURL, localAddr, ctx.devUUID); err != nil {
				log.Info(err)
				continue
			}
			connected = true
			break
		}
		if connected == true {
			wstunnelclient.Start()
			ctx.wstunnelclient = wstunnelclient
			break
		}
		log.Infof("Could not connect to %s using intf %s\n", destURL, ifname)
	}
}
