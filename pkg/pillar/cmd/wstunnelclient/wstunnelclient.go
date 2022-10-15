// Copyright (c) 2018,2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package wstunnelclient

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
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
	agentbase.AgentBase
	subGlobalConfig      pubsub.Subscription
	GCInitialized        bool
	subAppInstanceConfig pubsub.Subscription
	serverNameAndPort    string
	wstunnelclient       *zedcloud.WSTunnelClient
	dnsContext           *DNSContext
	devUUID              uuid.UUID
	// XXX add any output from scanAIConfigs()?

	// cli options
	versionPtr *bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctx *wstunnelclientContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctx.versionPtr = flagSet.Bool("v", false, "Version")
}

var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	wscCtx := wstunnelclientContext{}
	agentbase.Init(&wscCtx, logger, log, agentName,
		agentbase.WithArguments(arguments))

	if *wscCtx.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	DNSctx := DNSContext{
		deviceNetworkStatus: &types.DeviceNetworkStatus{},
	}

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &wscCtx,
		CreateHandler: handleGlobalConfigCreate,
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
		MyAgentName:   agentName,
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &DNSctx,
		CreateHandler: handleDNSCreate,
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
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceConfig{},
		Activate:      false,
		Ctx:           &wscCtx,
		CreateHandler: handleAppInstanceConfigCreate,
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

	// Wait until we have been onboarded aka know our own UUID
	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		MyAgentName:   agentName,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      true,
		Persistent:    true,
		Ctx:           &wscCtx,
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
	for wscCtx.devUUID == nilUUID {
		log.Functionf("Waiting for OnboardStatus UUID")
		select {
		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed onboarded")

	// Pick up debug aka log level before we start real work
	for !wscCtx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	wscCtx.dnsContext = &DNSctx
	// Wait for knowledge about IP addresses. XXX needed?
	for !DNSctx.DNSinitialized {
		log.Functionf("Waiting for DeviceNetworkStatus\n")
		select {
		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)
		}
	}

	for {
		select {
		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

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

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*wstunnelclientContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s\n", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s\n", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*wstunnelclientContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s\n", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s\n", key)
}

func handleDNSCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Functionf("handleDNSImpl: ignoring %s\n", key)
		return
	}
	log.Functionf("handleDNSImpl for %s\n", key)
	// Ignore test status and timestamps
	if ctx.deviceNetworkStatus.MostlyEqual(status) {
		log.Functionf("handleDNSImpl no change\n")
		ctx.DNSinitialized = true
		return
	}
	log.Functionf("handleDNSImpl: changed %v",
		cmp.Diff(*ctx.deviceNetworkStatus, status))
	*ctx.deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)
	if newAddrCount != 0 && ctx.usableAddressCount == 0 {
		log.Functionf("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.usableAddressCount, newAddrCount)
		// XXX do we need to trigger something like a reconnect?
	}
	ctx.DNSinitialized = true
	ctx.usableAddressCount = newAddrCount
	log.Functionf("handleDNSImpl done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Functionf("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)
	ctx.DNSinitialized = false
	ctx.usableAddressCount = newAddrCount
	log.Functionf("handleDNSDelete done for %s\n", key)
}

func handleAppInstanceConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppInstanceConfigImpl(ctxArg, key, statusArg)
}

func handleAppInstanceConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppInstanceConfigImpl(ctxArg, key, statusArg)
}

func handleAppInstanceConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleAppInstanceConfigImpl for %s\n", key)
	// XXX config := configArg.(types.AppInstanceConfig)
	ctx := ctxArg.(*wstunnelclientContext)
	scanAIConfigs(ctx)
	log.Functionf("handleAppInstanceConfigImpl done for %s\n", key)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleAppInstanceConfigDelete for %s\n", key)
	// XXX config := configArg).(types.AppInstanceConfig)
	ctx := ctxArg.(*wstunnelclientContext)
	scanAIConfigs(ctx)
	log.Functionf("handleAppInstanceConfigDelete done for %s\n", key)
}

// walk over all instances to determine new value
func scanAIConfigs(ctx *wstunnelclientContext) {

	isTunnelRequired := false
	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	for _, c := range items {
		config := c.(types.AppInstanceConfig)
		log.Tracef("Remote console status for app-instance: %s: %t\n",
			config.DisplayName, config.RemoteConsole)
		isTunnelRequired = config.RemoteConsole || isTunnelRequired
	}
	log.Functionf("Tunnel check status after checking app-instance configs: %t\n",
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
			log.Tracef("Skipping connection using non-mangement intf %s\n",
				ifname)
			continue
		}
		wstunnelclient := zedcloud.InitializeTunnelClient(log, ctx.serverNameAndPort, "localhost:4822")
		destURL := wstunnelclient.Tunnel

		addrCount, err := types.CountLocalAddrAnyNoLinkLocalIf(*deviceNetworkStatus,
			ifname)
		if err != nil {
			log.Errorf("CountLocalIPv4AddrAnyNoLinkLocalIf failed for %s: %v",
				ifname, err)
			continue
		}

		log.Functionf("Connecting to %s using intf %s #sources %d\n",
			destURL, ifname, addrCount)

		if addrCount == 0 {
			errStr := fmt.Sprintf("No IP addresses to connect to %s using intf %s",
				destURL, ifname)
			log.Functionln(errStr)
			continue
		}

		var connected bool
		for retryCount := 0; retryCount < addrCount; retryCount++ {
			localAddr, err := types.GetLocalAddrAnyNoLinkLocal(*deviceNetworkStatus,
				retryCount, ifname)
			if err != nil {
				log.Function(err)
				continue
			}

			proxyURL, _ := zedcloud.LookupProxy(log, deviceNetworkStatus,
				ifname, destURL)
			if err := wstunnelclient.TestConnection(deviceNetworkStatus, proxyURL, localAddr, ctx.devUUID); err != nil {
				log.Function(err)
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
		log.Functionf("Could not connect to %s using intf %s\n", destURL, ifname)
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
	ctx := ctxArg.(*wstunnelclientContext)
	ctx.devUUID = status.DeviceUUID
}
