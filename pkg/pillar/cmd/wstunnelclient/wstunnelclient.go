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
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	log "github.com/sirupsen/logrus"
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
	subDeviceNetworkStatus *pubsub.Subscription
	deviceNetworkStatus    *types.DeviceNetworkStatus
}

type wstunnelclientContext struct {
	subGlobalConfig      *pubsub.Subscription
	subAppInstanceConfig *pubsub.Subscription
	serverNameAndPort    string
	wstunnelclient       *zedcloud.WSTunnelClient
	dnsContext           *DNSContext
	// XXX add any output from scanAIConfigs()?
}

var debug = false
var debugOverride bool // From command line arg

func Run() {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	curpartPtr := flag.String("c", "", "Current partition")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	curpart := *curpartPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	logf, err := agentlog.Init(agentName, curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}

	log.Infof("Starting %s\n", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName)

	DNSctx := DNSContext{
		deviceNetworkStatus: &types.DeviceNetworkStatus{},
	}

	wscCtx := wstunnelclientContext{}

	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &wscCtx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.MaxProcessTimeWarn = warningTime
	subGlobalConfig.MaxProcessTimeError = errorTime
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.CreateHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	wscCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &DNSctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.MaxProcessTimeWarn = warningTime
	subDeviceNetworkStatus.MaxProcessTimeError = errorTime
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.CreateHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	DNSctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Look for AppInstanceConfig from zedagent
	// XXX is it better to look for AppInstanceStatus from zedmanager?
	subAppInstanceConfig, err := pubsub.Subscribe("zedagent",
		types.AppInstanceConfig{}, false, &wscCtx)
	if err != nil {
		log.Fatal(err)
	}
	subAppInstanceConfig.MaxProcessTimeWarn = warningTime
	subAppInstanceConfig.MaxProcessTimeError = errorTime
	subAppInstanceConfig.ModifyHandler = handleAppInstanceConfigModify
	subAppInstanceConfig.CreateHandler = handleAppInstanceConfigModify
	subAppInstanceConfig.DeleteHandler = handleAppInstanceConfigDelete
	wscCtx.subAppInstanceConfig = subAppInstanceConfig

	//get server name
	bytes, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
	}
	wscCtx.serverNameAndPort = strings.TrimSpace(string(bytes))

	subAppInstanceConfig.Activate()

	wscCtx.dnsContext = &DNSctx
	// Wait for knowledge about IP addresses. XXX needed?
	for !DNSctx.DNSinitialized {
		log.Infof("Waiting for DomainNetworkStatus\n")
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
		}
	}

	for {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAppInstanceConfig.C:
			subAppInstanceConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName)
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
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
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
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

// Handles both create and modify events
func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(*ctx.deviceNetworkStatus, status) {
		log.Infof("handleDNSModify no change\n")
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
	// XXX config := cast.CastAppInstanceConfig(configArg)
	ctx := ctxArg.(*wstunnelclientContext)
	scanAIConfigs(ctx)
	log.Infof("handleAppInstanceConfigModify done for %s\n", key)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleAppInstanceConfigDelete for %s\n", key)
	// XXX config := cast.CastAppInstanceConfig(configArg)]
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
		config := cast.CastAppInstanceConfig(c)
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
		wstunnelclient := zedcloud.InitializeTunnelClient(ctx.serverNameAndPort, "localhost:4822")
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

			proxyURL, _ := zedcloud.LookupProxy(deviceNetworkStatus,
				ifname, destURL)
			if err := wstunnelclient.TestConnection(proxyURL, localAddr); err != nil {
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
