// Copyright (c) 2018,2019 Zededa, Inc.
// All rights reserved.

package wstunnelclient

import (
	"flag"
	"fmt"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	// XXX "github.com/zededa/go-provision/zedcloud"
	"os"
	"time"
)

const (
	agentName = "wstunnelclient"
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
	// XXX add any output from scanAIConfigs()?
}

var debug = false
var debugOverride bool // From command line arg

func Run() {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	logf, err := agentlog.Init(agentName)
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
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	wscCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &DNSctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
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
	subAppInstanceConfig.ModifyHandler = handleAppInstanceConfigModify
	subAppInstanceConfig.DeleteHandler = handleAppInstanceConfigDelete
	wscCtx.subAppInstanceConfig = subAppInstanceConfig
	subAppInstanceConfig.Activate()

	// Wait for knowledge about IP addresses. XXX needed?
	for !DNSctx.DNSinitialized {
		log.Infof("Waiting for DomainNetworkStatus\n")
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
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
			agentlog.StillRunning(agentName)
		}
	}
}

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

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*DNSContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(*ctx.deviceNetworkStatus, status) {
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

func handleAppInstanceConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX config := cast.CastAppInstanceConfig(configArg)
	ctx := ctxArg.(*wstunnelclientContext)
	scanAIConfigs(ctx)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX config := cast.CastAppInstanceConfig(configArg)]
	ctx := ctxArg.(*wstunnelclientContext)
	scanAIConfigs(ctx)
}

// walk over all instances to determine new value
func scanAIConfigs(ctx *wstunnelclientContext) {

	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	for key, c := range items {
		config := cast.CastAppInstanceConfig(c)
		// XXX insert checks; remove log
		log.Infof("Found AppInstanceConfig for %s, %s\n",
			key, config.Key())
	}
}
