// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Wait for having IP addresses for a few minutes
// so that we are likely to have an address when we run ntp

package waitforaddr

import (
	"flag"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "waitforaddr"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Set from Makefile
var Version = "No version specified"

// Context for handleDNSModify
type DNSContext struct {
	deviceNetworkStatus    types.DeviceNetworkStatus
	usableAddressCount     int
	DNSinitialized         bool // Received DeviceNetworkStatus
	subDeviceNetworkStatus pubsub.Subscription
}

var debug = false
var debugOverride bool // From command line arg
var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg
	flagSet := flag.NewFlagSet(agentName, flag.ExitOnError)
	versionPtr := flagSet.Bool("v", false, "Version")
	debugPtr := flagSet.Bool("d", false, "Debug flag")
	noPidPtr := flagSet.Bool("p", false, "Do not check for running agent")
	if err := flagSet.Parse(arguments); err != nil {
		log.Fatal(err)
	}
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	noPidFlag := *noPidPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}
	if !noPidFlag {
		if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
			log.Fatal(err)
		}
	}
	log.Functionf("Starting %s\n", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	DNSctx := DNSContext{}

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

	// Wait until we have an address or 5 minutes, whichever comes first
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()

	done := false
	for DNSctx.usableAddressCount == 0 && !done {
		log.Functionf("Waiting for usable address(es)\n")
		select {
		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case <-timer.C:
			log.Functionln("Exit since we got timeout")
			done = true

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	return 0
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
		cmp.Diff(ctx.deviceNetworkStatus, status))
	ctx.deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus)
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
	ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus)
	ctx.DNSinitialized = false
	ctx.usableAddressCount = newAddrCount
	log.Functionf("handleDNSDelete done for %s\n", key)
}
