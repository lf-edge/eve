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
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
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
	agentbase.AgentBase
	deviceNetworkStatus    types.DeviceNetworkStatus
	usableAddressCount     int
	DNSinitialized         bool // Received DeviceNetworkStatus
	subDeviceNetworkStatus pubsub.Subscription
	// cli options
	versionPtr *bool
	noPidPtr   *bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctx *DNSContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctx.versionPtr = flagSet.Bool("v", false, "Version")
	ctx.noPidPtr = flagSet.Bool("p", false, "Do not check for running agent")
}

var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	DNSctx := DNSContext{}
	args := []agentbase.AgentOpt{agentbase.WithArguments(arguments), agentbase.WithBaseDir(baseDir)}
	if !*DNSctx.noPidPtr {
		args = append(args, agentbase.WithPidFile())
	}
	agentbase.Init(&DNSctx, logger, log, agentName, args...)

	if *DNSctx.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

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
