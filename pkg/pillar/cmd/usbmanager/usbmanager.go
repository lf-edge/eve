// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package usbmanager

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "usbmanager"
	// Time limits for event loop handlers
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	stillRunningInterval = 25 * time.Second
)

var (
	logger *logrus.Logger
	log    *base.LogObject
)

type usbdevice struct {
	busnum                  uint16
	portnum                 string
	devnum                  uint16
	vendorID                uint32
	productID               uint32
	devicetype              string
	usbControllerPCIAddress string
	ueventFilePath          string
}

type usbmanagerContext struct {
	agentbase.AgentBase
	subscriptions  []pubsub.Subscription
	controller     usbmanagerController
	runningDomains map[string]struct{} // mapping DomainStatus.DomainName
}

func newUsbmanagerContext() *usbmanagerContext {
	usbCtx := &usbmanagerContext{}
	usbCtx.controller.init()

	usbCtx.runningDomains = make(map[string]struct{})

	return usbCtx
}

// Run - Main function - invoked from zedbox.go
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	usbCtx := newUsbmanagerContext()
	usbCtx.subscriptions = make([]pubsub.Subscription, 0)

	agentbase.Init(usbCtx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Wait until we have been onboarded aka know our own UUID, but we don't use the UUID
	err := utils.WaitForOnboarded(ps, log, agentName, warningTime, errorTime)
	if err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed onboarded")

	if err := utils.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed Vault Status")

	currentHypervisor := hypervisor.BootTimeHypervisor()
	_, ok := currentHypervisor.(hypervisor.KvmContext)
	if ok {
		usbCtx.subscribe(ps)
	} else {
		log.Warnf("usbmanager is disabled as hypervisor %s is used\n", currentHypervisor.Name())
	}

	usbCtx.process(ps)

	return 0
}
