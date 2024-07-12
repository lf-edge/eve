// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	verifier "github.com/lf-edge/eve/pkg/pillar/cmd/verifier/lib"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	"github.com/sirupsen/logrus"
)

// Any state used by handlers goes here

// VerifierContext is the context for the verifier agent
type VerifierContext struct {
	agentbase.AgentBase
	ps                   *pubsub.PubSub
	subVerifyImageConfig pubsub.Subscription
	pubVerifyImageStatus pubsub.Publication
	subGlobalConfig      pubsub.Subscription

	GCInitialized bool
	// cli options
	versionPtr *bool
	logger     *logrus.Logger
	log        *base.LogObject

	handlers map[string]chan<- Notify
}

// NewVerifierContext creates a new verifier context
func NewVerifierContext(ps *pubsub.PubSub, logger *logrus.Logger, log *base.LogObject) *VerifierContext {
	return &VerifierContext{
		ps:       ps,
		logger:   logger,
		log:      log,
		handlers: make(map[string]chan<- Notify),
	}
}

// Run runs the verifier agent
func (ctx *VerifierContext) Run(arguments []string, baseDir string) int {
	// Any state needed by handler functions
	agentbase.Init(ctx, ctx.logger, ctx.log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithArguments(arguments))

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(agentName, warningTime, errorTime)

	// Wait until we have been onboarded aka know our own UUID, but we don't use the UUID
	err := wait.WaitForOnboarded(ctx.ps, ctx.log, agentName, warningTime, errorTime)
	if err != nil {
		ctx.log.Fatal(err)
	}
	ctx.log.Functionf("processed onboarded")

	// Set up our publications before the subscriptions so ctx is set
	pubVerifyImageStatus, err := ctx.ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.VerifyImageStatus{},
		})
	if err != nil {
		ctx.log.Fatal(err)
	}
	ctx.pubVerifyImageStatus = pubVerifyImageStatus

	// Look for global config such as log levels
	subGlobalConfig, err := ctx.ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: ctx.handleGlobalConfigCreate,
		ModifyHandler: ctx.handleGlobalConfigModify,
		DeleteHandler: ctx.handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		ctx.log.Fatal(err)
	}
	ctx.subGlobalConfig = subGlobalConfig
	if err := subGlobalConfig.Activate(); err != nil {
		ctx.log.Fatal(err)
	}

	subVerifyImageConfig, err := ctx.ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VerifyImageConfig{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: ctx.create,
		ModifyHandler: ctx.modify,
		DeleteHandler: ctx.delete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		ctx.log.Fatal(err)
	}
	ctx.subVerifyImageConfig = subVerifyImageConfig
	if err := subVerifyImageConfig.Activate(); err != nil {
		ctx.log.Fatal(err)
	}

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		ctx.log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(agentName, warningTime, errorTime)
	}
	ctx.log.Functionf("processed GlobalConfig")

	if err := wait.WaitForVault(ctx.ps, ctx.log, agentName, warningTime, errorTime); err != nil {
		ctx.log.Fatal(err)
	}

	ctx.log.Functionf("processed vault status")

	// create the directories
	v, err = verifier.NewVerifier(basePath, ctx.log)
	if err != nil {
		ctx.log.Fatal(err)
	}

	// Publish status for any objects that were verified before reboot
	// It re-checks shas for existing images
	ctx.init()

	// Report to volumemgr that init is done
	if err := pubVerifyImageStatus.SignalRestarted(); err != nil {
		ctx.log.Fatal(err)
	}
	ctx.log.Functionf("SignalRestarted done")

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subVerifyImageConfig.MsgChan():
			subVerifyImageConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func (ctx *VerifierContext) init() {

	ctx.log.Functionln("handleInit")

	// Init reverification of the shas can take minutes for large objects
	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	defer stillRunning.Stop()
	waitForVerifiedObjectsChan := make(chan bool, 1)
	go func() {
		ctx.log.Notice("Waiting for initial objects to be verified")
		// Create VerifyImageStatus for objects that were verified before reboot
		handleInitVerifiedObjects(ctx)
		waitForVerifiedObjectsChan <- true
	}()
	objectsVerified := false
	for !objectsVerified {
		select {
		case <-waitForVerifiedObjectsChan:
			ctx.log.Notice("Initial objects verification done")
			objectsVerified = true
		case <-stillRunning.C:
			ctx.ps.StillRunning(agentName, warningTime, errorTime)
		}
	}

	ctx.log.Functionln("handleInit done")
}
