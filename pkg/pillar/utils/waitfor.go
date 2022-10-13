// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"time"

	info "github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
)

//Context is a helper struct used to pass around in pubsub handlers
type Context struct {
	Initialized bool
}

// WaitForVault waits until it receives a types.VaultStatus msg, for types.DefaultVaultName
// and the status does not indicate any error
func WaitForVault(ps *pubsub.PubSub, log *base.LogObject, agentName string, warningTime, errorTime time.Duration) error {
	// Look for vault status
	Ctx := &Context{}
	subVaultStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "vaultmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VaultStatus{},
		Activate:      false,
		Ctx:           Ctx,
		CreateHandler: handleVaultStatusCreate,
		ModifyHandler: handleVaultStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	subVaultStatus.Activate()

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait for vault to be ready, which might be delayed due to attestation
	for !Ctx.Initialized {
		log.Functionf("Waiting for VaultStatus initialized")
		select {
		case change := <-subVaultStatus.MsgChan():
			subVaultStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	subVaultStatus.Close()
	stillRunning.Stop()
	return nil
}

func handleVaultStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVaultStatusImpl(ctxArg, key, statusArg)
}

func handleVaultStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleVaultStatusImpl(ctxArg, key, statusArg)
}

func handleVaultStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*Context)
	vault := statusArg.(types.VaultStatus)
	if vault.Name == types.DefaultVaultName && vault.ConversionComplete &&
		vault.Status != info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR {
		ctx.Initialized = true
	}
}

// WaitForOnboarded waits until it receives a types.OnboardingStatus msg with
// a non-zero UUID
func WaitForOnboarded(ps *pubsub.PubSub, log *base.LogObject, agentName string, warningTime, errorTime time.Duration) error {
	// Look for vault status
	Ctx := &Context{}
	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		MyAgentName:   agentName,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      true,
		Persistent:    true,
		Ctx:           Ctx,
		CreateHandler: handleOnboardStatusCreate,
		ModifyHandler: handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait for Onboarding to be done by client
	for !Ctx.Initialized {
		log.Functionf("Waiting for OnboardStatus initialized")
		select {
		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	stillRunning.Stop()
	subOnboardStatus.Close()
	return nil
}

// Really a constant
var nilUUID = uuid.UUID{}

// Set Initialized if the UUID is not nil
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
	ctx := ctxArg.(*Context)

	if status.DeviceUUID == nilUUID {
		return
	}
	ctx.Initialized = true
}

// WaitForUserContainerd waits until user containerd started
func WaitForUserContainerd(ps *pubsub.PubSub, log *base.LogObject, agentName string, warningTime, errorTime time.Duration) error {
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)
	checkTicker := time.NewTicker(5 * time.Second)
	initialized := false

	for !initialized {
		log.Noticeln("Waiting for user containerd socket initialized")
		select {
		case <-checkTicker.C:
			ctrdClient, err := containerd.NewContainerdClient(true)
			if err != nil {
				log.Tracef("user containerd not ready: %v", err)
				continue
			}
			_ = ctrdClient.CloseClient()
			initialized = true
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	stillRunning.Stop()
	return nil
}

// WaitForFile waits for file with defined filename exists
func WaitForFile(ps *pubsub.PubSub, log *base.LogObject, agentName string, warningTime, errorTime time.Duration, filename string) {
	// return if file exists
	if utils.FileExists(filename) {
		return
	}
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)
	checkTicker := time.NewTicker(5 * time.Second)
	waitingStart := time.Now()
	done := false

	log.Noticeln("WaitForFile initialized")

	for !done {
		select {
		case <-checkTicker.C:
			if utils.FileExists(filename) {
				done = true
			}
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
		ps.CheckMaxTimeTopic(agentName, "WaitForFile", waitingStart, warningTime, errorTime)
	}
	stillRunning.Stop()
}
