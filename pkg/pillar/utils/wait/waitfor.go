// Copyright (c) 2020-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package wait

import (
	"time"

	info "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Context is a helper struct used to pass around in pubsub handlers
type Context struct {
	Initialized bool
	Status      types.OnboardingStatus
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
func WaitForOnboarded(ps *pubsub.PubSub, log *base.LogObject, agentName string, warningTime, errorTime time.Duration) (types.OnboardingStatus, error) {
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
		return types.OnboardingStatus{}, err
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
	return Ctx.Status, nil
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
	ctx.Status = status
	ctx.Initialized = true
}

// ForEvalStatus waits until it receives a types.EvalStatus msg that allows onboarding.
// This is used during device boot to ensure evaluation manager has completed its checks
// before allowing the device to proceed with onboarding to the controller.
func ForEvalStatus(ps *pubsub.PubSub, log *base.LogObject, agentName string, warningTime, errorTime time.Duration) error {
	Ctx := &Context{}
	subEvalStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "evalmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.EvalStatus{},
		Activate:      false,
		Persistent:    false,
		Ctx:           Ctx,
		CreateHandler: handleEvalStatusCreate,
		ModifyHandler: handleEvalStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	subEvalStatus.Activate()

	// Check if we have existing EvalStatus
	item, err := subEvalStatus.Get("evalmgr")
	if err == nil {
		evalStatus := item.(types.EvalStatus)
		if evalStatus.IsOnboardingAllowed() {
			log.Noticef("Found existing EvalStatus that allows onboarding: phase=%s", evalStatus.Phase)
			Ctx.Initialized = true
		} else {
			reason := evalStatus.OnboardingBlockReason()
			log.Noticef("Found existing EvalStatus but onboarding blocked: %s", reason)
		}
	} else {
		log.Noticef("No EvalStatus found, will wait for evalmgr")
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait for EvalStatus that allows onboarding
	for !Ctx.Initialized {
		log.Functionf("Waiting for EvalStatus that allows onboarding")
		select {
		case change := <-subEvalStatus.MsgChan():
			subEvalStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	stillRunning.Stop()
	subEvalStatus.Close()
	log.Noticef("EvalStatus received, onboarding allowed")
	return nil
}

func handleEvalStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleEvalStatusImpl(ctxArg, key, statusArg)
}

func handleEvalStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleEvalStatusImpl(ctxArg, key, statusArg)
}

func handleEvalStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*Context)
	status := statusArg.(types.EvalStatus)

	if key != "evalmgr" {
		return
	}

	// Check if onboarding is allowed
	if status.IsOnboardingAllowed() {
		ctx.Initialized = true
	}
}
