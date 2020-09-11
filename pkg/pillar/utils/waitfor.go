// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	info "github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"time"
)

//Context is a helper struct used to pass around in pubsub handlers
type Context struct {
	Initialized bool
}

//WaitForVault waits till it receives types.VaultStatus msg, for types.DefaultVaultName
//and the status does not indicate any error
func WaitForVault(ps *pubsub.PubSub, agentName string, warningTime, errorTime time.Duration) error {
	// Look for vault status
	Ctx := &Context{}
	subVaultStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "vaultmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VaultStatus{},
		Activate:      false,
		Ctx:           Ctx,
		CreateHandler: handleVaultStatusModify,
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
		select {
		case change := <-subVaultStatus.MsgChan():
			subVaultStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	subVaultStatus.Close()
	return nil
}

func handleVaultStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*Context)
	vault := statusArg.(types.VaultStatus)
	if vault.Name == types.DefaultVaultName &&
		vault.Status != info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR {
		ctx.Initialized = true
	}
}
