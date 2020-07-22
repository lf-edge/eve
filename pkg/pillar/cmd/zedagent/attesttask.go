// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// all things related to running remote attestation with the Controller

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	zattest "github.com/lf-edge/eve/pkg/pillar/attest"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	log "github.com/sirupsen/logrus"
)

//TpmAgentImpl implements zattest.TpmAgent interface
type TpmAgentImpl struct{}

//VerifierImpl implements zattest.Verifier interface
type VerifierImpl struct{}

//WatchdogImpl implements zattest.Watchdog interface
type WatchdogImpl struct{}

// Attest Information Context
type attestContext struct {
	zedagentCtx  *zedagentContext
	attestModCtx *zattest.Context
}

//SendNonceRequest implements SendNonceRequest method of zattest.Verifier
func (server *VerifierImpl) SendNonceRequest(ctx *zattest.Context) error {
	//XXX: Fill it in when Controller code is ready
	return nil
}

//SendAttestQuote implements SendAttestQuote method of zattest.Verifier
func (server *VerifierImpl) SendAttestQuote(ctx *zattest.Context) error {
	//XXX: Fill it in when Controller code is ready
	return nil
}

//SendAttestEscrow implements SendAttestEscrow method of zattest.Verifier
func (server *VerifierImpl) SendAttestEscrow(ctx *zattest.Context) error {
	//XXX: Fill it in when Controller code is ready
	return nil
}

//SendInternalQuoteRequest implements SendInternalQuoteRequest method of zattest.TpmAgent
func (agent *TpmAgentImpl) SendInternalQuoteRequest(ctx *zattest.Context) error {
	//XXX: Fill it in along with the above methods
	return nil
}

//PunchWatchdog implements PunchWatchdog method of zattest.Watchdog
func (wd *WatchdogImpl) PunchWatchdog(ctx *zattest.Context) error {
	log.Debug("[ATTEST] Punching watchdog")
	agentlog.StillRunning(agentName+"attest", warningTime, errorTime)
	return nil
}

// initialize attest pubsub trigger handlers and channels
func attestModuleInitialize(ctx *zedagentContext, ps *pubsub.PubSub) error {
	zattest.RegisterExternalIntf(&TpmAgentImpl{}, &VerifierImpl{}, &WatchdogImpl{})

	//retryTime is 15 seconds, watchdogTime is 15 seconds
	c, err := zattest.New(15, 15)
	if err != nil {
		return err
	}
	ctx.attestCtx.attestModCtx = c
	return nil
}

// start the task threads
func attestModuleStart(ctx *zedagentContext) error {
	log.Info("[ATTEST] Starting attestation task")
	if ctx.attestCtx == nil {
		return fmt.Errorf("No attest module context")
	}
	if ctx.attestCtx.attestModCtx == nil {
		return fmt.Errorf("No state machine context found")
	}
	go ctx.attestCtx.attestModCtx.EnterEventLoop()
	return nil
}
