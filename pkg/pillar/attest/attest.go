// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"time"
)

//Event represents an event in the attest state machine
type Event int

//State represents a state in the attest state machine
type State int

//Events
const (
	EventInitialize Event = iota + 0
	EventNonceRecvd
	EventInternalQuoteRecvd
	EventRetryTimerExpiry
	EventNonceMismatch
	EventQuoteMismatch
	EventNoQuoteCertRecvd
	EventAttestEscrowRecorded
	EventAttestEscrowFailed
	EventAttestSuccessful
	EventRestart
)

//States
const (
	StateNone State = iota + 0
	StateNonceWait
	StateInternalQuoteWait
	StateAttestWait
	StateAttestEscrowWait
	StateRestartWait
	StateComplete
)

//String returns human readable equivalent of an Event
func (event Event) String() string {
	switch event {
	case EventInitialize:
		return "EventInitialize"
	case EventNonceRecvd:
		return "EventNonceRecvd"
	case EventInternalQuoteRecvd:
		return "EventInternalQuoteRecvd"
	case EventRetryTimerExpiry:
		return "EventRetryTimerExpiry"
	case EventNonceMismatch:
		return "EventNonceMismatch"
	case EventQuoteMismatch:
		return "EventQuoteMismatch"
	case EventNoQuoteCertRecvd:
		return "EventNoQuoteCertRecvd"
	case EventAttestEscrowRecorded:
		return "EventAttestEscrowRecorded"
	case EventAttestEscrowFailed:
		return "EventAttestEscrowFailed"
	case EventAttestSuccessful:
		return "EventAttestSuccessful"
	case EventRestart:
		return "EventRestart"
	default:
		return "Unknown Event"
	}
}

//String returns human readable string of a State
func (state State) String() string {
	switch state {
	case StateNone:
		return "StateNone"
	case StateNonceWait:
		return "StateNonceWait"
	case StateInternalQuoteWait:
		return "StateInternalQuoteWait"
	case StateAttestWait:
		return "StateAttestWait"
	case StateAttestEscrowWait:
		return "StateAttestEscrowWait"
	case StateRestartWait:
		return "StateRestartWait"
	case StateComplete:
		return "StateComplete"
	default:
		return "Unknown State"
	}
}

//Verifier needs to be implemented by the consumer of this package
//It contains interface definitions for interacting with attestation server
type Verifier interface {
	SendNonceRequest(ctx *Context) error
	SendAttestQuote(ctx *Context) error
	SendAttestEscrow(ctx *Context) error
}

//TpmAgent needs to be implemented by the consumer of this package
//It contains interface definitions for interacting with TPM manager
type TpmAgent interface {
	SendInternalQuoteRequest(ctx *Context) error
}

//Various error codes to be returned to this package from external interfaces
var (
	ErrControllerUnavailable = errors.New("Controller is unavailable")
	ErrNonceMismatch         = errors.New("Nonce Mismatch")
	ErrQuoteMismatch         = errors.New("Quote Mismatch")
	ErrNoCertYet             = errors.New("No Cert Found")
	ErrInfoTokenInvalid      = errors.New("Provided Integrity Token is Invalid")
	ErrTpmAgentUnavailable   = errors.New("TPM agent is unavailable")
)

//External interfaces to the state machine
//For unit-testing, these will be redirected to their mock versions.
var tpmAgent TpmAgent
var verifier Verifier

//Context has all the runtime context required to run this state machine
type Context struct {
	event                 Event
	state                 State
	restartTimer          *time.Timer
	eventTrigger          chan Event
	retryTime             time.Duration
	restartRequestPending bool
	watchdogTime          time.Duration
}

//Transition represents an event triggered from a state
type Transition struct {
	event Event
	state State
}

//EventHandler represents a handler function for a Transition
type EventHandler func(*Context) error

//the state machine
var transitions = map[Transition]EventHandler{
	{EventInitialize, StateNone}:                       handleInitializeAtNone,                       //goes to NonceWait
	{EventRetryTimerExpiry, StateRestartWait}:          handleRetryTimerExpiryAtRestartWait,          //goes to NonceWait
	{EventRestart, StateRestartWait}:                   handleRestart,                                //goes to RestartWait
	{EventNonceRecvd, StateNonceWait}:                  handleNonceRecvdAtNonceWait,                  //goes to InternalQuoteWait
	{EventRetryTimerExpiry, StateNonceWait}:            handleRetryTimerExpiryAtNonceWait,            //goes to InternalQuoteWait
	{EventRestart, StateNonceWait}:                     handleRestart,                                //goes to RestartWait
	{EventInternalQuoteRecvd, StateInternalQuoteWait}:  handleInternalQuoteRecvdAtInternalQuoteWait,  //goes to AttestWait
	{EventRetryTimerExpiry, StateInternalQuoteWait}:    handleRetryTimerExpiryAtInternalQuoteWait,    //retries in InternalQuoteWait
	{EventRestart, StateInternalQuoteWait}:             handleRestart,                                //goes to RestartWait
	{EventNonceMismatch, StateAttestWait}:              handleNonceMismatchAtAttestWait,              //goes to RestartWait
	{EventQuoteMismatch, StateAttestWait}:              handleQuoteMismatchAtAttestWait,              //goes to RestartWait
	{EventNoQuoteCertRecvd, StateAttestWait}:           handleNoQuoteCertRcvdAtAttestWait,            //goes to RestartWait
	{EventAttestSuccessful, StateAttestWait}:           handleAttestSuccessfulAtAttestWait,           //goes to AttestEscrowWait | RestartWait
	{EventRetryTimerExpiry, StateAttestWait}:           handleRetryTimerExpiryAtAttestWait,           //retries in AttestWait
	{EventRestart, StateAttestWait}:                    handleRestart,                                //goes to RestartWait
	{EventAttestEscrowFailed, StateAttestEscrowWait}:   handleAttestEscrowFailedAtAttestEscrowWait,   //goes to RestartWait (XXX: optimise)
	{EventAttestEscrowRecorded, StateAttestEscrowWait}: handleAttestEscrowRecordedAtAttestEscrowWait, //goes to Complete | RestartWait
	{EventRetryTimerExpiry, StateAttestEscrowWait}:     handleRetryTimerExpiryWhileAttestEscrowWait,  //goes to Complete | RestartWait
	{EventRestart, StateAttestEscrowWait}:              handleRestart,                                //goes to RestartWait
	{EventRestart, StateComplete}:                      handleRestartAtStateComplete,                 //goes to RestartWait
}

//some helpers
func triggerSelfEvent(ctx *Context, event Event) error {
	go func() {
		ctx.eventTrigger <- event
	}()
	return nil
}

func startNewRetryTimer(ctx *Context) error {
	ctx.restartTimer.Stop()
	log.Debugf("Starting retry timer at %v\n", time.Now())
	if ctx.retryTime == 0 {
		return fmt.Errorf("retryTime not initialized")
	}
	ctx.restartTimer = time.NewTimer(ctx.retryTime * time.Second)
	return nil
}

//The event handlers
func handleInitializeAtNone(ctx *Context) error {
	log.Debug("handleInitializeAtNone")
	ctx.state = StateNonceWait
	err := verifier.SendNonceRequest(ctx)
	if err == nil {
		triggerSelfEvent(ctx, EventNonceRecvd)
		return nil
	}
	log.Errorf("Error %v while sending nonce request\n", err)
	switch err {
	case ErrControllerUnavailable:
		return startNewRetryTimer(ctx)
	default:
		return fmt.Errorf("Unknown error %v", err)
	}
}

func handleNonceRecvdAtNonceWait(ctx *Context) error {
	log.Debug("handleNonceRecvdAtNonceWait")
	ctx.state = StateInternalQuoteWait
	err := tpmAgent.SendInternalQuoteRequest(ctx)
	if err == nil {
		return nil
	}
	log.Errorf("Error %v while sending internal quote request\n", err)
	switch err {
	case ErrTpmAgentUnavailable:
		return startNewRetryTimer(ctx)
	default:
		return fmt.Errorf("Unknown error %v", err)
	}
}

func handleInternalQuoteRecvdAtInternalQuoteWait(ctx *Context) error {
	log.Debug("handleInternalQuoteRecvdAtInternalQuoteWait")
	ctx.state = StateAttestWait
	err := verifier.SendAttestQuote(ctx)
	if err == nil {
		triggerSelfEvent(ctx, EventAttestSuccessful)
		return nil
	}
	log.Errorf("Error %v while sending quote\n", err)
	switch err {
	case ErrNonceMismatch:
		return triggerSelfEvent(ctx, EventNonceMismatch)
	case ErrQuoteMismatch:
		return triggerSelfEvent(ctx, EventQuoteMismatch)
	case ErrNoCertYet:
		return triggerSelfEvent(ctx, EventNoQuoteCertRecvd)
	case ErrControllerUnavailable:
		return startNewRetryTimer(ctx)
	default:
		return fmt.Errorf("Unknown error %v", err)
	}
}

func handleAttestSuccessfulAtAttestWait(ctx *Context) error {
	log.Debug("handleAttestSuccessfulAtAttestWait")
	ctx.state = StateAttestEscrowWait
	err := verifier.SendAttestEscrow(ctx)
	if err == nil {
		triggerSelfEvent(ctx, EventAttestEscrowRecorded)
		return nil
	}
	log.Errorf("Error %v while sending attest escrow keys\n", err)
	switch err {
	case ErrControllerUnavailable:
		return startNewRetryTimer(ctx)
	case ErrInfoTokenInvalid:
		ctx.state = StateRestartWait
		startNewRetryTimer(ctx)
	default:
		return fmt.Errorf("Unknown error %v", err)
	}
	//keep the compiler happy
	return nil
}

func handleAttestEscrowRecordedAtAttestEscrowWait(ctx *Context) error {
	log.Debug("handleAttestEscrowRecordedAtAttestEscrowWait")
	ctx.state = StateComplete
	if ctx.restartRequestPending {
		ctx.state = StateRestartWait
		startNewRetryTimer(ctx)
	}
	return nil
}

func handleRestartAtStateComplete(ctx *Context) error {
	log.Debug("handleRestartAtStateComplete")
	ctx.state = StateRestartWait
	return startNewRetryTimer(ctx)
}

func handleRestart(ctx *Context) error {
	log.Debug("handleRestart")
	ctx.restartRequestPending = true
	return nil
}

func handleNonceMismatchAtAttestWait(ctx *Context) error {
	log.Debug("handleNonceMismatchAtAttestWait")
	ctx.state = StateRestartWait
	return startNewRetryTimer(ctx)
}

func handleQuoteMismatchAtAttestWait(ctx *Context) error {
	log.Debug("handleQuoteMismatchAtAttestWait")
	return handleNonceMismatchAtAttestWait(ctx)
}

func handleNoQuoteCertRcvdAtAttestWait(ctx *Context) error {
	log.Debug("handleNoQuoteCertRcvdAtAttestWait")
	return handleNonceMismatchAtAttestWait(ctx)
}

func handleAttestEscrowFailedAtAttestEscrowWait(ctx *Context) error {
	log.Debug("handleAttestEscrowFailedAtAttestEscrowWait")
	ctx.state = StateRestartWait
	return startNewRetryTimer(ctx)
}

func handleRetryTimerExpiryAtRestartWait(ctx *Context) error {
	log.Debug("handleRetryTimerExpiryAtRestartWait")
	ctx.state = StateNone
	return triggerSelfEvent(ctx, EventInitialize)
}

func handleRetryTimerExpiryAtNonceWait(ctx *Context) error {
	log.Debug("handleRetryTimerExpiryAtNonceWait")
	ctx.state = StateNone
	return triggerSelfEvent(ctx, EventInitialize)
}

func handleRetryTimerExpiryAtAttestWait(ctx *Context) error {
	//try re-sending quote
	log.Debug("handleRetryTimerExpiryAtAttestWait")
	return handleInternalQuoteRecvdAtInternalQuoteWait(ctx)
}

func handleRetryTimerExpiryWhileAttestEscrowWait(ctx *Context) error {
	//try re-sending escrow info
	log.Debug("handleRetryTimerExpiryWhileAttestEscrowWait")
	return handleAttestSuccessfulAtAttestWait(ctx)
}

func handleRetryTimerExpiryAtInternalQuoteWait(ctx *Context) error {
	log.Debug("handleRetryTimerExpiryAtInternalQuoteWait")
	return handleNonceRecvdAtNonceWait(ctx)
}

func despatchEvent(event Event, state State, ctx *Context) error {
	elem, ok := transitions[Transition{event: event, state: state}]
	if ok {
		return elem(ctx)
	} else {
		log.Fatalf("Unexpected Event %s in State %s\n",
			event.String(), state.String())
		//just to keep compiler happy
		return fmt.Errorf("Unexpected Event %s in State %s\n",
			event.String(), state.String())
	}
}
