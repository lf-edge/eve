// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Event represents an event in the attest state machine
type Event int

// Events
const (
	EventInitialize Event = iota + 0
	EventNonceRecvd
	EventInternalQuoteRecvd
	EventInternalEscrowRecvd
	EventRetryTimerExpiry
	EventNonceMismatch
	EventQuoteMismatch
	EventNoQuoteCertRecvd
	EventAttestEscrowRecorded
	EventNoEscrow
	EventAttestEscrowFailed
	EventAttestSuccessful
	EventRestart
)

// String returns human readable equivalent of an Event
func (event Event) String() string {
	switch event {
	case EventInitialize:
		return "EventInitialize"
	case EventNonceRecvd:
		return "EventNonceRecvd"
	case EventInternalQuoteRecvd:
		return "EventInternalQuoteRecvd"
	case EventInternalEscrowRecvd:
		return "EventInternalEscrowRecvd"
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
	case EventNoEscrow:
		return "EventNoEscrow"
	case EventAttestSuccessful:
		return "EventAttestSuccessful"
	case EventRestart:
		return "EventRestart"
	default:
		return "Unknown Event"
	}
}

// Verifier needs to be implemented by the consumer of this package
// It contains interface definitions for interacting with attestation server
type Verifier interface {
	SendNonceRequest(ctx *Context) error
	SendAttestQuote(ctx *Context) error
	SendAttestEscrow(ctx *Context) error
}

// TpmAgent needs to be implemented by the consumer of this package
// It contains interface definitions for interacting with TPM manager
type TpmAgent interface {
	SendInternalQuoteRequest(ctx *Context) error
}

// Various error codes to be returned to this package from external interfaces
var (
	ErrControllerReqFailed = errors.New("Controller Request Failed")
	ErrControllerError     = errors.New("Response from Controller has issues")
	ErrNonceMismatch       = errors.New("Nonce Mismatch")
	ErrQuoteMismatch       = errors.New("Quote Mismatch")
	ErrNoCertYet           = errors.New("No Cert Found")
	ErrITokenMismatch      = errors.New("Mismatch in integrity-token")
	ErrTpmAgentUnavailable = errors.New("TPM agent is unavailable")
	ErrNoEscrowData        = errors.New("No Escrow Data available")
	ErrNoVerifier          = errors.New("No verifier support in Controller")
)

// Watchdog needs to be implemented by the consumer of this package
// It contains interface definition for punching watchdog (not having it is okay)
type Watchdog interface {
	PunchWatchdog(ctx *Context) error
}

// External interfaces to the state machine
// For unit-testing, these will be redirected to their mock versions.
var tpmAgent TpmAgent
var verifier Verifier
var watchdog Watchdog

// RegisterExternalIntf is used to fill up external interface implementations
func RegisterExternalIntf(t TpmAgent, v Verifier, w Watchdog) {
	tpmAgent = t
	verifier = v
	watchdog = w
}

// Context has all the runtime context required to run this state machine
type Context struct {
	PubSub                *pubsub.PubSub
	log                   *base.LogObject
	event                 Event
	state                 types.AttestState
	restartTimer          *time.Timer
	eventTrigger          chan Event
	retryTime             time.Duration //in seconds
	restartRequestPending bool
	watchdogTickerTime    time.Duration //in seconds
	//OpaqueCtx for consumer module's own use
	OpaqueCtx interface{}
	types.ErrorAndTime
}

// Transition represents an event triggered from a state
type Transition struct {
	event Event
	state types.AttestState
}

// New returns a new instance of the state machine
func New(ps *pubsub.PubSub, log *base.LogObject, retryTime, watchdogTickerTime time.Duration, opaque interface{}) (*Context, error) {
	return &Context{
		PubSub:             ps,
		log:                log,
		event:              EventInitialize,
		state:              types.StateNone,
		eventTrigger:       make(chan Event, 1),
		retryTime:          retryTime,
		watchdogTickerTime: watchdogTickerTime,
		OpaqueCtx:          opaque,
	}, nil
}

// Initialize initializes the new instance of state machine
func (ctx *Context) Initialize() error {
	return nil
}

// GetState returns current state
func (ctx *Context) GetState() types.AttestState {
	return getStateAtomic(ctx)
}

// EventHandler represents a handler function for a Transition
type EventHandler func(*Context) error

// the state machine
var transitions = map[Transition]EventHandler{
	{EventInitialize, types.StateNone}:                        handleInitializeAtNone,                        //goes to NonceWait
	{EventRestart, types.StateNone}:                           handleRestartAtNone,                           //goes to NonceWait
	{EventRetryTimerExpiry, types.StateRestartWait}:           handleRetryTimerExpiryAtRestartWait,           //goes to NonceWait
	{EventRestart, types.StateRestartWait}:                    handleRestart,                                 //goes to RestartWait
	{EventNonceRecvd, types.StateNonceWait}:                   handleNonceRecvdAtNonceWait,                   //goes to InternalQuoteWait
	{EventRetryTimerExpiry, types.StateNonceWait}:             handleRetryTimerExpiryAtNonceWait,             //goes to InternalQuoteWait
	{EventRestart, types.StateNonceWait}:                      handleRestart,                                 //goes to RestartWait
	{EventInternalQuoteRecvd, types.StateInternalQuoteWait}:   handleInternalQuoteRecvdAtInternalQuoteWait,   //goes to AttestWait
	{EventRetryTimerExpiry, types.StateInternalQuoteWait}:     handleRetryTimerExpiryAtInternalQuoteWait,     //retries in InternalQuoteWait
	{EventRestart, types.StateInternalQuoteWait}:              handleRestart,                                 //goes to RestartWait
	{EventRestart, types.StateInternalEscrowWait}:             handleRestart,                                 //goes to RestartWait
	{EventInternalEscrowRecvd, types.StateInternalEscrowWait}: handleInternalEscrowRecvdAtInternalEscrowWait, //goes to AttestEscrowWait
	{EventNonceMismatch, types.StateAttestWait}:               handleNonceMismatchAtAttestWait,               //goes to RestartWait
	{EventQuoteMismatch, types.StateAttestWait}:               handleQuoteMismatchAtAttestWait,               //goes to RestartWait
	{EventNoQuoteCertRecvd, types.StateAttestWait}:            handleNoQuoteCertRcvdAtAttestWait,             //goes to RestartWait
	{EventAttestSuccessful, types.StateAttestWait}:            handleAttestSuccessfulAtAttestWait,            //goes to AttestEscrowWait | RestartWait
	{EventRetryTimerExpiry, types.StateAttestWait}:            handleRetryTimerExpiryAtAttestWait,            //retries in AttestWait
	{EventRestart, types.StateAttestWait}:                     handleRestart,                                 //goes to RestartWait
	{EventAttestEscrowFailed, types.StateAttestEscrowWait}:    handleAttestEscrowFailedAtAttestEscrowWait,    //goes to RestartWait (XXX: optimise)
	{EventNoEscrow, types.StateAttestEscrowWait}:              handleNoEscrowAtAttestEscrowWait,              //goes to InternalEscrowWait
	{EventAttestEscrowRecorded, types.StateAttestEscrowWait}:  handleAttestEscrowRecordedAtAttestEscrowWait,  //goes to Complete | RestartWait
	{EventRetryTimerExpiry, types.StateAttestEscrowWait}:      handleRetryTimerExpiryWhileAttestEscrowWait,   //goes to Complete | RestartWait
	{EventRestart, types.StateAttestEscrowWait}:               handleRestart,                                 //goes to RestartWait
	{EventRestart, types.StateComplete}:                       handleRestartAtStateComplete,                  //goes to RestartWait

	////////////// wildcard event handlers below this///////////////////
	{EventInternalEscrowRecvd, types.StateAny}: handleInternalEscrowRecvdAtAnyOther, //stays in the same state
}

// some helpers
func triggerSelfEvent(ctx *Context, event Event) error {
	go func() {
		ctx.eventTrigger <- event
	}()
	return nil
}

func setStateAtomic(ctx *Context, state types.AttestState) {
	atomic.StoreInt32((*int32)(&ctx.state), int32(state))
}

func getStateAtomic(ctx *Context) types.AttestState {
	return types.AttestState(atomic.LoadInt32((*int32)(&ctx.state)))
}

// Kickstart starts the state machine with EventInitialize
func Kickstart(ctx *Context) {
	ctx.eventTrigger <- EventInitialize
}

// RestartAttestation adds EventRestart event to the fsm
// To avoid hanging forever we use a conditional send here.
func RestartAttestation(ctx *Context) {
	select {
	case ctx.eventTrigger <- EventRestart:
		// Do nothing more
	default:
		ctx.log.Warnf("RestartAttestation(): already triggered, still not processed")
	}
}

// InternalQuoteRecvd adds EventInternalQuoteRecvd to the fsm
func InternalQuoteRecvd(ctx *Context) {
	ctx.eventTrigger <- EventInternalQuoteRecvd
}

// InternalEscrowDataRecvd adds EventInternalEscrowRecvd to the fsm
func InternalEscrowDataRecvd(ctx *Context) {
	ctx.eventTrigger <- EventInternalEscrowRecvd
}

func startNewRetryTimer(ctx *Context) error {
	if ctx.restartTimer != nil {
		ctx.restartTimer.Stop()
	}
	ctx.log.Tracef("Starting retry timer at %v", time.Now())
	if ctx.retryTime == 0 {
		return fmt.Errorf("retryTime not initialized")
	}
	ctx.restartTimer = time.NewTimer(ctx.retryTime * time.Second)
	return nil
}

// The event handlers
func handleInitializeAtNone(ctx *Context) error {
	ctx.log.Trace("handleInitializeAtNone")
	setStateAtomic(ctx, types.StateNonceWait)
	err := verifier.SendNonceRequest(ctx)
	if err == nil {
		triggerSelfEvent(ctx, EventNonceRecvd)
		return nil
	}
	ctx.log.Errorf("Error %v while sending nonce request", err)
	switch err {
	case ErrControllerReqFailed:
		return startNewRetryTimer(ctx)
	case ErrNoVerifier:
		//Verifier support is missing in Controller
		//let the state machine wait in this state forever
		//until we get an EventRestart
		return nil
	default:
		return fmt.Errorf("Unknown error %v", err)
	}
}

func handleRestartAtNone(ctx *Context) error {
	ctx.log.Trace("handleRestartAtNone")

	//same handling as EventRestart
	return handleInitializeAtNone(ctx)
}

func handleNonceRecvdAtNonceWait(ctx *Context) error {
	ctx.log.Trace("handleNonceRecvdAtNonceWait")
	setStateAtomic(ctx, types.StateInternalQuoteWait)
	err := tpmAgent.SendInternalQuoteRequest(ctx)
	if err == nil {
		return nil
	}
	ctx.log.Errorf("Error %v while sending internal quote request", err)
	switch err {
	case ErrTpmAgentUnavailable:
		return startNewRetryTimer(ctx)
	default:
		return fmt.Errorf("Unknown error %v", err)
	}
}

func handleInternalQuoteRecvdAtInternalQuoteWait(ctx *Context) error {
	ctx.log.Trace("handleInternalQuoteRecvdAtInternalQuoteWait")
	setStateAtomic(ctx, types.StateAttestWait)
	err := verifier.SendAttestQuote(ctx)
	if err == nil {
		triggerSelfEvent(ctx, EventAttestSuccessful)
		return nil
	}
	ctx.log.Errorf("Error %v while sending quote", err)
	switch err {
	case ErrNonceMismatch:
		return triggerSelfEvent(ctx, EventNonceMismatch)
	case ErrQuoteMismatch:
		return triggerSelfEvent(ctx, EventQuoteMismatch)
	case ErrNoCertYet:
		return triggerSelfEvent(ctx, EventNoQuoteCertRecvd)
	case ErrControllerReqFailed:
		return startNewRetryTimer(ctx)
	case ErrNoVerifier:
		//Verifier support is missing in Controller
		//We should not have got here since Nonce request
		//itself should have failed. But still being defensive.
		//let the state machine wait in this state forever
		//until we get an EventRestart
		return nil
	default:
		return fmt.Errorf("Unknown error %v", err)
	}
}

func handleAttestSuccessfulAtAttestWait(ctx *Context) error {
	ctx.log.Trace("handleAttestSuccessfulAtAttestWait")
	setStateAtomic(ctx, types.StateAttestEscrowWait)
	err := verifier.SendAttestEscrow(ctx)
	if err == nil {
		triggerSelfEvent(ctx, EventAttestEscrowRecorded)
		return nil
	}
	ctx.log.Errorf("Error %v while sending attest escrow keys", err)
	switch err {
	case ErrControllerReqFailed:
		return startNewRetryTimer(ctx)
	case ErrNoEscrowData:
		return triggerSelfEvent(ctx, EventNoEscrow)
	case ErrITokenMismatch:
		return triggerSelfEvent(ctx, EventAttestEscrowFailed)
	case ErrNoVerifier:
		//Verifier support is missing in Controller
		//We should not have got here, since Nonce request
		//itself should have failed. But still being defensive.
		//let the state machine wait in this state forever
		//until we get an EventRestart
		return nil
	default:
		return fmt.Errorf("Unknown error %v", err)
	}
}

func handleAttestEscrowRecordedAtAttestEscrowWait(ctx *Context) error {
	ctx.log.Trace("handleAttestEscrowRecordedAtAttestEscrowWait")
	setStateAtomic(ctx, types.StateComplete)
	if ctx.restartRequestPending {
		setStateAtomic(ctx, types.StateRestartWait)
		startNewRetryTimer(ctx)
	}
	return nil
}

func handleRestartAtStateComplete(ctx *Context) error {
	ctx.log.Trace("handleRestartAtStateComplete")
	setStateAtomic(ctx, types.StateRestartWait)
	return startNewRetryTimer(ctx)
}

func handleRestart(ctx *Context) error {
	ctx.log.Trace("handleRestart")
	ctx.restartRequestPending = true
	return nil
}

func handleNonceMismatchAtAttestWait(ctx *Context) error {
	ctx.log.Trace("handleNonceMismatchAtAttestWait")
	setStateAtomic(ctx, types.StateRestartWait)
	return startNewRetryTimer(ctx)
}

func handleQuoteMismatchAtAttestWait(ctx *Context) error {
	ctx.log.Trace("handleQuoteMismatchAtAttestWait")
	return handleNonceMismatchAtAttestWait(ctx)
}

func handleNoQuoteCertRcvdAtAttestWait(ctx *Context) error {
	ctx.log.Trace("handleNoQuoteCertRcvdAtAttestWait")
	return handleNonceMismatchAtAttestWait(ctx)
}

func handleAttestEscrowFailedAtAttestEscrowWait(ctx *Context) error {
	ctx.log.Trace("handleAttestEscrowFailedAtAttestEscrowWait")
	setStateAtomic(ctx, types.StateRestartWait)
	return startNewRetryTimer(ctx)
}

func handleInternalEscrowRecvdAtInternalEscrowWait(ctx *Context) error {
	ctx.log.Trace("handleInternalEscrowRecvdAtInternalEscrowWait")
	//try sending escrow data now
	return handleAttestSuccessfulAtAttestWait(ctx)
}

// handleInternalEscrowRecvdAtAnyOther handles EventInternalEscrowRecvd
// at any other state, other than types.StateInternalQuoteWait.
// for types.StateInternalQuoteWait, we have handleInternalEscrowRecvdAtInternalEscrowWait
func handleInternalEscrowRecvdAtAnyOther(ctx *Context) error {
	ctx.log.Trace("handleInternalEscrowRecvdAtAnyOther")
	switch ctx.state {
	case types.StateInternalEscrowWait:
		//We should not have reached here since there is an explicit
		//handler. Log an error about this, and call the actual
		//handler. don't fatal
		ctx.log.Errorf("[ATTEST] Unexpected wildcard handler in (%s, %s)",
			ctx.state.String(), ctx.event.String())
		return handleInternalEscrowRecvdAtInternalEscrowWait(ctx)
	default:
		//no-op, since escrow data is already saved by caller
		//we are not waiting for escrow data
		return nil
	}
}

func handleNoEscrowAtAttestEscrowWait(ctx *Context) error {
	ctx.log.Trace("handleNoEscrowAtAttestEscrowWait")
	//Wait till we get escrow data published
	setStateAtomic(ctx, types.StateInternalEscrowWait)
	return nil
}

func handleRetryTimerExpiryAtRestartWait(ctx *Context) error {
	ctx.log.Trace("handleRetryTimerExpiryAtRestartWait")
	setStateAtomic(ctx, types.StateNone)
	ctx.restartRequestPending = false
	return triggerSelfEvent(ctx, EventInitialize)
}

func handleRetryTimerExpiryAtNonceWait(ctx *Context) error {
	ctx.log.Trace("handleRetryTimerExpiryAtNonceWait")
	setStateAtomic(ctx, types.StateNone)
	return triggerSelfEvent(ctx, EventInitialize)
}

func handleRetryTimerExpiryAtAttestWait(ctx *Context) error {
	//try re-sending quote
	ctx.log.Trace("handleRetryTimerExpiryAtAttestWait")
	return handleInternalQuoteRecvdAtInternalQuoteWait(ctx)
}

func handleRetryTimerExpiryWhileAttestEscrowWait(ctx *Context) error {
	//try re-sending escrow info
	ctx.log.Trace("handleRetryTimerExpiryWhileAttestEscrowWait")
	return handleAttestSuccessfulAtAttestWait(ctx)
}

func handleRetryTimerExpiryAtInternalQuoteWait(ctx *Context) error {
	ctx.log.Trace("handleRetryTimerExpiryAtInternalQuoteWait")
	return handleNonceRecvdAtNonceWait(ctx)
}

func despatchEvent(event Event, state types.AttestState, ctx *Context) error {
	elem, ok := transitions[Transition{event: event, state: state}]
	if ok {
		return elem(ctx)
	}
	//Specific handler is not found, look for a wildcard handler
	elem, ok = transitions[Transition{event: event, state: types.StateAny}]
	if ok {
		ctx.log.Noticef("Calling wildcard handler(Event %s in State %s)",
			event.String(), state.String())
		return elem(ctx)
	} else {
		ctx.log.Fatalf("Unexpected Event %s in State %s",
			event.String(), state.String())
		//just to keep compiler happy
		return fmt.Errorf("Unexpected Event %s in State %s",
			event.String(), state.String())
	}
}

func punchWatchdog(ctx *Context) {
	//if there is one registered
	if watchdog != nil {
		watchdog.PunchWatchdog(ctx)
	}
}

// EnterEventLoop is the eternel event loop for the state machine
func (ctx *Context) EnterEventLoop() {
	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(ctx.watchdogTickerTime * time.Second)
	punchWatchdog(ctx)

	ctx.restartTimer = time.NewTimer(1 * time.Second)
	ctx.restartTimer.Stop()

	for {
		select {
		case ctx.event = <-ctx.eventTrigger:
			ctx.log.Trace("[ATTEST] despatching event")
			if err := despatchEvent(ctx.event, ctx.state, ctx); err != nil {
				ctx.log.Errorf("%v", err)
			}
		case <-ctx.restartTimer.C:
			ctx.log.Trace("[ATTEST] EventRetryTimerExpiry event")
			triggerSelfEvent(ctx, EventRetryTimerExpiry)
		case <-stillRunning.C:
			ctx.log.Trace("[ATTEST] stillRunning event")
			punchWatchdog(ctx)
		}
	}
}
