// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
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

//States
const (
	StateNone               State = iota + 0 //State when (Re)Starting attestation
	StateNonceWait                           //Waiting for response from Controller for Nonce request
	StateInternalQuoteWait                   //Waiting for internal PCR quote to be published
	StateInternalEscrowWait                  //Waiting for internal Escrow data to be published
	StateAttestWait                          //Waiting for response from Controller for PCR quote
	StateAttestEscrowWait                    //Waiting for response from Controller for Escrow data
	StateRestartWait                         //Waiting for restart timer to expire, to start all over again
	StateComplete                            //Everything w.r.t attestation is complete
	StateAny                                 //Not a real state per se. helps defining wildcard transitions(below)
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

//String returns human readable string of a State
func (state State) String() string {
	switch state {
	case StateNone:
		return "StateNone"
	case StateNonceWait:
		return "StateNonceWait"
	case StateInternalQuoteWait:
		return "StateInternalQuoteWait"
	case StateInternalEscrowWait:
		return "StateInternalEscrowWait"
	case StateAttestWait:
		return "StateAttestWait"
	case StateAttestEscrowWait:
		return "StateAttestEscrowWait"
	case StateRestartWait:
		return "StateRestartWait"
	case StateComplete:
		return "StateComplete"
	case StateAny:
		return "StateAny"
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

//Watchdog needs to be implemented by the consumer of this package
//It contains interface definition for punching watchdog (not having it is okay)
type Watchdog interface {
	PunchWatchdog(ctx *Context) error
}

//External interfaces to the state machine
//For unit-testing, these will be redirected to their mock versions.
var tpmAgent TpmAgent
var verifier Verifier
var watchdog Watchdog

//RegisterExternalIntf is used to fill up external interface implementaions
func RegisterExternalIntf(t TpmAgent, v Verifier, w Watchdog) {
	tpmAgent = t
	verifier = v
	watchdog = w
}

//Context has all the runtime context required to run this state machine
type Context struct {
	PubSub                *pubsub.PubSub
	log                   *base.LogObject
	event                 Event
	state                 State
	restartTimer          *time.Timer
	eventTrigger          chan Event
	retryTime             time.Duration //in seconds
	restartRequestPending bool
	watchdogTickerTime    time.Duration //in seconds
	//OpaqueCtx for consumer module's own use
	OpaqueCtx interface{}
	types.ErrorAndTime
}

//Transition represents an event triggered from a state
type Transition struct {
	event Event
	state State
}

//New returns a new instance of the state machine
func New(ps *pubsub.PubSub, log *base.LogObject, retryTime, watchdogTickerTime time.Duration, opaque interface{}) (*Context, error) {
	return &Context{
		PubSub:             ps,
		log:                log,
		event:              EventInitialize,
		state:              StateNone,
		eventTrigger:       make(chan Event),
		retryTime:          retryTime,
		watchdogTickerTime: watchdogTickerTime,
		OpaqueCtx:          opaque,
	}, nil
}

//Initialize initializes the new instance of state machine
func (ctx *Context) Initialize() error {
	return nil
}

//GetState returns current state
func (ctx *Context) GetState() State {
	return ctx.state
}

//EventHandler represents a handler function for a Transition
type EventHandler func(*Context) error

//the state machine
var transitions = map[Transition]EventHandler{
	{EventInitialize, StateNone}:                        handleInitializeAtNone,                        //goes to NonceWait
	{EventRestart, StateNone}:                           handleRestartAtNone,                           //goes to NonceWait
	{EventRetryTimerExpiry, StateRestartWait}:           handleRetryTimerExpiryAtRestartWait,           //goes to NonceWait
	{EventRestart, StateRestartWait}:                    handleRestart,                                 //goes to RestartWait
	{EventNonceRecvd, StateNonceWait}:                   handleNonceRecvdAtNonceWait,                   //goes to InternalQuoteWait
	{EventRetryTimerExpiry, StateNonceWait}:             handleRetryTimerExpiryAtNonceWait,             //goes to InternalQuoteWait
	{EventRestart, StateNonceWait}:                      handleRestart,                                 //goes to RestartWait
	{EventInternalQuoteRecvd, StateInternalQuoteWait}:   handleInternalQuoteRecvdAtInternalQuoteWait,   //goes to AttestWait
	{EventRetryTimerExpiry, StateInternalQuoteWait}:     handleRetryTimerExpiryAtInternalQuoteWait,     //retries in InternalQuoteWait
	{EventRestart, StateInternalQuoteWait}:              handleRestart,                                 //goes to RestartWait
	{EventRestart, StateInternalEscrowWait}:             handleRestart,                                 //goes to RestartWait
	{EventInternalEscrowRecvd, StateInternalEscrowWait}: handleInternalEscrowRecvdAtInternalEscrowWait, //goes to AttestEscrowWait
	{EventNonceMismatch, StateAttestWait}:               handleNonceMismatchAtAttestWait,               //goes to RestartWait
	{EventQuoteMismatch, StateAttestWait}:               handleQuoteMismatchAtAttestWait,               //goes to RestartWait
	{EventNoQuoteCertRecvd, StateAttestWait}:            handleNoQuoteCertRcvdAtAttestWait,             //goes to RestartWait
	{EventAttestSuccessful, StateAttestWait}:            handleAttestSuccessfulAtAttestWait,            //goes to AttestEscrowWait | RestartWait
	{EventRetryTimerExpiry, StateAttestWait}:            handleRetryTimerExpiryAtAttestWait,            //retries in AttestWait
	{EventRestart, StateAttestWait}:                     handleRestart,                                 //goes to RestartWait
	{EventAttestEscrowFailed, StateAttestEscrowWait}:    handleAttestEscrowFailedAtAttestEscrowWait,    //goes to RestartWait (XXX: optimise)
	{EventNoEscrow, StateAttestEscrowWait}:              handleNoEscrowAtAttestEscrowWait,              //goes to InternalEscrowWait
	{EventAttestEscrowRecorded, StateAttestEscrowWait}:  handleAttestEscrowRecordedAtAttestEscrowWait,  //goes to Complete | RestartWait
	{EventRetryTimerExpiry, StateAttestEscrowWait}:      handleRetryTimerExpiryWhileAttestEscrowWait,   //goes to Complete | RestartWait
	{EventRestart, StateAttestEscrowWait}:               handleRestart,                                 //goes to RestartWait
	{EventRestart, StateComplete}:                       handleRestartAtStateComplete,                  //goes to RestartWait

	////////////// wildcard event handlers below this///////////////////
	{EventInternalEscrowRecvd, StateAny}: handleInternalEscrowRecvdAtAnyOther, //stays in the same state
}

//some helpers
func triggerSelfEvent(ctx *Context, event Event) error {
	go func() {
		ctx.eventTrigger <- event
	}()
	return nil
}

//Kickstart starts the state machine with EventInitialize
func Kickstart(ctx *Context) {
	ctx.eventTrigger <- EventInitialize
}

//RestartAttestation adds EventRestart event to the fsm
func RestartAttestation(ctx *Context) {
	ctx.eventTrigger <- EventRestart
}

//InternalQuoteRecvd adds EventInternalQuoteRecvd to the fsm
func InternalQuoteRecvd(ctx *Context) {
	ctx.eventTrigger <- EventInternalQuoteRecvd
}

//InternalEscrowDataRecvd adds EventInternalEscrowRecvd to the fsm
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

//The event handlers
func handleInitializeAtNone(ctx *Context) error {
	ctx.log.Trace("handleInitializeAtNone")
	ctx.state = StateNonceWait
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
	ctx.state = StateInternalQuoteWait
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
	ctx.state = StateAttestWait
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
	ctx.state = StateAttestEscrowWait
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
	ctx.state = StateComplete
	if ctx.restartRequestPending {
		ctx.state = StateRestartWait
		startNewRetryTimer(ctx)
	}
	return nil
}

func handleRestartAtStateComplete(ctx *Context) error {
	ctx.log.Trace("handleRestartAtStateComplete")
	ctx.state = StateRestartWait
	return startNewRetryTimer(ctx)
}

func handleRestart(ctx *Context) error {
	ctx.log.Trace("handleRestart")
	ctx.restartRequestPending = true
	return nil
}

func handleNonceMismatchAtAttestWait(ctx *Context) error {
	ctx.log.Trace("handleNonceMismatchAtAttestWait")
	ctx.state = StateRestartWait
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
	ctx.state = StateRestartWait
	return startNewRetryTimer(ctx)
}

func handleInternalEscrowRecvdAtInternalEscrowWait(ctx *Context) error {
	ctx.log.Trace("handleInternalEscrowRecvdAtInternalEscrowWait")
	//try sending escrow data now
	return handleAttestSuccessfulAtAttestWait(ctx)
}

//handleInternalEscrowRecvdAtAnyOther handles EventInternalEscrowRecvd
//at any other state, other than StateInternalQuoteWait.
//for StateInternalQuoteWait, we have handleInternalEscrowRecvdAtInternalEscrowWait
func handleInternalEscrowRecvdAtAnyOther(ctx *Context) error {
	ctx.log.Trace("handleInternalEscrowRecvdAtAnyOther")
	switch ctx.state {
	case StateInternalEscrowWait:
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
	ctx.state = StateInternalEscrowWait
	return nil
}

func handleRetryTimerExpiryAtRestartWait(ctx *Context) error {
	ctx.log.Trace("handleRetryTimerExpiryAtRestartWait")
	ctx.state = StateNone
	ctx.restartRequestPending = false
	return triggerSelfEvent(ctx, EventInitialize)
}

func handleRetryTimerExpiryAtNonceWait(ctx *Context) error {
	ctx.log.Trace("handleRetryTimerExpiryAtNonceWait")
	ctx.state = StateNone
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

func despatchEvent(event Event, state State, ctx *Context) error {
	elem, ok := transitions[Transition{event: event, state: state}]
	if ok {
		return elem(ctx)
	}
	//Specific handler is not found, look for a wildcard handler
	elem, ok = transitions[Transition{event: event, state: StateAny}]
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

//EnterEventLoop is the eternel event loop for the state machine
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
