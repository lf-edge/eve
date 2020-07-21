// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package attest

import "testing"
import "time"
import "fmt"

type VerifierMock struct{}

var (
	simulateControllerUnavailable = false
	simulateNonceMismatch         = false
	simulateQuoteMismatch         = false
	simulateNoCertToValidate      = false
	simulateITokenMismatch        = false
	simulateTpmAgentDown          = false
)

func (server *VerifierMock) SendNonceRequest(ctx *Context) error {
	if simulateControllerUnavailable == true {
		fmt.Printf("Simulating Controller being down\n")
		return ErrControllerUnavailable
	}

	return nil
}

func (server *VerifierMock) SendAttestQuote(ctx *Context) error {
	if simulateControllerUnavailable == true {
		fmt.Printf("Simulating Controller being down\n")
		return ErrControllerUnavailable
	}

	if simulateNonceMismatch == true {
		fmt.Printf("Simulating Nonce mismatch\n")
		return ErrNonceMismatch
	}

	if simulateQuoteMismatch == true {
		fmt.Printf("Simulating Quote mismatch\n")
		return ErrQuoteMismatch
	}

	if simulateNoCertToValidate == true {
		fmt.Printf("Simulating No quote cert in Controller\n")
		return ErrNoCertYet
	}

	return nil
}

func (server *VerifierMock) SendAttestEscrow(ctx *Context) error {
	if simulateControllerUnavailable == true {
		fmt.Printf("Simulating Controller being down\n")
		return ErrControllerUnavailable
	}

	if simulateITokenMismatch == true {
		return ErrInfoTokenInvalid
	}

	return nil
}

type TpmAgentMock struct{}

func (agent *TpmAgentMock) SendInternalQuoteRequest(ctx *Context) error {
	if simulateTpmAgentDown {
		return ErrTpmAgentUnavailable
	}
	return nil
}

func initTest() *Context {
	tpmAgent = &TpmAgentMock{}
	verifier = &VerifierMock{}
	simulateControllerUnavailable = false
	simulateNonceMismatch = false
	simulateQuoteMismatch = false
	simulateNoCertToValidate = false
	simulateITokenMismatch = false
	simulateTpmAgentDown = false

	ctx := &Context{
		event:        EventInitialize,
		state:        StateNone,
		restartTimer: time.NewTimer(1 * time.Second),
		eventTrigger: make(chan Event),
		retryTime:    1,
	}
	ctx.restartTimer.Stop()
	return ctx
}

func TestGoodPath(t *testing.T) {
	fmt.Println("------TestGoodPath-------")
	ctx := initTest()
	stopTrigger := make(chan int)

	go func() {
		ctx.eventTrigger <- EventInitialize
		for ctx.state != StateInternalQuoteWait {
			time.Sleep(1 * time.Second)
		}
		ctx.eventTrigger <- EventInternalQuoteRecvd
		time.Sleep(10 * time.Second)
		stopTrigger <- 1
	}()
	for {
		select {
		case trigger := <-ctx.eventTrigger:
			if err := despatchEvent(trigger, ctx.state, ctx); err != nil {
				t.Errorf("%v", err)
			}
		case <-stopTrigger:
			if ctx.state != StateComplete {
				t.Errorf("Expected %s, Got %s", StateComplete.String(), ctx.state.String())
			}
			return
		}
	}
}

func TestNonceMismatch(t *testing.T) {
	fmt.Println("-------TestNonceMismatch---")
	ctx := initTest()
	simulateNonceMismatch = true

	go func() {
		ctx.eventTrigger <- EventInitialize
		for ctx.state != StateInternalQuoteWait {
			time.Sleep(1 * time.Second)
		}
		ctx.eventTrigger <- EventInternalQuoteRecvd
	}()
	for {
		select {
		case trigger := <-ctx.eventTrigger:
			if err := despatchEvent(trigger, ctx.state, ctx); err != nil {
				t.Errorf("%v", err)
			}
		case <-ctx.restartTimer.C:
			if ctx.state != StateRestartWait {
				t.Errorf("Expected %s, Got %s", StateRestartWait.String(), ctx.state.String())
			}
			return
		}
	}
}

func TestQuoteMismatch(t *testing.T) {
	fmt.Println("-------TestQuoteMismatch------")
	ctx := initTest()
	simulateQuoteMismatch = true

	go func() {
		ctx.eventTrigger <- EventInitialize
		for ctx.state != StateInternalQuoteWait {
			time.Sleep(1 * time.Second)
		}
		ctx.eventTrigger <- EventInternalQuoteRecvd
	}()
	for {
		select {
		case trigger := <-ctx.eventTrigger:
			if err := despatchEvent(trigger, ctx.state, ctx); err != nil {
				t.Errorf("%v", err)
			}
		case <-ctx.restartTimer.C:
			if ctx.state != StateRestartWait {
				t.Errorf("Expected %s, Got %s", StateRestartWait.String(), ctx.state.String())
			}
			return
		}
	}
}

func TestNoCertInController(t *testing.T) {
	fmt.Println("-------TestNoCertInController------")
	ctx := initTest()
	simulateNoCertToValidate = true

	go func() {
		ctx.eventTrigger <- EventInitialize
		for ctx.state != StateInternalQuoteWait {
			time.Sleep(1 * time.Second)
		}
		ctx.eventTrigger <- EventInternalQuoteRecvd
	}()
	for {
		select {
		case trigger := <-ctx.eventTrigger:
			if err := despatchEvent(trigger, ctx.state, ctx); err != nil {
				t.Errorf("%v", err)
			}
		case <-ctx.restartTimer.C:
			if ctx.state != StateRestartWait {
				t.Errorf("Expected %s, Got %s", StateRestartWait.String(), ctx.state.String())
			}
			return
		}
	}
}

func TestControllerNotAvbleInNonceWait(t *testing.T) {
	fmt.Println("-----TestControllerNotAvbleInNonceWait--")
	ctx := initTest()
	simulateControllerUnavailable = true

	go func() {
		ctx.eventTrigger <- EventInitialize
		for ctx.state != StateInternalQuoteWait {
			time.Sleep(1 * time.Second)
		}
		ctx.eventTrigger <- EventInternalQuoteRecvd
	}()
	for {
		select {
		case trigger := <-ctx.eventTrigger:
			if err := despatchEvent(trigger, ctx.state, ctx); err != nil {
				t.Errorf("%v", err)
			}
		case <-ctx.restartTimer.C:
			if ctx.state != StateNonceWait {
				t.Errorf("Expected %s, Got %s", StateNonceWait.String(), ctx.state.String())
			}
			return
		}
	}
}

func TestControllerNotAvbleInAttestWait(t *testing.T) {
	fmt.Println("--------TestControllerNotAvbleInAttestWait----")
	ctx := initTest()

	go func() {
		ctx.state = StateInternalQuoteWait
		simulateControllerUnavailable = true
		ctx.eventTrigger <- EventInternalQuoteRecvd
	}()
	for {
		select {
		case trigger := <-ctx.eventTrigger:
			if err := despatchEvent(trigger, ctx.state, ctx); err != nil {
				t.Errorf("%v", err)
			}
		case <-ctx.restartTimer.C:
			if ctx.state != StateAttestWait {
				t.Errorf("Expected %s, Got %s", StateAttestWait.String(), ctx.state.String())
			}
			return
		}
	}
}

func TestControllerNotAvbleInAttestEscrowWait(t *testing.T) {
	fmt.Println("--------TestControllerNotAvbleInAttestEscrowWait----")
	ctx := initTest()

	go func() {
		ctx.state = StateAttestWait
		simulateControllerUnavailable = true
		ctx.eventTrigger <- EventAttestSuccessful
	}()
	for {
		select {
		case trigger := <-ctx.eventTrigger:
			if err := despatchEvent(trigger, ctx.state, ctx); err != nil {
				t.Errorf("%v", err)
			}
		case <-ctx.restartTimer.C:
			if ctx.state != StateAttestEscrowWait {
				t.Errorf("Expected %s, Got %s", StateAttestEscrowWait.String(), ctx.state.String())
			}
			return
		}
	}
}
