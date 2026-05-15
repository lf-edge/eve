// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"net/http"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func newSelfRegisterCtx(sender *fakeControllerSender, led ledNotifier) *clientContext {
	return &clientContext{
		sender:            sender,
		led:               led,
		serverNameAndPort: "test.example:8080",
	}
}

// Note: selfRegister currently always returns done=false when myPost
// produced any HTTP response (the `done = false` override at the end of
// the HTTPResp != nil block). Success is declared later by doGetUUID.
// These tests assert the LED pattern emitted for each status code; the
// done value is exercised only on the no-response path.

func TestSelfRegister_StatusCodeLEDPatterns(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantLed []types.LedBlinkCount
	}{
		{
			name:    "200 - onboarded only (no override branch)",
			status:  http.StatusOK,
			wantLed: []types.LedBlinkCount{types.LedBlinkOnboarded},
		},
		{
			name:    "201 - onboarded only (no override branch)",
			status:  http.StatusCreated,
			wantLed: []types.LedBlinkCount{types.LedBlinkOnboarded},
		},
		{
			name:    "400 - connected then onboarding failure",
			status:  http.StatusBadRequest,
			wantLed: []types.LedBlinkCount{types.LedBlinkConnectedToController, types.LedBlinkOnboardingFailure},
		},
		{
			name:    "504 - connected then onboarding failure",
			status:  http.StatusGatewayTimeout,
			wantLed: []types.LedBlinkCount{types.LedBlinkConnectedToController, types.LedBlinkOnboardingFailure},
		},
		{
			name:    "500 - connected then onboarding failure",
			status:  http.StatusInternalServerError,
			wantLed: []types.LedBlinkCount{types.LedBlinkConnectedToController, types.LedBlinkOnboardingFailure},
		},
		{
			name:    "403 - connected then onboarding failure not found",
			status:  http.StatusForbidden,
			wantLed: []types.LedBlinkCount{types.LedBlinkConnectedToController, types.LedBlinkOnboardingFailureNotFound},
		},
		{
			name:    "409 - onboarding failure then conflict",
			status:  http.StatusConflict,
			wantLed: []types.LedBlinkCount{types.LedBlinkOnboardingFailure, types.LedBlinkOnboardingFailureConflict},
		},
		{
			name:    "304 - connected then conflict",
			status:  http.StatusNotModified,
			wantLed: []types.LedBlinkCount{types.LedBlinkConnectedToController, types.LedBlinkOnboardingFailureConflict},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakeControllerSender{sends: []sendResponse{
				{rv: controllerconn.SendRetval{HTTPResp: httpResp(tc.status, "application/x-proto-binary")}},
			}}
			led := &recordingLedNotifier{}
			ctx := newSelfRegisterCtx(sender, led)

			done := ctx.selfRegister(&testTLSCfg, []byte("device-cert-pem"), 0)
			if done {
				t.Errorf("done = true; selfRegister always returns false when an HTTP response is received")
			}
			if !ledEqual(led.patterns, tc.wantLed) {
				t.Errorf("led = %v, want %v", led.patterns, tc.wantLed)
			}
		})
	}
}

func TestSelfRegister_NetworkErrorNoLED(t *testing.T) {
	sender := &fakeControllerSender{sends: []sendResponse{
		{rv: controllerconn.SendRetval{Status: types.SenderStatusUpgrade}, err: errors.New("net err")},
	}}
	led := &recordingLedNotifier{}
	ctx := newSelfRegisterCtx(sender, led)

	done := ctx.selfRegister(&testTLSCfg, []byte("device-cert-pem"), 0)
	if done {
		t.Errorf("done = true, want false on network error")
	}
	if len(led.patterns) != 0 {
		t.Errorf("led = %v, want no emissions when HTTPResp is nil", led.patterns)
	}
}

func TestSelfRegister_LedManagerDisabled(t *testing.T) {
	sender := &fakeControllerSender{
		ledManagerDisabled: true,
		sends: []sendResponse{
			{rv: controllerconn.SendRetval{HTTPResp: httpResp(http.StatusBadRequest, "application/x-proto-binary")}},
		},
	}
	led := &recordingLedNotifier{}
	ctx := newSelfRegisterCtx(sender, led)

	_ = ctx.selfRegister(&testTLSCfg, []byte("device-cert-pem"), 0)
	if len(led.patterns) != 0 {
		t.Errorf("led = %v, want no emissions when LED manager disabled", led.patterns)
	}
}
