// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var testTLSCfg = tls.Config{} //nolint:gochecknoglobals

func httpResp(status int, contentType string) *http.Response {
	r := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{},
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

func newMyPostCtx(sender *fakeControllerSender) *clientContext {
	return &clientContext{
		sender:            sender,
		serverNameAndPort: "test.example:8080",
	}
}

func ledEqual(got, want []types.LedBlinkCount) bool {
	if len(want) == 0 && len(got) == 0 {
		return true
	}
	return reflect.DeepEqual(got, want)
}

func TestMyPost_SendErrorClassification(t *testing.T) {
	tests := []struct {
		name    string
		status  types.SenderStatus
		wantLed []types.LedBlinkCount
	}{
		{name: "upgrade", status: types.SenderStatusUpgrade},
		{name: "refused", status: types.SenderStatusRefused},
		{name: "cert invalid", status: types.SenderStatusCertInvalid},
		{name: "cert miss", status: types.SenderStatusCertMiss},
		{name: "not found emits connected", status: types.SenderStatusNotFound,
			wantLed: []types.LedBlinkCount{types.LedBlinkConnectedToController}},
		{name: "unknown sender status (default branch)", status: types.SenderStatusNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakeControllerSender{sends: []sendResponse{
				{rv: controllerconn.SendRetval{Status: tc.status}, err: errors.New("send failed")},
			}}
			led := &recordingLedNotifier{}
			ctx := newMyPostCtx(sender)

			done, _ := ctx.myPost(led, &testTLSCfg, "http://x/y", false, 0, bytes.NewBufferString(""))
			if done {
				t.Errorf("done = true, want false on send error")
			}
			if !ledEqual(led.patterns, tc.wantLed) {
				t.Errorf("led = %v, want %v", led.patterns, tc.wantLed)
			}
		})
	}
}

func TestMyPost_HTTPStatusBranches(t *testing.T) {
	tests := []struct {
		name      string
		resp      *http.Response
		body      []byte
		wantDone  bool
		wantLed   []types.LedBlinkCount
		authError error
	}{
		{
			name:     "200 with empty body",
			resp:     httpResp(http.StatusOK, "application/x-proto-binary"),
			wantDone: true,
			wantLed:  []types.LedBlinkCount{types.LedBlinkOnboarded},
		},
		{
			name:     "201 Created with empty body",
			resp:     httpResp(http.StatusCreated, "application/x-proto-binary"),
			wantDone: true,
			wantLed:  []types.LedBlinkCount{types.LedBlinkOnboarded},
		},
		{
			name:     "409 Conflict",
			resp:     httpResp(http.StatusConflict, "application/x-proto-binary"),
			wantDone: false,
			wantLed:  []types.LedBlinkCount{types.LedBlinkOnboardingFailure},
		},
		{
			name:     "404 Not Found",
			resp:     httpResp(http.StatusNotFound, "application/x-proto-binary"),
			wantDone: false,
			wantLed:  []types.LedBlinkCount{types.LedBlinkConnectedToController},
		},
		{
			name:     "401 Unauthorized",
			resp:     httpResp(http.StatusUnauthorized, "application/x-proto-binary"),
			wantDone: false,
			wantLed:  []types.LedBlinkCount{types.LedBlinkConnectedToController},
		},
		{
			name:     "304 Not Modified",
			resp:     httpResp(http.StatusNotModified, "application/x-proto-binary"),
			wantDone: false,
			wantLed:  []types.LedBlinkCount{types.LedBlinkConnectedToController},
		},
		{
			name:     "500 default branch",
			resp:     httpResp(http.StatusInternalServerError, "application/x-proto-binary"),
			wantDone: false,
			wantLed:  []types.LedBlinkCount{types.LedBlinkConnectedToController},
		},
		{
			name:     "200 missing content-type",
			resp:     httpResp(http.StatusOK, ""),
			wantDone: false,
			wantLed:  []types.LedBlinkCount{types.LedBlinkOnboarded},
		},
		{
			name:     "200 unparseable content-type",
			resp:     httpResp(http.StatusOK, "garbage; ; ;"),
			wantDone: false,
			wantLed:  []types.LedBlinkCount{types.LedBlinkOnboarded},
		},
		{
			name:     "200 unsupported MIME",
			resp:     httpResp(http.StatusOK, "text/html"),
			wantDone: false,
			wantLed:  []types.LedBlinkCount{types.LedBlinkOnboarded},
		},
		{
			name:     "200 with body and auth verify ok",
			resp:     httpResp(http.StatusOK, "application/x-proto-binary"),
			body:     []byte("payload"),
			wantDone: true,
			wantLed:  []types.LedBlinkCount{types.LedBlinkOnboarded},
		},
		{
			name:      "200 with body and auth verify fails",
			resp:      httpResp(http.StatusOK, "application/x-proto-binary"),
			body:      []byte("payload"),
			authError: errors.New("bad container"),
			wantDone:  false,
			wantLed:   []types.LedBlinkCount{types.LedBlinkOnboarded, types.LedBlinkInvalidAuthContainer},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakeControllerSender{
				sends: []sendResponse{
					{rv: controllerconn.SendRetval{HTTPResp: tc.resp, RespContents: tc.body}},
				},
				authVerifyErr: tc.authError,
			}
			led := &recordingLedNotifier{}
			ctx := newMyPostCtx(sender)

			done, _ := ctx.myPost(led, &testTLSCfg, "http://x/y", false, 0, bytes.NewBufferString(""))
			if done != tc.wantDone {
				t.Errorf("done = %v, want %v", done, tc.wantDone)
			}
			if !ledEqual(led.patterns, tc.wantLed) {
				t.Errorf("led = %v, want %v", led.patterns, tc.wantLed)
			}
			if tc.body != nil && tc.authError == nil && sender.authVerifyCalls != 1 {
				t.Errorf("authVerifyCalls = %d, want 1", sender.authVerifyCalls)
			}
		})
	}
}
