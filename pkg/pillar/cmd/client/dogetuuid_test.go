// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"net/http"
	"testing"
	"time"

	eveuuid "github.com/lf-edge/eve-api/go/eveuuid"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
)

func mustMarshalUUIDResponse(t *testing.T, msg *eveuuid.UuidResponse) []byte {
	t.Helper()
	b, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return b
}

func newDoGetUUIDCtx(sender *fakeControllerSender, led ledNotifier) *clientContext {
	ctx := &clientContext{
		sender:            sender,
		led:               led,
		serverNameAndPort: "test.example:8080",
		getCertsTimer:     time.NewTimer(time.Hour),
	}
	ctx.getCertsTimer.Stop()
	return ctx
}

func TestDoGetUUID_SuccessExtractsUUIDAndLEDs(t *testing.T) {
	const goodUUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	body := mustMarshalUUIDResponse(t, &eveuuid.UuidResponse{
		Uuid:         goodUUID,
		Manufacturer: "Dell",
		ProductName:  "PowerEdge R740",
	})
	sender := &fakeControllerSender{sends: []sendResponse{
		{rv: controllerconn.SendRetval{
			HTTPResp:     httpResp(http.StatusOK, "application/x-proto-binary"),
			RespContents: body,
		}},
	}}
	led := &recordingLedNotifier{}
	ctx := newDoGetUUIDCtx(sender, led)

	done, devUUID, model := ctx.doGetUUID(&testTLSCfg, 0)
	if !done {
		t.Fatal("done = false, want true")
	}
	if devUUID.String() != goodUUID {
		t.Errorf("devUUID = %s, want %s", devUUID, goodUUID)
	}
	if model != "Dell.PowerEdge R740" {
		t.Errorf("model = %q, want %q", model, "Dell.PowerEdge R740")
	}
	// myPost emits Onboarded for 200; doGetUUID emits Onboarded again on parse success.
	wantLed := []types.LedBlinkCount{types.LedBlinkOnboarded, types.LedBlinkOnboarded}
	if !ledEqual(led.patterns, wantLed) {
		t.Errorf("led = %v, want %v", led.patterns, wantLed)
	}
}

func TestDoGetUUID_CertMissSchedulesTimer(t *testing.T) {
	sender := &fakeControllerSender{sends: []sendResponse{
		{rv: controllerconn.SendRetval{Status: types.SenderStatusCertMiss}, err: errors.New("cert miss")},
	}}
	led := &recordingLedNotifier{}
	ctx := newDoGetUUIDCtx(sender, led)

	done, _, _ := ctx.doGetUUID(&testTLSCfg, 0)
	if done {
		t.Error("done = true, want false on cert miss")
	}
	if ctx.getCertsTimer == nil {
		t.Fatal("getCertsTimer = nil, want a re-armed timer")
	}
	select {
	case <-ctx.getCertsTimer.C:
	case <-time.After(2 * time.Second):
		t.Fatal("getCertsTimer did not fire within 2s; was not re-armed by doGetUUID")
	}
}

func TestDoGetUUID_ParseFailureReturnsFalse(t *testing.T) {
	sender := &fakeControllerSender{sends: []sendResponse{
		{rv: controllerconn.SendRetval{
			HTTPResp:     httpResp(http.StatusOK, "application/x-proto-binary"),
			RespContents: []byte("not a valid uuid response proto"),
		}},
	}}
	led := &recordingLedNotifier{}
	ctx := newDoGetUUIDCtx(sender, led)

	done, _, _ := ctx.doGetUUID(&testTLSCfg, 0)
	if done {
		t.Error("done = true, want false on parse failure")
	}
}

func TestDoGetUUID_NetworkErrorNoTimer(t *testing.T) {
	sender := &fakeControllerSender{sends: []sendResponse{
		{rv: controllerconn.SendRetval{Status: types.SenderStatusRefused}, err: errors.New("refused")},
	}}
	led := &recordingLedNotifier{}
	ctx := newDoGetUUIDCtx(sender, led)

	// Drain any pre-set timer to ensure the test observes a fresh state.
	select {
	case <-ctx.getCertsTimer.C:
	default:
	}
	done, _, _ := ctx.doGetUUID(&testTLSCfg, 0)
	if done {
		t.Error("done = true, want false on network error")
	}
	// Timer must remain quiescent (no fresh re-arm on this code path).
	select {
	case <-ctx.getCertsTimer.C:
		t.Error("getCertsTimer fired on non-CertMiss network error; should not have re-armed")
	case <-time.After(100 * time.Millisecond):
	}
}
