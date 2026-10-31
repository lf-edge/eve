// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package witnessstatus

import (
	"errors"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func reset() {
	mu.Lock()
	cached = types.WitnessStatus{}
	pub = nil
	mu.Unlock()
}

// TestErrorClearedOnRecovery: an error explains one state, so reaching
// another must not leave the old explanation attached.
func TestErrorClearedOnRecovery(t *testing.T) {
	reset()
	SetError(errors.New("join refused"), "10.244.244.5")
	got := Get()
	if got.State != types.WitnessEtcdStateError {
		t.Fatalf("State = %v, want Error", got.State)
	}
	if got.Error.Error == "" {
		t.Fatal("SetError recorded no error text")
	}
	SetState(types.WitnessEtcdStateJoined, "10.244.244.5")
	if got := Get(); got.Error.Error != "" {
		t.Errorf("error text survived recovery: %q", got.Error.Error)
	}
}

// TestIdleReportsNoWitnessIP: idle means no witness runs here, so
// echoing an address would suggest one does.
func TestIdleReportsNoWitnessIP(t *testing.T) {
	reset()
	SetState(types.WitnessEtcdStateJoined, "10.244.244.5")
	SetState(types.WitnessEtcdStateIdle, "")
	if got := Get(); got.WitnessIP != "" {
		t.Errorf("WitnessIP = %q, want empty when idle", got.WitnessIP)
	}
}

// TestPublishBeforeRegisterIsSafe: the kube role never registers this
// publication, and the witness reports state before pubsub is up.
func TestPublishBeforeRegisterIsSafe(t *testing.T) {
	reset()
	SetState(types.WitnessEtcdStateIdle, "")
	SetError(errors.New("x"), "")
}
