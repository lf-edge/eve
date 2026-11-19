// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
)

type tokenFakes struct {
	running     string
	rotatedTo   []string
	provisioned int
	pending     bool
}

func stubTokenDeps(t *testing.T, running string) *tokenFakes {
	t.Helper()
	f := &tokenFakes{running: running}
	origCM, origCP, origST, origRT, origPC :=
		isClusterMode, clusterConfigPresent, storedToken, rotateToNewToken, provisionConfig
	origRP, origMRP := restartPending, markRestartPending
	isClusterMode = func() (bool, error) { return true, nil }
	clusterConfigPresent = func() (bool, error) { return true, nil }
	storedToken = func() (string, error) { return f.running, nil }
	rotateToNewToken = func(_ context.Context, tok string) error {
		f.rotatedTo = append(f.rotatedTo, tok)
		return nil
	}
	provisionConfig = func(context.Context, bool) error { f.provisioned++; return nil }
	restartPending = func() (bool, error) { return f.pending, nil }
	markRestartPending = func() error { f.pending = true; return nil }
	t.Cleanup(func() {
		isClusterMode, clusterConfigPresent, storedToken, rotateToNewToken, provisionConfig =
			origCM, origCP, origST, origRT, origPC
		restartPending, markRestartPending = origRP, origMRP
		nextTokenAttempt = time.Time{}
		nextTokenRestart = time.Time{}
	})
	return f
}

// TestReconcileClusterTokenBacksOffAfterFailure: a failed rotation must
// not be retried on the very next health run.
func TestReconcileClusterTokenBacksOffAfterFailure(t *testing.T) {
	f := stubTokenDeps(t, "K10abc::server:old")
	rotateToNewToken = func(_ context.Context, tok string) error {
		f.rotatedTo = append(f.rotatedTo, tok)
		return errors.New("no quorum")
	}
	cs := &k3s.ClusterStatus{IsBootstrapNode: true, EncryptedToken: "new"}
	if err := ReconcileClusterToken(t.Context(), cs); err == nil {
		t.Fatal("want the rotation error")
	}
	if err := ReconcileClusterToken(t.Context(), cs); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(f.rotatedTo) != 1 {
		t.Errorf("rotated %d times, want 1 (second run inside the backoff)", len(f.rotatedTo))
	}
}

func TestReconcileClusterTokenRotatesChangedToken(t *testing.T) {
	f := stubTokenDeps(t, "K10abc::server:old")
	cs := &k3s.ClusterStatus{IsBootstrapNode: true, EncryptedToken: "new", ClusterID: "c2"}
	if err := ReconcileClusterToken(t.Context(), cs); err != nil {
		t.Fatalf("ReconcileClusterToken: %v", err)
	}
	if len(f.rotatedTo) != 1 || f.rotatedTo[0] != "new" {
		t.Errorf("rotated to %v, want [new]", f.rotatedTo)
	}
	if f.provisioned != 1 {
		t.Errorf("drop-in rewritten %d times, want 1", f.provisioned)
	}
	if !f.pending {
		t.Error("restart not armed after rotating")
	}
}

func TestReconcileClusterTokenNoOp(t *testing.T) {
	cases := []struct {
		name string
		cs   k3s.ClusterStatus
	}{
		{"token unchanged", k3s.ClusterStatus{IsBootstrapNode: true, EncryptedToken: "old"}},
		{"not bootstrap", k3s.ClusterStatus{EncryptedToken: "new"}},
	}
	for _, c := range cases {
		f := stubTokenDeps(t, "K10abc::server:old")
		if err := ReconcileClusterToken(t.Context(), &c.cs); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(f.rotatedTo) != 0 || f.provisioned != 0 {
			t.Errorf("%s: rotated %v, provisioned %d; want neither", c.name, f.rotatedTo, f.provisioned)
		}
	}
}

// TestReconcileClusterTokenSkipsTransition: a single→cluster transition
// has not written the drop-in yet and rotates the token itself.
func TestReconcileClusterTokenSkipsTransition(t *testing.T) {
	f := stubTokenDeps(t, "K10abc::server:single")
	clusterConfigPresent = func() (bool, error) { return false, nil }
	cs := &k3s.ClusterStatus{IsBootstrapNode: true, EncryptedToken: "new"}
	if err := ReconcileClusterToken(t.Context(), cs); err != nil {
		t.Fatalf("ReconcileClusterToken: %v", err)
	}
	if len(f.rotatedTo) != 0 {
		t.Errorf("rotated %v mid-transition", f.rotatedTo)
	}
}
