// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
)

type fakeRestartAPI struct {
	published string
	notReady  bool
	holder    string
	restarts  int
}

func (f *fakeRestartAPI) PublishedHash(context.Context) (string, error) { return f.published, nil }
func (f *fakeRestartAPI) Publish(_ context.Context, h string) error     { f.published = h; return nil }
func (f *fakeRestartAPI) AllNodesReady(context.Context) (bool, error)   { return !f.notReady, nil }
func (f *fakeRestartAPI) HoldsLease(_ context.Context, h string) (bool, error) {
	return f.holder == h, nil
}
func (f *fakeRestartAPI) AcquireLease(_ context.Context, h string, _ time.Time) (bool, error) {
	if f.holder != "" && f.holder != h {
		return false, nil
	}
	f.holder = h
	return true, nil
}
func (f *fakeRestartAPI) ReleaseLease(_ context.Context, h string) error {
	if f.holder == h {
		f.holder = ""
	}
	return nil
}

func stubRestartAPI(t *testing.T, api *fakeRestartAPI) {
	t.Helper()
	orig := newTokenRestartAPI
	newTokenRestartAPI = func() (tokenRestartAPI, error) { return api, nil }
	t.Cleanup(func() { newTokenRestartAPI = orig })
}

func reconcileRestart(t *testing.T, cs *k3s.ClusterStatus, node string, api *fakeRestartAPI) {
	t.Helper()
	if err := ReconcileTokenRestart(t.Context(), cs, node, func() { api.restarts++ }); err != nil {
		t.Fatalf("ReconcileTokenRestart(%s): %v", node, err)
	}
}

// TestTokenRestartBootstrapFirstThenMembers walks one rotation: the
// bootstrap node restarts and publishes, then one member at a time.
func TestTokenRestartBootstrapFirstThenMembers(t *testing.T) {
	f := stubTokenDeps(t, "K10abc::server:new")
	api := &fakeRestartAPI{published: k3s.TokenHash("old")}
	stubRestartAPI(t, api)
	boot := &k3s.ClusterStatus{IsBootstrapNode: true, EncryptedToken: "new"}
	member := &k3s.ClusterStatus{EncryptedToken: "new"}

	// Rotated, not yet restarted: members must wait for the publish.
	f.pending = true
	f.running = "K10abc::server:old"
	reconcileRestart(t, member, "m1", api)
	if api.restarts != 0 {
		t.Fatal("member restarted before the bootstrap node published")
	}
	f.running = "K10abc::server:new"
	reconcileRestart(t, boot, "b", api)
	if api.restarts != 1 || api.holder != "b" {
		t.Fatalf("bootstrap: restarts %d, holder %q; want 1, b", api.restarts, api.holder)
	}
	if api.published == k3s.TokenHash("new") {
		t.Fatal("published before the bootstrap node restarted")
	}

	// Bootstrap back up: it publishes and releases.
	f.pending = false
	reconcileRestart(t, boot, "b", api)
	if api.published != k3s.TokenHash("new") || api.holder != "" {
		t.Fatalf("after restart: published %q, holder %q", api.published, api.holder)
	}

	// Members take turns.
	f.running = "K10abc::server:old"
	reconcileRestart(t, member, "m1", api)
	reconcileRestart(t, member, "m2", api)
	if api.restarts != 2 || api.holder != "m1" {
		t.Fatalf("members: restarts %d, holder %q; want 2, m1", api.restarts, api.holder)
	}
	f.running = "K10abc::server:new"
	reconcileRestart(t, member, "m1", api)
	if api.holder != "" {
		t.Errorf("m1 kept the lease after restarting on the new token")
	}
}

func TestTokenRestartWaitsForAllNodesReady(t *testing.T) {
	stubTokenDeps(t, "K10abc::server:old")
	api := &fakeRestartAPI{published: k3s.TokenHash("new"), notReady: true}
	stubRestartAPI(t, api)
	reconcileRestart(t, &k3s.ClusterStatus{EncryptedToken: "new"}, "m1", api)
	if api.restarts != 0 || api.holder != "" {
		t.Errorf("restarted with a node not Ready")
	}
}

// TestLeaseFree: a holder that died mid-restart must not block the others
// beyond the lease duration.
func TestLeaseFree(t *testing.T) {
	now := time.Now()
	held := func(holder string, renewed time.Time) *coordinationv1.Lease {
		t := metav1.NewMicroTime(renewed)
		return &coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptr.To(holder),
			LeaseDurationSeconds: ptr.To(int32(tokenRestartLeaseDuration / time.Second)),
			RenewTime:            &t,
		}}
	}
	cases := []struct {
		name string
		l    *coordinationv1.Lease
		want bool
	}{
		{"unheld", &coordinationv1.Lease{}, true},
		{"ours", held("m1", now), true},
		{"other, live", held("m2", now), false},
		{"other, expired", held("m2", now.Add(-tokenRestartLeaseDuration-time.Second)), true},
	}
	for _, c := range cases {
		if got := leaseFree(c.l, "m1", now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
