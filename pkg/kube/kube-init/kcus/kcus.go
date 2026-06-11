// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kcus subscribes to pillar's KubeClusterUpdateStatus
// topic and caches the latest payload behind accessors.
//
// KubeClusterUpdateStatus is zedagent's record of per-node
// component-update progress: which KubeVersion is the target,
// what stage we're at (downloading/installing/completed/failed),
// and which node is acting. kube-init reads it in
// update.updateFailed to decide whether the current generation's
// upgrade attempt has already failed once — if it has, the
// per-tick retry is skipped to avoid thrashing.
//
// Per-tick read; no boot-time blocking wait. Subscription
// Persistent=true because the topic file lives under /persist (it
// has to survive a reboot mid-upgrade to gate the next boot's
// retry).
//
// Latent bug fixed by the migration. The file-reading port
// declared a local kcusJSON with DestinationKubeUpdateVersion
// typed as string, but pillar's KubeClusterUpdateStatus has it as
// uint32 — JSON serialised as a number, not a quoted string —
// so encoding/json silently zeroed the field and the
// "fail-fast on same-version retry" gate never fired. Using
// pillar's struct directly via TopicImpl makes the comparison
// exact and the bug goes away.
package kcus

import (
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// SubscriptionLabel is the Manager label kube-init registers this
// subscription under.
const SubscriptionLabel = "KubeClusterUpdateStatus"

// publisherAgentName is zedagent — see the explicit comment in
// pkg/pillar/cmd/zedagent's pubKubeClusterUpdateStatus
// NewPublication call. The file lives under
// /persist/status/zedagent/KubeClusterUpdateStatus/global.json,
// not under .../zedkube/, which the file-reading shell port had
// wrong.
const publisherAgentName = "zedagent"

var (
	mu     sync.RWMutex
	have   bool
	cached types.KubeClusterUpdateStatus
)

// Register creates the KubeClusterUpdateStatus subscription on
// the supplied Manager. Handlers update the package-local cache.
func Register(m *pubsubclient.Manager) error {
	_, err := m.Register(SubscriptionLabel, pubsub.SubscriptionOptions{
		AgentName:     publisherAgentName,
		MyAgentName:   pubsubclient.AgentName,
		TopicImpl:     types.KubeClusterUpdateStatus{},
		Persistent:    true,
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
	})
	return err
}

func handleCreate(_ interface{}, _ string, val interface{}) {
	setCached(val.(types.KubeClusterUpdateStatus))
}

func handleModify(_ interface{}, _ string, val interface{}, _ interface{}) {
	setCached(val.(types.KubeClusterUpdateStatus))
}

func handleDelete(_ interface{}, _ string, _ interface{}) {
	mu.Lock()
	have = false
	cached = types.KubeClusterUpdateStatus{}
	mu.Unlock()
}

func setCached(v types.KubeClusterUpdateStatus) {
	mu.Lock()
	cached = v
	have = true
	mu.Unlock()
}

// Get returns the cached KubeClusterUpdateStatus. The bool is
// false when no delivery has arrived yet OR after a Delete. The
// caller treats !ok as "no prior failure" so a missing or empty
// status never blocks a retry.
func Get() (types.KubeClusterUpdateStatus, bool) {
	mu.RLock()
	defer mu.RUnlock()
	return cached, have
}

// SetForTest seeds the cache with a fixed value. Exported so
// other packages' tests can stage a particular status without
// going through Register. Pair with ResetForTest in t.Cleanup so
// state does not leak between tests.
func SetForTest(v types.KubeClusterUpdateStatus) {
	setCached(v)
}

// ResetForTest wipes the cache. Pair with SetForTest in
// t.Cleanup. Idempotent.
func ResetForTest() {
	mu.Lock()
	have = false
	cached = types.KubeClusterUpdateStatus{}
	mu.Unlock()
}
