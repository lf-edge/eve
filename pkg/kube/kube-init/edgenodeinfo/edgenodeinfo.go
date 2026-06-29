// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package edgenodeinfo subscribes to pillar's EdgeNodeInfo topic
// (published by zedagent under /run/zedagent/EdgeNodeInfo/) and
// caches the latest payload behind accessors for the rest of
// kube-init.
//
// Replaces the per-package os.ReadFile + json.Unmarshal helpers
// the Go port previously carried (one in prereqs, one in k3s,
// one in update). The data model is identical — the same
// types.EdgeNodeInfo struct pillar publishes — only the delivery
// mechanism changes from polled file to pushed subscription.
//
// API shape:
//
//   - Register(m) hands the subscription to the shared
//     pubsubclient.Manager. Call once at startup from main.go
//     before m.Run is started.
//   - WaitForFirst(ctx) blocks until the first delivery arrives,
//     for boot-time code that cannot proceed without the device
//     identity (prereqs.WaitDeviceName).
//   - Get / DeviceName / DeviceID are non-blocking lookups for
//     steady-state code that has another reason to know the
//     device identity is already published (e.g. readiness
//     checks running long after onboarding).
package edgenodeinfo

import (
	"context"
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// SubscriptionLabel is the Manager label kube-init registers the
// EdgeNodeInfo subscription under. Exported so tests and future
// callers that need the Subscription handle directly (via
// Manager.Sub) can name it without re-typing the string.
const SubscriptionLabel = "EdgeNodeInfo"

// publisherAgentName is zedagent — the pillar agent that owns
// EdgeNodeInfo. Hard-coded because the topic ownership is a
// pillar-side architectural decision, not a kube-init config.
const publisherAgentName = "zedagent"

// State held across Register / WaitForFirst / Get. Hidden in the
// package so callers cannot accidentally mutate it.
var (
	mu       sync.RWMutex
	have     bool
	cached   types.EdgeNodeInfo
	firstCh  = make(chan struct{})
	firstSet bool
)

// Register creates the EdgeNodeInfo subscription on the supplied
// Manager. Handlers update the package-local cache; the first
// successful delivery closes firstCh so WaitForFirst returns. Safe
// to call once at startup; rejected if called more than once
// (Manager itself enforces label uniqueness).
func Register(m *pubsubclient.Manager) error {
	_, err := m.Register(SubscriptionLabel, pubsub.SubscriptionOptions{
		AgentName:     publisherAgentName,
		MyAgentName:   pubsubclient.AgentName,
		TopicImpl:     types.EdgeNodeInfo{},
		Persistent:    false,
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
	})
	return err
}

// handleCreate / handleModify share the same body — pubsub delivers
// Create on the first observation and Modify on subsequent ones,
// but we treat them identically because callers only care about
// "the latest published value".
func handleCreate(_ interface{}, _ string, val interface{}) {
	setCached(val.(types.EdgeNodeInfo))
}

func handleModify(_ interface{}, _ string, val interface{}, _ interface{}) {
	setCached(val.(types.EdgeNodeInfo))
}

// handleDelete marks the cache as empty. It does NOT close any
// channels — if a deletion happens after WaitForFirst returned,
// callers can observe the empty state via Get; if it happens before,
// the subsequent Create re-arms via setCached.
func handleDelete(_ interface{}, _ string, _ interface{}) {
	mu.Lock()
	have = false
	cached = types.EdgeNodeInfo{}
	mu.Unlock()
}

func setCached(v types.EdgeNodeInfo) {
	mu.Lock()
	cached = v
	have = true
	first := !firstSet
	firstSet = true
	mu.Unlock()
	if first {
		close(firstCh)
	}
}

// WaitForFirst blocks until the EdgeNodeInfo subscription delivers
// its first payload, then returns the cached value. ctx
// cancellation returns ctx.Err() so the caller can distinguish
// shutdown from "not yet". After the first delivery the channel
// stays closed, so subsequent calls return immediately with the
// current cache.
func WaitForFirst(ctx context.Context) (types.EdgeNodeInfo, error) {
	select {
	case <-firstCh:
		mu.RLock()
		defer mu.RUnlock()
		return cached, nil
	case <-ctx.Done():
		return types.EdgeNodeInfo{}, ctx.Err()
	}
}

// Get returns the cached EdgeNodeInfo. The bool is false when no
// delivery has arrived yet OR when the topic was deleted; callers
// that need to distinguish "never published" from "deleted after
// publish" should use WaitForFirst's channel-close as the "ever
// arrived" signal.
func Get() (types.EdgeNodeInfo, bool) {
	mu.RLock()
	defer mu.RUnlock()
	return cached, have
}

// DeviceName returns the cached DeviceName, or "" if no delivery
// has arrived yet. Convenience wrapper for the common case of
// "I just want the operator-chosen device name as a string".
func DeviceName() string {
	info, ok := Get()
	if !ok {
		return ""
	}
	return info.DeviceName
}

// DeviceID returns the cached DeviceID as a string, or "" if no
// delivery has arrived yet. The underlying field is uuid.UUID;
// the string form matches what the old os.ReadFile path returned.
func DeviceID() string {
	info, ok := Get()
	if !ok {
		return ""
	}
	return info.DeviceID.String()
}
