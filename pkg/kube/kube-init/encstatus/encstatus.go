// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package encstatus subscribes to pillar's EdgeNodeClusterStatus
// topic (published by zedkube under
// /run/zedkube/EdgeNodeClusterStatus/) and caches the latest
// payload behind accessors.
//
// EdgeNodeClusterStatus is the load-bearing topic for kube-init:
// it carries the bootstrap server IP, encrypted cluster token,
// per-node cluster IP + prefix, and the ClusterID UUID that
// gates the single↔cluster transitions.
//
// kube-init consumes it across several layers:
//
//   - k3s.GetClusterStatus translates the raw pillar payload
//     into the simpler ClusterStatus the rest of kube-init
//     consumes (string IPs, parsed mask, validated invariants).
//   - k3s.ClusterStatusPresent gates the cluster-config monitor's
//     transition decisions on whether a live cluster exists.
//   - waitForBootstrapServer uses Present() to bail out cleanly
//     when the controller withdraws the cluster mid-join.
//
// Per-tick reads in steady state; the subscription is not
// Persistent (zedkube publishes to /run only).
package encstatus

import (
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// SubscriptionLabel is the Manager label kube-init registers
// this subscription under.
const SubscriptionLabel = "EdgeNodeClusterStatus"

// publisherAgentName is zedkube — the pillar agent that owns
// EdgeNodeClusterStatus. Publication is /run-only.
const publisherAgentName = "zedkube"

var (
	mu          sync.RWMutex
	have        bool
	cached      types.EdgeNodeClusterStatus
	subscribers []chan struct{}
)

// Register creates the EdgeNodeClusterStatus subscription on
// the supplied Manager. Handlers update the package-local
// cache.
func Register(m *pubsubclient.Manager) error {
	_, err := m.Register(SubscriptionLabel, pubsub.SubscriptionOptions{
		AgentName:     publisherAgentName,
		MyAgentName:   pubsubclient.AgentName,
		TopicImpl:     types.EdgeNodeClusterStatus{},
		Persistent:    false,
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
	})
	return err
}

func handleCreate(_ interface{}, _ string, val interface{}) {
	setCached(val.(types.EdgeNodeClusterStatus))
}

func handleModify(_ interface{}, _ string, val interface{}, _ interface{}) {
	setCached(val.(types.EdgeNodeClusterStatus))
}

func handleDelete(_ interface{}, _ string, _ interface{}) {
	mu.Lock()
	have = false
	cached = types.EdgeNodeClusterStatus{}
	subs := append([]chan struct{}(nil), subscribers...)
	mu.Unlock()
	notify(subs)
}

func setCached(v types.EdgeNodeClusterStatus) {
	mu.Lock()
	cached = v
	have = true
	subs := append([]chan struct{}(nil), subscribers...)
	mu.Unlock()
	notify(subs)
}

// notify fans out a non-blocking edge to every subscriber. The
// channel is buffered size-1 so a slow consumer still gets at
// least one wake-up per burst; further edges coalesce harmlessly.
func notify(subs []chan struct{}) {
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Subscribe returns a buffered (size-1) channel that receives an
// empty struct on every cache change (create, modify, or delete).
// The cancel function removes the channel from the fan-out list;
// callers MUST invoke it on shutdown to avoid leaking subscribers.
//
// The channel is coalescing: bursts of changes deliver at most
// one wake-up. Consumers read the current state with Get/Present
// after each wake.
func Subscribe() (ch <-chan struct{}, cancel func()) {
	c := make(chan struct{}, 1)
	mu.Lock()
	subscribers = append(subscribers, c)
	mu.Unlock()
	return c, func() {
		mu.Lock()
		for i, x := range subscribers {
			if x == c {
				subscribers = append(subscribers[:i], subscribers[i+1:]...)
				break
			}
		}
		mu.Unlock()
	}
}

// Get returns the cached EdgeNodeClusterStatus. The bool is
// false when no delivery has arrived yet OR after a Delete.
// Callers that need the kube-init-flavoured ClusterStatus view
// use k3s.GetClusterStatus, which validates + translates on top
// of this raw cache.
func Get() (types.EdgeNodeClusterStatus, bool) {
	mu.RLock()
	defer mu.RUnlock()
	return cached, have
}

// Present reports whether the cached payload represents a live
// cluster: a delivery has occurred AND the ClusterID UUID is
// non-zero. A zero UUID is how pillar signals a controller-side
// cluster delete on a non-Persistent topic — the publication
// stays but its content goes to the zero sentinel — so callers
// like the cluster-config monitor must distinguish "no cluster"
// from "joining a cluster but UUID not assigned yet".
func Present() bool {
	mu.RLock()
	defer mu.RUnlock()
	return have && cached.ClusterID.UUID != uuid.Nil
}

// SetForTest seeds the cache with a fixed value. Exported so
// cross-package tests can stage a particular status.
func SetForTest(v types.EdgeNodeClusterStatus) {
	setCached(v)
}

// ResetForTest wipes the cache.
func ResetForTest() {
	mu.Lock()
	have = false
	cached = types.EdgeNodeClusterStatus{}
	mu.Unlock()
}
