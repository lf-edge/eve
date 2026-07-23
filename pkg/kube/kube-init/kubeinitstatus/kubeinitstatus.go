// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kubeinitstatus is a kube-init-local pubsub topic that
// publishes the daemon's high-level lifecycle phase so other
// goroutines can wake up event-driven rather than polling state
// markers.
//
// Today the topic carries a single bit, AllComponentsInitialized,
// which gates the cluster-config monitor's transition decisions.
// The struct has room for additional phase signals (e.g. "k3s
// fully ready", "longhorn settled") without breaking the wire
// shape.
//
// kube-init is BOTH publisher and subscriber. We use pillar's
// pubsub bus (not an in-process channel) for symmetry with the
// other kube-init topics and to keep the lifecycle observable
// from outside the process — operators can inspect
// /run/kube-init/KubeInitStatus/global.json to see the current
// phase.
//
// The on-disk file marker at state.AllComponentsInitialized is
// kept for cross-package readers that only need "are we past
// bootstrap?" semantics (k3s.config, components/) — those callers
// don't need event-driven wake-ups and the file is the simpler
// primitive for them. main.go writes both in lock-step so the two
// never disagree.
package kubeinitstatus

import (
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// KubeInitStatus is the published payload. Single struct so the
// topic key set stays trivial (always "global").
type KubeInitStatus struct {
	// AllComponentsInitialized goes true exactly once per daemon
	// lifetime, after the deploy graph has succeeded and the
	// on-disk marker has been written.
	AllComponentsInitialized bool
}

// Key implements pubsub.LocalCollection so the publication
// indexes by a fixed global key — there is only one
// kube-init-status per daemon.
func (KubeInitStatus) Key() string { return "global" }

// SubscriptionLabel is the Manager label kube-init registers
// the subscription under.
const SubscriptionLabel = "KubeInitStatus"

// publisherAgentName is also kube-init: the daemon subscribes to
// its own publication. Same agent name on both sides is supported
// by pillar pubsub.
const publisherAgentName = pubsubclient.AgentName

var (
	mu          sync.RWMutex
	pub         pubsub.Publication
	cached      KubeInitStatus
	subscribers []chan struct{}
)

// RegisterPublisher creates the publication. Must be called once
// at startup, before m.Run(). After this Publish is safe to call.
func RegisterPublisher(m *pubsubclient.Manager) error {
	p, err := m.NewPublication(pubsub.PublicationOptions{
		AgentName: pubsubclient.AgentName,
		TopicType: KubeInitStatus{},
		// Not Persistent: the on-disk state.AllComponentsInitialized
		// marker is the boot-survives record; this topic is the
		// in-flight event channel. On daemon restart, main.go
		// reads the file marker and re-publishes accordingly.
		Persistent: false,
	})
	if err != nil {
		return err
	}
	mu.Lock()
	pub = p
	mu.Unlock()
	return nil
}

// RegisterSubscriber registers the subscription on m. The
// subscriber writes through to the package-local cache so Get and
// Subscribe consumers see the current value without going back to
// pubsub.
func RegisterSubscriber(m *pubsubclient.Manager) error {
	_, err := m.Register(SubscriptionLabel, pubsub.SubscriptionOptions{
		AgentName:     publisherAgentName,
		MyAgentName:   pubsubclient.AgentName,
		TopicImpl:     KubeInitStatus{},
		Persistent:    false,
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
	})
	return err
}

func handleCreate(_ interface{}, _ string, val interface{}) {
	setCached(val.(KubeInitStatus))
}

func handleModify(_ interface{}, _ string, val interface{}, _ interface{}) {
	setCached(val.(KubeInitStatus))
}

func handleDelete(_ interface{}, _ string, _ interface{}) {
	mu.Lock()
	cached = KubeInitStatus{}
	subs := append([]chan struct{}(nil), subscribers...)
	mu.Unlock()
	notify(subs)
}

func setCached(v KubeInitStatus) {
	mu.Lock()
	cached = v
	subs := append([]chan struct{}(nil), subscribers...)
	mu.Unlock()
	notify(subs)
}

func notify(subs []chan struct{}) {
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Publish updates the package-local cache and writes the new
// value to the pubsub topic. Returns an error if the publisher
// has not been registered yet (programming error).
func Publish(s KubeInitStatus) error {
	mu.Lock()
	p := pub
	mu.Unlock()
	if p == nil {
		return errNoPublisher
	}
	// Self-cache: pubsub's own delivery loop will also fire the
	// handlers on us, but seeding the cache here guarantees a
	// caller that reads Get() right after Publish observes the
	// new value even before the pubsub round-trip completes.
	setCached(s)
	return p.Publish(s.Key(), s)
}

// Get returns the cached status.
func Get() KubeInitStatus {
	mu.RLock()
	defer mu.RUnlock()
	return cached
}

// Subscribe returns a coalescing channel (buffered size-1) that
// receives an empty struct on every cache change. The cancel
// function removes the channel; callers must invoke it on
// shutdown.
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

// SetForTest seeds the cache without touching the publisher.
// Cross-package tests use this to stage a particular phase.
func SetForTest(s KubeInitStatus) {
	setCached(s)
}

// ResetForTest wipes the cache.
func ResetForTest() {
	mu.Lock()
	cached = KubeInitStatus{}
	mu.Unlock()
}

// errNoPublisher reports that Publish was called before
// RegisterPublisher. Sentinel so tests can match it.
var errNoPublisher = &configError{"kubeinitstatus: publisher not registered"}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }
