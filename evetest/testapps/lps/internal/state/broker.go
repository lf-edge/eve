// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"sort"
	"sync"

	"github.com/lf-edge/eve-api/go/profile"
)

// Broker tracks pending configuration changes and fans out notifications
// to subscribers. Two subscription flavors exist:
//
//   - Pending subscribers (SubscribePending) receive a wake-up whenever
//     the pending-endpoint set grows via MarkPending. They are the
//     audience for the LPS Signal endpoint (GET /api/v1/signal).
//   - Any subscribers (SubscribeAny) receive a wake-up for MarkPending
//     AND for NotifyAny events. They are the audience for the UI event
//     stream (GET /manage/v1/events).
//
// All subscriber channels are size-1 buffered and delivered via a
// non-blocking send; a slow subscriber simply coalesces into the next
// wake-up. Subscribers must re-read broker or state on each tick rather
// than relying on the channel to carry payload.
type Broker struct {
	mu          sync.Mutex
	pending     map[profile.ConfigEndpoint]bool
	pendingSubs map[chan struct{}]struct{}
	anySubs     map[chan struct{}]struct{}
}

// NewBroker creates an empty Broker.
func NewBroker() *Broker {
	return &Broker{
		pending:     make(map[profile.ConfigEndpoint]bool),
		pendingSubs: make(map[chan struct{}]struct{}),
		anySubs:     make(map[chan struct{}]struct{}),
	}
}

// MarkPending records that the given endpoint has a configuration change
// not yet delivered to EVE. Wakes up both pending and any subscribers.
func (b *Broker) MarkPending(ep profile.ConfigEndpoint) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending[ep] = true
	b.wakeLocked(b.pendingSubs)
	b.wakeLocked(b.anySubs)
}

// ConsumePending clears the pending bit for the given endpoint. Called
// by the LPS handlers after a successful response to EVE. Intentionally
// does not notify any subscriber — consumption is a local state update.
func (b *Broker) ConsumePending(ep profile.ConfigEndpoint) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pending, ep)
}

// NotifyAny wakes up the "any" subscribers without marking any endpoint
// as pending. Used for state changes that are interesting to the UI but
// that do not need to be signaled to EVE — for example, state received
// from EVE (which it obviously already has) or local changes that do
// not alter any config response (such as a server-token rotation).
func (b *Broker) NotifyAny() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.wakeLocked(b.anySubs)
}

// SnapshotPending returns the currently pending endpoints in a
// deterministic order. Returns nil when nothing is pending.
func (b *Broker) SnapshotPending() []profile.ConfigEndpoint {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pending) == 0 {
		return nil
	}
	eps := make([]profile.ConfigEndpoint, 0, len(b.pending))
	for ep := range b.pending {
		eps = append(eps, ep)
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i] < eps[j] })
	return eps
}

// SubscribePending registers a subscriber that wakes up on MarkPending
// events only. The returned channel is size-1 buffered. The caller must
// invoke the returned unsubscribe function when exiting.
func (b *Broker) SubscribePending() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.pendingSubs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.pendingSubs, ch)
		b.mu.Unlock()
	}
}

// SubscribeAny registers a subscriber that wakes up on both MarkPending
// and NotifyReceived events.
func (b *Broker) SubscribeAny() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.anySubs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.anySubs, ch)
		b.mu.Unlock()
	}
}

// wakeLocked performs a non-blocking send on every channel in the given
// subscriber set. The caller must hold b.mu.
func (b *Broker) wakeLocked(subs map[chan struct{}]struct{}) {
	for ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
