// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package pubsubclient is kube-init's thin façade over pillar's
// pubsub library. It centralises subscription management so the
// rest of kube-init can register topics from any package without
// having to plumb a pubsub.PubSub handle through every constructor.
//
// Pattern adapted from pkg/pillar/cmd/monitor/subscriptions.go:
//
//   - All subscriptions live in a single map keyed by topic label.
//   - Subscriptions are created with Activate=false so subscriber
//     packages can register in any order at startup without
//     racing against incoming events.
//   - One Run() goroutine drives them all through
//     pubsub.MultiChannelWatch — no goroutine-per-topic.
//
// Pillar's pubsub uses Unix sockets under /run/pubsub and JSON
// state files under /run/<agent>/... and /persist/status/<agent>/...
// — all paths the kube container already bind-mounts from the host
// (see pkg/kube/build.yml). No infrastructure setup is needed
// beyond constructing the Manager once at startup.
package pubsubclient

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/sirupsen/logrus"
)

// AgentName is the identity kube-init uses on pubsub. Other agents
// see it as the MyAgentName of subscriptions and the AgentName of
// any publications kube-init eventually adds (none yet).
const AgentName = "kube-init"

// Manager owns the pubsub.PubSub handle and the set of
// subscriptions kube-init has registered. Construct once at
// startup, register subscriptions before Run, then Run blocks
// pumping events until ctx is cancelled.
type Manager struct {
	ps     *pubsub.PubSub
	log    *base.LogObject
	logger *logrus.Logger

	mu      sync.Mutex
	subs    map[string]pubsub.Subscription
	running bool
}

// New constructs a Manager backed by pillar's socket driver. The
// logger is the same one kube-init uses for its own logging;
// pubsub internals trace through it, prefixed by AgentName.
func New(rootLogger *logrus.Logger) (*Manager, error) {
	if rootLogger == nil {
		return nil, errors.New("pubsubclient.New: nil logger")
	}
	log := base.NewSourceLogObject(rootLogger, AgentName, 0)
	ps := pubsub.New(
		&socketdriver.SocketDriver{Logger: rootLogger, Log: log},
		rootLogger, log)
	return &Manager{
		ps:     ps,
		log:    log,
		logger: rootLogger,
		subs:   make(map[string]pubsub.Subscription),
	}, nil
}

// Register creates a subscription with the supplied options and
// stores it under label. Activate is forced to false; the Manager
// activates all registered subscriptions together at Run() so
// startup ordering between subscribers does not matter.
//
// Duplicate labels are a wiring error and return an error.
// Calling after Run has started is also rejected — the Manager
// doesn't support dynamic registration today; if it ever needs
// to, the run-loop will have to be restructured.
func (m *Manager) Register(label string, opts pubsub.SubscriptionOptions) (pubsub.Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil, fmt.Errorf("pubsubclient: Register(%q) after Run started", label)
	}
	if _, exists := m.subs[label]; exists {
		return nil, fmt.Errorf("pubsubclient: duplicate subscription label %q", label)
	}
	opts.Activate = false
	sub, err := m.ps.NewSubscription(opts)
	if err != nil {
		return nil, fmt.Errorf("pubsubclient: new subscription %q: %w", label, err)
	}
	m.subs[label] = sub
	return sub, nil
}

// Sub returns the subscription registered under label. Panics if
// absent — Sub is meant for handler bodies that need to call
// sub.Get(...) by key on the topic that fired them, where the
// label is known at the call site. A missing label is always a
// programmer error worth failing fast on.
func (m *Manager) Sub(label string) pubsub.Subscription {
	m.mu.Lock()
	defer m.mu.Unlock()
	sub, ok := m.subs[label]
	if !ok {
		panic(fmt.Sprintf("pubsubclient: no subscription registered for %q", label))
	}
	return sub
}

// Run activates every registered subscription and blocks pumping
// their events through pubsub.MultiChannelWatch. Returns when ctx
// is cancelled. Designed to be called from a single goroutine in
// main.go after all subscribers have registered.
//
// Run is not re-entrant — a second concurrent call returns an
// error. Once it returns, the Manager should be considered
// terminated; subscription handlers will not fire again until a
// new Manager is constructed.
func (m *Manager) Run(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("pubsubclient: Run called twice")
	}
	m.running = true
	for label, sub := range m.subs {
		if err := sub.Activate(); err != nil {
			m.mu.Unlock()
			return fmt.Errorf("pubsubclient: activate %s: %w", label, err)
		}
	}
	watches := make([]pubsub.ChannelWatch, 0, len(m.subs)+1)
	for _, sub := range m.subs {
		watches = append(watches, pubsub.WatchAndProcessSubChanges(sub))
	}
	m.mu.Unlock()

	// ctx-cancel watch so the run-loop returns cleanly on
	// kube-init shutdown. The Callback signals MultiChannelWatch
	// to exit by returning true.
	watches = append(watches, pubsub.ChannelWatch{
		Chan: reflect.ValueOf(ctx.Done()),
		Callback: func(_ interface{}) (exit bool) {
			return true
		},
	})

	pubsub.MultiChannelWatch(watches)
	return ctx.Err()
}
