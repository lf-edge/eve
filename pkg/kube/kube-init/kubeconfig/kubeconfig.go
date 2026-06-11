// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kubeconfig subscribes to pillar's KubeConfig topic
// (published by zedkube under /persist/status/zedkube/KubeConfig/)
// and caches the latest payload behind accessors for the rest of
// kube-init.
//
// The current sole consumer is update.getDesiredK3sVersion, which
// reads K3sVersion to override the build's compile-time k3s
// version when the controller has set one. Per-tick read; no
// blocking wait at boot — if the subscription has not delivered
// yet, callers fall back to the compile-time default.
//
// API shape mirrors edgenodeinfo: Register hands the subscription
// to the shared Manager; Get returns the cached payload + a
// "present" bool; K3sVersion is a convenience getter for the one
// field anything reads today.
//
// Latent bug fixed by the migration: the file-reading version
// declared a local struct with json:"k3sVersion" tag, but pillar's
// types.KubeConfig has no tag on K3sVersion, so the marshalled
// JSON key is "K3sVersion". The previous reader therefore
// silently zeroed K3sVersion on every read and forced every device
// onto the compile-time default regardless of controller intent.
// Using pillar's struct directly (via TopicImpl) avoids the
// re-typing and the tag mismatch.
package kubeconfig

import (
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// SubscriptionLabel is the Manager label kube-init registers this
// subscription under.
const SubscriptionLabel = "KubeConfig"

// publisherAgentName is zedkube — the pillar agent that owns
// KubeConfig. Pubsub uses Persistent=true for this topic; the file
// lives under /persist/status/zedkube/KubeConfig/.
const publisherAgentName = "zedkube"

var (
	mu     sync.RWMutex
	have   bool
	cached types.KubeConfig
)

// Register creates the KubeConfig subscription on the supplied
// Manager. Handlers update the package-local cache. Persistent is
// true because pillar publishes this topic to /persist (survives
// reboots), but kube-init still wants fresh deliveries after
// connection, so the Manager activates with the default behaviour.
func Register(m *pubsubclient.Manager) error {
	_, err := m.Register(SubscriptionLabel, pubsub.SubscriptionOptions{
		AgentName:     publisherAgentName,
		MyAgentName:   pubsubclient.AgentName,
		TopicImpl:     types.KubeConfig{},
		Persistent:    true,
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
	})
	return err
}

func handleCreate(_ interface{}, _ string, val interface{}) {
	setCached(val.(types.KubeConfig))
}

func handleModify(_ interface{}, _ string, val interface{}, _ interface{}) {
	setCached(val.(types.KubeConfig))
}

func handleDelete(_ interface{}, _ string, _ interface{}) {
	mu.Lock()
	have = false
	cached = types.KubeConfig{}
	mu.Unlock()
}

func setCached(v types.KubeConfig) {
	mu.Lock()
	cached = v
	have = true
	mu.Unlock()
}

// Get returns the cached KubeConfig. The bool is false when no
// delivery has arrived yet OR after a Delete. Callers that need a
// fallback to a compile-time default use !ok to choose; callers
// that genuinely require the override fail loudly.
func Get() (types.KubeConfig, bool) {
	mu.RLock()
	defer mu.RUnlock()
	return cached, have
}

// K3sVersion returns the cached K3sVersion override, or "" when no
// delivery has arrived yet, when the override is empty, or after a
// Delete. Convenience wrapper for update.getDesiredK3sVersion.
func K3sVersion() string {
	cfg, ok := Get()
	if !ok {
		return ""
	}
	return cfg.K3sVersion
}
