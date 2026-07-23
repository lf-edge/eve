// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package encconfig subscribes to pillar's EdgeNodeClusterConfig
// topic (published by zedagent under
// /run/zedagent/EdgeNodeClusterConfig/) and caches the latest
// payload behind accessors.
//
// The topic carries the controller-delivered cluster shape:
// ClusterType (Base / ReplicatedStorage / HA), the bootstrap
// node IP and join token, IsWorkerNode / BootstrapNode flags,
// the TieBreakerNodeID, MasterNodeIDs, and the encrypted token
// + registration manifest blobs.
//
// kube-init consumes two slices:
//
//   - k3s.GetClusterType reads ClusterType to decide which
//     storage policy applies (the deploy graph branches on this).
//   - tiebreaker.ConfigIsSet / ConfigGetNodeUUID read
//     TieBreakerNodeID to know whether a tie-breaker is
//     configured and what its UUID is.
//
// Per-tick reads in steady state; no boot-time blocking wait.
// Subscription is not persistent (zedagent publishes to /run
// only).
package encconfig

import (
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// SubscriptionLabel is the Manager label kube-init registers
// this subscription under.
const SubscriptionLabel = "EdgeNodeClusterConfig"

// publisherAgentName is zedagent — the pillar agent that owns
// EdgeNodeClusterConfig. Publication is not Persistent; the
// JSON state file lives under /run/zedagent only.
const publisherAgentName = "zedagent"

var (
	mu     sync.RWMutex
	have   bool
	cached types.EdgeNodeClusterConfig
)

// Register creates the EdgeNodeClusterConfig subscription on
// the supplied Manager. Handlers update the package-local
// cache.
func Register(m *pubsubclient.Manager) error {
	_, err := m.Register(SubscriptionLabel, pubsub.SubscriptionOptions{
		AgentName:     publisherAgentName,
		MyAgentName:   pubsubclient.AgentName,
		TopicImpl:     types.EdgeNodeClusterConfig{},
		Persistent:    false,
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
	})
	return err
}

func handleCreate(_ interface{}, _ string, val interface{}) {
	setCached(val.(types.EdgeNodeClusterConfig))
}

func handleModify(_ interface{}, _ string, val interface{}, _ interface{}) {
	setCached(val.(types.EdgeNodeClusterConfig))
}

func handleDelete(_ interface{}, _ string, _ interface{}) {
	mu.Lock()
	have = false
	cached = types.EdgeNodeClusterConfig{}
	mu.Unlock()
}

func setCached(v types.EdgeNodeClusterConfig) {
	mu.Lock()
	cached = v
	have = true
	mu.Unlock()
}

// Get returns the cached EdgeNodeClusterConfig. The bool is
// false when no delivery has arrived yet OR after a Delete.
func Get() (types.EdgeNodeClusterConfig, bool) {
	mu.RLock()
	defer mu.RUnlock()
	return cached, have
}

// ClusterType returns the cluster type from the cached config.
// On no delivery, returns types.ClusterTypeNone — the caller
// (k3s.GetClusterType) maps that onto ClusterTypeReplicated to
// preserve the historical default for devices the controller
// has not configured yet.
func ClusterType() types.ClusterType {
	cfg, ok := Get()
	if !ok {
		return types.ClusterTypeNone
	}
	return cfg.ClusterType
}

// NativeK8sOrchestrationEnabled reports whether native Kubernetes
// orchestration of user workloads (registration manifest + kube-vip
// load balancer) is active for this cluster. True for the legacy
// ClusterTypeK3sBase, and for ClusterTypeReplicatedStorage when the
// controller opts in via EdgeNodeClusterConfig.EnableNativeK8SOrchestration.
// Mirrors pillar/types.EdgeNodeClusterConfig.NativeK8sOrchestrationEnabled;
// kept here so kube-init callers do not need to reach into the
// pillar types directly.
func NativeK8sOrchestrationEnabled() bool {
	cfg, ok := Get()
	if !ok {
		return false
	}
	return cfg.NativeK8sOrchestrationEnabled()
}

// TieBreakerUUID returns the tie-breaker node's UUID from the
// cached config, or "" if no delivery has arrived or the field
// is unset.
func TieBreakerUUID() string {
	cfg, ok := Get()
	if !ok {
		return ""
	}
	if cfg.TieBreakerNodeID.UUID == uuid.Nil {
		return ""
	}
	return cfg.TieBreakerNodeID.UUID.String()
}

// SetForTest seeds the cache with a fixed value. Exported so
// cross-package tests can stage a particular config.
func SetForTest(v types.EdgeNodeClusterConfig) {
	setCached(v)
}

// ResetForTest wipes the cache.
func ResetForTest() {
	mu.Lock()
	have = false
	cached = types.EdgeNodeClusterConfig{}
	mu.Unlock()
}
