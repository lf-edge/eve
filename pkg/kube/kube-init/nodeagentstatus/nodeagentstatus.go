// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package nodeagentstatus subscribes to pillar nodeagent's
// NodeAgentStatus topic and answers whether the kube component update
// pass may start.
//
// On an EVE image under test, nodeagent falls back to the other
// partition if the image cannot reach the controller. The components
// cannot be downgraded, so the pass waits until the controller has been
// reached on this image; nodeagent does not fall back after that.
package nodeagentstatus

import (
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// SubscriptionLabel is the Manager label kube-init registers this
// subscription under.
const SubscriptionLabel = "NodeAgentStatus"

const publisherAgentName = "nodeagent"

// NodeAgentStatus is kube-init's view of pillar's types.NodeAgentStatus.
// The vendored pillar can lag behind the tree, so the two are coupled by
// topic name and JSON field names only; a field renamed in pillar must
// be renamed here.
type NodeAgentStatus struct {
	Name              string
	UpdateInprogress  bool
	ControllerReached bool
}

// Key is the key in pubsub.
func (status NodeAgentStatus) Key() string {
	return status.Name
}

var (
	mu     sync.RWMutex
	have   bool
	cached NodeAgentStatus
)

// Register creates the NodeAgentStatus subscription on the Manager.
func Register(m *pubsubclient.Manager) error {
	_, err := m.Register(SubscriptionLabel, pubsub.SubscriptionOptions{
		AgentName:     publisherAgentName,
		MyAgentName:   pubsubclient.AgentName(),
		TopicImpl:     NodeAgentStatus{},
		CreateHandler: handleCreate,
		ModifyHandler: handleModify,
		DeleteHandler: handleDelete,
	})
	return err
}

func handleCreate(_ interface{}, _ string, val interface{}) {
	set(val.(NodeAgentStatus), true)
}

func handleModify(_ interface{}, _ string, val interface{}, _ interface{}) {
	set(val.(NodeAgentStatus), true)
}

func handleDelete(_ interface{}, _ string, _ interface{}) {
	set(NodeAgentStatus{}, false)
}

func set(v NodeAgentStatus, ok bool) {
	mu.Lock()
	cached, have = v, ok
	mu.Unlock()
}

// UpdateAllowed reports whether the component update pass may start:
// nodeagent has published, and either this image is not under test or
// it has reached the controller.
func UpdateAllowed() bool {
	mu.RLock()
	defer mu.RUnlock()
	return have && (!cached.UpdateInprogress || cached.ControllerReached)
}

// SetForTest seeds the cache. Pair with ResetForTest in t.Cleanup.
func SetForTest(v NodeAgentStatus) {
	set(v, true)
}

// ResetForTest wipes the cache.
func ResetForTest() {
	set(NodeAgentStatus{}, false)
}
