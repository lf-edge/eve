// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// mockPubSub satisfies pubsub.Publication and pubsub.Subscription enough
// for baseosmgr's handlers. Only Get/GetAll/Iterate/Publish/Unpublish are
// meaningful; everything else is a stub.
type mockPubSub struct {
	items map[string]interface{}
}

func newMockPubSub() *mockPubSub {
	return &mockPubSub{items: map[string]interface{}{}}
}

// pubsub.Publication

func (m *mockPubSub) CheckMaxSize(string, interface{}) error { return nil }
func (m *mockPubSub) Publish(key string, item interface{}) error {
	m.items[key] = item
	return nil
}
func (m *mockPubSub) Unpublish(key string) error {
	delete(m.items, key)
	return nil
}
func (m *mockPubSub) SignalRestarted() error { return nil }
func (m *mockPubSub) ClearRestarted() error  { return nil }
func (m *mockPubSub) Get(key string) (interface{}, error) {
	v, ok := m.items[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return v, nil
}
func (m *mockPubSub) GetAll() map[string]interface{} {
	out := make(map[string]interface{}, len(m.items))
	for k, v := range m.items {
		out[k] = v
	}
	return out
}
func (m *mockPubSub) Iterate(fn base.StrMapFunc) {
	for k, v := range m.items {
		if !fn(k, v) {
			return
		}
	}
}
func (m *mockPubSub) Close() error { return nil }

// pubsub.Subscription extras

func (m *mockPubSub) Restarted() bool               { return false }
func (m *mockPubSub) RestartCounter() int           { return 0 }
func (m *mockPubSub) Synchronized() bool            { return true }
func (m *mockPubSub) ProcessChange(_ pubsub.Change) {}
func (m *mockPubSub) MsgChan() <-chan pubsub.Change { return nil }
func (m *mockPubSub) Activate() error               { return nil }

// testCtx wraps baseOsMgrContext with the underlying mock maps so tests
// can pre-populate subscriptions and inspect publications without the
// type assertions needed at every call site.
type testCtx struct {
	ctx                  *baseOsMgrContext
	pubBaseOsStatus      *mockPubSub
	pubZbootStatus       *mockPubSub
	pubBaseOsMgrStatus   *mockPubSub
	pubNodeDrainRequest  *mockPubSub
	subBaseOsConfig      *mockPubSub
	subContentTreeStatus *mockPubSub
	subZbootConfig       *mockPubSub
	subNodeAgentStatus   *mockPubSub
	subZedAgentStatus    *mockPubSub
	subNodeDrainStatus   *mockPubSub
	subGlobalConfig      *mockPubSub
	tmpDir               string
}

// newTestCtx builds a baseOsMgrContext suitable for handler tests:
// mock publications/subscriptions, default global config, and paths
// pointed at a per-test temporary directory so counter persistence
// doesn't touch /persist/.
func newTestCtx(t *testing.T) *testCtx {
	t.Helper()
	initTestLog()
	tmp := t.TempDir()
	tc := &testCtx{
		pubBaseOsStatus:      newMockPubSub(),
		pubZbootStatus:       newMockPubSub(),
		pubBaseOsMgrStatus:   newMockPubSub(),
		pubNodeDrainRequest:  newMockPubSub(),
		subBaseOsConfig:      newMockPubSub(),
		subContentTreeStatus: newMockPubSub(),
		subZbootConfig:       newMockPubSub(),
		subNodeAgentStatus:   newMockPubSub(),
		subZedAgentStatus:    newMockPubSub(),
		subNodeDrainStatus:   newMockPubSub(),
		subGlobalConfig:      newMockPubSub(),
		tmpDir:               tmp,
	}
	ctx := &baseOsMgrContext{
		globalConfig: types.DefaultConfigItemValueMap(),
		paths: &pathConfig{
			currentRetryUpdateCounter: filepath.Join(tmp, "current_retry_update_counter"),
			configRetryUpdateCounter:  filepath.Join(tmp, "config_retry_update_counter"),
			forceFallbackCounter:      filepath.Join(tmp, "forceFallbackCounter"),
		},
		pubBaseOsStatus:      tc.pubBaseOsStatus,
		pubZbootStatus:       tc.pubZbootStatus,
		pubBaseOsMgrStatus:   tc.pubBaseOsMgrStatus,
		pubNodeDrainRequest:  tc.pubNodeDrainRequest,
		subBaseOsConfig:      tc.subBaseOsConfig,
		subContentTreeStatus: tc.subContentTreeStatus,
		subZbootConfig:       tc.subZbootConfig,
		subNodeAgentStatus:   tc.subNodeAgentStatus,
		subZedAgentStatus:    tc.subZedAgentStatus,
		subNodeDrainStatus:   tc.subNodeDrainStatus,
		subGlobalConfig:      tc.subGlobalConfig,
	}
	tc.ctx = ctx
	return tc
}
