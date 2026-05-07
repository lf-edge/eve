// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// mockPubSub satisfies pubsub.Publication and pubsub.Subscription enough
// for nodeagent's handlers. Only Get/GetAll/Iterate/Publish/Unpublish are
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

// newTestNodeagentContext builds a nodeagentContext suitable for
// handler tests: mock publications/subscriptions, default global
// config, and a recording stub for startNodeOperation. The returned
// helpers expose the underlying maps so tests can pre-populate
// subscriptions and inspect publications.
type testCtx struct {
	ctx                *nodeagentContext
	pubNodeAgentStatus *mockPubSub
	pubZbootConfig     *mockPubSub
	subZbootStatus     *mockPubSub
	subDomainStatus    *mockPubSub
	scheduledOps       []scheduledOp
}

type scheduledOp struct {
	op      types.DeviceOperation
	reason  string
	bootRsn types.BootReason
}

func newTestCtx() *testCtx {
	initTestLog()
	tc := &testCtx{
		pubNodeAgentStatus: newMockPubSub(),
		pubZbootConfig:     newMockPubSub(),
		subZbootStatus:     newMockPubSub(),
		subDomainStatus:    newMockPubSub(),
	}
	ctx := &nodeagentContext{}
	ctx.globalConfig = types.DefaultConfigItemValueMap()
	ctx.pubNodeAgentStatus = tc.pubNodeAgentStatus
	ctx.pubZbootConfig = tc.pubZbootConfig
	ctx.subZbootStatus = tc.subZbootStatus
	ctx.subDomainStatus = tc.subDomainStatus
	ctx.minRebootDelay = 0
	ctx.maxDomainHaltTime = 0
	ctx.domainHaltWaitIncrement = 1
	ctx.startNodeOperation = func(op types.DeviceOperation) {
		tc.scheduledOps = append(tc.scheduledOps, scheduledOp{
			op:      op,
			reason:  ctx.requestedRebootReason,
			bootRsn: ctx.requestedBootReason,
		})
	}
	tc.ctx = ctx
	return tc
}
