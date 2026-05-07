// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"fmt"
	"time"

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

// --- mockZboot ------------------------------------------------------

// mockZboot is a recording stub of the Zboot interface. By default
// every partition label is valid, the partition list is IMGA/IMGB,
// and the device is on IMGA with no upgrade in progress.
type mockZboot struct {
	currentPart       string
	otherPart         string
	currentInProgress bool
	otherUpdating     bool
	resetCalled       int
	poweroffCalled    int
	validLabels       map[string]bool
}

func newMockZboot() *mockZboot {
	return &mockZboot{
		currentPart: "IMGA",
		otherPart:   "IMGB",
		validLabels: map[string]bool{"IMGA": true, "IMGB": true},
	}
}

func (m *mockZboot) EveCurrentPartition() string             { return m.currentPart }
func (m *mockZboot) IsCurrentPartitionStateInProgress() bool { return m.currentInProgress }
func (m *mockZboot) IsValidPartitionLabel(s string) bool     { return m.validLabels[s] }
func (m *mockZboot) GetValidPartitionLabels() []string       { return []string{"IMGA", "IMGB"} }
func (m *mockZboot) GetOtherPartition() string               { return m.otherPart }
func (m *mockZboot) IsOtherPartitionStateUpdating() bool     { return m.otherUpdating }
func (m *mockZboot) Reset()                                  { m.resetCalled++ }
func (m *mockZboot) Poweroff()                               { m.poweroffCalled++ }

// --- mockRebootStore -------------------------------------------------

// mockRebootStore records writes and serves reads from in-memory state.
type mockRebootStore struct {
	rebootReason string
	rebootTime   time.Time
	rebootStack  string
	bootReason   types.BootReason
	bootTime     time.Time
	rebootImage  string

	discardedRebootReason bool
	discardedBootReason   bool
	discardedRebootImage  bool
	written               []rebootWrite
}

type rebootWrite struct {
	reason string
	br     types.BootReason
	agent  string
	pid    int
	last   bool
}

func (m *mockRebootStore) GetRebootReason() (string, time.Time, string) {
	return m.rebootReason, m.rebootTime, m.rebootStack
}
func (m *mockRebootStore) GetBootReason() (types.BootReason, time.Time) {
	return m.bootReason, m.bootTime
}
func (m *mockRebootStore) GetRebootImage() string { return m.rebootImage }
func (m *mockRebootStore) DiscardRebootReason()   { m.discardedRebootReason = true }
func (m *mockRebootStore) DiscardBootReason()     { m.discardedBootReason = true }
func (m *mockRebootStore) DiscardRebootImage()    { m.discardedRebootImage = true }
func (m *mockRebootStore) WriteRebootReason(reason string, br types.BootReason,
	agent string, pid int, last bool) {
	m.written = append(m.written, rebootWrite{reason, br, agent, pid, last})
}

// --- testCtx --------------------------------------------------------

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
	zboot              *mockZboot
	rebootStore        *mockRebootStore
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
		zboot:              newMockZboot(),
		rebootStore:        &mockRebootStore{},
	}
	ctx := &nodeagentContext{}
	ctx.globalConfig = types.DefaultConfigItemValueMap()
	ctx.pubNodeAgentStatus = tc.pubNodeAgentStatus
	ctx.pubZbootConfig = tc.pubZbootConfig
	ctx.subZbootStatus = tc.subZbootStatus
	ctx.subDomainStatus = tc.subDomainStatus
	ctx.zboot = tc.zboot
	ctx.rebootStore = tc.rebootStore
	ctx.paths = defaultPathConfig()
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
