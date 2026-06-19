// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package domainmgr

import (
	"fmt"
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Minimal mock: pubsub.Publication
// ---------------------------------------------------------------------------

type mockPublication struct {
	items map[string]interface{}
}

func newMockPublication() *mockPublication {
	return &mockPublication{items: make(map[string]interface{})}
}

func (m *mockPublication) CheckMaxSize(_ string, _ interface{}) error { return nil }
func (m *mockPublication) SignalRestarted() error                     { return nil }
func (m *mockPublication) ClearRestarted() error                      { return nil }
func (m *mockPublication) Close() error                               { return nil }
func (m *mockPublication) Iterate(_ base.StrMapFunc)                  {}
func (m *mockPublication) Unpublish(key string) error                 { delete(m.items, key); return nil }
func (m *mockPublication) Get(key string) (interface{}, error) {
	v, ok := m.items[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return v, nil
}
func (m *mockPublication) GetAll() map[string]interface{} {
	out := make(map[string]interface{}, len(m.items))
	for k, v := range m.items {
		out[k] = v
	}
	return out
}
func (m *mockPublication) Publish(key string, item interface{}) error {
	m.items[key] = item
	return nil
}

// ---------------------------------------------------------------------------
// Minimal mock: pubsub.Subscription (used by lookupDomainConfig — returns nil)
// ---------------------------------------------------------------------------

type mockSubscription struct{}

func (m *mockSubscription) Get(_ string) (interface{}, error) { return nil, fmt.Errorf("not found") }
func (m *mockSubscription) GetAll() map[string]interface{}    { return nil }
func (m *mockSubscription) Iterate(_ base.StrMapFunc)         {}
func (m *mockSubscription) Restarted() bool                   { return false }
func (m *mockSubscription) RestartCounter() int               { return 0 }
func (m *mockSubscription) Synchronized() bool                { return true }
func (m *mockSubscription) ProcessChange(_ pubsub.Change)     {}
func (m *mockSubscription) MsgChan() <-chan pubsub.Change     { return nil }
func (m *mockSubscription) Activate() error                   { return nil }
func (m *mockSubscription) Close() error                      { return nil }

// ---------------------------------------------------------------------------
// Minimal mock: types.Task — only Info() is meaningful for verifyStatus tests
// ---------------------------------------------------------------------------

type mockKubeTask struct {
	infoState types.SwState
	infoID    int
	infoErr   error
}

func (m *mockKubeTask) Info(_ string) (int, types.SwState, error) {
	return m.infoID, m.infoState, m.infoErr
}
func (m *mockKubeTask) Setup(_ types.DomainStatus, _ types.DomainConfig, _ *types.AssignableAdapters, _ *types.ConfigItemValueMap, _ *os.File) error {
	return nil
}
func (m *mockKubeTask) VirtualTPMSetup(_ string, _ *types.WatchdogParam) error     { return nil }
func (m *mockKubeTask) VirtualTPMTerminate(_ string, _ *types.WatchdogParam) error { return nil }
func (m *mockKubeTask) VirtualTPMTeardown(_ string, _ *types.WatchdogParam) error  { return nil }
func (m *mockKubeTask) OemWindowsLicenseKeySetup(_ *types.OemWindowsLicenseKeyInfo) error {
	return nil
}
func (m *mockKubeTask) Create(_ string, _ string, _ *types.DomainConfig) (int, error) {
	return 0, nil
}
func (m *mockKubeTask) Start(_ string) error        { return nil }
func (m *mockKubeTask) Stop(_ string, _ bool) error { return nil }
func (m *mockKubeTask) Delete(_ string) error       { return nil }
func (m *mockKubeTask) Cleanup(_ string) error      { return nil }

// ---------------------------------------------------------------------------
// Minimal mock: hypervisor.Hypervisor — only Task() is called by verifyStatus
// ---------------------------------------------------------------------------

type mockKubeHypervisor struct {
	task *mockKubeTask
}

func (m *mockKubeHypervisor) Name() string                          { return "mock-kube" }
func (m *mockKubeHypervisor) Task(_ *types.DomainStatus) types.Task { return m.task }
func (m *mockKubeHypervisor) PCIReserve(_ string) error             { return nil }
func (m *mockKubeHypervisor) PCIRelease(_ string) error             { return nil }
func (m *mockKubeHypervisor) PCISameController(_, _ string) bool    { return false }
func (m *mockKubeHypervisor) GetHostCPUMem() (types.HostMemory, error) {
	return types.HostMemory{}, nil
}
func (m *mockKubeHypervisor) GetDomsCPUMem() (map[string]types.DomainMetric, error) {
	return nil, nil
}
func (m *mockKubeHypervisor) GetCapabilities() (*types.Capabilities, error) { return nil, nil }
func (m *mockKubeHypervisor) CountMemOverhead(_ string, _ uuid.UUID, _, _, _, _ int64, _ []types.IoAdapter, _ *types.AssignableAdapters, _ *types.ConfigItemValueMap) (uint64, error) {
	return 0, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestDomainContext(pub *mockPublication) *domainContext {
	return &domainContext{
		subDomainConfig: &mockSubscription{},
		pubDomainStatus: pub,
	}
}

func newTestDomainStatus(name string, state types.SwState, activated bool) *types.DomainStatus {
	return &types.DomainStatus{
		DomainName: name,
		State:      state,
		Activated:  activated,
	}
}

func swapHyper(t *testing.T, h hypervisor.Hypervisor) {
	t.Helper()
	saved := hyper
	hyper = h
	t.Cleanup(func() { hyper = saved })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestVerifyStatusKubeRescheduleToBooting: a previously Running domain whose
// VMI enters the Scheduling phase (Init:0/1 pod) should transition to BOOTING
// with Activated=false so the recovery path can fire later.
func TestVerifyStatusKubeRescheduleToBooting(t *testing.T) {
	pub := newMockPublication()
	swapHyper(t, &mockKubeHypervisor{task: &mockKubeTask{infoState: types.SCHEDULING, infoID: 1}})

	ctx := newTestDomainContext(pub)
	status := newTestDomainStatus("test-domain", types.RUNNING, true)

	verifyStatus(ctx, status)

	assert.Equal(t, types.BOOTING, status.State, "rescheduling VMI should report BOOTING")
	assert.False(t, status.Activated, "Activated must be false to enable recovery path")
	assert.NotEmpty(t, pub.items, "DomainStatus should be published after transition")
}

// TestVerifyStatusKubeRecoveryToRunning: a domain that was set to BOOTING
// (Activated=false) while the VMI was rescheduling should recover to RUNNING
// once Info() reports the domain is Running again.
func TestVerifyStatusKubeRecoveryToRunning(t *testing.T) {
	pub := newMockPublication()
	swapHyper(t, &mockKubeHypervisor{task: &mockKubeTask{infoState: types.RUNNING, infoID: 1}})

	ctx := newTestDomainContext(pub)
	status := newTestDomainStatus("test-domain", types.BOOTING, false)

	verifyStatus(ctx, status)

	assert.Equal(t, types.RUNNING, status.State, "recovered VMI should report RUNNING")
	assert.True(t, status.Activated, "Activated must be true after recovery")
	assert.NotEmpty(t, pub.items, "DomainStatus should be published after recovery")
}

// TestVerifyStatusKubeRoundTrip: exercises the full RUNNING → BOOTING → RUNNING
// cycle that occurs when a virt-launcher pod goes through Init:0/1 and recovers.
func TestVerifyStatusKubeRoundTrip(t *testing.T) {
	pub := newMockPublication()
	mockTask := &mockKubeTask{infoState: types.SCHEDULING, infoID: 1}
	swapHyper(t, &mockKubeHypervisor{task: mockTask})

	ctx := newTestDomainContext(pub)
	status := newTestDomainStatus("test-domain", types.RUNNING, true)

	// Phase 1: VMI enters Scheduling — should go BOOTING
	verifyStatus(ctx, status)
	assert.Equal(t, types.BOOTING, status.State)
	assert.False(t, status.Activated)

	// Phase 2: VMI recovers to Running — should go RUNNING
	mockTask.infoState = types.RUNNING
	verifyStatus(ctx, status)
	assert.Equal(t, types.RUNNING, status.State)
	assert.True(t, status.Activated)
}

// TestVerifyStatusKubeAlreadyBooting: if the domain is already in BOOTING
// state (Activated=false), a subsequent SCHEDULING observation must not
// re-publish or double-transition.
func TestVerifyStatusKubeAlreadyBooting(t *testing.T) {
	pub := newMockPublication()
	// infoID must match status.DomainId (both 0) so the domainID-changed branch
	// does not fire and trigger a spurious publish.
	swapHyper(t, &mockKubeHypervisor{task: &mockKubeTask{infoState: types.SCHEDULING, infoID: 0}})

	ctx := newTestDomainContext(pub)
	status := newTestDomainStatus("test-domain", types.BOOTING, false)

	verifyStatus(ctx, status)

	// State and Activated unchanged; nothing published for this domain
	assert.Equal(t, types.BOOTING, status.State, "state should not change when already BOOTING")
	assert.False(t, status.Activated)
	assert.Empty(t, pub.items, "should not publish when already in BOOTING state")
}
