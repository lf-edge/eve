// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// mockZboot is an in-memory replacement for the production Zboot
// adapter. Tests configure it by mutating the fields directly:
//
//	tc.zb.cur = "IMGA"
//	tc.zb.parts["IMGB"] = mockPart{state: "unused"}
//
// All Set* methods record their effects on parts so subsequent reads
// reflect what the production code would have done.
type mockPart struct {
	state    string
	devname  string
	sizeB    uint64
	short    string
	shortErr error
	long     string
}

type mockZboot struct {
	valid           []string // valid partition labels (ordered)
	cur             string
	other           string
	parts           map[string]*mockPart
	writeErr        error                        // returned by WriteToPartition
	markActiveErr   error                        // returned by MarkCurrentPartitionStateActive
	writeCalls      []string                     // list of "ref→part" pairs recorded
	markActiveCalls int                          // count
	setUpdating     int                          // count (other-state updating)
	setUnused       int                          // count (other-state unused)
	hooks           map[string]func(args ...any) // optional hooks
}

func newMockZboot() *mockZboot {
	return &mockZboot{
		valid: []string{"IMGA", "IMGB"},
		cur:   "IMGA",
		other: "IMGB",
		parts: map[string]*mockPart{
			"IMGA": {state: "active", devname: "/dev/dummy3", sizeB: 1 << 30},
			"IMGB": {state: "unused", devname: "/dev/dummy4", sizeB: 1 << 30},
		},
	}
}

func (m *mockZboot) GetCurrentPartition() string       { return m.cur }
func (m *mockZboot) GetOtherPartition() string         { return m.other }
func (m *mockZboot) GetValidPartitionLabels() []string { return append([]string{}, m.valid...) }

func (m *mockZboot) IsValidPartitionLabel(s string) bool {
	for _, v := range m.valid {
		if v == s {
			return true
		}
	}
	return false
}

func (m *mockZboot) IsCurrentPartition(s string) bool { return s == m.cur }
func (m *mockZboot) IsOtherPartition(s string) bool   { return s == m.other }

func (m *mockZboot) GetPartitionState(s string) string {
	if p, ok := m.parts[s]; ok {
		return p.state
	}
	return ""
}

func (m *mockZboot) GetPartitionDevname(s string) string {
	if p, ok := m.parts[s]; ok {
		return p.devname
	}
	return ""
}

func (m *mockZboot) GetPartitionSizeInBytes(s string) uint64 {
	if p, ok := m.parts[s]; ok {
		return p.sizeB
	}
	return 0
}

func (m *mockZboot) GetShortVersion(s string) (string, error) {
	if p, ok := m.parts[s]; ok {
		return p.short, p.shortErr
	}
	return "", nil
}

func (m *mockZboot) GetLongVersion(s string) string {
	if p, ok := m.parts[s]; ok {
		return p.long
	}
	return ""
}

func (m *mockZboot) SetOtherPartitionStateUpdating() {
	m.setUpdating++
	if p, ok := m.parts[m.other]; ok {
		p.state = "updating"
	}
}

func (m *mockZboot) SetOtherPartitionStateUnused() {
	m.setUnused++
	if p, ok := m.parts[m.other]; ok {
		p.state = "unused"
	}
}

func (m *mockZboot) MarkCurrentPartitionStateActive() error {
	m.markActiveCalls++
	if m.markActiveErr != nil {
		return m.markActiveErr
	}
	if p, ok := m.parts[m.cur]; ok {
		p.state = "active"
	}
	return nil
}

func (m *mockZboot) WriteToPartition(image, partName string) error {
	m.writeCalls = append(m.writeCalls, image+"→"+partName)
	return m.writeErr
}

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
	zb                   *mockZboot
	tmpDir               string

	// drain seam knobs — tests that exercise shouldDeferForNodeDrain
	// / handleNodeDrainStatusImpl set these to drive specific status
	// values, otherwise the default getNodeDrainStatus returns
	// NOTSUPPORTED so the kube path short-circuits.
	drainStatus       *kubeapi.NodeDrainStatus
	drainRequestErr   error
	drainRequestCalls []kubeapi.DrainRequester

	// HV-type seam knobs — tests for the EVE-k personality switch
	// override these.
	currentIsKube    bool
	versionIsKube    map[string]bool
	versionIsKubeErr error
}

// newTestCtx builds a baseOsMgrContext suitable for handler tests:
// mock publications/subscriptions, default global config, paths
// pointed at a per-test temporary directory so counter persistence
// doesn't touch /persist/, and a mockZboot defaulting to IMGA=active /
// IMGB=unused.
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
		zb:                   newMockZboot(),
		tmpDir:               tmp,
		versionIsKube:        map[string]bool{},
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
		zboot:                tc.zb,
		seams: seams{
			isHVTypeKube: func() bool {
				return tc.currentIsKube
			},
			isVersionHVTypeKube: func(v string) (bool, error) {
				if tc.versionIsKubeErr != nil {
					return false, tc.versionIsKubeErr
				}
				return tc.versionIsKube[v], nil
			},
			getNodeDrainStatus: func(_ pubsub.Subscription) *kubeapi.NodeDrainStatus {
				if tc.drainStatus != nil {
					return tc.drainStatus
				}
				return &kubeapi.NodeDrainStatus{Status: kubeapi.NOTSUPPORTED}
			},
			requestNodeDrain: func(_ pubsub.Publication, requester kubeapi.DrainRequester, _ string) error {
				tc.drainRequestCalls = append(tc.drainRequestCalls, requester)
				return tc.drainRequestErr
			},
		},
	}
	tc.ctx = ctx
	return tc
}

// seedZbootStatus is a small helper that publishes a ZbootStatus matching
// the mockZboot's current view of a partition, the way Run() does at
// startup. Many tests need this because the production code reads
// PartitionState/CurrentPartition/ShortVersion through the published
// ZbootStatus rather than via the Zboot interface directly.
func (tc *testCtx) seedZbootStatus(part string) {
	p := tc.zb.parts[part]
	if p == nil {
		return
	}
	st := types.ZbootStatus{
		PartitionLabel:   part,
		PartitionDevname: p.devname,
		PartitionState:   p.state,
		ShortVersion:     p.short,
		LongVersion:      p.long,
		CurrentPartition: tc.zb.cur == part,
	}
	tc.pubZbootStatus.items[part] = st
}
