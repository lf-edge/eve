// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// TEMPORARY: delete this file together with legacyPinDefaultPolicy once the
// controller sends a CPU placement policy of its own.

package domainmgr

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// A controller that can only set pin_cpu must still get whole-core placement:
// two vCPUs land on both SMT siblings of one physical core, and the guest is
// shown threads=2 so it can see which of its vCPUs are siblings. Thread-granular
// placement -- what pin_cpu used to mean -- gives it neither.
func TestPlacementForIntent_LegacyPinDefaultsToWholeCoreSMT(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	ps := testPubSub(t)
	config := pinnedConfigForTest("pincpu-only", types.CPUPlacementPolicy{})
	ctx := &domainContext{
		placer:                      testPlacer(t),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	}

	placement, err := placementFor(&config)
	if err != nil {
		t.Fatalf("a pin_cpu-only workload must be placeable: %v", err)
	}
	if !placement.TopologyAware || placement.Mode != cpuallocator.ModeWholeCoreSMT {
		t.Fatalf("want topology-aware whole-core-smt, got aware=%v mode=%v",
			placement.TopologyAware, placement.Mode)
	}

	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion
	if err := assignCPUs(ctx, &config, &status); err != nil {
		t.Fatalf("assignCPUs: %v", err)
	}
	// The two host CPUs have to be the siblings of one core, not two threads of
	// two different cores, and the guest topology has to say so.
	want := types.CPUTopology{Sockets: 1, Cores: 1, Threads: 2}
	if status.VMTopology != want {
		t.Errorf("guest topology = %+v, want %+v", status.VMTopology, want)
	}
	if len(status.OrderedCPUs) != 2 {
		t.Fatalf("want 2 pinned host CPUs, got %v", status.OrderedCPUs)
	}
	if !areSiblingsInTestTopology(status.OrderedCPUs[0], status.OrderedCPUs[1]) {
		t.Errorf("host CPUs %v are not SMT siblings of one core",
			status.OrderedCPUs)
	}
}

// areSiblingsInTestTopology reads the sibling relation out of testPlacer's
// numbering, where thread 0 of core N is CPU N and thread 1 is CPU N+4.
func areSiblingsInTestTopology(a, b uint32) bool {
	if a > b {
		a, b = b, a
	}
	return b-a == 4
}

// A workload the controller did not pin is untouched by the default: it stays in
// the shared pool.
func TestPlacementForIntent_UnpinnedIsUnaffected(t *testing.T) {
	isolatePinningOverride(t)
	var config types.DomainConfig
	config.UUIDandVersion.UUID = uuid.NewV5(uuid.NamespaceOID, "unpinned")
	config.DisplayName = "unpinned"
	config.VmConfig.VCpus = 2

	placement, err := placementFor(&config)
	if err != nil {
		t.Fatalf("placementFor: %v", err)
	}
	if placement.TopologyAware {
		t.Errorf("an unpinned workload must not become topology-aware, got %+v",
			placement)
	}
	if effectiveCPUsPinned(&config) {
		t.Error("an unpinned workload must not be pinned by the default")
	}
}

// An explicit controller policy still wins, including one that asks for
// thread-granular placement: the default speaks only for a controller that said
// nothing at all.
func TestPlacementForIntent_ExplicitPolicyBeatsTheDefault(t *testing.T) {
	isolatePinningOverride(t)
	config := pinnedConfigForTest("threadgranular", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated,
	})

	placement, err := placementFor(&config)
	if err != nil {
		t.Fatalf("placementFor: %v", err)
	}
	if placement.TopologyAware {
		t.Errorf("dedicated without full_pcpus_only must stay thread-granular, "+
			"got %+v", placement)
	}
}

// The /persist override remains the operator's escape hatch: asking for one
// thread per core has to survive the default.
func TestPlacementForIntent_PersistOverrideBeatsTheDefault(t *testing.T) {
	isolatePinningOverride(t)
	config := pinnedConfigForTest("onepercore", types.CPUPlacementPolicy{})
	writePinningEntryForTest(t, config.UUIDandVersion.UUID, &PinningEntry{
		DisplayName:    config.DisplayName,
		CPUPolicy:      "static",
		PolicyOptions:  fullPCPUs(),
		ThreadsPerCore: 1,
	})

	placement, err := placementFor(&config)
	if err != nil {
		t.Fatalf("placementFor: %v", err)
	}
	if placement.Mode != cpuallocator.ModeOnePerCore {
		t.Errorf("the override must still select one-per-core, got %v",
			placement.Mode)
	}
}

// An odd vCPU count cannot be served on two-thread cores, and the default does
// not quietly fall back to thread-granular placement: the workload would then be
// reported as pinned while getting none of what pinning was turned on for.
func TestPlacementForIntent_OddVCPUCountFailsClosed(t *testing.T) {
	isolatePinningOverride(t)
	config := pinnedConfigForTest("odd", types.CPUPlacementPolicy{})
	config.VmConfig.VCpus = 3

	placement, err := placementFor(&config)
	if err != nil {
		t.Fatalf("placementFor: %v", err)
	}
	err = validateVCPUCount(placement, config.VCpus)
	var perr *placementError
	if !errors.As(err, &perr) || perr.Code != types.ErrorCodeCPUPolicyOddVCPU {
		t.Fatalf("want %q for 3 vCPUs on whole cores, got %v",
			types.ErrorCodeCPUPolicyOddVCPU, err)
	}
}
