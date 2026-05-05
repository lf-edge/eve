// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"net"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// ---------------------------------------------------------------------------
// Bond tests
// ---------------------------------------------------------------------------

func TestBondEqual(t *testing.T) {
	t.Parallel()
	base := Bond{
		BondConfig: types.BondConfig{
			Mode:     types.BondModeActiveBackup,
			LacpRate: types.LacpRateUnspecified,
			MIIMonitor: types.BondMIIMonitor{
				Enabled:  true,
				Interval: 100,
				UpDelay:  200,
			},
		},
		IfName:            "bond0",
		AggregatedIfNames: []string{"eth0", "eth1"},
		MTU:               1500,
	}
	type test struct {
		name     string
		a, b     Bond
		expEqual bool
	}
	tests := []test{
		{
			name:     "identical",
			a:        base,
			b:        base,
			expEqual: true,
		},
		{
			name: "aggregated interfaces in different order (EqualSets)",
			a:    base,
			b: Bond{
				BondConfig:        base.BondConfig,
				IfName:            "bond0",
				AggregatedIfNames: []string{"eth1", "eth0"},
				MTU:               1500,
			},
			expEqual: true,
		},
		{
			name: "different mode",
			a:    base,
			b: Bond{
				BondConfig: types.BondConfig{
					Mode: types.BondMode802Dot3AD,
					MIIMonitor: types.BondMIIMonitor{
						Enabled:  true,
						Interval: 100,
						UpDelay:  200,
					},
				},
				IfName:            "bond0",
				AggregatedIfNames: []string{"eth0", "eth1"},
				MTU:               1500,
			},
			expEqual: false,
		},
		{
			name: "different LacpRate",
			a:    base,
			b: Bond{
				BondConfig: types.BondConfig{
					Mode:     types.BondModeActiveBackup,
					LacpRate: types.LacpRateFast,
					MIIMonitor: types.BondMIIMonitor{
						Enabled:  true,
						Interval: 100,
						UpDelay:  200,
					},
				},
				IfName:            "bond0",
				AggregatedIfNames: []string{"eth0", "eth1"},
				MTU:               1500,
			},
			expEqual: false,
		},
		{
			name: "different MII monitor interval",
			a:    base,
			b: Bond{
				BondConfig: types.BondConfig{
					Mode:     types.BondModeActiveBackup,
					LacpRate: types.LacpRateUnspecified,
					MIIMonitor: types.BondMIIMonitor{
						Enabled:  true,
						Interval: 200,
						UpDelay:  200,
					},
				},
				IfName:            "bond0",
				AggregatedIfNames: []string{"eth0", "eth1"},
				MTU:               1500,
			},
			expEqual: false,
		},
		{
			name: "different MTU",
			a:    base,
			b: Bond{
				BondConfig:        base.BondConfig,
				IfName:            "bond0",
				AggregatedIfNames: []string{"eth0", "eth1"},
				MTU:               9000,
			},
			expEqual: false,
		},
		{
			name: "different aggregated interfaces",
			a:    base,
			b: Bond{
				BondConfig:        base.BondConfig,
				IfName:            "bond0",
				AggregatedIfNames: []string{"eth0"},
				MTU:               1500,
			},
			expEqual: false,
		},
		{
			name: "different ARP monitor",
			a:    base,
			b: Bond{
				BondConfig: types.BondConfig{
					Mode:     types.BondModeActiveBackup,
					LacpRate: types.LacpRateUnspecified,
					MIIMonitor: types.BondMIIMonitor{
						Enabled:  true,
						Interval: 100,
						UpDelay:  200,
					},
					ARPMonitor: types.BondArpMonitor{
						Enabled:   true,
						Interval:  1000,
						IPTargets: []net.IP{net.ParseIP("192.168.1.1")},
					},
				},
				IfName:            "bond0",
				AggregatedIfNames: []string{"eth0", "eth1"},
				MTU:               1500,
			},
			expEqual: false,
		},
	}
	for _, tc := range tests {
		got := tc.a.Equal(tc.b)
		if got != tc.expEqual {
			t.Errorf("TEST CASE %q: Equal() = %v, want %v", tc.name, got, tc.expEqual)
		}
	}
}

func TestBondGetMTU(t *testing.T) {
	t.Parallel()
	if got := (Bond{MTU: 0}).GetMTU(); got != types.DefaultMTU {
		t.Errorf("GetMTU() with zero MTU = %d, want DefaultMTU %d", got, types.DefaultMTU)
	}
	if got := (Bond{MTU: 9000}).GetMTU(); got != 9000 {
		t.Errorf("GetMTU() with 9000 = %d, want 9000", got)
	}
}

func TestBondDependencies(t *testing.T) {
	t.Parallel()
	b := Bond{
		IfName:            "bond0",
		AggregatedIfNames: []string{"eth0", "eth1"},
	}
	deps := b.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("Dependencies() returned %d deps, want 2", len(deps))
	}
	names := map[string]bool{}
	for _, dep := range deps {
		if dep.RequiredItem.ItemType != genericitems.PhysIfTypename {
			t.Errorf("dep.ItemType = %q, want %q", dep.RequiredItem.ItemType, genericitems.PhysIfTypename)
		}
		names[dep.RequiredItem.ItemName] = true
	}
	if !names["eth0"] || !names["eth1"] {
		t.Errorf("deps should reference eth0 and eth1, got %v", names)
	}
	// MustSatisfy on the eth0 dependency: requires IOUsageBondAggrIf and
	// MasterIfName == "bond0".
	eth0Dep := depByName(t, deps, "eth0")
	goodPhysIf := PhysIf{
		PhysIfName:   "eth0",
		Usage:        genericitems.IOUsageBondAggrIf,
		MasterIfName: "bond0",
	}
	wrongUsage := PhysIf{
		PhysIfName:   "eth0",
		Usage:        genericitems.IOUsageAdapter,
		MasterIfName: "bond0",
	}
	wrongMaster := PhysIf{
		PhysIfName:   "eth0",
		Usage:        genericitems.IOUsageBondAggrIf,
		MasterIfName: "bond1",
	}
	if !eth0Dep.MustSatisfy(goodPhysIf) {
		t.Error("MustSatisfy(correct physif) = false, want true")
	}
	if eth0Dep.MustSatisfy(wrongUsage) {
		t.Error("MustSatisfy(wrong usage) = true, want false")
	}
	if eth0Dep.MustSatisfy(wrongMaster) {
		t.Error("MustSatisfy(wrong master) = true, want false")
	}
}

func TestBondDependenciesEmpty(t *testing.T) {
	t.Parallel()
	b := Bond{IfName: "bond0", AggregatedIfNames: nil}
	if deps := b.Dependencies(); len(deps) != 0 {
		t.Errorf("Dependencies() with no members = %d deps, want 0", len(deps))
	}
}

func TestBondNeedsRecreate(t *testing.T) {
	t.Parallel()
	c := &BondConfigurator{}
	base := Bond{
		BondConfig: types.BondConfig{
			Mode:     types.BondModeActiveBackup,
			LacpRate: types.LacpRateUnspecified,
			MIIMonitor: types.BondMIIMonitor{
				Enabled:  true,
				Interval: 100,
			},
		},
		IfName:            "bond0",
		AggregatedIfNames: []string{"eth0", "eth1"},
		MTU:               1500,
	}
	type test struct {
		name      string
		old, new  Bond
		expCreate bool
	}
	tests := []test{
		{
			name:      "no change",
			old:       base,
			new:       base,
			expCreate: false,
		},
		{
			name: "only aggregated interfaces changed",
			old:  base,
			new: Bond{
				BondConfig:        base.BondConfig,
				IfName:            "bond0",
				AggregatedIfNames: []string{"eth0"},
				MTU:               1500,
			},
			expCreate: false,
		},
		{
			name: "only MTU changed",
			old:  base,
			new: Bond{
				BondConfig:        base.BondConfig,
				IfName:            "bond0",
				AggregatedIfNames: base.AggregatedIfNames,
				MTU:               9000,
			},
			expCreate: false,
		},
		{
			name: "mode changed",
			old:  base,
			new: Bond{
				BondConfig: types.BondConfig{
					Mode:     types.BondMode802Dot3AD,
					LacpRate: types.LacpRateUnspecified,
					MIIMonitor: types.BondMIIMonitor{
						Enabled:  true,
						Interval: 100,
					},
				},
				IfName:            "bond0",
				AggregatedIfNames: base.AggregatedIfNames,
				MTU:               1500,
			},
			expCreate: true,
		},
		{
			name: "LacpRate changed",
			old:  base,
			new: Bond{
				BondConfig: types.BondConfig{
					Mode:     types.BondModeActiveBackup,
					LacpRate: types.LacpRateFast,
					MIIMonitor: types.BondMIIMonitor{
						Enabled:  true,
						Interval: 100,
					},
				},
				IfName:            "bond0",
				AggregatedIfNames: base.AggregatedIfNames,
				MTU:               1500,
			},
			expCreate: true,
		},
		{
			name: "MIIMonitor changed",
			old:  base,
			new: Bond{
				BondConfig: types.BondConfig{
					Mode:     types.BondModeActiveBackup,
					LacpRate: types.LacpRateUnspecified,
					MIIMonitor: types.BondMIIMonitor{
						Enabled:  true,
						Interval: 200,
					},
				},
				IfName:            "bond0",
				AggregatedIfNames: base.AggregatedIfNames,
				MTU:               1500,
			},
			expCreate: true,
		},
		{
			name: "ARPMonitor changed",
			old:  base,
			new: Bond{
				BondConfig: types.BondConfig{
					Mode:     types.BondModeActiveBackup,
					LacpRate: types.LacpRateUnspecified,
					ARPMonitor: types.BondArpMonitor{
						Enabled:  true,
						Interval: 1000,
					},
				},
				IfName:            "bond0",
				AggregatedIfNames: base.AggregatedIfNames,
				MTU:               1500,
			},
			expCreate: true,
		},
	}
	for _, tc := range tests {
		got := c.NeedsRecreate(tc.old, tc.new)
		if got != tc.expCreate {
			t.Errorf("TEST CASE %q: NeedsRecreate() = %v, want %v", tc.name, got, tc.expCreate)
		}
	}
}

func TestIsFailoverBondMode(t *testing.T) {
	t.Parallel()
	type test struct {
		mode       types.BondMode
		isFailover bool
	}
	tests := []test{
		{types.BondModeActiveBackup, true},
		{types.BondModeBalanceTLB, true},
		{types.BondModeBalanceALB, true},
		{types.BondModeBalanceRR, false},
		{types.BondMode802Dot3AD, false},
		{types.BondModeBalanceXOR, false},
		{types.BondModeBroadcast, false},
		{types.BondModeUnspecified, false},
	}
	for _, tc := range tests {
		got := isFailoverBondMode(tc.mode)
		if got != tc.isFailover {
			t.Errorf("isFailoverBondMode(%v) = %v, want %v", tc.mode, got, tc.isFailover)
		}
	}
}

// ---------------------------------------------------------------------------
// Vlan tests
// ---------------------------------------------------------------------------

func TestVlanEqual(t *testing.T) {
	t.Parallel()
	base := Vlan{
		IfName:       "eth0.100",
		ParentIfName: "eth0",
		ID:           100,
		MTU:          1500,
	}
	type test struct {
		name     string
		a, b     Vlan
		expEqual bool
	}
	tests := []test{
		{
			name:     "identical",
			a:        base,
			b:        base,
			expEqual: true,
		},
		{
			name:     "different parent",
			a:        base,
			b:        Vlan{IfName: "eth0.100", ParentIfName: "eth1", ID: 100, MTU: 1500},
			expEqual: false,
		},
		{
			name:     "different VLAN ID",
			a:        base,
			b:        Vlan{IfName: "eth0.100", ParentIfName: "eth0", ID: 200, MTU: 1500},
			expEqual: false,
		},
		{
			name:     "different MTU",
			a:        base,
			b:        Vlan{IfName: "eth0.100", ParentIfName: "eth0", ID: 100, MTU: 9000},
			expEqual: false,
		},
	}
	for _, tc := range tests {
		got := tc.a.Equal(tc.b)
		if got != tc.expEqual {
			t.Errorf("TEST CASE %q: Equal() = %v, want %v", tc.name, got, tc.expEqual)
		}
	}
}

func TestVlanGetMTU(t *testing.T) {
	t.Parallel()
	if got := (Vlan{MTU: 0}).GetMTU(); got != types.DefaultMTU {
		t.Errorf("GetMTU() with zero MTU = %d, want DefaultMTU %d", got, types.DefaultMTU)
	}
	if got := (Vlan{MTU: 9000}).GetMTU(); got != 9000 {
		t.Errorf("GetMTU() with 9000 = %d, want 9000", got)
	}
}

func TestVlanDependencies(t *testing.T) {
	t.Parallel()
	v := Vlan{
		IfName:       "eth0.100",
		ParentIfName: "eth0",
		ID:           100,
		MTU:          1500,
	}
	deps := v.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("Dependencies() returned %d deps, want 1", len(deps))
	}
	dep := deps[0]
	if dep.RequiredItem.ItemType != genericitems.AdapterTypename {
		t.Errorf("dep.ItemType = %q, want %q", dep.RequiredItem.ItemType, genericitems.AdapterTypename)
	}
	if dep.RequiredItem.ItemName != "eth0" {
		t.Errorf("dep.ItemName = %q, want %q", dep.RequiredItem.ItemName, "eth0")
	}

	goodAdapter := Adapter{IfName: "eth0", UsedAsVlanParent: true, MTU: 1500}
	notVlanParent := Adapter{IfName: "eth0", UsedAsVlanParent: false, MTU: 1500}
	tooSmallMTU := Adapter{IfName: "eth0", UsedAsVlanParent: true, MTU: 1000}
	// Non-Adapter item: MustSatisfy uses a type assertion with ok check → false.
	nonAdapter := PhysIf{PhysIfName: "eth0"}

	if !dep.MustSatisfy(goodAdapter) {
		t.Error("MustSatisfy(good adapter) = false, want true")
	}
	if dep.MustSatisfy(notVlanParent) {
		t.Error("MustSatisfy(not vlan parent) = true, want false")
	}
	if dep.MustSatisfy(tooSmallMTU) {
		t.Error("MustSatisfy(MTU too small) = true, want false")
	}
	if dep.MustSatisfy(nonAdapter) {
		t.Error("MustSatisfy(non-adapter) = true, want false")
	}
}

func TestVlanNeedsRecreate(t *testing.T) {
	t.Parallel()
	c := &VlanConfigurator{}
	base := Vlan{IfName: "eth0.100", ParentIfName: "eth0", ID: 100, MTU: 1500}
	type test struct {
		name      string
		old, new  Vlan
		expCreate bool
	}
	tests := []test{
		{
			name:      "no change",
			old:       base,
			new:       base,
			expCreate: false,
		},
		{
			name:      "only MTU changed",
			old:       base,
			new:       Vlan{IfName: "eth0.100", ParentIfName: "eth0", ID: 100, MTU: 9000},
			expCreate: false,
		},
		{
			name:      "parent changed",
			old:       base,
			new:       Vlan{IfName: "eth0.100", ParentIfName: "eth1", ID: 100, MTU: 1500},
			expCreate: true,
		},
		{
			name:      "VLAN ID changed",
			old:       base,
			new:       Vlan{IfName: "eth0.100", ParentIfName: "eth0", ID: 200, MTU: 1500},
			expCreate: true,
		},
	}
	for _, tc := range tests {
		got := c.NeedsRecreate(tc.old, tc.new)
		if got != tc.expCreate {
			t.Errorf("TEST CASE %q: NeedsRecreate() = %v, want %v", tc.name, got, tc.expCreate)
		}
	}
}
