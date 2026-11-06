// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

var (
	wlA = uuid.FromStringOrNil("00000000-0000-0000-0000-00000000000a")
	wlB = uuid.FromStringOrNil("00000000-0000-0000-0000-00000000000b")
	wlC = uuid.FromStringOrNil("00000000-0000-0000-0000-00000000000c")
	wlD = uuid.FromStringOrNil("00000000-0000-0000-0000-00000000000d")
)

func holding(owner uuid.UUID, cpus ...cputopology.LCPU) map[cputopology.LCPU]uuid.UUID {
	m := map[cputopology.LCPU]uuid.UUID{}
	for _, c := range cpus {
		m[c] = owner
	}
	return m
}

func merge(maps ...map[cputopology.LCPU]uuid.UUID) map[cputopology.LCPU]uuid.UUID {
	out := map[cputopology.LCPU]uuid.UUID{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// A is refused; its planned CPUs are held by B, whose own planned CPUs are held
// by C, whose planned CPUs are free. B alone is not enough: restarting A and B
// leaves B's new slot occupied, so C has to move too. D sits on its planned
// CPUs and is nobody's obstacle, so it keeps running.
func TestRepackMembers_FollowsTheChain(t *testing.T) {
	holders := merge(holding(wlB, 0, 4), holding(wlC, 1, 5), holding(wlD, 3, 7))
	plan := map[uuid.UUID]cpuallocator.Result{
		wlA: plannedOn(0, 4),
		wlB: plannedOn(1, 5),
		wlC: plannedOn(2, 6),
		wlD: plannedOn(3, 7),
	}
	members := repackMembers(holders, plan, map[uuid.UUID]bool{wlA: true})
	if !members[wlB] || !members[wlC] {
		t.Errorf("members = %v, want B (on A's slot) and C (on B's new slot)", members)
	}
	if members[wlD] {
		t.Error("D is on its planned slot and in nobody's way; it must not be restarted")
	}
	if members[wlA] {
		t.Error("the beneficiary is not a member of its own repack")
	}
}

// With no workload needing a repack, a running workload whose CPUs differ from
// its plan entry is left alone: landing on other CPUs of equal quality is not a
// reason to restart it.
func TestRepackMembers_NoBeneficiaryNoMembers(t *testing.T) {
	holders := holding(wlB, 0, 4)
	plan := map[uuid.UUID]cpuallocator.Result{wlB: plannedOn(1, 5)}
	if members := repackMembers(holders, plan, map[uuid.UUID]bool{}); len(members) != 0 {
		t.Errorf("members = %v, want none", members)
	}
}

// A running beneficiary (placed sub-optimally) holds CPUs of its own; the walk
// must not count it as standing in its own way.
func TestRepackMembers_RunningBeneficiary(t *testing.T) {
	holders := merge(holding(wlA, 2, 6), holding(wlB, 0, 4))
	plan := map[uuid.UUID]cpuallocator.Result{
		wlA: plannedOn(0, 4),
		wlB: plannedOn(2, 6),
	}
	members := repackMembers(holders, plan, map[uuid.UUID]bool{wlA: true})
	if !members[wlB] || members[wlA] || len(members) != 1 {
		t.Errorf("members = %v, want exactly B", members)
	}
}

func TestUnplacedHolders(t *testing.T) {
	holders := merge(holding(wlB, 0, 4), holding(wlC, 1, 5))
	plan := map[uuid.UUID]cpuallocator.Result{
		wlB: plannedOn(0, 4),
		wlC: {Status: cpuallocator.Insufficient},
	}
	got := unplacedHolders(holders, plan)
	if len(got) != 1 || got[0] != wlC {
		t.Errorf("unplaced = %v, want [C]", got)
	}
}

// With the isolated pool full, the plan "fits" a third isolated workload only
// by leaving out one already running. That is an eviction, and must be reported
// as a shortage, not as a repack that restarts the others for nothing.
func TestLiveAllocationError_EvictionIsNotARepack(t *testing.T) {
	plan := map[uuid.UUID]cpuallocator.Result{wlA: plannedOn(12, 13, 14, 15)}
	live := cpuallocator.Result{Status: cpuallocator.Insufficient, Message: "need 2 free cores, have 0"}

	err := liveAllocationError("h4-c", wlA, live, plan, []string{"h4-a"}, []string{"h4-b"})
	if err.Status != types.CPUPlacementStatusInsufficient {
		t.Errorf("code = %q, want %q (%s)", err.Status,
			types.CPUPlacementStatusInsufficient, err.Msg)
	}
	if !strings.Contains(err.Msg, "h4-b") {
		t.Errorf("the message must name the running workload the plan leaves out: %s", err.Msg)
	}

	if repack := liveAllocationError("n6-a", wlA, live, plan, []string{"n8-a"}, nil); repack.Status !=
		types.CPUPlacementStatusNeedsRepack {
		t.Errorf("a plan that places every running workload is a repack, got %q", repack.Status)
	}
}
