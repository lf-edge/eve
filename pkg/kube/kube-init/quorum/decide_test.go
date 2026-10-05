// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package quorum

import (
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
)

func gen(id string, n uint32) k3s.Generation { return k3s.Generation{ClusterID: id, Counter: n} }

// TestDecide is the contract for when a node converges. The expensive
// mistakes are in both directions: acting when it should not resets a
// healthy cluster, and not acting when it should leaves a node holding
// etcd state from a cluster that no longer exists.
func TestDecide(t *testing.T) {
	cases := []struct {
		name string
		in   Inputs
		want Action
	}{
		{
			name: "converged",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 1), Recorded: true,
				HasEtcdState: true},
			want: ActionNone,
		},
		{
			name: "seed promotes on a bump",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 0), Recorded: true,
				IsSeed: true, HasEtcdState: true},
			want: ActionPromote,
		},
		{
			// The node powered off across the increment. It has a
			// record from when it joined, so the difference is visible
			// even though it was absent for the change - but with only
			// two physical nodes, seeing this at all as a non-seed means
			// the controller has not withdrawn its cluster config yet,
			// which is not this package's problem to solve.
			name: "non-seed does nothing on a bump",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 0), Recorded: true,
				HasEtcdState: true},
			want: ActionNone,
		},
		{
			// A counter that moves backwards still means the cluster
			// changed under this node. Treating only increases as real
			// would leave a seed on state everyone else discarded.
			name: "seed promotes even on a decrease",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 3), Recorded: true,
				IsSeed: true, HasEtcdState: true},
			want: ActionPromote,
		},
		{
			name: "seed promotes for a different cluster id",
			in: Inputs{Want: gen("b", 0), Applied: gen("a", 0), Recorded: true,
				IsSeed: true, HasEtcdState: true},
			want: ActionPromote,
		},
		{
			// The contract: a recovery moves join_server_ip to the
			// survivor. A seed that already owned it when it recorded
			// the generation is not being named, and resetting it would
			// strand a peer whose witness-backed quorum was fine.
			name: "seed rejects a bump when it was already seed",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 0), Recorded: true,
				AppliedAsSeed: true, IsSeed: true, HasEtcdState: true},
			want: ActionReject,
		},
		{
			name: "seed rejects a decrease when it was already seed",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 3), Recorded: true,
				AppliedAsSeed: true, IsSeed: true, HasEtcdState: true},
			want: ActionReject,
		},
		{
			name: "converged seed is left alone",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 1), Recorded: true,
				AppliedAsSeed: true, IsSeed: true, HasEtcdState: true},
			want: ActionNone,
		},
		{
			// A different cluster ID is a different cluster, not a bump.
			name: "was-seed promotes for a different cluster id",
			in: Inputs{Want: gen("b", 0), Applied: gen("a", 0), Recorded: true,
				AppliedAsSeed: true, IsSeed: true, HasEtcdState: true},
			want: ActionPromote,
		},
		{
			// The old seed's config is normally withdrawn, but if it is
			// not, it must still not act on a bump naming someone else.
			name: "was-seed that lost the seed role does nothing",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 0), Recorded: true,
				AppliedAsSeed: true, HasEtcdState: true},
			want: ActionNone,
		},
		{
			// First boot of a fresh node. Nothing to converge to.
			name: "first sighting at generation 0 only records",
			in:   Inputs{Want: gen("a", 0)},
			want: ActionNone,
		},
		{
			// The upgrade case, and the one that would hurt most: a
			// healthy member meeting the record for the first time
			// after an EVE upgrade. It has etcd state and no record,
			// but no recovery has ever happened, so acting here would
			// reset a working cluster.
			name: "healthy member upgrading into this code only records",
			in:   Inputs{Want: gen("a", 0), IsSeed: true, HasEtcdState: true},
			want: ActionNone,
		},
		{
			// A node with no etcd state has nothing to reset from,
			// however far the counter has moved.
			name: "fresh seed joining after a recovery only records",
			in:   Inputs{Want: gen("a", 2), IsSeed: true},
			want: ActionNone,
		},
		{
			// The narrow gap: a seed whose first boot under this code
			// happens only after a recovery. No record, but its etcd
			// belongs to the cluster as it was before.
			name: "seed that missed the record still promotes",
			in:   Inputs{Want: gen("a", 1), IsSeed: true, HasEtcdState: true},
			want: ActionPromote,
		},
		{
			// A non-seed with no record needs no nuance at all: nothing
			// this package does ever applies to it.
			name: "non-seed that missed the record still does nothing",
			in:   Inputs{Want: gen("a", 1), HasEtcdState: true},
			want: ActionNone,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Decide(c.in); got != c.want {
				t.Errorf("Decide() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestActionRoundTrip(t *testing.T) {
	for _, want := range []Action{ActionNone, ActionPromote} {
		got, err := parseAction(want.String())
		if err != nil || got != want {
			t.Errorf("round trip of %v gave (%v, %v)", want, got, err)
		}
	}
	// A rejection is never recorded as an intent, so it must not parse.
	if _, err := parseAction(ActionReject.String()); err == nil {
		t.Error("parseAction accepted a reject, which is never an intent")
	}
	if _, err := parseAction("nonsense"); err == nil {
		t.Error("parseAction accepted an unknown action")
	}
}

// TestNextApplied: a non-seed must not record a bump, or a join_server_ip
// change arriving after it would find nothing left to promote for.
func TestNextApplied(t *testing.T) {
	cases := []struct {
		name        string
		in          Inputs
		wantGen     k3s.Generation
		wantAsSeed  bool
		wantWritten bool
	}{
		{name: "first sighting records the baseline",
			in:      Inputs{Want: gen("a", 2), IsSeed: true},
			wantGen: gen("a", 2), wantAsSeed: true, wantWritten: true},
		{name: "non-seed first sighting records without the seed bit",
			in:      Inputs{Want: gen("a", 2)},
			wantGen: gen("a", 2), wantWritten: true},
		{name: "non-seed leaves a bump pending",
			in:      Inputs{Want: gen("a", 1), Applied: gen("a", 0), Recorded: true},
			wantGen: gen("a", 0)},
		{name: "non-seed pending bump still drops the seed bit",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 0), Recorded: true,
				AppliedAsSeed: true},
			wantGen: gen("a", 0), wantWritten: true},
		{name: "converged non-seed drops the seed bit",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 1), Recorded: true,
				AppliedAsSeed: true},
			wantGen: gen("a", 1), wantWritten: true},
		{name: "converged seed keeps the seed bit and writes nothing",
			in: Inputs{Want: gen("a", 1), Applied: gen("a", 1), Recorded: true,
				AppliedAsSeed: true, IsSeed: true},
			wantGen: gen("a", 1), wantAsSeed: true},
		{name: "non-seed records a different cluster",
			in:      Inputs{Want: gen("b", 0), Applied: gen("a", 3), Recorded: true},
			wantGen: gen("b", 0), wantWritten: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, asSeed, write := nextApplied(c.in)
			if g != c.wantGen || asSeed != c.wantAsSeed || write != c.wantWritten {
				t.Errorf("nextApplied() = (%v, %v, %v), want (%v, %v, %v)",
					g, asSeed, write, c.wantGen, c.wantAsSeed, c.wantWritten)
			}
		})
	}
}
