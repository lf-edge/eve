// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package quorum converges this node to the controller's quorum-loss
// recovery generation.
//
// Losing quorum is not something a device can fix on its own: with a
// majority of etcd members gone, the survivors cannot elect a leader or
// agree to evict anyone, so no amount of local retrying helps. The
// controller breaks the tie by naming a new seed and incrementing
// EdgeNodeCluster.quorum_recovery_generation. The node now named by
// join_server_ip forces its etcd into a single-member cluster; every
// other current or former member has its cluster config withdrawn
// outright instead and rejoins later through the ordinary join workflow,
// so this package never acts on their behalf.
package quorum

import (
	"fmt"
	"log"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/encconfig"
	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
)

// Action is what a node must do to converge to a generation.
type Action int

// Actions.
const (
	// ActionNone: already converged, or a first sighting that only
	// needs recording.
	ActionNone Action = iota
	// ActionPromote: force this node's etcd into a single-member
	// cluster and become the sole bootstrap.
	ActionPromote
	// ActionReject: the controller bumped the generation without moving
	// join_server_ip off this node, which is not a recovery. Nothing is
	// done and the bump is reported back instead.
	ActionReject
)

// String returns the action name, which is also what the intent
// records.
func (a Action) String() string {
	switch a {
	case ActionPromote:
		return "promote"
	case ActionReject:
		return "reject"
	default:
		return "none"
	}
}

// parseAction reads back what String wrote.
func parseAction(s string) (Action, error) {
	switch s {
	case "promote":
		return ActionPromote, nil
	case "none":
		return ActionNone, nil
	}
	return ActionNone, fmt.Errorf("unknown recovery action %q", s)
}

// Inputs is what the decision is made from.
type Inputs struct {
	// Want is the generation the controller is asking for.
	Want k3s.Generation
	// Applied is what this node last converged to, and Recorded says
	// whether it has ever recorded one.
	Applied  k3s.Generation
	Recorded bool
	// AppliedAsSeed is true when this node was already the seed when it
	// recorded Applied, and has not been seen as anything else since.
	AppliedAsSeed bool
	// IsSeed is true when this node owns join_server_ip, which is the
	// controller's way of naming the survivor to promote.
	IsSeed bool
	// HasEtcdState is true when this node holds an initialised etcd
	// data directory, meaning it was a member of some cluster.
	HasEtcdState bool
}

// Decide returns the action that converges this node to Inputs.Want.
//
// Comparison is by inequality, never "newer than". The counter is a
// uint32 that a controller-side restore or a device reprovision can
// move backwards, and a node that ignored a decrease would keep state
// the rest of the cluster has discarded.
//
// Only the seed ever has anything to do here. A non-seed node seeing a
// generation it has not recorded means the controller withdrew its
// cluster config without this node noticing yet, or has not withdrawn
// it as expected, or has bumped the generation ahead of moving
// join_server_ip to this node. There is no action for this package to
// take on its behalf: it converges by leaving and rejoining through the
// ordinary join workflow, not by wiping in place, and the bump stays
// unrecorded (see nextApplied) so it still applies if this node becomes
// the seed.
func Decide(in Inputs) Action {
	if in.Recorded && in.Applied == in.Want {
		return ActionNone
	}
	// A recovery moves join_server_ip to the survivor, so a node that
	// was already the seed at the generation it recorded is not being
	// named by this bump. Acting would reset a cluster whose seed still
	// has its witness and therefore its quorum, and strand the peer.
	// Another cluster ID is a different cluster, not a bump.
	if in.IsSeed && in.Recorded && in.AppliedAsSeed &&
		in.Applied.ClusterID == in.Want.ClusterID {
		return ActionReject
	}
	if !in.IsSeed {
		return ActionNone
	}
	if !in.Recorded {
		// Never recorded. Two very different situations look the same
		// here, and getting them the wrong way round is expensive.
		//
		// Counter 0 means no recovery has ever happened for this
		// cluster, so there is nothing to converge to: this is either a
		// node joining for the first time or, just as common, a node
		// that was already a healthy member before this code existed
		// and is meeting the record for the first time after an EVE
		// upgrade. Acting on it would reset a working cluster.
		//
		// Above 0 a recovery has happened. A seed with no record but
		// with etcd state was already a member before this reset: its
		// data belongs to the cluster as it was before, so it still
		// has to promote. Without etcd state there is nothing to reset
		// from, so recording is enough.
		if in.Want.Counter == 0 || !in.HasEtcdState {
			return ActionNone
		}
	}
	return ActionPromote
}

// Evaluate reports the action this node owes the controller's recovery
// generation, if any.
//
// Resuming an action already begun takes precedence over deciding
// afresh, so a crash mid-action cannot change its mind about what it
// was doing.
//
// A device with no cluster config has nothing to converge to, which is
// not the same as being at generation zero, so it is left alone.
//
// When nothing is owed, the current generation is recorded as the
// baseline the first time it is seen. That is what makes a later change
// visible to a node that was powered off when it happened: without a
// record, absence and agreement look identical. A later change seen by a
// non-seed is not recorded, see nextApplied.
//
// A generation change on a node that was already the seed is not a
// recovery, so it is rejected and reported rather than acted on.
func Evaluate() (in Intent, needed bool, err error) {
	cs, err := k3s.GetClusterStatus()
	if err != nil {
		return Intent{}, false, nil //nolint:nilerr // not clustered
	}
	if resumed, found, err := Resume(); err != nil {
		return Intent{}, false, err
	} else if found {
		log.Printf("resuming %s for generation %s", resumed.Action, resumed.Generation)
		return resumed, true, nil
	}

	applied, appliedAsSeed, recorded, err := readApplied()
	if err != nil {
		return Intent{}, false, err
	}
	want, isSeed := controllerIntent(cs)
	action := Decide(Inputs{
		Want:          want,
		Applied:       applied,
		AppliedAsSeed: appliedAsSeed,
		Recorded:      recorded,
		IsSeed:        isSeed,
		HasEtcdState:  k3s.EtcdClusterInitialized(),
	})
	switch action {
	case ActionReject:
		return Intent{}, false, reportRejection(applied, want)
	case ActionNone:
		in := Inputs{Want: want, Applied: applied, AppliedAsSeed: appliedAsSeed,
			Recorded: recorded, IsSeed: isSeed}
		if g, asSeed, write := nextApplied(in); write {
			if err := WriteApplied(g, asSeed); err != nil {
				return Intent{}, false, err
			}
			log.Printf("recorded quorum-recovery baseline %s", g)
		}
		if !isSeed || (recorded && applied == want) {
			// Nothing is being rejected any more: the controller
			// withdrew the bump, or this node is no longer the seed.
			if err := ClearFailure(); err != nil {
				return Intent{}, false, err
			}
		}
		return Intent{}, false, nil
	}
	return Intent{Generation: want, Action: action, StartedAt: time.Now()}, true, nil
}

// nextApplied is what to record as the applied generation when nothing is
// owed: the generation, the role bit, and whether to write at all.
//
// A bump seen by a non-seed is left pending rather than recorded. The
// controller may move join_server_ip to this node in a later config
// change than the bump, and recording it here would make this node
// believe it had already converged, so it would never promote and the
// controller would have to bump again. Only the role bit is refreshed,
// so a node promoted later is not mistaken for one that was always seed.
// A different cluster ID is a different cluster, not a pending bump.
func nextApplied(in Inputs) (g k3s.Generation, asSeed, write bool) {
	switch {
	case !in.Recorded:
		return in.Want, in.IsSeed, true
	case !in.IsSeed && in.Applied.ClusterID == in.Want.ClusterID:
		return in.Applied, false, in.AppliedAsSeed
	case in.Applied == in.Want:
		return in.Applied, in.AppliedAsSeed, false
	default:
		return in.Want, in.IsSeed, true
	}
}

// reportRejection records why a generation change was ignored, for
// StampNodeStatus to report to the controller. Left in place until the
// controller withdraws the bump, so the record is only rewritten when
// the reason changes.
func reportRejection(applied, want k3s.Generation) error {
	cause := fmt.Errorf("this device already owns join_server_ip, so changing the "+
		"generation from %d to %d does not name a new seed; ignoring it "+
		"(a recovery moves join_server_ip to the surviving device)",
		applied.Counter, want.Counter)
	msg := fmt.Sprintf("Failed to promote cluster to generation %d: %v", want.Counter, cause)
	if prev, found, err := ReadFailure(); err == nil && found && prev == msg {
		return nil
	}
	log.Printf("quorum recovery: %v", cause)
	return WriteFailure(want, cause)
}

// controllerIntent is the generation this node owes and whether it is the
// seed, taken from the config zedagent publishes rather than the status
// zedkube mirrors from it.
//
// A recovery is asked for when the cluster has lost quorum, which is when
// zedkube's own Kubernetes calls stall and its status stops being
// refreshed: on a two-node cluster the promotion took nine minutes to
// arrive that way, against two seconds for the config. Everything after
// the reset may wait for zedkube — the refreshed status, the witness veth
// NIM plugs from it, the witness itself — because the reset is what makes
// those possible again. The reset must not.
//
// The status still supplies what the reset runs with, the decrypted token
// above all, which only zedkube can produce. That is safe: a recovery
// preserves the token, so the last status published before quorum was
// lost still describes it.
//
// Falls back to the status when no config has arrived, which is the shape
// every other reader here assumes.
func controllerIntent(cs *k3s.ClusterStatus) (want k3s.Generation, isSeed bool) {
	want = k3s.Generation{
		ClusterID: cs.ClusterID,
		Counter:   cs.QuorumRecoveryGeneration,
	}
	isSeed = cs.IsBootstrapNode
	if !encconfig.Present() {
		return want, isSeed
	}
	cfg, ok := encconfig.Get()
	if !ok {
		return want, isSeed
	}
	return k3s.Generation{
		ClusterID: cfg.ClusterID.UUID.String(),
		Counter:   cfg.QuorumRecoveryGeneration,
	}, cfg.BootstrapNode
}
