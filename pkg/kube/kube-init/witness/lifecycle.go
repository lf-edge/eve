// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package witness

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/etcd"
	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/quorum"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// ErrNotWanted reports that no witness should run on this device right
// now. Not a failure: it is the steady state on every device that is
// not the seed, and on every cluster with no witness configured.
var ErrNotWanted = errors.New("witness not wanted on this device")

// ErrFenced reports that the seed is resetting the cluster and the
// witness must wait. Transient, unlike ErrNotWanted: the FSM retries
// rather than parking.
var ErrFenced = errors.New("witness held off while the seed resets the cluster")

// membershipMarker records which cluster's etcd the data directory
// belongs to. Under /var/lib, which is the witness's own persistent
// storage, so it survives reboots alongside the data it describes.
var membershipMarker = "/var/lib/witness/membership"

// dataDir is the k3s state the witness accumulates as a member.
var dataDir = "/var/lib/rancher/k3s"

// Fenced reports whether the seed is mid-promote and the witness must
// hold off, and why.
//
// Joining during a reset puts this witness in the membership the reset
// is about to discard: it vanishes from the cluster while still
// believing it is a member, and leaves its peer URL registered for the
// next join to collide with. Waiting costs one vote for the length of a
// reset, during which the cluster has no quorum to improve anyway.
func Fenced() (bool, string) { return quorum.WitnessFenceHeld() }

// Wanted reports whether this device should be running the witness.
//
// The witness always co-locates with whichever device currently owns
// join_server_ip, so ownership is the placement rule; there is no
// separate placement field in the API. A device that is not the seed
// runs no witness, and neither does any device when the controller
// configured no witness IP.
func Wanted(cs *k3s.ClusterStatus) bool {
	return cs != nil && cs.WitnessIP != "" && cs.IsBootstrapNode
}

// membership is the identity of the cluster the local data belongs to.
//
// The same generation the kube role converges to, and deliberately the
// same type: a witness keyed on a format that drifted from the nodes'
// would wipe when it should not, or worse, not when it should.
//
// The recovery counter is part of it because a quorum recovery forcibly
// resets the cluster while keeping the UUID the controller assigned, so
// the surviving node starts an etcd cluster that every former member's
// data is incompatible with. Keying on the UUID alone would miss that,
// leaving the witness crash-looping against state etcd refuses until
// someone wipes it by hand.
func membership(cs *k3s.ClusterStatus) k3s.Generation {
	return k3s.Generation{
		ClusterID: cs.ClusterID,
		Counter:   cs.QuorumRecoveryGeneration,
	}
}

// SyncMembership wipes the witness's k3s state when it belongs to a
// different cluster, or to the same cluster before a quorum recovery,
// and records what the state now belongs to.
//
// Wiping is the only option: etcd refuses to join a cluster whose ID
// does not match the one in its data directory, and the certificates
// are signed by a CA the new cluster does not know. A witness left with
// stale state crash-loops instead of voting.
//
// The marker is written before k3s starts rather than after it joins.
// A wipe that ran but was not recorded would repeat on the next boot,
// destroying a freshly joined member each time.
func SyncMembership(cs *k3s.ClusterStatus) error {
	want := membership(cs)
	got, recorded, err := readMembership()
	if err != nil {
		return err
	}
	if recorded && got == want {
		return nil
	}
	if recorded {
		log.Printf("witness: membership changed (%q -> %q), wiping local etcd state",
			got, want)
		if err := wipeDataDir(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(membershipMarker), 0755); err != nil {
		return fmt.Errorf("create membership dir: %w", err)
	}
	if err := state.AtomicWriteFile(membershipMarker,
		[]byte(want.String()+"\n"), 0644); err != nil {
		return fmt.Errorf("write membership marker: %w", err)
	}
	return nil
}

func readMembership() (g k3s.Generation, recorded bool, err error) {
	raw, err := os.ReadFile(membershipMarker)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return k3s.Generation{}, false, nil
		}
		return k3s.Generation{}, false,
			fmt.Errorf("read membership marker: %w", err)
	}
	return k3s.ParseGeneration(string(raw))
}

// wipeDataDir removes the server state tied to a specific cluster: the
// etcd database, the cluster CA and issued certificates, credentials
// and staged manifests. What is left is the k3s install itself, which
// is cluster-independent.
func wipeDataDir() error {
	for _, sub := range []string{
		"server/db", "server/tls", "server/cred", "server/manifests", "agent",
	} {
		path := filepath.Join(dataDir, sub)
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("wipe %s: %w", path, err)
		}
	}
	log.Printf("witness: wiped %s", dataDir)
	return nil
}

// leaveTimeout bounds the departure. Short on purpose: going idle is
// not allowed to hang on an etcd that is already unreachable.
var leaveTimeout = 15 * time.Second

// Leave removes this witness from the cluster's etcd membership.
//
// Must run while k3s is still up, since it talks to the local etcd. A
// member left behind keeps its peer URL registered, and the witness
// re-joining later, or a replacement witness on another device taking
// the same IP, collides with it and the join fails.
//
// Best-effort by design. If etcd is already gone there is nothing to
// remove from here, and the cluster still has to converge: the seed
// prunes stale witness members before admitting a new one. Failing to
// leave must not stop the witness going idle, or a controller
// withdrawing the witness could never take effect.
func Leave(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, leaveTimeout)
	defer cancel()

	members, err := etcd.Members(ctx)
	if err != nil {
		log.Printf("witness: cannot read membership to leave: %v "+
			"(the seed prunes stale members before a re-join)", err)
		return
	}
	ours := etcd.FindByNamePrefix(members, NodeName)
	if len(ours) == 0 {
		return
	}
	for _, m := range ours {
		if err := etcd.RemoveMember(ctx, m); err != nil {
			log.Printf("witness: leave: %v "+
				"(the seed prunes stale members before a re-join)", err)
			continue
		}
		log.Printf("witness: removed own etcd member %s (%s)", m.Name, m.IDHex())
	}
}

// PruneMembers removes every witness member from the cluster's etcd.
//
// Run by the seed while the fence is held, so no witness is joining and
// anything found is left over. A witness whose device died had no
// chance to leave, and its entry keeps the witness address registered:
// the replacement claims the same address, since the address follows the
// seed rather than the device, so the two collide and the join fails.
//
// Best-effort. The etcd it talks to has just come back from a reset, and
// a cluster that will not answer yet is better retried on the next join
// than treated as a failed recovery.
func PruneMembers(ctx context.Context) {
	members, err := etcd.Members(ctx)
	if err != nil {
		log.Printf("witness: cannot read membership to prune: %v", err)
		return
	}
	for _, m := range etcd.FindByNamePrefix(members, NodeName) {
		if err := etcd.RemoveMember(ctx, m); err != nil {
			log.Printf("witness: prune %s: %v", m.Name, err)
			continue
		}
		log.Printf("witness: pruned stale etcd member %s (%s)", m.Name, m.IDHex())
	}
}
