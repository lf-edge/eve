// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// On disk paths owned by this file. Declared as `var` so tests can
// redirect them onto temp dirs.

// startupRankFile records this node's 0-based position in the
// sorted control-plane node list. SaveStartupRank writes it; the
// supervisor reads it on the next boot via ConsumeStartupRank.
// /var/lib is a bind-mount of /persist/vault/kube — survives
// reboot.
var startupRankFile = "/var/lib/cluster-startup-rank"

// stagger per-rank base unit. The shell uses 25s; matching that
// gives the same convergence behaviour across hybrid Go/shell
// fleets during the rollout.
var startupRankDelayUnit = 25 * time.Second

// replicatedStorageMinMasters is the minimum number of
// control-plane nodes that must be visible before we trust the
// sorted IP list enough to record a rank. Replicated storage
// always provisions three masters; rank computed from a partial
// cluster could place this node at position 0 of 1 when it should
// have been position 2 of 3.
const replicatedStorageMinMasters = 3

// SaveStartupRank queries the control-plane node list, computes
// this node's 0-based rank in the sorted list, and writes it to
// startupRankFile. No-op when:
//
//   - the node is not in cluster mode (single-node, no etcd to
//     stagger);
//   - cluster_node_ip is empty (no ENC status yet);
//   - the rank file already exists (already saved this boot);
//   - the local IP is not yet in the control-plane list (worker
//     node or master that hasn't finished joining — computeRank
//     returns -1 and we retry on the next tick);
//   - replicated storage and fewer than 3 control-plane nodes
//     are visible (the missing master would compute the wrong
//     rank — retry on the next health tick).
//
// Called once per health worker tick. Idempotent.
//
// Addresses upstream commit be1537e68 ("stagger k3s startup using
// persisted control-plane rank") which introduced the equivalent
// shell flow in cluster-init.sh.
func SaveStartupRank(ctx context.Context, status *k3s.ClusterStatus) error {
	if status == nil {
		return nil
	}
	inCluster, err := state.IsMarked(state.EdgeNodeClusterMode)
	if err != nil {
		return fmt.Errorf("check cluster-mode marker: %w", err)
	}
	if !inCluster || status.ClusterIP == "" {
		return nil
	}
	// Already ranked this boot — re-query would be a waste and
	// the rank is stable across the rest of this boot anyway.
	if _, err := os.Stat(startupRankFile); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", startupRankFile, err)
	}

	masters, err := listControlPlaneIPs(ctx)
	if err != nil {
		return fmt.Errorf("list control-plane IPs: %w", err)
	}
	if len(masters) == 0 {
		return nil
	}

	ct, err := k3s.GetClusterType()
	if err != nil {
		log.Printf("stagger: get cluster type: %v (assuming replicated)", err)
		ct = k3s.ClusterTypeReplicated
	}
	if ct == k3s.ClusterTypeReplicated && len(masters) < replicatedStorageMinMasters {
		log.Printf("stagger: %d/%d control-plane nodes visible, will retry",
			len(masters), replicatedStorageMinMasters)
		return nil
	}

	rank := computeRank(status.ClusterIP, masters)
	if rank < 0 {
		// Local node not in the master list yet; retry next tick.
		log.Printf("stagger: local node %s not in control-plane list yet, will retry",
			status.ClusterIP)
		return nil
	}
	log.Printf("stagger: %s rank=%d (%d control-plane nodes)",
		status.ClusterIP, rank, len(masters))
	body := strconv.Itoa(rank) + "\n"
	return state.AtomicWriteFile(startupRankFile, []byte(body), 0644)
}

// ConsumeStartupRank reads the rank file, deletes it, and returns
// the per-rank delay (rank * startupRankDelayUnit). Zero delay if
// the file is absent, malformed, or the node is not in cluster
// mode. The file is consumed (removed) so the delay only applies
// to the boot immediately after SaveStartupRank wrote it.
//
// Returns (delay, true) when a positive delay should be applied,
// (0, false) otherwise.
func ConsumeStartupRank() (time.Duration, bool) {
	inCluster, err := state.IsMarked(state.EdgeNodeClusterMode)
	if err != nil {
		log.Printf("stagger: check cluster-mode marker: %v (no delay)", err)
		return 0, false
	}
	if !inCluster {
		return 0, false
	}
	data, err := os.ReadFile(startupRankFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("stagger: read %s: %v", startupRankFile, err)
		}
		return 0, false
	}
	// Consume regardless of parse outcome so a malformed file
	// doesn't keep applying every boot.
	if rmErr := os.Remove(startupRankFile); rmErr != nil {
		log.Printf("stagger: remove %s: %v", startupRankFile, rmErr)
	}
	rank, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		log.Printf("stagger: invalid rank %q in %s: %v",
			string(data), startupRankFile, err)
		return 0, false
	}
	if rank <= 0 {
		return 0, false
	}
	delay := time.Duration(rank) * startupRankDelayUnit
	log.Printf("stagger: rank=%d, delaying k3s start by %s", rank, delay)
	return delay, true
}

// listControlPlaneIPs returns the InternalIP of every node
// carrying the control-plane label. Used as input to
// computeRank.
func listControlPlaneIPs(ctx context.Context) ([]string, error) {
	cmd := kubectlx.CmdContext(ctx,
		"get", "nodes",
		"-l", "node-role.kubernetes.io/control-plane",
		"-o", `jsonpath={range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}`,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl get nodes: %w (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
	var ips []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ips = append(ips, line)
	}
	return ips, nil
}

// computeRank returns the 0-based position of self in the IP
// list once sorted by numeric IP value. Returns -1 if self is
// not present in the list. Sorting numerically (not
// lexicographically) so 10.0.0.10 sorts after 10.0.0.9 rather
// than before.
func computeRank(self string, all []string) int {
	sorted := make([]string, 0, len(all))
	sorted = append(sorted, all...)
	sort.Slice(sorted, func(i, j int) bool {
		return ipLess(sorted[i], sorted[j])
	})
	for i, ip := range sorted {
		if ip == self {
			return i
		}
	}
	return -1
}

// ipLess compares two IP-address strings numerically. Falls back
// to a string compare if either side fails to parse, so a
// non-IPv4 hostname doesn't crash the sort — the rank is then
// stable but might not match the shell's sort -t. -k order.
func ipLess(a, b string) bool {
	ai := net.ParseIP(a)
	bi := net.ParseIP(b)
	if ai == nil || bi == nil {
		return a < b
	}
	a4, b4 := ai.To4(), bi.To4()
	if a4 != nil && b4 != nil {
		for i := 0; i < 4; i++ {
			if a4[i] != b4[i] {
				return a4[i] < b4[i]
			}
		}
		return false
	}
	// IPv6 or mixed: byte-wise compare on the 16-byte form.
	a16, b16 := ai.To16(), bi.To16()
	for i := 0; i < 16; i++ {
		if a16[i] != b16[i] {
			return a16[i] < b16[i]
		}
	}
	return false
}
