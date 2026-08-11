// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/etcd"
	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// Paths owned by this file. `var` for test override.

// MasterleaseCleanupFlag is the marker file set during a
// single→cluster transition (on the bootstrap node) and cleared
// by CleanupStaleMasterleases on success. Lives under /var/lib
// (bind-mount of /persist/vault/kube) so it survives reboot until
// cleanup actually runs.
var MasterleaseCleanupFlag state.Marker = "/var/lib/masterlease-cleanup-needed"

var (
	etcdCACert = "/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt"
	etcdCert   = "/var/lib/rancher/k3s/server/tls/etcd/client.crt"
	etcdKey    = "/var/lib/rancher/k3s/server/tls/etcd/client.key"

	// etcdctl path is resolved at call time; production has it
	// at /usr/bin/etcdctl (see Dockerfile).
	etcdctlPath = "/usr/bin/etcdctl"

	// etcdEndpoint is the local etcd server. We talk only to the
	// local endpoint because the cleanup runs on the bootstrap
	// node and we don't need the cluster-wide view to delete a
	// stale lease — etcd replicates the delete.
	etcdEndpoint = "https://127.0.0.1:2379"
)

const masterLeasesPrefix = "/registry/masterleases/"

// CleanupStaleMasterleases removes etcd masterlease entries that
// belong to no current etcd member. k3s's HA endpoint reconciler
// reads every key under /registry/masterleases/ and stamps each IP
// into the kubernetes service EndpointSlice; an entry nothing
// answers on causes ~30 s TCP timeouts on the share of API
// connections balanced onto it (kubectl, Multus SetNetworkStatus,
// CDI importer).
//
// Membership rather than the cluster subnet, because the stranded
// address differs: a single→cluster transition leaves the node's old
// LAN address behind, a quorum recovery a former member's cluster
// address. Only membership catches both, and it cannot delete a lease
// that is coming back, a rejoining node being a member again before
// its apiserver re-registers.
//
// Not left to the lease TTL, which would mean trusting a timeout to
// survive the datastore rewrite a reset performs.
//
// Gated by MasterleaseCleanupFlag, which the single→cluster
// transition sets after token rotation on the bootstrap node and a
// quorum-recovery promote sets after the reset. No-op on every
// other boot.
//
// Tolerates etcd-not-yet-ready — unreadable membership, empty
// lease list, etcdctl exec error, missing certs — by leaving the
// flag in place and returning nil, so the next health-worker tick
// retries. The flag is cleared only after a pass that could see
// both the membership and the leases, which is the only kind that
// proves there is nothing left to remove.
//
// Addresses upstream commit d5664c079 ("kube: clean up stale etcd
// masterleases after single-to-cluster transition").
func CleanupStaleMasterleases(ctx context.Context, status *k3s.ClusterStatus) error {
	flagged, err := state.IsMarked(MasterleaseCleanupFlag)
	if err != nil {
		return fmt.Errorf("check %s: %w", MasterleaseCleanupFlag, err)
	}
	if !flagged {
		return nil
	}
	if status == nil || !status.IsBootstrapNode || status.ClusterIP == "" {
		// Cleanup is bootstrap-only — the bootstrap is the etcd
		// member that holds the single-node lease at conversion
		// time. Non-bootstrap nodes never had that lease.
		return nil
	}
	if _, err := os.Stat(etcdCACert); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("masterleases: etcd CA cert %s not yet present, will retry",
				etcdCACert)
			return nil
		}
		return fmt.Errorf("stat etcd CA: %w", err)
	}

	memberIPs, err := memberAddresses(ctx)
	if err != nil {
		log.Printf("masterleases: membership unreadable, will retry: %v", err)
		return nil
	}
	if len(memberIPs) == 0 {
		log.Printf("masterleases: no members reported, will retry")
		return nil
	}

	leases, err := listMasterleases(ctx)
	if err != nil {
		log.Printf("masterleases: list failed, will retry: %v", err)
		return nil
	}
	if len(leases) == 0 {
		log.Printf("masterleases: empty list, will retry")
		return nil
	}
	log.Printf("masterleases: %d entries seen: %s",
		len(leases), strings.Join(leases, " "))

	removed := 0
	for _, key := range staleLeases(leases, memberIPs) {
		log.Printf("masterleases: removing stale lease %s (no etcd member holds it)",
			strings.TrimPrefix(key, masterLeasesPrefix))
		if err := deleteMasterlease(ctx, key); err != nil {
			log.Printf("masterleases: delete %s: %v", key, err)
			continue
		}
		removed++
	}

	if err := state.Unmark(MasterleaseCleanupFlag); err != nil {
		log.Printf("masterleases: clear flag: %v", err)
	}
	log.Printf("masterleases: cleanup done (removed %d stale entries)", removed)
	return nil
}

// staleLeases returns the lease keys no current member holds.
//
// A key that does not parse as an address is left alone: this function
// only ever deletes, and deleting something it cannot identify is worse
// than leaving it for a human to look at.
func staleLeases(leases []string, members map[string]bool) []string {
	var stale []string
	for _, key := range leases {
		ip := net.ParseIP(strings.TrimSpace(strings.TrimPrefix(key, masterLeasesPrefix)))
		if ip == nil {
			log.Printf("masterleases: skipping unparsable key %q", key)
			continue
		}
		if members[ip.String()] {
			continue
		}
		stale = append(stale, key)
	}
	return stale
}

// memberAddresses is the set of IPs the current etcd membership
// reports, taken from client URLs because that is the address an
// apiserver on that node registers its lease under. A member that is
// merely down still counts: its lease is not stale, it is idle, and
// deleting it would only flap when the node returns.
func memberAddresses(ctx context.Context) (map[string]bool, error) {
	members, err := etcd.Members(ctx)
	if err != nil {
		return nil, err
	}
	ips := make(map[string]bool, len(members))
	for _, m := range members {
		for _, raw := range m.ClientURLs {
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			host := u.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				ips[ip.String()] = true
			}
		}
	}
	return ips, nil
}

// listMasterleases returns the full set of keys under
// /registry/masterleases/. Empty list (no error) means etcd is
// reachable but no leases are written yet.
func listMasterleases(ctx context.Context) ([]string, error) {
	args := []string{
		"--endpoints", etcdEndpoint,
		"--cacert", etcdCACert,
		"--cert", etcdCert,
		"--key", etcdKey,
		"get", masterLeasesPrefix, "--prefix", "--keys-only",
	}
	cmd := exec.CommandContext(ctx, etcdctlPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("etcdctl get: %w (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
	var keys []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		keys = append(keys, line)
	}
	return keys, nil
}

// deleteMasterlease removes a single masterlease key from etcd.
func deleteMasterlease(ctx context.Context, key string) error {
	args := []string{
		"--endpoints", etcdEndpoint,
		"--cacert", etcdCACert,
		"--cert", etcdCert,
		"--key", etcdKey,
		"del", key,
	}
	cmd := exec.CommandContext(ctx, etcdctlPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("etcdctl del: %w (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}
