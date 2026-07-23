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
	"os/exec"
	"strings"

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

// CleanupStaleMasterleases removes etcd masterlease entries whose
// IP is outside the current cluster network. k3s's HA endpoint
// reconciler reads every key under /registry/masterleases/ and
// stamps each IP into the kubernetes service EndpointSlice; a
// stale entry left over from the pre-transition single-node IP
// causes ~30 s TCP timeouts on every third API connection
// (kubectl, Multus SetNetworkStatus, CDI importer).
//
// Gated by MasterleaseCleanupFlag, which the single→cluster
// transition flow sets after token rotation completes on the
// bootstrap. No-op on every other boot.
//
// The function tolerates etcd-not-yet-ready (empty lease list,
// etcdctl exec error, missing certs) by leaving the flag in
// place and returning nil — the next health-worker tick will
// retry. The flag is cleared only after at least one stale entry
// was successfully deleted OR the lease list contains exactly
// the local node.
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
	if status.PrefixLen <= 0 {
		log.Printf("masterleases: cluster prefix length unknown, skipping")
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

	clusterNet, err := buildClusterNet(status.ClusterIP, status.PrefixLen)
	if err != nil {
		return fmt.Errorf("build cluster net: %w", err)
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
	for _, key := range leases {
		ipStr := strings.TrimPrefix(key, masterLeasesPrefix)
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			log.Printf("masterleases: skipping unparsable key %q", key)
			continue
		}
		if clusterNet.Contains(ip) {
			continue
		}
		log.Printf("masterleases: removing stale lease %s (outside cluster %s)",
			ipStr, clusterNet.String())
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

// buildClusterNet returns the cluster subnet derived from the
// node's cluster IP and the prefix length received in
// EdgeNodeClusterStatus.ClusterIPPrefix.Mask.
func buildClusterNet(ip string, prefixLen int) (*net.IPNet, error) {
	cidr := fmt.Sprintf("%s/%d", ip, prefixLen)
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cluster CIDR %q: %w", cidr, err)
	}
	return n, nil
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
