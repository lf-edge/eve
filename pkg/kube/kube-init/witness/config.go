// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package witness

import (
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// Drop-in files written to k3s's config directory. k3s merges every
// *.yaml there in lexical order, so the numeric prefixes fix precedence.
const (
	nodeNameConfig = "00-nodename.yaml"
	clusterConfig  = "01-clusterconfig.yaml"
	networkConfig  = "02-network.yaml"
	etcdOnlyConfig = "03-etcd-only.yaml"
	etcdArgsConfig = "04-etcd.yaml"
)

// joinAPIPort is the seed's supervisor/apiserver port.
const joinAPIPort = "6443"

// EtcdArgs are the etcd settings the witness runs with.
//
// These must match pkg/kube's, because k3s treats etcd configuration as
// cluster-critical and every member stores the same data: a witness is a
// full voting member, not a partial replica. A witness given a smaller
// quota-backend-bytes than the nodes would hit its quota first and
// raise a NOSPACE alarm, which turns the whole cluster read-only.
// TestEtcdArgsMatchKube pins them together.
var EtcdArgs = []string{
	"quota-backend-bytes=8589934592",
	"auto-compaction-mode=periodic",
	"auto-compaction-retention=1h",
	"snapshot-count=5000",
	// The witness is the one member that should never win an election.
	// Its storage is the slowest of the three, so a witness leader
	// makes every write wait on it. A longer election timeout biases
	// raft towards the nodes that actually run workloads. It stays
	// within etcd's requirement that the timeout be at least 5x the
	// heartbeat interval, which k3s leaves at the 100ms default.
	"election-timeout=5000",
}

// Configure renders every k3s drop-in the witness needs. Idempotent.
//
// Unlike the kube role there is no image-supplied config.yaml behind
// this: rendering the static parts here too keeps one source of truth,
// and lets a test hold the etcd settings against pkg/kube's.
func Configure(cs *k3s.ClusterStatus) error {
	if err := validate(cs); err != nil {
		return err
	}
	for _, f := range []struct {
		name    string
		content string
	}{
		{nodeNameConfig, nodeNameYAML()},
		{clusterConfig, clusterYAML(cs)},
		{networkConfig, networkYAML(cs)},
		{etcdOnlyConfig, etcdOnlyYAML()},
		{etcdArgsConfig, etcdArgsYAML()},
	} {
		path := filepath.Join(k3s.K3sConfigDir, f.name)
		if err := state.AtomicWriteFile(path, []byte(f.content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	log.Printf("witness config rendered for seed %s (node-ip %s)",
		cs.JoinServerIP, cs.WitnessIP)
	return nil
}

// validate rejects a cluster status the witness cannot run against.
// Each of these would otherwise surface as an obscure k3s failure
// minutes later.
func validate(cs *k3s.ClusterStatus) error {
	switch {
	case cs == nil:
		return fmt.Errorf("no cluster status")
	case cs.WitnessIP == "":
		return fmt.Errorf("no witness IP configured")
	case cs.JoinServerIP == "":
		return fmt.Errorf("no join server IP")
	case cs.EncryptedToken == "":
		return fmt.Errorf("no cluster token")
	}
	return nil
}

func nodeNameYAML() string {
	return fmt.Sprintf("node-name: %q\n", NodeName)
}

func clusterYAML(cs *k3s.ClusterStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "server: \"https://%s:%s\"\n", bracketIPv6(cs.JoinServerIP), joinAPIPort)
	fmt.Fprintf(&b, "token: %q\n", cs.EncryptedToken)
	return b.String()
}

func networkYAML(cs *k3s.ClusterStatus) string {
	// node-ip is what k3s derives etcd's peer and client URLs from.
	// Setting those directly through etcd-arg instead breaks bootstrap
	// reconcile, so this is the only supported lever.
	return fmt.Sprintf("node-ip: %q\n", cs.WitnessIP)
}

// etcdOnlyYAML strips k3s down to etcd.
//
// disable-agent removes the kubelet, which is what keeps the witness out
// of the cluster as a Node and, more importantly, stops its kubelet
// reconciling pod cgroups that belong to the kube container: the two
// share a host-visible cgroup tree.
//
// The apiserver, scheduler and controller-manager go too. An enabled
// witness apiserver joins the kubernetes Service endpoint pool, so
// roughly a third of API traffic is round-robined to a process with no
// route into the pod network, where it fails with "no route to host".
func etcdOnlyYAML() string {
	return strings.Join([]string{
		"disable-agent: true",
		"disable-apiserver: true",
		"disable-scheduler: true",
		"disable-controller-manager: true",
		"disable-cloud-controller: true",
		"disable-network-policy: true",
		"egress-selector-mode: \"disabled\"",
		"disable:",
		"  - servicelb",
		"  - traefik",
		"  - coredns",
		"  - local-storage",
		"  - metrics-server",
		"",
	}, "\n")
}

func etcdArgsYAML() string {
	var b strings.Builder
	b.WriteString("etcd-expose-metrics: true\n")
	b.WriteString("etcd-arg:\n")
	for _, arg := range EtcdArgs {
		fmt.Fprintf(&b, "  - %q\n", arg)
	}
	return b.String()
}

// bracketIPv6 wraps a literal IPv6 address for use in a URL.
func bracketIPv6(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return "[" + ip + "]"
	}
	return ip
}
