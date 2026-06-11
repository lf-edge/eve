// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package mgmtproxy carries the kube-init side of the cost-aware
// management proxy that pillar runs at MGMTPROXY_URL. The proxy
// terminates HTTPS_PROXY connections from kube-side clients
// (containerd image pulls, kubectl-against-public-URLs, the k3s
// installer bootstrap curl) and routes them through whichever
// uplink the controller has marked as cheapest.
//
// Helpers here are deliberately pure: callers pass cluster IP and
// prefix length explicitly rather than this package reading
// EdgeNodeClusterStatus on its own — that keeps the package free
// of imports on the rest of kube-init and free of cycles.
//
// Mirrors the helpers in pkg/kube/cluster-utils.sh from upstream
// commit 7ec6f2a64 ("mgmtproxy: cost-aware CONNECT kube proxy for
// containerd & kubectl image/manifest").
package mgmtproxy

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Endpoint and well-known paths owned by this package. var so tests
// can redirect; same convention as the rest of kube-init.
//
//   - URL is the local-loopback endpoint where pillar's mgmtproxy
//     listens. Kube-side clients dial this as HTTPS_PROXY.
//   - DisableFlag is the operator off-switch: touch the file and the
//     next containerd (or kube-init) launch bypasses proxy injection.
//     Use this for live triage when the proxy itself is suspect:
//       touch /run/kube/mgmtproxy-disable && killall containerd
//   - CNI0IP / CNI0URL are the link-local anchor that CDI importer
//     pods reach via the cni0 alias address (see Phase 3 task on
//     setup_cni0_proxy_ip; that wiring lives elsewhere but uses the
//     same constant).
//   - SentinelFile is written by WriteContainerdSentinel so an
//     operator can see what env vars were passed at containerd's
//     last start — containerd itself unsets HTTPS_PROXY after
//     reading it for the CRI image-pull client, so /proc/<pid>/environ
//     becomes unreliable.
var (
	URL          = "http://127.0.0.1:5443"
	DisableFlag  = "/run/kube/mgmtproxy-disable"
	CNI0IP       = "169.254.100.1"
	CNI0URL      = "http://169.254.100.1:5443"
	SentinelFile = "/run/mgmtproxy-containerd-env"
)

// Fixed NO_PROXY entries that apply on every node: loopback, k3s
// service + pod CIDRs (defaults — see pkg/kube/config.yaml does not
// override them), link-local, localhost, and cluster DNS suffixes.
// Per-call the cluster node IP/prefix is appended if known.
const baseNoProxy = "127.0.0.0/8,10.42.0.0/16,10.43.0.0/16," +
	"169.254.0.0/16,localhost,.svc,.cluster.local"

// Enabled reports whether the proxy env should be injected. The
// only off-switch is the DisableFlag file. Any error stat-ing the
// flag (other than "not exist") is treated as enabled — failing
// open here matches the shell's bare `-f` test.
func Enabled() bool {
	_, err := os.Stat(DisableFlag)
	return os.IsNotExist(err)
}

// NoProxy returns the NO_PROXY value to pair with HTTPS_PROXY=URL.
// When clusterIP is non-empty, the cluster network is appended so
// inter-node traffic (worker kubectl talking to the control-plane
// IP in kubeconfig) bypasses the proxy. prefixLen > 0 emits the
// /N suffix; prefixLen <= 0 falls back to the bare IP (matches the
// shell's behaviour when get_cluster_prefix_len is unavailable).
func NoProxy(clusterIP string, prefixLen int) string {
	if clusterIP == "" {
		return baseNoProxy
	}
	if prefixLen > 0 {
		return fmt.Sprintf("%s,%s/%d", baseNoProxy, clusterIP, prefixLen)
	}
	return baseNoProxy + "," + clusterIP
}

// Env returns the HTTPS_PROXY+NO_PROXY environment slice ready to
// append to an exec.Cmd's Env when launching a subprocess that
// should route through mgmtproxy.
//
// Returns nil when the off-switch is present — callers can do
//
//	cmd.Env = append(os.Environ(), mgmtproxy.Env(ip, pfx)...)
//
// without branching; appending nil is a no-op.
//
// The env is deliberately scoped per-launch; this package never
// touches process-global env, because k3s itself (kubelet,
// apiserver, controller-manager, scheduler) must NOT see
// HTTPS_PROXY — that would route intra-cluster HTTPS through the
// proxy and break the cluster.
func Env(clusterIP string, prefixLen int) []string {
	if !Enabled() {
		return nil
	}
	return []string{
		"HTTPS_PROXY=" + URL,
		"NO_PROXY=" + NoProxy(clusterIP, prefixLen),
	}
}

// WriteContainerdSentinel records what env was passed to the
// most recent containerd launch. Operators read SentinelFile to
// confirm proxy injection happened (or didn't) without having to
// chase containerd's mutating /proc/<pid>/environ.
//
// Always writes the file: even when disabled, the file documents
// the off-switch state. Errors are best-effort — a missing /run
// directory at very early boot is the only realistic failure and
// not worth blocking the containerd launch over.
func WriteContainerdSentinel(pid int, clusterIP string, prefixLen int) error {
	var body strings.Builder
	fmt.Fprintf(&body, "pid=%d\n", pid)
	fmt.Fprintf(&body, "started=%s\n", time.Now().Format(time.RFC3339))
	if Enabled() {
		fmt.Fprintf(&body, "HTTPS_PROXY=%s\n", URL)
		fmt.Fprintf(&body, "NO_PROXY=%s\n", NoProxy(clusterIP, prefixLen))
	} else {
		fmt.Fprintf(&body, "HTTPS_PROXY=(disabled — flag %s present)\n", DisableFlag)
		fmt.Fprintln(&body, "NO_PROXY=(none)")
	}
	if err := os.WriteFile(SentinelFile, []byte(body.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", SentinelFile, err)
	}
	return nil
}
