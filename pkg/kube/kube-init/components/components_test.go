// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/deploy"
)

// TestReplaceField covers the indent-preserving line rewriter used
// to substitute base64 cert/key data into the admin kubeconfig.
// The non-trivial properties:
//   - Leading whitespace of the matched line is preserved.
//   - Lines that don't start with the prefix are left alone.
//   - Lines whose prefix appears mid-line (not at start of the
//     trimmed text) are NOT matched.
//   - All matching lines are rewritten (multi-line behaviour).
func TestReplaceField(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		prefix  string
		newVal  string
		want    string
	}{
		{
			name:   "preserves indent on matched line",
			in:     "    client-certificate-data: OLD\n",
			prefix: "client-certificate-data:",
			newVal: "NEW",
			want:   "    client-certificate-data: NEW\n",
		},
		{
			name:   "leaves non-matching lines unchanged",
			in:     "apiVersion: v1\n  client-key-data: OLD\nkind: Config\n",
			prefix: "client-key-data:",
			newVal: "NEW",
			want:   "apiVersion: v1\n  client-key-data: NEW\nkind: Config\n",
		},
		{
			name:   "tab-indented lines preserve their tab",
			in:     "\tclient-certificate-data: OLD",
			prefix: "client-certificate-data:",
			newVal: "NEW",
			want:   "\tclient-certificate-data: NEW",
		},
		{
			name:   "prefix mid-line does NOT match",
			in:     "  # client-certificate-data: should not replace\n",
			prefix: "client-certificate-data:",
			newVal: "NEW",
			want:   "  # client-certificate-data: should not replace\n",
		},
		{
			name: "multiple matching lines all replaced",
			in: "  client-certificate-data: A\n" +
				"  some-other: x\n" +
				"  client-certificate-data: B\n",
			prefix: "client-certificate-data:",
			newVal: "NEW",
			want: "  client-certificate-data: NEW\n" +
				"  some-other: x\n" +
				"  client-certificate-data: NEW\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := replaceField(c.in, c.prefix, c.newVal); got != c.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, c.want)
			}
		})
	}
}

// TestBuildFeatureGatesPatch covers the JSON-string construction
// against quoting/comma edge cases. We don't validate the JSON
// against a parser — the assertion is on the literal output shape
// that kubectl --type=merge -p= consumes.
func TestBuildFeatureGatesPatch(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{
			name: "single gate produces no trailing comma",
			in:   []string{"GPU"},
			want: `{"spec":{"configuration":{"developerConfiguration":{"featureGates":["GPU"]}}}}`,
		},
		{
			name: "multiple gates comma-joined",
			in:   []string{"HostDisk", "Snapshot", "GPU"},
			want: `{"spec":{"configuration":{"developerConfiguration":{"featureGates":["HostDisk","Snapshot","GPU"]}}}}`,
		},
		{
			name: "empty list produces empty array (NOT a null)",
			in:   []string{},
			want: `{"spec":{"configuration":{"developerConfiguration":{"featureGates":[]}}}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildFeatureGatesPatch(c.in); got != c.want {
				t.Errorf("\ngot:  %s\nwant: %s", got, c.want)
			}
		})
	}
}

// TestParseAllNodesReady covers the node-status parser. The
// non-trivial behaviour is:
//   - "Ready,SchedulingDisabled" must count as Ready (cordoned
//     tie-breaker node is still Ready).
//   - "NotReady" must NOT match.
//   - Any single non-Ready row makes the whole result false.
//   - Zero rows is an error, not "all ready".
func TestParseAllNodesReady(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    bool
		wantErr bool
	}{
		{
			name: "all Ready",
			in:   "node-a Ready master 5m v1\nnode-b Ready worker 5m v1",
			want: true,
		},
		{
			name: "one node cordoned (Ready,SchedulingDisabled) still all-ready",
			in:   "node-a Ready master 5m v1\nnode-b Ready,SchedulingDisabled tie-breaker 5m v1",
			want: true,
		},
		{
			name: "one NotReady → false",
			in:   "node-a Ready master 5m v1\nnode-b NotReady worker 5m v1",
			want: false,
		},
		{
			name:    "zero rows → error",
			in:      "",
			wantErr: true,
		},
		{
			name: "row with too few fields → false (no panic)",
			in:   "node-a",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseAllNodesReady(c.in)
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v wantErr=%v", err, c.wantErr)
			}
			if got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestParseLonghornDSReady covers the DaemonSet-readiness parser.
// The non-trivial behaviour:
//   - Fewer than 3 lines is "not ready" (Longhorn has 3 DaemonSets
//     and we won't claim ready until all are accounted for).
//   - "0,0" is treated as not-ready even though equal (a not-yet-
//     scheduled DaemonSet shouldn't satisfy readiness).
//   - Mismatched numbers ("1,2") is not-ready.
//   - Blank lines are skipped.
//   - A malformed row (no comma) returns false (defensive).
func TestParseLonghornDSReady(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "three rows all matching numbers",
			in:   "1,1\n1,1\n1,1",
			want: true,
		},
		{
			name: "blank lines are skipped",
			in:   "1,1\n\n1,1\n\n1,1\n",
			want: true,
		},
		{
			name: "fewer than 3 rows → false",
			in:   "1,1\n1,1",
			want: false,
		},
		{
			name: "0,0 row → false even though equal",
			in:   "1,1\n0,0\n1,1",
			want: false,
		},
		{
			name: "numberReady < desired → false",
			in:   "1,1\n1,2\n1,1",
			want: false,
		},
		{
			name: "row without comma → false",
			in:   "1,1\nmalformed\n1,1",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseLonghornDSReady(c.in); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestParseFirstIPv4 covers the `ip -o -4 addr show` parser. Non-
// trivial behaviour:
//   - Strips the /<mask> suffix.
//   - Picks the FIRST inet entry only.
//   - Returns "" on output that has no inet entry.
//   - Doesn't confuse "inet6" with "inet" (we scan fields[i] == "inet").
func TestParseFirstIPv4(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "standard ip -o -4 addr line",
			in:   "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0",
			want: "10.0.0.5",
		},
		{
			name: "first of multiple inet entries wins",
			in: "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255\n" +
				"3: eth1    inet 192.168.1.1/24 brd 192.168.1.255",
			want: "10.0.0.5",
		},
		{
			name: "no inet entry returns empty",
			in:   "2: eth0    state UP qlen 1000",
			want: "",
		},
		{
			name: "inet6 alone does NOT match",
			in:   "2: eth0    inet6 fe80::1/64 scope link",
			want: "",
		},
		{
			name: "empty input returns empty",
			in:   "",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseFirstIPv4(c.in); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestBuildDeployGraph covers the deploy.Graph wiring. The two
// non-trivial properties:
//
//  1. `longhorn` must declare Deps:["manifests"] — Longhorn's PVC
//     controller needs storage-classes.yaml in the auto-deploy dir
//     before its config applies. A regression here is silent in
//     unit-land and only manifests at runtime.
//
//  2. kubevirt/cdi must be appended ONLY when installKubevirt is
//     true, AND each must carry BestEffortWaitReadyTimeout matching
//     the CR-converge budget (without it the deploy package's
//     30-second default cap fires prematurely).
func TestBuildDeployGraph(t *testing.T) {
	addr := NodeAddress{IP: "10.0.0.5", Prefix: "/32"}

	t.Run("longhorn depends on manifests", func(t *testing.T) {
		g := buildDeployGraph("dev", addr, false /*installKubevirt*/)
		longhorn := findNode(t, g.Nodes, "longhorn")
		if len(longhorn.Deps) != 1 || longhorn.Deps[0] != "manifests" {
			t.Errorf("longhorn.Deps = %v, want [manifests]", longhorn.Deps)
		}
		// No other node should depend on anything (single real edge
		// in the whole graph).
		for _, n := range g.Nodes {
			if n.Name == "longhorn" {
				continue
			}
			if len(n.Deps) != 0 {
				t.Errorf("node %q has unexpected Deps %v", n.Name, n.Deps)
			}
		}
	})

	t.Run("kubevirt/cdi omitted when flag false", func(t *testing.T) {
		g := buildDeployGraph("dev", addr, false)
		for _, n := range g.Nodes {
			if n.Name == "kubevirt" || n.Name == "cdi" {
				t.Errorf("did not expect node %q when installKubevirt=false", n.Name)
			}
		}
	})

	t.Run("kubevirt/cdi present with BestEffort + timeout when flag true", func(t *testing.T) {
		g := buildDeployGraph("dev", addr, true)
		kv := findNode(t, g.Nodes, "kubevirt")
		cdi := findNode(t, g.Nodes, "cdi")
		for _, n := range []*deploy.Node{kv, cdi} {
			if !n.BestEffort {
				t.Errorf("node %q: BestEffort = false, want true", n.Name)
			}
			if n.BestEffortWaitReadyTimeout <= 0 {
				t.Errorf("node %q: BestEffortWaitReadyTimeout = %v, "+
					"want > 0 (otherwise deploy.go falls back to a 30s default)",
					n.Name, n.BestEffortWaitReadyTimeout)
			}
		}
	})
}

func findNode(t *testing.T, nodes []deploy.Node, name string) *deploy.Node {
	t.Helper()
	for i := range nodes {
		if nodes[i].Name == name {
			return &nodes[i]
		}
	}
	t.Fatalf("node %q not in graph", name)
	return nil
}

// TestKubeVirtLabelsToRemove covers the kubectl-label argument
// builder used during KubeVirt uninstall. The non-trivial bit is
// the "key-" suffix (which is how `kubectl label` expresses
// "remove this label"). Map iteration is unordered so we verify
// the result via set semantics.
func TestKubeVirtLabelsToRemove(t *testing.T) {
	in := map[string]string{
		"kubernetes.io/hostname":         "n1",
		"node.kubevirt.io/cpu-manager":   "true",
		"kubevirt.io/schedulable":        "true",
		"node.alpha.kubernetes.io/ttl":   "0",
	}
	got := kubeVirtLabelsToRemove(in)

	gotSet := make(map[string]bool, len(got))
	for _, k := range got {
		if !strings.HasSuffix(k, "-") {
			t.Errorf("argument %q must end with kubectl's '-' deletion suffix", k)
		}
		gotSet[k] = true
	}
	if len(got) != 2 ||
		!gotSet["node.kubevirt.io/cpu-manager-"] ||
		!gotSet["kubevirt.io/schedulable-"] {
		t.Errorf("got %v, want exactly the two kubevirt.io label keys with - suffix", got)
	}
}
