// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/deploy"
	"github.com/vishvananda/netlink"
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
		name   string
		in     string
		prefix string
		newVal string
		want   string
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

// TestBuildDeployGraph covers the deploy.Graph wiring. The two
// non-trivial properties:
//
//  1. `longhorn` must declare PolicyDeps:["manifests"] — Longhorn's
//     PVC controller needs storage-classes.yaml in the auto-deploy
//     dir before its config applies. A regression here is silent in
//     unit-land and only manifests at runtime.
//
//  2. kubevirt/cdi must be appended ONLY when installKubevirt is
//     true, AND each must carry ReadyTimeout matching the CR-
//     converge budget (without it the deploy package's 30-second
//     default cap fires prematurely).
func TestBuildDeployGraph(t *testing.T) {
	addr := NodeAddress{IP: "10.0.0.5", Prefix: "/32"}

	t.Run("longhorn depends on manifests", func(t *testing.T) {
		g := buildDeployGraph("dev", addr, false /*installKubevirt*/)
		longhorn := findComponent(t, g.Components, "longhorn")
		if len(longhorn.PolicyDeps) != 1 || longhorn.PolicyDeps[0] != "manifests" {
			t.Errorf("longhorn.PolicyDeps = %v, want [manifests]", longhorn.PolicyDeps)
		}
		// longhorn is the only PolicyDeps user; every other ordering
		// is a readiness condition expressed via Requires/Emits.
		for _, c := range g.Components {
			if c.Name == "longhorn" {
				continue
			}
			if len(c.PolicyDeps) != 0 {
				t.Errorf("component %q has unexpected PolicyDeps %v", c.Name, c.PolicyDeps)
			}
		}
	})

	t.Run("kubevirt/cdi omitted when flag false", func(t *testing.T) {
		g := buildDeployGraph("dev", addr, false)
		gated := map[string]bool{"kubevirt": true, "cdi": true, "cdi-operator": true}
		for _, c := range g.Components {
			if gated[c.Name] {
				t.Errorf("did not expect component %q when installKubevirt=false", c.Name)
			}
		}
	})

	t.Run("kubevirt/cdi present with BestEffort + timeout when flag true", func(t *testing.T) {
		g := buildDeployGraph("dev", addr, true)
		kv := findComponent(t, g.Components, "kubevirt")
		cdiOp := findComponent(t, g.Components, "cdi-operator")
		cdi := findComponent(t, g.Components, "cdi")
		for _, c := range []*deploy.Component{kv, cdiOp, cdi} {
			if !c.BestEffort {
				t.Errorf("component %q: BestEffort = false, want true", c.Name)
			}
			if c.ReadyTimeout <= 0 {
				t.Errorf("component %q: ReadyTimeout = %v, "+
					"want > 0 (otherwise deploy.go falls back to a 30s default)",
					c.Name, c.ReadyTimeout)
			}
		}
	})
}

func findComponent(t *testing.T, cs []deploy.Component, name string) *deploy.Component {
	t.Helper()
	for i := range cs {
		if cs[i].Name == name {
			return &cs[i]
		}
	}
	t.Fatalf("component %q not in graph", name)
	return nil
}

// TestKubeVirtLabelsToRemove verifies the helper returns exactly
// the label keys containing "kubevirt.io" from a mixed set — used
// by removeKubeVirtNodeLabels to build a merge patch that nulls
// each key. Map iteration is unordered so we verify via set semantics.
func TestKubeVirtLabelsToRemove(t *testing.T) {
	in := map[string]string{
		"kubernetes.io/hostname":       "n1",
		"node.kubevirt.io/cpu-manager": "true",
		"kubevirt.io/schedulable":      "true",
		"node.alpha.kubernetes.io/ttl": "0",
	}
	got := kubeVirtLabelsToRemove(in)

	gotSet := make(map[string]bool, len(got))
	for _, k := range got {
		gotSet[k] = true
	}
	if len(got) != 2 ||
		!gotSet["node.kubevirt.io/cpu-manager"] ||
		!gotSet["kubevirt.io/schedulable"] {
		t.Errorf("got %v, want exactly the two kubevirt.io label keys", got)
	}
}

// TestRealGraphSignalEdges pins the edges the live graph resolves to.
// Every pod-creating component must sit behind multus: multus writes
// 00-multus.conf, the node's primary CNI config, so starting them
// concurrently races pod creation against the CNI delegate changing.
func TestRealGraphSignalEdges(t *testing.T) {
	cases := []struct {
		name            string
		installKubevirt bool
		want            []deploy.Edge
	}{
		{
			name: "without kubevirt",
			want: []deploy.Edge{
				{From: "manifests", To: "longhorn", Rule: "policy"},
				{From: "multus", To: "longhorn", Rule: "signal", Signal: deploy.MultusCNIReady},
				{From: "namespace", To: "multus", Rule: "signal", Signal: deploy.EveKubeAppNamespaceExists},
			},
		},
		{
			// CDI is two components: the operator serves its own CR's
			// admission webhook, so the CR waits on CDIOperatorReady
			// and inherits MultusCNIReady transitively.
			name:            "with kubevirt",
			installKubevirt: true,
			want: []deploy.Edge{
				{From: "cdi-operator", To: "cdi", Rule: "signal", Signal: deploy.CDIOperatorReady},
				{From: "manifests", To: "longhorn", Rule: "policy"},
				{From: "multus", To: "cdi-operator", Rule: "signal", Signal: deploy.MultusCNIReady},
				{From: "multus", To: "kubevirt", Rule: "signal", Signal: deploy.MultusCNIReady},
				{From: "multus", To: "longhorn", Rule: "signal", Signal: deploy.MultusCNIReady},
				{From: "namespace", To: "multus", Rule: "signal", Signal: deploy.EveKubeAppNamespaceExists},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Also asserts signal validation passes: an unproduced or
			// doubly-produced signal fails here rather than at boot.
			got, err := GraphEdges(c.installKubevirt)
			if err != nil {
				t.Fatalf("GraphEdges: %v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %d edges %+v, want %d %+v",
					len(got), got, len(c.want), c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Errorf("edge[%d] = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestPickDefaultRoute covers the two ways default-route selection went
// wrong against a real device: the kernel spells a default destination
// as either nil or 0.0.0.0/0, and a multi-uplink node has one default
// route per uplink so the lowest metric must win rather than whichever
// netlink happened to return first.
func TestPickDefaultRoute(t *testing.T) {
	allZero := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	subnet := &net.IPNet{IP: net.IPv4(192, 168, 1, 0), Mask: net.CIDRMask(24, 32)}

	cases := []struct {
		name   string
		routes []netlink.Route
		want   int
	}{
		{
			name:   "nil Dst is a default route",
			routes: []netlink.Route{{Dst: nil, LinkIndex: 2, Priority: 5000}},
			want:   0,
		},
		{
			name:   "0.0.0.0/0 Dst is a default route",
			routes: []netlink.Route{{Dst: allZero, LinkIndex: 2, Priority: 5000}},
			want:   0,
		},
		{
			name:   "non-default destination is ignored",
			routes: []netlink.Route{{Dst: subnet, LinkIndex: 2, Priority: 5000}},
			want:   -1,
		},
		{
			name: "lowest metric wins regardless of order",
			routes: []netlink.Route{
				{Dst: nil, LinkIndex: 3, Priority: 5001},
				{Dst: nil, LinkIndex: 2, Priority: 5000},
			},
			want: 1,
		},
		{
			name: "default is picked past leading non-defaults",
			routes: []netlink.Route{
				{Dst: subnet, LinkIndex: 9, Priority: 0},
				{Dst: allZero, LinkIndex: 2, Priority: 5000},
			},
			want: 1,
		},
		{
			name:   "no routes at all",
			routes: nil,
			want:   -1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pickDefaultRoute(c.routes); got != c.want {
				t.Errorf("pickDefaultRoute = %d, want %d", got, c.want)
			}
		})
	}
}

// TestBuildRestartPatch pins where the annotation lands. Stamping the
// workload's own metadata instead of spec.template.metadata is an easy
// slip that produces a patch the API server accepts happily and which
// restarts nothing — the failure would be silent and would only show up
// as pods still running the old CNI config.
func TestBuildRestartPatch(t *testing.T) {
	ts := time.Date(2026, 8, 2, 19, 30, 0, 0, time.UTC)
	got := buildRestartPatch(ts)

	var doc struct {
		Spec struct {
			Template struct {
				Metadata struct {
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("patch is not valid JSON: %v (%s)", err, got)
	}

	stamp, ok := doc.Spec.Template.Metadata.Annotations[restartedAtAnnotation]
	if !ok {
		t.Fatalf("%s missing from spec.template.metadata.annotations: %s",
			restartedAtAnnotation, got)
	}
	if want := ts.Format(time.RFC3339); stamp != want {
		t.Errorf("restartedAt = %q, want %q", stamp, want)
	}

	// A merge patch with only the template stanza leaves every other
	// field of the DaemonSet alone, which is the point — we are not
	// re-specifying the workload, just nudging its pods.
	var top map[string]any
	if err := json.Unmarshal(got, &top); err != nil {
		t.Fatalf("unmarshal top level: %v", err)
	}
	if len(top) != 1 {
		t.Errorf("patch touches %d top-level keys, want only \"spec\": %s", len(top), got)
	}
}
