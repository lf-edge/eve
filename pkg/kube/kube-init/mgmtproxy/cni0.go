// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package mgmtproxy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
)

// CNI0Result reports the outcome of SetupCNI0ProxyIP without
// requiring callers to parse error strings. The three "non-error"
// outcomes are distinct because the steady-state caller logs each
// differently: Skipped is a normal cold-boot state (flannel hasn't
// created cni0 yet), AlreadyAssigned is the steady-state no-op,
// Assigned is worth a single log line.
type CNI0Result int

// Values for CNI0Result. See type doc.
const (
	// CNI0Skipped is returned when the cni0 interface does not
	// exist yet. Cold boot before k3s has started and the first
	// pod is scheduled (which is when flannel creates cni0).
	CNI0Skipped CNI0Result = iota
	// CNI0AlreadyAssigned is returned when the link-local anchor
	// is already present on cni0. The steady-state no-op.
	CNI0AlreadyAssigned
	// CNI0Assigned is returned when the anchor was newly added.
	// Recovery path after a flannel restart that recreated cni0
	// without the anchor.
	CNI0Assigned
)

// SetupCNI0ProxyIP assigns CNI0IP/32 to the cni0 interface so CDI
// importer pods on this node can reach the local mgmtproxy via
// HTTPS_PROXY=CNI0URL. Link-local addresses are not routed by
// flannel across nodes, so each pod always hits its own node's
// cni0 and its own node's mgmtproxy.
//
// Idempotent and safe to call on every steady-state tick: when the
// anchor is already present this is a (fast) no-op; when flannel
// has restarted and recreated cni0 without it, the next tick
// re-applies it. Only relevant on kubevirt-installed nodes — the
// caller is responsible for that gating.
//
// Mirrors setup_cni0_proxy_ip() from upstream commit 7ec6f2a64.
func SetupCNI0ProxyIP() (CNI0Result, error) {
	if !cni0Exists() {
		return CNI0Skipped, nil
	}
	if cni0HasAnchor() {
		return CNI0AlreadyAssigned, nil
	}
	anchor := CNI0IP + "/32"
	cmd := exec.Command("ip", "addr", "add", anchor, "dev", "cni0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return CNI0Skipped, fmt.Errorf(
			"ip addr add %s dev cni0: %w (output: %s)",
			anchor, err, strings.TrimSpace(string(out)))
	}
	return CNI0Assigned, nil
}

// cni0Exists reports whether the cni0 interface is currently
// present. Returns false on any error from `ip link show cni0`
// since the only practical failure is "no such device", which is
// indistinguishable from a transient ip-command error for our
// purposes — both cases yield CNI0Skipped, which the caller logs
// at info level on the first occurrence and silently ignores
// afterwards.
func cni0Exists() bool {
	return exec.Command("ip", "link", "show", "cni0").Run() == nil
}

// cni0HasAnchor reports whether CNI0IP is currently configured on
// the cni0 interface. False on any ip-command error — the next
// tick retries and either finds the anchor present or adds it.
func cni0HasAnchor() bool {
	out, err := exec.Command("ip", "addr", "show", "dev", "cni0").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), CNI0IP)
}

// cdiImportProxyNoProxy is the noProxy list passed to CDI's
// importProxy spec. Differs from the host-side NO_PROXY value
// (mgmtproxy.NoProxy) because importer pods run INSIDE the cluster
// — they need to bypass the proxy for cluster-internal targets,
// not the host's loopback and the node's cluster IP. Settled on
// during the testing of upstream commit 7ec6f2a64 against the
// Rancher/Helm DataVolumeTemplate flow.
const cdiImportProxyNoProxy = "10.42.0.0/16,10.43.0.0/16,127.0.0.0/8," +
	"localhost,.svc,.cluster.local,169.254.0.0/16"

// PatchCDIProxyConfig patches the CDI CR so importer pods receive
// HTTPSProxy=CNI0URL. Importer pods are the ones created when a
// Rancher/Helm DataVolumeTemplate uses source.http.url or
// source.registry.url; uploader pods (used by virtctl image-upload
// or the EVE-managed source.upload path) are not affected.
//
// Idempotent: kubectl patch with the same payload is a no-op
// (merge type, server-side check). Safe to call on every
// steady-state tick — that's how we recover if an upgrade resets
// the CDI CR.
//
// Mirrors patch_cdi_proxy_config() from upstream commit 7ec6f2a64.
func PatchCDIProxyConfig(ctx context.Context) error {
	patch := buildCDIProxyPatch(CNI0URL, cdiImportProxyNoProxy)
	cmd := kubectlx.CmdContext(ctx, "patch", "cdi", "cdi",
		"--type", "merge", "-p", patch)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubectl patch cdi: %w (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}

// buildCDIProxyPatch returns the merge-patch JSON for the CDI CR's
// importProxy spec. Extracted as a pure function so we can pin the
// JSON layout in a unit test without exercising kubectl.
func buildCDIProxyPatch(httpsProxy, noProxy string) string {
	return fmt.Sprintf(
		`{"spec":{"config":{"importProxy":{"HTTPSProxy":%q,"noProxy":%q}}}}`,
		httpsProxy, noProxy)
}
