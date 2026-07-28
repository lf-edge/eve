// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package mgmtproxy

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

const cni0LinkName = "cni0"

// cdiGVR is the dynamic resource ref for the CDI CR whose
// importProxy config we manage from mgmtproxy.
var cdiGVR = schema.GroupVersionResource{
	Group: "cdi.kubevirt.io", Version: "v1beta1", Resource: "cdis",
}

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
	link, err := netlink.LinkByName(cni0LinkName)
	if err != nil {
		var nfErr netlink.LinkNotFoundError
		if errors.As(err, &nfErr) {
			return CNI0Skipped, nil
		}
		return CNI0Skipped, fmt.Errorf("lookup cni0: %w", err)
	}
	addr, err := netlink.ParseAddr(CNI0IP + "/32")
	if err != nil {
		return CNI0Skipped, fmt.Errorf("parse %s/32: %w", CNI0IP, err)
	}
	if has, err := cni0HasAnchor(link, addr.IP); err != nil {
		return CNI0Skipped, err
	} else if has {
		return CNI0AlreadyAssigned, nil
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return CNI0Skipped, fmt.Errorf("add %s to cni0: %w", addr, err)
	}
	return CNI0Assigned, nil
}

// cni0HasAnchor reports whether want is already assigned to link.
// Errors surface — the caller treats them as "assume unassigned" is
// unsafe here (would produce a duplicate-add error).
func cni0HasAnchor(link netlink.Link, want net.IP) (bool, error) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return false, fmt.Errorf("list cni0 addrs: %w", err)
	}
	for _, a := range addrs {
		if a.IP.Equal(want) {
			return true, nil
		}
	}
	return false, nil
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
// Mirrors patch_cdi_proxy_config() from upstream commits 7ec6f2a64
// and c3225bd45 (the "skip when config already matches" guard).
func PatchCDIProxyConfig(ctx context.Context) error {
	// Skip (and stay silent) when the CDI CR already carries the
	// desired importProxy config. This runs every steady-state tick
	// for upgrade/reset recovery; patching unconditionally would
	// spam k3s-install.log and issue a pointless kubectl patch each
	// iteration. Fall through on any query error — the patch is
	// itself idempotent, so worst case we do one unneeded write.
	if cdiProxyConfigMatches(ctx, CNI0URL, cdiImportProxyNoProxy) {
		return nil
	}
	patch := buildCDIProxyPatch(CNI0URL, cdiImportProxyNoProxy)
	_, err := kubeclient.Default().Dynamic.Resource(cdiGVR).
		Patch(ctx, "cdi", types.MergePatchType, []byte(patch), metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patch cdi: %w", err)
	}
	return nil
}

// cdiProxyConfigMatches reports whether the CDI CR's importProxy
// spec already equals the desired (httpsProxy, noProxy) pair. Any
// kubectl error is treated as "not matching" so the caller falls
// through to the (idempotent) patch attempt.
func cdiProxyConfigMatches(ctx context.Context, httpsProxy, noProxy string) bool {
	cur, err := cdiProxyGet(ctx, "HTTPSProxy")
	if err != nil || cur != httpsProxy {
		return false
	}
	cur, err = cdiProxyGet(ctx, "noProxy")
	if err != nil || cur != noProxy {
		return false
	}
	return true
}

// cdiProxyGet reads a specific field from the CDI CR's
// spec.config.importProxy. Empty string with nil error is possible
// when the field is unset; the caller treats that as a mismatch.
// key is one of "HTTPSProxy" or "noProxy".
func cdiProxyGet(ctx context.Context, key string) (string, error) {
	obj, err := kubeclient.Default().Dynamic.Resource(cdiGVR).
		Get(ctx, "cdi", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	// spec.config.importProxy.<key>
	spec, _ := obj.Object["spec"].(map[string]any)
	config, _ := spec["config"].(map[string]any)
	importProxy, _ := config["importProxy"].(map[string]any)
	v, _ := importProxy[key].(string)
	return v, nil
}

// buildCDIProxyPatch returns the merge-patch JSON for the CDI CR's
// importProxy spec. Extracted as a pure function so we can pin the
// JSON layout in a unit test without exercising kubectl.
func buildCDIProxyPatch(httpsProxy, noProxy string) string {
	return fmt.Sprintf(
		`{"spec":{"config":{"importProxy":{"HTTPSProxy":%q,"noProxy":%q}}}}`,
		httpsProxy, noProxy)
}
