// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package update drives the cross-reboot upgrade flow for both the
// node-local k3s binary and the cluster-scoped components managed by
// kube-init (multus, kubevirt, cdi, longhorn).
//
// Responsibilities:
//
//   - Track the last successfully applied KubeVersion via a marker
//     file under /var/lib so resumption after reboot knows whether
//     work is outstanding.
//   - Compare the running k3s version against the
//     controller-specified desired version and perform an in-place
//     binary swap (verified by sha256) when a change is needed.
//   - Iterate the cluster components, ask the update-component
//     helper whether each is at its expected manifest version, and
//     drive an upgrade with a readiness poll between each.
//   - Publish KubeClusterUpdateStatus to pillar so the controller
//     observes per-component progress.
//
// All k3s and kubectl process invocations go through the k3s and
// kubectlx packages; this package does not own those primitives.
package update
