// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import "strings"

// ToK8sName converts an EVE device name into a Kubernetes-compatible
// node name: lowercased, with underscores replaced by dashes.
//
// Kubernetes node names must match the RFC 1123 lower-case DNS label
// shape. EVE device names are operator-chosen and historically allow
// uppercase and underscores; this function normalises them at the
// kube-init boundary so the underlying device name stays as the
// operator chose it.
func ToK8sName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}
