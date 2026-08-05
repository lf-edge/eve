// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package k3s renders the on-disk k3s lifecycle artifacts that
// kube-init manages: config drop-ins under K3sConfigDir, and cluster
// token rotation primitives. Process supervision and install/unpack
// land in sibling files in subsequent commits.
package k3s
