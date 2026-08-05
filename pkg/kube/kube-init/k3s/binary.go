// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

// Binary paths. Declared as `var` for unit-test override; production
// callers treat them as constants.

var (
	// k3sBinDir is the directory where the k3s binary lives on disk
	// after first-boot unpack.
	k3sBinDir = "/var/lib/k3s/bin"

	// K3sBinaryPath is the absolute path to the unpacked k3s binary.
	K3sBinaryPath = k3sBinDir + "/k3s"

	// K3sSymlink is the stable $PATH location that symlinks onto
	// K3sBinaryPath. Invocations go through this path because it is
	// stable across in-place upgrades while K3sBinaryPath may briefly
	// point at a stale copy during an update.
	K3sSymlink = "/usr/bin/k3s"
)
