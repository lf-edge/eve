// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

// EveSSHCommonArgs defines common SSH client options used when connecting
// to EVE devices during tests. These options enforce non-interactive
// operation, use only the specified identity key, apply a short connection
// timeout, and disable host key verification to simplify ephemeral
// test environments.
var EveSSHCommonArgs = []string{
	"-o", "IdentitiesOnly=yes",
	"-o", "ConnectTimeout=5",
	"-o", "StrictHostKeyChecking=no",
	"-o", "UserKnownHostsFile=/dev/null",
}
