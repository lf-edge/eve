// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

// EveSSHCommonArgs defines common SSH client options used when connecting
// to EVE devices during tests. These options enforce non-interactive
// operation, use only the specified identity key, apply a connection
// timeout, and disable host key verification to simplify ephemeral
// test environments.
//
// ConnectTimeout is generous because the local endpoint this ssh client
// connects to is a tunnel whose server side probes each candidate mgmt IP
// (up to 3 attempts x 3s each) before the real connection to EVE is
// established; a short timeout here can expire while that probing is
// still in progress, well before the tunnel would have succeeded.
var EveSSHCommonArgs = []string{
	"-o", "IdentitiesOnly=yes",
	"-o", "ConnectTimeout=30",
	"-o", "StrictHostKeyChecking=no",
	"-o", "UserKnownHostsFile=/dev/null",
}
