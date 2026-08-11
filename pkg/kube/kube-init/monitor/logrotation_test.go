// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"slices"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/role"
)

// The witness shares the log directory with the node's kube role, so
// each role may only rotate and prune what it writes itself.
func TestLogOwnershipPerRole(t *testing.T) {
	restore := role.Override(role.Witness)
	if got := rotatedLogs(); !slices.Equal(got, []string{"witness.log"}) {
		t.Errorf("witness rotates %v, want only witness.log", got)
	}
	if got := raftLogPrefix(); got != "witness-" {
		t.Errorf("witness raft prefix = %q, want witness-", got)
	}
	restore()

	restore = role.Override(role.Kube)
	defer restore()
	got := rotatedLogs()
	if slices.Contains(got, "witness.log") || !slices.Contains(got, "k3s.log") {
		t.Errorf("node rotates %v, want k3s.log and not witness.log", got)
	}
	if got := raftLogPrefix(); got != "k3s-" {
		t.Errorf("node raft prefix = %q, want k3s-", got)
	}
}
