// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package witness

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// ErrPrunePending reports that stale witness members still have to be
// cleared before this witness can join. Transient like ErrFenced: the
// FSM retries rather than parking.
var ErrPrunePending = errors.New("waiting for stale witness members to be pruned")

// pruneRequest is raised by a witness about to cold-join and cleared by
// the kube role on the same device once it has pruned. On /run, which
// both containers share and which clears on reboot, like the quorum
// fence: a request lost to a crash is re-raised by the next pass,
// whereas one that outlived its purpose would only cost a prune of a
// membership that has nothing to prune.
var pruneRequest = "/run/kube/witness-prune-request"

// ColdJoin reports whether the witness holds no etcd state, and so is
// not in the cluster's membership.
//
// This is what makes pruning by name safe. A cold-joining witness cannot
// be any of the members it is about to remove, and the design allows
// only one witness, so every member named after one is stale. A warm
// restart, where the data directory survived, must never prune: the
// witness's own live member is the one that would match.
func ColdJoin() bool {
	_, err := os.Stat(filepath.Join(dataDir, "server", "db"))
	return errors.Is(err, os.ErrNotExist)
}

// RequestPrune asks the kube role on this device to clear stale witness
// members. Idempotent.
func RequestPrune(reason string) error {
	if err := os.MkdirAll(filepath.Dir(pruneRequest), 0755); err != nil {
		return fmt.Errorf("create prune request dir: %w", err)
	}
	if err := state.AtomicWriteFile(pruneRequest, []byte(reason+"\n"), 0644); err != nil {
		return fmt.Errorf("write %s: %w", pruneRequest, err)
	}
	log.Printf("witness: asked the node to prune stale witness members before joining")
	return nil
}

// PruneRequested reports whether a witness is waiting on a prune, and
// the address it means to claim. Read by the kube role.
func PruneRequested() (requested bool, reason string) {
	raw, err := os.ReadFile(pruneRequest)
	if err != nil {
		return false, ""
	}
	return true, string(raw)
}

// ClearPruneRequest reports the prune done. Called by the kube role.
func ClearPruneRequest() error {
	if err := os.Remove(pruneRequest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", pruneRequest, err)
	}
	return nil
}
