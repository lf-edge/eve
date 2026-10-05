// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package quorum

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// witnessFence is held by the seed for the length of a promote. On
// /run, which both containers share and which clears on reboot: a fence
// lost to a crash means the witness may join early, which costs a
// rejoin, whereas one that outlived its promote would keep the witness
// down indefinitely.
var witnessFence = "/run/kube/witness-fence"

// HoldWitnessFence tells the witness not to join while a promote is in
// flight.
//
// A witness that joins mid-reset is added to the membership the reset is
// about to discard, so it disappears from the cluster while still
// believing it is a member, and its peer URL is left registered for the
// next join to collide with. Waiting costs one vote for the length of
// the reset, during which the cluster has no quorum anyway.
func HoldWitnessFence(reason string) error {
	if err := os.MkdirAll(filepath.Dir(witnessFence), 0755); err != nil {
		return fmt.Errorf("create fence dir: %w", err)
	}
	if err := state.AtomicWriteFile(witnessFence, []byte(reason+"\n"), 0644); err != nil {
		return fmt.Errorf("write %s: %w", witnessFence, err)
	}
	log.Printf("witness fence held: %s", reason)
	return nil
}

// ReleaseWitnessFence lets the witness join again.
func ReleaseWitnessFence() error {
	if err := os.Remove(witnessFence); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", witnessFence, err)
	}
	return nil
}

// WitnessFenceHeld reports whether a promote is in flight, and why.
// Read by the witness role.
func WitnessFenceHeld() (held bool, reason string) {
	raw, err := os.ReadFile(witnessFence)
	if err != nil {
		return false, ""
	}
	return true, string(raw)
}
