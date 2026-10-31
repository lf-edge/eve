// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package witness supervises the etcd-only member that gives a
// two-node HA cluster its third quorum vote.
package witness

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/etcd"
)

// NodeName is the k3s node name of the witness. Fixed rather than
// derived from the device, so the member is recognisable in a member
// list and survives the witness moving between devices. k3s appends a
// random suffix, so the etcd member appears as "eve-witness-<8 hex>".
const NodeName = "eve-witness"

// pollInterval between membership checks while waiting to join.
var pollInterval = 5 * time.Second

// ErrNotJoined is returned when the witness is still not a voting
// member by the deadline.
var ErrNotJoined = errors.New("witness has not joined the etcd cluster")

// WaitJoined blocks until this witness is a started, voting member of
// the cluster's etcd, or timeout elapses.
//
// This is the witness's equivalent of the kube role's node-Ready wait,
// and it is the only thing that proves the witness is doing its job.
// k3s staying alive proves nothing: a witness with a wrong token, an
// unreachable seed, a stale cluster ID or a colliding peer URL keeps
// running and never joins, so without this the FSM would reach RUNNING
// on a member that contributes no vote.
//
// Being merely present is not enough either. etcd adds a new member as
// a learner, which replicates the log but does not vote until etcd
// promotes it, so quorum does not improve until then.
func WaitJoined(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var lastErr error
	for {
		joined, err := IsJoined(ctx)
		if err != nil {
			// Expected while etcd is still coming up: the client
			// port is not listening and the certs may not be
			// written yet.
			lastErr = err
			log.Printf("witness: membership check: %v", err)
		} else if joined {
			log.Printf("witness: joined the etcd cluster as a voting member")
			return nil
		}

		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("%w after %s: %v", ErrNotJoined, timeout, lastErr)
			}
			return fmt.Errorf("%w after %s", ErrNotJoined, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// IsJoined reports whether this witness is a started, voting member.
func IsJoined(ctx context.Context) (bool, error) {
	members, err := etcd.Members(ctx)
	if err != nil {
		return false, err
	}
	for _, m := range etcd.FindByNamePrefix(members, NodeName) {
		if m.Voting() {
			return true, nil
		}
	}
	return false, nil
}
