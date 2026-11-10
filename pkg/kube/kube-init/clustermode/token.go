// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
)

// tokenReconcileTimeout bounds one rotation attempt so a wedged apiserver
// cannot stall the health worker. A later tick tries again.
var tokenReconcileTimeout = 3 * time.Minute

// tokenRetryBackoff spaces out attempts after a failed rotation, so one
// that cannot succeed (e.g. no etcd quorum) does not stall every health run.
var tokenRetryBackoff = 5 * time.Minute

// nextTokenAttempt needs no lock: health worker runs never overlap.
var nextTokenAttempt time.Time

// Indirections for tests.
var (
	isClusterMode        = k3s.IsClusterMode
	clusterConfigPresent = k3s.ClusterConfigPresent
	storedToken          = k3s.StoredToken
	rotateToNewToken     = k3s.RotateToNewToken
	provisionConfig      = k3s.ProvisionClusterConfig
)

// ReconcileClusterToken rotates the running cluster's token to the
// controller-supplied one when the two differ, as they do after the
// controller replaces the cluster (new ClusterID and token) without the
// node leaving cluster mode. Only the bootstrap node rotates.
//
// This is the rotate step of https://docs.k3s.io/cli/token, which also
// requires every server to be restarted with the new token; that is
// ReconcileTokenRestart, armed here by TokenRestartPending.
//
// Without this the drop-in carries the new token from the next Configure
// on, and that k3s start cannot decrypt its own bootstrap data.
//
// k3s must be running, so this is called from the RUNNING health worker.
// The drop-in check skips a single→cluster transition still in flight,
// which rotates the token itself.
func ReconcileClusterToken(ctx context.Context, cs *k3s.ClusterStatus) error {
	if !cs.IsBootstrapNode {
		return nil
	}
	if cluster, err := isClusterMode(); err != nil || !cluster {
		return err
	}
	if present, err := clusterConfigPresent(); err != nil || !present {
		return err
	}
	running, err := storedToken()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read running token: %w", err)
	}
	if k3s.SameToken(running, cs.EncryptedToken) {
		return nil
	}
	if time.Now().Before(nextTokenAttempt) {
		return nil
	}

	log.Printf("cluster token differs from the running one (cluster %s) — rotating",
		cs.ClusterID)
	rctx, cancel := context.WithTimeout(ctx, tokenReconcileTimeout)
	defer cancel()
	if err := rotateToNewToken(rctx, cs.EncryptedToken); err != nil {
		nextTokenAttempt = time.Now().Add(tokenRetryBackoff)
		return fmt.Errorf("rotate cluster token (retry in %v): %w", tokenRetryBackoff, err)
	}
	if err := markRestartPending(); err != nil {
		return fmt.Errorf("arm restart after rotation: %w", err)
	}
	// The drop-in may still hold the old token, e.g. after a start that
	// fell back to it; rewrite it so the next k3s start uses the new one.
	if err := provisionConfig(ctx, false); err != nil {
		return fmt.Errorf("rewrite cluster config after rotation: %w", err)
	}
	return nil
}
