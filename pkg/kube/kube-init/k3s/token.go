// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// k3sTokenFile is where k3s writes the current cluster token after
// `k3s token rotate`. Polling this file is how we know a rotation
// has taken effect.
var k3sTokenFile = "/var/lib/rancher/k3s/server/token"

// Token poll cadences. Declared as var so tests can shrink them;
// production callers treat them as constants.
var (
	tokenPollInterval          = 2 * time.Second
	bootstrapTokenPollInterval = 5 * time.Second
	// tokenRotateRetryTimeout is how long we wait for the token file
	// to reflect the request before re-issuing `k3s token rotate`.
	// 60s catches the case where the rotate command silently failed
	// or the apiserver was momentarily unavailable.
	tokenRotateRetryTimeout = 60 * time.Second
)

// tokenReadMaxConsecutiveErrors bounds infinite spin when the token
// file read fails with anything other than ENOENT (permission denied,
// EIO, EISDIR, ...). ENOENT is treated as transient because k3s
// creates the file lazily.
const tokenReadMaxConsecutiveErrors = 6

// ErrTokenRotateAbandoned indicates a token-rotate poll loop gave
// up after repeated non-transient failures to read the token file.
var ErrTokenRotateAbandoned = errors.New("token rotate abandoned after repeated read failures")

// RotateToNewToken rotates the cluster token to the supplied value
// and blocks until the on-disk token file reflects it. The rotate
// command is re-issued every tokenRotateRetryTimeout while the file
// remains stale; the loop terminates on success, on caller-ctx
// cancellation, or after tokenReadMaxConsecutiveErrors non-ENOENT
// read failures (ErrTokenRotateAbandoned).
func RotateToNewToken(ctx context.Context, newToken string) error {
	if newToken == "" {
		return errors.New("rotate to new token: new token must not be empty")
	}
	log.Printf("rotating cluster token to controller-provided token")

	if err := runTokenRotate(ctx, newToken); err != nil {
		// Not fatal — the poll loop below re-issues on timeout.
		log.Printf("initial token rotate failed: %v (will retry via polling)", err)
	}

	needle := "server:" + newToken
	return pollUntilTokenChanges(ctx, bootstrapTokenPollInterval,
		func(content string) bool { return strings.Contains(content, needle) },
		func() error { return runTokenRotate(ctx, newToken) },
	)
}

// RotateToken rotates the cluster token to a k3s-generated value
// and blocks until the on-disk token file changes from its previous
// value. Used by the HA→single transition path where any new token
// suffices — only that it differs from the prior (potentially
// compromised) one.
//
// Symmetry with RotateToNewToken: same retry-on-stale and same
// bounded-read-error policy. Earlier versions silently spun forever
// if the rotate exec failed; this version re-issues every
// tokenRotateRetryTimeout.
func RotateToken(ctx context.Context) error {
	log.Printf("rotating cluster token (k3s-generated)")
	currentData, err := os.ReadFile(k3sTokenFile)
	if err != nil {
		return fmt.Errorf("rotate token: read current token: %w", err)
	}
	currentToken := strings.TrimSpace(string(currentData))

	if err := runGeneratedTokenRotate(ctx); err != nil {
		log.Printf("initial k3s-generated token rotate failed: %v (will retry via polling)", err)
	}
	return pollUntilTokenChanges(ctx, tokenPollInterval,
		func(content string) bool {
			return strings.TrimSpace(content) != currentToken
		},
		func() error { return runGeneratedTokenRotate(ctx) },
	)
}

// pollUntilTokenChanges is the shared poll loop. It returns once
// match(currentBody) is true, the caller's ctx is done, or
// non-transient read failures exceed tokenReadMaxConsecutiveErrors.
// rotateRetry is called every tokenRotateRetryTimeout while the file
// still does not match.
func pollUntilTokenChanges(
	ctx context.Context,
	interval time.Duration,
	match func(body string) bool,
	rotateRetry func() error,
) error {
	// Check immediately to skip a wasted poll interval on fast rotates.
	if data, err := os.ReadFile(k3sTokenFile); err == nil && match(string(data)) {
		log.Printf("cluster token rotation observed")
		return nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	retryStart := time.Now()
	nonENOENTErrors := 0

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("rotate token: %w", ctx.Err())
		case <-ticker.C:
		}
		data, err := os.ReadFile(k3sTokenFile)
		switch {
		case err == nil:
			nonENOENTErrors = 0
			if match(string(data)) {
				log.Printf("cluster token rotation observed")
				return nil
			}
		case errors.Is(err, os.ErrNotExist):
			// k3s hasn't created the file yet — keep polling.
			log.Printf("token file %s not yet present", k3sTokenFile)
		default:
			nonENOENTErrors++
			log.Printf("cannot read token file %s: %v (consecutive non-ENOENT errors: %d)",
				k3sTokenFile, err, nonENOENTErrors)
			if nonENOENTErrors >= tokenReadMaxConsecutiveErrors {
				return fmt.Errorf("%w: %d consecutive read failures (last: %v)",
					ErrTokenRotateAbandoned, nonENOENTErrors, err)
			}
		}

		if time.Since(retryStart) >= tokenRotateRetryTimeout {
			log.Printf("token file unchanged after %v, re-issuing rotate", tokenRotateRetryTimeout)
			if err := rotateRetry(); err != nil {
				log.Printf("token rotate retry failed: %v", err)
			}
			retryStart = time.Now()
		}
	}
}

// runTokenRotate executes `k3s token rotate --new-token=<v>` once.
func runTokenRotate(ctx context.Context, newToken string) error {
	cmd := exec.CommandContext(ctx, K3sSymlink, "token", "rotate",
		"--new-token="+newToken)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("k3s token rotate --new-token: %w (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runGeneratedTokenRotate executes `k3s token rotate` once and lets
// k3s pick the new token.
func runGeneratedTokenRotate(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, K3sSymlink, "token", "rotate")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("k3s token rotate: %w (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}
