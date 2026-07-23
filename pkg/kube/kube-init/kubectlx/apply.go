// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"
)

// ErrClass classifies a kubectl failure. The classification drives
// retry behaviour: only Transient is retried; AlreadyExists is treated
// as success; Fatal is surfaced immediately.
type ErrClass int

const (
	// ErrClassUnknown means the stderr did not match any known
	// pattern. Treated as Transient by ApplyWithBackoff so a novel
	// kubectl error does not fail outright; logged distinctly so the
	// pattern table can grow over time.
	ErrClassUnknown ErrClass = iota

	// ErrClassTransient is a kubectl error that is expected to clear
	// on its own: discovery cache races, API-server unavailability,
	// etcd leader changes, webhook readiness races. Worth retrying.
	ErrClassTransient

	// ErrClassAlreadyExists is short-circuit success — the resource
	// is already present in the desired state. Most kubectl apply
	// calls won't hit this (apply is idempotent), but `kubectl create`
	// and a few apply-with-immutable-field paths can.
	ErrClassAlreadyExists

	// ErrClassFatal is a configuration or permission error that will
	// not clear on retry: RBAC forbidden, schema invalid, manifest
	// not found, unauthorized. Surface immediately.
	ErrClassFatal
)

// String returns the short stable name of the error class
// ("transient", "alreadyExists", "fatal", "unknown"). Used in log
// lines and in the exhaustion error message; downstream tooling may
// match on these strings, so keep them stable.
func (c ErrClass) String() string {
	switch c {
	case ErrClassTransient:
		return "transient"
	case ErrClassAlreadyExists:
		return "alreadyExists"
	case ErrClassFatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// transientPatterns are substrings (case-insensitive) that indicate
// the kubectl error is worth retrying. These are deliberately narrow
// — anything not on this list and not on the fatal list is treated as
// ErrClassUnknown (which ApplyWithBackoff retries with a warning).
var transientPatterns = []string{
	// CRD discovery cache race: apply a CR immediately after its
	// CRD before kubectl's discovery cache catches up.
	"no matches for kind",
	"the server could not find the requested resource",

	// API server is starting up, restarting, or behind a leader
	// change. Common during k3s startup. We match both "connection
	// refused" (Go net dial errors) and "was refused" (kubectl's own
	// "The connection to the server X was refused" wording).
	"connection refused",
	"was refused",
	"the server is currently unable to handle the request",
	"etcdserver: leader changed",
	"etcdserver: request timed out",
	"i/o timeout",
	"unexpected eof",
	"tls handshake timeout",

	// Webhook not yet ready (admission controller pod still
	// rolling out).
	"failed calling webhook",
	// matches kubectl's `webhook "<name>": ... connection refused` chain
	// when the webhook pod is still rolling out.
	`webhook "`,
	"context deadline exceeded",

	// Transient throttling.
	"too many requests",
}

// fatalPatterns are substrings (case-insensitive) that indicate the
// kubectl error will not clear on retry. Surface these immediately so
// the FSM can move to recycle/backoff instead of spinning forever.
var fatalPatterns = []string{
	"forbidden",
	"unauthorized",
	"is invalid",
	"error validating data",
	"error parsing",
	// kubectl's exact shape when -f points at a missing manifest:
	//   error: the path "<path>": no such file or directory
	// Anchoring on `the path "` avoids matching unrelated ENOENT
	// messages that can appear in longer error chains (e.g. a missing
	// kubeconfig path embedded in a transient API error).
	`the path "`,
	"unable to recognize", // bad apiVersion in manifest
}

// alreadyExistsPatterns are substrings (case-insensitive) that
// indicate the resource is already present. Treated as success.
var alreadyExistsPatterns = []string{
	"alreadyexists",
	"already exists",
}

// ClassifyKubectlErr inspects kubectl stderr/combined output and
// returns the appropriate ErrClass. The classifier is intentionally
// pattern-based rather than parsing structured output: kubectl's
// human-readable stderr is the only thing that's stable across
// versions and across different command shapes (apply, create, wait,
// rollout, ...).
//
// The order of checks matters:
//  1. AlreadyExists wins over everything (we don't want to retry on
//     a resource that's already there).
//  2. Fatal wins over Transient (an "invalid" manifest can also
//     mention "connection refused" in a longer error chain — fail
//     fast on the structural problem).
//  3. Transient is the third priority.
//  4. Unknown is the default.
func ClassifyKubectlErr(out string) ErrClass {
	low := strings.ToLower(out)

	for _, p := range alreadyExistsPatterns {
		if strings.Contains(low, p) {
			return ErrClassAlreadyExists
		}
	}
	for _, p := range fatalPatterns {
		if strings.Contains(low, p) {
			return ErrClassFatal
		}
	}
	for _, p := range transientPatterns {
		if strings.Contains(low, strings.ToLower(p)) {
			return ErrClassTransient
		}
	}
	return ErrClassUnknown
}

// runOnceFn is the package-level seam for executing a single kubectl
// invocation. Production code uses execRunOnce (which shells out via
// the local CmdContext helper). Tests override this to return canned
// (output, error) pairs without spawning kubectl, so the retry loop
// in runWithBackoff can be exercised hermetically.
var runOnceFn = execRunOnce

// ApplyOptions tunes ApplyWithBackoff. Zero values give sane defaults.
type ApplyOptions struct {
	// MaxAttempts is the absolute cap on retry count. After this
	// many failed attempts ApplyWithBackoff returns the last error
	// even if the classification says "transient". Default: 10.
	MaxAttempts int

	// InitialBackoff is the first sleep between retries. Default:
	// 1 second.
	InitialBackoff time.Duration

	// MaxBackoff caps the per-attempt sleep. Default: 30 seconds.
	MaxBackoff time.Duration

	// CommandTimeout bounds each individual kubectl invocation.
	// 0 means no per-attempt timeout (caller's ctx still applies).
	// Default: 60 seconds.
	CommandTimeout time.Duration

	// ExtraArgs are appended to the base apply command. Use for
	// e.g. `--server-side`, `--field-manager=kube-init`,
	// `--validate=false`, namespace overrides.
	ExtraArgs []string

	// rng is overridable for deterministic tests.
	rng *rand.Rand
}

func (o *ApplyOptions) withDefaults() {
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 10
	}
	if o.InitialBackoff <= 0 {
		o.InitialBackoff = 1 * time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 30 * time.Second
	}
	if o.CommandTimeout <= 0 {
		o.CommandTimeout = 60 * time.Second
	}
}

// ErrApplyExhausted is returned by ApplyWithBackoff when MaxAttempts
// is reached without success. The wrapped error is the last kubectl
// failure, with classification context preserved in the message.
var ErrApplyExhausted = errors.New("kubectl apply: max attempts exhausted")

// ApplyWithBackoff runs `kubectl apply -f <file> [extraArgs...]` with:
//   - exponential backoff (doubled each attempt, capped at MaxBackoff)
//   - jitter (uniform 0..backoff/2 added)
//   - per-attempt timeout (bounds a single kubectl invocation)
//   - error classification (Fatal short-circuits; AlreadyExists is
//     success; Transient/Unknown are retried)
//   - max attempt cap (no spin-forever)
//
// Returns nil on success or AlreadyExists. Returns the wrapped
// kubectl error for Fatal classifications. When MaxAttempts is reached
// it returns an error that satisfies both errors.Is(err,
// ErrApplyExhausted) and errors.Is(err, <last kubectl exec error>),
// so callers can distinguish "we hit the retry cap" from "fatal" while
// still being able to inspect the underlying cause.
//
// The caller's ctx is honoured throughout — cancelling ctx between
// attempts aborts the loop immediately, and during an attempt aborts
// the running kubectl process via KubectlCmdContext.
func ApplyWithBackoff(ctx context.Context, file string, opts ApplyOptions) error {
	opts.withDefaults()

	baseArgs := append([]string{"apply", "-f", file}, opts.ExtraArgs...)
	return runWithBackoff(ctx, baseArgs, opts)
}

// CreateWithBackoff is the create-equivalent of ApplyWithBackoff. Use
// for resources where create-not-apply is required (e.g. one-shot
// Jobs whose generateName must produce a fresh object each time).
//
// AlreadyExists is still treated as success — if the caller wants
// "fail on already exists" they should use raw kubectlx.Run.
func CreateWithBackoff(ctx context.Context, file string, opts ApplyOptions) error {
	opts.withDefaults()

	baseArgs := append([]string{"create", "-f", file}, opts.ExtraArgs...)
	return runWithBackoff(ctx, baseArgs, opts)
}

// runWithBackoff is the shared retry loop for Apply/Create. Kept
// unexported so the two public entry points stay the only supported
// shapes.
func runWithBackoff(ctx context.Context, baseArgs []string, opts ApplyOptions) error {
	if opts.rng == nil {
		opts.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	var lastErr error
	var lastClass ErrClass
	backoff := opts.InitialBackoff

	for attempt := 1; attempt <= opts.MaxAttempts; attempt++ {
		// Honour caller cancellation before each attempt.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("kubectl %v cancelled before attempt %d: %w",
				baseArgs, attempt, err)
		}

		out, err := runOnceFn(ctx, baseArgs, opts.CommandTimeout)
		if err == nil {
			if attempt > 1 {
				log.Printf("kubectlx: kubectl %v succeeded on attempt %d",
					baseArgs, attempt)
			}
			return nil
		}

		class := ClassifyKubectlErr(out)
		lastErr = fmt.Errorf("kubectl %v: %w (output: %s)",
			baseArgs, err, strings.TrimSpace(out))
		lastClass = class

		switch class {
		case ErrClassAlreadyExists:
			log.Printf("kubectlx: kubectl %v: resource already exists, treating as success",
				baseArgs)
			return nil

		case ErrClassFatal:
			log.Printf("kubectlx: kubectl %v: fatal error on attempt %d, not retrying: %v",
				baseArgs, attempt, lastErr)
			return lastErr

		case ErrClassUnknown:
			log.Printf("kubectlx: kubectl %v: unclassified error on attempt %d (retrying): %v",
				baseArgs, attempt, lastErr)

		case ErrClassTransient:
			log.Printf("kubectlx: kubectl %v: transient error on attempt %d (retrying): %v",
				baseArgs, attempt, lastErr)
		}

		// Don't sleep after the final attempt.
		if attempt == opts.MaxAttempts {
			break
		}

		// Exponential backoff with jitter. Jitter is bounded to half
		// the backoff so the sleep is always in [backoff, 1.5*backoff).
		jitter := time.Duration(opts.rng.Int63n(int64(backoff/2 + 1)))
		sleep := backoff + jitter

		select {
		case <-ctx.Done():
			return fmt.Errorf("kubectl %v cancelled during backoff after attempt %d (last error: %w): %w",
				baseArgs, attempt, lastErr, ctx.Err())
		case <-time.After(sleep):
		}

		// Double for next attempt, but cap.
		backoff *= 2
		if backoff > opts.MaxBackoff {
			backoff = opts.MaxBackoff
		}
	}

	return errors.Join(
		fmt.Errorf("%w: kubectl %v failed %d times (last class=%s)",
			ErrApplyExhausted, baseArgs, opts.MaxAttempts, lastClass),
		lastErr,
	)
}

// ErrAttemptTimeout marks an error returned by execRunOnce when the
// per-attempt timeout fired but the caller's ctx is still alive. This
// lets the retry loop and tests tell "this single kubectl invocation
// took too long" apart from "the caller asked us to stop".
var ErrAttemptTimeout = errors.New("kubectlx: per-attempt timeout")

// execRunOnce executes a single kubectl invocation under a per-attempt
// timeout (if set) carved from the caller's ctx. Returns the combined
// output and the exec error.
//
// If the per-attempt timeout fires while the caller's ctx is still
// alive, the returned error wraps ErrAttemptTimeout so callers can
// distinguish it from caller-driven cancellation. If the caller's ctx
// is itself cancelled, that cancellation surfaces normally via the
// exec error.
func execRunOnce(ctx context.Context, args []string, timeout time.Duration) (string, error) {
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := CmdContext(runCtx, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && timeout > 0 && ctx.Err() == nil && runCtx.Err() != nil {
		// The runCtx deadline fired but the caller's ctx is still
		// healthy — this is a per-attempt timeout, not caller cancel.
		err = fmt.Errorf("%w (after %s): %w", ErrAttemptTimeout, timeout, err)
	}
	return string(out), err
}
