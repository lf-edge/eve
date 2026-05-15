// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// formatTimeout
// ---------------------------------------------------------------------------

func TestFormatTimeout(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want string
	}{
		{"zero defaults to 5m", 0, "5m"},
		{"negative defaults to 5m", -1 * time.Second, "5m"},
		{"500ms rounds up to 1s", 500 * time.Millisecond, "1s"},
		{"30s", 30 * time.Second, "30s"},
		{"60s renders as 1m", 60 * time.Second, "1m"},
		{"5m", 5 * time.Minute, "5m"},
		{"3600s renders as 1h", 3600 * time.Second, "1h"},
		{"90s stays seconds", 90 * time.Second, "90s"},
		{"2h", 2 * time.Hour, "2h"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatTimeout(tc.in)
			if got != tc.want {
				t.Fatalf("formatTimeout(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// argv builders
// ---------------------------------------------------------------------------

func TestCRDEstablishedArgs(t *testing.T) {
	got := crdEstablishedArgs("widgets.example.com", 2*time.Minute)
	want := WaitArgs{
		"wait",
		"--for=condition=established",
		"--timeout=2m",
		"crd/widgets.example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crdEstablishedArgs argv mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestRolloutStatusArgs(t *testing.T) {
	cases := []struct {
		name      string
		kind      string
		namespace string
		obj       string
		timeout   time.Duration
		want      WaitArgs
	}{
		{
			name:      "deployment with namespace",
			kind:      "deployment",
			namespace: "default",
			obj:       "nginx",
			timeout:   3 * time.Minute,
			want: WaitArgs{
				"rollout", "status",
				"deployment/nginx",
				"--timeout=3m",
				"-n", "default",
			},
		},
		{
			name:      "daemonset without namespace omits -n",
			kind:      "daemonset",
			namespace: "",
			obj:       "kube-multus-ds",
			timeout:   30 * time.Second,
			want: WaitArgs{
				"rollout", "status",
				"daemonset/kube-multus-ds",
				"--timeout=30s",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rolloutStatusArgs(tc.kind, tc.namespace, tc.obj, tc.timeout)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rolloutStatusArgs argv mismatch\n got: %v\nwant: %v", got, tc.want)
			}
		})
	}
}

func TestJobCompleteArgs(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		obj       string
		timeout   time.Duration
		want      WaitArgs
	}{
		{
			name:      "with namespace",
			namespace: "longhorn-system",
			obj:       "longhorn-uninstall",
			timeout:   10 * time.Minute,
			want: WaitArgs{
				"wait",
				"--for=condition=complete",
				"--timeout=10m",
				"-n", "longhorn-system",
				"job/longhorn-uninstall",
			},
		},
		{
			name:      "without namespace",
			namespace: "",
			obj:       "one-shot",
			timeout:   30 * time.Second,
			want: WaitArgs{
				"wait",
				"--for=condition=complete",
				"--timeout=30s",
				"job/one-shot",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := jobCompleteArgs(tc.namespace, tc.obj, tc.timeout)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("jobCompleteArgs argv mismatch\n got: %v\nwant: %v", got, tc.want)
			}
		})
	}
}

func TestConditionArgs(t *testing.T) {
	got := conditionArgs(
		"kubevirt", "kubevirt", "kubevirt",
		"{.status.phase}", "Deployed",
		5*time.Minute,
	)
	want := WaitArgs{
		"wait",
		"--for=jsonpath={.status.phase}=Deployed",
		"--timeout=5m",
		"-n", "kubevirt",
		"kubevirt/kubevirt",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("conditionArgs argv mismatch\n got: %v\nwant: %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// ClassifyKubectlErr
// ---------------------------------------------------------------------------

func TestClassifyKubectlErr(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want ErrClass
	}{
		// AlreadyExists takes priority over everything.
		{
			name: "AlreadyExists wins",
			out:  `Error from server (AlreadyExists): widgets.example.com "default" already exists`,
			want: ErrClassAlreadyExists,
		},
		{
			name: "lowercase already exists string",
			out:  `error: namespaces "kube-system" already exists`,
			want: ErrClassAlreadyExists,
		},

		// Fatal classifications.
		{
			name: "RBAC forbidden",
			out:  `Error from server (Forbidden): configmaps is forbidden: User "system:serviceaccount:default:example" cannot watch resource`,
			want: ErrClassFatal,
		},
		{
			name: "schema invalid",
			out:  `The Deployment "nginx" is invalid: spec.template.spec.containers[0].image: Required value`,
			want: ErrClassFatal,
		},
		{
			name: "manifest file missing",
			out:  `error: the path "/etc/foo/missing.yaml": no such file or directory`,
			want: ErrClassFatal,
		},
		{
			name: "unable to recognize bad apiVersion",
			out:  `error: unable to recognize "deploy.yaml": no matches for kind "Widget" in version "example.com/v999"`,
			// "unable to recognize" is fatal; even though "no matches
			// for kind" is also present (transient), fatal wins.
			want: ErrClassFatal,
		},
		{
			name: "Unauthorized",
			out:  `Error from server (Unauthorized): the server has asked for the client to provide credentials`,
			want: ErrClassFatal,
		},

		// Transient classifications.
		{
			name: "no matches for kind (CRD discovery race)",
			out:  `error: unable to find a resource: no matches for kind "Widget"`,
			// This message does NOT contain "unable to recognize",
			// so it should still classify as Transient.
			want: ErrClassTransient,
		},
		{
			name: "API server starting up",
			out:  `The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?`,
			want: ErrClassTransient,
		},
		{
			name: "etcd leader changed",
			out:  `Error from server: rpc error: etcdserver: leader changed`,
			want: ErrClassTransient,
		},
		{
			name: "webhook not ready",
			out:  `Internal error occurred: failed calling webhook "validating.kubevirt.io": Post "https://...": dial tcp: connection refused`,
			// "connection refused" is also a transient match; either
			// way → Transient.
			want: ErrClassTransient,
		},
		{
			name: "throttled",
			out:  `Error from server: too many requests`,
			want: ErrClassTransient,
		},
		{
			name: "TLS handshake timeout",
			out:  `error: TLS handshake timeout`,
			want: ErrClassTransient,
		},

		// Unknown.
		{
			name: "empty string is unknown",
			out:  ``,
			want: ErrClassUnknown,
		},
		{
			name: "novel kubectl error is unknown",
			out:  `error: an error i have never seen before`,
			want: ErrClassUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyKubectlErr(tc.out)
			if got != tc.want {
				t.Fatalf("ClassifyKubectlErr(%q) = %v, want %v",
					tc.out, got, tc.want)
			}
		})
	}
}

func TestErrClassString(t *testing.T) {
	cases := map[ErrClass]string{
		ErrClassUnknown:       "unknown",
		ErrClassTransient:     "transient",
		ErrClassAlreadyExists: "alreadyExists",
		ErrClassFatal:         "fatal",
		ErrClass(99):          "unknown",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("ErrClass(%d).String() = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// ApplyOptions defaults
// ---------------------------------------------------------------------------

func TestApplyOptionsDefaults(t *testing.T) {
	var opts ApplyOptions
	opts.withDefaults()

	if opts.MaxAttempts != 10 {
		t.Errorf("MaxAttempts default = %d, want 10", opts.MaxAttempts)
	}
	if opts.InitialBackoff != 1*time.Second {
		t.Errorf("InitialBackoff default = %v, want 1s", opts.InitialBackoff)
	}
	if opts.MaxBackoff != 30*time.Second {
		t.Errorf("MaxBackoff default = %v, want 30s", opts.MaxBackoff)
	}
	if opts.CommandTimeout != 60*time.Second {
		t.Errorf("CommandTimeout default = %v, want 60s", opts.CommandTimeout)
	}

	// Explicit non-zero values are preserved.
	custom := ApplyOptions{
		MaxAttempts:    3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     500 * time.Millisecond,
		CommandTimeout: 5 * time.Second,
	}
	custom.withDefaults()
	if custom.MaxAttempts != 3 || custom.InitialBackoff != 100*time.Millisecond ||
		custom.MaxBackoff != 500*time.Millisecond || custom.CommandTimeout != 5*time.Second {
		t.Errorf("custom values not preserved: %+v", custom)
	}
}

// ---------------------------------------------------------------------------
// runWithBackoff: retry loop semantics
// ---------------------------------------------------------------------------

// fakeRunner installs a stub runOnceFn that returns a scripted sequence
// of (output, error) pairs, one per call. Restores the original on
// cleanup. Records the args of every call for inspection.
type fakeRunner struct {
	t        *testing.T
	scripted []runResult
	calls    [][]string
	idx      int
	orig     func(context.Context, []string, time.Duration) (string, error)
}

type runResult struct {
	out string
	err error
}

func newFakeRunner(t *testing.T, results []runResult) *fakeRunner {
	t.Helper()
	fr := &fakeRunner{
		t:        t,
		scripted: results,
		orig:     runOnceFn,
	}
	runOnceFn = fr.run
	t.Cleanup(func() { runOnceFn = fr.orig })
	return fr
}

func (fr *fakeRunner) run(_ context.Context, args []string, _ time.Duration) (string, error) {
	if fr.idx >= len(fr.scripted) {
		fr.t.Fatalf("fakeRunner: ran out of scripted results at call %d (args=%v)",
			fr.idx+1, args)
	}
	dup := append([]string(nil), args...)
	fr.calls = append(fr.calls, dup)
	r := fr.scripted[fr.idx]
	fr.idx++
	return r.out, r.err
}

// fastOpts returns ApplyOptions tuned for fast tests: 1ms backoff, no
// real per-attempt timeout, deterministic rng.
func fastOpts(maxAttempts int) ApplyOptions {
	return ApplyOptions{
		MaxAttempts:    maxAttempts,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
		CommandTimeout: 0, // skip per-attempt timeout in tests
		rng:            rand.New(rand.NewSource(1)),
	}
}

func TestApplyWithBackoff_SuccessFirstTry(t *testing.T) {
	newFakeRunner(t, []runResult{
		{out: "deployment.apps/foo created", err: nil},
	})

	if err := ApplyWithBackoff(context.Background(), "/tmp/x.yaml", fastOpts(5)); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestApplyWithBackoff_TransientThenSuccess(t *testing.T) {
	transientErr := errors.New("exit 1")
	fr := newFakeRunner(t, []runResult{
		{out: `error: no matches for kind "Foo"`, err: transientErr},
		{out: `error: connection refused`, err: transientErr},
		{out: "configured", err: nil},
	})

	if err := ApplyWithBackoff(context.Background(), "/tmp/x.yaml", fastOpts(5)); err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if len(fr.calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(fr.calls))
	}
}

func TestApplyWithBackoff_FatalShortCircuits(t *testing.T) {
	fatalErr := errors.New("exit 1")
	fr := newFakeRunner(t, []runResult{
		{out: `Error from server (Forbidden): configmaps is forbidden`, err: fatalErr},
		// More results scripted but should never be consumed.
		{out: "should not be reached", err: nil},
	})

	err := ApplyWithBackoff(context.Background(), "/tmp/x.yaml", fastOpts(5))
	if err == nil {
		t.Fatalf("expected fatal error, got nil")
	}
	if len(fr.calls) != 1 {
		t.Fatalf("fatal should not retry; expected 1 call, got %d", len(fr.calls))
	}
	if errors.Is(err, ErrApplyExhausted) {
		t.Fatalf("fatal error should not be wrapped as ErrApplyExhausted; got: %v", err)
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("error should preserve underlying message; got: %v", err)
	}
}

func TestApplyWithBackoff_AlreadyExistsIsSuccess(t *testing.T) {
	fr := newFakeRunner(t, []runResult{
		{out: `Error from server (AlreadyExists): namespaces "x" already exists`,
			err: errors.New("exit 1")},
	})

	if err := ApplyWithBackoff(context.Background(), "/tmp/x.yaml", fastOpts(5)); err != nil {
		t.Fatalf("AlreadyExists should be success, got: %v", err)
	}
	if len(fr.calls) != 1 {
		t.Fatalf("AlreadyExists should not retry; expected 1 call, got %d", len(fr.calls))
	}
}

func TestApplyWithBackoff_UnknownIsRetried(t *testing.T) {
	// Unknown errors should retry (we'd rather over-retry than
	// under-retry against a novel kubectl message).
	someErr := errors.New("exit 1")
	fr := newFakeRunner(t, []runResult{
		{out: "an error i have never seen before", err: someErr},
		{out: "another novel error", err: someErr},
		{out: "configured", err: nil},
	})

	if err := ApplyWithBackoff(context.Background(), "/tmp/x.yaml", fastOpts(5)); err != nil {
		t.Fatalf("expected eventual success, got: %v", err)
	}
	if len(fr.calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(fr.calls))
	}
}

func TestApplyWithBackoff_ExhaustedReturnsSentinel(t *testing.T) {
	transientErr := errors.New("exit 1")
	fr := newFakeRunner(t, []runResult{
		{out: `error: connection refused`, err: transientErr},
		{out: `error: connection refused`, err: transientErr},
		{out: `error: connection refused`, err: transientErr},
	})

	err := ApplyWithBackoff(context.Background(), "/tmp/x.yaml", fastOpts(3))
	if err == nil {
		t.Fatalf("expected exhaustion error, got nil")
	}
	if !errors.Is(err, ErrApplyExhausted) {
		t.Fatalf("expected ErrApplyExhausted, got: %v", err)
	}
	if len(fr.calls) != 3 {
		t.Fatalf("expected 3 calls (== MaxAttempts), got %d", len(fr.calls))
	}
}

func TestApplyWithBackoff_ContextCancelledBetweenAttempts(t *testing.T) {
	transientErr := errors.New("exit 1")

	// Cancel the context the moment runOnce returns its second
	// result. That fires the cancellation exactly between the second
	// attempt and the third backoff sleep — deterministic regardless
	// of CI load, no wall-clock dependency.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var calls int
	orig := runOnceFn
	runOnceFn = func(_ context.Context, _ []string, _ time.Duration) (string, error) {
		calls++
		if calls == 2 {
			cancel()
		}
		return "error: connection refused", transientErr
	}
	t.Cleanup(func() { runOnceFn = orig })

	err := ApplyWithBackoff(ctx, "/tmp/x.yaml", fastOpts(10))
	if err == nil {
		t.Fatalf("expected cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled in error chain, got: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected exactly 2 calls before cancel takes effect, got %d", calls)
	}
}

func TestApplyWithBackoff_PreCancelledContext(t *testing.T) {
	fr := newFakeRunner(t, []runResult{
		{out: "should not be called", err: nil},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ApplyWithBackoff(ctx, "/tmp/x.yaml", fastOpts(5))
	if err == nil {
		t.Fatalf("expected cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if len(fr.calls) != 0 {
		t.Fatalf("pre-cancelled ctx should run 0 attempts, got %d", len(fr.calls))
	}
}

func TestApplyWithBackoff_ExtraArgsAppended(t *testing.T) {
	fr := newFakeRunner(t, []runResult{
		{out: "configured", err: nil},
	})

	opts := fastOpts(1)
	opts.ExtraArgs = []string{"-n", "kube-system", "--server-side"}

	if err := ApplyWithBackoff(context.Background(), "/tmp/x.yaml", opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"apply", "-f", "/tmp/x.yaml", "-n", "kube-system", "--server-side"}
	if !reflect.DeepEqual(fr.calls[0], want) {
		t.Fatalf("argv mismatch\n got: %v\nwant: %v", fr.calls[0], want)
	}
}

func TestCreateWithBackoff_UsesCreateVerb(t *testing.T) {
	fr := newFakeRunner(t, []runResult{
		{out: "job.batch/x created", err: nil},
	})

	if err := CreateWithBackoff(context.Background(), "/tmp/job.yaml", fastOpts(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"create", "-f", "/tmp/job.yaml"}
	if !reflect.DeepEqual(fr.calls[0], want) {
		t.Fatalf("argv mismatch\n got: %v\nwant: %v", fr.calls[0], want)
	}
}

// ---------------------------------------------------------------------------
// Cmd / CmdContext argv + KUBECONFIG env
// ---------------------------------------------------------------------------

// findKubeconfigEnv returns the value of KUBECONFIG in env, or "" if absent.
func findKubeconfigEnv(env []string) string {
	const prefix = "KUBECONFIG="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix)
		}
	}
	return ""
}

func TestCmd_ArgvAndKubeconfig(t *testing.T) {
	cmd := Cmd("get", "pods", "-A")

	if cmd.Path != k3sBinary {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, k3sBinary)
	}
	wantArgs := []string{k3sBinary, "kubectl", "get", "pods", "-A"}
	if !reflect.DeepEqual(cmd.Args, wantArgs) {
		t.Errorf("cmd.Args = %v, want %v", cmd.Args, wantArgs)
	}
	if kc := findKubeconfigEnv(cmd.Env); kc != "/etc/rancher/k3s/k3s.yaml" {
		t.Errorf("KUBECONFIG = %q, want /etc/rancher/k3s/k3s.yaml", kc)
	}
}

func TestCmdContext_ArgvAndKubeconfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cmd := CmdContext(ctx, "apply", "-f", "/tmp/x.yaml")

	if cmd.Path != k3sBinary {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, k3sBinary)
	}
	wantArgs := []string{k3sBinary, "kubectl", "apply", "-f", "/tmp/x.yaml"}
	if !reflect.DeepEqual(cmd.Args, wantArgs) {
		t.Errorf("cmd.Args = %v, want %v", cmd.Args, wantArgs)
	}
	if kc := findKubeconfigEnv(cmd.Env); kc != "/etc/rancher/k3s/k3s.yaml" {
		t.Errorf("KUBECONFIG = %q, want /etc/rancher/k3s/k3s.yaml", kc)
	}
}

// ---------------------------------------------------------------------------
// ClassifyKubectlErr priority: AlreadyExists wins over Fatal
// ---------------------------------------------------------------------------

func TestClassifyKubectlErr_AlreadyExistsBeatsFatal(t *testing.T) {
	// Output legitimately matches BOTH an alreadyExists pattern and a
	// fatal pattern. AlreadyExists must win — re-running an apply
	// against an existing resource is not a hard error worth surfacing.
	out := `Error from server (AlreadyExists): widgets.example.com "x" already exists; previous error: forbidden`
	if got := ClassifyKubectlErr(out); got != ErrClassAlreadyExists {
		t.Errorf("expected AlreadyExists to win over Fatal, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// runWithBackoff: cancel-during-backoff is deterministic
// ---------------------------------------------------------------------------

func TestApplyWithBackoff_CancelDuringBackoff(t *testing.T) {
	// Drive the cancel inside the backoff sleep by firing it from a
	// timer after the first attempt returns. We confirm the loop wakes
	// from <-ctx.Done() rather than running another kubectl call.
	transientErr := errors.New("exit 1")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var attempts int
	orig := runOnceFn
	runOnceFn = func(_ context.Context, _ []string, _ time.Duration) (string, error) {
		attempts++
		if attempts == 1 {
			time.AfterFunc(5*time.Millisecond, cancel)
		}
		return "error: connection refused", transientErr
	}
	t.Cleanup(func() { runOnceFn = orig })

	opts := ApplyOptions{
		MaxAttempts:    10,
		InitialBackoff: 200 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
		CommandTimeout: 0,
		rng:            rand.New(rand.NewSource(1)),
	}
	err := ApplyWithBackoff(ctx, "/tmp/x.yaml", opts)
	if err == nil {
		t.Fatalf("expected cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled in error chain, got: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 attempt before cancel during sleep, got %d", attempts)
	}
}

// ---------------------------------------------------------------------------
// execRunOnce: per-attempt timeout vs caller cancel
// ---------------------------------------------------------------------------

// runViaSleep mirrors execRunOnce's timeout-classification logic but
// shells out to /bin/sleep instead of k3sBinary so the test does not
// depend on the EVE rootfs being present. The branch under test is the
// "ctx alive, runCtx dead → wrap in ErrAttemptTimeout" logic.
func runViaSleep(ctx context.Context, secs string, timeout time.Duration) (string, error) {
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, "sleep", secs)
	out, err := cmd.CombinedOutput()
	if err != nil && timeout > 0 && ctx.Err() == nil && runCtx.Err() != nil {
		err = fmt.Errorf("%w (after %s): %w", ErrAttemptTimeout, timeout, err)
	}
	return string(out), err
}

func TestExecRunOnce_PerAttemptTimeoutWraps(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep binary not available")
	}
	_, err := runViaSleep(context.Background(), "5", 20*time.Millisecond)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if !errors.Is(err, ErrAttemptTimeout) {
		t.Fatalf("expected ErrAttemptTimeout in chain, got: %v", err)
	}
}

func TestExecRunOnce_CallerCancelNotWrapped(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep binary not available")
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)

	_, err := runViaSleep(ctx, "5", 10*time.Second)
	if err == nil {
		t.Fatalf("expected cancellation error, got nil")
	}
	if errors.Is(err, ErrAttemptTimeout) {
		t.Fatalf("caller-cancel should not be classified as per-attempt timeout: %v", err)
	}
}
