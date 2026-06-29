// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"
)

// Default timeout for readiness waits when callers pass 0.
const defaultWaitTimeout = 5 * time.Minute

// WaitArgs builds the kubectl argv for a typed wait. It is exported so
// tests can assert on argv construction without spawning kubectl.
type WaitArgs []string

// crdEstablishedArgs builds:
//
//	kubectl wait --for=condition=established --timeout=<dur> crd/<name>
func crdEstablishedArgs(name string, timeout time.Duration) WaitArgs {
	return WaitArgs{
		"wait",
		"--for=condition=established",
		"--timeout=" + formatTimeout(timeout),
		"crd/" + name,
	}
}

// rolloutStatusArgs builds:
//
//	kubectl rollout status <kind>/<name> -n <ns> --timeout=<dur>
func rolloutStatusArgs(kind, namespace, name string, timeout time.Duration) WaitArgs {
	args := WaitArgs{
		"rollout", "status",
		kind + "/" + name,
		"--timeout=" + formatTimeout(timeout),
	}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	return args
}

// jobCompleteArgs builds:
//
//	kubectl wait --for=condition=complete --timeout=<dur> -n <ns> job/<name>
func jobCompleteArgs(namespace, name string, timeout time.Duration) WaitArgs {
	args := WaitArgs{
		"wait",
		"--for=condition=complete",
		"--timeout=" + formatTimeout(timeout),
	}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	args = append(args, "job/"+name)
	return args
}

// conditionArgs builds a generic:
//
//	kubectl wait --for=jsonpath=<jsonpath>=<want> --timeout=<dur> [-n <ns>] <kind>/<name>
//
// Use this when no first-class helper exists (e.g. KubeVirt CR
// `Available` condition).
func conditionArgs(kind, namespace, name, jsonPath, want string, timeout time.Duration) WaitArgs {
	args := WaitArgs{
		"wait",
		"--for=jsonpath=" + jsonPath + "=" + want,
		"--timeout=" + formatTimeout(timeout),
	}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	args = append(args, kind+"/"+name)
	return args
}

// formatTimeout renders a duration in the format kubectl expects
// (`30s`, `5m`, `1h`). kubectl rejects fractional units, so we round
// to whole seconds.
func formatTimeout(d time.Duration) string {
	if d <= 0 {
		d = defaultWaitTimeout
	}
	// Round up so a 500ms request still produces `1s`.
	secs := int64((d + time.Second - 1) / time.Second)
	if secs%3600 == 0 {
		return strconv.FormatInt(secs/3600, 10) + "h"
	}
	if secs%60 == 0 {
		return strconv.FormatInt(secs/60, 10) + "m"
	}
	return strconv.FormatInt(secs, 10) + "s"
}

// runWait executes the given kubectl wait/rollout command under the
// caller's context and returns the combined output for log/error use.
func runWait(ctx context.Context, args WaitArgs) error {
	cmd := CmdContext(ctx, []string(args)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// ctx cancellation surfaces as a non-zero exit; surface it
		// distinctly so callers can tell timeout-from-kubectl apart
		// from caller cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("kubectl %v cancelled: %w (output: %s)",
				[]string(args), ctxErr, string(out))
		}
		return fmt.Errorf("kubectl %v: %w (output: %s)",
			[]string(args), err, string(out))
	}
	return nil
}

// WaitCRDEstablished blocks until the named CRD reports
// `Established=True`, or until timeout / ctx cancel.
//
// This MUST be called between `kubectl apply -f crd.yaml` and any
// `kubectl apply` that references the CRD's kind, otherwise the second
// apply can race the API server's discovery cache and fail with
// `no matches for kind "Foo"`.
func WaitCRDEstablished(ctx context.Context, name string, timeout time.Duration) error {
	args := crdEstablishedArgs(name, timeout)
	log.Printf("kubectlx: waiting for CRD %s to be Established (timeout=%s)",
		name, formatTimeout(timeout))
	return runWait(ctx, args)
}

// WaitDeploymentReady blocks until `kubectl rollout status` reports
// the deployment is fully rolled out.
func WaitDeploymentReady(ctx context.Context, namespace, name string, timeout time.Duration) error {
	args := rolloutStatusArgs("deployment", namespace, name, timeout)
	log.Printf("kubectlx: waiting for deployment %s/%s to roll out (timeout=%s)",
		namespace, name, formatTimeout(timeout))
	return runWait(ctx, args)
}

// WaitDaemonSetReady blocks until `kubectl rollout status` reports
// the daemonset is fully rolled out (every desired pod is ready).
func WaitDaemonSetReady(ctx context.Context, namespace, name string, timeout time.Duration) error {
	args := rolloutStatusArgs("daemonset", namespace, name, timeout)
	log.Printf("kubectlx: waiting for daemonset %s/%s to roll out (timeout=%s)",
		namespace, name, formatTimeout(timeout))
	return runWait(ctx, args)
}

// WaitJobComplete blocks until the given Job reports
// `condition=complete=True`. Returns an error if the Job fails or the
// wait times out.
func WaitJobComplete(ctx context.Context, namespace, name string, timeout time.Duration) error {
	args := jobCompleteArgs(namespace, name, timeout)
	log.Printf("kubectlx: waiting for job %s/%s to complete (timeout=%s)",
		namespace, name, formatTimeout(timeout))
	return runWait(ctx, args)
}

// WaitForCondition is a generic fallback that waits for a JSONPath
// expression on the named resource to equal `want`. Use it when no
// first-class helper is appropriate (e.g. waiting on a CR-defined
// status field).
//
// Example:
//
//	WaitForCondition(ctx, "kubevirt", "kubevirt", "kubevirt",
//	    "{.status.phase}", "Deployed", 5*time.Minute)
func WaitForCondition(ctx context.Context, kind, namespace, name, jsonPath, want string, timeout time.Duration) error {
	args := conditionArgs(kind, namespace, name, jsonPath, want, timeout)
	log.Printf("kubectlx: waiting for %s/%s %s=%s (timeout=%s)",
		kind, name, jsonPath, want, formatTimeout(timeout))
	return runWait(ctx, args)
}
