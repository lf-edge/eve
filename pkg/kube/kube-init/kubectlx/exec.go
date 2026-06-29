// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// k3sBinary is the absolute path to the k3s multi-call binary. The
// EVE kube linuxkit container ships only the single `k3s` binary;
// kubectl, ctr, and crictl are invoked as `k3s kubectl <args>` /
// `k3s ctr <args>` / `k3s crictl <args>`. There is no standalone
// kubectl binary on the EVE rootfs.
//
// /usr/bin/k3s is the standard install location on the kube container
// rootfs (also on $PATH); we hard-code the absolute path here to avoid
// any dependence on PATH lookup in the kube-init process environment.
const k3sBinary = "/usr/bin/k3s"

// Run shells out to `k3s kubectl <args...>` with the standard k3s
// kubeconfig and returns the trimmed combined output. On non-zero
// exit it returns a wrapped error that includes the argv and the
// captured output.
//
// This is the canonical way to invoke a one-shot kubectl command
// from kube-init code. For commands that need stdin attached or
// long-running invocations that must honour context cancellation,
// use Cmd or CmdContext respectively.
func Run(args ...string) (string, error) {
	fullArgs := append([]string{"kubectl"}, args...)
	cmd := exec.Command(k3sBinary, fullArgs...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		return outStr, fmt.Errorf("kubectl %s: %w (output: %s)",
			strings.Join(args, " "), err, outStr)
	}
	return outStr, nil
}

// Cmd returns an *exec.Cmd for `k3s kubectl <args...>` with the
// standard K3s kubeconfig in its environment. Use this when you need
// to attach stdin, capture stdout and stderr separately, or otherwise
// customize the command before running it.
//
// The returned command is NOT cancellable via context — for that, use
// CmdContext.
func Cmd(args ...string) *exec.Cmd {
	fullArgs := append([]string{"kubectl"}, args...)
	cmd := exec.Command(k3sBinary, fullArgs...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	return cmd
}

// CmdContext is the cancellable equivalent of Cmd. The returned
// *exec.Cmd is built via exec.CommandContext, so cancelling ctx
// (timeout or explicit cancel) will SIGKILL the kubectl process.
//
// Use this for any kubectl invocation that may block for a non-trivial
// time — `kubectl wait`, `kubectl rollout status`, long-running
// `kubectl apply` against a slow API server — so the kube-init daemon
// can shut down promptly on SIGTERM.
func CmdContext(ctx context.Context, args ...string) *exec.Cmd {
	fullArgs := append([]string{"kubectl"}, args...)
	cmd := exec.CommandContext(ctx, k3sBinary, fullArgs...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	return cmd
}
