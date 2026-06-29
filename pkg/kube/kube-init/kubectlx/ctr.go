// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// K8sContainerdNamespace is the containerd namespace that kubelet uses
// for all kubelet-managed pods. Images for kubelet pods MUST be
// imported here; the default containerd namespace is visible to `ctr`
// but NOT to kubelet, so images landed there are invisible to pods.
//
// Exported so callers that need the namespace for other purposes
// (e.g. assembling their own command line for a one-off) don't have
// to hard-code the string.
const K8sContainerdNamespace = "k8s.io"

// CtrRun invokes `k3s ctr -a <user-containerd-socket> -n k8s.io <args...>`
// and returns the trimmed combined output. Non-zero exit wraps the
// error with the argv + output for forensics. Background context —
// prefer CtrRunContext for cancellable invocations.
func CtrRun(args ...string) (string, error) {
	return CtrRunContext(context.Background(), args...)
}

// CtrRunContext is the cancellable form of CtrRun.
func CtrRunContext(ctx context.Context, args ...string) (string, error) {
	cmd := CtrCmd(ctx, args...)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		return outStr, fmt.Errorf("ctr %s: %w (output: %s)",
			strings.Join(args, " "), err, outStr)
	}
	return outStr, nil
}

// CtrCmd returns an *exec.Cmd for the standard ctr invocation.
// Use this when the caller needs to attach stdin/stdout/stderr
// separately or customise the command before running it.
//
// The returned command already includes the user-containerd socket
// (`-a /run/containerd-user/containerd.sock`) and the k8s.io
// namespace (`-n k8s.io`); callers provide only the subcommand
// args (e.g. "images", "import", "/images/foo.tar").
func CtrCmd(ctx context.Context, args ...string) *exec.Cmd {
	fullArgs := append([]string{
		"ctr",
		"-a", state.ContainerdSocket,
		"-n", K8sContainerdNamespace,
	}, args...)
	return exec.CommandContext(ctx, k3sBinary, fullArgs...)
}
