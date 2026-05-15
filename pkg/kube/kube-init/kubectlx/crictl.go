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

// CrictlRun invokes `k3s crictl --runtime-endpoint=unix://<socket>
// <args...>` and returns the trimmed combined output. Unlike ctr,
// crictl speaks the CRI gRPC surface — so its view of images and
// containers is always scoped to the kubelet's containerd namespace,
// and no `-n` flag is passed.
func CrictlRun(args ...string) (string, error) {
	return CrictlRunContext(context.Background(), args...)
}

// CrictlRunContext is the cancellable form of CrictlRun.
func CrictlRunContext(ctx context.Context, args ...string) (string, error) {
	cmd := CrictlCmd(ctx, args...)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		return outStr, fmt.Errorf("crictl %s: %w (output: %s)",
			strings.Join(args, " "), err, outStr)
	}
	return outStr, nil
}

// CrictlCmd returns an *exec.Cmd for the standard crictl invocation
// with the user-containerd's CRI endpoint wired up. Callers provide
// the subcommand args (e.g. "inspecti", "docker.io/foo:bar").
func CrictlCmd(ctx context.Context, args ...string) *exec.Cmd {
	fullArgs := append([]string{
		"crictl",
		"--runtime-endpoint=unix://" + state.ContainerdSocket,
	}, args...)
	return exec.CommandContext(ctx, k3sBinary, fullArgs...)
}
