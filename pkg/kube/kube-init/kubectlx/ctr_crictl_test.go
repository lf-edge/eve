// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// TestCtrCmd_Argv verifies that CtrCmd assembles the expected
// argv: the k3s multi-call binary path, the `ctr` subcommand,
// the user-containerd socket, and the k8s.io namespace — in
// that order — followed by whatever args the caller passed.
func TestCtrCmd_Argv(t *testing.T) {
	cmd := CtrCmd(context.Background(), "images", "import", "/images/foo.tar")

	if cmd.Path != k3sBinary {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, k3sBinary)
	}

	want := []string{
		k3sBinary,
		"ctr",
		"-a", state.ContainerdSocket,
		"-n", K8sContainerdNamespace,
		"images", "import", "/images/foo.tar",
	}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Errorf("cmd.Args = %v,\n           want %v", cmd.Args, want)
	}
}

// TestCtrCmd_EmptyArgs verifies the base invocation without any
// user args — useful e.g. for `ctr -a <socket> -n k8s.io --help`.
func TestCtrCmd_EmptyArgs(t *testing.T) {
	cmd := CtrCmd(context.Background())
	want := []string{
		k3sBinary,
		"ctr",
		"-a", state.ContainerdSocket,
		"-n", K8sContainerdNamespace,
	}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Errorf("cmd.Args = %v, want %v", cmd.Args, want)
	}
}

// TestCtrCmd_NamespaceIsK8sIO guards against an accidental change to
// the namespace constant — images imported into any namespace other
// than `k8s.io` are invisible to kubelet, so this is load-bearing.
func TestCtrCmd_NamespaceIsK8sIO(t *testing.T) {
	if K8sContainerdNamespace != "k8s.io" {
		t.Fatalf("K8sContainerdNamespace = %q, want %q (changing this will hide pre-imported images from kubelet)",
			K8sContainerdNamespace, "k8s.io")
	}
}

// TestCtrCmd_ContextCancelled verifies that the returned *exec.Cmd
// honours the context (so cancellation at the caller SIGKILLs ctr).
// We don't actually run ctr — just assert the Cmd carries the Ctx
// we supplied via CommandContext.
func TestCtrCmd_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := CtrCmd(ctx, "images", "list")
	cancel()
	// exec.Cmd doesn't expose ctx directly pre-1.20; use Cancel hook
	// to confirm context was attached. If Cancel is non-nil the Cmd
	// was built via CommandContext (what we want).
	if cmd.Cancel == nil {
		t.Errorf("CtrCmd did not attach a context-cancel hook; "+
			"must be built via exec.CommandContext so callers can cancel ctr on SIGTERM")
	}
}

// TestCrictlCmd_Argv is the crictl counterpart: no namespace flag
// (crictl talks to the CRI gRPC endpoint which is always scoped to
// k8s.io), but an explicit --runtime-endpoint pointing at the user
// containerd's unix socket.
func TestCrictlCmd_Argv(t *testing.T) {
	cmd := CrictlCmd(context.Background(), "inspecti", "docker.io/foo:bar")

	if cmd.Path != k3sBinary {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, k3sBinary)
	}

	want := []string{
		k3sBinary,
		"crictl",
		"--runtime-endpoint=unix://" + state.ContainerdSocket,
		"inspecti", "docker.io/foo:bar",
	}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Errorf("cmd.Args = %v,\n           want %v", cmd.Args, want)
	}
}

// TestCrictlCmd_EmptyArgs verifies the base invocation.
func TestCrictlCmd_EmptyArgs(t *testing.T) {
	cmd := CrictlCmd(context.Background())
	want := []string{
		k3sBinary,
		"crictl",
		"--runtime-endpoint=unix://" + state.ContainerdSocket,
	}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Errorf("cmd.Args = %v, want %v", cmd.Args, want)
	}
}

// TestCrictlCmd_ContextAttached mirrors the ctr test.
func TestCrictlCmd_ContextAttached(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := CrictlCmd(ctx, "pods")
	cancel()
	if cmd.Cancel == nil {
		t.Errorf("CrictlCmd did not attach a context-cancel hook")
	}
}
