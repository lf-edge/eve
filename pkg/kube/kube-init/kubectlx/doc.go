// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kubectlx wraps the k3s multi-call binary for the subcommands
// kube-init uses:
//
//   - kubectl (Run, Cmd, CmdContext — exec.go) — goes via
//     `k3s kubectl <args>` with KUBECONFIG wired in.
//   - ctr (CtrRun, CtrCmd — ctr.go) — goes via
//     `k3s ctr -a <user-containerd-socket> -n k8s.io <args>`.
//     The k8s.io namespace is load-bearing: images imported into
//     any other namespace are invisible to kubelet.
//   - crictl (CrictlRun, CrictlCmd — crictl.go) — goes via
//     `k3s crictl --runtime-endpoint=unix://<socket> <args>`.
//
// The package also provides typed kubectl primitives for apply/create
// with classified backoff (apply.go) and readiness waits (wait.go).
// The typed waits exist so callers do not have to treat a successful
// `kubectl apply` as proof that the resource is ready to use: `kubectl
// apply` returns once the API server has persisted the object;
// downstream callers can still race the CRD's discovery cache, an
// operator's reconciler, or an admission webhook's readiness. Pair
// every apply with the appropriate wait when ordering matters.
//
// Having one place that assembles the `/usr/bin/k3s …` prefix also
// means the binary path, the containerd socket path, and the k8s.io
// namespace string are each hard-coded exactly once per subcommand
// family — not copy-pasted across every call site.
package kubectlx
