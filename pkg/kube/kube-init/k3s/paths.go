// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

// On-disk paths owned by this package. Declared as `var` rather than
// `const` so unit tests can redirect them onto temp dirs via
// t.Cleanup. Production callers MUST treat these as constants.

// K3sConfigDir is the k3s config drop-in directory. k3s reads every
// *.yaml in this directory in lexical order at startup, merging them.
var K3sConfigDir = "/etc/rancher/k3s/config.yaml.d"

// UserOverrideSrc is the controller-delivered config override
// payload, persisted to the vault by the user-config pubsub pipeline
// and consumed by ApplyUserOverrides.
var UserOverrideSrc = "/persist/vault/k3s-user-override.yaml"

// EncStatusFile is the pubsub-published EdgeNodeClusterStatus JSON
// written by zedkube when the device is part of an HA cluster.
// Lives under /run because the publication is not Persistent —
// /persist/status/zedkube/EdgeNodeClusterStatus/ never appears.
var EncStatusFile = "/run/zedkube/EdgeNodeClusterStatus/global.json"

// ClusterConfigFile is the controller-delivered EdgeNodeClusterConfig
// JSON. zedagent publishes it under /run; the Persistent mirror
// under /persist/status/zedagent/ is NOT written, so reading from
// /persist would stall the daemon waiting for a file that never
// appears.
var ClusterConfigFile = "/run/zedagent/EdgeNodeClusterConfig/global.json"

// EdgeNodeInfoPath holds the EdgeNodeInfo status (DeviceName, etc.)
// kube-init reads at config time to derive the Kubernetes node
// name. Same caveat as ClusterConfigFile: live in /run only, no
// /persist mirror.
var EdgeNodeInfoPath = "/run/zedagent/EdgeNodeInfo/global.json"

// clusterWaitFile is a sentinel placed at /run while we are blocked
// waiting for the bootstrap server.
var clusterWaitFile = "/run/kube/cluster-change-wait-ongoing"

// multusLinkSource is the path to the multus CNI binary on the host
// rootfs that gets symlinked into the k3s data directory.
var multusLinkSource = "/var/lib/cni/bin/multus"

// installLogPath is where `k3s check-config` stdout/stderr is
// appended on every install/re-install. /persist so the log survives
// reboots.
var installLogPath = "/persist/kubelog/k3s-install.log"

// supervisorLogFile is where the Supervisor appends k3s server
// stdout/stderr.
var supervisorLogFile = "/persist/kubelog/k3s.log"

// supervisorHooksDir holds executable pre-restart hooks the
// Supervisor runs when invoked by the FSM (not on crash recovery).
var supervisorHooksDir = "/etc/k3s-supervisor/hooks.d"

// supervisorPidFile is where the Supervisor records the current
// k3s process PID for external readers.
var supervisorPidFile = "/run/k3s.pid"

// procRoot is /proc, parameterised so tests can route the descendant
// and port-binding scans onto a fixture tree.
var procRoot = "/proc"
