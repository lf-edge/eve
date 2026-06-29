// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// Readiness-wait cadences. Vars so tests can shrink them.
var (
	kubeconfigPollInterval = 5 * time.Second
	nodeReadyPollInterval  = 5 * time.Second
	podReadyPollInterval   = 10 * time.Second
)

// WaitReady blocks until k3s is fully operational: kubeconfig
// appeared + copied, the local node reports Ready, the node-uuid
// label is applied, and every pod in kube-system is Ready.
//
// The supplied timeout bounds the whole sequence (a fresh
// context.WithTimeout is derived from ctx and consumed inside).
//
// Step 4 (label node) is non-fatal — a label-application failure
// only matters for cross-node addressing in HA clusters and the FSM
// can retry later.
func WaitReady(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := WaitKubeconfig(ctx); err != nil {
		return fmt.Errorf("wait kubeconfig: %w", err)
	}

	info, ok := edgenodeinfo.Get()
	if !ok {
		return fmt.Errorf("EdgeNodeInfo not yet published; subscription has not delivered")
	}
	if info.DeviceName == "" {
		return fmt.Errorf("EdgeNodeInfo.DeviceName is empty (corrupted payload)")
	}
	uuid := info.DeviceID.String()
	if uuid == "" {
		return fmt.Errorf("EdgeNodeInfo.DeviceID is empty (corrupted payload)")
	}
	nodeName := state.ToK8sName(info.DeviceName)

	if err := waitNodeReady(ctx, nodeName); err != nil {
		return fmt.Errorf("wait node ready: %w", err)
	}

	if err := labelNodeUUID(nodeName, uuid); err != nil {
		log.Printf("warning: failed to label node %s with uuid: %v", nodeName, err)
	}

	if err := waitSystemPodsReady(ctx); err != nil {
		return fmt.Errorf("wait system pods ready: %w", err)
	}
	log.Printf("k3s is fully ready")
	return nil
}

// WaitKubeconfig polls state.K3sKubeconfig until it appears, then
// copies it to KubeconfigCopy. The poll honours ctx — the caller is
// expected to bound the wait via context.WithTimeout.
func WaitKubeconfig(ctx context.Context) error {
	log.Printf("waiting for kubeconfig at %s", state.K3sKubeconfig)

	ticker := time.NewTicker(kubeconfigPollInterval)
	defer ticker.Stop()
	for {
		present, err := fileExists(state.K3sKubeconfig)
		if err != nil {
			return fmt.Errorf("stat %s: %w", state.K3sKubeconfig, err)
		}
		if present {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s: %w",
				state.K3sKubeconfig, ctx.Err())
		case <-ticker.C:
		}
	}

	if err := copyKubeconfig(); err != nil {
		return fmt.Errorf("copy kubeconfig: %w", err)
	}
	log.Printf("kubeconfig ready and copied to %s", KubeconfigCopy)
	return nil
}

// fileExists is the cousin of os.Stat that distinguishes
// "definitely absent" (false, nil) from "we cannot tell" (false,
// err) — silently treating EACCES/EIO as "absent" hides the
// underlying breakage from the FSM.
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// copyKubeconfig atomically copies state.K3sKubeconfig to
// KubeconfigCopy, ensuring the destination directory exists.
func copyKubeconfig() error {
	if err := os.MkdirAll(KubeconfigCopyDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", KubeconfigCopyDir, err)
	}
	data, err := os.ReadFile(state.K3sKubeconfig)
	if err != nil {
		return fmt.Errorf("read %s: %w", state.K3sKubeconfig, err)
	}
	if err := state.AtomicWriteFile(KubeconfigCopy, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", KubeconfigCopy, err)
	}
	return nil
}

// waitNodeReady polls `kubectl get node/<name>` until the node
// shows Ready status.
func waitNodeReady(ctx context.Context, nodeName string) error {
	log.Printf("waiting for node %s to be Ready", nodeName)

	ticker := time.NewTicker(nodeReadyPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for node %s to be Ready: %w",
				nodeName, ctx.Err())
		case <-ticker.C:
		}
		out, err := kubectlx.Run("get", "node/"+nodeName, "--no-headers")
		if err != nil {
			// kubectl returns non-zero while the API is starting up
			// or while the node hasn't registered yet — keep polling.
			continue
		}
		if nodeIsReady(out, nodeName) {
			log.Printf("node %s is Ready", nodeName)
			return nil
		}
	}
}

// nodeIsReady parses `kubectl get node/X --no-headers` output and
// reports whether the named node is in Ready status.
//
// Output line shape:
//
//	mynode   Ready    control-plane,master   5m   v1.34.2+k3s1
//	mynode   NotReady control-plane,master   1s   v1.34.2+k3s1
//
// Scans every line and matches on both the nodeName column and the
// status column — never on the status column alone, because a
// multi-row response with the wrong node first would false-positive.
func nodeIsReady(kubectlOutput, nodeName string) bool {
	scanner := bufio.NewScanner(strings.NewReader(kubectlOutput))
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) >= 2 && f[0] == nodeName && f[1] == "Ready" {
			return true
		}
	}
	return false
}

// labelNodeUUID applies the `node-uuid=<uuid>` label to nodeName,
// overwriting any prior value.
func labelNodeUUID(nodeName, uuid string) error {
	label := fmt.Sprintf("node-uuid=%s", uuid)
	out, err := kubectlx.Run("label", "node", nodeName, label, "--overwrite")
	if err != nil {
		return fmt.Errorf("kubectl label: %w (output: %s)", err, out)
	}
	log.Printf("labelled node %s with node-uuid=%s", nodeName, uuid)
	return nil
}

// waitSystemPodsReady blocks until every pod in kube-system reports
// Ready or has finished (Completed/Succeeded). Progress is logged
// every time the ready/total count changes, including the list of
// pods we are still waiting on.
func waitSystemPodsReady(ctx context.Context) error {
	log.Printf("waiting for all system pods to be Ready")
	ticker := time.NewTicker(podReadyPollInterval)
	defer ticker.Stop()

	var lastReady, lastTotal int
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for system pods: %w", ctx.Err())
		case <-ticker.C:
		}
		ready, total, notReady := countSystemPods()
		if total == 0 {
			continue
		}
		if ready != lastReady || total != lastTotal {
			if len(notReady) > 0 {
				log.Printf("system pods: [%d/%d] ready, waiting on: %s",
					ready, total, strings.Join(notReady, ", "))
			}
			lastReady, lastTotal = ready, total
		}
		if ready == total {
			log.Printf("all system pods are Ready [%d/%d]", ready, total)
			return nil
		}
	}
}

// countSystemPods queries `kubectl -n kube-system get pods` and
// returns (readyCount, totalCount, notReadyDescriptions). Errors
// and empty output collapse to (0, 0, nil) — they may be transient
// during api-server startup; the caller is expected to keep polling.
func countSystemPods() (int, int, []string) {
	out, err := kubectlx.Run("-n", "kube-system", "get", "pods", "--no-headers")
	if err != nil || strings.TrimSpace(out) == "" {
		return 0, 0, nil
	}
	return parseSystemPodsOutput(out)
}

// parseSystemPodsOutput is the pure-string half of countSystemPods,
// factored out so tests can drive it with canned kubectl outputs.
//
// Each input line is `NAME READY STATUS RESTARTS AGE`. A pod counts
// as ready when:
//   - STATUS is Completed or Succeeded (finished Job pods), OR
//   - the READY column shows all containers ready (e.g. "1/1") AND
//     is not "0/N".
//
// Not-ready descriptions include the status in parentheses so
// operator output identifies the failure mode at a glance.
func parseSystemPodsOutput(out string) (int, int, []string) {
	var ready, total int
	var notReady []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		total++
		status := fields[2]
		if status == "Completed" || status == "Succeeded" {
			ready++
			continue
		}
		parts := strings.SplitN(fields[1], "/", 2)
		if len(parts) == 2 && parts[0] == parts[1] && parts[0] != "0" {
			ready++
		} else {
			notReady = append(notReady, fields[0]+"("+status+")")
		}
	}
	return ready, total, notReady
}
