// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// longhornUninstallGuard signals an uninstall is in flight. Sits on
// /tmp because it is per-boot state; once cleared, the next steady
// tick reverts to ordinary readiness reporting.
const longhornUninstallGuard state.Marker = "/tmp/replicated-storage-uninstall-inprogress"

// longhornCfgFilename is the auto-deploy filename for the
// runtime-side Longhorn configuration the operator drops.
const longhornCfgFilename = "longhorn-cfg.yaml"

// longhornReadyOnce throttles the "Longhorn is ready" log line to
// once per process lifetime so steady-state log noise doesn't fill
// /persist with the same line every tick.
var longhornReadyOnce sync.Once

// LonghornIsReady reports whether Longhorn is fully operational on
// this node. Called periodically by the FSM's running-state monitor;
// self-heals by recreating a missing longhorn.io node object when
// it observes one.
//
// Returns (true, nil) for three "nothing to report" cases that
// callers treat as "Longhorn is up to date":
//   - the node is in base-k3s mode (no Longhorn at all).
//   - longhorn-system namespace is absent (not installed yet).
//
// Returns (false, nil) when Longhorn is genuinely not ready (or an
// uninstall is in flight).
//
// Returns (false, err) when we cannot tell — marker-read failure,
// etc. Callers should treat a non-nil error as "do not act on the
// bool, retry the check next tick".
func LonghornIsReady(ctx context.Context) (bool, error) {
	uninstalling, err := state.IsMarked(longhornUninstallGuard)
	if err != nil {
		return false, fmt.Errorf("check longhorn uninstall guard: %w", err)
	}
	if uninstalling {
		return false, nil
	}
	baseMode, err := state.IsMarked(state.BaseK3sMode)
	if err != nil {
		return false, fmt.Errorf("check base-k3s marker: %w", err)
	}
	if baseMode {
		return true, nil
	}
	if _, err := kubectl("get", "namespace/longhorn-system"); err != nil {
		// Namespace probe failure: most often "not installed yet",
		// but could also be an API outage. Treat as "ready" (i.e.
		// "no Longhorn to wait for") to match the previous shell
		// flow; an API outage will surface elsewhere.
		return true, nil
	}
	if !longhornDaemonSetsReady() {
		return false, nil
	}
	nodeName := readDeviceK8sName()
	if nodeName == "" {
		return false, nil
	}
	if _, err := kubectl("get", "nodes.longhorn.io", nodeName,
		"-n", longhornNamespace); err != nil {
		log.Printf("longhorn node %s missing, creating", nodeName)
		if cErr := longhornNodeCreate(nodeName); cErr != nil {
			log.Printf("warning: create longhorn node %s: %v", nodeName, cErr)
		}
		return false, nil
	}
	if !longhornEngineDeployedOnNode(ctx, nodeName) {
		return false, nil
	}
	longhornReadyOnce.Do(func() {
		log.Printf("Longhorn is ready on node %s", nodeName)
	})
	return true, nil
}

// engineImageList captures just the fields longhornEngineDeployedOnNode
// needs from `kubectl get engineimage -o json`.
type engineImageList struct {
	Items []struct {
		Status struct {
			NodeDeploymentMap map[string]bool `json:"nodeDeploymentMap"`
		} `json:"status"`
	} `json:"items"`
}

// longhornEngineDeployedOnNode reports whether every Longhorn engine
// image has nodeDeploymentMap[nodeName]==true. When it does not, it
// recycles the engine-image pod on this node plus a longhorn-manager
// pod on a different node so the controller re-reconciles state.
func longhornEngineDeployedOnNode(ctx context.Context, nodeName string) bool {
	out, err := kubectl("get", "engineimage", "-n", longhornNamespace, "-o", "json")
	if err != nil {
		return false
	}
	var result engineImageList
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		log.Printf("warning: parse engineimage list: %v", err)
		return false
	}
	if len(result.Items) == 0 {
		log.Printf("no Longhorn engine images found")
		return false
	}
	for _, item := range result.Items {
		deployed, ok := item.Status.NodeDeploymentMap[nodeName]
		if !ok || !deployed {
			log.Printf("engine image not deployed on %s, recycling pods", nodeName)
			deleteEngineAndManagerPods(ctx, nodeName, item.Status.NodeDeploymentMap)
			return false
		}
	}
	return true
}

// deleteEngineAndManagerPods recycles the engine-image pod on
// nodeName and one longhorn-manager pod on a peer node that owns
// the deployment map. Recycling forces a state refresh.
//
// Delete failures are logged (a silent failure would loop the
// caller forever calling this function without making progress).
func deleteEngineAndManagerPods(ctx context.Context, nodeName string, ndm map[string]bool) {
	out, err := kubectl("get", "pods", "-n", longhornNamespace,
		"--field-selector", "spec.nodeName="+nodeName,
		"-l", "longhorn.io/component=engine-image",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		log.Printf("warning: list engine-image pods on %s: %v", nodeName, err)
	} else {
		for _, pod := range strings.Fields(strings.TrimSpace(out)) {
			phase, pErr := kubectl("get", "pod", pod, "-n", longhornNamespace,
				"-o", "jsonpath={.status.phase}")
			if pErr != nil {
				log.Printf("warning: get pod %s phase: %v", pod, pErr)
				continue
			}
			if strings.TrimSpace(phase) != "Running" {
				continue
			}
			log.Printf("deleting engine pod %s on %s", pod, nodeName)
			if _, dErr := kubectl("delete", "pod", pod,
				"-n", longhornNamespace); dErr != nil {
				log.Printf("warning: delete engine pod %s: %v", pod, dErr)
			}
		}
	}

	// A peer longhorn-manager pod (any node that has deployed=true
	// and is not us) — one delete is enough to refresh state.
	for owner, deployed := range ndm {
		if !deployed || owner == nodeName {
			continue
		}
		mgrOut, mErr := kubectl("get", "pods", "-n", longhornNamespace,
			"--field-selector", "spec.nodeName="+owner,
			"-l", "app=longhorn-manager",
			"-o", "jsonpath={.items[*].metadata.name}")
		if mErr != nil {
			log.Printf("warning: list longhorn-manager pods on %s: %v", owner, mErr)
			return
		}
		for _, pod := range strings.Fields(strings.TrimSpace(mgrOut)) {
			log.Printf("deleting longhorn-manager pod %s on %s", pod, owner)
			if _, dErr := kubectl("delete", "pod", pod,
				"-n", longhornNamespace); dErr != nil {
				log.Printf("warning: delete manager pod %s: %v", pod, dErr)
			}
		}
		return
	}
}

// LonghornPostInstallConfig copies the runtime Longhorn config
// into the k3s auto-deploy dir. Idempotent: writes a marker after
// the copy and short-circuits when the marker is already present.
//
// Returns an error rather than logging-and-swallowing so callers
// can decide whether to retry on the next tick or surface the
// problem to the FSM.
func LonghornPostInstallConfig() error {
	src := "/etc/" + longhornCfgFilename
	dst := filepath.Join(manifestsDst, longhornCfgFilename)
	marker := state.Marker(dst)
	marked, err := state.IsMarked(marker)
	if err != nil {
		return fmt.Errorf("check longhorn post-install marker: %w", err)
	}
	if marked {
		return nil
	}
	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("copy longhorn post-install config: %w", err)
	}
	return nil
}

// LonghornPostInstallConfigClean removes the runtime Longhorn
// config from the auto-deploy dir.
func LonghornPostInstallConfigClean() {
	dst := filepath.Join(manifestsDst, longhornCfgFilename)
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("warning: remove longhorn config from manifests: %v", err)
	}
}

// CheckOverwriteNsmounter works around longhorn/longhorn#6857 by
// copying a fixed nsmounter binary into every running
// longhorn-csi-plugin pod that has not yet been patched. A marker
// file inside the pod marks completion so re-runs are no-ops.
func CheckOverwriteNsmounter(ctx context.Context) {
	out, err := kubectl("get", "pods", "-n", longhornNamespace,
		"-l", "app=longhorn-csi-plugin",
		"--field-selector", "status.phase=Running",
		"-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		log.Printf("warning: list longhorn-csi-plugin pods: %v", err)
		return
	}

	const markerPath = "/usr/local/sbin/nsmounter.updated"
	const nsmounterSrc = "/usr/bin/nsmounter"

	for _, pod := range strings.Fields(strings.TrimSpace(out)) {
		if _, err := kubectl("exec", pod, "-n", longhornNamespace,
			"-c", "longhorn-csi-plugin", "--",
			"test", "-f", markerPath); err == nil {
			continue
		}
		log.Printf("patching nsmounter in pod %s", pod)
		data, readErr := os.ReadFile(nsmounterSrc)
		if readErr != nil {
			log.Printf("warning: read nsmounter binary: %v", readErr)
			return
		}
		cpCmd := "cat > /usr/local/sbin/nsmounter && chmod +x /usr/local/sbin/nsmounter"
		cmd := kubectlx.Cmd("exec", "-i", pod, "-n", longhornNamespace,
			"-c", "longhorn-csi-plugin", "--",
			"sh", "-c", cpCmd)
		cmd.Stdin = strings.NewReader(string(data))
		if cpOut, cpErr := cmd.CombinedOutput(); cpErr != nil {
			log.Printf("warning: copy nsmounter into %s: %v (%s)",
				pod, cpErr, strings.TrimSpace(string(cpOut)))
			continue
		}
		if _, touchErr := kubectl("exec", pod, "-n", longhornNamespace,
			"-c", "longhorn-csi-plugin", "--",
			"touch", markerPath); touchErr != nil {
			log.Printf("warning: touch nsmounter marker in %s: %v", pod, touchErr)
		}
	}
}
