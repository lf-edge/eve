// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

// Inputs of ReconcileNvidiaGPU. var so tests can redirect.
//
//   - NvidiaPlatformFile is written by pkg/nvidia for the platform it was
//     built for (nvidia-jp5, nvidia-jp6, nvidia-jp7, nvidia-gb, ai-generic). Its absence
//     means the image has no NVIDIA userland.
//   - NvidiaModuleDir exists while nvidia.ko is loaded.
//   - NvidiaCDISpecDirs are where containerd looks for CDI specs: Jetson
//     ships a static one in /etc/cdi, nv-init.sh generates the discrete-GPU
//     one in /run/cdi once NVML answers.
var (
	NvidiaPlatformFile = "/opt/vendor/nvidia/eve-platform"
	NvidiaModuleDir    = "/sys/module/nvidia"
	NvidiaCDISpecDirs  = []string{"/etc/cdi", "/run/cdi"}
	nvidiaManifestsSrc = manifestsSrc
)

// NvidiaGPUNodeLabel marks a node whose NVIDIA GPU is usable. The device
// plugin DaemonSet pkg/kube ships selects on it with the value "true".
const NvidiaGPUNodeLabel = "eve.lfedge.org/nvidia-gpu"

// nvidiaPluginManifestName is the device plugin manifest pkg/kube ships for
// every NVIDIA platform, and its name in the auto-deploy dir.
const nvidiaPluginManifestName = "nvidia-device-plugin.yml"

// nvidiaLegacyManifestGlob matches the versioned names older EVE versions
// staged the manifest under.
const nvidiaLegacyManifestGlob = "nvidia-device-plugin-*.yml"

// nvidiaCDIKind is the CDI kind NVIDIA's GPU specs declare.
const nvidiaCDIKind = "nvidia.com/gpu"

// Read and write NvidiaGPUNodeLabel on this node. var so tests run without
// an API server.
var (
	nvidiaGetNodeLabel = getOwnNodeNvidiaLabel
	nvidiaSetNodeLabel = setOwnNodeNvidiaLabel
)

// nvidiaAPICallBudget bounds each node Get and Patch the reconcile makes.
// client-go applies no client-side deadline, kube-init leaves
// rest.Config.Timeout unset (see apiCallBudget in k3s/readiness.go), and
// the health worker's context has no deadline either. Without a per-call
// bound a hung apiserver would park the serial health worker on this
// call, and every later tick behind it. var so tests can shorten it.
var nvidiaAPICallBudget = 10 * time.Second

// nvidiaLabelCleared latches once an image without an NVIDIA userland has
// confirmed the label is absent, so the tick costs nothing there afterwards.
var nvidiaLabelCleared bool

// ReconcileNvidiaGPU deploys the NVIDIA device plugin to the nodes that can
// run it. On an image with an NVIDIA userland it stages the plugin manifest;
// the DaemonSet selects nodes labelled
// NvidiaGPUNodeLabel=true, and each node labels only itself, while nvidia.ko
// is loaded and an NVIDIA CDI spec exists. Elsewhere the plugin pod could not
// start, and a kube-system pod that never becomes Ready holds kube-init's
// readiness wait.
//
// Same shape as ReconcileSRIOVManifests: idempotent, called on every
// steady-state tick. Running every tick is what lets a GPU or driver that
// comes up late, or a manifest shipped by an EVE update, take effect.
func ReconcileNvidiaGPU(ctx context.Context) error {
	return reconcileNvidiaGPU(ctx, manifestsDst)
}

// reconcileNvidiaGPU is the path-parameterised core of ReconcileNvidiaGPU.
func reconcileNvidiaGPU(ctx context.Context, manifestsDstDir string) error {
	_, err := os.ReadFile(NvidiaPlatformFile)
	if errors.Is(err, os.ErrNotExist) {
		return clearStaleNvidiaLabel(ctx)
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", NvidiaPlatformFile, err)
	}
	if err := stageNvidiaPluginManifest(filepath.Join(nvidiaManifestsSrc, nvidiaPluginManifestName), manifestsDstDir); err != nil {
		return err
	}
	usable, err := nvidiaGPUUsable()
	if err != nil {
		return err
	}
	return reconcileNvidiaNodeLabel(ctx, usable)
}

// clearStaleNvidiaLabel drops a label left by an earlier image with an
// NVIDIA userland. The manifest it staged stays on /persist and keeps the
// DaemonSet, which schedules nothing without the label.
func clearStaleNvidiaLabel(ctx context.Context) error {
	if nvidiaLabelCleared {
		return nil
	}
	if err := reconcileNvidiaNodeLabel(ctx, false); err != nil {
		return err
	}
	nvidiaLabelCleared = true
	return nil
}

func stageNvidiaPluginManifest(src, manifestsDstDir string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if _, err := os.Stat(manifestsDstDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Owned by the k3s server; the next tick retries.
			return nil
		}
		return fmt.Errorf("stat %s: %w", manifestsDstDir, err)
	}
	dst := filepath.Join(manifestsDstDir, nvidiaPluginManifestName)
	if err := copyIfChanged(dst, data, 0o644); err != nil {
		return fmt.Errorf("copy NVIDIA device plugin manifest: %w", err)
	}
	return removeLegacyNvidiaManifests(manifestsDstDir)
}

// removeLegacyNvidiaManifests drops manifests staged under a versioned name.
// They declare the same DaemonSet, so k3s would keep re-applying the stale
// one over the current one.
func removeLegacyNvidiaManifests(manifestsDstDir string) error {
	legacy, err := filepath.Glob(filepath.Join(manifestsDstDir, nvidiaLegacyManifestGlob))
	if err != nil {
		return fmt.Errorf("glob legacy NVIDIA manifests: %w", err)
	}
	for _, f := range legacy {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove legacy NVIDIA manifest: %w", err)
		}
		log.Printf("removed legacy NVIDIA manifest %s", f)
	}
	return nil
}

// nvidiaGPUUsable reports whether nvidia.ko is loaded and an NVIDIA CDI spec
// exists. That holds for integrated GPUs and discrete ones alike, whatever
// bus they sit on.
func nvidiaGPUUsable() (bool, error) {
	if _, err := os.Stat(NvidiaModuleDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", NvidiaModuleDir, err)
	}
	return nvidiaCDISpecPresent()
}

// nvidiaCDISpecPresent reports whether any spec in NvidiaCDISpecDirs declares
// the NVIDIA GPU kind. A missing dir holds no spec; any other failure to read
// one is an error, so a transient failure never takes the label away.
func nvidiaCDISpecPresent() (bool, error) {
	for _, dir := range NvidiaCDISpecDirs {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("list %s: %w", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return false, fmt.Errorf("read %s: %w", filepath.Join(dir, e.Name()), err)
			}
			if bytes.Contains(data, []byte(nvidiaCDIKind)) {
				return true, nil
			}
		}
	}
	return false, nil
}

func reconcileNvidiaNodeLabel(ctx context.Context, want bool) error {
	value, has, err := nvidiaGetNodeLabel(ctx)
	if err != nil {
		return fmt.Errorf("read node label %s: %w", NvidiaGPUNodeLabel, err)
	}
	if want == has && (!want || value == "true") {
		return nil
	}
	if err := nvidiaSetNodeLabel(ctx, want); err != nil {
		return fmt.Errorf("set node label %s=%v: %w", NvidiaGPUNodeLabel, want, err)
	}
	if want {
		log.Printf("labelled node %s=true: nvidia module loaded and NVIDIA CDI spec present", NvidiaGPUNodeLabel)
	} else {
		log.Printf("removed node label %s: no usable NVIDIA GPU", NvidiaGPUNodeLabel)
	}
	return nil
}

func ownNode() (typedcorev1.NodeInterface, string, error) {
	if !kubeclient.HasDefault() {
		return nil, "", errors.New("kube client not initialised yet")
	}
	name := readDeviceK8sName()
	if name == "" {
		return nil, "", errors.New("device name not yet available")
	}
	return kubeclient.Default().Clientset.CoreV1().Nodes(), name, nil
}

func getOwnNodeNvidiaLabel(ctx context.Context) (string, bool, error) {
	nodes, name, err := ownNode()
	if err != nil {
		return "", false, err
	}
	return getNodeNvidiaLabel(ctx, nodes, name)
}

func getNodeNvidiaLabel(ctx context.Context, nodes typedcorev1.NodeInterface,
	name string) (string, bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, nvidiaAPICallBudget)
	defer cancel()
	n, err := nodes.Get(callCtx, name, metav1.GetOptions{})
	if err != nil {
		return "", false, fmt.Errorf("get node %s: %w", name, err)
	}
	value, has := n.Labels[NvidiaGPUNodeLabel]
	return value, has, nil
}

func setOwnNodeNvidiaLabel(ctx context.Context, on bool) error {
	nodes, name, err := ownNode()
	if err != nil {
		return err
	}
	return patchNodeNvidiaLabel(ctx, nodes, name, on)
}

// patchNodeNvidiaLabel sets the label to "true", or removes it: a null
// value in a JSON merge patch deletes the key.
func patchNodeNvidiaLabel(ctx context.Context, nodes typedcorev1.NodeInterface,
	name string, on bool) error {
	var value any
	if on {
		value = "true"
	}
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"labels": map[string]any{NvidiaGPUNodeLabel: value},
		},
	})
	if err != nil {
		return fmt.Errorf("build label patch: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, nvidiaAPICallBudget)
	defer cancel()
	if _, err := nodes.Patch(callCtx, name, types.MergePatchType, patch,
		metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch node %s: %w", name, err)
	}
	return nil
}
