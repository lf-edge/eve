// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
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

// longhornEngineImagesGVR is the Longhorn EngineImage CRD resource.
// The Longhorn Node CRD is shared via kubectlx.LonghornNodesGVR.
var longhornEngineImagesGVR = schema.GroupVersionResource{
	Group: "longhorn.io", Version: "v1beta2", Resource: "engineimages",
}

// LonghornIsReady reports whether Longhorn is fully operational on
// this node. Called periodically by the FSM's running-state monitor;
// self-heals by recreating a missing longhorn.io node object when
// it observes one.
//
// Returns (true, nil) when ready, (false, nil) when transiently not
// ready, (false, err) when the check itself failed.
func LonghornIsReady(ctx context.Context) (bool, error) {
	uninstalling, err := state.IsMarked(longhornUninstallGuard)
	if err != nil {
		return false, fmt.Errorf("check longhorn uninstall guard: %w", err)
	}
	if uninstalling {
		return false, nil
	}
	nkm, err := state.IsMarked(state.NativeKubernetesMode)
	if err != nil {
		return false, fmt.Errorf("check native-kubernetes-mode marker: %w", err)
	}
	if nkm {
		return true, nil
	}
	kc := kubeclient.Default()
	if _, err := kc.Clientset.CoreV1().Namespaces().
		Get(ctx, kubectlx.LonghornNamespace, metav1.GetOptions{}); err != nil {
		// Namespace probe failure: most often "not installed yet",
		// but could also be an API outage. Treat as "ready" (i.e.
		// "no Longhorn to wait for"); an API outage will surface
		// elsewhere.
		return true, nil
	}
	if !longhornDaemonSetsReady(ctx) {
		return false, nil
	}
	nodeName := readDeviceK8sName()
	if nodeName == "" {
		return false, nil
	}
	if _, err := kc.Dynamic.Resource(kubectlx.LonghornNodesGVR).Namespace(kubectlx.LonghornNamespace).
		Get(ctx, nodeName, metav1.GetOptions{}); err != nil {
		if !apierrors.IsNotFound(err) {
			// Anything other than NotFound (Forbidden, Unauthorized,
			// ServerTimeout, dial failure) is NOT "node missing" —
			// treating it as such loops the monitor firing spurious
			// Create attempts against an API that isn't misconfigured.
			log.Printf("warning: get longhorn node %s: %v", nodeName, err)
			return false, nil
		}
		log.Printf("longhorn node %s missing, creating", nodeName)
		if cErr := longhornNodeCreate(ctx, nodeName); cErr != nil {
			log.Printf("warning: create longhorn node %s: %v", nodeName, cErr)
		}
		return false, nil
	}
	sched, err := longhornNodeSchedulable(ctx, nodeName)
	if err != nil {
		log.Printf("warning: read longhorn node %s Schedulable: %v", nodeName, err)
		return false, nil
	}
	switch sched {
	case "True":
		if !longhornEngineDeployedOnNode(ctx, nodeName) {
			return false, nil
		}
	case "False":
		// Tie-breaker path: scheduling disabled, no engine expected.
	default:
		log.Printf("longhorn node %s: Schedulable=%q (expected True/False), not ready yet",
			nodeName, sched)
		return false, nil
	}
	longhornReadyOnce.Do(func() {
		log.Printf("Longhorn is ready on node %s", nodeName)
	})
	return true, nil
}

// longhornNodeSchedulable reads the Longhorn node's Schedulable
// condition status. Returns "True", "False", or the raw value
// (including empty string when the condition is not yet present).
func longhornNodeSchedulable(ctx context.Context, nodeName string) (string, error) {
	obj, err := kubeclient.Default().Dynamic.Resource(kubectlx.LonghornNodesGVR).
		Namespace(kubectlx.LonghornNamespace).Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	status, _ := obj.Object["status"].(map[string]any)
	conditions, _ := status["conditions"].([]any)
	for _, c := range conditions {
		cm, _ := c.(map[string]any)
		if t, _ := cm["type"].(string); t == "Schedulable" {
			s, _ := cm["status"].(string)
			return s, nil
		}
	}
	return "", nil
}

// longhornEngineDeployedOnNode reports whether every Longhorn engine
// image has nodeDeploymentMap[nodeName]==true. When it does not, it
// recycles the engine-image pod on this node plus a longhorn-manager
// pod on a different node so the controller re-reconciles state.
func longhornEngineDeployedOnNode(ctx context.Context, nodeName string) bool {
	list, err := kubeclient.Default().Dynamic.Resource(longhornEngineImagesGVR).
		Namespace(kubectlx.LonghornNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false
	}
	if len(list.Items) == 0 {
		log.Printf("no Longhorn engine images found")
		return false
	}
	for _, item := range list.Items {
		status, _ := item.Object["status"].(map[string]any)
		ndm, statusHasMap := status["nodeDeploymentMap"].(map[string]any)
		if !statusHasMap {
			// Fresh CR — longhorn-manager hasn't populated
			// status.nodeDeploymentMap yet. Not the same as "engine
			// not deployed on us" (which would justify a pod
			// recycle); it's "no data yet, come back next event".
			return false
		}
		deployed, keyPresent := ndm[nodeName].(bool)
		if !keyPresent {
			// This node's slot missing from the map — same
			// "reconciler hasn't seen us yet" state as above.
			// Do NOT recycle pods on this shape.
			return false
		}
		if !deployed {
			log.Printf("engine image not deployed on %s, recycling pods", nodeName)
			ndmBool := make(map[string]bool, len(ndm))
			for k, v := range ndm {
				b, _ := v.(bool)
				ndmBool[k] = b
			}
			deleteEngineAndManagerPods(ctx, nodeName, ndmBool)
			return false
		}
	}
	return true
}

// deleteEngineAndManagerPods recycles the engine-image pod on
// nodeName and one longhorn-manager pod on a peer node that owns
// the deployment map. Recycling forces a state refresh.
func deleteEngineAndManagerPods(ctx context.Context, nodeName string, ndm map[string]bool) {
	kc := kubeclient.Default()
	podClient := kc.Clientset.CoreV1().Pods(kubectlx.LonghornNamespace)

	// engine-image pods on this node.
	pods, err := podClient.List(ctx, metav1.ListOptions{
		LabelSelector: "longhorn.io/component=engine-image",
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		log.Printf("warning: list engine-image pods on %s: %v", nodeName, err)
	} else {
		for _, p := range pods.Items {
			if p.Status.Phase != corev1.PodRunning {
				continue
			}
			log.Printf("deleting engine pod %s on %s", p.Name, nodeName)
			if err := podClient.Delete(ctx, p.Name, metav1.DeleteOptions{}); err != nil {
				log.Printf("warning: delete engine pod %s: %v", p.Name, err)
			}
		}
	}

	// A peer longhorn-manager pod (any node that has deployed=true
	// and is not us) — one delete is enough to refresh state.
	for owner, deployed := range ndm {
		if !deployed || owner == nodeName {
			continue
		}
		mgrPods, err := podClient.List(ctx, metav1.ListOptions{
			LabelSelector: "app=longhorn-manager",
			FieldSelector: "spec.nodeName=" + owner,
		})
		if err != nil {
			log.Printf("warning: list longhorn-manager pods on %s: %v", owner, err)
			return
		}
		for _, p := range mgrPods.Items {
			log.Printf("deleting longhorn-manager pod %s on %s", p.Name, owner)
			if err := podClient.Delete(ctx, p.Name, metav1.DeleteOptions{}); err != nil {
				log.Printf("warning: delete manager pod %s: %v", p.Name, err)
			}
		}
		return
	}
}

// LonghornPostInstallConfig copies the runtime Longhorn config
// into the k3s auto-deploy dir. Idempotent.
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
	kc := kubeclient.Default()
	pods, err := kc.Clientset.CoreV1().Pods(kubectlx.LonghornNamespace).List(ctx,
		metav1.ListOptions{
			LabelSelector: "app=longhorn-csi-plugin",
			FieldSelector: "status.phase=Running",
		})
	if err != nil {
		log.Printf("warning: list longhorn-csi-plugin pods: %v", err)
		return
	}

	const markerPath = "/usr/local/sbin/nsmounter.updated"
	const nsmounterSrc = "/usr/bin/nsmounter"

	for _, p := range pods.Items {
		if err := podExec(ctx, p.Name, kubectlx.LonghornNamespace, "longhorn-csi-plugin",
			[]string{"test", "-f", markerPath}, nil); err == nil {
			continue
		}
		log.Printf("patching nsmounter in pod %s", p.Name)
		data, readErr := os.ReadFile(nsmounterSrc)
		if readErr != nil {
			log.Printf("warning: read nsmounter binary: %v", readErr)
			return
		}
		if err := podExec(ctx, p.Name, kubectlx.LonghornNamespace, "longhorn-csi-plugin",
			[]string{"install", "-m", "0755", "/dev/stdin", "/usr/local/sbin/nsmounter"},
			bytes.NewReader(data)); err != nil {
			log.Printf("warning: install nsmounter into %s: %v", p.Name, err)
			continue
		}
		if err := podExec(ctx, p.Name, kubectlx.LonghornNamespace, "longhorn-csi-plugin",
			[]string{"touch", markerPath}, nil); err != nil {
			log.Printf("warning: touch nsmounter marker in %s: %v", p.Name, err)
		}
	}
}

// podExec runs command inside container of pod in namespace via the
// k8s exec subresource. stdout+stderr are always captured and, if the
// command fails, folded into the returned error so callers get the
// diagnostic without threading buffers through the callsite.
// NotFound on the pod surfaces as-is so callers can distinguish
// "pod gone" from "command failed inside pod".
func podExec(
	ctx context.Context, podName, namespace, container string,
	command []string, stdin io.Reader,
) error {
	kc := kubeclient.Default()
	req := kc.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(podName).Namespace(namespace).
		SubResource("exec")
	opts := &corev1.PodExecOptions{
		Container: container,
		Command:   command,
		Stdin:     stdin != nil,
		Stdout:    true,
		Stderr:    true,
	}
	req.VersionedParams(opts, scheme.ParameterCodec)

	execURL, err := url.Parse(req.URL().String())
	if err != nil {
		return fmt.Errorf("build exec URL: %w", err)
	}
	exec, err := remotecommand.NewSPDYExecutor(kc.Config, "POST", execURL)
	if err != nil {
		return fmt.Errorf("build SPDY executor: %w", err)
	}
	var stdout, stderr bytes.Buffer
	streamOpts := remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}
	if stdin != nil {
		streamOpts.Stdin = stdin
	}
	if err := exec.StreamWithContext(ctx, streamOpts); err != nil {
		if apierrors.IsNotFound(err) {
			return err
		}
		return fmt.Errorf("exec %s -c %s: %w (stdout=%q stderr=%q)",
			podName, container, err,
			strings.TrimSpace(stdout.String()),
			strings.TrimSpace(stderr.String()))
	}
	return nil
}
