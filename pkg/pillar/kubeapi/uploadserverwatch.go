// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// uploadServerMaxRestarts is how many times the CDI upload server may restart
// during one virtctl attempt before RolloutDiskToPVC gives up on the attempt.
// After the data reaches 100% virtctl waits up to 24 h for CDI's processing and
// says nothing while the server crash-loops (lf-edge/eve#6856); a few restarts
// is enough to tell a crash loop from a one-off.
const uploadServerMaxRestarts = 3

// uploadServerCheckInterval is how often the upload server pod is checked.
const uploadServerCheckInterval = 15 * time.Second

// uploadServerWatch counts the restarts of the CDI upload server for one PVC
// since the watch began. Restarts a pod already had are not counted, and a pod
// that CDI replaces does not reset the count.
type uploadServerWatch struct {
	client      kubernetes.Interface
	pvcName     string
	maxRestarts int32

	podUID   types.UID
	baseline int32 // restarts the current pod already had when the watch began
	last     int32 // restarts of the current pod at the last check
	carried  int32 // restarts counted on pods since replaced
}

func newUploadServerWatch(client kubernetes.Interface, pvcName string) *uploadServerWatch {
	return &uploadServerWatch{client: client, pvcName: pvcName, maxRestarts: uploadServerMaxRestarts}
}

// check returns why the upload server should be considered failed, or "" while
// it is not (yet) crash-looping. Lookup errors count as "not failed": the
// attempt keeps its own timeout as the backstop.
func (w *uploadServerWatch) check(ctx context.Context) string {
	podName := "cdi-upload-" + w.pvcName
	pvc, err := w.client.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).
		Get(ctx, w.pvcName, metav1.GetOptions{})
	if err == nil {
		if name, ok := pvc.Annotations["cdi.kubevirt.io/storage.uploadPodName"]; ok && name != "" {
			podName = name
		}
	}
	pod, err := w.client.CoreV1().Pods(EVEKubeNameSpace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return ""
	}

	restarts, reason := podRestarts(pod)
	if pod.UID != w.podUID {
		if w.podUID == "" {
			// The pod that was there when the watch began: its earlier
			// restarts belong to earlier attempts.
			w.baseline = restarts
		} else {
			// CDI replaced the pod during the watch: keep what the old one
			// counted, and count all of the new one's restarts.
			w.carried += w.last - w.baseline
			w.baseline = 0
		}
		w.podUID = pod.UID
	}
	w.last = restarts
	counted := w.carried + restarts - w.baseline
	if counted < w.maxRestarts {
		return ""
	}
	if reason == "" {
		reason = "unknown"
	}
	return fmt.Sprintf("CDI upload server %s restarted %d times (last exit: %s)",
		podName, counted, reason)
}

// podRestarts sums the restart counts of a pod's containers and returns the
// most informative last termination reason among them.
func podRestarts(pod *corev1.Pod) (int32, string) {
	var restarts int32
	reason := ""
	for _, cs := range pod.Status.ContainerStatuses {
		restarts += cs.RestartCount
		if t := cs.LastTerminationState.Terminated; t != nil {
			r := t.Reason
			if r == "" {
				r = fmt.Sprintf("exit code %d", t.ExitCode)
			}
			if reason == "" || r == "OOMKilled" {
				reason = r
			}
		}
	}
	return restarts, reason
}

// watchUploadServer polls the upload server for pvcName until ctx is done, and
// calls onFailure once, with the reason, if it starts crash-looping.
func watchUploadServer(ctx context.Context, log *base.LogObject, w *uploadServerWatch,
	interval time.Duration, onFailure func(reason string)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if reason := w.check(ctx); reason != "" {
			log.Errorf("RolloutDiskToPVC pvc:%s: %s, abandoning the upload attempt", w.pvcName, reason)
			onFailure(reason)
			return
		}
	}
}
