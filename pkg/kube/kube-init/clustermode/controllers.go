// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// ControllerRestartFlag is the marker file set during a single→cluster
// transition on the bootstrap node and cleared by RestartStaleControllers
// once the controller pods have been recycled. Lives under /var/lib
// (bind-mount of /persist/vault/kube) so it survives a kube-init restart
// until the recycle actually happens.
var ControllerRestartFlag state.Marker = "/var/lib/controller-restart-needed"

// controllerNamespaces are the namespaces whose controllers sit in the
// app-volume path (Longhorn, CDI, KubeVirt) or serve it (CoreDNS,
// local-path-provisioner for CDI scratch space).
var controllerNamespaces = map[string]bool{
	"kube-system":     true,
	"longhorn-system": true,
	"cdi":             true,
	"kubevirt":        true,
}

// informerDaemonSets are the DaemonSets in controllerNamespaces whose pods
// run controllers. Every other DaemonSet there is either data path
// (engine-image, csi-plugin) or node plumbing (multus, kube-vip) and has no
// cache worth refreshing.
var informerDaemonSets = map[string]bool{
	"longhorn-manager": true,
	"virt-handler":     true,
}

// RestartStaleControllers deletes the controller pods on this node after a
// single→cluster transition so they come back with fresh informer caches.
//
// On the bootstrap node the transition restarts k3s with --cluster-init,
// which migrates the sqlite datastore into a new embedded etcd. The migrated
// etcd starts its revision counter from the number of keys copied, typically
// well below the last kine resourceVersion, while the pods keep running
// through the k3s restart (they live in the user containerd, not in k3s).
// Their reflectors resume watching from the old, now-future resourceVersion
// and drop every event until etcd counts past it - minutes to hours of
// controllers blind to new objects. Longhorn is the visible casualty: a
// freshly created Volume CR never shows up in longhorn-manager's cache, so
// CSI CreateVolume fails with "not found" and then "already exists" forever,
// and the app's PVC upload fails.
//
// Data-path pods (instance-manager, engine-image, csi-plugin) and
// everything in the app namespace are left alone: they hold no informer
// state that matters here, and recycling them would interrupt volume I/O.
//
// Gated by ControllerRestartFlag. Only pods created before the flag was
// armed are recycled: k3s is stopped from then until the migration, so
// anything newer already listed from the new etcd. That keeps a retry,
// after a failed delete or an unreachable API, from recycling the fresh
// replacements again. The flag is cleared once every stale pod is gone.
func RestartStaleControllers(ctx context.Context, status *k3s.ClusterStatus, nodeName string) error {
	flagged, err := state.IsMarked(ControllerRestartFlag)
	if err != nil {
		return fmt.Errorf("check %s: %w", ControllerRestartFlag, err)
	}
	if !flagged {
		return nil
	}
	fi, err := os.Stat(string(ControllerRestartFlag))
	if err != nil {
		return fmt.Errorf("stat %s: %w", ControllerRestartFlag, err)
	}
	armedAt := fi.ModTime()
	if status == nil || !status.IsBootstrapNode {
		// Only the bootstrap migrates its datastore. A joining node's
		// old pods do not exist in the cluster it joins, so its kubelet
		// tears them down without help.
		return state.Unmark(ControllerRestartFlag)
	}
	if !kubeclient.HasDefault() {
		return nil
	}

	podClient := kubeclient.Default().Clientset.CoreV1().Pods(metav1.NamespaceAll)
	pods, err := podClient.List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		log.Printf("controllers: list pods on %s failed, will retry: %v", nodeName, err)
		return nil
	}

	onNode := pods.Items[:0]
	for _, p := range pods.Items {
		if p.Spec.NodeName == nodeName {
			onNode = append(onNode, p)
		}
	}

	var errs []error
	stale := staleControllerPods(onNode, armedAt)
	for _, p := range stale {
		err := kubeclient.Default().Clientset.CoreV1().Pods(p.Namespace).
			Delete(ctx, p.Name, metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete pod %s/%s: %w", p.Namespace, p.Name, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	log.Printf("controllers: recycled %d controller pod(s) on %s after datastore migration",
		len(stale), nodeName)
	return state.Unmark(ControllerRestartFlag)
}

// staleControllerPods selects the pods RestartStaleControllers recycles:
// live pods created before armedAt in controllerNamespaces that belong to
// a Deployment, plus the pods of informerDaemonSets.
func staleControllerPods(pods []corev1.Pod, armedAt time.Time) []corev1.Pod {
	var out []corev1.Pod
	for _, p := range pods {
		if !controllerNamespaces[p.Namespace] || p.DeletionTimestamp != nil {
			continue
		}
		if !p.CreationTimestamp.Time.Before(armedAt) {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		owner := metav1.GetControllerOf(&p)
		if owner == nil {
			continue
		}
		switch owner.Kind {
		case "ReplicaSet":
			out = append(out, p)
		case "DaemonSet":
			if informerDaemonSets[owner.Name] {
				out = append(out, p)
			}
		}
	}
	return out
}
