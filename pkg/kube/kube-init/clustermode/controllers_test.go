// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// preMigration is a creation time safely before any flag armed in a test.
var preMigration = metav1.NewTime(time.Now().Add(-time.Hour))

func ownedPod(ns, name, ownerKind, ownerName string) corev1.Pod {
	isController := true
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, CreationTimestamp: preMigration},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if ownerKind != "" {
		p.OwnerReferences = []metav1.OwnerReference{{
			Kind: ownerKind, Name: ownerName, Controller: &isController,
		}}
	}
	return p
}

func podNames(pods []corev1.Pod) []string {
	var names []string
	for _, p := range pods {
		names = append(names, p.Namespace+"/"+p.Name)
	}
	return names
}

func TestStaleControllerPodsSelection(t *testing.T) {
	deleting := ownedPod("longhorn-system", "csi-provisioner-b", "ReplicaSet", "csi-provisioner-7c")
	deleting.DeletionTimestamp = &metav1.Time{}
	completed := ownedPod("kube-system", "helm-install-traefik", "ReplicaSet", "x")
	completed.Status.Phase = corev1.PodSucceeded
	fresh := ownedPod("longhorn-system", "csi-provisioner-new", "ReplicaSet", "csi-provisioner-7c")
	fresh.CreationTimestamp = metav1.Now()

	pods := []corev1.Pod{
		ownedPod("longhorn-system", "csi-provisioner-a", "ReplicaSet", "csi-provisioner-7c"),
		ownedPod("longhorn-system", "longhorn-manager-x", "DaemonSet", "longhorn-manager"),
		ownedPod("longhorn-system", "engine-image-ei-1", "DaemonSet", "engine-image-ei-b4bcf0a5"),
		ownedPod("longhorn-system", "longhorn-csi-plugin-x", "DaemonSet", "longhorn-csi-plugin"),
		ownedPod("longhorn-system", "instance-manager-1", "InstanceManager", "instance-manager-1"),
		ownedPod("cdi", "cdi-deployment-a", "ReplicaSet", "cdi-deployment-6b"),
		ownedPod("kubevirt", "virt-handler-x", "DaemonSet", "virt-handler"),
		ownedPod("kube-system", "coredns-a", "ReplicaSet", "coredns-7f"),
		ownedPod("kube-system", "kube-multus-ds-x", "DaemonSet", "kube-multus-ds"),
		ownedPod("eve-kube-app", "virt-launcher-app", "VirtualMachineInstance", "app"),
		ownedPod("eve-kube-app", "cdi-upload-pvc", "", ""),
		ownedPod("longhorn-system", "bare-pod", "", ""),
		deleting,
		completed,
		fresh,
	}

	got := podNames(staleControllerPods(pods, time.Now().Add(-time.Minute)))
	want := []string{
		"longhorn-system/csi-provisioner-a",
		"longhorn-system/longhorn-manager-x",
		"cdi/cdi-deployment-a",
		"kubevirt/virt-handler-x",
		"kube-system/coredns-a",
	}
	if !slices.Equal(got, want) {
		t.Errorf("staleControllerPods() = %v, want %v", got, want)
	}
}

func withControllerFlag(t *testing.T) {
	t.Helper()
	saved := ControllerRestartFlag
	ControllerRestartFlag = state.Marker(filepath.Join(t.TempDir(), "controller-restart-needed"))
	t.Cleanup(func() { ControllerRestartFlag = saved })
}

func TestRestartStaleControllersNoFlagIsNoop(t *testing.T) {
	withControllerFlag(t)
	err := RestartStaleControllers(context.Background(),
		&k3s.ClusterStatus{IsBootstrapNode: true}, "node")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRestartStaleControllersNonBootstrapClearsFlag(t *testing.T) {
	withControllerFlag(t)
	if err := state.Mark(ControllerRestartFlag); err != nil {
		t.Fatal(err)
	}
	for _, cs := range []*k3s.ClusterStatus{nil, {IsBootstrapNode: false}} {
		if err := RestartStaleControllers(context.Background(), cs, "node"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if marked, _ := state.IsMarked(ControllerRestartFlag); marked {
			t.Errorf("flag still armed for status %+v", cs)
		}
	}
}

func TestRestartStaleControllersWithoutClientKeepsFlag(t *testing.T) {
	withControllerFlag(t)
	if err := state.Mark(ControllerRestartFlag); err != nil {
		t.Fatal(err)
	}
	err := RestartStaleControllers(context.Background(),
		&k3s.ClusterStatus{IsBootstrapNode: true}, "node")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if marked, _ := state.IsMarked(ControllerRestartFlag); !marked {
		t.Error("flag cleared although no pod was recycled")
	}
}

// TestRestartStaleControllersDeletesOnlyStalePodsOnThisNode drives the
// delete path through a fake clientset: only this node's pre-migration
// controller pods go, and the flag is cleared afterwards.
func TestRestartStaleControllersDeletesOnlyStalePodsOnThisNode(t *testing.T) {
	withControllerFlag(t)

	onNode := func(p corev1.Pod, node string) *corev1.Pod {
		p.Spec.NodeName = node
		return &p
	}
	fresh := ownedPod("longhorn-system", "csi-attacher-new", "ReplicaSet", "csi-attacher-64")
	fresh.CreationTimestamp = metav1.NewTime(time.Now().Add(time.Hour))

	cs := k8sfake.NewClientset(
		onNode(ownedPod("longhorn-system", "longhorn-manager-x", "DaemonSet", "longhorn-manager"), "node-a"),
		onNode(ownedPod("cdi", "cdi-deployment-a", "ReplicaSet", "cdi-deployment-6b"), "node-a"),
		onNode(ownedPod("longhorn-system", "instance-manager-1", "InstanceManager", "im"), "node-a"),
		onNode(fresh, "node-a"),
		onNode(ownedPod("cdi", "cdi-deployment-b", "ReplicaSet", "cdi-deployment-6b"), "node-b"),
	)
	kubeclient.SetDefault(&kubeclient.Client{Clientset: cs})
	t.Cleanup(func() { kubeclient.SetDefault(nil) })

	if err := state.Mark(ControllerRestartFlag); err != nil {
		t.Fatal(err)
	}
	if err := RestartStaleControllers(context.Background(),
		&k3s.ClusterStatus{IsBootstrapNode: true}, "node-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	left, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range left.Items {
		got = append(got, p.Namespace+"/"+p.Name)
	}
	slices.Sort(got)
	want := []string{
		"cdi/cdi-deployment-b",
		"longhorn-system/csi-attacher-new",
		"longhorn-system/instance-manager-1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("pods left = %v, want %v", got, want)
	}
	if marked, _ := state.IsMarked(ControllerRestartFlag); marked {
		t.Error("flag still armed after every stale pod was deleted")
	}
}

// TestRestartStaleControllersCutoffIsFlagMtime pins that the cutoff comes
// from when the flag was armed, not from when the pass runs.
func TestRestartStaleControllersCutoffIsFlagMtime(t *testing.T) {
	withControllerFlag(t)
	if err := state.Mark(ControllerRestartFlag); err != nil {
		t.Fatal(err)
	}
	armed := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(string(ControllerRestartFlag), armed, armed); err != nil {
		t.Fatal(err)
	}

	recreated := ownedPod("cdi", "cdi-deployment-new", "ReplicaSet", "cdi-deployment-6b")
	recreated.CreationTimestamp = metav1.NewTime(armed.Add(time.Minute))
	recreated.Spec.NodeName = "node-a"
	cs := k8sfake.NewClientset(&recreated)
	kubeclient.SetDefault(&kubeclient.Client{Clientset: cs})
	t.Cleanup(func() { kubeclient.SetDefault(nil) })

	if err := RestartStaleControllers(context.Background(),
		&k3s.ClusterStatus{IsBootstrapNode: true}, "node-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := cs.CoreV1().Pods("cdi").Get(context.Background(), recreated.Name, metav1.GetOptions{}); err != nil {
		t.Errorf("pod created after the flag was armed was recycled: %v", err)
	}
}
