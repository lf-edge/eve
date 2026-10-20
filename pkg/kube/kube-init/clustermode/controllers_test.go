// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
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
	saved := recyclePods
	recyclePods = func() controllerPods { return nil }
	t.Cleanup(func() { recyclePods = saved })
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

// fakePods is an in-memory controllerPods. list ignores the node, as an API
// that dropped the field selector would, so the node check in
// RestartStaleControllers is exercised too.
type fakePods struct {
	pods       []corev1.Pod
	failDelete map[string]bool // "namespace/name" -> delete fails
}

func (f *fakePods) list(context.Context, string) ([]corev1.Pod, error) {
	return slices.Clone(f.pods), nil
}

func (f *fakePods) delete(_ context.Context, namespace, name string) error {
	key := namespace + "/" + name
	if f.failDelete[key] {
		return errors.New("injected delete failure")
	}
	f.pods = slices.DeleteFunc(f.pods, func(p corev1.Pod) bool {
		return p.Namespace+"/"+p.Name == key
	})
	return nil
}

func (f *fakePods) names() []string {
	var got []string
	for _, p := range f.pods {
		got = append(got, p.Namespace+"/"+p.Name)
	}
	slices.Sort(got)
	return got
}

func withFakePods(t *testing.T, pods ...corev1.Pod) *fakePods {
	t.Helper()
	f := &fakePods{pods: pods}
	saved := recyclePods
	recyclePods = func() controllerPods { return f }
	t.Cleanup(func() { recyclePods = saved })
	return f
}

func onNode(p corev1.Pod, node string) corev1.Pod {
	p.Spec.NodeName = node
	return p
}

// Only this node's pre-migration controller pods go, and the flag is
// cleared afterwards.
func TestRestartStaleControllersDeletesOnlyStalePodsOnThisNode(t *testing.T) {
	withControllerFlag(t)
	fresh := ownedPod("longhorn-system", "csi-attacher-new", "ReplicaSet", "csi-attacher-64")
	fresh.CreationTimestamp = metav1.NewTime(time.Now().Add(time.Hour))
	f := withFakePods(t,
		onNode(ownedPod("longhorn-system", "longhorn-manager-x", "DaemonSet", "longhorn-manager"), "node-a"),
		onNode(ownedPod("cdi", "cdi-deployment-a", "ReplicaSet", "cdi-deployment-6b"), "node-a"),
		onNode(ownedPod("longhorn-system", "instance-manager-1", "InstanceManager", "im"), "node-a"),
		onNode(fresh, "node-a"),
		onNode(ownedPod("cdi", "cdi-deployment-b", "ReplicaSet", "cdi-deployment-6b"), "node-b"),
	)

	if err := state.Mark(ControllerRestartFlag); err != nil {
		t.Fatal(err)
	}
	if err := RestartStaleControllers(context.Background(),
		&k3s.ClusterStatus{IsBootstrapNode: true}, "node-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{
		"cdi/cdi-deployment-b",
		"longhorn-system/csi-attacher-new",
		"longhorn-system/instance-manager-1",
	}
	if got := f.names(); !slices.Equal(got, want) {
		t.Errorf("pods left = %v, want %v", got, want)
	}
	if marked, _ := state.IsMarked(ControllerRestartFlag); marked {
		t.Error("flag still armed after every stale pod was deleted")
	}
}

// A failed delete keeps the flag armed for the next tick, and the retry only
// touches what is left of the original set.
func TestRestartStaleControllersKeepsFlagOnDeleteFailure(t *testing.T) {
	withControllerFlag(t)
	f := withFakePods(t,
		onNode(ownedPod("cdi", "cdi-deployment-a", "ReplicaSet", "cdi-deployment-6b"), "node-a"),
		onNode(ownedPod("longhorn-system", "longhorn-manager-x", "DaemonSet", "longhorn-manager"), "node-a"),
	)
	f.failDelete = map[string]bool{"cdi/cdi-deployment-a": true}

	if err := state.Mark(ControllerRestartFlag); err != nil {
		t.Fatal(err)
	}
	if err := RestartStaleControllers(context.Background(),
		&k3s.ClusterStatus{IsBootstrapNode: true}, "node-a"); err == nil {
		t.Fatal("expected the delete failure to be returned")
	}
	if marked, _ := state.IsMarked(ControllerRestartFlag); !marked {
		t.Fatal("flag cleared although a stale pod is still there")
	}

	f.failDelete = nil
	if err := RestartStaleControllers(context.Background(),
		&k3s.ClusterStatus{IsBootstrapNode: true}, "node-a"); err != nil {
		t.Fatalf("retry: unexpected error: %v", err)
	}
	if got := f.names(); len(got) != 0 {
		t.Errorf("pods left after retry = %v, want none", got)
	}
	if marked, _ := state.IsMarked(ControllerRestartFlag); marked {
		t.Error("flag still armed after the retry deleted the rest")
	}
}

// The cutoff comes from when the flag was armed, not from when the pass runs.
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
	f := withFakePods(t, onNode(recreated, "node-a"))

	if err := RestartStaleControllers(context.Background(),
		&k3s.ClusterStatus{IsBootstrapNode: true}, "node-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := f.names(); !slices.Equal(got, []string{"cdi/cdi-deployment-new"}) {
		t.Errorf("pod created after the flag was armed was recycled: left %v", got)
	}
}
