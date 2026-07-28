// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const lhTestNode = "test-node"

func lhDaemonset(name string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "longhorn-system"},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
			},
		},
	}
}

func lhPod(dsName string, ready bool) *corev1.Pod {
	phase := corev1.PodRunning
	if !ready {
		phase = corev1.PodPending
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dsName + "-pod",
			Namespace: "longhorn-system",
			Labels:    map[string]string{"app": dsName},
		},
		Spec: corev1.PodSpec{NodeName: lhTestNode},
		Status: corev1.PodStatus{
			Phase:             phase,
			ContainerStatuses: []corev1.ContainerStatus{{Ready: ready}},
		},
	}
}

// healthyLonghornObjects returns the three daemonsets checkLonghornReady
// expects, each with a Running-and-Ready pod on lhTestNode.
func healthyLonghornObjects() []runtime.Object {
	names := []string{"longhorn-manager", "longhorn-csi-plugin", "engine-image-ei-abcdef12"}
	objs := make([]runtime.Object, 0, len(names)*2)
	for _, n := range names {
		objs = append(objs, lhDaemonset(n), lhPod(n, true))
	}
	return objs
}

func TestCheckLonghornReadyHealthy(t *testing.T) {
	client := fake.NewSimpleClientset(healthyLonghornObjects()...)
	if err := checkLonghornReady(client, lhTestNode); err != nil {
		t.Fatalf("expected ready, got %v", err)
	}
}

// A daemonset that is not one of longhorn's own must not gate storage. EVE's
// collect-info leaves a SupportBundle agent daemonset behind in this namespace
// which never becomes ready, and it used to block every volume on the node.
func TestCheckLonghornReadyIgnoresStrayDaemonset(t *testing.T) {
	objs := healthyLonghornObjects()
	objs = append(objs, lhDaemonset("longhorn-support-bundle-agent"))
	client := fake.NewSimpleClientset(objs...)
	if err := checkLonghornReady(client, lhTestNode); err != nil {
		t.Fatalf("stray daemonset must not gate readiness, got %v", err)
	}
}

func TestCheckLonghornReadyMissingExpectedDaemonset(t *testing.T) {
	objs := []runtime.Object{
		lhDaemonset("longhorn-manager"), lhPod("longhorn-manager", true),
		lhDaemonset("longhorn-csi-plugin"), lhPod("longhorn-csi-plugin", true),
	}
	client := fake.NewSimpleClientset(objs...)
	err := checkLonghornReady(client, lhTestNode)
	if err == nil {
		t.Fatal("expected an error when engine-image is absent")
	}
}

func TestCheckLonghornReadyExpectedDaemonsetNotReady(t *testing.T) {
	names := []string{"longhorn-manager", "longhorn-csi-plugin", "engine-image-ei-abcdef12"}
	var objs []runtime.Object
	for _, n := range names {
		objs = append(objs, lhDaemonset(n), lhPod(n, n != "longhorn-manager"))
	}
	client := fake.NewSimpleClientset(objs...)
	if err := checkLonghornReady(client, lhTestNode); err == nil {
		t.Fatal("expected an error when an expected daemonset pod is not ready")
	}
}
