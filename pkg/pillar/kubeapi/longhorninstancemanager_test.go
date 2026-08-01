// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"errors"
	"testing"

	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeInstanceManagerLister struct {
	items []lhv1beta2.InstanceManager
	err   error
}

func (f fakeInstanceManagerLister) List(context.Context, metav1.ListOptions) (
	*lhv1beta2.InstanceManagerList, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &lhv1beta2.InstanceManagerList{Items: f.items}, nil
}

func instanceManager(nodeID string, state lhv1beta2.InstanceManagerState) lhv1beta2.InstanceManager {
	return lhv1beta2.InstanceManager{
		Spec:   lhv1beta2.InstanceManagerSpec{NodeID: nodeID},
		Status: lhv1beta2.InstanceManagerStatus{CurrentState: state},
	}
}

func TestInstanceManagerRunningOnNode(t *testing.T) {
	const thisNode = "node-a"

	testMatrix := map[string]struct {
		items       []lhv1beta2.InstanceManager
		expectReady bool
	}{
		"running on this node": {
			items:       []lhv1beta2.InstanceManager{instanceManager(thisNode, lhv1beta2.InstanceManagerStateRunning)},
			expectReady: true,
		},
		// The reported failure: the pod is still pulling its ~440 MB image, so
		// the CR exists but cannot serve a volume yet.
		"starting on this node": {
			items:       []lhv1beta2.InstanceManager{instanceManager(thisNode, lhv1beta2.InstanceManagerStateStarting)},
			expectReady: false,
		},
		"error on this node": {
			items:       []lhv1beta2.InstanceManager{instanceManager(thisNode, lhv1beta2.InstanceManagerStateError)},
			expectReady: false,
		},
		"running only on another node": {
			items:       []lhv1beta2.InstanceManager{instanceManager("node-b", lhv1beta2.InstanceManagerStateRunning)},
			expectReady: false,
		},
		"another node running, this one starting": {
			items: []lhv1beta2.InstanceManager{
				instanceManager("node-b", lhv1beta2.InstanceManagerStateRunning),
				instanceManager(thisNode, lhv1beta2.InstanceManagerStateStarting),
			},
			expectReady: false,
		},
		"several on this node, one running": {
			items: []lhv1beta2.InstanceManager{
				instanceManager(thisNode, lhv1beta2.InstanceManagerStateStopped),
				instanceManager(thisNode, lhv1beta2.InstanceManagerStateRunning),
			},
			expectReady: true,
		},
		"none at all": {
			items:       nil,
			expectReady: false,
		},
	}

	for name, test := range testMatrix {
		t.Run(name, func(t *testing.T) {
			ready, err := instanceManagerRunningOnNode(context.Background(),
				fakeInstanceManagerLister{items: test.items}, thisNode)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ready != test.expectReady {
				t.Errorf("ready = %v, want %v", ready, test.expectReady)
			}
		})
	}
}

func TestInstanceManagerRunningOnNodeListError(t *testing.T) {
	listErr := errors.New("api unreachable")
	ready, err := instanceManagerRunningOnNode(context.Background(),
		fakeInstanceManagerLister{err: listErr}, "node-a")
	if !errors.Is(err, listErr) {
		t.Errorf("err = %v, want %v", err, listErr)
	}
	if ready {
		t.Error("ready = true on list error, want false")
	}
}

const imTestNode = "im-test-node"

func imDaemonset(name string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: longhornNamespace},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
			},
		},
	}
}

func imPod(dsName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dsName + "-pod",
			Namespace: longhornNamespace,
			Labels:    map[string]string{"app": dsName},
		},
		Spec: corev1.PodSpec{NodeName: imTestNode},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Ready: true}},
		},
	}
}

func imHealthyDaemonsets() []runtime.Object {
	names := []string{"longhorn-manager", "longhorn-csi-plugin", "engine-image-ei-abcdef12"}
	objs := make([]runtime.Object, 0, len(names)*2)
	for _, n := range names {
		objs = append(objs, imDaemonset(n), imPod(n))
	}
	return objs
}

// Healthy DaemonSets alone must not make the node ready: the instance-manager
// gate runs afterwards and its verdict is what checkLonghornReady returns.
func TestCheckLonghornReadyAppliesInstanceManagerGate(t *testing.T) {
	gateErr := errors.New("longhorn instance-manager not running on node")

	testMatrix := map[string]struct {
		gate      func(context.Context, string) error
		expectErr error
	}{
		"gate satisfied": {
			gate:      func(context.Context, string) error { return nil },
			expectErr: nil,
		},
		"gate unsatisfied": {
			gate:      func(context.Context, string) error { return gateErr },
			expectErr: gateErr,
		},
	}

	for name, test := range testMatrix {
		t.Run(name, func(t *testing.T) {
			saved := instanceManagerReady
			t.Cleanup(func() { instanceManagerReady = saved })
			instanceManagerReady = test.gate

			client := fake.NewSimpleClientset(imHealthyDaemonsets()...)
			err := checkLonghornReady(client, imTestNode)
			if !errors.Is(err, test.expectErr) {
				t.Errorf("err = %v, want %v", err, test.expectErr)
			}
		})
	}
}
