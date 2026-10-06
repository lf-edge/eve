// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"errors"
	"testing"

	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeDiskStatusGetter struct {
	node *lhv1beta2.Node
	err  error
}

func (f fakeDiskStatusGetter) Get(context.Context, string, metav1.GetOptions) (*lhv1beta2.Node, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.node, nil
}

// readyDiskStatus is a Status.DiskStatus entry recording recovery and a
// True Ready condition -- what the disk monitor writes once it has
// successfully run for this disk at least once.
func readyDiskStatus(uuid string) *lhv1beta2.DiskStatus {
	return &lhv1beta2.DiskStatus{
		DiskUUID: uuid,
		Conditions: []lhv1beta2.Condition{
			{Type: lhv1beta2.DiskConditionTypeReady, Status: lhv1beta2.ConditionStatusTrue},
		},
	}
}

func TestNodeDiskStatusReady(t *testing.T) {
	const thisNode = "node-a"

	testMatrix := map[string]struct {
		node        *lhv1beta2.Node
		expectReady bool
	}{
		"no disks in spec yet": {
			node:        &lhv1beta2.Node{},
			expectReady: false,
		},
		"disk in spec, no status entry at all": {
			node: &lhv1beta2.Node{
				Spec: lhv1beta2.NodeSpec{
					Disks: map[string]lhv1beta2.DiskSpec{"default-disk-abc": {}},
				},
			},
			expectReady: false,
		},
		// The reported failure: Spec.Disks gets a fresh entry as soon as
		// Longhorn sees the node, well before the disk monitor -- which
		// needs a running instance-manager -- has ever completed.
		"disk in spec, status entry present but no UUID recorded yet": {
			node: &lhv1beta2.Node{
				Spec: lhv1beta2.NodeSpec{
					Disks: map[string]lhv1beta2.DiskSpec{"default-disk-abc": {}},
				},
				Status: lhv1beta2.NodeStatus{
					DiskStatus: map[string]*lhv1beta2.DiskStatus{"default-disk-abc": {}},
				},
			},
			expectReady: false,
		},
		"disk UUID recorded but Ready condition not yet True": {
			node: &lhv1beta2.Node{
				Spec: lhv1beta2.NodeSpec{
					Disks: map[string]lhv1beta2.DiskSpec{"default-disk-abc": {}},
				},
				Status: lhv1beta2.NodeStatus{
					DiskStatus: map[string]*lhv1beta2.DiskStatus{
						"default-disk-abc": {DiskUUID: "845b5e73-..."},
					},
				},
			},
			expectReady: false,
		},
		"disk fully recorded and ready": {
			node: &lhv1beta2.Node{
				Spec: lhv1beta2.NodeSpec{
					Disks: map[string]lhv1beta2.DiskSpec{"default-disk-abc": {}},
				},
				Status: lhv1beta2.NodeStatus{
					DiskStatus: map[string]*lhv1beta2.DiskStatus{
						"default-disk-abc": readyDiskStatus("845b5e73-..."),
					},
				},
			},
			expectReady: true,
		},
		// Every disk must be recorded, at least one must be ready; see
		// nodeDiskStatusReady.
		"two disks, one ready and one recorded but degraded": {
			node: &lhv1beta2.Node{
				Spec: lhv1beta2.NodeSpec{
					Disks: map[string]lhv1beta2.DiskSpec{
						"default-disk-abc": {}, "default-disk-def": {},
					},
				},
				Status: lhv1beta2.NodeStatus{
					DiskStatus: map[string]*lhv1beta2.DiskStatus{
						"default-disk-abc": readyDiskStatus("845b5e73-..."),
						"default-disk-def": {DiskUUID: "1f2e3d4c-..."},
					},
				},
			},
			expectReady: true,
		},
		"two disks, one ready and one not yet recorded": {
			node: &lhv1beta2.Node{
				Spec: lhv1beta2.NodeSpec{
					Disks: map[string]lhv1beta2.DiskSpec{
						"default-disk-abc": {}, "default-disk-def": {},
					},
				},
				Status: lhv1beta2.NodeStatus{
					DiskStatus: map[string]*lhv1beta2.DiskStatus{
						"default-disk-abc": readyDiskStatus("845b5e73-..."),
						"default-disk-def": {},
					},
				},
			},
			expectReady: false,
		},
	}

	for name, test := range testMatrix {
		t.Run(name, func(t *testing.T) {
			ready, err := nodeDiskStatusReady(context.Background(),
				fakeDiskStatusGetter{node: test.node}, thisNode)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ready != test.expectReady {
				t.Errorf("ready = %v, want %v", ready, test.expectReady)
			}
		})
	}
}

func TestNodeDiskStatusReadyGetError(t *testing.T) {
	getErr := errors.New("api unreachable")
	ready, err := nodeDiskStatusReady(context.Background(),
		fakeDiskStatusGetter{err: getErr}, "node-a")
	if !errors.Is(err, getErr) {
		t.Errorf("err = %v, want %v", err, getErr)
	}
	if ready {
		t.Error("ready = true on get error, want false")
	}
}
