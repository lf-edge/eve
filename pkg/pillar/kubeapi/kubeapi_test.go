// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEvalFailoverStorage(t *testing.T) {
	const failedNode = "n1"
	failedRep := withReplica(safeReplica("vol-b-r2", "n2"), func(r *lhv1beta2.Replica) {
		r.Spec.FailedAt = tsLate
	})
	repsByVol := map[string][]lhv1beta2.Replica{
		"vol-a": {safeReplica("vol-a-r1", failedNode), safeReplica("vol-a-r2", "n2")},
		"vol-b": {safeReplica("vol-b-r1", failedNode), failedRep},
		"vol-c": {safeReplica("vol-c-r1", failedNode), safeReplica("vol-c-r2", "n2"), safeReplica("vol-c-r3", "n3")},
	}
	listReps := funcLHReplicaLister{fn: func(opts metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
		vol := strings.TrimPrefix(opts.LabelSelector, "longhornvolume=")
		return &lhv1beta2.ReplicaList{Items: repsByVol[vol]}, nil
	}}
	getVol := func(desired int) funcLHVolGetter {
		return funcLHVolGetter{fn: func(string) (*lhv1beta2.Volume, error) {
			return &lhv1beta2.Volume{Spec: lhv1beta2.VolumeSpec{NumberOfReplicas: desired}}, nil
		}}
	}

	tests := []struct {
		name         string
		vols         []string
		listReps     lhReplicaLister
		getVol       lhVolumeGetter
		wantProceed  bool
		wantReasonIn string
		wantVols     []failoverVolSummary
	}{
		{
			name:        "all volumes have a safe survivor",
			vols:        []string{"vol-a", "vol-c"},
			listReps:    listReps,
			getVol:      getVol(3),
			wantProceed: true,
			wantVols: []failoverVolSummary{
				{name: "vol-a", survivors: 1, desired: 3, failedNodeReplicas: []string{"vol-a-r1"}},
				{name: "vol-c", survivors: 2, desired: 3, failedNodeReplicas: []string{"vol-c-r1"}},
			},
		},
		{
			name:         "one volume has only a failed survivor",
			vols:         []string{"vol-a", "vol-b"},
			listReps:     listReps,
			getVol:       getVol(2),
			wantReasonIn: "vol-b",
		},
		{
			name: "replica list error",
			vols: []string{"vol-a"},
			listReps: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				return nil, errors.New("api down")
			}},
			getVol:       getVol(2),
			wantReasonIn: "vol-a",
		},
		{
			name:        "no longhorn volumes",
			listReps:    listReps,
			getVol:      getVol(2),
			wantProceed: true,
		},
		{
			name:        "survivors less than desired",
			vols:        []string{"vol-a"},
			listReps:    listReps,
			getVol:      getVol(2),
			wantProceed: true,
			wantVols:    []failoverVolSummary{{name: "vol-a", survivors: 1, desired: 2, failedNodeReplicas: []string{"vol-a-r1"}}},
		},
		{
			name:     "volume get error leaves desired unknown",
			vols:     []string{"vol-a"},
			listReps: listReps,
			getVol: funcLHVolGetter{fn: func(string) (*lhv1beta2.Volume, error) {
				return nil, errors.New("api down")
			}},
			wantProceed: true,
			wantVols:    []failoverVolSummary{{name: "vol-a", survivors: 1, desired: 0, failedNodeReplicas: []string{"vol-a-r1"}}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wdKicks := 0
			d := evalFailoverStorage(newTestLog(), tc.vols, failedNode, tc.listReps, tc.getVol, func() { wdKicks++ })
			if d.proceed != tc.wantProceed {
				t.Fatalf("proceed = %v, want %v (reason %q)", d.proceed, tc.wantProceed, d.reason)
			}
			if !tc.wantProceed && !strings.Contains(d.reason, tc.wantReasonIn) {
				t.Errorf("reason %q does not contain %q", d.reason, tc.wantReasonIn)
			}
			if !reflect.DeepEqual(d.vols, tc.wantVols) {
				t.Errorf("vols = %+v, want %+v", d.vols, tc.wantVols)
			}
			if wdKicks < len(d.vols) {
				t.Errorf("watchdog kicked %d times for %d volumes", wdKicks, len(d.vols))
			}
		})
	}
}
