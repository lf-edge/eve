// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"testing"

	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
)

func TestLhSpecMergePatch(t *testing.T) {
	got, err := lhSpecMergePatch(map[string]interface{}{"cron": "0 2 * * *"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"spec":{"cron":"0 2 * * *"}}`; string(got) != want {
		t.Errorf("patch = %s, want %s", got, want)
	}
}

// TestLhVolumeNodePatch pins that only the node, and a missing backup
// target, are sent: every other volume field stays out of the patch.
func TestLhVolumeNodePatch(t *testing.T) {
	cases := []struct {
		name         string
		backupTarget string
		want         string
	}{
		{"backup target set", "nfs-target",
			`{"spec":{"nodeID":"node-b"}}`},
		{"backup target missing", "",
			`{"spec":{"backupTargetName":"default","nodeID":"node-b"}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vol := &lhv1beta2.Volume{Spec: lhv1beta2.VolumeSpec{
				NodeID:           "node-a",
				BackupTargetName: c.backupTarget,
				NumberOfReplicas: 2,
			}}
			got, err := lhVolumeNodePatch(vol, "node-b")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Errorf("patch = %s, want %s", got, c.want)
			}
		})
	}
}
