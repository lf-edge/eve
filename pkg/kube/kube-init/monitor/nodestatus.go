// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"encoding/json"
	"log"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/witnessstatus"
	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// lastStamped is the annotation set last written, so an unchanged tick
// costs nothing. Status changes rarely and the tick is every
// 15 seconds; patching regardless would be a steady stream of writes
// into etcd for no new information.
var lastStamped map[string]string

// StampNodeStatus publishes what only this node knows onto its own Node
// object: on the device hosting the witness, the witness's status.
//
// This is the route node-uuid already takes. The elected cluster-info
// reporter builds its message from the kube API, so anything it cannot
// read there has to be put there by the node that knows it, and a
// witness has no Node object of its own to carry its own.
func (m *Monitor) StampNodeStatus(ctx context.Context) {
	// An empty value removes the annotation. A parked witness (Idle) is
	// not a witness on this node, and leaving its annotation behind
	// would let it shadow the real one on the node that now hosts it.
	annotations := map[string]string{types.NodeWitnessAnnotation: ""}

	if witnessstatus.Received() {
		if status := witnessstatus.Get(); status.State != types.WitnessEtcdStateIdle {
			encoded, err := json.Marshal(status)
			if err != nil {
				log.Printf("warning: encode witness status: %v", err)
				return
			}
			annotations[types.NodeWitnessAnnotation] = string(encoded)
		}
	}

	if sameAnnotations(annotations, lastStamped) {
		return
	}
	patch, err := buildStampPatch(annotations)
	if err != nil {
		log.Printf("warning: build node status patch: %v", err)
		return
	}
	nodes := kubeclient.Default().Clientset.CoreV1().Nodes()
	if _, err := nodes.Patch(ctx, m.deviceName, k8stypes.MergePatchType,
		patch, metav1.PatchOptions{}); err != nil {
		log.Printf("warning: stamp node status: %v", err)
		return
	}
	lastStamped = annotations
}

// buildStampPatch builds a merge patch setting each annotation, where an
// empty value deletes it.
func buildStampPatch(annotations map[string]string) ([]byte, error) {
	patched := make(map[string]*string, len(annotations))
	for k, v := range annotations {
		if v == "" {
			patched[k] = nil
			continue
		}
		patched[k] = &v
	}
	return json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": patched},
	})
}

func sameAnnotations(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
