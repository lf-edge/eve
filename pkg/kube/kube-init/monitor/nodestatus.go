// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/quorum"
	"github.com/lf-edge/eve/pkg/kube/kube-init/witnessstatus"
	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// lastStamped is the annotation set last written, so an unchanged tick
// costs nothing. Recovery status changes rarely and the tick is every
// 15 seconds; patching regardless would be a steady stream of writes
// into etcd for no new information.
var lastStamped map[string]string

// absentAnnotations is the set of annotations known to be off this node's
// object. An annotation is only in it once a tick has made sure of that,
// because a previous kube-init, or a previous role of this node, may have
// left one.
var absentAnnotations = map[string]bool{}

// stampedAnnotations are the annotations StampNodeStatus owns, each
// removed when it has nothing to say.
var stampedAnnotations = []string{
	types.NodeRecoveryAnnotation,
	types.NodeWitnessAnnotation,
}

// recoveryState is what this node remembers about quorum recovery, as
// StampNodeStatus reads it from disk.
type recoveryState struct {
	applied   uint32
	recorded  bool
	asSeed    bool
	appliedAt time.Time
	// intent is when a convergence under way began, nil if none is.
	intent *time.Time
	// failure is why the latest attempt failed or a bump was rejected.
	failure string
}

// hasStatusToReport is whether this node has anything to tell the
// controller about quorum recovery: a failure, or a recorded generation
// that means something. That is the case for a node that has been the
// seed or is converging.
//
// A node that never was the seed holds a generation bump pending in case
// it is later promoted (see quorum.nextApplied), so its applied generation
// trails the controller's without anything being owed; reporting it would
// show a recovery that is not happening.
func (s recoveryState) hasStatusToReport() bool {
	return s.failure != "" || (s.recorded && (s.asSeed || s.intent != nil))
}

// status is what to report to the controller, nil when there is nothing
// to say.
func (s recoveryState) status() *types.KubeQuorumRecoveryStatus {
	if !s.hasStatusToReport() {
		return nil
	}
	status := types.KubeQuorumRecoveryStatus{AppliedGeneration: s.applied}
	if s.recorded {
		// When it got there, so a reader can tell a node that converged
		// a moment ago from one that has been at this generation since
		// it was first recorded.
		status.LastTransitionAt = s.appliedAt
		// An intent on disk means a convergence is under way, and its
		// generation is the one being worked towards rather than the
		// one reached.
		if s.intent != nil {
			status.Converging = true
			status.LastTransitionAt = *s.intent
		}
	}
	if s.failure != "" {
		status.Error.SetErrorDescription(types.ErrorDescription{Error: s.failure})
	}
	return &status
}

// readRecoveryState loads the recovery record; a part that cannot be
// read is left out and logged, so one bad read does not hide the rest.
func readRecoveryState() recoveryState {
	var s recoveryState
	// A bump quorum rejected (see quorum.Evaluate) is reported through
	// the same failure record as a convergence that failed.
	if msg, found, err := quorum.ReadFailure(); err != nil {
		log.Printf("warning: read recovery failure: %v", err)
	} else if found {
		s.failure = msg
	}
	applied, recorded, err := quorum.ReadApplied()
	if err != nil {
		log.Printf("warning: read applied generation: %v", err)
		return s
	}
	if !recorded {
		return s
	}
	s.applied, s.recorded = applied.Counter, true
	if s.asSeed, err = quorum.ReadAppliedAsSeed(); err != nil {
		log.Printf("warning: read applied role: %v", err)
	}
	if at, recorded, err := quorum.AppliedAt(); err != nil {
		log.Printf("warning: read applied timestamp: %v", err)
	} else if recorded {
		s.appliedAt = at
	}
	if in, found, err := quorum.ReadIntent(); err != nil {
		log.Printf("warning: read recovery intent: %v", err)
	} else if found {
		s.intent = &in.StartedAt
	}
	return s
}

// StampNodeStatus publishes what only this node knows onto its own Node
// object: how far it has converged to the controller's recovery
// generation, and, on the device hosting it, the witness's status.
//
// This is the route node-uuid already takes. The elected cluster-info
// reporter builds its message from the kube API, so anything it cannot
// read there has to be put there by the node that knows it, and a
// witness has no Node object of its own to carry its own.
//
// A node with nothing to report has the annotation removed, not just left
// unwritten: it may carry one from before it stopped having anything to
// say, and a stale generation reads as a current one. That includes a
// witness that is parked (Idle): it is not the witness of the cluster, and
// its annotation would shadow the real one on the node now hosting it.
func (m *Monitor) StampNodeStatus(ctx context.Context) {
	annotations := map[string]string{}

	if status := readRecoveryState().status(); status != nil {
		if encoded, err := json.Marshal(status); err != nil {
			log.Printf("warning: encode recovery status: %v", err)
		} else {
			annotations[types.NodeRecoveryAnnotation] = string(encoded)
		}
	}

	if witnessstatus.Received() {
		if status := witnessstatus.Get(); status.State != types.WitnessEtcdStateIdle {
			if encoded, err := json.Marshal(status); err != nil {
				log.Printf("warning: encode witness status: %v", err)
			} else {
				annotations[types.NodeWitnessAnnotation] = string(encoded)
			}
		}
	}

	var remove []string
	for _, key := range stampedAnnotations {
		if _, stamping := annotations[key]; !stamping && !absentAnnotations[key] {
			remove = append(remove, key)
		}
	}
	if len(remove) == 0 && (len(annotations) == 0 || sameAnnotations(annotations, lastStamped)) {
		return
	}
	patch, err := statusPatch(annotations, remove)
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
	for _, key := range stampedAnnotations {
		_, stamping := annotations[key]
		absentAnnotations[key] = !stamping
	}
}

// statusPatch is a merge patch setting the given annotations and deleting
// the named ones, which a merge patch does by setting them to null.
func statusPatch(set map[string]string, remove []string) ([]byte, error) {
	annotations := map[string]any{}
	for k, v := range set {
		annotations[k] = v
	}
	for _, k := range remove {
		annotations[k] = nil
	}
	return json.Marshal(map[string]any{"metadata": map[string]any{"annotations": annotations}})
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
