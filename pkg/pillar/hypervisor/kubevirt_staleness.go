// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"strconv"
	"strings"

	uuid "github.com/satori/go.uuid"
	appsv1 "k8s.io/api/apps/v1"
	v1 "kubevirt.io/api/core/v1"
)

// staleVMIRSGeneration reports whether vmirs is a superseded generation of
// the given app's VMIRS: it carries the app's App-Domain-Name label prefix
// ("<uuid>."), its object name differs from the desired generation's name,
// and its trailing purge-counter suffix parses as strictly less than
// desiredCounter.
//
// The label lives on Spec.Selector.MatchLabels (and the pod template),
// not on the VMIRS object's own ObjectMeta.Labels - CreateReplicaVMIConfig
// never sets that field at all - so this reads the selector, not
// vmirs.GetLabels().
//
// Name inequality, not label or version comparison, is what distinguishes
// "this generation" from "an older one": a non-purge config edit bumps the
// label's embedded config version without renaming the object, so a
// version-only rule would misclassify the current generation as stale.
//
// An unparsable or missing counter suffix is never considered stale, since
// there is nothing to safely compare it against.
func staleVMIRSGeneration(
	vmirs v1.VirtualMachineInstanceReplicaSet, appUUID uuid.UUID,
	desiredName string, desiredCounter uint32) bool {
	var label string
	if vmirs.Spec.Selector != nil {
		label = vmirs.Spec.Selector.MatchLabels[eveLabelKey]
	}
	if !strings.HasPrefix(label, appUUID.String()+".") {
		return false
	}
	name := vmirs.GetName()
	if name == desiredName {
		return false
	}
	counter, ok := trailingCounter(name)
	if !ok {
		return false
	}
	return counter < desiredCounter
}

// stalePodReplicaSetGeneration is staleVMIRSGeneration's analogue for a
// NOHYPER app's plain container ReplicaSet. Unlike the VMIRS case, this
// object's own ObjectMeta.Labels does carry the App-Domain-Name label -
// see CreateReplicaPodConfig - because there is no pre-existing convention
// on this type to follow instead.
func stalePodReplicaSetGeneration(
	rs appsv1.ReplicaSet, appUUID uuid.UUID, desiredName string, desiredCounter uint32) bool {
	label := rs.GetLabels()[eveLabelKey]
	if !strings.HasPrefix(label, appUUID.String()+".") {
		return false
	}
	name := rs.GetName()
	if name == desiredName {
		return false
	}
	counter, ok := trailingCounter(name)
	if !ok {
		return false
	}
	return counter < desiredCounter
}

// stalePodReplicaSetNames is staleVMIRSNames's ReplicaSet-Pod analogue.
func stalePodReplicaSetNames(
	list []appsv1.ReplicaSet, appUUID uuid.UUID, desiredName string, desiredCounter uint32) []string {
	var names []string
	for _, rs := range list {
		if stalePodReplicaSetGeneration(rs, appUUID, desiredName, desiredCounter) {
			names = append(names, rs.GetName())
		}
	}
	return names
}

// trailingCounter extracts the purge-counter suffix from a name of the form
// "<anything>-<counter>" (see base.GetAppKubeNameWithPurge), i.e. the
// digits after the last hyphen. ok is false if there is no hyphen or the
// suffix is not a valid non-negative integer.
func trailingCounter(name string) (counter uint32, ok bool) {
	idx := strings.LastIndex(name, "-")
	if idx < 0 || idx == len(name)-1 {
		return 0, false
	}
	n, err := strconv.ParseUint(name[idx+1:], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// staleVMIRSNames returns the names of every VMIRS in vmirsList that is a
// stale generation of appUUID's app, per staleVMIRSGeneration. Pure and
// side-effect free; callers are responsible for actually enumerating
// vmirsList from the cluster and for deleting whatever it returns.
func staleVMIRSNames(
	vmirsList []v1.VirtualMachineInstanceReplicaSet, appUUID uuid.UUID,
	desiredName string, desiredCounter uint32) []string {
	var names []string
	for _, vmirs := range vmirsList {
		if staleVMIRSGeneration(vmirs, appUUID, desiredName, desiredCounter) {
			names = append(names, vmirs.GetName())
		}
	}
	return names
}
