// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !k

package kubeapi

import (
	"context"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// WaitForKubernetesOptions is the options type for WaitForKubernetes.
// Defined here so callers can reference it without a build tag.
type WaitForKubernetesOptions struct {
	WaitForKubevirt bool
	WaitForLonghorn bool
}

// WaitForKubernetes in this file is just stub for non EVE-k builds.
func WaitForKubernetes(string, *pubsub.PubSub, *time.Ticker, string, WaitForKubernetesOptions,
	...pubsub.ChannelWatch) error {
	panic("WaitForKubernetes is not built")
}

// CleanupStaleVMIRs in this file is just stub for non EVE-k builds.
func CleanupStaleVMIRs() (int, error) {
	panic("CleanupStaleVMIRs is not built")
}

// GetPVCList in this file is just stub for non EVE-k builds.
func GetPVCList(*base.LogObject) ([]string, error) {
	panic("GetPVCList is not built")
}

// RequestNodeDrain is a stub for non EVE-k builds
func RequestNodeDrain(pubsub.Publication, DrainRequester, string) error {
	// Nothing to do here, just noop
	return fmt.Errorf("nokube requested drain, should not get here")
}

// GetNodeDrainStatus is a stub for non EVE-k builds
func GetNodeDrainStatus(pubsub.Subscription, *base.LogObject) *NodeDrainStatus {
	// No need to query for inprogress operations, just a noop
	return &NodeDrainStatus{Status: NOTSUPPORTED}
}

// IsClusterMode  is a stub for non EVE-k builds
func IsClusterMode(ps *pubsub.PubSub, log *base.LogObject, agentName string) bool {
	return false
}

// DetachOldWorkload is a stub for non EVE-k builds
func DetachOldWorkload(log *base.LogObject, virtLauncherPodName string) error {
	return nil
}

// GetSupportedReplicaCountForCluster is an empty implementation for non-kubevirt builds
func GetSupportedReplicaCountForCluster() (int, error) {
	return 0, nil
}

// GetStorageClassForReplicaCount is an empty implementation for non-kubevirt builds
func GetStorageClassForReplicaCount(count int) string {
	return ""
}

// ClusterStorageReadyForVolumes is a stub for non EVE-k builds (no cluster storage).
func ClusterStorageReadyForVolumes(*base.LogObject, string) bool {
	return true
}

// PVCAdoptionState mirrors the k-build type, with the same four values in
// the same order, so callers can reference it without a build tag. See the
// k-build definition for what each value means. Only PVCStateUnknown is ever
// returned on this build: there is no PVC/Longhorn concept to adopt from on
// classic hypervisors, so there is never anything to adopt and callers fall
// through to the normal ContentTree-gated path.
type PVCAdoptionState int

// These states mirror the k-build's meanings; see cdiupload.go there.
const (
	PVCStateUnknown PVCAdoptionState = iota
	PVCStateReady
	PVCStateNotReady
	PVCStateAbsent
)

// ProbePVCAdoption is a stub for non EVE-k builds.
func ProbePVCAdoption(string, *base.LogObject) PVCAdoptionState {
	return PVCStateUnknown
}

// EnsureVMsDeschedulerAnnotated is a stub for non EVE-k builds.
func EnsureVMsDeschedulerAnnotated(*base.LogObject) error {
	return nil
}

// WaitForLonghornReady is a stub for non EVE-k builds.
func WaitForLonghornReady(ctx context.Context, log *base.LogObject, nodeName string) error {
	return nil
}

// VolumeDirInternalEntriesMap is a stub for non EVE-k builds; returns empty map
// since Longhorn does not co-locate files in non-k configurations.
func VolumeDirInternalEntriesMap() map[string]struct{} {
	return map[string]struct{}{}
}
