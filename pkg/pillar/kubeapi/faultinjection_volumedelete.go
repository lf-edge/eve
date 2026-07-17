// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k && faultinjection

package kubeapi

import (
	"os"
)

// Fault-injection markers for the volume-delete path, mirroring the
// file-existence idiom of DrainStatusFaultInjectionWait. This file is compiled
// in only under the faultinjection build tag (FAULT_INJECTION=y), so production
// images never carry it; the no-op variant in
// faultinjection_volumedelete_disabled.go is used otherwise. When present, a
// test creates a marker to make a delete fail at a chosen layer, then removes it
// to observe recovery. Two markers target different layers so a test can pin
// down which operation failed:
//   - VolumeDestroyFaultPath makes volumeHandlerCSI.DestroyVolume fail for ANY
//     volume, including replicated ones (which otherwise skip the PVC delete),
//     so it exercises volumemgr's delete-retry loop directly.
//   - DeletePVCFaultPath makes kubeapi.DeletePVC fail, reproducing a realistic
//     k8s PVC-delete error on the non-replicated path.
const (
	VolumeDestroyFaultPath = "/tmp/VolumeDestroy_FaultInjection_Fail"
	DeletePVCFaultPath     = "/tmp/DeletePVC_FaultInjection_Fail"
)

// VolumeDestroyFaultInjected reports whether the DestroyVolume fault marker is
// present; while it is, DestroyVolume returns a synthetic error.
func VolumeDestroyFaultInjected() bool {
	_, err := os.Stat(VolumeDestroyFaultPath)
	return err == nil
}

// DeletePVCFaultInjected reports whether the DeletePVC fault marker is present;
// while it is, DeletePVC returns a synthetic error.
func DeletePVCFaultInjected() bool {
	_, err := os.Stat(DeletePVCFaultPath)
	return err == nil
}
