// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve-api/go/info"
)

// KubeCompUpdateStatus is the update progress of KubeComp
type KubeCompUpdateStatus uint8

// Enum of KubeCompUpdateStatus
const (
	CompStatusUnknown        KubeCompUpdateStatus = iota + 0 // CompStatusUnknown Unable to determine
	CompStatusDownload                                       // CompStatusDownload begun
	CompStatusDownloadFailed                                 // CompStatusDownloadFailed download failed
	CompStatusInProgress                                     // CompStatusInProgress update in progress
	CompStatusFailed                                         // CompStatusFailed update
	CompStatusCompleted                                      // CompStatusCompleted update
)

// KubeCompUpdateStatusFromStr converts a string representation to KubeCompUpdateStatus
func KubeCompUpdateStatusFromStr(status string) KubeCompUpdateStatus {
	switch status {
	case "download":
		return CompStatusDownload
	case "download_failed":
		return CompStatusDownloadFailed
	case "in_progress":
		return CompStatusInProgress
	case "failed":
		return CompStatusFailed
	case "completed":
		return CompStatusCompleted
	default:
		return CompStatusUnknown
	}
}

// KubeCompUpdateStatus converts KubeCompUpdateStatus to the eve-api info.KubeCompUpdateStatus
func (state KubeCompUpdateStatus) KubeCompUpdateStatus() info.KubeCompUpdateStatus {
	switch state {
	case CompStatusDownload:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_DOWNLOAD
	case CompStatusDownloadFailed:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_DOWNLOAD_FAILED
	case CompStatusInProgress:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_IN_PROGRESS
	case CompStatusFailed:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_FAILED
	case CompStatusCompleted:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_COMPLETED
	default:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_UNSPECIFIED
	}
}

// KubeComp is a Kubernetes Component / infrastructure service
type KubeComp uint8

// Enum of KubeComp
const (
	CompUnknown    KubeComp = iota + 0 // CompUnknown an unknown component defined
	CompContainerd                     // CompContainerd embedded containerd in k3s
	CompK3s                            // CompK3s k3s running in kube service container
	CompMultus                         // CompMultus networking services
	CompKubevirt                       // CompKubevirt vm services
	CompCdi                            // CompCdi disk image uploading
	CompLonghorn                       // CompLonghorn replicated storage volumes
)

// KubeCompFromStr converts from a string to KubeComp
func KubeCompFromStr(compStr string) KubeComp {
	switch compStr {
	case "containerd":
		return CompContainerd
	case "k3s":
		return CompK3s
	case "multus":
		return CompMultus
	case "kubevirt":
		return CompKubevirt
	case "cdi":
		return CompCdi
	case "longhorn":
		return CompLonghorn
	}
	return CompUnknown
}

// KubeComp converts from KubeComp to the eve-api info.KubeComp
func (comp KubeComp) KubeComp() info.KubeComp {
	switch comp {
	case CompContainerd:
		return info.KubeComp_KUBE_COMP_CONTAINERD
	case CompK3s:
		return info.KubeComp_KUBE_COMP_K3S
	case CompMultus:
		return info.KubeComp_KUBE_COMP_MULTUS
	case CompKubevirt:
		return info.KubeComp_KUBE_COMP_KUBEVIRT
	case CompCdi:
		return info.KubeComp_KUBE_COMP_CDI
	case CompLonghorn:
		return info.KubeComp_KUBE_COMP_LONGHORN
	}
	return info.KubeComp_KUBE_COMP_UNSPECIFIED
}

// KubeClusterUpdateStatus tracks the cluster update progress of various
// infrastructure components used for networking, hypervisor, and storage services.
type KubeClusterUpdateStatus struct {
	CurrentNode                  string
	Component                    KubeComp
	Status                       KubeCompUpdateStatus
	DestinationKubeUpdateVersion uint32

	// error strings across all steps/StorageStatus
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}
