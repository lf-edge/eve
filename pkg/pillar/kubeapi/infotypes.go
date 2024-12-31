// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

type KubeCompUpdateStatus uint8

const (
	COMP_STATUS_UNKNOWN         KubeCompUpdateStatus = iota + 0 // UNKNOWN Unable to determine
	COMP_STATUS_DOWNLOAD                                        // DOWNLOAD begun
	COMP_STATUS_DOWNLOAD_FAILED                                 // DOWNLOAD_FAILED
	COMP_STATUS_IN_PROGRESS                                     // IN_PROGRESS update in progress
	COMP_STATUS_FAILED                                          // FAILED update
	COMP_STATUS_COMPLETED                                       // COMPLETE update
)

func KubeCompUpdateStatusFromStr(status string) KubeCompUpdateStatus {
	switch status {
	case "download":
		return COMP_STATUS_DOWNLOAD
	case "download_failed":
		return COMP_STATUS_DOWNLOAD_FAILED
	case "in_progress":
		return COMP_STATUS_IN_PROGRESS
	case "failed":
		return COMP_STATUS_FAILED
	case "completed":
		return COMP_STATUS_COMPLETED
	default:
		return COMP_STATUS_UNKNOWN
	}
}

func (state KubeCompUpdateStatus) KubeCompUpdateStatus() info.KubeCompUpdateStatus {
	switch state {
	case COMP_STATUS_DOWNLOAD:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_DOWNLOAD
	case COMP_STATUS_DOWNLOAD_FAILED:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_DOWNLOAD_FAILED
	case COMP_STATUS_IN_PROGRESS:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_IN_PROGRESS
	case COMP_STATUS_FAILED:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_FAILED
	case COMP_STATUS_COMPLETED:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_COMPLETED
	default:
		return info.KubeCompUpdateStatus_KUBE_COMP_UPDATE_STATUS_UNSPECIFIED
	}
}

type KubeComp uint8

const (
	COMP_UNKNOWN KubeComp = iota + 0
	COMP_CONTAINERD
	COMP_K3S
	COMP_MULTUS
	COMP_KUBEVIRT
	COMP_CDI
	COMP_LONGHORN
)

func KubeCompFromStr(compStr string) KubeComp {
	switch compStr {
	case "containerd":
		return COMP_CONTAINERD
	case "k3s":
		return COMP_K3S
	case "multus":
		return COMP_MULTUS
	case "kubevirt":
		return COMP_KUBEVIRT
	case "cdi":
		return COMP_CDI
	case "longhorn":
		return COMP_LONGHORN
	}
	return COMP_UNKNOWN
}

func (comp KubeComp) KubeComp() info.KubeComp {
	switch comp {
	case COMP_CONTAINERD:
		return info.KubeComp_KUBE_COMP_CONTAINERD
	case COMP_K3S:
		return info.KubeComp_KUBE_COMP_K3S
	case COMP_MULTUS:
		return info.KubeComp_KUBE_COMP_MULTUS
	case COMP_KUBEVIRT:
		return info.KubeComp_KUBE_COMP_KUBEVIRT
	case COMP_CDI:
		return info.KubeComp_KUBE_COMP_CDI
	case COMP_LONGHORN:
		return info.KubeComp_KUBE_COMP_LONGHORN
	}
	return info.KubeComp_KUBE_COMP_UNSPECIFIED
}

type KubeClusterUpdateStatus struct {
	CurrentNode                  string
	Component                    KubeComp
	Status                       KubeCompUpdateStatus
	DestinationKubeUpdateVersion uint32

	// error strings across all steps/StorageStatus
	// ErrorAndTime provides SetErrorNow() and ClearError()
	types.ErrorAndTime
}
