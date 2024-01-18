// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

const (
	EVEKubeNameSpace  = "eve-kube-app"
	EVEkubeConfigFile = "/run/.kube/k3s/k3s.yaml"
	// NetworkInstanceNAD : name of (singleton) NAD used to define connection between
	// pod and (any) network instance.
	NetworkInstanceNAD = "network-instance-attachment"
	// EVE k3s default namespace
	VolumeCSINameSpace = "eve-kube-app"
	// CSI clustered storage class
	VolumeCSIClusterStorageClass = "longhorn"
	// Default local storage class
	VolumeCSILocalStorageClass = "local-path"
)
