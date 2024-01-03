// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

const (
	// EVEKubeNameSpace : Common namespace for all EVE kubernetes components
	EVEKubeNameSpace = "eve-kube-app"
	// EVEkubeConfigFile : EVE k3s config file
	EVEkubeConfigFile = "/run/.kube/k3s/k3s.yaml"
	// NetworkInstanceNAD : name of (singleton) NAD used to define connection between
	// pod and (any) network instance.
	NetworkInstanceNAD = "network-instance-attachment"
	// VMIPodNamePrefix : prefix added to name of every pod created to run VM.
	VMIPodNamePrefix = "virt-launcher-"
	// VolumeCSINameSpace : EVE k3s storage default namespace
	VolumeCSINameSpace = "eve-kube-app"
	// VolumeCSIClusterStorageClass : CSI clustered storage class
	VolumeCSIClusterStorageClass = "longhorn"
	// VolumeCSILocalStorageClass : Default local storage class
	VolumeCSILocalStorageClass = "local-path"
)
