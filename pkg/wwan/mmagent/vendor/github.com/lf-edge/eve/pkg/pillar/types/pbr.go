// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Constants for policy-based routing used in NIM and zedrouter.

package types

const (
	// KubeSvcRT : index of the routing table used for the Kubernetes service prefix.
	// Only used in the Kubevirt mode.
	KubeSvcRT = 400

	// DPCBaseRTIndex : base index for per-port routing tables used for device
	// connectivity (between EVE and remote endpoints, such as the controller),
	// i.e. used for DevicePortConfig (abbreviated to DPC).
	// Routing table ID is a sum of the base with the interface index of the corresponding
	// physical interface.
	DPCBaseRTIndex = 500

	// NIBaseRTIndex : base index for per-NI (network instance) routing tables used
	// for external connectivity (between applications and remote endpoints).
	// Routing table ID is a sum of the base with the "bridge number" allocated
	// (and persisted) for every network instance.
	NIBaseRTIndex = 800

	// PbrNatOutGatewayPrio : IP rule priority for packets destined to gateway(bridge ip) coming from apps.
	PbrNatOutGatewayPrio = 9999
	// PbrNatOutPrio : IP rule priority for packets destined to internet coming from apps
	PbrNatOutPrio = 10000
	// PbrNatInPrio : IP rule priority for external packets coming in towards apps
	PbrNatInPrio = 11000
	// PbrLocalDestPrio : IP rule priority for packets destined to locally owned addresses
	PbrLocalDestPrio = 12000
	// PbrKubeNetworkPrio : IP rule priority for traffic flowing through the Kubernetes
	// network.
	PbrKubeNetworkPrio = 13000
	// PbrLocalOrigPrio : IP rule priority for locally (dom0) generated packets
	PbrLocalOrigPrio = 15000
)
