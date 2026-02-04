// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Constants for policy-based routing used in NIM and zedrouter.

package types

const (
	// KubeSvcRT : index of the routing table used for the Kubernetes service prefix.
	// Only used in the EVE 'k' image.
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

	// For components that do not follow EVE's source-based routing and instead
	// use the main routing table (e.g., pulling Kubernetes system images for eve-k),
	// route metrics are assigned to reflect interface usage and priority.
	//
	// Each interface receives a unique metric to ensure deterministic ordering
	// of default routes in the main routing table. Metrics are derived from a
	// base value depending on interface usage and an incremental offset based on
	// interface cost and order within the configuration.

	// MgmtPortBaseMetric is the base metric value for all management ports.
	// The final metric for each management port is calculated as:
	//   MgmtPortBaseMetric + index_in_cost_order
	MgmtPortBaseMetric = 5000

	// AppSharedPortBaseMetric is the base metric value for all app-shared ports.
	// The final metric for each app-shared port is calculated as:
	//   AppSharedPortBaseMetric + index_in_cost_order
	AppSharedPortBaseMetric = 10000
)
