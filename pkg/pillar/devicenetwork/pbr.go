// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

const (
	// DPCBaseRTIndex : base index for per-port routing tables used for device
	// connectivity (between EVE and remote endpoints, such as the controller),
	// i.e. used for DevicePortConfig (abbreviated to DPC).
	// Routing table ID is a sum of the base with the interface index of the corresponding
	// physical interface.
	DPCBaseRTIndex = 500

	// NIBaseRTIndex : base index for per-NI (network instance) routing tables used
	// for uplink connectivity (between applications and remote endpoints).
	// Routing table ID is a sum of the base with the "bridge number" allocated
	// (and persisted) for every network instance.
	NIBaseRTIndex = 800

	// PbrLocalDestPrio : IP rule priority for packets destined to locally owned addresses
	PbrLocalDestPrio = 12000
	// PbrLocalOrigPrio : IP rule priority for locally generated packets
	PbrLocalOrigPrio = 15000

	// PbrNatOutGatewayPrio : IP rule priority for packets destined to gateway(bridge ip) coming from apps.
	PbrNatOutGatewayPrio = 9999
	// PbrNatOutPrio : IP rule priority for packets destined to internet coming from apps
	PbrNatOutPrio = 10000
	// PbrNatInPrio : IP rule priority for external packets coming in towards apps
	PbrNatInPrio = 11000
)
