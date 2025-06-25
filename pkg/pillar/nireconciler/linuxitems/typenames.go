// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

const (
	// VIFTypename : typename for VIF.
	VIFTypename = "VIF"
	// IPRuleTypename : typename for Linux IP rules.
	IPRuleTypename = "IPRule"
	// BridgeTypename : typename for Linux bridges.
	BridgeTypename = "Bridge"
	// BridgeFwdMaskTypename : typename for Linux bridge forwarding mask configuration.
	BridgeFwdMaskTypename = "BridgeFwdMask"
	// BridgePortTypename : typename for network interface added into a Linux bridge.
	BridgePortTypename = "BridgePort"
	// DummyIfTypename : typename for Linux dummy interface.
	DummyIfTypename = "DummyInterface"
	// VLANBridgeTypename : typename for (Linux bridge) enabled for VLANs.
	VLANBridgeTypename = "VLANBridge"
	// VLANPortTypename : typename for bridged port with configured VLAN(s).
	VLANPortTypename = "VLANPort"
	// SysctlTypename : typename for kernel config applied via sysctl.
	SysctlTypename = "Sysctl"
	// BPDUGuardTypename : typename for BPDU guard enabled on a bridge port.
	BPDUGuardTypename = "BPDUGuard"
	// TCIngressTypename : typename for TC-ingress qdisc.
	TCIngressTypename = "TCIngress"
	// TCMirrorTypename : typename for TC rule mirroring matched packets.
	TCMirrorTypename = "TCMirror"
)
