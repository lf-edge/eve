// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Type definitions of arguments used for RPC methods called by eve-bridge CNI plugin.
// Imported by both eve-bridge (RPC client) and pillar/zedrouter (RPC server).

package cnirpc

import (
	"net"

	uuid "github.com/satori/go.uuid"
)

// CommonCNIRPCArgs : arguments used for every CNI RPC method
// (called by eve-bridge, served by zedrouter).
type CommonCNIRPCArgs struct {
	Pod AppPod
	// Interface inside the pod.
	PodInterface NetInterfaceWithNs
}

// CommonCNIRPCRetval : a set of values returned by every CNI RPC method.
type CommonCNIRPCRetval struct {
	AppUUID uuid.UUID
}

// ConnectPodAtL2Args : arguments for the ConnectPodAtL2 RPC method.
type ConnectPodAtL2Args struct {
	CommonCNIRPCArgs
}

// ConnectPodAtL2Retval : type of the value returned by the ConnectPodAtL2 RPC method.
type ConnectPodAtL2Retval struct {
	CommonCNIRPCRetval
	UseDHCP bool
	// Interfaces include the bridge interface and both sides of the VETH connecting
	// pod with the host.
	Interfaces []NetInterfaceWithNs
}

// ConnectPodAtL3Args : arguments for the ConnectPodAtL3 RPC method.
type ConnectPodAtL3Args struct {
	CommonCNIRPCArgs
	PodIPAMConfig
}

// ConnectPodAtL3Retval : type of the value returned by the ConnectPodAtL3 RPC method.
type ConnectPodAtL3Retval struct {
	CommonCNIRPCRetval
}

// DisconnectPodArgs : arguments for the DisconnectPod RPC method.
type DisconnectPodArgs struct {
	CommonCNIRPCArgs
}

// DisconnectPodRetval : type of the value returned by the DisconnectPod RPC method.
type DisconnectPodRetval struct {
	CommonCNIRPCRetval
	UsedDHCP bool
}

// CheckPodConnectionArgs : arguments for the CheckPodConnection RPC method.
type CheckPodConnectionArgs struct {
	CommonCNIRPCArgs
}

// CheckPodConnectionRetval : type of the value returned by the CheckPodConnection RPC method.
type CheckPodConnectionRetval struct {
	CommonCNIRPCRetval
	UsesDHCP bool
}

// AppPod is defined only in the Kubernetes mode.
// It describes Kubernetes Pod under which a given app is running.
type AppPod struct {
	Name string
	// NetNsPath references network namespace of the Kubernetes pod
	// inside which the application is running.
	NetNsPath string
}

// NetInterfaceWithNs : single network interface (configured by zedrouter for Kube CNI).
type NetInterfaceWithNs struct {
	Name      string
	MAC       net.HardwareAddr
	NetNsPath string
}

// PodIPAMConfig : IP config assigned to Pod by a Kubernetes IPAM plugin.
type PodIPAMConfig struct {
	IPs    []PodIPAddress
	Routes []PodRoute
	DNS    PodDNS
}

// PodIPAddress : ip address assigned to kubernetes pod network interface.
type PodIPAddress struct {
	Address *net.IPNet
	Gateway net.IP
}

// PodRoute : network IP route configured for kubernetes pod network interface.
type PodRoute struct {
	Dst *net.IPNet
	GW  net.IP
}

// PodDNS : settings for DNS resolver inside a kubernetes pod.
type PodDNS struct {
	Nameservers []string
	Domain      string
	Search      []string
	Options     []string
}
