// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
)

// namePrefix is prepended to all domain (VM) names created by a device
// provider. This ensures that test/dev resources are clearly separated from
// user-managed objects. When listing devices, the prefix is stripped so that
// callers see only their original names.
const namePrefix = "ev-"

// networkPrefix is namePrefix without the "-" separator, used for
// network/bridge/VNet and TAP interface names instead of namePrefix. These
// names are not listed back to users and, for uplink/xconnect networks, are
// also used verbatim as Proxmox SDN VNet names, which are capped at 8
// characters, so they drop the separator to save space. It is a var, not a
// const, because Go does not treat string-slice expressions as constant
// expressions even when the operand is a constant.
var networkPrefix = strings.TrimSuffix(namePrefix, "-")

// uplinkNetwork is the name of the uplink network (dual-stack whenever an
// IPv6 uplink subnet is configured), used verbatim by all providers as both
// the internal bookkeeping key and the actual bridge/VNet resource name.
var uplinkNetwork = networkPrefix + "u"

// fullCapabilitySet returns all provider capabilities. It is advertised by the
// libvirt and qemu providers, which run on the local host and can apply the
// host-level network tweaks needed to forward link-local L2 protocols, and which
// support emulated TPM.
func fullCapabilitySet() []api.Capability {
	return []api.Capability{
		api.Capability_CAPABILITY_FORWARD_LACP,
		api.Capability_CAPABILITY_FORWARD_EAPOL,
		api.Capability_CAPABILITY_FORWARD_LLDP,
		api.Capability_CAPABILITY_TPM,
	}
}

// Used as a constant.
var ipv4Loopback = net.IPv4(127, 0, 0, 1)

// ErrNotFound indicates the named device was not found.
var ErrNotFound = errors.New("device not found")

// CommonProviderConf defines common network configuration shared by all providers.
type CommonProviderConf struct {
	// SDNUplinkIPv4Subnet is the IPv4 subnet of the uplink network
	// used for evetest SDN instances.
	SDNUplinkIPv4Subnet *net.IPNet

	// SDNUplinkIPv6Subnet is the IPv6 subnet of the uplink network,
	// enabling dual-stack (IPv4/IPv6) connectivity to evetest SDN instances.
	// If nil, the uplink network is IPv4-only.
	SDNUplinkIPv6Subnet *net.IPNet
}

// GetCommonProviderConf reads, validates, and derives the common provider
// network configuration from environment variables.
//
// It expects an IPv4 SDN uplink subnet to be provided, used for all uplink
// connectivity. An optional IPv6 SDN uplink subnet may also be provided to
// enable dual-stack connectivity.
func GetCommonProviderConf() (conf CommonProviderConf, err error) {
	// Read and parse the required SDN uplink IPv4 subnet.
	ipv4SubnetStr := viper.GetString(constants.SDNUplinkIPv4SubnetEnv)
	if ipv4SubnetStr == "" {
		return conf, fmt.Errorf("%s is undefined", constants.SDNUplinkIPv4SubnetEnv)
	}
	_, ipv4Subnet, err := net.ParseCIDR(ipv4SubnetStr)
	if err != nil {
		return conf, fmt.Errorf(
			"failed to parse %s: %w",
			constants.SDNUplinkIPv4SubnetEnv, err,
		)
	}

	// Ensure this is an IPv4 network.
	ones, bits := ipv4Subnet.Mask.Size()
	if bits != 32 {
		return conf, fmt.Errorf(
			"%s must be an IPv4 network, got %s",
			constants.SDNUplinkIPv4SubnetEnv, ipv4Subnet.String(),
		)
	}

	// Require at least a /30 to leave room for a gateway and DHCP addresses.
	if ones > 30 {
		return conf, fmt.Errorf(
			"maximum allowed prefix length for %s is /30, got /%d",
			constants.SDNUplinkIPv4SubnetEnv, ones,
		)
	}
	conf.SDNUplinkIPv4Subnet = ipv4Subnet

	// Read and parse the optional SDN uplink IPv6 subnet.
	ipv6SubnetStr := viper.GetString(constants.SDNUplinkIPv6SubnetEnv)
	if ipv6SubnetStr != "" {
		_, ipv6Subnet, err := net.ParseCIDR(ipv6SubnetStr)
		if err != nil {
			return conf, fmt.Errorf(
				"failed to parse %s: %w",
				constants.SDNUplinkIPv6SubnetEnv, err,
			)
		}

		// Ensure this is an IPv6 network.
		if ipv6Subnet.IP.To16() == nil || ipv6Subnet.IP.To4() != nil {
			return conf, fmt.Errorf(
				"%s must be an IPv6 network, got %s",
				constants.SDNUplinkIPv6SubnetEnv, ipv6Subnet.String(),
			)
		}

		conf.SDNUplinkIPv6Subnet = ipv6Subnet
	}

	return conf, nil
}

// archFromRuntime maps the Go runtime architecture to api.ArchType.
func archFromRuntime() ([]api.ArchType, error) {
	switch runtime.GOARCH {
	case "amd64":
		return []api.ArchType{api.ArchType_ARCH_AMD64}, nil
	case "arm64":
		return []api.ArchType{api.ArchType_ARCH_ARM64}, nil
	default:
		return nil, fmt.Errorf("unrecognized local runtime architecture: %s",
			runtime.GOARCH)
	}
}

// prefixedName converts external name -> internal provider-used name.
func prefixedName(name string) string {
	return namePrefix + name
}

// unprefixedName converts internal provider-used name back to external name.
// If the prefix doesn't match, returns empty string.
func unprefixedName(name string) string {
	if strings.HasPrefix(name, namePrefix) {
		return strings.TrimPrefix(name, namePrefix)
	}
	return ""
}

// xconnectBridgePrefix is the name prefix shared by all xconnect networks/bridges/VNets.
var xconnectBridgePrefix = networkPrefix + "x"

// xconnectNetworkName returns a short, deterministic name for a point-to-point
// link between two device interfaces, used verbatim by all providers as both
// the internal bookkeeping key and the actual bridge/VNet resource name. It
// hashes the (order-independent) device/interface pair with SHA1 and uses the
// first 5 hex characters to stay within Proxmox's 8-character VNet name limit.
func xconnectNetworkName(aDevice, aIface, bDevice, bIface string) string {
	devices := []string{aDevice + "-" + aIface, bDevice + "-" + bIface}
	if devices[0] > devices[1] {
		devices[0], devices[1] = devices[1], devices[0]
	}
	h := sha1.Sum([]byte(devices[0] + "-" + devices[1]))
	return xconnectBridgePrefix + hex.EncodeToString(h[:])[:5]
}

// generateTapName generates a short, deterministic TAP name by hashing the tuple
// (device name, interface name).
func generateTapName(devName, ifaceName string) string {
	h := sha1.Sum([]byte(devName + ":" + ifaceName))
	hash := hex.EncodeToString(h[:])[:5]
	return networkPrefix + "t" + hash
}

// enableLACPForwardingOnXConnectBridges sets the per-port
// IFLA_BRPORT_GROUP_FWD_MASK on all slave ports of every xconnect bridge
// (identified by the xconnectBridgePrefix name prefix) to allow LACPDU forwarding.
// The bridge-level group_fwd_mask cannot include LACP (bit 2) because the
// kernel rejects BR_GROUPFWD_RESTRICTED bits. However, the per-port mask
// does not have this restriction.
func enableLACPForwardingOnXConnectBridges() error {
	const lacpFwdMask = 0x4 // bit 2 = 01:80:C2:00:00:02 (LACPDU)
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links: %w", err)
	}
	// Build a set of xconnect bridge ifindexes.
	xconnectBridges := make(map[int]bool)
	for _, link := range links {
		if link.Type() == "bridge" &&
			strings.HasPrefix(link.Attrs().Name, xconnectBridgePrefix) {
			xconnectBridges[link.Attrs().Index] = true
		}
	}
	// Set per-port group_fwd_mask on all ports of xconnect bridges.
	for _, link := range links {
		if !xconnectBridges[link.Attrs().MasterIndex] {
			continue
		}
		if err := netlink.LinkSetBRSlaveGroupFwdMask(link, lacpFwdMask); err != nil {
			return fmt.Errorf("failed to set per-port group_fwd_mask on %q: %w",
				link.Attrs().Name, err)
		}
	}
	return nil
}
