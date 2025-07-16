// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/configitems"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	// Dependency graph modeling current/intended network configuration.
	// *SG are names of sub-graphs.
	configGraphName    = "SDN-Config"
	physicalIfsSG      = "Physical-Interfaces"
	tunnelIfsSG        = "Tunnel-Interfaces"
	trafficControlSG   = "Traffic-Control"
	hostConnectivitySG = "Host-Connectivity"
	bridgesSG          = "Bridges"
	firewallSG         = "Firewall"
	networkSGPrefix    = "Network-"
	endpointSGPrefix   = "Endpoint-"

	// Iptables chain used to implement firewall rules.
	fwIptablesChain = "firewall"

	// ifNameMaxLen is a limit for interface names in the Linux kernel (IFNAMSIZ).
	ifNameMaxLen = 15

	// Priority for IP rules directing traffic to per-network routing tables.
	networkSrcIPRulePriority = 300
	networkDstIPRulePriority = 400
	networkRTBaseIndex       = 500
)

var allIPv4, allIPv6 *net.IPNet

func init() {
	_, allIPv4, _ = net.ParseCIDR("0.0.0.0/0")
	_, allIPv6, _ = net.ParseCIDR("::/0")
}

// Update external items inside the graph with the current state.
func (a *agent) updateCurrentState() (changed bool) {
	if a.currentState == nil {
		graphArgs := dg.InitArgs{Name: configGraphName}
		a.currentState = dg.New(graphArgs)
		changed = true
	}
	currentPhysIfs := dg.New(dg.InitArgs{Name: physicalIfsSG})
	// Port connecting SDN VM with the host.
	netIf, found := a.macLookup.GetInterfaceByMAC(constants.SDNHostPortMACPrefix, true)
	if found {
		currentPhysIfs.PutItem(configitems.PhysIf{
			LogicalLabel: hostPortLogicalLabel,
			MAC:          netIf.MAC,
		}, &reconciler.ItemStateData{
			State:         reconciler.ItemStateCreated,
			LastOperation: reconciler.OperationCreate,
		})
	}
	// Ports to be connected with EVE VM(s).
	for _, port := range a.netModel.Ports {
		// MAC address is already validated
		mac, _ := net.ParseMAC(port.GetSdnMacAddress())
		if _, found := a.macLookup.GetInterfaceByMAC(mac, false); found {
			currentPhysIfs.PutItem(configitems.PhysIf{
				LogicalLabel: port.LogicalLabel,
				MAC:          mac,
			}, &reconciler.ItemStateData{
				State:         reconciler.ItemStateCreated,
				LastOperation: reconciler.OperationCreate,
			})
		}
	}
	// Is there any actual change?
	prevSG := a.currentState.SubGraph(physicalIfsSG)
	if prevSG == nil || len(prevSG.DiffItems(currentPhysIfs)) > 0 {
		a.currentState.PutSubGraph(currentPhysIfs)
		changed = true
	}
	return changed
}

// Update graph with the intended state based on the network model stored in a.netModel
func (a *agent) updateIntendedState() {
	a.allocNetworkIndexes()
	graphArgs := dg.InitArgs{Name: configGraphName}
	a.intendedState = dg.New(graphArgs)
	a.intendedState.PutSubGraph(a.getIntendedPhysIfs())
	a.intendedState.PutSubGraph(a.getIntendedTunIfs())
	a.intendedState.PutSubGraph(a.getIntendedHostConnectivity())
	a.intendedState.PutSubGraph(a.getIntendedTrafficControl())
	a.intendedState.PutSubGraph(a.getIntendedBridges())
	a.intendedState.PutSubGraph(a.getIntendedFirewall())
	for _, network := range a.netModel.GetNetworks() {
		a.intendedState.PutSubGraph(a.getIntendedNetwork(network))
	}
	for _, dnsSrv := range a.netModel.GetEndpoints().GetDnsServers() {
		a.intendedState.PutSubGraph(a.getIntendedDNSSrvEp(dnsSrv))
	}
	for _, proxy := range a.netModel.GetEndpoints().GetExplicitProxies() {
		a.intendedState.PutSubGraph(a.getIntendedExProxyEp(proxy))
	}
	for _, proxy := range a.netModel.GetEndpoints().GetTransparentProxies() {
		a.intendedState.PutSubGraph(a.getIntendedTProxyEp(proxy))
	}
	for _, httpSrv := range a.netModel.GetEndpoints().GetHttpServers() {
		a.intendedState.PutSubGraph(a.getIntendedHTTPSrvEp(httpSrv))
	}
	for _, scepSrv := range a.netModel.GetEndpoints().GetScepServers() {
		a.intendedState.PutSubGraph(a.getIntendedScepSrvEp(scepSrv))
	}

	//nolint:godox
	// TODO: ntp servers, netboot servers
}

func (a *agent) getIntendedPhysIfs() dg.Graph {
	graphArgs := dg.InitArgs{Name: physicalIfsSG}
	intendedCfg := dg.New(graphArgs)
	netIf, found := a.macLookup.GetInterfaceByMAC(constants.SDNHostPortMACPrefix, true)
	if found {
		intendedCfg.PutItem(configitems.PhysIf{
			LogicalLabel: hostPortLogicalLabel,
			MAC:          netIf.MAC,
		}, nil)
	}
	for _, port := range a.netModel.GetPorts() {
		// MAC address is already validated
		mac, _ := net.ParseMAC(port.GetSdnMacAddress())
		intendedCfg.PutItem(configitems.PhysIf{
			LogicalLabel: port.GetLogicalLabel(),
			MAC:          mac,
		}, nil)
	}
	return intendedCfg
}

func (a *agent) getIntendedTunIfs() dg.Graph {
	graphArgs := dg.InitArgs{Name: tunnelIfsSG}
	intendedCfg := dg.New(graphArgs)
	for _, tun := range a.tunnels {
		var ips []*net.IPNet
		for _, addr := range tun.IpAddresses {
			// Already validated in ConnectTunnel.
			ip, subnet, _ := net.ParseCIDR(addr)
			ips = append(ips, &net.IPNet{
				IP:   ip,
				Mask: subnet.Mask,
			})
		}
		intendedCfg.PutItem(configitems.Tun{
			IfName:      a.tunIfName(tun),
			ClientID:    tun.ClientId,
			MTU:         uint16(tun.Mtu),
			IPAddresses: ips,
		}, nil)
		for _, route := range tun.Routes {
			// Already validated in ConnectTunnel.
			_, dstNet, _ := net.ParseCIDR(route.DstNetwork)
			gwIP := net.ParseIP(route.Gateway)
			intendedCfg.PutItem(configitems.Route{
				NetNamespace: configitems.MainNsName,
				Table:        syscall.RT_TABLE_MAIN,
				DstNet:       dstNet,
				OutputIf: configitems.RouteOutIf{
					TunIfName: a.tunIfName(tun),
				},
				GwIP: gwIP,
			}, nil)
		}
	}
	return intendedCfg
}

func (a *agent) getIntendedHostConnectivity() dg.Graph {
	graphArgs := dg.InitArgs{Name: hostConnectivitySG}
	intendedCfg := dg.New(graphArgs)
	netIf, found := a.macLookup.GetInterfaceByMAC(constants.SDNHostPortMACPrefix, true)
	if !found {
		// Without interface connecting SDN with the host it is clearly
		// not possible to establish host connectivity.
		return intendedCfg
	}
	intendedCfg.PutItem(configitems.NetNamespace{
		NsName: configitems.MainNsName,
	}, nil)
	intendedCfg.PutItem(configitems.IfHandle{
		PhysIf: configitems.PhysIf{
			MAC:          netIf.MAC,
			LogicalLabel: hostPortLogicalLabel,
		},
		Usage:   configitems.IfUsageL3,
		AdminUP: true,
		MTU:     maxMTU,
	}, nil)
	intendedCfg.PutItem(configitems.Sysctl{
		EnableIPv4Forwarding:  true,
		EnableIPv6Forwarding:  true,
		BridgeNfCallIptables:  false,
		BridgeNfCallIP6tables: false,
		DisableIPv6DAD:        true,
	}, nil)
	intendedCfg.PutItem(configitems.DhcpClient{
		PhysIf: configitems.PhysIf{
			MAC:          netIf.MAC,
			LogicalLabel: hostPortLogicalLabel,
		},
		LogFile: "/run/dhcpcd.log",
	}, nil)
	intendedCfg.PutItem(configitems.IptablesChain{
		ChainName: "POSTROUTING",
		Table:     "nat",
		ForIPv6:   false,
		Rules: []configitems.IptablesRule{
			{
				Args:        []string{"-o", netIf.IfName, "-j", "MASQUERADE"},
				Description: "S-NAT traffic leaving SDN VM towards the host OS",
			},
		},
	}, nil)
	intendedCfg.PutItem(configitems.IptablesChain{
		ChainName: "POSTROUTING",
		Table:     "nat",
		ForIPv6:   true,
		Rules: []configitems.IptablesRule{
			{
				Args:        []string{"-o", netIf.IfName, "-j", "MASQUERADE"},
				Description: "S-NAT traffic leaving SDN VM towards the host OS",
			},
		},
	}, nil)
	return intendedCfg
}

func (a *agent) getIntendedTrafficControl() dg.Graph {
	graphArgs := dg.InitArgs{Name: trafficControlSG}
	intendedCfg := dg.New(graphArgs)
	emptyTC := &api.TrafficControl{}
	for _, port := range a.netModel.GetPorts() {
		if port.GetTrafficControl() == nil ||
			proto.Equal(port.GetTrafficControl(), emptyTC) {
			continue
		}
		// MAC address is already validated
		mac, _ := net.ParseMAC(port.GetSdnMacAddress())
		intendedCfg.PutItem(configitems.TrafficControl{
			TrafficControl: port.GetTrafficControl(),
			PhysIf: configitems.PhysIf{
				LogicalLabel: port.GetLogicalLabel(),
				MAC:          mac,
			},
		}, nil)
	}
	return intendedCfg
}

func (a *agent) getIntendedBridges() dg.Graph {
	graphArgs := dg.InitArgs{Name: bridgesSG}
	intendedCfg := dg.New(graphArgs)
	for _, port := range a.netModel.GetPorts() {
		labeledItem := a.netModel.items.getItem(
			(&api.Port{}).ItemType(), port.GetLogicalLabel())
		masterID, hasMaster := labeledItem.referencedBy[api.PortMasterRef]
		if !hasMaster {
			// Port is not really used.
			continue
		}
		mac, _ := net.ParseMAC(port.GetSdnMacAddress()) // already validated
		var usage configitems.IfUsage
		switch masterID.typename {
		case (&api.Bridge{}).ItemType():
			usage = configitems.IfUsageBridged
		case (&api.Bond{}).ItemType():
			usage = configitems.IfUsageAggregated
		}
		intendedCfg.PutItem(configitems.IfHandle{
			PhysIf: configitems.PhysIf{
				MAC:          mac,
				LogicalLabel: port.GetLogicalLabel(),
			},
			ParentLL: masterID.logicalLabel,
			Usage:    usage,
			AdminUP:  port.GetAdminUp(),
			MTU:      maxMTU,
		}, nil)
	}
	for _, bond := range a.netModel.GetBonds() {
		labeledItem := a.netModel.items.getItem(
			(&api.Bond{}).ItemType(), bond.GetLogicalLabel())
		var aggrPhysIfs []configitems.PhysIf
		for _, ref := range labeledItem.referencing {
			if ref.refKey == api.PortMasterRef {
				port := a.netModel.items[ref.itemID].LabeledItem
				mac, _ := net.ParseMAC(port.(*api.Port).GetSdnMacAddress())
				aggrPhysIfs = append(aggrPhysIfs, configitems.PhysIf{
					MAC:          mac,
					LogicalLabel: ref.logicalLabel,
				})
			}
		}
		intendedCfg.PutItem(configitems.Bond{
			Bond:              bond,
			IfName:            a.bondIfName(bond.GetLogicalLabel()),
			AggregatedPhysIfs: aggrPhysIfs,
			MTU:               maxMTU,
		}, nil)
	}
	for _, bridge := range a.netModel.GetBridges() {
		vlans := make(map[uint16]struct{})
		labeledItem := a.netModel.items.getItem(
			(&api.Bridge{}).ItemType(), bridge.GetLogicalLabel())
		for refKey, refBy := range labeledItem.referencedBy {
			if strings.HasPrefix(refKey, api.NetworkBridgeRefPrefix) {
				network := a.netModel.items[refBy].LabeledItem
				if vlanID := network.(*api.Network).VlanId; vlanID != 0 {
					vlans[uint16(vlanID)] = struct{}{}
				}
			} else if strings.HasPrefix(refKey, api.EndpointBridgeRefPrefix) {
				endpoint := a.getEndpoint(refBy.logicalLabel)
				if vlanID := endpoint.GetDirectL2Connect().GetVlanId(); vlanID != 0 {
					vlans[uint16(vlanID)] = struct{}{}
				}
			}
		}
		var vlanList []uint16
		for vlanID := range vlans {
			vlanList = append(vlanList, vlanID)
		}
		var bridgedPhysIfs []configitems.BridgedPhysIf
		var bridgedBonds []configitems.BridgedBondIf
		for _, ref := range labeledItem.referencing {
			if ref.refKey != api.PortMasterRef {
				continue
			}
			var accessVLAN uint16
			if bridge.GetPnac().GetEnable_8021X() {
				if a.isPortAuthenticated[ref.logicalLabel] {
					accessVLAN = uint16(bridge.GetPnac().GetPostAuthVlanId())
				} else {
					accessVLAN = uint16(bridge.GetPnac().GetPreAuthVlanId())
				}
			}
			switch ref.typename {
			case (&api.Port{}).ItemType():
				port := a.netModel.items[ref.itemID].LabeledItem
				mac, _ := net.ParseMAC(port.(*api.Port).GetSdnMacAddress())
				bridgedPhysIfs = append(bridgedPhysIfs, configitems.BridgedPhysIf{
					PhysIf: configitems.PhysIf{
						MAC:          mac,
						LogicalLabel: ref.logicalLabel,
					},
					AccessVLAN: accessVLAN,
				})
			case (&api.Bond{}).ItemType():
				bridgedBonds = append(bridgedBonds, configitems.BridgedBondIf{
					IfName:     a.bondIfName(ref.logicalLabel),
					AccessVLAN: accessVLAN,
				})
			}
		}
		brIfName := a.bridgeIfName(bridge.GetLogicalLabel())
		intendedCfg.PutItem(configitems.Bridge{
			IfName:       brIfName,
			LogicalLabel: bridge.GetLogicalLabel(),
			PhysIfs:      bridgedPhysIfs,
			BondIfs:      bridgedBonds,
			VLANs:        vlanList,
			MTU:          maxMTU,
			WithSTP:      bridge.GetWithStp(),
		}, nil)
		if bridge.GetPnac().GetEnable_8021X() {
			var eapUsers []configitems.EAPUser
			for _, user := range bridge.GetPnac().GetUsers() {
				eapUsers = append(eapUsers, configitems.EAPUser{
					Identity: user.GetIdentity(),
					Methods:  user.GetMethods(),
					Password: user.GetPassword(),
				})
			}
			intendedCfg.PutItem(configitems.Hostapd{
				DaemonName:       bridge.GetLogicalLabel(),
				BridgeIfName:     brIfName,
				CaCertPem:        bridge.GetPnac().GetCaCertPem(),
				CaKeyPem:         bridge.GetPnac().GetCaKeyPem(),
				Users:            eapUsers,
				ReauthGeneration: bridge.GetPnac().GetReauthGeneration(),
			}, nil)
		}
	}
	return intendedCfg
}

func (a *agent) getIntendedNetwork(network *api.Network) dg.Graph {
	graphArgs := dg.InitArgs{Name: networkSGPrefix + network.GetLogicalLabel()}
	intendedCfg := dg.New(graphArgs)

	// Process IP configuration.
	ipv4Subnet, gwIPv4, dhcpv4 := a.getNetworkIPConf(network, false)
	ipv6Subnet, gwIPv6, dhcpv6 := a.getNetworkIPConf(network, true)
	gwIPs := filterOutNilAddrs(gwIPv4, gwIPv6)
	vethInIPv4, vethOutIPv4, vethInIPv6, vethOutIPv6 := a.getNetworkRtVethIPs(network)
	vethInIPs := filterOutNilAddrs(vethInIPv4, vethInIPv6)
	vethOutIPs := filterOutNilAddrs(vethOutIPv4, vethOutIPv6)
	var (
		ipv4DNSServers []net.IP
		ipv6DNSServers []net.IP
		allDNSServers  []net.IP
	)
	if ipv4Subnet != nil {
		for _, dnsServer := range dhcpv4.GetDns().GetPublicDns() {
			ipv4DNSServers = append(ipv4DNSServers, net.ParseIP(dnsServer))
		}
		for _, dnsServer := range dhcpv4.GetDns().GetPrivateDns() {
			ep := a.getEndpoint(dnsServer)
			epIPv4, _ := a.getEndpointIP(ep, false)
			if epIPv4 != nil {
				ipv4DNSServers = append(ipv4DNSServers, epIPv4)
			}
		}
	}
	if ipv6Subnet != nil {
		for _, dnsServer := range dhcpv6.GetDns().GetPublicDns() {
			ipv6DNSServers = append(ipv6DNSServers, net.ParseIP(dnsServer))
		}
		for _, dnsServer := range dhcpv6.GetDns().GetPrivateDns() {
			ep := a.getEndpoint(dnsServer)
			epIPv6, _ := a.getEndpointIP(ep, true)
			if epIPv6 != nil {
				ipv6DNSServers = append(ipv6DNSServers, epIPv6)
			}
		}
	}
	allDNSServers = append([]net.IP{}, ipv4DNSServers...)
	allDNSServers = append(allDNSServers, ipv6DNSServers...)

	// Network namespace connected with the bridge using veth.
	brVethName, brInIfName, brOutIfName := a.networkBrVethName(network.LogicalLabel)
	nsName := a.networkNsName(network.LogicalLabel)
	netNs := configitems.NetNamespace{
		NsName: nsName,
	}
	intendedCfg.PutItem(netNs, nil)
	intendedCfg.PutItem(configitems.Sysctl{
		NetNamespace:          nsName,
		EnableIPv4Forwarding:  true,
		EnableIPv6Forwarding:  true,
		BridgeNfCallIptables:  true,
		BridgeNfCallIP6tables: true,
		DisableIPv6DAD:        true,
	}, nil)
	intendedCfg.PutItem(configitems.Veth{
		VethName: brVethName,
		Peer1: configitems.VethPeer{
			IfName:       brInIfName,
			NetNamespace: nsName,
			IPAddresses:  gwIPs,
			MTU:          uint16(network.Mtu),
		},
		Peer2: configitems.VethPeer{
			IfName:       brOutIfName,
			NetNamespace: configitems.MainNsName,
			MasterBridge: &configitems.MasterBridge{
				IfName: a.bridgeIfName(network.Bridge),
				VLAN:   uint16(network.VlanId),
			},
			MTU: uint16(network.Mtu),
		},
	}, nil)

	// Another veth used to connect network with the main "router".
	rtVethName, rtInIfName, rtOutIfName := a.networkRtVethName(network.GetLogicalLabel())
	intendedCfg.PutItem(configitems.Veth{
		VethName: rtVethName,
		Peer1: configitems.VethPeer{
			IfName:       rtInIfName,
			NetNamespace: nsName,
			IPAddresses:  vethInIPs,
			MTU:          uint16(network.GetMtu()),
		},
		Peer2: configitems.VethPeer{
			IfName:       rtOutIfName,
			NetNamespace: configitems.MainNsName,
			IPAddresses:  vethOutIPs,
			MTU:          uint16(network.GetMtu()),
		},
	}, nil)

	// DHCP server.
	if dhcpv4.GetEnable() || dhcpv6.GetEnable() {
		dhcpIPv4Subnet := ipv4Subnet
		if !dhcpv4.GetEnable() {
			dhcpIPv4Subnet = nil
		}
		dhcpIPv6Subnet := ipv6Subnet
		if !dhcpv6.GetEnable() {
			dhcpIPv6Subnet = nil
		}
		var ipv4Range, ipv6Range configitems.IPRange
		if dhcpIPv4Subnet != nil {
			ipv4Range = a.subnetToHostIPRange(dhcpIPv4Subnet)
			if dhcpv4.GetIpRange().GetFromIp() != "" {
				ipv4Range.FromIP = net.ParseIP(dhcpv4.GetIpRange().GetFromIp())
				ipv4Range.ToIP = net.ParseIP(dhcpv4.GetIpRange().GetToIp())
			}
		}
		if dhcpIPv6Subnet != nil {
			ipv6Range = a.subnetToHostIPRange(dhcpIPv6Subnet)
			if dhcpv6.GetIpRange().GetFromIp() != "" {
				ipv6Range.FromIP = net.ParseIP(dhcpv6.GetIpRange().GetFromIp())
				ipv6Range.ToIP = net.ParseIP(dhcpv6.GetIpRange().GetToIp())
			}
		}
		ipv4NtpServer := dhcpv4.GetPublicNtp()
		if dhcpv4.GetPrivateNtp() != "" {
			ep := a.getEndpoint(dhcpv4.GetPrivateNtp())
			epIPv4, _ := a.getEndpointIP(ep, false)
			if epIPv4 != nil {
				ipv4NtpServer = epIPv4.String()
			}
		}
		ipv6NtpServer := dhcpv6.GetPublicNtp()
		if dhcpv6.GetPrivateNtp() != "" {
			ep := a.getEndpoint(dhcpv6.GetPrivateNtp())
			epIPv6, _ := a.getEndpointIP(ep, true)
			if epIPv6 != nil {
				ipv4NtpServer = epIPv6.String()
			}
		}
		var gatewayIPv4 net.IP
		if gwIPv4 != nil && !dhcpv4.GetWithoutDefaultRoute() {
			gatewayIPv4 = gwIPv4.IP
		}
		var staticEntries []configitems.MACToIP
		if dhcpv4.GetEnable() {
			for _, entry := range dhcpv4.GetStaticEntries() {
				mac, _ := net.ParseMAC(entry.GetMac())
				staticEntries = append(staticEntries, configitems.MACToIP{
					MAC: mac,
					IP:  net.ParseIP(entry.GetIp()),
				})
			}
		}
		if dhcpv6.GetEnable() {
			for _, entry := range dhcpv6.GetStaticEntries() {
				mac, _ := net.ParseMAC(entry.GetMac())
				staticEntries = append(staticEntries, configitems.MACToIP{
					MAC: mac,
					IP:  net.ParseIP(entry.GetIp()),
				})
			}
		}
		// It is already validated that IPv4 and IPv6 config do not define different
		// domain names.
		var domainName string
		if dhcpv4.GetEnable() && dhcpv4.GetDomainName() != "" {
			domainName = dhcpv4.GetDomainName()
		} else if dhcpv6.GetEnable() {
			domainName = dhcpv6.GetDomainName()
		}
		var ipv4LeaseTime, ipv6LeaseTime time.Duration
		if ls := dhcpv4.GetLeaseTimeSeconds(); ls > 0 {
			ipv4LeaseTime = time.Duration(ls) * time.Second
		}
		if ls := dhcpv6.GetLeaseTimeSeconds(); ls > 0 {
			ipv6LeaseTime = time.Duration(ls) * time.Second
		}
		intendedCfg.PutItem(configitems.DhcpServer{
			ServerName:     network.GetLogicalLabel(),
			NetNamespace:   nsName,
			VethName:       brVethName,
			VethPeerIfName: brInIfName,
			IPv4Subnet:     dhcpIPv4Subnet,
			IPv6Subnet:     dhcpIPv6Subnet,
			IPv4Range:      ipv4Range,
			IPv6Range:      ipv6Range,
			StaticEntries:  staticEntries,
			GatewayIPv4:    gatewayIPv4,
			DomainName:     domainName,
			DNSServers:     allDNSServers,
			IPv4NTPServer:  ipv4NtpServer,
			IPv6NTPServer:  ipv6NtpServer,
			WPAD:           dhcpv4.GetWpad(),
			IPv4LeaseTime:  ipv4LeaseTime,
			IPv6LeaseTime:  ipv6LeaseTime,
		}, nil)
	}

	// IPv6 router advertisement.
	if ipv6Subnet != nil {
		advManagedFlag := dhcpv6.GetEnable() && dhcpv6.GetIpRange().GetFromIp() != ""
		advAutonomous := !advManagedFlag
		advOtherConfigFlag := dhcpv6.GetEnable() &&
			(dhcpv6.GetPrivateNtp() != "" || dhcpv6.GetPublicNtp() != "")
		advDNSServers := ipv6DNSServers
		if advManagedFlag || advOtherConfigFlag {
			// If DHCPv6 is being used, do not advertise DNS servers twice.
			advDNSServers = nil
		}
		intendedCfg.PutItem(configitems.Radvd{
			DaemonName:          network.GetLogicalLabel(),
			NetNamespace:        nsName,
			VethName:            brVethName,
			VethPeerIfName:      brInIfName,
			Subnet:              ipv6Subnet,
			MTU:                 uint16(network.GetMtu()),
			AdvManagedFlag:      advManagedFlag,
			AdvOtherConfigFlag:  advOtherConfigFlag,
			AdvAutonomous:       advAutonomous,
			DNSServers:          advDNSServers,
			WithoutDefaultRoute: dhcpv6.GetWithoutDefaultRoute(),
		}, nil)
	}

	// Transparent proxy.
	if network.GetTransparentProxy() != "" {
		ep := a.getEndpoint(network.GetTransparentProxy())
		httpsPorts := []*api.ProxyPort{{Port: 443}}
		controllerPort := a.netModel.GetControllerConfig().GetControllerPort()
		if controllerPort != 443 {
			httpsPorts = append(httpsPorts, &api.ProxyPort{Port: controllerPort})
		}
		epIPv4, _ := a.getEndpointIP(ep, false)
		epIPv6, _ := a.getEndpointIP(ep, true)
		if epIPv4 != nil {
			intendedCfg.PutItem(
				a.getIptablesChainForTranspProxy(nsName, epIPv4, httpsPorts), nil)
		}
		if epIPv6 != nil {
			intendedCfg.PutItem(
				a.getIptablesChainForTranspProxy(nsName, epIPv6, httpsPorts), nil)
		}
	}

	// When user is accessing EVE using "sdn fwd" command, the source IP
	// is from the internal IP subnet.
	// Make sure that the IP address is S-NATed before sending packets to EVE.
	// Otherwise, the responses could be routed out via wrong EVE network ports.
	intendedCfg.PutItem(configitems.IptablesChain{
		NetNamespace: nsName,
		ChainName:    "POSTROUTING",
		Table:        "nat",
		ForIPv6:      false,
		RefersVeths:  []string{rtVethName},
		Rules: []configitems.IptablesRule{
			{
				Args: []string{"-o", brInIfName, "-s", internalIPv4Subnet.String(),
					"-j", "MASQUERADE"},
				Description: "S-NAT traffic leaving SDN VM towards EVE with internal source IP",
			},
		},
	}, nil)
	intendedCfg.PutItem(configitems.IptablesChain{
		NetNamespace: nsName,
		ChainName:    "POSTROUTING",
		Table:        "nat",
		ForIPv6:      true,
		RefersVeths:  []string{rtVethName},
		Rules: []configitems.IptablesRule{
			{
				Args: []string{"-o", brInIfName, "-s", internalIPv6Subnet.String(),
					"-j", "MASQUERADE"},
				Description: "S-NAT traffic leaving SDN VM towards EVE with internal source IP",
			},
		},
	}, nil)

	// Add routing configuration.
	a.getIntendedNetworkRouting(network, intendedCfg)
	return intendedCfg
}

func (a *agent) getIntendedNetworkRouting(network *api.Network, intendedCfg dg.Graph) {
	nsName := a.networkNsName(network.GetLogicalLabel())
	index, hasIndex := a.networkIndex[network.GetLogicalLabel()]
	if !hasIndex {
		log.Fatalf("missing index for network %s", network.LogicalLabel)
	}
	rt := networkRTBaseIndex + index

	ipv4Subnet, _, _ := a.getNetworkIPConf(network, false)
	ipv6Subnet, _, _ := a.getNetworkIPConf(network, true)
	rtVethName, rtInIfName, rtOutIfName := a.networkRtVethName(network.GetLogicalLabel())
	brVethName, brInIfName, _ := a.networkBrVethName(network.GetLogicalLabel())
	vethInIPv4, vethOutIPv4, vethInIPv6, vethOutIPv6 := a.getNetworkRtVethIPs(network)

	if ipv4Subnet != nil {
		intendedCfg.PutItem(configitems.IPRule{
			SrcNet:   ipv4Subnet,
			Table:    rt,
			Priority: networkSrcIPRulePriority,
		}, nil)
		intendedCfg.PutItem(configitems.IPRule{
			DstNet:   ipv4Subnet,
			Table:    rt,
			Priority: networkDstIPRulePriority,
		}, nil)
	}
	if ipv6Subnet != nil {
		intendedCfg.PutItem(configitems.IPRule{
			SrcNet:   ipv6Subnet,
			Table:    rt,
			Priority: networkSrcIPRulePriority,
		}, nil)
		intendedCfg.PutItem(configitems.IPRule{
			DstNet:   ipv6Subnet,
			Table:    rt,
			Priority: networkDstIPRulePriority,
		}, nil)
	}

	// - default route from inside the network namespace
	if ipv4Subnet != nil {
		intendedCfg.PutItem(configitems.Route{
			NetNamespace: nsName,
			Table:        syscall.RT_TABLE_MAIN,
			DstNet:       allIPv4,
			OutputIf: configitems.RouteOutIf{
				VethName:       rtVethName,
				VethPeerIfName: rtInIfName,
			},
			GwIP: vethOutIPv4.IP,
		}, nil)
	}
	if ipv6Subnet != nil {
		intendedCfg.PutItem(configitems.Route{
			NetNamespace: nsName,
			Table:        syscall.RT_TABLE_MAIN,
			DstNet:       allIPv6,
			OutputIf: configitems.RouteOutIf{
				VethName:       rtVethName,
				VethPeerIfName: rtInIfName,
			},
			GwIP: vethOutIPv6.IP,
		}, nil)
	}

	// - route for every L3-connected endpoint
	epTypename := (&api.Endpoint{}).ItemType()
	for itemID, item := range a.netModel.items {
		if itemID.typename != epTypename {
			continue
		}
		ep := a.labeledItemToEndpoint(item)
		if ep.GetDirectL2Connect().GetBridge() != "" {
			// This endpoint has direct L2 connection to EVE, skip.
			continue
		}
		epIPv4, epIPv4Subnet := a.getEndpointIP(ep, false)
		epIPv6, epIPv6Subnet := a.getEndpointIP(ep, true)
		reachable := network.GetRouter() == nil ||
			generics.ContainsItem(network.GetRouter().GetReachableEndpoints(),
				ep.GetLogicalLabel())
		if reachable {
			epVethName, _, epOutIfName := a.endpointVethName(ep.GetLogicalLabel())
			if epIPv4Subnet != nil {
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       epIPv4Subnet,
					OutputIf: configitems.RouteOutIf{
						VethName:       epVethName,
						VethPeerIfName: epOutIfName,
					},
					GwIP: epIPv4,
				}, nil)
			}
			if epIPv6Subnet != nil {
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       epIPv6Subnet,
					OutputIf: configitems.RouteOutIf{
						VethName:       epVethName,
						VethPeerIfName: epOutIfName,
					},
					GwIP: epIPv6,
				}, nil)
			}
		} else {
			if epIPv4Subnet != nil {
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       epIPv4Subnet,
				}, nil)
			}
			if epIPv6Subnet != nil {
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       epIPv6Subnet,
				}, nil)
			}
		}
	}

	// - route for every other network (including itself)
	for _, network2 := range a.netModel.GetNetworks() {
		net2IPv4Subnet, _, _ := a.getNetworkIPConf(network2, false)
		net2IPv6Subnet, _, _ := a.getNetworkIPConf(network2, true)
		reachable := network.GetRouter() == nil ||
			network2.GetLogicalLabel() == network.GetLogicalLabel() ||
			generics.ContainsItem(
				network.GetRouter().GetReachableNetworks(),
				network2.GetLogicalLabel())
		if reachable {
			net2VethName, _, net2OutIfName := a.networkRtVethName(network2.GetLogicalLabel())
			if net2IPv4Subnet != nil {
				net2VethInIPv4, _ := a.genVethIPsForNetwork(
					network2.GetLogicalLabel(), false)
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       net2IPv4Subnet,
					OutputIf: configitems.RouteOutIf{
						VethName:       net2VethName,
						VethPeerIfName: net2OutIfName,
					},
					GwIP: net2VethInIPv4.IP,
				}, nil)
			}
			if net2IPv6Subnet != nil {
				net2VethInIPv6, _ := a.genVethIPsForNetwork(
					network2.GetLogicalLabel(), true)
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       net2IPv6Subnet,
					OutputIf: configitems.RouteOutIf{
						VethName:       net2VethName,
						VethPeerIfName: net2OutIfName,
					},
					GwIP: net2VethInIPv6.IP,
				}, nil)
			}
		} else {
			if net2IPv4Subnet != nil {
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       net2IPv4Subnet,
				}, nil)
			}
			if net2IPv6Subnet != nil {
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       net2IPv6Subnet,
				}, nil)
			}
		}
	}

	// - link-local routes for the tunnel subnets
	//   (this is always installed to per-network RTs, for evetest to be able to reach
	//    EVE network even if it does not have outside reachability enabled)
	for _, tun := range a.tunnels {
		for _, addr := range tun.IpAddresses {
			// Already validated in ConnectTunnel.
			_, tunNet, _ := net.ParseCIDR(addr)
			intendedCfg.PutItem(configitems.Route{
				NetNamespace: configitems.MainNsName,
				Table:        rt,
				DstNet:       tunNet,
				OutputIf: configitems.RouteOutIf{
					TunIfName: a.tunIfName(tun),
				},
			}, nil)
		}
	}

	// - route for the outside world if enabled
	outsideRechability := network.GetRouter() == nil ||
		network.GetRouter().GetOutsideReachability()
	hostPort, hostPortfound := a.macLookup.GetInterfaceByMAC(
		constants.SDNHostPortMACPrefix, true)
	if outsideRechability {
		if hostPortfound {
			hostGwIPv4 := a.getHostGwIP(false)
			if hostGwIPv4 != nil {
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       allIPv4,
					OutputIf: configitems.RouteOutIf{
						PhysIf: configitems.PhysIf{
							MAC:          hostPort.MAC,
							LogicalLabel: hostPortLogicalLabel,
						},
					},
					GwIP: hostGwIPv4,
				}, nil)
			}
			hostGwIPv6 := a.getHostGwIP(true)
			if hostGwIPv6 != nil {
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       allIPv6,
					OutputIf: configitems.RouteOutIf{
						PhysIf: configitems.PhysIf{
							MAC:          hostPort.MAC,
							LogicalLabel: hostPortLogicalLabel,
						},
					},
					GwIP: hostGwIPv6,
				}, nil)
			}
		}
		for _, tun := range a.tunnels {
			for _, route := range tun.Routes {
				// Already validated in ConnectTunnel.
				_, dstNet, _ := net.ParseCIDR(route.DstNetwork)
				gwIP := net.ParseIP(route.Gateway)
				intendedCfg.PutItem(configitems.Route{
					NetNamespace: configitems.MainNsName,
					Table:        rt,
					DstNet:       dstNet,
					OutputIf: configitems.RouteOutIf{
						TunIfName: a.tunIfName(tun),
					},
					GwIP: gwIP,
				}, nil)
			}
		}
	}

	// - routes towards EVE
	routesTowardsEVE := network.GetRouter().GetRoutesTowardsEve()
	for _, route := range routesTowardsEVE {
		_, dstNetwork, _ := net.ParseCIDR(route.GetDstNetwork())
		ipv4 := dstNetwork.IP.To4() != nil
		gatewayIP := net.ParseIP(route.GetGateway())
		intendedCfg.PutItem(configitems.IPRule{
			SrcNet:   dstNetwork,
			Table:    rt,
			Priority: networkSrcIPRulePriority,
		}, nil)
		intendedCfg.PutItem(configitems.IPRule{
			DstNet:   dstNetwork,
			Table:    rt,
			Priority: networkDstIPRulePriority,
		}, nil)
		intendedCfg.PutItem(configitems.Route{
			NetNamespace: nsName,
			Table:        syscall.RT_TABLE_MAIN,
			DstNet:       dstNetwork,
			OutputIf: configitems.RouteOutIf{
				VethName:       brVethName,
				VethPeerIfName: brInIfName,
			},
			GwIP: gatewayIP,
		}, nil)
		if ipv4 && ipv4Subnet != nil {
			intendedCfg.PutItem(configitems.Route{
				NetNamespace: configitems.MainNsName,
				Table:        rt,
				DstNet:       dstNetwork,
				OutputIf: configitems.RouteOutIf{
					VethName:       rtVethName,
					VethPeerIfName: rtOutIfName,
				},
				GwIP: vethInIPv4.IP,
			}, nil)
		}
		if !ipv4 && ipv6Subnet != nil {
			intendedCfg.PutItem(configitems.Route{
				NetNamespace: configitems.MainNsName,
				Table:        rt,
				DstNet:       dstNetwork,
				OutputIf: configitems.RouteOutIf{
					VethName:       rtVethName,
					VethPeerIfName: rtOutIfName,
				},
				GwIP: vethInIPv6.IP,
			}, nil)
		}
	}

	// - everything else is unreachable
	intendedCfg.PutItem(configitems.Route{
		NetNamespace: configitems.MainNsName,
		Table:        rt,
		DstNet:       allIPv4,
		Metric:       ^uint32(0), // Lowest prio.
	}, nil)
	intendedCfg.PutItem(configitems.Route{
		NetNamespace: configitems.MainNsName,
		Table:        rt,
		DstNet:       allIPv6,
		Metric:       ^uint32(0), // Lowest prio.
	}, nil)
}

// Returns chain with iptables rules to transparently redirect traffic into a proxy.
func (a *agent) getIptablesChainForTranspProxy(
	nsName string, epIP net.IP, httpsPorts []*api.ProxyPort) configitems.IptablesChain {
	dnatRules := []configitems.IptablesRule{
		{
			Args: []string{"-p", "tcp", "--dport", "80", "-j", "DNAT",
				"--to-destination", epIP.String()},
			Description: "Send HTTP traffic into the proxy",
		},
	}
	for _, httpsPort := range httpsPorts {
		dnatRules = append(dnatRules, configitems.IptablesRule{
			Args: []string{"-p", "tcp", "--dport", strconv.Itoa(int(httpsPort.Port)),
				"-j", "DNAT", "--to-destination", epIP.String()},
			Description: fmt.Sprintf("Send HTTPS traffic (port %d) into the proxy",
				httpsPort.Port),
		})
	}
	return configitems.IptablesChain{
		NetNamespace: nsName,
		ChainName:    "PREROUTING",
		Table:        "nat",
		ForIPv6:      false,
		Rules:        dnatRules,
	}
}

func (a *agent) getIntendedFirewall() dg.Graph {
	graphArgs := dg.InitArgs{Name: firewallSG}
	intendedCfg := dg.New(graphArgs)
	iptablesRules := make([]configitems.IptablesRule, 0,
		2+len(a.netModel.GetFirewall().GetRules()))
	ip6tablesRules := make([]configitems.IptablesRule, 0,
		2+len(a.netModel.GetFirewall().GetRules()))
	// Allow any subsequent traffic that results from an already allowed connection.
	matchAlreadyAllowed := configitems.IptablesRule{
		Args: []string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	iptablesRules = append(iptablesRules, matchAlreadyAllowed)
	ip6tablesRules = append(ip6tablesRules, matchAlreadyAllowed)
	// Add explicitly configured firewall rules.
	for _, rule := range a.netModel.GetFirewall().GetRules() {
		iptablesRule, ip6tablesRule := a.getIntendedFwRule(rule)
		if len(iptablesRule.Args) != 0 {
			iptablesRules = append(iptablesRules, iptablesRule)
		}
		if len(ip6tablesRule.Args) != 0 {
			ip6tablesRules = append(ip6tablesRules, ip6tablesRule)
		}
	}
	// Implicitly allow everything not matched by the rules above.
	allowTheRest := &api.FwRule{Action: api.FwAction_FW_ALLOW}
	iptablesRule, ip6tablesRule := a.getIntendedFwRule(allowTheRest)
	iptablesRules = append(iptablesRules, iptablesRule)
	ip6tablesRules = append(ip6tablesRules, ip6tablesRule)
	intendedCfg.PutItem(configitems.IptablesChain{
		NetNamespace: configitems.MainNsName,
		ChainName:    fwIptablesChain,
		Table:        "filter",
		ForIPv6:      false,
		Rules:        iptablesRules,
	}, nil)
	intendedCfg.PutItem(configitems.IptablesChain{
		NetNamespace: configitems.MainNsName,
		ChainName:    fwIptablesChain,
		Table:        "filter",
		ForIPv6:      true,
		Rules:        ip6tablesRules,
	}, nil)
	// Link the firewall chain with every network and endpoint (outside) interface.
	veths := make([]string, 0,
		len(a.netModel.GetNetworks())+len(a.netModel.GetEndpoints().GetAll()))
	iptablesRules = nil
	for _, network := range a.netModel.GetNetworks() {
		rtVethName, _, rtOutIfName := a.networkRtVethName(network.GetLogicalLabel())
		veths = append(veths, rtVethName)
		iptablesRules = append(iptablesRules, configitems.IptablesRule{
			Args: []string{"-i", rtOutIfName, "-j", fwIptablesChain},
		})
	}
	for _, ep := range a.netModel.GetEndpoints().GetAll() {
		epVethName, _, epOutIfName := a.endpointVethName(ep.GetLogicalLabel())
		veths = append(veths, epVethName)
		iptablesRules = append(iptablesRules, configitems.IptablesRule{
			Args: []string{"-i", epOutIfName, "-j", fwIptablesChain},
		})
	}
	intendedCfg.PutItem(configitems.IptablesChain{
		NetNamespace: configitems.MainNsName,
		ChainName:    "FORWARD",
		Table:        "filter",
		ForIPv6:      false,
		Rules:        iptablesRules,
		RefersVeths:  veths,
		RefersChains: []string{fwIptablesChain},
	}, nil)
	intendedCfg.PutItem(configitems.IptablesChain{
		NetNamespace: configitems.MainNsName,
		ChainName:    "FORWARD",
		Table:        "filter",
		ForIPv6:      true,
		Rules:        iptablesRules,
		RefersVeths:  veths,
		RefersChains: []string{fwIptablesChain},
	}, nil)
	return intendedCfg
}

func (a *agent) getIntendedFwRule(
	rule *api.FwRule) (iptablesRule, ip6tablesRule configitems.IptablesRule) {
	var ipv4RuleArgs, ipv6RuleArgs []string
	ipv4 := true
	ipv6 := true
	if rule.GetSrcSubnet() != "" {
		_, subnet, _ := net.ParseCIDR(rule.GetSrcSubnet())
		if subnet.IP.To4() != nil {
			ipv4RuleArgs = append(ipv4RuleArgs, "-s", rule.GetSrcSubnet())
			ipv6 = false
		} else {
			ipv6RuleArgs = append(ipv6RuleArgs, "-s", rule.GetSrcSubnet())
			ipv4 = false
		}
	}
	if rule.GetDstSubnet() != "" {
		_, subnet, _ := net.ParseCIDR(rule.GetDstSubnet())
		if subnet.IP.To4() != nil {
			ipv4RuleArgs = append(ipv4RuleArgs, "-d", rule.GetDstSubnet())
			ipv6 = false
		} else {
			ipv6RuleArgs = append(ipv6RuleArgs, "-d", rule.GetDstSubnet())
			ipv4 = false
		}
	}
	switch rule.GetProtocol() {
	case api.FwProto_ANY_PROTO:
		ipv4RuleArgs = append(ipv4RuleArgs, "-p", "all")
		ipv6RuleArgs = append(ipv6RuleArgs, "-p", "all")
	case api.FwProto_ICMP:
		ipv4RuleArgs = append(ipv4RuleArgs, "-p", "icmp")
		ipv6RuleArgs = append(ipv6RuleArgs, "-p", "icmpv6")
	case api.FwProto_TCP:
		ipv4RuleArgs = append(ipv4RuleArgs, "-p", "tcp")
		ipv6RuleArgs = append(ipv6RuleArgs, "-p", "tcp")
	case api.FwProto_UDP:
		ipv4RuleArgs = append(ipv4RuleArgs, "-p", "udp")
		ipv6RuleArgs = append(ipv6RuleArgs, "-p", "udp")
	}
	if len(rule.GetPorts()) > 0 {
		var ports []string
		for _, port := range rule.GetPorts() {
			ports = append(ports, strconv.Itoa(int(port)))
		}
		matchPorts := []string{"--match", "multiport", "--dport", strings.Join(ports, ",")}
		ipv4RuleArgs = append(ipv4RuleArgs, matchPorts...)
		ipv6RuleArgs = append(ipv6RuleArgs, matchPorts...)
	}
	switch rule.GetAction() {
	case api.FwAction_FW_ALLOW:
		ipv4RuleArgs = append(ipv4RuleArgs, "-j", "ACCEPT")
		ipv6RuleArgs = append(ipv6RuleArgs, "-j", "ACCEPT")
	case api.FwAction_FW_REJECT:
		ipv4RuleArgs = append(ipv4RuleArgs, "-j", "REJECT")
		ipv6RuleArgs = append(ipv6RuleArgs, "-j", "REJECT")
	case api.FwAction_FW_DROP:
		ipv4RuleArgs = append(ipv4RuleArgs, "-j", "DROP")
		ipv6RuleArgs = append(ipv6RuleArgs, "-j", "DROP")
	}
	if ipv4 {
		iptablesRule = configitems.IptablesRule{
			Args: ipv4RuleArgs,
		}
	}
	if ipv6 {
		ip6tablesRule = configitems.IptablesRule{
			Args: ipv6RuleArgs,
		}
	}
	return iptablesRule, ip6tablesRule
}

func (a *agent) getIntendedDNSSrvEp(dnsSrv *api.DNSServer) dg.Graph {
	logicalLabel := dnsSrv.GetEndpoint().GetLogicalLabel()
	graphArgs := dg.InitArgs{Name: endpointSGPrefix + logicalLabel}
	intendedCfg := dg.New(graphArgs)
	a.putEpCommonConfig(intendedCfg, dnsSrv.GetEndpoint(), nil)
	var (
		upstreamServers []net.IP
		staticEntries   []configitems.DNSEntry
	)
	nsName := a.endpointNsName(logicalLabel)
	vethName, inIfName, _ := a.endpointVethName(logicalLabel)
	for _, upstreamServer := range dnsSrv.GetUpstreamServers() {
		upstreamServers = append(upstreamServers, net.ParseIP(upstreamServer))
	}
	for _, staticEntry := range dnsSrv.GetStaticEntries() {
		var fqdn string
		var ipv4, ipv6 net.IP
		if staticEntry.GetEndpointFqdnRef() != "" {
			ep := a.getEndpoint(staticEntry.GetEndpointFqdnRef())
			fqdn = ep.GetFqdn()
		} else {
			fqdn = staticEntry.GetFqdnLiteral()
		}
		if staticEntry.GetEndpointIpRef() != nil {
			ep := a.getEndpoint(staticEntry.GetEndpointIpRef().GetLogicalLabel())
			switch staticEntry.GetEndpointIpRef().GetIpVersion() {
			case api.IPVersion_ANY:
				ipv4, _ = a.getEndpointIP(ep, false)
				ipv6, _ = a.getEndpointIP(ep, true)
			case api.IPVersion_IPV4:
				ipv4, _ = a.getEndpointIP(ep, false)
			case api.IPVersion_IPV6:
				ipv6, _ = a.getEndpointIP(ep, true)
			}
		} else {
			ip := net.ParseIP(staticEntry.GetIpLiteral())
			if ip != nil {
				if ip.To4() == nil {
					ipv6 = ip
				} else {
					ipv4 = ip
				}
			}
		}
		if ipv4 != nil {
			staticEntries = append(staticEntries, configitems.DNSEntry{
				FQDN: fqdn,
				IP:   ipv4,
			})
		}
		if ipv6 != nil {
			staticEntries = append(staticEntries, configitems.DNSEntry{
				FQDN: fqdn,
				IP:   ipv6,
			})
		}
	}
	intendedCfg.PutItem(configitems.DNSServer{
		ServerName:      logicalLabel,
		NetNamespace:    nsName,
		VethName:        vethName,
		VethPeerIfName:  inIfName,
		StaticEntries:   staticEntries,
		UpstreamServers: upstreamServers,
	}, nil)
	return intendedCfg
}

func (a *agent) getIntendedExProxyEp(proxy *api.ExplicitProxy) dg.Graph {
	logicalLabel := proxy.GetEndpoint().GetLogicalLabel()
	graphArgs := dg.InitArgs{Name: endpointSGPrefix + logicalLabel}
	intendedCfg := dg.New(graphArgs)
	a.putEpCommonConfig(intendedCfg, proxy.GetEndpoint(),
		proxy.GetProxy().GetDnsClientConfig())
	nsName := a.endpointNsName(logicalLabel)
	vethName, _, _ := a.endpointVethName(logicalLabel)
	epIPs := a.getEndpointAllIPs(proxy.GetEndpoint())
	var httpsPorts []*api.ProxyPort
	if proxy.GetHttpsProxy().GetPort() != 0 {
		httpsPorts = append(httpsPorts, proxy.GetHttpsProxy())
	}
	httpPort := proxy.GetHttpProxy()
	intendedCfg.PutItem(configitems.HTTPProxy{
		Proxy:        proxy.GetProxy(),
		ProxyName:    logicalLabel,
		NetNamespace: nsName,
		VethName:     vethName,
		ListenIPs:    epIPs,
		Hostname:     proxy.GetEndpoint().GetFqdn(),
		HTTPPort:     httpPort,
		HTTPSPorts:   httpsPorts,
		Users:        proxy.GetUsers(),
	}, nil)
	return intendedCfg
}

func (a *agent) getIntendedTProxyEp(proxy *api.TransparentProxy) dg.Graph {
	logicalLabel := proxy.GetEndpoint().GetLogicalLabel()
	graphArgs := dg.InitArgs{Name: endpointSGPrefix + logicalLabel}
	intendedCfg := dg.New(graphArgs)
	a.putEpCommonConfig(intendedCfg, proxy.GetEndpoint(),
		proxy.GetProxy().GetDnsClientConfig())
	nsName := a.endpointNsName(logicalLabel)
	vethName, _, _ := a.endpointVethName(logicalLabel)
	epIPs := a.getEndpointAllIPs(proxy.GetEndpoint())
	httpsPorts := []*api.ProxyPort{{Port: 443}}
	controllerPort := a.netModel.GetControllerConfig().GetControllerPort()
	if controllerPort != 443 {
		httpsPorts = append(httpsPorts, &api.ProxyPort{Port: controllerPort})
	}
	intendedCfg.PutItem(configitems.HTTPProxy{
		Proxy:        proxy.GetProxy(),
		ProxyName:    logicalLabel,
		NetNamespace: nsName,
		VethName:     vethName,
		ListenIPs:    epIPs,
		HTTPPort:     &api.ProxyPort{Port: 80},
		HTTPSPorts:   httpsPorts,
		Transparent:  true,
	}, nil)
	return intendedCfg
}

func (a *agent) getIntendedHTTPSrvEp(httpSrv *api.HTTPServer) dg.Graph {
	logicalLabel := httpSrv.GetEndpoint().GetLogicalLabel()
	graphArgs := dg.InitArgs{Name: endpointSGPrefix + logicalLabel}
	intendedCfg := dg.New(graphArgs)
	a.putEpCommonConfig(intendedCfg, httpSrv.GetEndpoint(), httpSrv.GetDnsClientConfig())
	nsName := a.endpointNsName(logicalLabel)
	vethName, _, _ := a.endpointVethName(logicalLabel)
	epIPs := a.getEndpointAllIPs(httpSrv.GetEndpoint())
	intendedCfg.PutItem(configitems.HTTPServer{
		ServerName:   logicalLabel,
		NetNamespace: nsName,
		VethName:     vethName,
		ListenIPs:    epIPs,
		HTTPPort:     uint16(httpSrv.GetHttpPort()),
		HTTPSPort:    uint16(httpSrv.GetHttpsPort()),
		CertPEM:      httpSrv.GetCertPem(),
		KeyPEM:       httpSrv.GetKeyPem(),
		Paths:        httpSrv.Paths,
	}, nil)
	return intendedCfg
}

func (a *agent) getIntendedScepSrvEp(scepSrv *api.SCEPServer) dg.Graph {
	logicalLabel := scepSrv.GetEndpoint().GetLogicalLabel()
	graphArgs := dg.InitArgs{Name: endpointSGPrefix + logicalLabel}
	intendedCfg := dg.New(graphArgs)
	a.putEpCommonConfig(intendedCfg, scepSrv.GetEndpoint(), nil)
	nsName := a.endpointNsName(logicalLabel)
	vethName, _, _ := a.endpointVethName(logicalLabel)
	intendedCfg.PutItem(configitems.SCEPServer{
		ServerName:      logicalLabel,
		NetNamespace:    nsName,
		VethName:        vethName,
		Port:            uint16(scepSrv.GetPort()),
		CACertPEM:       scepSrv.GetCaCertPem(),
		CAKeyPEM:        scepSrv.GetCaKeyPem(),
		ChallengeSecret: scepSrv.GetChallengePassword(),
	}, nil)
	return intendedCfg
}

func (a *agent) putEpCommonConfig(
	graph dg.Graph, ep *api.Endpoint, dnsClient *api.DNSClientConfig) {
	vethName, inIfName, outIfName := a.endpointVethName(ep.GetLogicalLabel())
	nsName := a.endpointNsName(ep.GetLogicalLabel())
	netNs := configitems.NetNamespace{
		NsName: nsName,
	}
	if dnsClient != nil {
		var dnsServers []net.IP
		for _, dnsServer := range dnsClient.GetPublicDns() {
			dnsServers = append(dnsServers, net.ParseIP(dnsServer))
		}
		for _, dnsServer := range dnsClient.GetPrivateDns() {
			ep := a.getEndpoint(dnsServer)
			serverIPv4, _ := a.getEndpointIP(ep, false)
			if serverIPv4 != nil {
				dnsServers = append(dnsServers, serverIPv4)
			}
			serverIPv6, _ := a.getEndpointIP(ep, true)
			if serverIPv6 != nil {
				dnsServers = append(dnsServers, serverIPv6)
			}
		}
		netNs.ResolvConf = configitems.ResolvConf{
			Create:     true,
			DNSServers: dnsServers,
		}
	}
	graph.PutItem(netNs, nil)
	graph.PutItem(configitems.Sysctl{
		NetNamespace:          nsName,
		EnableIPv4Forwarding:  true,
		EnableIPv6Forwarding:  true,
		BridgeNfCallIptables:  true,
		BridgeNfCallIP6tables: true,
		DisableIPv6DAD:        true,
	}, nil)
	// Prepare IP config.
	l2Direct := ep.GetDirectL2Connect().GetBridge() != ""
	epIPv4, ipv4Subnet := a.getEndpointIP(ep, false)
	epIPv6, ipv6Subnet := a.getEndpointIP(ep, true)
	var epIPs []*net.IPNet
	if epIPv4 != nil {
		epIPs = append(epIPs, &net.IPNet{IP: epIPv4, Mask: ipv4Subnet.Mask})
	}
	if epIPv6 != nil {
		epIPs = append(epIPs, &net.IPNet{IP: epIPv6, Mask: ipv6Subnet.Mask})
	}
	var gwIPv4, gwIPv6 *net.IPNet
	var gwIPs []*net.IPNet
	if !l2Direct && ipv4Subnet != nil {
		gwIPv4 = a.genEndpointGwIP(ipv4Subnet, epIPv4)
		gwIPs = append(gwIPs, gwIPv4)
	}
	if !l2Direct && ipv6Subnet != nil {
		gwIPv6 = a.genEndpointGwIP(ipv6Subnet, epIPv6)
		gwIPs = append(gwIPs, gwIPv6)
	}
	// Connect endpoint using a VETH.
	var masterBridge *configitems.MasterBridge
	if l2Direct {
		masterBridge = &configitems.MasterBridge{
			IfName: a.bridgeIfName(ep.GetDirectL2Connect().GetBridge()),
			VLAN:   uint16(ep.GetDirectL2Connect().GetVlanId()),
		}
	}
	graph.PutItem(configitems.Veth{
		VethName: vethName,
		Peer1: configitems.VethPeer{
			IfName:       inIfName,
			NetNamespace: nsName,
			IPAddresses:  epIPs,
			MTU:          uint16(ep.Mtu),
		},
		Peer2: configitems.VethPeer{
			IfName:       outIfName,
			NetNamespace: configitems.MainNsName,
			IPAddresses:  gwIPs,
			MTU:          uint16(ep.Mtu),
			MasterBridge: masterBridge,
		},
	}, nil)
	// Configure default route(s).
	if !l2Direct && ipv4Subnet != nil {
		graph.PutItem(configitems.Route{
			NetNamespace: nsName,
			DstNet:       allIPv4,
			OutputIf: configitems.RouteOutIf{
				VethName:       vethName,
				VethPeerIfName: inIfName,
			},
			GwIP: gwIPv4.IP,
		}, nil)
	}
	if !l2Direct && ipv6Subnet != nil {
		graph.PutItem(configitems.Route{
			NetNamespace: nsName,
			DstNet:       allIPv6,
			OutputIf: configitems.RouteOutIf{
				VethName:       vethName,
				VethPeerIfName: inIfName,
			},
			GwIP: gwIPv6.IP,
		}, nil)
	}
}

func (a *agent) tunIfName(tun *api.SDNTunnel) string {
	return fmt.Sprintf("tun-%s", tun.ClientId)
}

func (a *agent) bondIfName(logicalLabel string) string {
	return a.genIfName("bond-", logicalLabel)
}

func (a *agent) bridgeIfName(logicalLabel string) string {
	return a.genIfName("br-", logicalLabel)
}

func (a *agent) networkNsName(logicalLabel string) string {
	return "network-" + logicalLabel
}

func (a *agent) endpointNsName(logicalLabel string) string {
	return "endpoint-" + logicalLabel
}

func (a *agent) networkBrVethName(logicalLabel string) (
	vethName, inIfName, outIfName string) {
	vethName = "net-br-" + logicalLabel
	inIfName = a.genIfName("net-br-in-", logicalLabel)
	outIfName = a.genIfName("net-br-out-", logicalLabel)
	return
}

func (a *agent) networkRtVethName(logicalLabel string) (
	vethName, inIfName, outIfName string) {
	vethName = "net-rt-" + logicalLabel
	inIfName = a.genIfName("net-rt-in-", logicalLabel)
	outIfName = a.genIfName("net-rt-out-", logicalLabel)
	return
}

func (a *agent) endpointVethName(logicalLabel string) (
	vethName, inIfName, outIfName string) {
	vethName = "ep-" + logicalLabel
	inIfName = a.genIfName("ep-in-", logicalLabel)
	outIfName = a.genIfName("ep-out-", logicalLabel)
	return
}

func (a *agent) getNetwork(logicalLabel string) *api.Network {
	item := a.netModel.items.getItem((&api.Network{}).ItemType(), logicalLabel)
	return item.LabeledItem.(*api.Network)
}

func (a *agent) getEndpoint(logicalLabel string) *api.Endpoint {
	item := a.netModel.items.getItem((&api.Endpoint{}).ItemType(), logicalLabel)
	return a.labeledItemToEndpoint(item)
}

func (a *agent) getNetworkIPConf(
	network *api.Network, forIPv6 bool) (subnet, gwIP *net.IPNet, dhcpConf *api.DHCP) {
	if forIPv6 {
		_, subnet, _ = net.ParseCIDR(network.GetIpv6().GetSubnet())
		if subnet == nil {
			return nil, nil, nil
		}
		gwIP = &net.IPNet{IP: net.ParseIP(network.GetIpv6().GetGwIp()),
			Mask: subnet.Mask}
		dhcpConf = network.GetIpv6().GetDhcp()
		return
	}
	_, subnet, _ = net.ParseCIDR(network.GetIpv4().GetSubnet())
	if subnet == nil {
		return nil, nil, nil
	}
	gwIP = &net.IPNet{IP: net.ParseIP(network.GetIpv4().GetGwIp()),
		Mask: subnet.Mask}
	dhcpConf = network.GetIpv4().GetDhcp()
	return
}

// Returns IP addresses assigned to VETHs connecting Network with the Router namespace.
func (a *agent) getNetworkRtVethIPs(
	network *api.Network) (vethInIPv4, vethOutIPv4, vethInIPv6, vethOutIPv6 *net.IPNet) {
	if network.GetIpv4().GetSubnet() != "" {
		vethInIPv4, vethOutIPv4 = a.genVethIPsForNetwork(network.GetLogicalLabel(), false)
	}
	if network.GetIpv6().GetSubnet() != "" {
		vethInIPv6, vethOutIPv6 = a.genVethIPsForNetwork(network.GetLogicalLabel(), true)
	}
	return
}

func (a *agent) getEndpointIP(
	ep *api.Endpoint, forIPv6 bool) (ip net.IP, subnet *net.IPNet) {
	if forIPv6 {
		ip = net.ParseIP(ep.GetIpv6().GetIp())
		_, subnet, _ = net.ParseCIDR(ep.GetIpv6().GetSubnet())
		if ip == nil || subnet == nil {
			return nil, nil
		}
		return ip.To16(), subnet
	}
	ip = net.ParseIP(ep.GetIpv4().GetIp())
	_, subnet, _ = net.ParseCIDR(ep.GetIpv4().GetSubnet())
	if ip == nil || subnet == nil {
		return nil, nil
	}
	return ip.To16(), subnet
}

func (a *agent) getEndpointAllIPs(ep *api.Endpoint) (epIPs []net.IP) {
	epIPv4, _ := a.getEndpointIP(ep, false)
	if epIPv4 != nil {
		epIPs = append(epIPs, epIPv4)
	}
	epIPv6, _ := a.getEndpointIP(ep, true)
	if epIPv6 != nil {
		epIPs = append(epIPs, epIPv6)
	}
	return epIPs
}

func (a *agent) labeledItemToEndpoint(item *labeledItem) *api.Endpoint {
	switch item.category {
	case (&api.DNSServer{}).ItemCategory():
		return item.LabeledItem.(*api.DNSServer).Endpoint
	case (&api.NTPServer{}).ItemCategory():
		return item.LabeledItem.(*api.NTPServer).Endpoint
	case (&api.HTTPServer{}).ItemCategory():
		return item.LabeledItem.(*api.HTTPServer).Endpoint
	case (&api.ExplicitProxy{}).ItemCategory():
		return item.LabeledItem.(*api.ExplicitProxy).Endpoint
	case (&api.TransparentProxy{}).ItemCategory():
		return item.LabeledItem.(*api.TransparentProxy).Endpoint
	case (&api.NetbootServer{}).ItemCategory():
		return item.LabeledItem.(*api.NetbootServer).Endpoint
	case (&api.SCEPServer{}).ItemCategory():
		return item.LabeledItem.(*api.SCEPServer).Endpoint
	default:
		log.Fatalf("Unexpected endpoint category: %s", item.category)
	}
	return &api.Endpoint{} // unreachable
}

func (a *agent) genIfName(prefix, logicalLabel string) string {
	ifNameLen := len(prefix) + len(logicalLabel)
	if ifNameLen <= ifNameMaxLen {
		return prefix + logicalLabel
	}
	hashLen := ifNameMaxLen - len(prefix)
	if hashLen < 3 {
		log.Fatalf("interface name prefix too long: %s", prefix)
	}
	if hashLen > 6 {
		hashLen = 6
	}
	return prefix + hashString(logicalLabel, hashLen)
}

const (
	// 32 letters (5 bits to fit single one)
	letters5b = "abcdefghijklmnopqrstuvwxyzABCDEF"
)

// hashString returns a hash of an arbitrarily long string.
// The hash will have <n> characters (shouldn't be more than 7).
func hashString(str string, n int) string {
	h := fnv.New32a()
	h.Write([]byte(str))
	hn := h.Sum32()
	var hash string
	bitMask5b := uint32((1 << 5) - 1)
	for i := 0; i < n; i++ {
		hash = string(letters5b[int(hn&bitMask5b)]) + hash
		hn >>= 5
	}
	return hash
}

func filterOutNilAddrs(addrs ...*net.IPNet) (filtered []*net.IPNet) {
	for _, addr := range addrs {
		if addr != nil {
			filtered = append(filtered, addr)
		}
	}
	return filtered
}
