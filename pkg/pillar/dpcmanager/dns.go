// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"fmt"
	"net"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

type geoService struct{}

// GetGeolocationInfo tries to obtain geolocation information corresponding
// to the given IP address.
func (g *geoService) GetGeolocationInfo(ipAddr net.IP) (*ipinfo.IPInfo, error) {
	// geolocation with short timeout
	opt := ipinfo.Options{
		Timeout:  5 * time.Second,
		SourceIp: ipAddr,
	}
	info, err := ipinfo.MyIPWithOptions(opt)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (m *DpcManager) updateDNS() {
	defer m.publishDNS()
	dpc := m.currentDPC()
	if dpc == nil {
		m.deviceNetStatus = types.DeviceNetworkStatus{}
		return
	}
	m.deviceNetStatus.DPCKey = dpc.Key
	m.deviceNetStatus.Version = dpc.Version
	m.deviceNetStatus.State = dpc.State
	m.deviceNetStatus.Testing = m.dpcVerify.inProgress
	m.deviceNetStatus.CurrentIndex = m.dpcList.CurrentIndex
	m.deviceNetStatus.RadioSilence = m.rsStatus
	oldDNS := m.deviceNetStatus
	m.deviceNetStatus.Ports = make([]types.NetworkPortStatus, len(dpc.Ports))
	for ix, port := range dpc.Ports {
		m.deviceNetStatus.Ports[ix].IfName = port.IfName
		m.deviceNetStatus.Ports[ix].Phylabel = port.Phylabel
		m.deviceNetStatus.Ports[ix].Logicallabel = port.Logicallabel
		m.deviceNetStatus.Ports[ix].SharedLabels = port.SharedLabels
		m.deviceNetStatus.Ports[ix].Alias = port.Alias
		m.deviceNetStatus.Ports[ix].IsMgmt = port.IsMgmt
		m.deviceNetStatus.Ports[ix].IsL3Port = port.IsL3Port
		m.deviceNetStatus.Ports[ix].Cost = port.Cost
		m.deviceNetStatus.Ports[ix].ProxyConfig = port.ProxyConfig
		m.deviceNetStatus.Ports[ix].WirelessCfg = port.WirelessCfg
		// Set fields from the config...
		m.deviceNetStatus.Ports[ix].Dhcp = port.Dhcp
		m.deviceNetStatus.Ports[ix].Type = port.Type
		_, subnet, _ := net.ParseCIDR(port.AddrSubnet)
		if subnet != nil {
			m.deviceNetStatus.Ports[ix].ConfiguredSubnet = subnet
		}
		// Start with any statically assigned values; update below
		m.deviceNetStatus.Ports[ix].DomainName = port.DomainName
		m.deviceNetStatus.Ports[ix].DNSServers = port.DNSServers
		m.deviceNetStatus.Ports[ix].ConfiguredNtpServers = port.NTPServers
		m.deviceNetStatus.Ports[ix].IgnoreDhcpNtpServers = port.IgnoreDhcpNtpServers
		// Prefer errors recorded by DPC verification.
		// New errors are recorded from this function only when there is none yet
		// (HasError() == false).
		m.deviceNetStatus.Ports[ix].InvalidConfig = port.InvalidConfig
		m.deviceNetStatus.Ports[ix].TestResults = port.TestResults
		m.deviceNetStatus.Ports[ix].WirelessStatus.WType = port.WirelessCfg.WType
		// If this is a cellular network connectivity, add status information
		// obtained from the wwan service.
		if port.WirelessCfg.WType == types.WirelessTypeCellular {
			wwanNetStatus := m.wwanStatus.GetNetworkStatus(port.Logicallabel)
			if wwanNetStatus != nil {
				m.deviceNetStatus.Ports[ix].WirelessStatus.Cellular = *wwanNetStatus
			}
		}
		// Do not try to get state data for interface which is in PCIback.
		ioBundle := m.adapters.LookupIoBundleLogicallabel(port.Logicallabel)
		if ioBundle != nil && ioBundle.IsPCIBack {
			err := fmt.Errorf("port %s is in PCIBack", port.Logicallabel)
			m.Log.Warnf("updateDNS: %v", err)
			if !m.deviceNetStatus.Ports[ix].HasError() {
				m.deviceNetStatus.Ports[ix].RecordFailure(err.Error())
			}
			continue
		}
		if port.IfName == "" {
			err := fmt.Errorf("port %s is missing interface name", port.Logicallabel)
			if !m.deviceNetStatus.Ports[ix].HasError() {
				m.deviceNetStatus.Ports[ix].RecordFailure(err.Error())
			}
			m.Log.Warnf("updateDNS: interface name of port %s is not yet known, "+
				"will not retrieve some attributes", port.Logicallabel)
			continue
		}
		// Get interface state data from the network stack.
		ifindex, exists, err := m.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if !exists || err != nil {
			err = fmt.Errorf("interface %s is missing", port.IfName)
			m.Log.Warnf("updateDNS: %v", err)
			if !m.deviceNetStatus.Ports[ix].HasError() {
				m.deviceNetStatus.Ports[ix].RecordFailure(err.Error())
			}
			continue
		}
		ifAttrs, err := m.NetworkMonitor.GetInterfaceAttrs(ifindex)
		if err != nil {
			m.Log.Warnf(
				"updateDNS: failed to get attrs for interface %s with index %d: %v",
				port.IfName, ifindex, err)
		} else {
			m.deviceNetStatus.Ports[ix].Up = ifAttrs.LowerUp
			m.deviceNetStatus.Ports[ix].MTU = ifAttrs.MTU
		}
		ipAddrs, macAddr, err := m.NetworkMonitor.GetInterfaceAddrs(ifindex)
		if err != nil {
			m.Log.Warnf(
				"updateDNS: failed to get IP addresses for interface %s with index %d: %v",
				port.IfName, ifindex, err)
			ipAddrs = nil
		}
		m.deviceNetStatus.Ports[ix].MacAddr = macAddr

		// Below this point we collect L3-specific info for the port.
		if !port.IsL3Port {
			m.deviceNetStatus.Ports[ix].AddrInfoList = nil
			continue
		}

		m.deviceNetStatus.Ports[ix].AddrInfoList = make([]types.AddrInfo, len(ipAddrs))
		if len(ipAddrs) == 0 {
			m.Log.Functionf("updateDNS: interface %s has NO IP addresses", port.IfName)
		}
		for i, addr := range ipAddrs {
			m.deviceNetStatus.Ports[ix].AddrInfoList[i].Addr = addr.IP
		}

		// Get DNS etc info from dhcpcd. Updates DomainName and DNSServers.
		err = m.getDHCPInfo(&m.deviceNetStatus.Ports[ix])
		if err != nil && dpc.State != types.DPCStateAsyncWait {
			m.Log.Error(err)
		}
		err = m.getDNSInfo(&m.deviceNetStatus.Ports[ix])
		if err != nil && dpc.State != types.DPCStateAsyncWait {
			m.Log.Error(err)
		}

		// Get used default routers aka gateways from kernel
		gws, err := m.NetworkMonitor.GetInterfaceDefaultGWs(ifindex)
		if err != nil {
			m.Log.Warnf(
				"updateDNS: failed to get default GWs for interface %s with index %d: %v",
				port.IfName, ifindex, err)
			gws = nil
		}
		m.deviceNetStatus.Ports[ix].DefaultRouters = gws

		// Attempt to get a wpad.dat file if so configured
		// Result is updating the Pacfile
		// We always redo this since we don't know what has changed
		// from the previous DeviceNetworkStatus.
		err = controllerconn.CheckAndGetNetworkProxy(
			m.Log, &m.deviceNetStatus, port.IfName, m.AgentMetrics)
		if err != nil {
			err = fmt.Errorf("updateDNS: CheckAndGetNetworkProxy failed for %s: %v",
				port.IfName, err)
			// XXX where can we return this failure?
			// Already have TestResults set from above
			m.Log.Error(err)
		}
	}

	// Preserve geo info for existing interface and IP address
	for portIdx := range m.deviceNetStatus.Ports {
		port := &m.deviceNetStatus.Ports[portIdx]
		for addrIdx := range port.AddrInfoList {
			// Need pointer since we are going to modify
			ai := &port.AddrInfoList[addrIdx]
			oai := oldDNS.GetPortAddrInfo(port.IfName, ai.Addr)
			if oai == nil {
				continue
			}
			ai.Geo = oai.Geo
			ai.LastGeoTimestamp = oai.LastGeoTimestamp
		}
	}
}

func (m *DpcManager) publishDNS() {
	err := m.PubDeviceNetworkStatus.Publish("global", m.deviceNetStatus)
	if err != nil {
		m.Log.Errorf("failed to publish DNS: %v", err)
	}
}

func (m *DpcManager) updateGeo() {
	var change bool
	for idx := range m.deviceNetStatus.Ports {
		port := &m.deviceNetStatus.Ports[idx]
		if m.deviceNetStatus.Version >= types.DPCIsMgmt && !port.IsMgmt {
			continue
		}
		if port.IfName == "" {
			continue
		}
		for i := range port.AddrInfoList {
			// Need pointer since we are going to modify.
			ai := &port.AddrInfoList[i]
			if ai.Addr.IsLinkLocalUnicast() {
				continue
			}
			numDNSServers := types.CountDNSServers(m.deviceNetStatus, port.IfName)
			if numDNSServers == 0 {
				continue
			}
			timePassed := time.Since(ai.LastGeoTimestamp)
			if timePassed < m.geoRedoInterval {
				continue
			}
			info, err := m.GeoService.GetGeolocationInfo(ai.Addr)
			if err != nil {
				// Ignore error
				m.Log.Functionf("updateGeo: GetGeolocationInfo failed %s\n", err)
				continue
			}
			// Note that if the global IP is unchanged we don't update anything.
			if info == nil || info.IP == ai.Geo.IP {
				continue
			}
			m.Log.Functionf("updateGeo: MyIPInfo changed from %v to %v\n",
				ai.Geo, *info)
			ai.Geo = *info
			ai.LastGeoTimestamp = time.Now()
			change = true
		}
	}
	if change {
		m.publishDNS()
	}
}

func (m *DpcManager) getDHCPInfo(port *types.NetworkPortStatus) error {
	// Run this even for static configuration, since dhcpcd is also used to apply it.
	if port.Dhcp != types.DhcpTypeClient && port.Dhcp != types.DhcpTypeStatic {
		return nil
	}
	if port.WirelessStatus.WType == types.WirelessTypeCellular {
		// IP configuration for cellular modems is retrieved and set by mmagent
		// from the wwan microservice. dhcpcd is not used.
		return nil
	}
	ifIndex, exists, err := m.NetworkMonitor.GetInterfaceIndex(port.IfName)
	if !exists {
		return nil
	}
	if err != nil {
		return fmt.Errorf("getDHCPInfo: failed to get index for interface %s: %v",
			port.IfName, err)
	}
	dhcpInfo, err := m.NetworkMonitor.GetInterfaceDHCPInfo(ifIndex)
	if err != nil {
		return fmt.Errorf("getDHCPInfo: failed to get DHCP info for interface %s: %v",
			port.IfName, err)
	}
	// Subnets configured on the interface.
	// The origin can be either an external DHCP server or a static IP config applied
	// via dhcpcd.
	port.IPv4Subnet = dhcpInfo.IPv4Subnet
	port.IPv6Subnets = dhcpInfo.IPv6Subnets
	// NTP servers obtained via DHCP and those configured manually are stored separately.
	// This allows to implement the IgnoreDhcpNtpServers option.
	if port.Dhcp == types.DhcpTypeClient {
		port.DhcpNtpServers = dhcpInfo.IPv4NtpServers
		port.DhcpNtpServers = append(port.DhcpNtpServers, dhcpInfo.IPv6NtpServers...)
		// dhcpInfo.HostnameNtpServers is empty in this case because neither DHCP
		// nor DHCPv6 allow to advertise NTP servers with hostname addresses.
	} else {
		port.ConfiguredNtpServers = dhcpInfo.HostnameNtpServers
		for _, ntpServer := range dhcpInfo.IPv4NtpServers {
			port.ConfiguredNtpServers = append(port.ConfiguredNtpServers, ntpServer.String())
		}
		for _, ntpServer := range dhcpInfo.IPv6NtpServers {
			port.ConfiguredNtpServers = append(port.ConfiguredNtpServers, ntpServer.String())
		}
	}
	return nil
}

func (m *DpcManager) getDNSInfo(port *types.NetworkPortStatus) error {
	ifIndex, exists, err := m.NetworkMonitor.GetInterfaceIndex(port.IfName)
	if !exists {
		return nil
	}
	if err != nil {
		return fmt.Errorf("getDNSInfo: failed to get index for interface %s: %v",
			port.IfName, err)
	}
	dnsInfoList, err := m.NetworkMonitor.GetInterfaceDNSInfo(ifIndex)
	if err != nil {
		return fmt.Errorf("getDNSInfo: failed to get DNS info for interface %s: %v",
			port.IfName, err)
	}
	preferIPv6 := port.Type == types.NetworkTypeIPV6 ||
		port.Type == types.NetworkTypeIpv6Only
	for _, dnsInfo := range dnsInfoList {
		port.DNSServers = append(port.DNSServers, dnsInfo.DNSServers...)
		if len(dnsInfo.Domains) > 0 {
			// We have only one DomainName field to report.
			// With dual-stack we pick the domain name for the preferred IP version.
			if port.DomainName == "" || dnsInfo.ForIPv6 == preferIPv6 {
				port.DomainName = dnsInfo.Domains[0]
			}
		}
	}
	port.DNSServers = generics.FilterDuplicatesFn(port.DNSServers, netutils.EqualIPs)
	return nil
}
