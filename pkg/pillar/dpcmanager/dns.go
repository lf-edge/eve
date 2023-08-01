// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"fmt"
	"net"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/types"
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
			m.deviceNetStatus.Ports[ix].Subnet = *subnet
		}
		// Start with any statically assigned values; update below
		m.deviceNetStatus.Ports[ix].DomainName = port.DomainName
		m.deviceNetStatus.Ports[ix].DNSServers = port.DnsServers
		m.deviceNetStatus.Ports[ix].NtpServer = port.NtpServer
		m.deviceNetStatus.Ports[ix].TestResults = port.TestResults
		// Do not try to get state data for interface which is in PCIback.
		ioBundle := m.adapters.LookupIoBundleIfName(port.IfName)
		if ioBundle != nil && ioBundle.IsPCIBack {
			err := fmt.Errorf("port %s is in PCIBack - ignored", port.IfName)
			m.Log.Warnf("updateDNS: %v", err)
			m.deviceNetStatus.Ports[ix].RecordFailure(err.Error())
			continue
		}
		// Get interface state data from the network stack.
		ifindex, exists, err := m.NetworkMonitor.GetInterfaceIndex(port.IfName)
		if !exists || err != nil {
			err = fmt.Errorf("port %s does not exist - ignored", port.IfName)
			m.Log.Warnf("updateDNS: %v", err)
			m.deviceNetStatus.Ports[ix].RecordFailure(err.Error())
			continue
		}
		var isUp bool
		ifAttrs, err := m.NetworkMonitor.GetInterfaceAttrs(ifindex)
		if err != nil {
			m.Log.Warnf(
				"updateDNS: failed to get attrs for interface %s with index %d: %v",
				port.IfName, ifindex, err)
		} else {
			isUp = ifAttrs.AdminUp
		}
		m.deviceNetStatus.Ports[ix].Up = isUp
		ipAddrs, macAddr, err := m.NetworkMonitor.GetInterfaceAddrs(ifindex)
		if err != nil {
			m.Log.Warnf(
				"updateDNS: failed to get IP addresses for interface %s with index %d: %v",
				port.IfName, ifindex, err)
			ipAddrs = nil
		}
		m.deviceNetStatus.Ports[ix].MacAddr = macAddr.String()
		m.deviceNetStatus.Ports[ix].AddrInfoList = make([]types.AddrInfo, len(ipAddrs))
		if len(ipAddrs) == 0 {
			m.Log.Functionf("updateDNS: interface %s has NO IP addresses", port.IfName)
		}
		for i, addr := range ipAddrs {
			m.deviceNetStatus.Ports[ix].AddrInfoList[i].Addr = addr.IP
		}
		// Get DNS etc info from dhcpcd. Updates DomainName and DnsServers.
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
		err = devicenetwork.CheckAndGetNetworkProxy(
			m.Log, &m.deviceNetStatus, port.IfName, m.ZedcloudMetrics)
		if err != nil {
			err = fmt.Errorf("updateDNS: CheckAndGetNetworkProxy failed for %s: %v",
				port.IfName, err)
			// XXX where can we return this failure?
			// Already have TestResults set from above
			m.Log.Error(err)
		}

		// If this is a cellular network connectivity, add status information
		// obtained from the wwan service.
		if port.WirelessCfg.WType == types.WirelessTypeCellular {
			wwanNetStatus, found := m.wwanStatus.LookupNetworkStatus(port.Logicallabel)
			if found {
				m.deviceNetStatus.Ports[ix].WirelessStatus = types.WirelessStatus{
					WType:    types.WirelessTypeCellular,
					Cellular: wwanNetStatus,
				}
			}
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
	if port.Dhcp != types.DT_CLIENT {
		return nil
	}
	if port.WirelessStatus.WType == types.WirelessTypeCellular {
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
	if dhcpInfo.Subnet != nil {
		port.Subnet = *dhcpInfo.Subnet
	}
	port.NtpServers = dhcpInfo.NtpServers
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
	dnsInfo, err := m.NetworkMonitor.GetInterfaceDNSInfo(ifIndex)
	if err != nil {
		return fmt.Errorf("getDNSInfo: failed to get DNS info for interface %s: %v",
			port.IfName, err)
	}
	port.DNSServers = dnsInfo.DNSServers
	// XXX just pick first since have one DomainName slot
	if len(dnsInfo.Domains) > 0 {
		port.DomainName = dnsInfo.Domains[0]
	}
	return nil
}
