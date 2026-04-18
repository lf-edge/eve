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
	dpc, haveDPC := m.getCurrentDPC()
	if !haveDPC {
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
		m.deviceNetStatus.Ports[ix].ConfigSource = port.ConfigSource
		// Set fields from the config...
		m.deviceNetStatus.Ports[ix].Dhcp = port.Dhcp
		m.deviceNetStatus.Ports[ix].Type = port.Type
		staticIP, staticSubnet, _ := net.ParseCIDR(port.AddrSubnet)
		m.deviceNetStatus.Ports[ix].ConfiguredSubnet = staticSubnet
		m.deviceNetStatus.Ports[ix].ConfiguredIP = staticIP
		staticIPNet := netutils.NewIPNet(staticIP, staticSubnet)
		m.deviceNetStatus.Ports[ix].IgnoredDhcpIPs = port.IgnoreDhcpIPAddresses
		m.deviceNetStatus.Ports[ix].L2Type = port.L2Type
		m.deviceNetStatus.Ports[ix].L2LinkConfig = port.L2LinkConfig
		// Prefer errors recorded by DPC verification.
		// New errors are recorded from this function only when there is none yet
		// (HasError() == false).
		m.deviceNetStatus.Ports[ix].InvalidConfig = port.InvalidConfig
		m.deviceNetStatus.Ports[ix].TestResults = port.TestResults
		// Error specific to locally-made configuration reported back to LPS.
		lpsConfigErr := m.getPortLpsConfigErr(port.Logicallabel)
		if lpsConfigErr != nil {
			m.deviceNetStatus.Ports[ix].LpsConfigError = lpsConfigErr.Error()
		}
		// If this is a bond port, add runtime bond status.
		if port.L2Type == types.L2LinkTypeBond {
			m.getBondStatus(&m.deviceNetStatus.Ports[ix], port, dpc)
		}
		// If this is a cellular network connectivity, add status information
		// obtained from the wwan service.
		m.deviceNetStatus.Ports[ix].WirelessStatus.WType = port.WirelessCfg.WType
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

		// Add 802.1x state information.
		m.getPNACStatus(&m.deviceNetStatus.Ports[ix], port, ifindex)

		// Below this point we collect L3-specific info for the port.
		if !port.IsL3Port {
			m.deviceNetStatus.Ports[ix].AddrInfoList = nil
			m.deviceNetStatus.Ports[ix].ClusterIPAddr = nil
			continue
		}

		addrInfoList := make([]types.AddrInfo, 0, len(ipAddrs))
		var clusterIPAddr net.IP
		if len(ipAddrs) == 0 {
			m.Log.Functionf("updateDNS: interface %s has NO IP addresses", port.IfName)
		}
		for _, addr := range ipAddrs {
			if port.IgnoreDhcpIPAddresses && addr.IP.To4() != nil &&
				!netutils.EqualIPNets(addr, staticIPNet) {
				// IP address received over DHCP is ignored.
				continue
			}
			// Cluster IP is kept separate from AddrInfoList — it is only
			// for inter-node communication and must not be used as a source
			// IP for controller-bound traffic.
			if m.clusterStatus.ClusterIPPrefix != nil &&
				m.clusterStatus.ClusterIPPrefix.Contains(addr.IP) {
				clusterIPAddr = addr.IP
				continue
			}
			// kube-vip VIPs are floating addresses managed by leader election —
			// they can migrate to another node at any time and no pillar code
			// uses them, so drop them entirely from DeviceNetworkStatus.
			// VIPs live on the same interface as the management IP by design
			// (kube-vip binds them to the same L3 port via hostNetwork).
			// We distinguish VIPs from the primary management IP by prefix
			// length: kube-vip (ARP mode) always assigns VIPs as /32 host
			// routes, while the management IP (DHCP-assigned or statically
			// configured) always has a subnet mask longer than /32 (e.g. /24).
			// Filtering only host-route addresses preserves the management IP
			// in AddrInfoList so that resolveLBInterfaces() can detect and
			// report the overlap when the controller misconfigures the LB CIDR
			// to include the mgmt IP.
			// Edge case: point-to-point interfaces (e.g. cellular/LTE) can
			// have a /32 management IP. If that IP also falls inside the LB
			// CIDR, checkLBCIDRConflict/resolveLBInterfaces will detect and
			// report the conflict, so kube-vip will not be deployed and no
			// real VIPs will exist on the interface.
			isLBVIP := false
			if ones, bits := addr.Mask.Size(); ones == bits {
				for _, prefix := range m.clusterStatus.LBIPPrefixes {
					_, lbNet, err := net.ParseCIDR(prefix)
					if err == nil && lbNet.Contains(addr.IP) {
						isLBVIP = true
						break
					}
				}
			}
			if isLBVIP {
				continue
			}
			addrInfoList = append(addrInfoList, types.AddrInfo{Addr: addr.IP})
		}
		m.deviceNetStatus.Ports[ix].AddrInfoList = addrInfoList
		m.deviceNetStatus.Ports[ix].ClusterIPAddr = clusterIPAddr

		// Get DNS etc info from dhcpcd. Updates DomainName and DNSServers.
		err = m.getDHCPInfo(&m.deviceNetStatus.Ports[ix], port)
		if err != nil && dpc.State != types.DPCStateAsyncWait {
			m.Log.Error(err)
		}
		err = m.getDNSInfo(&m.deviceNetStatus.Ports[ix], port)
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

func (m *DpcManager) getDHCPInfo(
	portStatus *types.NetworkPortStatus, portConfig types.NetworkPortConfig) error {
	if portStatus.Dhcp != types.DhcpTypeClient && portStatus.Dhcp != types.DhcpTypeStatic {
		// Neither DHCP not static IP config is enabled.
		return nil
	}
	// Static configuration is either merged with or replaces DHCP-provided
	// settings, depending on the IgnoreDhcp* flags.
	portStatus.NtpServers = append(
		[]netutils.HostnameOrIP{}, portConfig.NTPServers...) // copy slice

	if portStatus.WirelessStatus.WType == types.WirelessTypeCellular {
		// IP configuration for cellular modems is retrieved and set by mmagent
		// from the wwan microservice. dhcpcd is not used.
		return nil
	}
	ifIndex, exists, err := m.NetworkMonitor.GetInterfaceIndex(portConfig.IfName)
	if !exists {
		return nil
	}
	if err != nil {
		return fmt.Errorf("getDHCPInfo: failed to get index for interface %s: %v",
			portConfig.IfName, err)
	}
	dhcpInfo, err := m.NetworkMonitor.GetInterfaceDHCPInfo(ifIndex)
	if err != nil {
		return fmt.Errorf("getDHCPInfo: failed to get DHCP info for interface %s: %v",
			portConfig.IfName, err)
	}
	// Subnets currently configured on the interface.
	// Obtained either from an external DHCP server or from static IP settings
	// applied via dhcpcd.
	portStatus.IPv4Subnet = dhcpInfo.IPv4Subnet
	portStatus.IPv6Subnets = dhcpInfo.IPv6Subnets
	// Add NTP servers learned via DHCP unless overridden by static configuration.
	if !portConfig.IgnoreDhcpNtpServers {
		portStatus.NtpServers = append(portStatus.NtpServers, dhcpInfo.IPv4NtpServers...)
		portStatus.NtpServers = append(portStatus.NtpServers, dhcpInfo.IPv6NtpServers...)
	}
	return nil
}

func (m *DpcManager) getDNSInfo(
	portStatus *types.NetworkPortStatus, portConfig types.NetworkPortConfig) error {
	if portStatus.Dhcp != types.DhcpTypeClient && portStatus.Dhcp != types.DhcpTypeStatic {
		// Neither DHCP not static IP config is enabled.
		return nil
	}
	// Static configuration is either merged with or replaces DHCP-provided
	// settings, depending on the IgnoreDhcp* flags. Since only one DomainName
	// can be reported per port, a statically configured value (if set) takes
	// precedence over the DHCP-provided one. And in the case of multiple DHCP-provided
	// domain names, we pick the domain name for the preferred IP version
	// (specified by types.NetworkType).
	portStatus.DomainName = portConfig.DomainName
	haveStaticDN := portConfig.DomainName != ""
	portStatus.DNSServers = append([]net.IP{}, portConfig.DNSServers...) // copy slice
	if portConfig.IgnoreDhcpDNSConfig {
		return nil
	}
	ifIndex, exists, err := m.NetworkMonitor.GetInterfaceIndex(portConfig.IfName)
	if !exists {
		return nil
	}
	if err != nil {
		return fmt.Errorf("getDNSInfo: failed to get index for interface %s: %v",
			portConfig.IfName, err)
	}
	dnsInfoList, err := m.NetworkMonitor.GetInterfaceDNSInfo(ifIndex)
	if err != nil {
		return fmt.Errorf("getDNSInfo: failed to get DNS info for interface %s: %v",
			portConfig.IfName, err)
	}
	preferIPv6 := portConfig.Type == types.NetworkTypeIPV6 ||
		portConfig.Type == types.NetworkTypeIpv6Only
	for _, dnsInfo := range dnsInfoList {
		portStatus.DNSServers = append(portStatus.DNSServers, dnsInfo.DNSServers...)
		if !haveStaticDN && len(dnsInfo.Domains) > 0 {
			// We have only one DomainName field to report.
			// With dual-stack we pick the domain name for the preferred IP version.
			if portStatus.DomainName == "" || dnsInfo.ForIPv6 == preferIPv6 {
				portStatus.DomainName = dnsInfo.Domains[0]
			}
		}
	}
	portStatus.DNSServers = generics.FilterDuplicatesFn(portStatus.DNSServers,
		netutils.EqualIPs)
	return nil
}

func (m *DpcManager) getPNACStatus(portStatus *types.NetworkPortStatus,
	portConfig types.NetworkPortConfig, ifIndex int) {
	if !portConfig.PNAC.Enabled {
		portStatus.PNAC = types.PNACStatus{}
		return
	}
	var errMsg string
	portStatus.PNAC.Enabled = true
	cert := m.getEnrolledCertStatus(portConfig.PNAC.CertEnrollmentProfileName)
	certIsAvail := cert != nil &&
		cert.CertFilepath != "" &&
		cert.PrivateKeyFilepath != ""
	if !certIsAvail {
		// Report missing certificate.
		switch {
		case cert == nil:
			errMsg = fmt.Sprintf(
				"No certificate enrollment status found for SCEP profile %q",
				portConfig.PNAC.CertEnrollmentProfileName,
			)
			portStatus.PNAC.Error.SetErrorDescription(
				types.ErrorDescription{
					Error: errMsg,
				},
			)
		case cert.Error.Error != "":
			portStatus.PNAC.Error = cert.Error
			errMsg = cert.Error.Error
		default:
			errMsg = fmt.Sprintf(
				"Certificate for SCEP profile %s is not available yet (state: %s)",
				cert.CertEnrollmentProfileName, cert.CertStatus.String())
			portStatus.PNAC.Error.SetErrorDescription(
				types.ErrorDescription{
					Error: errMsg,
				})
		}
	} else {
		// Get PNAC run-time status from wpa_supplicant.
		pnacStatus, err := m.NetworkMonitor.GetPNACStatus(ifIndex)
		if err != nil {
			errMsg = fmt.Sprintf(
				"Failed to get PNAC status for interface %s with index %d: %v",
				portConfig.IfName, ifIndex, err)
			portStatus.PNAC.Error.SetErrorDescription(
				types.ErrorDescription{
					Error: errMsg,
				},
			)
		} else {
			portStatus.PNAC = pnacStatus
		}
	}
	if errMsg != "" {
		portStatus.RecordFailure(errMsg)
	}
}

func (m *DpcManager) getBondStatus(
	portStatus *types.NetworkPortStatus,
	portConfig types.NetworkPortConfig,
	dpc types.DevicePortConfig) {

	bondIfIndex, err := m.getBondIfIndex(portConfig.IfName)
	if err != nil {
		return
	}
	bondStatus, err := m.NetworkMonitor.GetBondStatus(bondIfIndex)
	if err != nil {
		m.Log.Warnf("getBondStatus: failed to get bond status for %s: %v",
			portConfig.IfName, err)
		return
	}

	portStatus.BondStatus.Mode = bondStatus.Mode

	// Active member: resolve ifindex to logical label.
	if bondStatus.ActiveMemberIfIndex > 0 {
		memberAttrs, err := m.NetworkMonitor.GetInterfaceAttrs(
			bondStatus.ActiveMemberIfIndex)
		if err == nil {
			if memberPort := dpc.LookupPortByIfName(memberAttrs.IfName); memberPort != nil {
				portStatus.BondStatus.ActiveMember = memberPort.Logicallabel
			}
		}
	}

	// MII monitoring.
	if bondStatus.Miimon > 0 {
		portStatus.BondStatus.MIIMonitor = types.BondMIIMonitorStatus{
			Enabled:         true,
			PollingInterval: bondStatus.Miimon,
			UpDelay:         bondStatus.UpDelay,
			DownDelay:       bondStatus.DownDelay,
		}
	}

	// ARP monitoring.
	if bondStatus.ArpInterval > 0 {
		portStatus.BondStatus.ARPMonitor = types.BondARPMonitorStatus{
			Enabled:         true,
			PollingInterval: bondStatus.ArpInterval,
			IPTargets:       bondStatus.ArpIPTargets,
			MissedMax:       bondStatus.ArpMissedMax,
		}
	}

	// LACP status.
	isLACP := bondStatus.LACPInfo != nil
	if isLACP {
		portStatus.BondStatus.LACP = types.BondLACPStatus{
			Enabled:            true,
			LACPRate:           portConfig.Bond.LacpRate,
			ActiveAggregatorID: bondStatus.LACPInfo.AggregatorID,
			PartnerMAC:         bondStatus.LACPInfo.PartnerMAC,
			ActorKey:           bondStatus.LACPInfo.ActorKey,
			PartnerKey:         bondStatus.LACPInfo.PartnerKey,
		}
	}

	// Per-member status (published for all bond modes).
	for _, member := range bondStatus.Members {
		memberAttrs, err := m.NetworkMonitor.GetInterfaceAttrs(member.IfIndex)
		if err != nil {
			continue
		}
		memberLL := memberAttrs.IfName
		if memberPort := dpc.LookupPortByIfName(memberAttrs.IfName); memberPort != nil {
			memberLL = memberPort.Logicallabel
		}
		memberStatus := types.BondMemberStatus{
			Logicallabel: memberLL,
			MIIUp:        member.MIIUp,
		}
		if isLACP {
			memberStatus.LACP = &types.BondMemberLACPStatus{
				AggregatorID:      member.AggregatorID,
				ActorChurnState:   member.ActorChurnState,
				PartnerChurnState: member.PartnerChurnState,
			}
		}
		portStatus.BondStatus.Members = append(portStatus.BondStatus.Members, memberStatus)
	}
}

// logBondActiveMemberChange logs a bond active member change using the already
// updated DeviceNetworkStatus to resolve labels.
func (m *DpcManager) logBondActiveMemberChange(bondIfIndex int) {
	bondAttrs, err := m.NetworkMonitor.GetInterfaceAttrs(bondIfIndex)
	if err != nil {
		// Probably a stale notification, ignore.
		return
	}
	// Find the corresponding port in DNS. The bond interface may have been
	// renamed to "k" + originalName when bridged by NIM (the bridge takes
	// the original name), so also try without the "k" prefix.
	portIfName := bondAttrs.IfName
	port := m.deviceNetStatus.LookupPortByIfName(portIfName)
	if port == nil && bondAttrs.MasterIfIndex != 0 {
		// Bond is under a bridge -- the bridge has the original port name.
		masterAttrs, err := m.NetworkMonitor.GetInterfaceAttrs(bondAttrs.MasterIfIndex)
		if err == nil && masterAttrs.IfType == "bridge" {
			port = m.deviceNetStatus.LookupPortByIfName(masterAttrs.IfName)
		}
	}
	bondLabel := portIfName
	activeMember := "none"
	if port != nil {
		bondLabel = port.Logicallabel
		if port.BondStatus.ActiveMember != "" {
			activeMember = port.BondStatus.ActiveMember
		}
	}
	m.Log.Noticef("Bond %s active member changed to %s", bondLabel, activeMember)
}

// getBondIfIndex returns the ifindex of the actual bond interface for the given
// port interface name. When the adapter is bridged by NIM, port.IfName refers
// to the bridge while the bond is renamed to "k" + port.IfName.
func (m *DpcManager) getBondIfIndex(portIfName string) (int, error) {
	ifIndex, exists, err := m.NetworkMonitor.GetInterfaceIndex(portIfName)
	if !exists || err != nil {
		return 0, fmt.Errorf("interface %s not found", portIfName)
	}
	attrs, err := m.NetworkMonitor.GetInterfaceAttrs(ifIndex)
	if err != nil {
		return 0, fmt.Errorf("failed to get attrs for %s: %w", portIfName, err)
	}
	if attrs.IfType == "bond" {
		return ifIndex, nil
	}
	if attrs.IfType == "bridge" {
		// The bond was renamed to "k" + portIfName and placed under this bridge.
		kernIfName := "k" + portIfName
		kernIfIndex, exists, err := m.NetworkMonitor.GetInterfaceIndex(kernIfName)
		if exists && err == nil {
			return kernIfIndex, nil
		}
	}
	return 0, fmt.Errorf("interface %s is neither a bond nor a bridge with a bond",
		portIfName)
}
