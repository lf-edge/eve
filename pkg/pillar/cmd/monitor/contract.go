// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

// This file is the single branch-variant mapping layer: it translates internal
// pkg/pillar/types into the stable, branch-invariant monitorapi contract.
//
// When adopting the monitor IPC contract to an older EVE release branch, this
// is the only file that should need changes — older branches have different
// type layouts and feature sets (e.g. VLANs are absent on 13.x). The contract
// package (pkg/pillar/types/monitorapi) and the generated Rust stay identical
// across branches.

import (
	"net"
	"net/netip"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/types/monitorapi"
	uuid "github.com/satori/go.uuid"
)

// onboardingStatusToContract maps the onboarding status.
func onboardingStatusToContract(s types.OnboardingStatus) monitorapi.OnboardingStatus {
	return monitorapi.OnboardingStatus{
		DeviceUUID:    s.DeviceUUID,
		HardwareModel: s.HardwareModel,
	}
}

// nodeStatusToContract assembles node identity from its several sources
// (server config, onboarding, EdgeNodeInfo, hardware serial).
func nodeStatusToContract(server string, onboarded bool, nodeUUID uuid.UUID,
	enInfo types.EdgeNodeInfo, serial string) monitorapi.NodeStatus {
	return monitorapi.NodeStatus{
		Server:    server,
		NodeUUID:  nodeUUID,
		Onboarded: onboarded,
		NodeName:  enInfo.DeviceName,
		Serial:    serial,
	}
}

func appSummaryToContract(s types.AppInstanceSummary) monitorapi.AppSummary {
	return monitorapi.AppSummary{
		Starting: uint32(s.TotalStarting),
		Running:  uint32(s.TotalRunning),
		Stopping: uint32(s.TotalStopping),
		Error:    uint32(s.TotalError),
	}
}

func ledBlinkCounterToContract(c types.LedBlinkCounter) monitorapi.LedBlinkCounter {
	return monitorapi.LedBlinkCounter{BlinkCounter: uint32(c.BlinkCounter)}
}

func tuiConfigToContract(logLevel string) monitorapi.TUIConfig {
	return monitorapi.TUIConfig{LogLevel: logLevel}
}

func downloaderStatusToContract(s types.DownloaderStatus) monitorapi.DownloaderStatus {
	return monitorapi.DownloaderStatus{
		Name:        s.Name,
		State:       s.State.String(),
		ContentType: s.ContentType,
		Progress:    uint32(s.Progress),
		CurrentSize: s.CurrentSize,
		TotalSize:   s.TotalSize,
		Error:       s.Error,
	}
}

func zedAgentStatusToContract(s types.ZedAgentStatus) monitorapi.ZedAgentStatus {
	return monitorapi.ZedAgentStatus{
		ConfigStatus:    configGetStatusToContract(s.ConfigGetStatus),
		DeviceState:     deviceStateToContract(s.DeviceState),
		AttestState:     attestStateToContract(s.AttestState),
		AttestError:     s.AttestError,
		BootReason:      bootReasonToContract(s.RequestedBootReason),
		RebootReason:    s.RequestedRebootReason,
		MaintenanceMode: s.MaintenanceMode,
	}
}

func configGetStatusToContract(s types.ConfigGetStatus) monitorapi.ConfigGetStatus {
	switch s {
	case types.ConfigGetFail:
		return monitorapi.ConfigGetStatusFail
	case types.ConfigGetTemporaryFail:
		return monitorapi.ConfigGetStatusTemporaryFail
	case types.ConfigGetReadSaved:
		return monitorapi.ConfigGetStatusReadSaved
	default:
		return monitorapi.ConfigGetStatusSuccess
	}
}

func deviceStateToContract(s types.DeviceState) monitorapi.DeviceState {
	switch s {
	case types.DEVICE_STATE_ONLINE:
		return monitorapi.DeviceStateOnline
	case types.DEVICE_STATE_REBOOTING:
		return monitorapi.DeviceStateRebooting
	case types.DEVICE_STATE_MAINTENANCE_MODE:
		return monitorapi.DeviceStateMaintenanceMode
	case types.DEVICE_STATE_BASEOS_UPDATING:
		return monitorapi.DeviceStateBaseOsUpdating
	case types.DEVICE_STATE_BOOTING:
		return monitorapi.DeviceStateBooting
	case types.DEVICE_STATE_PREPARING_POWEROFF:
		return monitorapi.DeviceStatePreparingPowerOff
	case types.DEVICE_STATE_POWERING_OFF:
		return monitorapi.DeviceStatePoweringOff
	case types.DEVICE_STATE_PREPARED_POWEROFF:
		return monitorapi.DeviceStatePreparedPowerOff
	default:
		return monitorapi.DeviceStateUnspecified
	}
}

func attestStateToContract(s types.AttestState) monitorapi.AttestState {
	switch s {
	case types.StateNonceWait:
		return monitorapi.AttestStateNonceWait
	case types.StateInternalQuoteWait:
		return monitorapi.AttestStateInternalQuoteWait
	case types.StateInternalEscrowWait:
		return monitorapi.AttestStateInternalEscrowWait
	case types.StateAttestWait:
		return monitorapi.AttestStateAttestWait
	case types.StateAttestEscrowWait:
		return monitorapi.AttestStateAttestEscrowWait
	case types.StateRestartWait:
		return monitorapi.AttestStateRestartWait
	case types.StateComplete:
		return monitorapi.AttestStateComplete
	default: // StateNone, StateAny
		return monitorapi.AttestStateNone
	}
}

func bootReasonToContract(s types.BootReason) monitorapi.BootReason {
	switch s {
	case types.BootReasonFirst:
		return monitorapi.BootReasonFirst
	case types.BootReasonRebootCmd:
		return monitorapi.BootReasonRebootCmd
	case types.BootReasonUpdate:
		return monitorapi.BootReasonUpdate
	case types.BootReasonFallback:
		return monitorapi.BootReasonFallback
	case types.BootReasonDisconnect:
		return monitorapi.BootReasonDisconnect
	case types.BootReasonFatal:
		return monitorapi.BootReasonFatal
	case types.BootReasonOOM:
		return monitorapi.BootReasonOom
	case types.BootReasonWatchdogHung:
		return monitorapi.BootReasonWatchdogHung
	case types.BootReasonWatchdogPid:
		return monitorapi.BootReasonWatchdogPid
	case types.BootReasonKernel:
		return monitorapi.BootReasonKernel
	case types.BootReasonPowerFail:
		return monitorapi.BootReasonPowerFail
	case types.BootReasonUnknown:
		return monitorapi.BootReasonUnknown
	case types.BootReasonVaultFailure:
		return monitorapi.BootReasonVaultFailure
	case types.BootReasonPoweroffCmd:
		return monitorapi.BootReasonPoweroffCmd
	case types.BootReasonParseFail:
		return monitorapi.BootReasonParseFail
	default:
		return monitorapi.BootReasonNone
	}
}

// deviceNetworkStatusToContract maps the runtime network status, nesting VLAN
// sub-interfaces under their parent physical port so the TUI gets a ready-made
// tree instead of a flat list it must correlate.
func deviceNetworkStatusToContract(dns types.DeviceNetworkStatus) monitorapi.NetworkStatus {
	var ifaces []monitorapi.NetworkInterface
	byLabel := map[string]int{} // parent logical label -> index in ifaces
	var vlanPorts []types.NetworkPortStatus

	for _, port := range dns.Ports {
		if port.L2Type == types.L2LinkTypeVLAN {
			vlanPorts = append(vlanPorts, port)
			continue
		}
		byLabel[port.Logicallabel] = len(ifaces)
		ifaces = append(ifaces, monitorapi.NetworkInterface{
			Name:    port.IfName,
			Label:   port.Logicallabel,
			MAC:     macString(port.MacAddr),
			Up:      port.Up,
			IsMgmt:  port.IsMgmt,
			Cost:    port.Cost,
			Media:   mediaToContract(port),
			Network: portNetworkToContract(port),
		})
	}

	for _, port := range vlanPorts {
		vlan := monitorapi.VLAN{
			ID:      port.VLAN.ID,
			Name:    port.IfName,
			Label:   port.Logicallabel,
			Up:      port.Up,
			IsMgmt:  port.IsMgmt,
			Network: portNetworkToContract(port),
		}
		if idx, ok := byLabel[port.VLAN.ParentPort]; ok {
			ifaces[idx].VLANs = append(ifaces[idx].VLANs, vlan)
			continue
		}
		// Parent not present in status: surface the VLAN as a top-level port so
		// its data isn't silently dropped.
		ifaces = append(ifaces, monitorapi.NetworkInterface{
			Name:    port.IfName,
			Label:   port.Logicallabel,
			Up:      port.Up,
			IsMgmt:  port.IsMgmt,
			Cost:    port.Cost,
			Media:   monitorapi.MediaEthernet{},
			Network: portNetworkToContract(port),
		})
	}

	return monitorapi.NetworkStatus{DPCKey: dns.DPCKey, Interfaces: ifaces}
}

// portNetworkToContract maps the L3 state shared by physical ports and VLANs.
func portNetworkToContract(port types.NetworkPortStatus) monitorapi.PortNetwork {
	pn := monitorapi.PortNetwork{
		IsDHCP: port.Dhcp == types.DhcpTypeClient,
		Domain: port.DomainName,
		Proxy:  proxyToContract(port.ProxyConfig),
	}
	for _, ai := range port.AddrInfoList {
		addr, ok := netip.AddrFromSlice(normalizeIP(ai.Addr))
		if !ok {
			continue
		}
		switch {
		case addr.Is4():
			pn.IPv4 = append(pn.IPv4, addr)
		case addr.Is6() && !addr.IsLinkLocalUnicast():
			pn.IPv6 = append(pn.IPv6, addr)
		}
	}
	if p, ok := prefixFromIPNet(port.IPv4Subnet); ok {
		pn.Subnet = &p
	}
	for _, r := range port.DefaultRouters {
		if a, ok := netip.AddrFromSlice(normalizeIP(r)); ok {
			pn.Routes = append(pn.Routes, a)
		}
	}
	for _, d := range port.DNSServers {
		if a, ok := netip.AddrFromSlice(normalizeIP(d)); ok {
			pn.DNSServers = append(pn.DNSServers, a)
		}
	}
	for _, n := range port.NtpServers {
		if s := n.String(); s != "" {
			pn.NTPServers = append(pn.NTPServers, s)
		}
	}
	if port.TestResults.LastError != "" {
		pn.Errors = append(pn.Errors, port.TestResults.LastError)
	}
	return pn
}

// proxyToContract collapses EVE's flat ProxyConfig (where WPAD/PAC/manual flags
// can coexist) into the contract's single-mode union, by priority.
func proxyToContract(pc types.ProxyConfig) monitorapi.ProxySettings {
	switch {
	case pc.NetworkProxyEnable:
		return monitorapi.ProxyWpad{URL: optString(pc.NetworkProxyURL)}
	case pc.Pacfile != "":
		return monitorapi.ProxyPac{PacFile: pc.Pacfile}
	case len(pc.Proxies) > 0:
		var servers []monitorapi.ProxyServer
		for _, p := range pc.Proxies {
			scheme := proxyScheme(p.Type)
			if scheme == "" {
				continue
			}
			servers = append(servers, monitorapi.ProxyServer{
				Scheme: scheme,
				Host:   p.Server,
				Port:   uint16(p.Port),
			})
		}
		if len(servers) == 0 {
			return monitorapi.ProxyNone{}
		}
		return monitorapi.ProxyManual{Servers: servers, Exceptions: splitExceptions(pc.Exceptions)}
	default:
		return monitorapi.ProxyNone{}
	}
}

// mediaToContract derives the physical-medium union from the port's wireless
// config/status (Ethernet when not wireless).
func mediaToContract(port types.NetworkPortStatus) monitorapi.NetworkMedia {
	switch port.WirelessCfg.WType {
	case types.WirelessTypeWifi:
		var ssid string
		if len(port.WirelessCfg.Wifi) > 0 {
			ssid = port.WirelessCfg.Wifi[0].SSID
		}
		return monitorapi.MediaWifi{SSID: ssid}
	case types.WirelessTypeCellular:
		return cellularToContract(port)
	default:
		return monitorapi.MediaEthernet{}
	}
}

func cellularToContract(port types.NetworkPortStatus) monitorapi.MediaCellular {
	st := port.WirelessStatus.Cellular
	mc := monitorapi.MediaCellular{
		Modem:    firstNonEmpty(st.Module.Model, st.Module.Name),
		IMEI:     st.Module.IMEI,
		Operator: firstNonEmpty(st.CurrentProvider.Description, st.CurrentProvider.PLMN),
		Roaming:  st.CurrentProvider.Roaming,
	}
	for _, rat := range st.CurrentRATs {
		mc.RATs = append(mc.RATs, string(rat))
	}
	// APN is config, keyed by SIM slot.
	apnBySlot := map[uint8]string{}
	for _, ap := range port.WirelessCfg.CellularV2.AccessPoints {
		apnBySlot[ap.SIMSlot] = ap.APN
	}
	for _, sim := range st.SimCards {
		mc.SIMs = append(mc.SIMs, monitorapi.SIM{
			Slot:      uint32(sim.SlotNumber),
			Activated: sim.SlotActivated,
			State:     sim.State,
			APN:       apnBySlot[sim.SlotNumber],
			ICCID:     sim.ICCID,
			IMSI:      sim.IMSI,
		})
	}
	for _, p := range st.VisibleProviders {
		mc.VisibleProviders = append(mc.VisibleProviders, monitorapi.CellProvider{
			PLMN:        p.PLMN,
			Description: p.Description,
			Forbidden:   p.Forbidden,
		})
	}
	return mc
}

func proxyScheme(t types.NetworkProxyType) monitorapi.ProxyScheme {
	switch t {
	case types.NetworkProxyTypeHTTP:
		return monitorapi.ProxySchemeHTTP
	case types.NetworkProxyTypeHTTPS:
		return monitorapi.ProxySchemeHTTPS
	case types.NetworkProxyTypeSOCKS:
		return monitorapi.ProxySchemeSOCKS
	case types.NetworkProxyTypeFTP:
		return monitorapi.ProxySchemeFTP
	default:
		return "" // NOPROXY / LAST: skip
	}
}

// ---- small helpers ----

func macString(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return ""
	}
	return mac.String()
}

// normalizeIP collapses a 4-in-16 representation so netip reports the right family.
func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func prefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(normalizeIP(n.IP))
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr, ones).Masked(), true
}

func splitExceptions(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
