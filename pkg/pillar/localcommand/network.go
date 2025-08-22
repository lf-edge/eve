// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// networkURLPath is the REST API path used to publish the current network
	// configuration and optionally retrieve a locally-made network configuration
	// for a subset of ports.
	networkURLPath = "/api/v1/network"
	// savedNetworkConfigFile is the filename used to persist the locally-made
	// network configuration.
	savedNetworkConfigFile = "localnetworkconfig"
	// networkPOSTInterval defines the normal interval for periodic POST requests to
	// publish the current network configuration and optionally retrieve a locally-made
	// network configuration for a subset of ports.
	networkPOSTInterval = time.Minute
	// networkPOSTThrottledInterval is the backoff interval used when LPS
	// signals throttling by returning HTTP 404.
	networkPOSTThrottledInterval = time.Hour
)

// Used as a constant.
var emptyConfig = types.DevicePortConfig{
	Version: types.DPCIsMgmt,
	Key:     "lps",
}

// initializeNetworkConfig initializes the local network configuration and sets up
// the periodic ticker. Loads persisted configuration if available, otherwise sets
// the default (empty local network configuration).
func (lc *LocalCmdAgent) initializeNetworkConfig() {
	lc.networkTicker = newTaskTicker(networkPOSTInterval)
	lc.networkConfig = emptyConfig
	config, err := lc.readSavedNetworkConfig()
	if err != nil {
		lc.Log.Errorf("%s: readSavedNetworkConfig failed: %v", logPrefix, err)
		// Overwrite missing/invalid persisted config with empty content.
		lc.persistNetworkConfig()
	} else {
		lc.networkConfig = config
	}
}

// runNetworkTask periodically publishes the current network configuration
// and may retrieve locally-generated configs for a subset of ports from LPS.
func (lc *LocalCmdAgent) runNetworkTask() {
	lc.Log.Functionf("%s: runNetworkTask: waiting for the first trigger", logPrefix)
	// Wait for the first trigger.
	<-lc.networkTicker.tickerChan()
	lc.Log.Functionf("%s: runNetworkTask: received the first trigger", logPrefix)
	// Trigger again to pass into the loop.
	lc.TriggerNetworkPOST()

	wdName := watchdogPrefix + "network"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	lc.Watchdog.RegisterFileWatchdog(wdName)

	task := func() {
		if paused := lc.tc.startTask(); paused {
			return
		}
		defer lc.tc.endTask()
		start := time.Now()
		networkConfig, receivedAt := lc.postNetworkInfo()
		lc.lastNetworkErr = lc.applyLocalNetworkConfig(networkConfig, receivedAt)
		lc.Watchdog.CheckMaxTimeTopic(wdName, "networkTask", start,
			warningTime, errorTime)
	}

	for {
		select {
		case <-lc.networkTicker.tickerChan():
			task()
		case <-stillRunning.C:
		}
		lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	}
}

// TriggerNetworkPOST forces an immediate tick of the networkTicker.
func (lc *LocalCmdAgent) TriggerNetworkPOST() {
	lc.networkTicker.tickNow()
}

// GetNetworkConfig returns the most recently submitted local network configuration
// from LPS.
func (lc *LocalCmdAgent) GetNetworkConfig() types.DevicePortConfig {
	lc.networkConfigMx.RLock()
	defer lc.networkConfigMx.RUnlock()
	return lc.networkConfig
}

// updateNetworkTicker adjusts the networkTicker’s interval.
// If throttling is enabled, the interval is stretched to the throttled interval
// (1 hour); otherwise, it returns to the normal 1-minute cadence.
func (lc *LocalCmdAgent) updateNetworkTicker(throttle bool) {
	interval := networkPOSTInterval
	if throttle {
		interval = networkPOSTThrottledInterval
	}
	lc.networkTicker.update(throttle, interval)
}

// postNetworkInfo reports the current network configuration to the LPS
// and returns locally-made network configuration for a subset of ports
// received in response.
//
// Returns:
//   - A LocalNetworkConfig if LPS responds with 200/201.
//   - Nil if LPS is not configured, no addresses are available,
//     LPS returns 204 (no updates to the previously submitted local config),
//     or all attempts fail.
//
// Status code handling:
//   - 404: switch to throttled posting interval, return nil.
//   - 200/201: return local config (token is not checked in this function).
//   - 204: no updates to the previously submitted local config to apply, return nil.
//   - Any other error or status: log and try other LPS addresses; if all fail, return nil.
func (lc *LocalCmdAgent) postNetworkInfo() (*profile.LocalNetworkConfig, time.Time) {
	var receivedRespAt time.Time
	if lc.lpsURL == nil {
		// LPS is not configured.
		return nil, receivedRespAt
	}
	if lc.lpsAddresses.empty() {
		lc.Log.Functionf(
			"%s: postNetworkInfo: cannot find any configured apps for LPS URL: %s",
			logPrefix, lc.lpsURL)
		return nil, receivedRespAt
	}

	netInfo, err := lc.collectNetworkInfo()
	if err != nil {
		lc.Log.Errorf("%s: collectNetworkInfo failed, skipping postNetworkInfo: %v",
			logPrefix, err)
		return nil, receivedRespAt
	}
	var errList []string
	for intf, srvAddrs := range lc.lpsAddresses.addrsByIface {
		for _, srvAddr := range srvAddrs {
			fullURL := srvAddr.destURL.String() + networkURLPath
			localConfig := &profile.LocalNetworkConfig{}
			resp, err := lc.CtrlClient.SendLocalProto(
				fullURL, intf, srvAddr.sourceIP, netInfo, localConfig)
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			receivedRespAt = time.Now()
			switch resp.StatusCode {
			case http.StatusNotFound:
				// Throttle sending to be about once per hour.
				lc.updateNetworkTicker(true)
				// Apply an empty LPS config to remove all local network overrides
				// and revert ports back to the controller-provided configuration.
				localConfig = &profile.LocalNetworkConfig{
					ServerToken: lc.lpsConfig.LpsToken,
				}
				return localConfig, receivedRespAt
			case http.StatusOK, http.StatusCreated:
				lc.updateNetworkTicker(false)
				return localConfig, receivedRespAt
			case http.StatusNoContent:
				lc.Log.Tracef("%s: LPS %s indicates no updates are needed "+
					"for the previously submitted local network configuration",
					logPrefix, lc.lpsURL)
				lc.updateNetworkTicker(false)
				return nil, receivedRespAt
			default:
				errList = append(errList, fmt.Sprintf(
					"wrong response status code: %d", resp.StatusCode))
				continue
			}
		}
	}
	lc.Log.Errorf("%s: postNetworkInfo: all attempts failed: %s",
		logPrefix, strings.Join(errList, ";"))
	return nil, receivedRespAt
}

// collectNetworkInfo combines information from various pubsub topics
// related to network configuration/status and returns a NetworkInfo message
// for publishing to the LPS.
func (lc *LocalCmdAgent) collectNetworkInfo() (*profile.NetworkInfo, error) {
	lc.networkConfigMx.RLock()
	defer lc.networkConfigMx.RUnlock()

	// Fetch the list of network configurations maintained by NIM.
	obj, err := lc.DevicePortConfigList.Get("global")
	if err != nil {
		err = fmt.Errorf(
			"failed to fetch the list of persisted network configurations: %w", err)
		lc.Log.Errorf("%s: collectNetworkInfo: %v", logPrefix, err)
		return nil, err
	}
	dpcl := obj.(types.DevicePortConfigList)
	if dpcl.CurrentIndex < 0 || dpcl.CurrentIndex >= len(dpcl.PortConfigList) {
		err = fmt.Errorf("no network configuration is currently active: %w", err)
		lc.Log.Errorf("%s: collectNetworkInfo: %v", logPrefix, err)
		return nil, err
	}
	latestDPC := dpcl.PortConfigList[0]
	currentDPC := dpcl.PortConfigList[dpcl.CurrentIndex]

	// Fetch the current network status.
	// This is needed to determine for each port which config is currently being applied.
	obj, err = lc.DeviceNetworkStatus.Get("global")
	if err != nil {
		err = fmt.Errorf(
			"failed to fetch the status of the current network configuration: %w", err)
		lc.Log.Errorf("%s: collectNetworkInfo: %v", logPrefix, err)
		return nil, err
	}
	dns := obj.(types.DeviceNetworkStatus)

	// Convert latest (and potentially also fallback) network config into proto.
	latestConfig := lc.dpcToProto(latestDPC, dns)
	var fallbackConfig []*profile.NetworkPortConfig
	isUsingFallbackConfig := dpcl.CurrentIndex > 0
	if isUsingFallbackConfig {
		fallbackConfig = lc.dpcToProto(currentDPC, dns)
	}

	var lastNetErrMsg string
	if lc.lastNetworkErr != nil {
		lastNetErrMsg = lc.lastNetworkErr.Error()
	}

	// Construct and return the final NetworkInfo message,
	// including the latest config, fallback config (if any),
	// current testing status, and the local config.
	networkInfo := &profile.NetworkInfo{
		LatestConfig:          latestConfig,
		ConfigTesting:         lc.getTestingStatus(currentDPC),
		IsUsingFallbackConfig: isUsingFallbackConfig,
		FallbackConfig:        fallbackConfig,
		LocalConfig: &profile.LocalNetworkConfigInfo{
			Ports:        lc.dpcToProto(lc.networkConfig, dns),
			ErrorMessage: lastNetErrMsg,
		},
	}
	return networkInfo, nil
}

// Convert DevicePortConfig into the corresponding list of port configs
// in the protobuf format.
func (lc *LocalCmdAgent) dpcToProto(dpc types.DevicePortConfig,
	dns types.DeviceNetworkStatus) (ports []*profile.NetworkPortConfig) {
	for _, port := range dpc.Ports {
		protoConfig := &profile.NetworkPortConfig{
			LogicalLabel: port.Logicallabel,
			PortAddresses: &profile.NetworkPortAddresses{
				InterfaceName: port.IfName,
				PciAddress:    port.PCIAddr,
				UsbAddress:    port.USBAddr,
			},
			UseDhcp: port.Dhcp == types.DhcpTypeClient,
			DhcpOptionsIgnore: &evecommon.DhcpOptionsIgnore{
				NtpServerExclusively:   port.IgnoreDhcpNtpServers,
				IpAddressesExclusively: port.IgnoreDhcpIPAddresses,
				DnsConfigExclusively:   port.IgnoreDhcpDNSConfig,
				GatewaysExclusively:    port.IgnoreDhcpGateways,
			},
			DnsServers: utils.ToStrings(port.DNSServers),
			DnsDomain:  port.DomainName,
			NtpServers: utils.ToStrings(port.NTPServers),
			Mtu:        uint32(port.MTU),
			ProxyConfig: &evecommon.ProxyConfig{
				NetworkProxyEnable: port.NetworkProxyEnable,
				Exceptions:         port.Exceptions,
				Pacfile:            port.Pacfile,
				NetworkProxyURL:    port.NetworkProxyURL,
				ProxyCertPEM:       port.ProxyCertPEM,
			},
			ConfigSource: port.ConfigSource.ToProto(),
		}

		// Determine if this port's config is currently applied.
		portStatus := dns.LookupPortByLogicallabel(port.Logicallabel)
		if portStatus != nil {
			if port.ConfigSource == portStatus.ConfigSource {
				protoConfig.ConfigApplied = true
			}
		}

		// Map internal IP version type to proto.
		switch port.Type {
		case types.NetworkTypeIPv4, types.NetworkTypeIPV6, types.NetworkTypeDualStack:
			protoConfig.IpVersion = profile.IPVersion_IP_VERSION_DUAL_STACK
		case types.NetworkTypeIpv4Only:
			protoConfig.IpVersion = profile.IPVersion_IP_VERSION_IPV4_ONLY
		case types.NetworkTypeIpv6Only:
			protoConfig.IpVersion = profile.IPVersion_IP_VERSION_IPV6_ONLY
		default:
			protoConfig.IpVersion = profile.IPVersion_IP_VERSION_UNSPECIFIED
		}

		// Copy error message if the port is in error state.
		if port.HasError() {
			protoConfig.ErrorMessage = dpc.LastError
		}

		// Convert proxy entries to proto.
		for _, proxy := range port.Proxies {
			protoConfig.ProxyConfig.Proxies = append(protoConfig.ProxyConfig.Proxies,
				proxy.ToProto())
		}

		// Static IP/subnet and gateway.
		if port.AddrSubnet != "" {
			protoConfig.IpAddresses = []string{port.AddrSubnet}
		}
		if port.Gateway != nil {
			protoConfig.Gateways = []string{port.Gateway.String()}
		}
		if port.Gateway != nil && port.Gateway.IsUnspecified() {
			protoConfig.WithoutDefaultRoute = true
		}
		if port.Dhcp == types.DhcpTypeStatic && port.Gateway == nil {
			protoConfig.WithoutDefaultRoute = true
		}
		if port.Dhcp == types.DhcpTypeClient && port.IgnoreDhcpGateways &&
			port.Gateway == nil {
			protoConfig.WithoutDefaultRoute = true
		}

		switch port.WirelessCfg.WType {
		// Convert cellular configuration.
		case types.WirelessTypeCellular:
			protoConfig.WirelessDeviceType = profile.WirelessType_WIRELESS_TYPE_CELLULAR
			cellularV2 := port.WirelessCfg.CellularV2
			cellConfig := &profile.CellularConfig{
				Probe: &profile.CellularConnectivityProbe{
					Disable:     cellularV2.Probe.Disable,
					CustomProbe: cellularV2.Probe.UserDefinedProbe.ToProto(),
				},
				LocationTracking: cellularV2.LocationTracking,
			}
			var accessPoint *types.CellularAccessPoint
			for _, ap := range port.WirelessCfg.CellularV2.AccessPoints {
				if ap.Activated {
					accessPoint = &ap
					break
				}
			}
			if accessPoint != nil {
				cellConfig.Apn = accessPoint.APN
				cellConfig.AttachApn = accessPoint.AttachAPN
				cellConfig.IpType = accessPoint.IPType.ToProto(lc.Log)
				cellConfig.AttachIpType = accessPoint.AttachIPType.ToProto(lc.Log)
				cellConfig.ActivateSimSlot = uint32(accessPoint.SIMSlot)
				cellConfig.ForbidRoaming = accessPoint.ForbidRoaming
				cellConfig.DefaultBearerAuth = &profile.CellularNetworkAuth{
					AuthProtocol: accessPoint.AuthProtocol.ToProto(),
				}
				cellConfig.AttachBearerAuth = &profile.CellularNetworkAuth{
					AuthProtocol: accessPoint.AttachAuthProtocol.ToProto(),
				}
			} else {
				lc.Log.Warnf("%s: dpcToProto: port %q: no activated cellular access point",
					logPrefix, port.Logicallabel)
			}
			protoConfig.WirelessConfig = &profile.NetworkPortConfig_CellularConfig{
				CellularConfig: cellConfig,
			}

		// Convert WiFi configuration.
		case types.WirelessTypeWifi:
			protoConfig.WirelessDeviceType = profile.WirelessType_WIRELESS_TYPE_WIFI
			var wifiConfig types.WifiConfig
			if len(port.WirelessCfg.Wifi) > 0 {
				wifiConfig = port.WirelessCfg.Wifi[0]
			}
			protoConfig.WirelessConfig = &profile.NetworkPortConfig_WifiConfig{
				WifiConfig: &profile.WifiConfig{
					Ssid:      wifiConfig.SSID,
					KeyScheme: wifiConfig.KeyScheme.ToProto(),
				},
			}
		}
		ports = append(ports, protoConfig)
	}
	return ports
}

// getTestingStatus returns the current testing status for a device network configuration.
func (lc *LocalCmdAgent) getTestingStatus(
	dpc types.DevicePortConfig) *profile.NetworkConfigTestingStatus {
	var connError string
	if dpc.HasError() {
		connError = dpc.LastError
	}
	return &profile.NetworkConfigTestingStatus{
		ControllerReachable: dpc.WasDPCWorking(),
		ConnectivityError:   connError,
		LastTestTime:        timestamppb.New(dpc.LastTestTime()),
		TestingInProgress:   dpc.State.InProgress(),
		TestingPhase:        dpc.State.Describe(),
	}
}

// applyLocalNetworkConfig applies a local network configuration received
// from the LPS.
//
// If the provided config is nil, no action is taken.
// If the token from LPS does not match the one received from the controller,
// the configuration is rejected.
// The function compares the new configuration against the current one
// and only applies and persists it if there is a meaningful difference.
func (lc *LocalCmdAgent) applyLocalNetworkConfig(
	localConfig *profile.LocalNetworkConfig, receivedAt time.Time) (err error) {
	if localConfig == nil {
		return nil
	}
	if localConfig.GetServerToken() != lc.lpsConfig.LpsToken {
		err = errors.New("invalid token submitted by LPS")
		lc.Log.Errorf("%s: %v", logPrefix, err)
		return err
	}

	// Convert LocalNetworkConfig to DPC.
	newNetworkConfig := emptyConfig
	for _, port := range localConfig.GetPorts() {
		newPortConfig, err := lc.networkPortConfigFromProto(port, receivedAt)
		if err != nil {
			return err
		}
		newNetworkConfig.Ports = append(newNetworkConfig.Ports, *newPortConfig)
	}

	lc.networkConfigMx.Lock()
	if lc.networkConfig.MostlyEqual(&newNetworkConfig) {
		// No actual configuration change to apply, just refresh the modification
		// timestamp of the persisted config.
		lc.touchNetworkConfig()
		lc.networkConfigMx.Unlock()
		return nil
	}
	lc.networkConfig = newNetworkConfig
	lc.persistNetworkConfig()
	lc.networkConfigMx.Unlock()
	lc.Log.Noticef("%s: Applying new local network configuration: %+v",
		logPrefix, newNetworkConfig)
	lc.ConfigAgent.ApplyLocalNetworkConfig(newNetworkConfig)
	return nil
}

// Convert protobuf definition of a port network configuration into the corresponding
// internal data type.
func (lc *LocalCmdAgent) networkPortConfigFromProto(protoConfig *profile.NetworkPortConfig,
	receivedAt time.Time) (config *types.NetworkPortConfig, err error) {
	if protoConfig == nil {
		return nil, nil
	}
	config = &types.NetworkPortConfig{
		ConfigSource: types.PortConfigSource{
			Origin:      types.NetworkConfigOriginLPS,
			SubmittedAt: receivedAt,
		},
	}
	logicalLabel := protoConfig.GetLogicalLabel()
	config.Logicallabel = logicalLabel

	// Lookup port physical addresses by the logical label.
	if logicalLabel == "" {
		err = errors.New("port configuration with undefined logical label")
		lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
			logPrefix, err, protoConfig)
		return nil, err
	}
	obj, err := lc.DevicePortConfigList.Get("global")
	if err != nil {
		err = fmt.Errorf(
			"failed to fetch the list of persisted network configurations: %w", err)
		lc.Log.Errorf("%s: networkPortConfigFromProto: %v", logPrefix, err)
		return nil, err
	}
	dpcl := obj.(types.DevicePortConfigList)
	if dpcl.CurrentIndex < 0 || dpcl.CurrentIndex >= len(dpcl.PortConfigList) {
		err = fmt.Errorf("no network configuration is currently active: %w", err)
		lc.Log.Errorf("%s: networkPortConfigFromProto: %v", logPrefix, err)
		return nil, err
	}
	dpc := dpcl.PortConfigList[dpcl.CurrentIndex]
	port := dpc.LookupPortByLogicallabel(logicalLabel)
	if port == nil {
		err = fmt.Errorf("port with logical label %q not found in the current config",
			logicalLabel)
		lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
			logPrefix, err, protoConfig)
		return nil, err
	}
	config.IfName = port.IfName
	config.USBAddr = port.USBAddr
	config.PCIAddr = port.PCIAddr
	config.Phylabel = port.Phylabel

	// Parse and validate MTU settings.
	mtu := protoConfig.GetMtu()
	switch {
	case mtu != 0 && mtu < types.MinMTU:
		err = fmt.Errorf("port %q: MTU (%d) is too small",
			logicalLabel, mtu)
		lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
			logPrefix, err, protoConfig)
		return nil, err
	case mtu > types.MaxMTU:
		err = fmt.Errorf("port %q: MTU (%d) is too large",
			logicalLabel, mtu)
		lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
			logPrefix, err, protoConfig)
		return nil, err
	default:
		config.MTU = uint16(mtu)
	}

	// Parse and validate IP configuration.
	switch protoConfig.IpVersion {
	case profile.IPVersion_IP_VERSION_UNSPECIFIED:
		// IP version not specified: default to dual-stack with IPv4 preferred.
		config.Type = types.NetworkTypeIPv4
	case profile.IPVersion_IP_VERSION_DUAL_STACK:
		config.Type = types.NetworkTypeDualStack
	case profile.IPVersion_IP_VERSION_IPV4_ONLY:
		config.Type = types.NetworkTypeIpv4Only
	case profile.IPVersion_IP_VERSION_IPV6_ONLY:
		config.Type = types.NetworkTypeIpv6Only
	}
	if protoConfig.UseDhcp {
		config.Dhcp = types.DhcpTypeClient
	} else {
		config.Dhcp = types.DhcpTypeStatic
	}
	if len(protoConfig.GetIpAddresses()) > 1 {
		// LPS API is ready for multiple static IP addresses, but the current
		// implementation supports only a single address.
		err = fmt.Errorf("port %q: multiple static IP addresses are not supported",
			logicalLabel)
		lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
			logPrefix, err, protoConfig)
		return nil, err
	}
	if len(protoConfig.GetIpAddresses()) == 1 {
		ipAddr := protoConfig.GetIpAddresses()[0]
		_, _, err = net.ParseCIDR(ipAddr)
		if err != nil {
			err = fmt.Errorf("port %q: invalid IP address %q: %w", logicalLabel,
				ipAddr, err)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		config.AddrSubnet = ipAddr
	}
	if len(protoConfig.GetGateways()) > 1 {
		// LPS API is ready for multiple static IP gateways, but the current
		// implementation supports only a single one.
		err = fmt.Errorf("port %q: multiple static IP gateways are not supported",
			logicalLabel)
		lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
			logPrefix, err, protoConfig)
		return nil, err
	}
	if len(protoConfig.GetGateways()) == 1 {
		gatewayIP := protoConfig.GetGateways()[0]
		ipAddr := net.ParseIP(gatewayIP)
		if ipAddr == nil {
			err = fmt.Errorf("port %q: invalid gateway IP address %q",
				logicalLabel, gatewayIP)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		config.Gateway = ipAddr
	}
	if protoConfig.WithoutDefaultRoute {
		// Setting the gateway to 0.0.0.0 disables installation of a default route,
		// applicable to both DHCP and static configurations.
		config.Gateway = net.ParseIP("0.0.0.0")
	}
	dhcpOptionsIgnore := protoConfig.GetDhcpOptionsIgnore()
	config.IgnoreDhcpIPAddresses = dhcpOptionsIgnore.GetIpAddressesExclusively()
	config.IgnoreDhcpGateways = dhcpOptionsIgnore.GetGatewaysExclusively()
	config.IgnoreDhcpDNSConfig = dhcpOptionsIgnore.GetDnsConfigExclusively()
	config.IgnoreDhcpNtpServers = dhcpOptionsIgnore.GetNtpServerExclusively()

	// Parse and validate DNS configuration.
	for _, dnsServer := range protoConfig.GetDnsServers() {
		ipAddr := net.ParseIP(dnsServer)
		if ipAddr == nil {
			err = fmt.Errorf("port %q: invalid DNS server IP address %q",
				logicalLabel, dnsServer)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		config.DNSServers = append(config.DNSServers, ipAddr)
	}
	config.DomainName = protoConfig.GetDnsDomain()

	// Parse NTP configuration.
	config.NTPServers = netutils.NewHostnameOrIPs(protoConfig.GetNtpServers()...)

	// Parse proxy configuration.
	proxyConfig := protoConfig.GetProxyConfig()
	config.NetworkProxyEnable = proxyConfig.GetNetworkProxyEnable()
	config.NetworkProxyURL = proxyConfig.GetNetworkProxyURL()
	config.Pacfile = proxyConfig.GetPacfile()
	config.Exceptions = proxyConfig.GetExceptions()
	config.ProxyCertPEM = proxyConfig.GetProxyCertPEM()
	for _, proxy := range proxyConfig.GetProxies() {
		var proxyEntry types.ProxyEntry
		proxyEntry.FromProto(proxy)
		config.Proxies = append(config.Proxies, proxyEntry)
	}

	// Parse and validate wireless configuration.
	switch protoConfig.GetWirelessDeviceType() {
	case profile.WirelessType_WIRELESS_TYPE_CELLULAR:
		cellConfig := protoConfig.GetCellularConfig()
		if cellConfig == nil {
			err = fmt.Errorf("port %q: missing cellular configuration",
				logicalLabel)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		config.WirelessCfg.WType = types.WirelessTypeCellular
		var ipType types.WwanIPType
		err = ipType.FromProto(cellConfig.GetIpType())
		if err != nil {
			err = fmt.Errorf("port %q: %w", logicalLabel, err)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		var attachIPType types.WwanIPType
		err = attachIPType.FromProto(cellConfig.GetAttachIpType())
		if err != nil {
			err = fmt.Errorf("port %q: %w", logicalLabel, err)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		var customProbe types.ConnectivityProbe
		err = customProbe.FromProto(cellConfig.GetProbe().GetCustomProbe())
		if err != nil {
			err = fmt.Errorf("port %q: %w", logicalLabel, err)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		defaultBearerAuth := cellConfig.GetDefaultBearerAuth()
		var authProtocol types.WwanAuthProtocol
		err = authProtocol.FromProto(defaultBearerAuth.GetAuthProtocol())
		if err != nil {
			err = fmt.Errorf("port %q: %w", logicalLabel, err)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		attachBearerAuth := cellConfig.GetAttachBearerAuth()
		var attachAuthProtocol types.WwanAuthProtocol
		err = attachAuthProtocol.FromProto(attachBearerAuth.GetAuthProtocol())
		if err != nil {
			err = fmt.Errorf("port %q: %w", logicalLabel, err)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		config.WirelessCfg.CellularV2 = types.CellNetPortConfig{
			AccessPoints: []types.CellularAccessPoint{
				{
					SIMSlot:      uint8(cellConfig.GetActivateSimSlot()),
					Activated:    true,
					APN:          cellConfig.GetApn(),
					IPType:       ipType,
					AuthProtocol: authProtocol,
					CleartextCredentials: types.WwanCleartextCredentials{
						Username: defaultBearerAuth.GetUsername(),
						Password: defaultBearerAuth.GetPassword(),
					},
					ForbidRoaming:      cellConfig.GetForbidRoaming(),
					AttachAPN:          cellConfig.GetAttachApn(),
					AttachIPType:       attachIPType,
					AttachAuthProtocol: attachAuthProtocol,
					AttachCleartextCredentials: types.WwanCleartextCredentials{
						Username: attachBearerAuth.GetUsername(),
						Password: attachBearerAuth.GetPassword(),
					},
				},
			},
			Probe: types.WwanProbe{
				Disable:          cellConfig.GetProbe().GetDisable(),
				UserDefinedProbe: customProbe,
			},
			LocationTracking: cellConfig.GetLocationTracking(),
		}

	case profile.WirelessType_WIRELESS_TYPE_WIFI:
		wifiConfig := protoConfig.GetWifiConfig()
		if wifiConfig == nil {
			err = fmt.Errorf("port %q: missing WiFi configuration",
				logicalLabel)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		config.WirelessCfg.WType = types.WirelessTypeWifi
		var keyScheme types.WifiKeySchemeType
		err = keyScheme.FromProto(wifiConfig.GetKeyScheme())
		if err != nil {
			err = fmt.Errorf("port %q: %w", logicalLabel, err)
			lc.Log.Errorf("%s: networkPortConfigFromProto: %v (proto=%v)",
				logPrefix, err, protoConfig)
			return nil, err
		}
		config.WirelessCfg.Wifi = []types.WifiConfig{
			{
				SSID:      wifiConfig.GetSsid(),
				KeyScheme: keyScheme,
				Identity:  wifiConfig.GetIdentity(),
				Password:  wifiConfig.GetPassword(),
			},
		}
	}
	return config, nil
}

// readSavedNetworkConfig reads persisted local network configuration from disk
// (if any exist) and unmarshals it into the DPC structure.
// Also logs the timestamp when the configuration was last modified.
// If no file exists, returns an empty DPC structure without error.
func (lc *LocalCmdAgent) readSavedNetworkConfig() (types.DevicePortConfig, error) {
	config := emptyConfig
	contents, ts, err := persist.ReadSavedConfig(lc.Log, savedNetworkConfigFile)
	if err != nil {
		return config, err
	}
	if contents != nil {
		err := json.Unmarshal(contents, &config)
		if err != nil {
			return config, err
		}
		lc.Log.Noticef("%s: Using saved local network configuration dated %s",
			logPrefix, ts.Format(time.RFC3339Nano))
		return config, nil
	}
	return config, nil
}

// persistNetworkConfig marshals the current in-memory DPC with local network
// configuration into JSON and saves it persistently on disk.
// Fatal-logs if marshalling fails.
func (lc *LocalCmdAgent) persistNetworkConfig() {
	contents, err := json.Marshal(lc.networkConfig)
	if err != nil {
		lc.Log.Fatalf("%s: persistNetworkConfig: Marshalling failed: %v", logPrefix, err)
	}
	persist.SaveConfig(lc.Log, savedNetworkConfigFile, contents)
	return
}

// touchNetworkConfig updates the modification timestamp of the persisted
// local network configuration without changing its contents.
func (lc *LocalCmdAgent) touchNetworkConfig() {
	persist.TouchSavedConfig(lc.Log, savedNetworkConfigFile)
}
