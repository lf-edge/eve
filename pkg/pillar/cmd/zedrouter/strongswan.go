// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// strongswan ipsec tunnel management routines

package zedrouter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const (
	AwsVpnClient      = "awsClient"
	AzureVpnClient    = "azureClient"
	OnPremVpnClient   = "onPremClient"
	OnPremVpnServer   = "onPremServer"
	PortIpAddrType    = "upLink" // XXX where is "upLink" set?
	AppLinkSubnetType = "appNet"
	AnyIpAddr         = "%any"
)

func strongSwanVpnConfigParse(opaqueConfig string) (types.VpnConfig, error) {
	log.Functionf("strongSwanVpnConfigParse(): parsing %s\n", opaqueConfig)
	vpnConfig := types.VpnConfig{}

	cb := []byte(opaqueConfig)
	strongSwanConfig := types.StrongSwanConfig{}
	if err := json.Unmarshal(cb, &strongSwanConfig); err != nil {
		log.Errorf("%s for strongSwanVpnConfigParse()\n", err.Error())
		return vpnConfig, err
	}

	// check for unique client profiles
	if err := checkForClientDups(strongSwanConfig); err != nil {
		return vpnConfig, err
	}

	// validate ip address/subnet configurations
	if err := vpnValidateIpAddr(strongSwanConfig.VpnGatewayIpAddr, false); err != nil {
		return vpnConfig, err
	}
	if err := vpnValidateSubnet(strongSwanConfig.VpnSubnetBlock); err != nil {
		return vpnConfig, err
	}
	if err := vpnValidateSubnet(strongSwanConfig.LocalSubnetBlock); err != nil {
		return vpnConfig, err
	}
	if err := vpnValidateLinkLocal(strongSwanConfig.VpnLocalIpAddr); err != nil {
		return vpnConfig, err
	}
	if err := vpnValidateLinkLocal(strongSwanConfig.VpnRemoteIpAddr); err != nil {
		return vpnConfig, err
	}

	for _, clientConfig := range strongSwanConfig.ClientConfigList {
		if err := vpnValidateIpAddr(clientConfig.IpAddr, false); err != nil {
			return vpnConfig, err
		}
		if err := vpnValidateSubnet(clientConfig.SubnetBlock); err != nil {
			return vpnConfig, err
		}
		tunnelConfig := clientConfig.TunnelConfig
		if err := vpnValidateLinkLocal(tunnelConfig.LocalIpAddr); err != nil {
			return vpnConfig, err
		}
		if err := vpnValidateLinkLocal(tunnelConfig.RemoteIpAddr); err != nil {
			return vpnConfig, err
		}
	}

	switch strongSwanConfig.VpnRole {
	case AwsVpnClient:
		// its always route based Vpn Service
		strongSwanConfig.PolicyBased = false
		strongSwanConfig.IsClient = true

		if len(strongSwanConfig.ClientConfigList) > 1 {
			return vpnConfig, errors.New("invalid client config")
		}
		// server ip address/subnet is must
		if strongSwanConfig.VpnGatewayIpAddr == "" ||
			strongSwanConfig.VpnGatewayIpAddr == AnyIpAddr ||
			strongSwanConfig.VpnGatewayIpAddr == PortIpAddrType {
			return vpnConfig, errors.New("vpn gateway not set")
		}
		if strongSwanConfig.VpnSubnetBlock == "" ||
			strongSwanConfig.VpnSubnetBlock == AppLinkSubnetType {
			return vpnConfig, errors.New("vpn subnet not set")
		}
		// flat configuration
		if len(strongSwanConfig.ClientConfigList) == 0 {
			if strongSwanConfig.VpnLocalIpAddr == "" ||
				strongSwanConfig.VpnRemoteIpAddr == "" {
				return vpnConfig, errors.New("invalid tunnel parameters")
			}
			// copy the parameters to the new structure
			strongSwanConfig.ClientConfigList = make([]types.VpnClientConfig, 1)
			clientConfig := new(types.VpnClientConfig)
			clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			clientConfig.TunnelConfig.LocalIpAddr = strongSwanConfig.VpnLocalIpAddr
			clientConfig.TunnelConfig.RemoteIpAddr = strongSwanConfig.VpnRemoteIpAddr
			clientConfig.SubnetBlock = strongSwanConfig.LocalSubnetBlock
			strongSwanConfig.ClientConfigList[0] = *clientConfig
		}
		for _, clientConfig := range strongSwanConfig.ClientConfigList {
			if clientConfig.PreSharedKey == "" {
				return vpnConfig, errors.New("invalid vpn parameters")
			}
			if clientConfig.TunnelConfig.LocalIpAddr == "" ||
				clientConfig.TunnelConfig.RemoteIpAddr == "" {
				return vpnConfig, errors.New("invalid tunnel parameters")
			}
		}

	case AzureVpnClient:
		if len(strongSwanConfig.ClientConfigList) > 1 {
			return vpnConfig, errors.New("invalid client config")
		}
		strongSwanConfig.IsClient = true
		// server ip address/subnet is must
		if strongSwanConfig.VpnGatewayIpAddr == "" ||
			strongSwanConfig.VpnGatewayIpAddr == AnyIpAddr ||
			strongSwanConfig.VpnGatewayIpAddr == PortIpAddrType {
			return vpnConfig, errors.New("vpn gateway not set")
		}
		if strongSwanConfig.VpnSubnetBlock == "" ||
			strongSwanConfig.VpnSubnetBlock == AppLinkSubnetType {
			return vpnConfig, errors.New("vpn subnet not set")
		}
		// flat configuration
		if len(strongSwanConfig.ClientConfigList) == 0 {
			// copy the parameters to the new structure
			strongSwanConfig.ClientConfigList = make([]types.VpnClientConfig, 1)
			clientConfig := new(types.VpnClientConfig)
			clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			clientConfig.SubnetBlock = strongSwanConfig.LocalSubnetBlock
			strongSwanConfig.ClientConfigList[0] = *clientConfig
		}

	case OnPremVpnClient:
		if len(strongSwanConfig.ClientConfigList) > 1 {
			return vpnConfig, errors.New("invalid client config")
		}
		strongSwanConfig.IsClient = true
		// server ip address is must
		if strongSwanConfig.VpnGatewayIpAddr == "" ||
			strongSwanConfig.VpnGatewayIpAddr == AnyIpAddr ||
			strongSwanConfig.VpnGatewayIpAddr == PortIpAddrType {
			return vpnConfig, errors.New("vpn gateway not set")
		}
		// for client, server side subnet information, is must
		if strongSwanConfig.VpnSubnetBlock == "" ||
			strongSwanConfig.VpnSubnetBlock == AppLinkSubnetType {
			return vpnConfig, errors.New("server subnet block not set")
		}
		// flat configuration
		if len(strongSwanConfig.ClientConfigList) == 0 {
			strongSwanConfig.ClientConfigList = make([]types.VpnClientConfig, 1)
			clientConfig := new(types.VpnClientConfig)
			clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			clientConfig.SubnetBlock = strongSwanConfig.LocalSubnetBlock
			strongSwanConfig.ClientConfigList[0] = *clientConfig
		}

	case OnPremVpnServer:
		strongSwanConfig.IsClient = false
		// if not mentioned, assume port ip address
		if strongSwanConfig.VpnGatewayIpAddr == "" {
			strongSwanConfig.VpnGatewayIpAddr = PortIpAddrType
		}
		// if not mentioned, assume appnet subnet
		if strongSwanConfig.VpnSubnetBlock == "" {
			strongSwanConfig.VpnSubnetBlock = AppLinkSubnetType
		}
		// single client/profile flat configuration
		if len(strongSwanConfig.ClientConfigList) == 0 {
			strongSwanConfig.ClientConfigList = make([]types.VpnClientConfig, 1)
			clientConfig := new(types.VpnClientConfig)
			clientConfig.IpAddr = AnyIpAddr
			clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			clientConfig.SubnetBlock = strongSwanConfig.LocalSubnetBlock
			strongSwanConfig.ClientConfigList[0] = *clientConfig
		}
		for _, clientConfig := range strongSwanConfig.ClientConfigList {
			if clientConfig.IpAddr == PortIpAddrType {
				return vpnConfig, errors.New("client can not take port Addr")
			}
			// for route based server, client subnet information is must
			if clientConfig.SubnetBlock == "" ||
				clientConfig.SubnetBlock == AppLinkSubnetType {
				if !strongSwanConfig.PolicyBased {
					return vpnConfig, errors.New("client subnet block not set")
				}
			}
		}
	default:
		return vpnConfig, errors.New("invalid vpn role: " + strongSwanConfig.VpnRole)
	}

	log.Traceln("strongSwanVpnConfigParse: ", strongSwanConfig)

	// fill up our structure
	vpnConfig.VpnRole = strongSwanConfig.VpnRole
	vpnConfig.PolicyBased = strongSwanConfig.PolicyBased
	vpnConfig.IsClient = strongSwanConfig.IsClient
	vpnConfig.GatewayConfig.IpAddr = strongSwanConfig.VpnGatewayIpAddr
	vpnConfig.GatewayConfig.SubnetBlock = strongSwanConfig.VpnSubnetBlock
	vpnConfig.ClientConfigList = make([]types.VpnClientConfig,
		len(strongSwanConfig.ClientConfigList))

	for idx, ssClientConfig := range strongSwanConfig.ClientConfigList {
		clientConfig := new(types.VpnClientConfig)
		clientConfig.IpAddr = ssClientConfig.IpAddr
		clientConfig.SubnetBlock = ssClientConfig.SubnetBlock
		clientConfig.PreSharedKey = ssClientConfig.PreSharedKey

		if vpnConfig.IsClient {
			if clientConfig.IpAddr == "" {
				clientConfig.IpAddr = PortIpAddrType
			}
			if clientConfig.SubnetBlock == "" {
				clientConfig.SubnetBlock = AppLinkSubnetType
			}
		}

		if clientConfig.PreSharedKey == "" {
			clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
		}
		clientConfig.TunnelConfig.LocalIpAddr = ssClientConfig.TunnelConfig.LocalIpAddr
		clientConfig.TunnelConfig.RemoteIpAddr = ssClientConfig.TunnelConfig.RemoteIpAddr
		vpnConfig.ClientConfigList[idx] = *clientConfig
	}

	if logrus.GetLevel() == logrus.TraceLevel {
		if bytes, err := json.Marshal(vpnConfig); err == nil {
			log.Tracef("strongSwanConfigParse(): %s\n",
				string(bytes))
		}
	}
	return vpnConfig, nil
}

func strongSwanVpnStatusParse(opaqueStatus string) (types.VpnConfig, error) {

	log.Tracef("strongSwanVpnStatusParse: parsing %s\n", opaqueStatus)

	cb := []byte(opaqueStatus)
	vpnConfig := types.VpnConfig{}
	if err := json.Unmarshal(cb, &vpnConfig); err != nil {
		log.Errorf("strongSwanVpnStatusParse(): %v\n", err.Error())
		return vpnConfig, err
	}
	return vpnConfig, nil
}

func strongSwanVpnCreate(vpnConfig types.VpnConfig) error {

	gatewayConfig := vpnConfig.GatewayConfig

	log.Errorf("StrongSwan IpSec Vpn Create %s:%v, %s:%s\n",
		vpnConfig.VpnRole, vpnConfig.PolicyBased,
		gatewayConfig.IpAddr, gatewayConfig.SubnetBlock)

	if err := charonRouteConfigCreate(vpnConfig.PolicyBased); err != nil {
		return err
	}

	// create ipsec.conf
	if err := ipSecConfigCreate(vpnConfig); err != nil {
		return err
	}

	// create ipsec.secrets
	if err := ipSecSecretConfigCreate(vpnConfig); err != nil {
		return err
	}

	// create tunnel interface
	if err := ipLinkTunnelCreate(vpnConfig); err != nil {
		return err
	}

	// create iptable rules
	if err := ipTablesRuleCreate(vpnConfig); err != nil {
		return err
	}

	// issue sysctl for ipsec
	if err := sysctlConfigCreate(vpnConfig); err != nil {
		return err
	}

	if err := sysctlConfigSet(); err != nil {
		return err
	}

	// request ipsec service start
	if err := ipSecActivate(vpnConfig); err != nil {
		return err
	}

	// request ip route create
	if err := ipRouteCreate(vpnConfig); err != nil {
		return err
	}
	return nil
}

func strongSwanVpnDelete(vpnConfig types.VpnConfig) error {

	gatewayConfig := vpnConfig.GatewayConfig

	log.Functionf("strongSwan IpSec Vpn Delete %s:%t, %s, %s\n",
		vpnConfig.VpnRole, vpnConfig.PolicyBased,
		gatewayConfig.IpAddr, gatewayConfig.SubnetBlock)

	// reset ipsec.conf/ipsec.secrets
	// set default files in place of existing
	if err := ipSecConfigDelete(); err != nil {
		return err
	}

	if err := ipSecSecretConfigDelete(); err != nil {
		return err
	}

	// request iptables rule delete
	if err := ipTablesRulesDelete(vpnConfig); err != nil {
		return err
	}

	// request ip route delete
	if err := ipRouteDelete(vpnConfig); err != nil {
		return err
	}

	// request tunnel interface delete
	if err := ipLinkTunnelDelete(vpnConfig); err != nil {
		return err
	}

	// sysctl for ipsec config reset
	if err := sysctlConfigReset(vpnConfig); err != nil {
		return err
	}

	// reset charon config
	charonConfigReset()
	return nil
}

func strongSwanVpnActivate(vpnConfig types.VpnConfig) error {

	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	if !vpnConfig.PolicyBased {
		// check iplink interface existence
		if err := ipLinkInfExists(tunnelConfig.Name); err != nil {
			log.Errorf("%s for %s ipLink status", err.Error(),
				tunnelConfig.Name)
			return err
		}
		// check iplink interface status
		if err := ipLinkIntfStateCheck(tunnelConfig.Name); err != nil {
			log.Errorf("%s for %s ipLink status", err.Error(),
				tunnelConfig.Name)
			// issue ifup command for the tunnel
			if err := issueIfUpCmd(tunnelConfig.Name); err != nil {
				return err
			}
			return err
		}
	}

	// check iptables rule status
	if err := ipTablesRuleCheck(vpnConfig); err != nil {
		log.Errorf("%s for %s ipTables status", err.Error(), tunnelConfig.Name)
		if err2 := ipTablesRuleCreate(vpnConfig); err2 != nil {
			return err2
		}
		return err
	}

	// check ipsec tunnel status
	if err := ipSecTunnelStateCheck(vpnConfig.VpnRole, tunnelConfig.Name); err != nil {
		log.Errorf("%s for %s ipSec status", err.Error(), tunnelConfig.Name)
		if err2 := ipSecActivate(vpnConfig); err2 != nil {
			return err2
		}
		return err
	}

	// check ip routes
	if err := ipRouteCheck(vpnConfig); err != nil {
		if err := ipRouteCreate(vpnConfig); err != nil {
			return err
		}
	}
	return nil
}

func strongSwanVpnInactivate(vpnConfig types.VpnConfig) error {
	if err := ipSecInactivate(vpnConfig); err != nil {
		return err
	}
	return nil
}

// misc utility routines
func checkForClientDups(config types.StrongSwanConfig) error {

	// check for at least one pre-shared key configuration
	if config.PreSharedKey == "" {
		if len(config.ClientConfigList) == 0 {
			return errors.New("preshared key not set")
		}
		for _, clientConfig := range config.ClientConfigList {
			if clientConfig.PreSharedKey == "" {
				return errors.New("preshared key not set")
			}
		}
	}

	// validate client config profiles, for
	// duplication of wild-card entries with
	// different PSKs or, duplicate ipaddress/subnets
	wildMatch := false
	wildCardPsk := config.PreSharedKey
	for idx0, client0 := range config.ClientConfigList {
		isWild0 := isClientWildCard(client0)
		if isWild0 {
			if wildCardPsk == "" && client0.PreSharedKey != "" {
				wildCardPsk = client0.PreSharedKey
			}
			if wildMatch && client0.PreSharedKey != "" &&
				wildCardPsk != client0.PreSharedKey {
				return errors.New("wild-card client pre-shared key mismatch")
			}
			wildMatch = true
		}

		for idx1, client1 := range config.ClientConfigList {
			if idx1 <= idx0 {
				continue
			}
			isWild1 := isClientWildCard(client1)
			if !isWild0 && !isWild1 && client0.IpAddr == client1.IpAddr {
				return errors.New("duplicate client config")
			}
			if client0.SubnetBlock != "" &&
				client0.SubnetBlock == client1.SubnetBlock {
				return errors.New("duplicate client subnet")
			}
		}
	}
	return nil
}

func isClientWildCard(client types.VpnClientConfig) bool {
	log.Functionf("isClientWildCard %s\n", client.IpAddr)
	if client.IpAddr == "" || client.IpAddr == AnyIpAddr ||
		client.IpAddr == PortIpAddrType {
		return true
	}
	if ip := net.ParseIP(client.IpAddr); ip != nil {
		return ip.IsUnspecified()
	}
	return false
}

func vpnValidateSubnet(netStr string) error {
	if netStr != "" && netStr != AppLinkSubnetType {
		if _, _, err := net.ParseCIDR(netStr); err != nil {
			return err
		}
	}
	return nil
}

func vpnValidateLinkLocal(ipNetStr string) error {
	if ipNetStr == "" {
		return nil
	}
	ip, _, err := net.ParseCIDR(ipNetStr)
	if err != nil {
		return err
	}
	if !ip.IsLinkLocalUnicast() {
		return errors.New("invalid link local: " + ipNetStr)
	}
	return nil
}

func vpnValidateIpAddr(ipAddrStr string, isValid bool) error {
	if ipAddrStr == "" || ipAddrStr == AnyIpAddr ||
		ipAddrStr == PortIpAddrType {
		if isValid {
			return errors.New("invalid ip address: " + ipAddrStr)
		}
		return nil
	}

	ip := net.ParseIP(ipAddrStr)
	if ip == nil {
		return errors.New("invalid ip address: " + ipAddrStr)
	}
	if !ip.IsGlobalUnicast() {
		return errors.New("not unicast ip address: " + ipAddrStr)
	}
	return nil
}

func isVpnStatusChanged(oldStatus, newStatus *types.VpnStatus) bool {
	if oldStatus == nil {
		return true
	}
	staleConnCount := 0
	stateChange := false
	if oldStatus.ActiveTunCount != newStatus.ActiveTunCount ||
		oldStatus.ConnectingTunCount != newStatus.ConnectingTunCount {
		stateChange = true
	}

	// stale connections
	for _, oldConn := range oldStatus.ActiveVpnConns {
		found := false
		for _, newConn := range newStatus.ActiveVpnConns {
			if oldConn.Name == newConn.Name &&
				oldConn.Id == newConn.Id {
				found = true
				break
			}
		}
		if !found {
			stateChange = true
			oldConn.MarkDelete = true
			staleConnCount++
		}
	}

	// check for new or, state/stats change
	for _, newConn := range newStatus.ActiveVpnConns {
		found := false
		for _, oldConn := range oldStatus.ActiveVpnConns {
			if oldConn.Name == newConn.Name &&
				oldConn.Id == newConn.Id {
				if ret := matchConnState(oldConn, newConn); !ret {
					stateChange = true
				}
				found = true
				break
			}
		}
		// new connection
		if !found {
			stateChange = true
		}
	}

	if staleConnCount != 0 {
		newStatus.StaleVpnConns = make([]*types.VpnConnStatus, staleConnCount)
		connIdx := 0
		for _, oldConn := range oldStatus.ActiveVpnConns {
			if oldConn.MarkDelete {
				oldConn.State = types.VPN_DELETED
				for _, oldLink := range oldConn.Links {
					oldLink.State = types.VPN_DELETED
				}
				newStatus.StaleVpnConns[connIdx] = oldConn
				connIdx++
			}
		}
	}
	return stateChange
}

func matchConnState(oldConn, newConn *types.VpnConnStatus) bool {
	if oldConn.State != newConn.State ||
		len(oldConn.Links) != len(newConn.Links) {
		return false
	}
	for _, oldLinkInfo := range oldConn.Links {
		for _, newLinkInfo := range newConn.Links {
			if oldLinkInfo.Id == newLinkInfo.Id {
				if oldLinkInfo.ReqId != newLinkInfo.ReqId ||
					oldLinkInfo.LInfo.SpiId != newLinkInfo.LInfo.SpiId ||
					oldLinkInfo.RInfo.SpiId != newLinkInfo.RInfo.SpiId {
					return false
				}
			}
		}
	}
	return true
}

func publishVpnMetricsAclCounters(vpnMetrics *types.VpnMetrics) {

	if pktStat, err := iptableCounterRuleStat(vpnCounterAcls[0]); err == nil {
		vpnMetrics.IkeStat.InPkts = pktStat
	}
	if pktStat, err := iptableCounterRuleStat(vpnCounterAcls[1]); err == nil {
		vpnMetrics.IkeStat.OutPkts = pktStat
	}
	if pktStat, err := iptableCounterRuleStat(vpnCounterAcls[2]); err == nil {
		vpnMetrics.NatTStat.InPkts = pktStat
	}
	if pktStat, err := iptableCounterRuleStat(vpnCounterAcls[3]); err == nil {
		vpnMetrics.NatTStat.OutPkts = pktStat
	}
	if pktStat, err := iptableCounterRuleStat(vpnCounterAcls[4]); err == nil {
		vpnMetrics.EspStat.InPkts = pktStat
	}
	if pktStat, err := iptableCounterRuleStat(vpnCounterAcls[5]); err == nil {
		vpnMetrics.EspStat.OutPkts = pktStat
	}
}

// get the cumulative stats
func incrementVpnMetricsConnStats(vpnMetrics *types.VpnMetrics,
	oldConnMetrics *types.VpnConnMetrics, linkStatus *types.VpnLinkStatus) {

	lStats := linkStatus.LInfo
	rStats := linkStatus.RInfo

	inPktStats := lStats.PktStats
	outPktStats := rStats.PktStats

	// existing connection
	if oldConnMetrics != nil &&
		oldConnMetrics.LEndPoint.LinkInfo.SpiId == lStats.SpiId &&
		oldConnMetrics.REndPoint.LinkInfo.SpiId == rStats.SpiId {

		oldInPktStats := oldConnMetrics.LEndPoint.PktStats
		inPktStats.Bytes -= oldInPktStats.Bytes
		inPktStats.Pkts -= oldInPktStats.Pkts

		oldOutPktStats := oldConnMetrics.REndPoint.PktStats
		outPktStats.Bytes -= oldOutPktStats.Bytes
		outPktStats.Pkts -= oldOutPktStats.Pkts
	}
	vpnMetrics.DataStat.InPkts.Bytes += inPktStats.Bytes
	vpnMetrics.DataStat.InPkts.Pkts += inPktStats.Pkts
	vpnMetrics.DataStat.OutPkts.Bytes += outPktStats.Bytes
	vpnMetrics.DataStat.OutPkts.Pkts += outPktStats.Pkts
}

func getUplink(ctx *zedrouterContext, llOrIfname string) (string, error) {

	if llOrIfname == "" {
		return llOrIfname, errors.New("port config is absent")
	}

	ifNameList := getIfNameListForLLOrIfname(ctx, llOrIfname)
	if len(ifNameList) != 0 {
		for _, ifName := range ifNameList {
			_, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus,
				0, ifName)
			if err != nil {
				continue
			}
			return ifName, nil
		}
	}
	errStr := fmt.Sprintf("%s is not available", llOrIfname)
	return llOrIfname, errors.New(errStr)
}

func strongSwanConfigGet(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) (types.VpnConfig, error) {

	port := types.NetLinkConfig{}
	appLink := types.NetLinkConfig{}
	vpnConfig := types.VpnConfig{}
	appNetPresent := false

	var err error
	var ifname string
	if status.SelectedUplinkIntf != "" {
		ifname, _ = getUplink(ctx, status.SelectedUplinkIntf)
	} else {
		ifname, err = getUplink(ctx, status.Logicallabel)
		if err != nil {
			return vpnConfig, err
		}
	}

	port.IfName = ifname
	// port ip address error
	srcIp, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus, 0,
		port.IfName)
	if err != nil {
		return vpnConfig, err
	}
	port.IpAddr = srcIp.String()

	// app net information
	if status.IpType != types.AddressTypeIPV4 {
		return vpnConfig, errors.New("appnet is not IPv4")
	}
	appNetPresent = true
	appLink.IfName = status.BridgeName
	appLink.SubnetBlock = status.Subnet.String()

	vpnCloudConfig, err := strongSwanVpnConfigParse(status.OpaqueConfig)
	if err != nil {
		return vpnConfig, err
	}

	// XXX:TBD  host names to ip addresses in the configuration
	vpnConfig.VpnRole = vpnCloudConfig.VpnRole
	vpnConfig.IsClient = vpnCloudConfig.IsClient
	vpnConfig.PolicyBased = vpnCloudConfig.PolicyBased
	vpnConfig.GatewayConfig = vpnCloudConfig.GatewayConfig
	vpnConfig.PortConfig = port
	vpnConfig.AppLinkConfig = appLink

	// fill and validate the ip address/subnet
	if vpnConfig.GatewayConfig.IpAddr == PortIpAddrType {
		vpnConfig.GatewayConfig.IpAddr = port.IpAddr
	}
	if appNetPresent &&
		vpnConfig.GatewayConfig.SubnetBlock == AppLinkSubnetType {
		vpnConfig.GatewayConfig.SubnetBlock = appLink.SubnetBlock
	}
	if err := vpnValidateIpAddr(vpnConfig.GatewayConfig.IpAddr, true); err != nil {
		return vpnConfig, err
	}
	if err := vpnValidateSubnet(vpnConfig.GatewayConfig.SubnetBlock); err != nil {
		return vpnConfig, err
	}
	vpnConfig.ClientConfigList = make([]types.VpnClientConfig,
		len(vpnCloudConfig.ClientConfigList))

	for idx, ssClientConfig := range vpnCloudConfig.ClientConfigList {
		clientConfig := new(types.VpnClientConfig)
		clientConfig.IpAddr = ssClientConfig.IpAddr
		clientConfig.SubnetBlock = ssClientConfig.SubnetBlock
		clientConfig.PreSharedKey = ssClientConfig.PreSharedKey
		clientConfig.TunnelConfig.Name = fmt.Sprintf("%s_%d", vpnConfig.VpnRole, idx)
		clientConfig.TunnelConfig.Key = "100"
		clientConfig.TunnelConfig.Mtu = "1419"
		clientConfig.TunnelConfig.Metric = "50"
		clientConfig.TunnelConfig.LocalIpAddr = ssClientConfig.TunnelConfig.LocalIpAddr
		clientConfig.TunnelConfig.RemoteIpAddr = ssClientConfig.TunnelConfig.RemoteIpAddr

		if clientConfig.IpAddr == PortIpAddrType {
			clientConfig.IpAddr = port.IpAddr
		}
		if appNetPresent &&
			clientConfig.SubnetBlock == AppLinkSubnetType {
			clientConfig.SubnetBlock = appLink.SubnetBlock
		}
		if clientConfig.IpAddr == "" {
			clientConfig.IpAddr = AnyIpAddr
		}
		// validate the ip address/subnet values
		if err := vpnValidateIpAddr(clientConfig.IpAddr, false); err != nil {
			return vpnConfig, err
		}
		if err := vpnValidateSubnet(clientConfig.SubnetBlock); err != nil {
			return vpnConfig, err
		}
		tunnelConfig := clientConfig.TunnelConfig
		if err := vpnValidateLinkLocal(tunnelConfig.LocalIpAddr); err != nil {
			return vpnConfig, err
		}
		if err := vpnValidateLinkLocal(tunnelConfig.RemoteIpAddr); err != nil {
			return vpnConfig, err
		}
		if clientConfig.SubnetBlock == vpnConfig.GatewayConfig.SubnetBlock {
			return vpnConfig, errors.New("Peer is on Same Subnet")
		}
		vpnConfig.ClientConfigList[idx] = *clientConfig
	}

	if !vpnConfig.IsClient {
		if vpnConfig.GatewayConfig.IpAddr != port.IpAddr {
			errorStr := vpnConfig.GatewayConfig.IpAddr
			errorStr = errorStr + ", port: " + port.IpAddr
			return vpnConfig, errors.New("IpAddr Mismatch, GatewayIp: " + errorStr)
		}
		// ensure appNet match
		if appNetPresent &&
			vpnConfig.GatewayConfig.SubnetBlock != "" &&
			vpnConfig.GatewayConfig.SubnetBlock != appLink.SubnetBlock {
			errorStr := vpnConfig.GatewayConfig.SubnetBlock + ", appNet: " + appLink.SubnetBlock
			return vpnConfig, errors.New("Subnet Mismatch: " + errorStr)
		}
	} else {
		// for clients
		if appNetPresent {
			for _, clientConfig := range vpnConfig.ClientConfigList {
				if clientConfig.SubnetBlock != "" &&
					clientConfig.SubnetBlock != appLink.SubnetBlock {
					errorStr := clientConfig.SubnetBlock
					errorStr = errorStr + ", appNet: " + appLink.SubnetBlock
					return vpnConfig, errors.New("Subnet Mismatch: " + errorStr)
				}
			}
		}
	}
	if logrus.GetLevel() == logrus.TraceLevel {
		if bytes, err := json.Marshal(vpnConfig); err == nil {
			log.Tracef("strongSwanVpnConfigGet(): %s\n",
				string(bytes))
		}
	}
	return vpnConfig, nil
}

func strongSwanVpnStatusGet(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus, nis *types.NetworkInstanceMetrics) bool {
	change := false
	if status.Type != types.NetworkInstanceTypeCloud {
		return change
	}
	vpnConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Functionf("StrongSwanVpn config absent\n")
		return change
	}
	vpnStatus := new(types.VpnStatus)
	if err := ipSecStatusCmdGet(vpnStatus); err != nil {
		return change
	}
	if err := swanCtlCmdGet(vpnStatus); err != nil {
		return change
	}

	vpnStatus.PolicyBased = vpnConfig.PolicyBased

	// if tunnel state have changed, update
	if change = isVpnStatusChanged(status.VpnStatus, vpnStatus); change {
		log.Tracef("vpn state change:%v\n", vpnStatus)
		status.VpnStatus = vpnStatus
	}
	// push the vpnMetrics here
	publishVpnMetrics(ctx, status, vpnStatus, nis)
	return change
}

func publishVpnMetrics(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus, vpnStatus *types.VpnStatus,
	nis *types.NetworkInstanceMetrics) {

	// get older metrics, if any
	vpnMetrics := new(types.VpnMetrics)
	oldMetrics := lookupNetworkInstanceMetrics(ctx, nis.Key())

	// for cumulative stats, take the old metrics stats
	// and add the difference to the metrics
	if oldMetrics != nil && oldMetrics.VpnMetrics != nil {
		vpnMetrics.DataStat.InPkts = oldMetrics.VpnMetrics.DataStat.InPkts
		vpnMetrics.DataStat.OutPkts = oldMetrics.VpnMetrics.DataStat.OutPkts
	}

	publishVpnConnMetrics(ctx, status, oldMetrics, vpnMetrics, vpnStatus)
	publishVpnMetricsAclCounters(vpnMetrics)
	nis.VpnMetrics = vpnMetrics
	return
}

func publishVpnConnMetrics(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus, oldMetrics *types.NetworkInstanceMetrics,
	vpnMetrics *types.VpnMetrics, vpnStatus *types.VpnStatus) {

	if len(vpnStatus.ActiveVpnConns) == 0 {
		return
	}
	vpnMetrics.VpnConns = make([]*types.VpnConnMetrics,
		len(vpnStatus.ActiveVpnConns))
	for idx, connStatus := range vpnStatus.ActiveVpnConns {
		connMetrics := new(types.VpnConnMetrics)
		connMetrics.Id = connStatus.Id
		connMetrics.Name = connStatus.Name
		connMetrics.NIType = status.Type
		connMetrics.EstTime = connStatus.EstTime
		connMetrics.LEndPoint.IpAddr = connStatus.LInfo.IpAddr
		connMetrics.REndPoint.IpAddr = connStatus.RInfo.IpAddr

		// get the last metrics
		oldConnMetrics := getVpnMetricsOldConnStats(oldMetrics, connStatus.Id)
		// loop through the current setof SAs
		for _, linkStatus := range connStatus.Links {
			if linkStatus.State != types.VPN_INSTALLED {
				continue
			}
			lStats := linkStatus.LInfo
			connMetrics.LEndPoint.LinkInfo.SpiId = lStats.SpiId
			connMetrics.LEndPoint.LinkInfo.SubNet = lStats.SubNet
			connMetrics.LEndPoint.PktStats = lStats.PktStats

			rStats := linkStatus.RInfo
			connMetrics.REndPoint.LinkInfo.SpiId = rStats.SpiId
			connMetrics.REndPoint.LinkInfo.SubNet = rStats.SubNet
			connMetrics.REndPoint.PktStats = rStats.PktStats

			// increment cumulative stats
			incrementVpnMetricsConnStats(vpnMetrics,
				oldConnMetrics, linkStatus)
		}
		vpnMetrics.VpnConns[idx] = connMetrics
	}
}

func getVpnMetricsOldConnStats(oldMetrics *types.NetworkInstanceMetrics,
	id string) *types.VpnConnMetrics {
	if oldMetrics == nil || oldMetrics.VpnMetrics == nil {
		return nil
	}
	for _, connStatus := range oldMetrics.VpnMetrics.VpnConns {
		if connStatus.Id == id {
			return connStatus
		}
	}
	return nil
}
