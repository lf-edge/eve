// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// strongswan ipsec tunnel management routines

package zedrouter

import (
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"net"
)

const (
	AwsVpnClient      = "awsClient"
	OnPremVpnClient   = "onPremClient"
	OnPremVpnServer   = "onPremServer"
	UpLinkIpAddrType  = "upLink"
	AppLinkSubnetType = "appNet"
	AnyIpAddr         = "%any"
)

// XXX currently, only AwsVpn StrongSwan Client IpSec Tunnel handling
// XXX add support for standalone StrongSwan Server/client

func strongswanCreate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	log.Printf("strongswanCreate(%s)\n", config.DisplayName)

	// parse and structure the config
	vpnConfig, err := strongSwanConfigGet(ctx, config)
	if err != nil {
		return err
	}

	// stringify and store in status
	bytes, err := json.Marshal(vpnConfig)
	if err != nil {
		return err
	}

	status.OpaqueStatus = string(bytes)
	log.Printf("StrongSwanCreate: %s\n", status.OpaqueStatus)

	// reset any previous config
	if err := ipSecServiceInactivate(vpnConfig); err != nil {
		return err
	}

	// create the ipsec config files, tunnel, routes  and filter-rules
	if err := strongSwanVpnCreate(vpnConfig); err != nil {
		log.Printf("%s StrongSwanVpn create\n", err.Error())
		return err
	}
	return nil
}

func strongswanDelete(status *types.NetworkServiceStatus) {

	log.Printf("strongswanDelete(%s)\n", status.DisplayName)

	vpnConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("strongswanDelete config absent\n")
		return
	}

	if err := strongSwanVpnDelete(vpnConfig); err != nil {
		log.Printf("%s StrongSwanVpn delete\n", err.Error())
	}
}

func strongswanActivate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus, netstatus *types.NetworkObjectStatus) error {

	log.Printf("strongswanActivate(%s)\n", status.DisplayName)

	vpnConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("StrongSwanVpn config absent\n")
		return err
	}

	if err := strongSwanVpnActivate(vpnConfig); err != nil {
		log.Printf("%s StrongSwanVpn activate\n", err.Error())
		return err
	}
	return nil
}

func strongswanInactivate(status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) {

	log.Printf("strongswanInactivate(%s)\n", status.DisplayName)
	vpnConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("StrongSwanVpn config absent\n")
	}

	if err := strongSwanVpnInactivate(vpnConfig); err != nil {
		log.Printf("%s StrongSwanVpn inactivate\n", err.Error())
		return
	}
}

// StrongSwan Vpn IpSec Tenneling handler routines
func strongSwanConfigGet(ctx *zedrouterContext,
	config types.NetworkServiceConfig) (types.VpnServiceConfig, error) {

	upLink := types.NetLinkConfig{}
	appLink := types.NetLinkConfig{}
	vpnConfig := types.VpnServiceConfig{}
	appNetPresent := false

	// if adapter is not set, return
	if config.Adapter == "" {
		return vpnConfig, errors.New("uplink config is absent")
	}

	// uplink ip address error
	srcIp, err := types.GetLocalAddrAny(*ctx.DeviceNetworkStatus, 0,
		config.Adapter)
	if err != nil {
		return vpnConfig, err
	}

	upLink.Name = config.Adapter
	upLink.IpAddr = srcIp.String()

	// app net information
	appNet := lookupNetworkObjectConfig(ctx, config.AppLink.String())
	if appNet != nil {
		if appNet.Type != types.NT_IPV4 {
			return vpnConfig, errors.New("appnet is not IPv4")
		}
		appNetPresent = true
		appLink.SubnetBlock = appNet.Subnet.String()
	}

	vpnCloudConfig, err := strongSwanVpnConfigParse(config.OpaqueConfig)
	if err != nil {
		return vpnConfig, err
	}

	// XXX:TBD  host names to ip addresses in the configuration
	vpnConfig.VpnRole = vpnCloudConfig.VpnRole
	vpnConfig.PolicyBased = vpnCloudConfig.PolicyBased
	vpnConfig.GatewayConfig = vpnCloudConfig.GatewayConfig
	vpnConfig.UpLinkConfig = upLink
	vpnConfig.AppLinkConfig = appLink

	// fill and validate the ip address/subnet
	if vpnConfig.GatewayConfig.IpAddr == UpLinkIpAddrType {
		vpnConfig.GatewayConfig.IpAddr = upLink.IpAddr
	}
	if appNetPresent &&
		vpnConfig.GatewayConfig.SubnetBlock == AppLinkSubnetType {
		vpnConfig.GatewayConfig.SubnetBlock = appLink.SubnetBlock
	}
	if err := strongSwanValidateIpAddr(vpnConfig.GatewayConfig.IpAddr, true); err != nil {
		return vpnConfig, err
	}
	if err := strongSwanValidateSubnet(vpnConfig.GatewayConfig.SubnetBlock); err != nil {
		return vpnConfig, err
	}
	vpnConfig.ClientConfigList = make([]types.VpnClientConfig,
		len(vpnCloudConfig.ClientConfigList))

	for idx, ssClientConfig := range vpnCloudConfig.ClientConfigList {
		clientConfig := new(types.VpnClientConfig)
		clientConfig.IpAddr = ssClientConfig.IpAddr
		clientConfig.SubnetBlock = ssClientConfig.SubnetBlock
		clientConfig.PreSharedKey = ssClientConfig.PreSharedKey
		clientConfig.TunnelConfig.Name = vpnConfig.VpnRole
		clientConfig.TunnelConfig.Key = "100"
		clientConfig.TunnelConfig.Mtu = "1419"
		clientConfig.TunnelConfig.Metric = "50"
		clientConfig.TunnelConfig.LocalIpAddr = ssClientConfig.TunnelConfig.LocalIpAddr
		clientConfig.TunnelConfig.RemoteIpAddr = ssClientConfig.TunnelConfig.RemoteIpAddr

		if clientConfig.IpAddr == UpLinkIpAddrType {
			clientConfig.IpAddr = upLink.IpAddr
		}
		if appNetPresent &&
			clientConfig.SubnetBlock == AppLinkSubnetType {
			clientConfig.SubnetBlock = appLink.SubnetBlock
		}
		if clientConfig.IpAddr == "" {
			clientConfig.IpAddr = AnyIpAddr
		}
		// validate the ip address/subnet values
		if err := strongSwanValidateIpAddr(clientConfig.IpAddr, false); err != nil {
			return vpnConfig, err
		}
		if err := strongSwanValidateSubnet(clientConfig.SubnetBlock); err != nil {
			return vpnConfig, err
		}
		tunnelConfig := clientConfig.TunnelConfig
		if err := strongSwanValidateLinkLocal(tunnelConfig.LocalIpAddr); err != nil {
			return vpnConfig, err
		}
		if err := strongSwanValidateLinkLocal(tunnelConfig.RemoteIpAddr); err != nil {
			return vpnConfig, err
		}
		vpnConfig.ClientConfigList[idx] = *clientConfig
	}

	if vpnConfig.VpnRole == OnPremVpnServer {
		if vpnConfig.GatewayConfig.IpAddr != upLink.IpAddr {
			errorStr := vpnConfig.GatewayConfig.IpAddr
			errorStr = errorStr + ", upLink: " + upLink.IpAddr
			return vpnConfig, errors.New("IpAddr Mismatch, GatewayIp: " + errorStr)
		}
		// ensure appNet match
		if appNetPresent &&
			vpnConfig.GatewayConfig.SubnetBlock != "" &&
			vpnConfig.GatewayConfig.SubnetBlock != appLink.SubnetBlock {
			errorStr := vpnConfig.GatewayConfig.SubnetBlock + ", appNet: " + appLink.SubnetBlock
			return vpnConfig, errors.New("Subnet Mismatch: " + errorStr)
		}
		return vpnConfig, nil
	}

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
	return vpnConfig, nil
}

func strongSwanVpnConfigParse(opaqueConfig string) (types.VpnServiceConfig, error) {
	log.Printf("strongSwanVpnConfigParse(): parsing %s\n", opaqueConfig)
	vpnConfig := types.VpnServiceConfig{}

	cb := []byte(opaqueConfig)
	strongSwanConfig := types.StrongSwanServiceConfig{}
	if err := json.Unmarshal(cb, &strongSwanConfig); err != nil {
		log.Printf("%s for strongSwanVpnConfigParse()\n", err.Error())
		return vpnConfig, err
	}

	// check for unique client profiles
	if err := checkForClientDups(strongSwanConfig); err != nil {
		return vpnConfig, err
	}

	// validate ip address/subnet configurations
	if err := strongSwanValidateIpAddr(strongSwanConfig.VpnGatewayIpAddr, false); err != nil {
		return vpnConfig, err
	}
	if err := strongSwanValidateSubnet(strongSwanConfig.VpnSubnetBlock); err != nil {
		return vpnConfig, err
	}
	if err := strongSwanValidateSubnet(strongSwanConfig.LocalSubnetBlock); err != nil {
		return vpnConfig, err
	}
	if err := strongSwanValidateLinkLocal(strongSwanConfig.VpnLocalIpAddr); err != nil {
		return vpnConfig, err
	}
	if err := strongSwanValidateLinkLocal(strongSwanConfig.VpnRemoteIpAddr); err != nil {
		return vpnConfig, err
	}

	for _, clientConfig := range strongSwanConfig.ClientConfigList {
		if err := strongSwanValidateIpAddr(clientConfig.IpAddr, false); err != nil {
			return vpnConfig, err
		}
		if err := strongSwanValidateSubnet(clientConfig.SubnetBlock); err != nil {
			return vpnConfig, err
		}
		tunnelConfig := clientConfig.TunnelConfig
		if err := strongSwanValidateLinkLocal(tunnelConfig.LocalIpAddr); err != nil {
			return vpnConfig, err
		}
		if err := strongSwanValidateLinkLocal(tunnelConfig.RemoteIpAddr); err != nil {
			return vpnConfig, err
		}
	}

	switch strongSwanConfig.VpnRole {
	case AwsVpnClient:
		// its always route based Vpn Service
		strongSwanConfig.PolicyBased = false

		if len(strongSwanConfig.ClientConfigList) > 1 {
			return vpnConfig, errors.New("invalid client config")
		}
		// server ip address/subnet is must
		if strongSwanConfig.VpnGatewayIpAddr == "" ||
			strongSwanConfig.VpnGatewayIpAddr == AnyIpAddr ||
			strongSwanConfig.VpnGatewayIpAddr == UpLinkIpAddrType {
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
			clientConfig.IpAddr = AnyIpAddr
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

	case OnPremVpnClient:
		if len(strongSwanConfig.ClientConfigList) > 1 {
			return vpnConfig, errors.New("invalid client config")
		}
		// server ip address is must
		if strongSwanConfig.VpnGatewayIpAddr == "" ||
			strongSwanConfig.VpnGatewayIpAddr == AnyIpAddr ||
			strongSwanConfig.VpnGatewayIpAddr == UpLinkIpAddrType {
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
			clientConfig.IpAddr = UpLinkIpAddrType
			clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			clientConfig.SubnetBlock = strongSwanConfig.LocalSubnetBlock
			if clientConfig.SubnetBlock == "" {
				clientConfig.SubnetBlock = AppLinkSubnetType
			}
			strongSwanConfig.ClientConfigList[0] = *clientConfig
		}

	case OnPremVpnServer:
		// if not mentioned, assume upLink ip address
		if strongSwanConfig.VpnGatewayIpAddr == "" {
			strongSwanConfig.VpnGatewayIpAddr = UpLinkIpAddrType
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
			if clientConfig.IpAddr == UpLinkIpAddrType {
				return vpnConfig, errors.New("client can not take uplink Addr")
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

	// fill up our structure
	vpnConfig.VpnRole = strongSwanConfig.VpnRole
	vpnConfig.PolicyBased = strongSwanConfig.PolicyBased
	vpnConfig.GatewayConfig.IpAddr = strongSwanConfig.VpnGatewayIpAddr
	vpnConfig.GatewayConfig.SubnetBlock = strongSwanConfig.VpnSubnetBlock
	vpnConfig.ClientConfigList = make([]types.VpnClientConfig,
		len(strongSwanConfig.ClientConfigList))

	for idx, ssClientConfig := range strongSwanConfig.ClientConfigList {
		clientConfig := new(types.VpnClientConfig)
		clientConfig.IpAddr = ssClientConfig.IpAddr
		clientConfig.SubnetBlock = ssClientConfig.SubnetBlock
		clientConfig.PreSharedKey = ssClientConfig.PreSharedKey

		if vpnConfig.VpnRole == OnPremVpnClient {
			if clientConfig.IpAddr == "" {
				clientConfig.IpAddr = UpLinkIpAddrType
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

	if debug {
		if bytes, err := json.Marshal(vpnConfig); err == nil {
			log.Printf("strongSwanConfigParse(): %s\n", string(bytes))
		}
	}
	return vpnConfig, nil
}

func strongSwanVpnStatusParse(opaqueStatus string) (types.VpnServiceConfig, error) {

	if debug {
		log.Printf("strongSwanVpnStatusParse: parsing %s\n", opaqueStatus)
	}

	cb := []byte(opaqueStatus)
	vpnConfig := types.VpnServiceConfig{}
	if err := json.Unmarshal(cb, &vpnConfig); err != nil {
		log.Printf("%s awsStrongSwanLocalConfig \n", err.Error())
		return vpnConfig, err
	}
	return vpnConfig, nil
}

func strongSwanVpnCreate(vpnConfig types.VpnServiceConfig) error {

	gatewayConfig := vpnConfig.GatewayConfig

	log.Printf("StrongSwan IpSec Vpn Create %s:%v, %s:%s\n",
		vpnConfig.VpnRole, vpnConfig.PolicyBased,
		gatewayConfig.IpAddr, gatewayConfig.SubnetBlock)

	if err := charonRouteConfigCreate(vpnConfig.PolicyBased); err != nil {
		return err
	}

	// create ipsec.conf
	if err := ipSecServiceConfigCreate(vpnConfig); err != nil {
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
	if err := ipSecServiceActivate(vpnConfig); err != nil {
		return err
	}

	// request ip route create
	if err := ipRouteCreate(vpnConfig); err != nil {
		return err
	}
	return nil
}

func strongSwanVpnDelete(vpnConfig types.VpnServiceConfig) error {

	gatewayConfig := vpnConfig.GatewayConfig

	log.Printf("strongSwan IpSec Vpn Delete %s:%s, %s, %s\n",
		vpnConfig.VpnRole, vpnConfig.PolicyBased,
		gatewayConfig.IpAddr, gatewayConfig.SubnetBlock)

	// reset ipsec.conf/ipsec.secrets
	// set default files in place of existing
	if err := ipSecServiceConfigDelete(); err != nil {
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

func strongSwanVpnActivate(vpnConfig types.VpnServiceConfig) error {

	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	if !vpnConfig.PolicyBased {
		// check iplink interface existence
		if err := ipLinkInfExists(tunnelConfig.Name); err != nil {
			log.Printf("%s for %s ipLink status", err.Error(),
				tunnelConfig.Name)
			return err
		}
		// check iplink interface status
		if err := ipLinkIntfStateCheck(tunnelConfig.Name); err != nil {
			log.Printf("%s for %s ipLink status", err.Error(),
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
		log.Printf("%s for %s ipTables status", err.Error(), tunnelConfig.Name)
		if err := ipTablesRuleCreate(vpnConfig); err != nil {
			return err
		}
		return err
	}

	// check ipsec tunnel status
	if err := ipSecTunnelStateCheck(vpnConfig.VpnRole, tunnelConfig.Name); err != nil {
		log.Printf("%s for %s ipSec status", err.Error(), tunnelConfig.Name)
		if err := ipSecServiceActivate(vpnConfig); err != nil {
			return err
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

func strongSwanVpnInactivate(vpnConfig types.VpnServiceConfig) error {
	if err := ipSecServiceInactivate(vpnConfig); err != nil {
		return err
	}
	return nil
}

// misc utility routines
func checkForClientDups(config types.StrongSwanServiceConfig) error {

	// check for atleast one pre-shared key configuration
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
	log.Printf("isClientWildCard %s\n", client.IpAddr)
	if client.IpAddr == "" || client.IpAddr == AnyIpAddr ||
		client.IpAddr == UpLinkIpAddrType {
		return true
	}
	if ip := net.ParseIP(client.IpAddr); ip != nil {
		return ip.IsUnspecified()
	}
	return false
}

func strongSwanValidateSubnet(netStr string) error {
	if netStr != "" && netStr != AppLinkSubnetType {
		if _, _, err := net.ParseCIDR(netStr); err != nil {
			return err
		}
	}
	return nil
}

func strongSwanValidateLinkLocal(ipNetStr string) error {
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

func strongSwanValidateIpAddr(ipAddrStr string, isValid bool) error {
	if ipAddrStr == "" || ipAddrStr == AnyIpAddr ||
		ipAddrStr == UpLinkIpAddrType {
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

func strongSwanVpnStatusGet(status *types.NetworkServiceStatus) bool {
	change := false
	vpnConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("StrongSwanVpn config absent\n")
		return change
	}
	vpnStatus := new(types.ServiceVpnStatus)
	if err := ipSecStatusCmdGet(vpnStatus); err != nil {
		return false
	}
	if err := swanCtlCmdGet(vpnStatus); err != nil {
		return false
	}

	vpnStatus.PolicyBased = vpnConfig.PolicyBased

	// if tunnel state have changed, update
	if change = isVpnStatusChanged(status.VpnStatus, vpnStatus); change {
		if debug {
			log.Printf("vpn state change:%v\n", vpnStatus)
		}
		status.VpnStatus = vpnStatus
	}
	return change
}

func isVpnStatusChanged(oldStatus, newStatus *types.ServiceVpnStatus) bool {
	if oldStatus == nil {
		return true
	}
	staleConnCount := 0
	var stateChange, statsChange bool
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
				if ret := matchConnStats(oldConn, newConn); !ret {
					statsChange = true
				}
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
	return stateChange || statsChange
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

func matchConnStats(oldConn, newConn *types.VpnConnStatus) bool {
	if oldConn.State != newConn.State ||
		len(oldConn.Links) != len(newConn.Links) {
		return false
	}
	for _, oldLinkInfo := range oldConn.Links {
		for _, newLinkInfo := range newConn.Links {
			if oldLinkInfo.Id == newLinkInfo.Id {
				if oldLinkInfo.LInfo.BytesCount != newLinkInfo.LInfo.BytesCount ||
					oldLinkInfo.LInfo.PktsCount != newLinkInfo.LInfo.PktsCount {
					return false
				}
				if oldLinkInfo.RInfo.BytesCount != newLinkInfo.RInfo.BytesCount ||
					oldLinkInfo.RInfo.PktsCount != newLinkInfo.RInfo.PktsCount {
					return false
				}
			}
		}
	}
	return true
}
