// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// strongswan ipsec tunnel management routines

package zedrouter

import (
	"encoding/json"
	"errors"
	"github.com/zededa/go-provision/types"
	"log"
	"net"
)

const (
	AwsVpnClient      = "awsClient"
	OnPremVpnClient   = "onPremClient"
	OnPremVpnServer   = "onPremServer"
	UpLinkIpAddrType  = "upLink"
	AppLinkSubnetType = "appNet"
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
		log.Printf("strongswanDelete config absent")
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
		log.Printf("StrongSwanVpn config absent")
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
		log.Printf("StrongSwanVpn config absent")
		return
	}

	if err := strongSwanVpnInactivate(vpnConfig); err != nil {
		log.Printf("%s StrongSwanVpn inactivate\n", err.Error())
	}
}

// StrongSwan Vpn IpSec Tenneling handler routines

func strongSwanConfigGet(ctx *zedrouterContext,
	config types.NetworkServiceConfig) (types.VpnServiceConfig, error) {

	upLink := types.NetLinkConfig{}
	appLink := types.NetLinkConfig{}
	vpnConfig := types.VpnServiceConfig{}

	// if adapter is not set, return
	if config.Adapter == "" {
		return vpnConfig, errors.New("uplink config is absent")
	}

	// uplink ip address error
	srcIp, err := types.GetLocalAddrAny(deviceNetworkStatus, 0, config.Adapter)
	if err != nil {
		return vpnConfig, err
	}

	upLink.Name = config.Adapter
	upLink.IpAddr = srcIp.String()

	// app net information
	appNet := lookupNetworkObjectConfig(ctx, config.AppLink.String())
	if appNet != nil {
		return vpnConfig, errors.New("appnet config is absent")
	}
	if appNet.Type != types.NT_IPV4 {
		return vpnConfig, errors.New("appnet is not IPv4")
	}
	appLink.SubnetBlock = appNet.Subnet.String()

	vpnCloudConfig, err := strongSwanVpnConfigParse(config.OpaqueConfig)
	if err != nil {
		return vpnConfig, err
	}

	// XXX:TBD  host names to ip addresses in the configuration
	vpnConfig.VpnRole = vpnCloudConfig.VpnRole
	vpnConfig.GatewayConfig = vpnCloudConfig.GatewayConfig
	vpnConfig.UpLinkConfig = upLink
	vpnConfig.AppLinkConfig = appLink

	// fill and validate the ip address/subnet
	if vpnConfig.GatewayConfig.IpAddr == UpLinkIpAddrType {
		vpnConfig.GatewayConfig.IpAddr = upLink.IpAddr
	}
	if ip := net.ParseIP(vpnConfig.GatewayConfig.IpAddr); ip == nil {
		return vpnConfig, errors.New("invalid ip address")
	}
	if vpnConfig.GatewayConfig.SubnetBlock == AppLinkSubnetType {
		vpnConfig.GatewayConfig.SubnetBlock = appLink.SubnetBlock
	}
	if vpnConfig.GatewayConfig.SubnetBlock != "" {
		if _, _, err := net.ParseCIDR(vpnConfig.GatewayConfig.SubnetBlock); err != nil {
			return vpnConfig, err
		}
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
		if clientConfig.SubnetBlock == AppLinkSubnetType {
			clientConfig.SubnetBlock = appLink.SubnetBlock
		}
		if clientConfig.IpAddr != "" {
			if ip := net.ParseIP(clientConfig.IpAddr); ip != nil {
				return vpnConfig, errors.New("invalid ip address")
			}
		} else {
			clientConfig.IpAddr = "%any"
		}
		// validate the ip address/subnet values
		if clientConfig.SubnetBlock != "" {
			if _, _, err := net.ParseCIDR(clientConfig.SubnetBlock); err != nil {
				return vpnConfig, err
			}
		}
		if clientConfig.TunnelConfig.LocalIpAddr != "" {
			if _, _, err := net.ParseCIDR(clientConfig.TunnelConfig.LocalIpAddr); err != nil {
				return vpnConfig, err
			}
		}
		if clientConfig.TunnelConfig.RemoteIpAddr != "" {
			if _, _, err := net.ParseCIDR(clientConfig.TunnelConfig.RemoteIpAddr); err != nil {
				return vpnConfig, err
			}
		}
		vpnConfig.ClientConfigList[idx] = *clientConfig
	}

	// check appLink match
	switch vpnConfig.VpnRole {
	case AwsVpnClient:
		for _, clientConfig := range vpnConfig.ClientConfigList {
			if clientConfig.SubnetBlock != appLink.SubnetBlock {
				return vpnConfig, errors.New("Client Subnet Mismatch, not appLink" + appLink.SubnetBlock)
			}
		}
	case OnPremVpnClient:
		for _, clientConfig := range vpnConfig.ClientConfigList {
			if clientConfig.SubnetBlock != appLink.SubnetBlock {
				return vpnConfig, errors.New("Client Subnet Mismatch, not appLink" + appLink.SubnetBlock)
			}
		}
	case OnPremVpnServer:
		// for onPremServer, validate ip/subnet with uplink/appnet
		if vpnConfig.GatewayConfig.IpAddr != upLink.IpAddr {
			return vpnConfig, errors.New("Gateway Ip Mismatch, not upLink" + upLink.IpAddr)
		}
		if vpnConfig.GatewayConfig.SubnetBlock != appLink.SubnetBlock {
			return vpnConfig, errors.New("Gateway Subnet Mismatch, not appLink" + appLink.SubnetBlock)
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

	// check for pre-shared key configuration
	if strongSwanConfig.PreSharedKey == "" {
		for _, clientConfig := range strongSwanConfig.ClientConfigList {
			if clientConfig.IpAddr == "" &&
				clientConfig.PreSharedKey == "" {
				return vpnConfig, errors.New("preshared key not set")
			}
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
		if strongSwanConfig.VpnGatewayIpAddr == "" {
			return vpnConfig, errors.New("vpn gateway not set")
		}
		if ip := net.ParseIP(strongSwanConfig.VpnGatewayIpAddr); ip == nil {
			return vpnConfig, errors.New("invalid ip address")
		}
		if strongSwanConfig.VpnSubnetBlock == "" {
			return vpnConfig, errors.New("invalid vpn subnet")
		}
		if _, _, err := net.ParseCIDR(strongSwanConfig.VpnSubnetBlock); err != nil {
			return vpnConfig, err
		}
		// flat configuration
		if len(strongSwanConfig.ClientConfigList) == 0 {
			if strongSwanConfig.VpnLocalIpAddr == "" ||
				strongSwanConfig.VpnRemoteIpAddr == "" {
				return vpnConfig, errors.New("invalid tunnel parameters")
			}
			// copy the paramters to the new structure
			strongSwanConfig.ClientConfigList = make([]types.VpnClientConfig, 1)
			clientConfig := new(types.VpnClientConfig)
			clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			clientConfig.TunnelConfig.LocalIpAddr = strongSwanConfig.VpnLocalIpAddr
			clientConfig.TunnelConfig.RemoteIpAddr = strongSwanConfig.VpnRemoteIpAddr
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
			// reset these, if set
			clientConfig.IpAddr = ""
			clientConfig.SubnetBlock = AppLinkSubnetType
		}

	case OnPremVpnClient:
		if len(strongSwanConfig.ClientConfigList) > 1 {
			return vpnConfig, errors.New("invalid client config")
		}
		// server ip address is must
		if strongSwanConfig.VpnGatewayIpAddr == "" {
			return vpnConfig, errors.New("vpn gateway not set")
		}
		if ip := net.ParseIP(strongSwanConfig.VpnGatewayIpAddr); ip == nil {
			return vpnConfig, errors.New("invalid ip address")
		}
		// for client, server side subnet information, is must
		if strongSwanConfig.VpnSubnetBlock == "" {
			return vpnConfig, errors.New("server subnet block not set")
		}
		if _, _, err := net.ParseCIDR(strongSwanConfig.VpnSubnetBlock); err != nil {
			return vpnConfig, err
		}
		// flat configuration
		if len(strongSwanConfig.ClientConfigList) == 0 {
			strongSwanConfig.ClientConfigList = make([]types.VpnClientConfig, 1)
			clientConfig := new(types.VpnClientConfig)
			clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			clientConfig.SubnetBlock = strongSwanConfig.LocalSubnetBlock
			strongSwanConfig.ClientConfigList[0] = *clientConfig
		}
		for _, clientConfig := range strongSwanConfig.ClientConfigList {
			if clientConfig.IpAddr != "" {
				if ip := net.ParseIP(clientConfig.IpAddr); ip == nil {
					return vpnConfig, errors.New("invalid ip address")
				}
			}
			// for policy based, if not set, assume appnet subnet
			if clientConfig.SubnetBlock == "" {
				if strongSwanConfig.PolicyBased == true {
					clientConfig.SubnetBlock = AppLinkSubnetType
				}
			} else {
				if _, _, err := net.ParseCIDR(clientConfig.SubnetBlock); err != nil {
					return vpnConfig, err
				}
			}
			if clientConfig.PreSharedKey == "" {
				clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			}
		}

	case OnPremVpnServer:
		// if not mentioned, assume upLink ip address
		if strongSwanConfig.VpnGatewayIpAddr == "" {
			strongSwanConfig.VpnGatewayIpAddr = UpLinkIpAddrType
		} else {
			if ip := net.ParseIP(strongSwanConfig.VpnGatewayIpAddr); ip == nil {
				return vpnConfig, errors.New("invalid ip address")
			}
		}
		// if not mentioned, assume appnet subnet
		if strongSwanConfig.VpnSubnetBlock == "" {
			strongSwanConfig.VpnSubnetBlock = AppLinkSubnetType
		} else {
			if _, _, err := net.ParseCIDR(strongSwanConfig.VpnSubnetBlock); err != nil {
				return vpnConfig, err
			}
		}
		// single client/profile flat configuration
		if len(strongSwanConfig.ClientConfigList) == 0 {
			strongSwanConfig.ClientConfigList = make([]types.VpnClientConfig, 1)
			clientConfig := new(types.VpnClientConfig)
			clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			clientConfig.SubnetBlock = strongSwanConfig.LocalSubnetBlock
			strongSwanConfig.ClientConfigList[0] = *clientConfig
		}
		for _, clientConfig := range strongSwanConfig.ClientConfigList {
			if clientConfig.IpAddr != "" {
				if ip := net.ParseIP(clientConfig.IpAddr); ip == nil {
					return vpnConfig, errors.New("invalid ip address")
				}
			}
			// for route based server, client subnet information is must
			if clientConfig.SubnetBlock == "" {
				if strongSwanConfig.PolicyBased == false {
					return vpnConfig, errors.New("client subnet block not set")
				}
			} else {
				// if mentioned, validate
				if _, _, err := net.ParseCIDR(clientConfig.SubnetBlock); err != nil {
					return vpnConfig, err
				}
			}
			if clientConfig.PreSharedKey == "" {
				clientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			}
		}
	default:
		return vpnConfig, errors.New("unsupported vpn role, " + strongSwanConfig.VpnRole)
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
		clientConfig.TunnelConfig.LocalIpAddr = ssClientConfig.TunnelConfig.LocalIpAddr
		clientConfig.TunnelConfig.RemoteIpAddr = ssClientConfig.TunnelConfig.RemoteIpAddr
		vpnConfig.ClientConfigList[idx] = *clientConfig
	}
	return vpnConfig, nil
}

func strongSwanVpnStatusParse(opaqueStatus string) (types.VpnServiceConfig, error) {

	log.Printf("strongSwanVpnStatusParse: parsing %s\n", opaqueStatus)

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

	log.Printf("StrongSwan IpSec Vpn Create %s:%s, %s:%s\n",
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

	if vpnConfig.PolicyBased == false {
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
