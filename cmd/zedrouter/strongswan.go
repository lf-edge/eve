// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// strongswan ipsec tunnel management routines

package zedrouter

import (
	"encoding/json"
	"errors"
	"github.com/zededa/go-provision/types"
	"log"
)

// XXX currently, only AwsVpn StrongSwan Client IpSec Tunnel handling
// XXX add support for standalone StrongSwan Server/client

func strongswanCreate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	log.Printf("strongswanCreate(%s)\n", config.DisplayName)

	vpnConfig, err := strongSwanVpnConfigParse(config.OpaqueConfig)
	if err != nil {
		return err
	}

	// if adapter is not set, return
	// XXX:FIXME add logic to pick up some uplink
	if config.Adapter == "" {
		err := errors.New("uplink config is absent")
		return err
	}

	// if address error
	srcIp, err := types.GetLocalAddrAny(deviceNetworkStatus, 0,
		config.Adapter)
	if err != nil {
		return err
	}

	// set the local config
	baseTunnelName := "tun_" + vpnConfig.VpnRole
	vpnLocalConfig := types.VpnServiceLocalConfig{}

	vpnLocalConfig.VpnRole = vpnConfig.VpnRole
	vpnLocalConfig.GatewayConfig = vpnConfig.GatewayConfig
	vpnLocalConfig.ClientConfigList = vpnConfig.ClientConfigList
	vpnLocalConfig.UpLinkConfig.Name = config.Adapter
	vpnLocalConfig.UpLinkConfig.IpAddr = srcIp.String()

	vpnLocalConfig.ClientConfigList = make([]types.VpnClientConfig,
		len(vpnConfig.ClientConfigList))

	for idx, clientConfig := range vpnConfig.ClientConfigList {
		localClientConfig := new (types.VpnClientConfig)
		localClientConfig.IpAddr = clientConfig.IpAddr
		if localClientConfig.IpAddr == "" {
			localClientConfig.IpAddr = "%any"
		}
		if localClientConfig.IpAddr == "upLink" {
			localClientConfig.IpAddr = srcIp.String()
		}
		localClientConfig.PreSharedKey = clientConfig.PreSharedKey
		localClientConfig.SubnetBlock = clientConfig.SubnetBlock
		localClientConfig.TunnelConfig.Name = baseTunnelName + "_" + string(idx)

		if vpnLocalConfig.VpnRole == "awsStrongSwanVpnClient" {
			localClientConfig.TunnelConfig.Key = string(100 + idx)
			localClientConfig.TunnelConfig.Mtu = "1419"
			localClientConfig.TunnelConfig.Metric = "50"
			localClientConfig.TunnelConfig.LocalIpAddr = clientConfig.TunnelConfig.LocalIpAddr
			localClientConfig.TunnelConfig.RemoteIpAddr = clientConfig.TunnelConfig.RemoteIpAddr
		}
		vpnLocalConfig.ClientConfigList[idx] = *localClientConfig
	}

	// stringify and store in status
	bytes, err := json.Marshal(vpnLocalConfig)
	if err != nil {
		return nil
	}

	status.OpaqueStatus = string(bytes)
	log.Printf("strongswanCreate :%s\n", status.OpaqueStatus)

	// create the ipsec config files, tunnel and filter-rules
	switch vpnConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		if err := awsStrongSwanClientCreate(vpnLocalConfig); err != nil {
			return err
		}

	case "onPremStrongSwanVpnClient":
		if err := onPremStrongSwanClientCreate(vpnLocalConfig); err != nil {
			return err
		}

	case "onPremStrongSwanVpnServer":
		if err := onPremStrongSwanServerCreate(vpnLocalConfig); err != nil {
			return err
		}

	}

	return nil
}

func strongswanDelete(status *types.NetworkServiceStatus) {

	log.Printf("strongswanDelete(%s)\n", status.DisplayName)

	vpnLocalConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("strongswanDelete config absent")
		return
	}

	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		if err := awsStrongSwanClientDelete(vpnLocalConfig); err != nil {
			log.Printf("%s awsStrongSwanVpnClient delete\n", err.Error())
		}

	case "onPremStrongSwanVpnClient":
		if err := onPremStrongSwanClientDelete(vpnLocalConfig); err != nil {
			log.Printf("%s OnPremStrongSwanClient delete\n", err.Error())
		}

	case "onPremStrongSwanVpnServer":
		if err := onPremStrongSwanServerDelete(vpnLocalConfig); err != nil {
			log.Printf("%s OnPremStrongSwanServer delete\n", err.Error())
		}
	}
}

func strongswanActivate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus, netstatus *types.NetworkObjectStatus) error {

	log.Printf("strongswanActivate(%s)\n", status.DisplayName)

	vpnLocalConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("strongswan local config absent")
		return err
	}

	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		if err := awsStrongSwanClientActivate(vpnLocalConfig); err != nil {
			return err
		}

	case "onPremStrongSwanVpnClient":
		if err := onPremStrongSwanClientActivate(vpnLocalConfig); err != nil {
			log.Printf("%s OnPremStrongSwanClient activate\n", err.Error())
			return err
		}

	case "onPremStrongSwanVpnServer":
		if err := onPremStrongSwanServerActivate(vpnLocalConfig); err != nil {
			log.Printf("%s OnPremStrongSwanServer activate\n", err.Error())
			return err
		}
	}
	return nil
}

func strongswanInactivate(status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) {

	log.Printf("strongswanInactivate(%s)\n", status.DisplayName)
	vpnLocalConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("strongswan local config absent")
		return
	}

	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		if err := awsStrongSwanClientInactivate(vpnLocalConfig); err != nil {
			log.Printf("%s awsStrongSwanVpnClient inactivate\n", err.Error())
		}

	case "onPremStrongSwanVpnClient":
		if err := onPremStrongSwanClientInactivate(vpnLocalConfig); err != nil {
			log.Printf("%s OnPremStrongSwanClient inactivate\n", err.Error())
		}

	case "onPremStrongSwanVpnServer":
		if err := onPremStrongSwanServerInactivate(vpnLocalConfig); err != nil {
			log.Printf("%s OnPremStrongSwanServer inactivate\n", err.Error())
		}
	}
}

// aws Vpn IpSec Tenneling handler routines
func strongSwanVpnConfigParse(opaqueConfig string) (types.VpnServiceConfig, error) {

	log.Printf("strongSwanVpnConfigParse: parsing %s\n", opaqueConfig)
	vpnConfig := types.VpnServiceConfig{}

	cb := []byte(opaqueConfig)
	strongSwanConfig := types.StrongSwanServiceConfig{}
	if err := json.Unmarshal(cb, &strongSwanConfig); err != nil {
		log.Printf("%s for StrongSwanVpnConfig\n", err.Error())
		return vpnConfig, err
	}

	// noting in, assume it to be aws strongswan client
	if strongSwanConfig.VpnRole == "" {
		strongSwanConfig.VpnRole = "awsStrongSwanVpnClient"
		strongSwanConfig.ClientConfigList = make([]types.VpnClientConfig, 1)
	}

	if strongSwanConfig.VpnGatewayIpAddr == "" {
		return vpnConfig, errors.New("vpn gateway not set")
	}

	for _, clientConfig := range strongSwanConfig.ClientConfigList {
		if clientConfig.PreSharedKey == "" {
			return vpnConfig, errors.New("preshared key not set")
		}
	}

	switch vpnConfig.VpnRole {

	case "awsStrongSwanVpnClient":
		if strongSwanConfig.VpnSubnetBlock == "" ||
			strongSwanConfig.VpnLocalIpAddr == "" ||
			strongSwanConfig.VpnRemoteIpAddr == "" ||
			strongSwanConfig.PreSharedKey == "" {
			return vpnConfig, errors.New("invalid parameters")
		}

	case "onPremStrongSwanVpnClient":
		if len(strongSwanConfig.ClientConfigList) != 1 {
			return vpnConfig, errors.New("invalid client config")
		}
		if strongSwanConfig.VpnSubnetBlock == "" {
			return vpnConfig, errors.New("invalid parameters")
		}
		for _, clientConfig := range strongSwanConfig.ClientConfigList {
			if clientConfig.SubnetBlock == "" {
				return vpnConfig, errors.New("subnet block not set")
			}
		}

	case "onPremStrongSwanVpnServer":

		if len(strongSwanConfig.ClientConfigList) == 0 {
			return vpnConfig, errors.New("invalid client config")
		}
		for _, clientConfig := range strongSwanConfig.ClientConfigList {
			if clientConfig.IpAddr == "" {
				return vpnConfig, errors.New("client IpAddr not set set")
			}
		}
	}

	// fill up our structure
	vpnConfig.VpnRole = strongSwanConfig.VpnRole
	vpnConfig.GatewayConfig.SubnetBlock = strongSwanConfig.VpnSubnetBlock
	vpnConfig.GatewayConfig.IpAddr = strongSwanConfig.VpnGatewayIpAddr
	vpnConfig.ClientConfigList = make ([]types.VpnClientConfig, len(strongSwanConfig.ClientConfigList))
	for idx, clientConfig := range strongSwanConfig.ClientConfigList {
		localClientConfig := new (types.VpnClientConfig)
		localClientConfig.IpAddr = clientConfig.IpAddr
		localClientConfig.SubnetBlock = clientConfig.SubnetBlock

		if strongSwanConfig.VpnRole == "awsStrongSwanVpnClient" {
			localClientConfig.PreSharedKey = strongSwanConfig.PreSharedKey
			localClientConfig.TunnelConfig.LocalIpAddr = strongSwanConfig.VpnLocalIpAddr
			localClientConfig.TunnelConfig.LocalIpAddr = strongSwanConfig.VpnRemoteIpAddr
		} else {
			localClientConfig.PreSharedKey = clientConfig.PreSharedKey
			localClientConfig.SubnetBlock = clientConfig.SubnetBlock
		}
		vpnConfig.ClientConfigList[idx] = *localClientConfig
	}

	return vpnConfig, nil
}

func strongSwanVpnStatusParse(opaqueStatus string) (types.VpnServiceLocalConfig, error) {

	log.Printf("strongSwanVpnStatusParse: parsing %s\n", opaqueStatus)

	cb := []byte(opaqueStatus)
	vpnLocalConfig := types.VpnServiceLocalConfig{}
	if err := json.Unmarshal(cb, &vpnLocalConfig); err != nil {
		log.Printf("%s awsStrongSwanLocalConfig \n", err.Error())
		return vpnLocalConfig, err
	}
	return vpnLocalConfig, nil
}

func awsStrongSwanClientCreate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	// set charon config
	if err := charonNoRouteConfigCreate(); err != nil {
		return err
	}

	log.Printf("Aws StrongSwan IpSec Client Create %s:%s, %s, %s, %s\n",
		tunnelConfig.Name, gatewayConfig.IpAddr,
		gatewayConfig.SubnetBlock, tunnelConfig.LocalIpAddr,
		tunnelConfig.RemoteIpAddr)

	// create ipsec.conf
	if err := ipSecServiceConfigCreate(vpnLocalConfig); err != nil {
		return err
	}

	// create ipsec.secrets
	if err := ipSecSecretConfigCreate(vpnLocalConfig); err != nil {
		return err
	}

	// create tunnel interface
	if err := ipLinkTunnelCreate(vpnLocalConfig); err != nil {
		return err
	}

	// create iptable rules
	if err := ipTablesRuleCreate(vpnLocalConfig); err != nil {
		return err
	}

	// issue sysctl for ipsec
	if err := sysctlConfigCreate(vpnLocalConfig); err != nil {
		return err
	}

	if err := sysctlConfigSet(); err != nil {
		return err
	}

	// request ipsec service start
	if err := ipSecServiceActivate(vpnLocalConfig); err != nil {
		return err
	}

	// request ip route create
	if err := ipRouteCreate(vpnLocalConfig); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanClientDelete(vpnLocalConfig types.VpnServiceLocalConfig) error {

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	log.Printf("Aws StrongSwan IpSec Client Delete %s:%s, %s\n",
		tunnelConfig.Name, gatewayConfig.IpAddr, gatewayConfig.SubnetBlock)

	// reset charon config
	if err := charonConfigReset(); err != nil {
		return err
	}

	// reset ipsec.conf/ipsec.secrets
	// set default files in place of existing
	if err := ipSecServiceConfigDelete(); err != nil {
		return err
	}

	if err := ipSecSecretConfigDelete(); err != nil {
		return err
	}

	// request iptables rule delete
	if err := ipTablesRulesDelete(vpnLocalConfig); err != nil {
		return err
	}

	// request ip route delete
	if err := ipRouteDelete(vpnLocalConfig); err != nil {
		return err
	}

	// request tunnel interface delete
	if err := ipLinkTunnelDelete(vpnLocalConfig); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanClientActivate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	// check iplink interface existence
	if err := ipLinkInfExists(tunnelConfig.Name); err != nil {
		log.Printf("%s for %s ipLink status", err.Error(), tunnelConfig.Name)
		return err
	}

	// check iplink interface status
	if err := ipLinkIntfStateCheck(tunnelConfig.Name); err != nil {
		log.Printf("%s for %s ipLink status", err.Error(), tunnelConfig.Name)
		// issue ifup command for the tunnel
		if err := issueIfUpCmd(tunnelConfig.Name); err != nil {
			return err
		}
		return err
	}

	// check iptables rule status
	if err := ipTablesRuleCheck(vpnLocalConfig); err != nil {
		log.Printf("%s for %s ipTables status", err.Error(), tunnelConfig.Name)
		if err := ipTablesRuleCreate(vpnLocalConfig); err != nil {
			return err
		}
		return err
	}

	// check ipsec tunnel up status
	if err := ipSecTunnelStateCheck(vpnLocalConfig.VpnRole, tunnelConfig.Name); err != nil {
		log.Printf("%s for %s ipSec status", err.Error(), tunnelConfig.Name)
		if err := ipSecServiceActivate(vpnLocalConfig); err != nil {
			return err
		}
		return err
	}

	// request ip route create
	if err := ipRouteCheck(vpnLocalConfig.VpnRole, tunnelConfig.Name,
		gatewayConfig.SubnetBlock); err != nil {
		if err := ipRouteCreate(vpnLocalConfig); err != nil {
			return err
		}
	}
	return nil
}

func awsStrongSwanClientInactivate(vpnLocalConfig types.VpnServiceLocalConfig) error {
	if err := ipSecServiceInactivate(vpnLocalConfig); err != nil {
		return err
	}
	return nil
}

// StrongSwan Client connecting to OnPrem Standalone Strongswan server

func onPremStrongSwanClientCreate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	log.Printf("StrongSwan IpSec Client Create %s:%s, %s\n",
		tunnelConfig.Name, gatewayConfig.IpAddr,
		gatewayConfig.SubnetBlock)

	// create ipsec.conf
	if err := ipSecServiceConfigCreate(vpnLocalConfig); err != nil {
		return err
	}

	// create ipsec.secrets
	if err := ipSecSecretConfigCreate(vpnLocalConfig); err != nil {
		return err
	}

	// create iptable rules
	if err := ipTablesRuleCreate(vpnLocalConfig); err != nil {
		return err
	}

	// issue sysctl for ipsec
	if err := sysctlConfigCreate(vpnLocalConfig); err != nil {
		return err
	}

	if err := sysctlConfigSet(); err != nil {
		return err
	}

	// request ipsec service start
	if err := ipSecServiceActivate(vpnLocalConfig); err != nil {
		return err
	}
	return nil
}

func onPremStrongSwanClientDelete(vpnLocalConfig types.VpnServiceLocalConfig) error {

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig
	log.Printf("StrongSwan IpSec Client Delete %s:%s, %s\n",
		tunnelConfig.Name, gatewayConfig.IpAddr, gatewayConfig.SubnetBlock)

	// reset ipsec.conf/ipsec.secrets
	// set default files in place of existing
	if err := ipSecServiceConfigDelete(); err != nil {
		return err
	}

	if err := ipSecSecretConfigDelete(); err != nil {
		return err
	}

	// request iptables rule delete
	if err := ipTablesRulesDelete(vpnLocalConfig); err != nil {
		return err
	}

	return nil
}

func onPremStrongSwanClientActivate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	// check iptables rule status
	if err := ipTablesRuleCheck(vpnLocalConfig); err != nil {
		log.Printf("%s for %s ipTables status", err.Error(), tunnelConfig.Name)
		if err := ipTablesRuleCreate(vpnLocalConfig); err != nil {
			return err
		}
		return err
	}

	// activate ipsec service
	if err := ipSecServiceActivate(vpnLocalConfig); err != nil {
		return err
	}

	return nil
}

func onPremStrongSwanClientInactivate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	if err := ipSecServiceInactivate(vpnLocalConfig); err != nil {
		return err
	}
	return nil
}

// OnPrem Standalone Strongswan server

func onPremStrongSwanServerCreate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig
	log.Printf("StrongSwan Vpn Server Create %s:%s, %s\n",
		tunnelConfig.Name, gatewayConfig.IpAddr, gatewayConfig.SubnetBlock)

	// create ipsec.conf
	if err := ipSecServiceConfigCreate(vpnLocalConfig); err != nil {
		return err
	}

	// create ipsec.secrets
	if err := ipSecSecretConfigCreate(vpnLocalConfig); err != nil {
		return err
	}

	// create iptable rules
	if err := ipTablesRuleCreate(vpnLocalConfig); err != nil {
		return err
	}

	// issue sysctl for ipsec
	if err := sysctlConfigCreate(vpnLocalConfig); err != nil {
		return err
	}

	if err := sysctlConfigSet(); err != nil {
		return err
	}

	// request ipsec service start
	if err := ipSecServiceActivate(vpnLocalConfig); err != nil {
		return err
	}
	return nil
}

func onPremStrongSwanServerDelete(vpnLocalConfig types.VpnServiceLocalConfig) error {

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	log.Printf("StrongSwan Vpn Server Delete %s:%s, %s\n",
		tunnelConfig.Name, gatewayConfig.IpAddr, gatewayConfig.SubnetBlock)

	// reset ipsec.conf/ipsec.secrets
	// set default files in place of existing
	if err := ipSecServiceConfigDelete(); err != nil {
		return err
	}

	if err := ipSecSecretConfigDelete(); err != nil {
		return err
	}

	// request iptables rule delete
	if err := ipTablesRulesDelete(vpnLocalConfig); err != nil {
		return err
	}

	return nil
}

func onPremStrongSwanServerActivate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	// check iptables rule status
	if err := ipTablesRuleCheck(vpnLocalConfig); err != nil {
		log.Printf("%s for %s ipTables status", err.Error(), tunnelConfig.Name)
		if err := ipTablesRuleCreate(vpnLocalConfig); err != nil {
			return err
		}
		return err
	}

	// activate ipsec service
	if err := ipSecServiceActivate(vpnLocalConfig); err != nil {
		return err
	}

	return nil
}

func onPremStrongSwanServerInactivate(vpnLocalConfig types.VpnServiceLocalConfig) error {
	if err := ipSecServiceInactivate(vpnLocalConfig); err != nil {
		return err
	}
	return nil
}
