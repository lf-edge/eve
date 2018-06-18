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


func strongswanCreate(config types.NetworkServiceConfig,
			status *types.NetworkServiceStatus) error {

	ipSecConfig, err := awsStrongSwanConfigParse(config.OpaqueConfig)
	if err != nil {
		return err
	}

	// if adapter is not set, return
	// XXX:FIXME add logic to pick up some uplink
	if config.Adapter == "" {
		err := errors.New("uplink config absent")
		return err
	}

	// if address error
	srcIp, err := types.GetLocalAddrAny(deviceNetworkStatus, 0,
							config.Adapter)
	if  err != nil {
		return err
	}
	
	// set the local config
	ipSecLocalConfig := types.IpSecLocalConfig {
			TunnelName   : "ipSecTunnel",
			UpLinkName   : config.Adapter,
			UpLinkIpAddr : srcIp.String(),
			IpTable      : "mangle",
			TunnelKey    : "100",
			Mtu          : "1419",
			Metric       : "50",
		}

	// create the ipsec config files, tunnel and rules
	if err := awsStrongSwanTunnelCreate(ipSecConfig,
				ipSecLocalConfig); err != nil {
		return err
	}

	return nil
}

func strongswanDelete(status *types.NetworkServiceStatus) {

	// set the local config
	ipSecLocalConfig := types.IpSecLocalConfig {
			TunnelName : "ipSecTunnel",
			IpTable    : "mangle",
		}

	if err := awsStrongSwanTunnelDelete(ipSecLocalConfig); err != nil {
		log.Printf("%s awsStrongSwanConfig delete\n", err.Error())
	}
}

func strongswanActivate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	if _, err := awsStrongSwanConfigParse(config.OpaqueConfig); err != nil {
		return err
	}

	if err := awsStrongSwanTunnelActivate(); err != nil {
		return err
	}
	return nil
}

func strongswanInactivate(status *types.NetworkServiceStatus) {

	if err := awsStrongSwanTunnelInactivate(); err != nil {
		log.Printf("%s awsStrongSwanTunnel deactivate\n", err.Error())
	}
}

// aws Vpn IpSec Tenneling handler routines
func awsStrongSwanConfigParse (opaqueConfig string) (types.AwsSSIpSecService, error) {

	cb := []byte(opaqueConfig)
	ipSecConfig := types.AwsSSIpSecService{}
	if err := json.Unmarshal(cb, &ipSecConfig); err != nil {
		log.Printf("%s awsStrongSwanConfig \n", err.Error())
		return ipSecConfig, err
	}
	return ipSecConfig, nil
}

func awsStrongSwanTunnelCreate(ipSecConfig types.AwsSSIpSecService,
			ipSecLocalConfig types.IpSecLocalConfig) error {

	// set charon config
	if err :=  charonConfigCreate(); err != nil {
		return err
	}

	// create ipsec.conf
	if err := ipSecServiceConfigCreate(ipSecLocalConfig.TunnelName,
				ipSecConfig.AwsVpnGateway,
				ipSecLocalConfig.TunnelKey); err != nil {
		return err
	}

	// create ipsec.secrets
	if err := ipSecSecretConfigCreate(ipSecConfig.AwsVpnGateway,
				ipSecConfig.PreSharedKey); err != nil {
		return err
	}

	// create tunnel interface
	if err := ipLinkTunnelCreate(ipSecLocalConfig.TunnelName,
				ipSecLocalConfig.UpLinkIpAddr,
				ipSecConfig.AwsVpnGateway,
				ipSecConfig.TunnelLocalIpAddr,
				ipSecConfig.TunnelRemoteIpAddr,
				ipSecLocalConfig.TunnelKey,
				ipSecLocalConfig.Mtu); err != nil {
		return err
	}

	// create iptable rules
	if err := ipTablesRuleCreate(ipSecLocalConfig.IpTable,
				ipSecLocalConfig.TunnelName, ipSecConfig.AwsVpnGateway,
				ipSecLocalConfig.TunnelKey); err != nil {
		return err
	}

	// request ip route create
	if err := ipRouteCreate(ipSecLocalConfig.TunnelName,
				ipSecConfig.AwsVpcSubnet, ipSecLocalConfig.Metric); err != nil {
		return err
	}

	// issue sysctl for ipsec
	if err := sysctlConfigCreate(ipSecLocalConfig.UpLinkName,
				ipSecLocalConfig.TunnelName); err != nil {
		return err
	}

	if err := sysctlConfigSet(); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanTunnelDelete(ipSecLocalConfig types.IpSecLocalConfig)  error {

	// reset ipsec.conf/ipsec.secrets
	// set default files in place of existing
	if err := ipSecServiceConfigDelete(); err != nil {
		return err
	}

	if err := ipSecSecretConfigDelete(); err != nil {
		return err
	}

	// request iptables flush
	if err := ipTablesRulesDelete(ipSecLocalConfig.IpTable); err != nil {
		return err
	}

	// request tunnel interface delete
	if err := ipLinkTunnelDelete(ipSecLocalConfig.TunnelName); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanTunnelActivate() error {
	// request ipsec service start
	if err := ipSecServiceActivate(); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanTunnelInactivate() error {
	if err:= ipSecServiceInactivate(); err != nil {
		return err
	}
	return nil
}
