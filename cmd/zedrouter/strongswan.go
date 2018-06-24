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

	ipSecConfig, err := awsStrongSwanConfigParse(config.OpaqueConfig)
	if err != nil {
		return err
	}

	if ipSecConfig.AwsVpnGateway == "" ||
		ipSecConfig.AwsVpcSubnet == "" ||
		ipSecConfig.VpnLocalIpAddr == "" ||
		ipSecConfig.VpnRemoteIpAddr == "" ||
		ipSecConfig.PreSharedKey == "" {
		return errors.New("invalid parameters")
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
	ipSecLocalConfig := types.IpSecLocalConfig{
		AwsVpnGateway: ipSecConfig.AwsVpnGateway,
		AwsVpcSubnet:  ipSecConfig.AwsVpcSubnet,
		TunnelName:    "ipSecTunnel",
		UpLinkName:    config.Adapter,
		UpLinkIpAddr:  srcIp.String(),
		IpTable:       "mangle",
		TunnelKey:     "100",
		Mtu:           "1419",
		Metric:        "50",
	}

	// stringify and store in status
	bytes, err := json.Marshal(ipSecLocalConfig)
	if err != nil {
		return nil
	}
	status.OpaqueStatus = string(bytes)

	// create the ipsec config files, tunnel and rules
	if err := awsStrongSwanIpSecTunnelCreate(ipSecConfig,
		ipSecLocalConfig); err != nil {
		return err
	}

	return nil
}

func strongswanDelete(status *types.NetworkServiceStatus) {

	ipSecLocalConfig, err := awsStrongSwanStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("strongswanDelete config absent")
		return
	}

	if err := awsStrongSwanTunnelDelete(ipSecLocalConfig); err != nil {
		log.Printf("%s awsStrongSwanConfig delete\n", err.Error())
	}
}

func strongswanActivate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	ipSecConfig, err := awsStrongSwanConfigParse(config.OpaqueConfig)
	if err != nil {
		return err
	}

	ipSecLocalConfig, err := awsStrongSwanStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("strongswan local config absent")
		return err
	}

	if err := awsStrongSwanTunnelActivate(ipSecConfig,
		ipSecLocalConfig); err != nil {
		return err
	}
	return nil
}

func strongswanInactivate(status *types.NetworkServiceStatus) {

	ipSecLocalConfig, err := awsStrongSwanStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Printf("strongswan local config absent")
		return
	}

	if err := awsStrongSwanTunnelInactivate(ipSecLocalConfig); err != nil {
		log.Printf("%s awsStrongSwanTunnel deactivate\n", err.Error())
	}
}

// aws Vpn IpSec Tenneling handler routines
func awsStrongSwanConfigParse(opaqueConfig string) (types.AwsSSIpSecService, error) {

	cb := []byte(opaqueConfig)
	ipSecConfig := types.AwsSSIpSecService{}
	if err := json.Unmarshal(cb, &ipSecConfig); err != nil {
		log.Printf("%s awsStrongSwanConfig \n", err.Error())
		return ipSecConfig, err
	}
	return ipSecConfig, nil
}

func awsStrongSwanStatusParse(opaqueStatus string) (types.IpSecLocalConfig, error) {

	cb := []byte(opaqueStatus)
	ipSecLocalConfig := types.IpSecLocalConfig{}
	if err := json.Unmarshal(cb, &ipSecLocalConfig); err != nil {
		log.Printf("%s awsStrongSwanLocalConfig \n", err.Error())
		return ipSecLocalConfig, err
	}
	return ipSecLocalConfig, nil
}

func awsStrongSwanIpSecTunnelCreate(ipSecConfig types.AwsSSIpSecService,
	ipSecLocalConfig types.IpSecLocalConfig) error {

	// set charon config
	if err := charonConfigCreate(); err != nil {
		return err
	}

	log.Printf("Creating IpSec Tunnel %s:%s, %s, %s, %s\n",
		ipSecLocalConfig.TunnelName, ipSecConfig.AwsVpnGateway,
		ipSecConfig.AwsVpcSubnet, ipSecConfig.VpnLocalIpAddr,
		ipSecConfig.VpnRemoteIpAddr)

	// create ipsec.conf
	if err := awsStrongSwanIpSecServiceConfigCreate(ipSecConfig,
		ipSecLocalConfig); err != nil {
		return err
	}

	// create ipsec.secrets
	if err := awsStrongSwanIpSecSecretConfigCreate(ipSecConfig); err != nil {
		return err
	}

	// create tunnel interface
	if err := awsStrongSwanIpLinkCreate(ipSecConfig,
		ipSecLocalConfig); err != nil {
		return err
	}

	// create iptable rules
	if err := awsStrongSwanIpTablesRuleCreate(ipSecLocalConfig); err != nil {
		return err
	}

	// issue sysctl for ipsec
	if err := awsStrongSwanSysctlConfigCreate(ipSecLocalConfig); err != nil {
		return err
	}

	if err := sysctlConfigSet(); err != nil {
		return err
	}

	// request ipsec service start
	if err := awsStrongSwanIpSecServiceActivate(ipSecLocalConfig); err != nil {
		return err
	}

	// request ip route create
	if err := awsStrongSwanIpRouteCreate(ipSecLocalConfig); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanTunnelDelete(ipSecLocalConfig types.IpSecLocalConfig) error {

	// reset ipsec.conf/ipsec.secrets
	// set default files in place of existing
	if err := ipSecServiceConfigDelete(); err != nil {
		return err
	}

	if err := ipSecSecretConfigDelete(); err != nil {
		return err
	}

	// request iptables rule delete
	if err := awsStronSwanIpTablesRuleDelete(ipSecLocalConfig); err != nil {
		return err
	}

	// request ip route delete
	if err := awsStrongSwanIpRouteDelete(ipSecLocalConfig); err != nil {
		return err
	}

	// request tunnel interface delete
	if err := awdStrongSwanIpLinkDelete(ipSecLocalConfig); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanTunnelActivate(ipSecConfig types.AwsSSIpSecService,
	ipSecLocalConfig types.IpSecLocalConfig) error {

	// check iplink interface existence
	if err := ipLinkInfExists(ipSecLocalConfig.TunnelName); err != nil {
		log.Printf("%s for %s ipLink status", err.Error(),
			ipSecLocalConfig.TunnelName)
		return err
	}

	// check iplink interface status
	if err := ipLinkIntfStateCheck(ipSecLocalConfig.TunnelName); err != nil {
		log.Printf("%s for %s ipLink status", err.Error(),
			ipSecLocalConfig.TunnelName)
		// issue ifup command for the tunnel
		if err := issueIfUpCmd(ipSecLocalConfig.TunnelName); err != nil {
			return err
		}
		return err
	}

	// check iptables rule status
	if err := ipTablesRuleCheck(ipSecLocalConfig.IpTable,
		ipSecLocalConfig.TunnelName,
		ipSecLocalConfig.AwsVpnGateway); err != nil {
		log.Printf("%s for %s ipTables status", err.Error(),
			ipSecLocalConfig.TunnelName)
		if err := awsStrongSwanIpTablesRuleCreate(ipSecLocalConfig); err != nil {
			return err
		}
		return err
	}

	// check ipsec tunnel up status
	if err := ipSecTunnelStateCheck(ipSecLocalConfig.TunnelName); err != nil {
		log.Printf("%s for %s ipSec status", err.Error(),
			ipSecLocalConfig.TunnelName)
		if err := awsStrongSwanIpSecServiceActivate(ipSecLocalConfig); err != nil {
			return err
		}
		return err
	}

	// request ip route create
	if err := ipRouteCheck(ipSecLocalConfig.TunnelName,
		ipSecLocalConfig.AwsVpcSubnet); err != nil {
		if err := awsStrongSwanIpRouteCreate(ipSecLocalConfig); err != nil {
			return err
		}
	}
	return nil
}

func awsStrongSwanTunnelInactivate(ipSecLocalConfig types.IpSecLocalConfig) error {
	if err := ipSecServiceInactivate(ipSecLocalConfig.TunnelName); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanIpSecServiceConfigCreate(ipSecConfig types.AwsSSIpSecService,
	ipSecLocalConfig types.IpSecLocalConfig) error {
	if err := ipSecServiceConfigCreate(ipSecLocalConfig.TunnelName,
		ipSecConfig.AwsVpnGateway,
		ipSecLocalConfig.TunnelKey); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanIpSecSecretConfigCreate(ipSecConfig types.AwsSSIpSecService) error {
	// create ipsec.secrets
	if err := ipSecSecretConfigCreate(ipSecConfig.AwsVpnGateway,
		ipSecConfig.PreSharedKey); err != nil {
		return err
	}
	return nil
}
func awsStrongSwanIpLinkCreate(ipSecConfig types.AwsSSIpSecService,
	ipSecLocalConfig types.IpSecLocalConfig) error {
	// create tunnel interface
	if err := ipLinkTunnelCreate(ipSecLocalConfig.TunnelName,
		ipSecLocalConfig.UpLinkIpAddr,
		ipSecConfig.AwsVpnGateway,
		ipSecConfig.VpnLocalIpAddr,
		ipSecConfig.VpnRemoteIpAddr,
		ipSecLocalConfig.TunnelKey,
		ipSecLocalConfig.Mtu); err != nil {
		return err
	}
	return nil
}

func awdStrongSwanIpLinkDelete(ipSecLocalConfig types.IpSecLocalConfig) error {
	// request tunnel interface delete
	if err := ipLinkTunnelDelete(ipSecLocalConfig.TunnelName); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanIpTablesRuleCreate(ipSecLocalConfig types.IpSecLocalConfig) error {
	if err := ipTablesRuleCreate(ipSecLocalConfig.IpTable,
		ipSecLocalConfig.TunnelName, ipSecLocalConfig.AwsVpnGateway,
		ipSecLocalConfig.TunnelKey); err != nil {
		return err
	}
	return nil
}

func awsStronSwanIpTablesRuleDelete(ipSecLocalConfig types.IpSecLocalConfig) error {
	// request ip route delete
	if err := ipTablesRulesDelete(ipSecLocalConfig.IpTable,
		ipSecLocalConfig.TunnelName, ipSecLocalConfig.AwsVpnGateway,
		ipSecLocalConfig.TunnelKey); err != nil {
		return err
	}
	return nil
}
func awsStrongSwanSysctlConfigCreate(ipSecLocalConfig types.IpSecLocalConfig) error {
	if err := sysctlConfigCreate(ipSecLocalConfig.UpLinkName,
		ipSecLocalConfig.TunnelName); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanIpSecServiceActivate(ipSecLocalConfig types.IpSecLocalConfig) error {
	if err := ipSecServiceActivate(ipSecLocalConfig.TunnelName); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanIpSecServiceInactivate(ipSecLocalConfig types.IpSecLocalConfig) error {
	if err := ipSecServiceInactivate(ipSecLocalConfig.TunnelName); err != nil {
		return err
	}
	return nil
}
func awsStrongSwanIpRouteCreate(ipSecLocalConfig types.IpSecLocalConfig) error {
	// request ip route create
	if err := ipRouteCreate(ipSecLocalConfig.TunnelName,
		ipSecLocalConfig.AwsVpcSubnet, ipSecLocalConfig.Metric); err != nil {
		return err
	}
	return nil
}

func awsStrongSwanIpRouteDelete(ipSecLocalConfig types.IpSecLocalConfig) error {
	// request ip route delete
	if err := ipRouteDelete(ipSecLocalConfig.TunnelName,
		ipSecLocalConfig.AwsVpcSubnet); err != nil {
		return err
	}
	return nil
}
