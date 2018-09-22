// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// ipsec tunnel management routines

package zedrouter

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"os/exec"
	"strings"
)

const (
	charonConfStr        = "# Options for charon IKE daemon\n"
	charonNoRouteConfStr = "# Options for charon IKE daemon\ncharon {\n install_routes = no\n}\n"
	charonRouteConfStr   = "# Options for charon IKE daemon\ncharon {\n install_routes = yes\n}\n"
	ipSecSecretHdrStr    = "# ipsec.secrets - IPSec secrets file\n"
	ipSecConfHdrStr      = "# ipsec.conf - default configuration\nconfig setup" +
		"\n\t uniqueids = no\n"
	ipSecTunHdrStr      = "\nconn "
	ipSecTunLeftSpecStr = "\n\tauto=start" + "\n\tleft=%defaultroute" +
		"\n\tleftid=0.0.0.0"
	ipSecTunRightSpecStr     = "\n\tright="
	ipSecTunSpecStr          = ipSecTunLeftSpecStr + ipSecTunRightSpecStr
	awsIpSecTunAttribSpecStr = "\n\trightid=%any" +
		"\n\ttype=tunnel" + "\n\tleftauth=psk" +
		"\n\trightauth=psk" + "\n\tkeyexchange=ikev1" +
		"\n\tike=aes128-sha1-modp1024" + "\n\tikelifetime=8h" +
		"\n\tesp=aes128-sha1-modp1024" + "\n\tlifetime=1h" +
		"\n\tkeyingtries=%forever" + "\n\tleftsubnet=0.0.0.0/0" +
		"\n\trightsubnet=0.0.0.0/0" + "\n\tdpddelay=10s" +
		"\n\tdpdtimeout=30s" + "\n\tdpdaction=restart" +
		"\n\tmark="
	ipSecClientTunAttribSpecStr = "\n\tleftfirewall=yes" + "\n\trightid=%any" +
		"\n\ttype=tunnel" + "\n\tleftauth=psk" +
		"\n\trightauth=psk" + "\n\tkeyexchange=ikev1" +
		"\n\tike=aes128-sha1-modp1024" +
		"\n\tikelifetime=8h" + "\n\tesp=aes128-sha1" +
		"\n\tlifetime=1h" + "\n\tkeyingtries=%forever" +
		"\n\tleftsubnet="
	ipSecClientTunRightSubnetSpecStr = "\n\trightsubnet="
	ipSecClientTunDpdSpecStr         = "\n\tdpddelay=10s" +
		"\n\tdpdtimeout=30s" +
		"\n\tdpdaction=restart" + "\n"
	ipSecSvrTunHdrSpecStr = "\nconn %default" +
		"\n\tkeylife=20m" +
		"\n\trekeymargin=3m" +
		"\n\tkeyingtries=1" +
		"\n\tauthby=psk" +
		"\n\tleftauth=psk" +
		"\n\trightauth=psk" +
		"\n\tkeyexchange=ikev1" +
		"\n\tike=aes128-sha1-modp1024" +
		"\n\tikelifetime=8h" +
		"\n\tesp=aes128-sha1" +
		"\n\tforceencaps=yes" +
		"\n\tlifetime=1h" +
		"\n"
	ipSecSvrTunLeftHdrSpecStr = "\nconn rw" +
		"\n\tleftid=%any" + "\n\tleft="
	ipSecSvrTunLeftAttribSpecStr = "\n\tleftfirewall=yes" +
		"\n\tleftsubnet=0.0.0.0/0" +
		"\n\ttype=tunnel" + "\n"
	ipSecSvrTunRightHdrSpecStr = "\nconn "
	ipSecSvrTunRightSpecStr    = "\n\talso=rw" +
		"\n\trightid=%any" +
		"\n\tright="
	ipSecSvrTunRightAttribSpecStr = "\n\trightsubnet=0.0.0.0/0" +
		"\n\tauto=add" + "\n"
)

func ipSecServiceActivate(vpnConfig types.VpnServiceConfig) error {
	tunnelConfig := vpnConfig.ClientConfigList[0].TunnelConfig
	switch vpnConfig.VpnRole {
	case AwsVpnClient:
		cmd := exec.Command("ipsec", "start")
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s start\n", err.Error(), "ipsec")
			return err
		}
	case OnPremVpnClient:
		cmd := exec.Command("ipsec", "start")
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s start\n", err.Error(), "ipsec")
			return err
		}
	case OnPremVpnServer:
		cmd := exec.Command("ipsec", "start")
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s start\n", err.Error(), "ipsec")
			return err
		}
	}
	log.Infof("ipSecService(%s) start OK\n", tunnelConfig.Name)
	return nil
}

func ipSecServiceInactivate(vpnConfig types.VpnServiceConfig) error {
	cmd := exec.Command("ipsec", "stop")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s stop\n", err.Error(), "ipsec")
		return err
	}
	log.Infof("ipSecService stop OK\n")
	return nil
}

func ipSecServiceStatus() (string, error) {
	cmd := exec.Command("ipsec", "status")
	out, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s status\n", err.Error(), "ipsec")
		return "", err
	}
	log.Infof("ipSecService() status %s\n", string(out))
	return string(out), nil
}

// check whether ipsec tunnel is up
func ipSecTunnelStateCheck(vpnRole string, tunnelName string) error {
	if err := checkIpSecServiceStatusCmd(tunnelName); err != nil {
		return err
	}
	log.Infof("%s IpSec Tunnel State OK\n", tunnelName)
	return nil
}

func ipTablesRuleCreate(vpnConfig types.VpnServiceConfig) error {

	gatewayConfig := vpnConfig.GatewayConfig
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	switch vpnConfig.VpnRole {
	case AwsVpnClient:
		return ipTablesAwsClientRulesSet(tunnelConfig.Name, gatewayConfig.IpAddr,
			tunnelConfig.Key)

	case OnPremVpnClient:
		return ipTablesSSClientRulesSet(tunnelConfig.Name, gatewayConfig.IpAddr)

	case OnPremVpnServer:
		return ipTablesSSServerRulesSet(tunnelConfig.Name, gatewayConfig.IpAddr)
	}

	return nil
}

func ipTablesRulesDelete(vpnConfig types.VpnServiceConfig) error {
	gatewayConfig := vpnConfig.GatewayConfig
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	switch vpnConfig.VpnRole {
	case AwsVpnClient:
		return ipTablesAwsClientRulesReset(tunnelConfig.Name, gatewayConfig.IpAddr,
			tunnelConfig.Key)

	case OnPremVpnClient:
		return ipTablesSSClientRulesReset(tunnelConfig.Name, gatewayConfig.IpAddr)

	case OnPremVpnServer:
		return ipTablesSSServerRulesReset(tunnelConfig.Name, gatewayConfig.IpAddr)
	}
	return nil
}

func ipTablesAwsClientRulesSet(tunnelName string, gatewayIpAddr string,
	tunnelKey string) error {

	ipTableName := "mangle"
	// set the iptable rules
	// forward rule
	cmd := exec.Command("iptables", "-t", ipTableName,
		"-I", "FORWARD", "1", "-o", tunnelName,
		"-p", "tcp", "--tcp-flags", "SYN,RST",
		"SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s forward rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// input rule
	cmd = exec.Command("iptables", "-t", ipTableName,
		"-I", "INPUT", "1", "-p", "esp", "-s", gatewayIpAddr,
		"-j", "MARK", "--set-xmark", tunnelKey)
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s input rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}
	log.Infof("ipTablesRuleSet(%s) OK\n", tunnelName)
	return nil
}

func ipTablesSSClientRulesSet(tunnelName string, gatewayIpAddr string) error {
	// set the iptable rules
	// input rule
	cmd := exec.Command("iptables",
		"-I", "INPUT", "1", "-p", "udp", "--dport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s input rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	cmd = exec.Command("iptables",
		"-I", "INPUT", "1", "-p", "udp", "--dport", "4500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s input rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// output rule
	cmd = exec.Command("iptables",
		"-I", "OUTPUT", "1", "-p", "udp", "--sport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s output rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	cmd = exec.Command("iptables",
		"-I", "OUTPUT", "1", "-p", "udp", "--sport", "4500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s output rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	log.Infof("ipTablesRuleSet(%s) OK\n", tunnelName)
	return nil
}

func ipTablesSSServerRulesSet(tunnelName string, gatewayIpAddr string) error {

	// setup the iptable rules
	// input rule
	cmd := exec.Command("iptables",
		"-I", "INPUT", "1", "-p", "udp", "--dport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s input rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	cmd = exec.Command("iptables",
		"-I", "INPUT", "1", "-p", "udp", "--dport", "4500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s input rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// output rule
	cmd = exec.Command("iptables",
		"-I", "OUTPUT", "1", "-p", "udp", "--sport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s output rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	cmd = exec.Command("iptables",
		"-I", "OUTPUT", "1", "-p", "udp", "--sport", "4500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s output rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}
	log.Infof("ipTablesRuleSet(%s) OK\n", tunnelName)
	return nil
}

func ipTablesAwsClientRulesReset(tunnelName string, gatewayIpAddr string,
	tunnelKey string) error {
	ipTableName := "mangle"

	// delete the iptable rules
	// forward rule
	cmd := exec.Command("iptables", "-t", ipTableName,
		"-D", "FORWARD", "-o", tunnelName,
		"-p", "tcp", "--tcp-flags", "SYN,RST",
		"SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s forward rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// input rule
	cmd = exec.Command("iptables", "-t", ipTableName,
		"-D", "INPUT", "-p", "esp", "-s", gatewayIpAddr,
		"-j", "MARK", "--set-xmark", tunnelKey)
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s input rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}
	log.Infof("ipTablesRuleReset(%s) OK\n", tunnelName)
	return nil
}

func ipTablesSSClientRulesReset(tunnelName string, vpnGateway string) error {

	// delete the iptable rules
	// input rule
	cmd := exec.Command("iptables",
		"-D", "INPUT", "-p", "udp", "--dport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s input rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	cmd = exec.Command("iptables",
		"-D", "INPUT", "-p", "udp", "--dport", "4500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s input rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// output rule
	cmd = exec.Command("iptables",
		"-D", "OUTPUT", "-p", "udp", "--sport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s output rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	cmd = exec.Command("iptables",
		"-D", "OUTPUT", "-p", "udp", "--sport", "4500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s output rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}
	log.Infof("ipTablesRuleReset(%s) OK\n", tunnelName)
	return nil
}

func ipTablesSSServerRulesReset(tunnelName string, gatewayIpAddr string) error {

	// delete the iptable rules
	// input rule
	cmd := exec.Command("iptables",
		"-D", "INPUT", "-p", "udp", "--dport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s input rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	cmd = exec.Command("iptables",
		"-D", "INPUT", "-p", "udp", "--dport", "4500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s output rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// output rule
	cmd = exec.Command("iptables",
		"-D", "OUTPUT", "-p", "udp", "--sport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s output rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	cmd = exec.Command("iptables",
		"-D", "OUTPUT", "-p", "udp", "--sport", "4500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s, %s output rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	log.Infof("ipTablesRuleRset(%s) reset OK\n", tunnelName)
	return nil
}

// check iptables rule status
func ipTablesRuleCheck(vpnConfig types.VpnServiceConfig) error {
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig
	gatewayConfig := vpnConfig.GatewayConfig

	switch vpnConfig.VpnRole {
	case AwsVpnClient:
		tableName := "mangle"
		if err := ipTablesChainMatch(tableName,
			"FORWARD", tunnelConfig.Name); err != nil {
			return err
		}
		if err := ipTablesChainMatch(tableName,
			"INPUT", gatewayConfig.IpAddr+"/32"); err != nil {
			return err
		}
		log.Infof("pTable(%s) check OK\n", tunnelConfig.Name)
	case OnPremVpnClient:
		log.Infof("ipTable(%s) check OK\n", tunnelConfig.Name)
	case OnPremVpnServer:
		log.Infof("ipTable(%s) check OK\n", tunnelConfig.Name)
	}
	return nil
}

func ipTablesChainMatch(tableName string, chainName string,
	matchString string) error {
	cmd := exec.Command("iptables", "-S", chainName)
	if tableName == "mangle" {
		cmd = exec.Command("iptables",
			"-t", tableName, "-S", chainName)
	}
	out, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s %s %s\n",
			err.Error(), "iptables", tableName, chainName)
		return err
	}
	outStr := string(out)
	outLines := strings.Split(outStr, "\n")
	for _, line := range outLines {
		outArr := strings.Fields(line)
		for _, field := range outArr {
			if field == matchString {
				return nil
			}
		}
	}
	errStr := tableName + " " + chainName + " " + matchString + " not found"
	return errors.New(errStr)
}

// XXX need to make sure the added route is duplicated by ipr.go to the
// correct table or add/delete from the correct table
func ipRouteCreate(vpnConfig types.VpnServiceConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	gatewayConfig := vpnConfig.GatewayConfig

	// for client config setup, create server subnet block route
	if vpnConfig.VpnRole == AwsVpnClient ||
		vpnConfig.VpnRole == OnPremVpnClient {
		clientConfig := vpnConfig.ClientConfigList[0]
		tunnelConfig := clientConfig.TunnelConfig

		cmd := exec.Command("ip", "route", "add", gatewayConfig.SubnetBlock,
			"dev", tunnelConfig.Name, "metric", tunnelConfig.Metric)
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s %s add\n",
				err.Error(), "iproute", gatewayConfig.SubnetBlock)
			return err
		}
		log.Infof("ipRoute(%s) add OK\n", tunnelConfig.Name)
		return nil
	}

	// for server config, create all client subnet block routes
	if vpnConfig.VpnRole == OnPremVpnServer {
		for _, clientConfig := range vpnConfig.ClientConfigList {
			tunnelConfig := clientConfig.TunnelConfig
			cmd := exec.Command("ip", "route", "add", clientConfig.SubnetBlock,
				"dev", tunnelConfig.Name, "metric", tunnelConfig.Metric)
			if _, err := cmd.Output(); err != nil {
				log.Errorf("%s for %s %s add\n",
					err.Error(), "iproute", clientConfig.SubnetBlock)
				return err
			}
			log.Infof("ipRoute(%s) %s create OK\n",
				tunnelConfig.Name, clientConfig.SubnetBlock)
		}
		return nil
	}
	return errors.New("unknown VpnRole: " + vpnConfig.VpnRole)
}

func ipRouteDelete(vpnConfig types.VpnServiceConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	gatewayConfig := vpnConfig.GatewayConfig

	// for client config setup, create server subnet route
	if vpnConfig.VpnRole == AwsVpnClient ||
		vpnConfig.VpnRole == OnPremVpnClient {

		tunnelConfig := vpnConfig.ClientConfigList[0].TunnelConfig
		cmd := exec.Command("ip", "route", "delete", gatewayConfig.SubnetBlock)
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s %s add\n",
				err.Error(), "iproute", gatewayConfig.SubnetBlock)
			return err
		}
		log.Infof("ipRoute(%s) %s delete OK\n", tunnelConfig.Name,
			gatewayConfig.SubnetBlock)
		return nil
	}

	// for server config, remove all client routes
	if vpnConfig.VpnRole == OnPremVpnServer {
		for _, clientConfig := range vpnConfig.ClientConfigList {
			tunnelConfig := clientConfig.TunnelConfig
			cmd := exec.Command("ip", "route", "delete", clientConfig.SubnetBlock)
			if _, err := cmd.Output(); err != nil {
				log.Errorf("%s for %s %s add\n",
					err.Error(), "iproute", clientConfig.SubnetBlock)
				return err
			}
			log.Infof("ipRoute(%s) %s delete OK\n",
				tunnelConfig.Name, clientConfig.SubnetBlock)
		}
		return nil
	}
	return errors.New("unknown VpnRole: " + vpnConfig.VpnRole)
}

func ipRouteCheck(vpnConfig types.VpnServiceConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	gatewayConfig := vpnConfig.GatewayConfig
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	// for client configs, check server subnet block route
	if vpnConfig.VpnRole == AwsVpnClient ||
		vpnConfig.VpnRole == OnPremVpnClient {
		cmd := exec.Command("ip", "route", "get", gatewayConfig.SubnetBlock)
		out, err := cmd.Output()
		if err != nil {
			log.Errorf("%s for %s %s check, no route\n",
				err.Error(), "iproute", gatewayConfig.SubnetBlock)
			return err
		}

		if err := ipRouteMatch(string(out), tunnelConfig.Name); err != nil {
			log.Errorf("%s for ipRoute(%s) check fail\n", err, tunnelConfig.Name)
			return err
		}
		log.Infof("ipRoute(%s) check OK\n", tunnelConfig.Name)
		return nil
	}

	// for server config, check all client subnet block routes
	if vpnConfig.VpnRole == OnPremVpnServer {
		for _, clientConfig := range vpnConfig.ClientConfigList {
			tunnelConfig := clientConfig.TunnelConfig
			cmd := exec.Command("ip", "route", "get", clientConfig.SubnetBlock)
			out, err := cmd.Output()
			if err != nil {
				log.Errorf("%s for %s %s check, no route\n",
					err.Error(), "iproute", clientConfig.SubnetBlock)
				return err
			}

			if err := ipRouteMatch(string(out), tunnelConfig.Name); err != nil {
				log.Errorf("%s for ipRoute(%s) check fail\n",
					err, tunnelConfig.Name)
				return err
			}
			log.Infof("ipRoute(%s) %s check OK\n",
				tunnelConfig.Name, clientConfig.SubnetBlock)
		}
		return nil
	}
	return errors.New("unknown VpnRole: " + vpnConfig.VpnRole)
}

func ipRouteMatch(outStr, matchString string) error {
	lines := strings.Split(outStr, "\n")
	for _, line := range lines {
		outArr := strings.Fields(line)
		for _, field := range outArr {
			if field == matchString {
				return nil
			}
		}
	}
	return errors.New("not found")
}

func ipLinkTunnelCreate(vpnConfig types.VpnServiceConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	gatewayConfig := vpnConfig.GatewayConfig
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig
	upLinkConfig := vpnConfig.UpLinkConfig

	log.Infof("%s: %s %s %s\n", tunnelConfig.Name, "ip link add",
		upLinkConfig.IpAddr, gatewayConfig.IpAddr)
	if vpnConfig.VpnRole == AwsVpnClient ||
		vpnConfig.VpnRole == OnPremVpnClient {
		cmd := exec.Command("ip", "link", "add",
			tunnelConfig.Name, "type", "vti", "local", upLinkConfig.IpAddr,
			"remote", gatewayConfig.IpAddr, "key", tunnelConfig.Key)
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s %s add on %s\n", err.Error(), "ip link",
				tunnelConfig.Name, upLinkConfig.IpAddr, gatewayConfig.IpAddr)
			return err
		}
	}

	// for server, create remote any
	if vpnConfig.VpnRole == OnPremVpnServer {
		cmd := exec.Command("ip", "link", "add",
			tunnelConfig.Name, "type", "vti", "local", upLinkConfig.IpAddr,
			"remote", "0.0.0.0")
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s %s add on %s\n", err.Error(), "ip link",
				tunnelConfig.Name, upLinkConfig.IpAddr, gatewayConfig.IpAddr)
			return err
		}
	}

	if vpnConfig.VpnRole == AwsVpnClient {
		log.Infof("%s: %s %s %s\n", tunnelConfig.Name, "ip link addr",
			tunnelConfig.LocalIpAddr, tunnelConfig.RemoteIpAddr)
		cmd := exec.Command("ip", "addr", "add",
			tunnelConfig.LocalIpAddr, "remote", tunnelConfig.RemoteIpAddr,
			"dev", tunnelConfig.Name)
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s %s addr add\n",
				err.Error(), "ip link", tunnelConfig.Name, tunnelConfig.LocalIpAddr,
				tunnelConfig.RemoteIpAddr)
			return err
		}
	}

	log.Infof("%s: %s %s\n", tunnelConfig.Name, "ip link mtu",
		tunnelConfig.Mtu)
	cmd := exec.Command("ip", "link", "set",
		tunnelConfig.Name, "up", "mtu", tunnelConfig.Mtu)
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s %s set mtu up\n",
			err.Error(), "ip link mtu", tunnelConfig.Name)
		return err
	}

	log.Infof("ipLink(%s) add OK\n", tunnelConfig.Name)
	return nil
}

func ipLinkTunnelDelete(vpnConfig types.VpnServiceConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	cmd := exec.Command("ip", "link", "delete", tunnelConfig.Name)
	_, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s %s delete\n",
			err.Error(), "ip link", tunnelConfig.Name)
		return err
	}
	log.Infof("ipLink(%s) delete OK\n", tunnelConfig.Name)
	return nil
}

func ipLinkInfExists(tunnelName string) error {
	// whether the tunnel exists
	// should trigger creating the ip link interface
	if err := checkIntfExistsCmd(tunnelName); err != nil {
		return err
	}
	return nil
}

func ipLinkIntfStateCheck(tunnelName string) error {

	// whether the tunnel exists
	// should trigger creating the ip link interface
	if err := ipLinkInfExists(tunnelName); err != nil {
		return err
	}

	// whether the tunnel ifstate is up
	// if not, try to make it up
	if err := checkIntfStateCmd(tunnelName); err != nil {
		return err
	}
	log.Infof("ipLink(%s) check OK\n", tunnelName)
	return nil
}

func ipSecServiceConfigCreate(vpnConfig types.VpnServiceConfig) error {

	clientConfigList := vpnConfig.ClientConfigList
	gatewayConfig := vpnConfig.GatewayConfig

	writeStr := ipSecConfHdrStr
	switch vpnConfig.VpnRole {
	case AwsVpnClient:
		// only one client
		tunnelConfig := clientConfigList[0].TunnelConfig
		writeStr = writeStr + ipSecTunHdrStr + tunnelConfig.Name
		writeStr = writeStr + ipSecTunSpecStr + gatewayConfig.IpAddr
		writeStr = writeStr + awsIpSecTunAttribSpecStr + tunnelConfig.Key
		writeStr = writeStr + "\n"

	case OnPremVpnClient:
		// only one client
		clientConfig := clientConfigList[0]
		tunnelConfig := clientConfig.TunnelConfig
		writeStr = writeStr + ipSecTunHdrStr + tunnelConfig.Name
		writeStr = writeStr + ipSecTunSpecStr + gatewayConfig.IpAddr
		writeStr = writeStr + ipSecClientTunAttribSpecStr
		writeStr = writeStr + clientConfig.SubnetBlock
		writeStr = writeStr + ipSecClientTunRightSubnetSpecStr
		writeStr = writeStr + gatewayConfig.SubnetBlock
		writeStr = writeStr + ipSecClientTunDpdSpecStr

	case OnPremVpnServer:
		writeStr = writeStr + ipSecSvrTunHdrSpecStr
		writeStr = writeStr + ipSecSvrTunLeftHdrSpecStr + gatewayConfig.IpAddr
		writeStr = writeStr + ipSecSvrTunLeftAttribSpecStr

		// one or more clients
		wildMatch := false
		for _, clientConfig := range clientConfigList {
			if match := isClientWildCard(clientConfig); match {
				log.Infof("wildCard Client %s\n", clientConfig.IpAddr)
				if wildMatch {
					continue
				}
				wildMatch = true
			}
			tunnelConfig := clientConfig.TunnelConfig
			writeStr = writeStr + ipSecSvrTunRightHdrSpecStr + tunnelConfig.Name
			writeStr = writeStr + ipSecSvrTunRightSpecStr + clientConfig.IpAddr
			writeStr = writeStr + ipSecSvrTunRightAttribSpecStr
		}

	default:
		return errors.New("unsupported vpn role: " + vpnConfig.VpnRole)
	}
	writeStr = writeStr + "\n"
	filename := "/etc/ipsec.conf"
	if err := ipSecConfigFileWrite(filename, writeStr); err != nil {
		return err
	}
	cmd := exec.Command("chmod", "600", filename)
	_, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s %s\n", err.Error(), "chmod", filename)
		return err
	}
	log.Infof("ipSecConfigWrite(%s) OK\n", gatewayConfig.IpAddr)
	return nil
}

func ipSecServiceConfigDelete() error {
	writeStr := ipSecConfHdrStr
	filename := "/etc/ipsec.conf"
	return ipSecConfigFileWrite(filename, writeStr)
}

func ipSecSecretConfigCreate(vpnConfig types.VpnServiceConfig) error {

	clientConfigList := vpnConfig.ClientConfigList
	gatewayConfig := vpnConfig.GatewayConfig

	writeStr := ipSecSecretHdrStr
	switch vpnConfig.VpnRole {
	case AwsVpnClient:
		// always one client
		for _, clientConfig := range clientConfigList {
			writeStr = writeStr + clientConfig.IpAddr + " "
			writeStr = writeStr + gatewayConfig.IpAddr
			writeStr = writeStr + " : PSK " + clientConfig.PreSharedKey
			writeStr = writeStr + "\n"
		}

	case OnPremVpnClient:
		// always one client
		for _, clientConfig := range clientConfigList {
			writeStr = writeStr + clientConfig.IpAddr + " "
			writeStr = writeStr + gatewayConfig.IpAddr
			writeStr = writeStr + " : PSK " + clientConfig.PreSharedKey
			writeStr = writeStr + "\n"
		}

	case OnPremVpnServer:
		wildMatch := false
		// one or more client(s)
		for _, clientConfig := range clientConfigList {
			if match := isClientWildCard(clientConfig); match {
				log.Infof("wildCard Client %s\n", clientConfig.IpAddr)
				// contains the preshared key
				if clientConfig.PreSharedKey == "" ||
					wildMatch {
					continue
				}
				wildMatch = true
			}
			secretStr := gatewayConfig.IpAddr + " " + clientConfig.IpAddr
			secretStr = secretStr + " : PSK " + clientConfig.PreSharedKey
			secretStr = secretStr + "\n"
			if !strings.Contains(writeStr, secretStr) {
				writeStr = writeStr + secretStr
			}
		}
	}
	writeStr = writeStr + "\n"
	filename := "/etc/ipsec.secrets"
	if err := ipSecConfigFileWrite(filename, writeStr); err != nil {
		return err
	}
	cmd := exec.Command("chmod", "600", filename)
	_, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s %s\n", err.Error(), "chmod", filename)
		return err
	}
	log.Infof("ipSecSecretWrite(%s) OK\n", gatewayConfig.IpAddr)
	return nil
}

func ipSecSecretConfigDelete() error {
	writeStr := ipSecSecretHdrStr
	filename := "/etc/ipsec.secrets"
	return ipSecConfigFileWrite(filename, writeStr)
}

func charonRouteConfigCreate(policyflag bool) error {
	filename := "/etc/strongswan.d/charon.conf"
	if policyflag {
		return ipSecConfigFileWrite(filename, charonRouteConfStr)
	}
	return ipSecConfigFileWrite(filename, charonNoRouteConfStr)
}

func charonConfigReset() error {
	filename := "/etc/strongswan.d/charon.conf"
	return ipSecConfigFileWrite(filename, charonConfStr)
}

func sysctlConfigCreate(vpnConfig types.VpnServiceConfig) error {

	upLinkConfig := vpnConfig.UpLinkConfig
	log.Infof("%s: %s config\n", upLinkConfig.Name, "sysctl")

	writeStr := ""
	if vpnConfig.PolicyBased {
		writeStr = writeStr + "\n net.ipv4.conf." + upLinkConfig.Name + ".disable_xfrm=0"
		writeStr = writeStr + "\n net.ipv4.conf." + upLinkConfig.Name + ".disable_policy=0\n"
	} else {
		writeStr = writeStr + "\n net.ipv4.conf." + upLinkConfig.Name + ".disable_xfrm=1"
		writeStr = writeStr + "\n net.ipv4.conf." + upLinkConfig.Name + ".disable_policy=1\n"
		for _, clientConfig := range vpnConfig.ClientConfigList {
			tunnelConfig := clientConfig.TunnelConfig
			log.Infof("%s: %s config\n", tunnelConfig.Name, "sysctl")
			writeStr = writeStr + "\n net.ipv4.conf." + tunnelConfig.Name + ".rp_filter=2"
			writeStr = writeStr + "\n net.ipv4.conf." + tunnelConfig.Name + ".disable_policy=1"
		}
	}
	filename := "/etc/sysctl.conf"
	if err := ipSecConfigFileWrite(filename, writeStr); err != nil {
		log.Errorf("sysctlConfigWrite() Fail\n")
		return err
	}
	log.Infof("sysctlConfigWrite() OK\n")
	return nil
}

func sysctlConfigReset(vpnConfig types.VpnServiceConfig) error {
	return nil
}

func sysctlConfigSet() error {
	cmd := exec.Command("sysctl", "-p")
	_, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s set \n", err.Error(), "sysctl")
		return err
	}
	log.Infof("sysctlConfigSet() OK\n")
	return nil
}

func ipSecConfigFileWrite(filename string, writeStr string) error {
	data := []byte(writeStr)
	if err := pubsub.WriteRename(filename, data); err != nil {
		return err
	}
	return nil
}

func checkIntfExistsCmd(intfName string) error {
	cmd := exec.Command("ifconfig", intfName)
	_, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s %s status\n",
			err.Error(), "ifconfig", intfName)
		return err
	}
	return nil
}

func checkIntfStateCmd(intfName string) error {
	cmd := exec.Command("ifconfig", intfName)
	out, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s %s status\n",
			err.Error(), "ifconfig", intfName)
		return err
	}
	outStr := string(out)
	lines := strings.Split(outStr, "\n")
	for _, line := range lines {
		outArr := strings.Fields(line)
		for _, field := range outArr {
			if field == "UP" ||
				field == "RUNNING" {
				return nil
			}
		}
	}
	return errors.New("interface is down")
}

func checkIpSecServiceStatusCmd(tunnelName string) error {
	cmd := exec.Command("ipsec", "status")
	out, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s %s status\n",
			err.Error(), "ipsec", tunnelName)
		return err
	}
	return checkIpSecStatusCmdOutput(tunnelName, string(out))
}

func checkIpSecStatusCmdOutput(tunnelName string, outStr string) error {
	lines := strings.Split(outStr, "\n")
	for _, line := range lines {
		outArr := strings.Fields(line)
		for _, field := range outArr {
			if field == tunnelName {
				return getIpSecLineState(outArr)
			}
		}
	}
	return nil
}

func getIpSecLineState(outArr []string) error {
	for _, field := range outArr {
		if field == "ESTABLISHED" {
			return nil
		}
		if field == "LISTENING" {
			return errors.New("connecting")
		}
	}
	return errors.New("not up")
}

func issueIfUpCmd(tunnelName string) error {
	cmd := exec.Command("ifup", tunnelName)
	_, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s %s\n",
			err.Error(), "ifup", tunnelName)
		return err
	}
	return nil
}
