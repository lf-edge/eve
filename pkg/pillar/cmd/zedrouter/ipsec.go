// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// ipsec tunnel management routines

package zedrouter

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	log "github.com/sirupsen/logrus"
)

type vpnAclRule struct {
	table  string
	chain  string
	proto  string
	sport  string
	dport  string
	dir    string
	intf   string
	target string
}

var vpnCounterAcls = []vpnAclRule{
	{chain: "INPUT", proto: "udp", sport: "500", target: "ACCEPT"},
	{chain: "OUTPUT", proto: "udp", dport: "500", target: "ACCEPT"},
	{chain: "INPUT", proto: "udp", sport: "4500", target: "ACCEPT"},
	{chain: "OUTPUT", proto: "udp", dport: "4500", target: "ACCEPT"},
	{chain: "INPUT", proto: "esp", target: "ACCEPT"},
	{chain: "OUTPUT", proto: "esp", target: "ACCEPT"},
}

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

	azureIpSecLeftTunAttribSpecStr = "\n\tauto=start" +
		"\n\tauthby=secret" +
		"\n\ttype=tunnel" + "\n\tkeyexchange=ikev2" +
		"\n\tike=aes128-sha1-modp1024" + "\n\tesp=aes128-sha1" +
		"\n\tleft=%any" + "\n\tleftsubnet="
	azureIpSecRightTunAttribSpecStr = "\n\trightid=%any" +
		"\n\tright="
	azureIpSecRightSubnetSpecStr = "\n\trightsubnet="

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

func ipSecActivate(vpnConfig types.VpnConfig) error {
	tunnelConfig := vpnConfig.ClientConfigList[0].TunnelConfig
	cmd := exec.Command("ipsec", "start")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s start\n", err.Error(), "ipsec")
		return err
	}
	log.Infof("ipSec(%s) start OK\n", tunnelConfig.Name)
	return nil
}

func ipSecInactivate(vpnConfig types.VpnConfig) error {
	cmd := exec.Command("ipsec", "stop")
	if _, err := cmd.Output(); err != nil {
		log.Errorf("%s for %s stop\n", err.Error(), "ipsec")
		return err
	}
	log.Infof("ipSec stop OK\n")
	return nil
}

func ipSecStatus() (string, error) {
	cmd := exec.Command("ipsec", "status")
	out, err := cmd.Output()
	if err != nil {
		log.Errorf("%s for %s status\n", err.Error(), "ipsec")
		return "", err
	}
	log.Infof("ipSec() status %s\n", string(out))
	return string(out), nil
}

// check whether ipsec tunnel is up
func ipSecTunnelStateCheck(vpnRole string, tunnelName string) error {
	if err := checkIpSecStatusCmd(tunnelName); err != nil {
		return err
	}
	log.Infof("%s IpSec Tunnel State OK\n", tunnelName)
	return nil
}

func ipTablesRuleCreate(vpnConfig types.VpnConfig) error {

	portConfig := vpnConfig.PortConfig
	gatewayConfig := vpnConfig.GatewayConfig
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	if vpnConfig.VpnRole == AwsVpnClient {
		if err := ipTablesAwsClientRulesSet(tunnelConfig.Name,
			gatewayConfig.IpAddr, tunnelConfig.Key); err != nil {
			return err
		}
	}
	if err := ipTablesCounterRulesSet(vpnConfig.PolicyBased,
		tunnelConfig.Name, portConfig.IfName); err != nil {
		return err
	}
	return nil
}

func ipTablesRulesDelete(vpnConfig types.VpnConfig) error {
	portConfig := vpnConfig.PortConfig
	gatewayConfig := vpnConfig.GatewayConfig
	if len(vpnConfig.ClientConfigList) == 0 {
		// Network instance creation must have failed.
		return nil
	}
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	if vpnConfig.VpnRole == AwsVpnClient {
		if err := ipTablesAwsClientRulesReset(tunnelConfig.Name,
			gatewayConfig.IpAddr, tunnelConfig.Key); err != nil {
			return err
		}
	}
	if err := ipTablesCounterRulesReset(vpnConfig.PolicyBased,
		tunnelConfig.Name, portConfig.IfName); err != nil {
		return err
	}
	return nil
}

func ipTablesAwsClientRulesSet(tunnelName string,
	gatewayIpAddr string, tunnelKey string) error {

	ipTableName := "mangle"
	// set the iptable rules
	// forward rule
	if err := iptables.IptableCmd("-t", ipTableName,
		"-I", "FORWARD", "1", "-o", tunnelName,
		"-p", "tcp", "--tcp-flags", "SYN,RST",
		"SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"); err != nil {
		log.Errorf("%s for %s, %s forward rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// input rule
	if err := iptables.IptableCmd("-t", ipTableName,
		"-I", "INPUT", "1", "-p", "esp", "-s", gatewayIpAddr,
		"-j", "MARK", "--set-xmark", tunnelKey); err != nil {
		log.Errorf("%s for %s, %s input rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	log.Infof("ipTablesAwsClientRuleSet(%s) OK\n", tunnelName)
	return nil
}

func ipTablesAwsClientRulesReset(tunnelName string,
	gatewayIpAddr string, tunnelKey string) error {
	ipTableName := "mangle"
	// delete the iptable rules
	// forward rule
	if err := iptables.IptableCmd("-t", ipTableName, "-D", "FORWARD", "-o", tunnelName,
		"-p", "tcp", "--tcp-flags", "SYN,RST",
		"SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"); err != nil {
		log.Errorf("%s for %s, %s forward rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// input rule
	if err := iptables.IptableCmd("-t", ipTableName, "-D", "INPUT",
		"-p", "esp", "-s", gatewayIpAddr,
		"-j", "MARK", "--set-xmark", tunnelKey); err != nil {
		log.Errorf("%s for %s, %s input rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}
	log.Infof("ipTablesAwsClientRulesReset(%s) OK\n", tunnelName)
	return nil
}

func ipTablesCounterRulesSet(policyBased bool,
	tunnelName string, portName string) error {
	for _, acl := range vpnCounterAcls {
		acl.intf = portName
		if err := iptableCounterRuleOp(acl, true); err != nil {
			return err
		}
	}
	log.Infof("ipTablesCounterRuleSet(%s) OK\n", tunnelName)
	return nil
}

func ipTablesCounterRulesReset(policyBased bool,
	tunnelName string, portName string) error {
	for _, acl := range vpnCounterAcls {
		acl.intf = portName
		if err := iptableCounterRuleOp(acl, false); err != nil {
			return err
		}
	}
	log.Infof("ipTablesCounterRulesReset(%s) OK\n", tunnelName)
	return nil
}

func iptableCounterRuleOp(acl vpnAclRule, set bool) error {
	if acl.chain == "" || acl.proto == "" {
		err := errors.New("Invalid counter acl")
		log.Errorf("%s for %s, %s rule create\n",
			err.Error(), "iptables", acl.chain)
		return err
	}
	var cmd []string
	if acl.table != "" {
		cmd = append(cmd, "-t")
		cmd = append(cmd, acl.table)
	}
	if set {
		cmd = append(cmd, "-I")
		//cmd = append(cmd, "1")
	} else {
		cmd = append(cmd, "-D")
	}
	cmd = append(cmd, acl.chain)
	cmd = append(cmd, "-p")
	cmd = append(cmd, acl.proto)
	if acl.sport != "" {
		cmd = append(cmd, "--sport")
		cmd = append(cmd, acl.sport)
	}
	if acl.dport != "" {
		cmd = append(cmd, "--dport")
		cmd = append(cmd, acl.dport)
	}
	if acl.intf != "" {
		switch acl.chain {
		case "INPUT":
			cmd = append(cmd, "-i")
		case "OUTPUT":
			cmd = append(cmd, "-o")
		case "FORWARD":
			if acl.dir == "in" {
				cmd = append(cmd, "-i")
			} else if acl.dir == "out" {
				cmd = append(cmd, "-o")
			} else {
				err := errors.New("direction not set")
				log.Errorf("%s for %s, %s rule create\n",
					err.Error(), "iptables", acl.chain)
				return err
			}
		}
		cmd = append(cmd, acl.intf)
	}

	cmd = append(cmd, "-j")
	cmd = append(cmd, acl.target)

	if err := iptables.IptableCmd(cmd...); err != nil {
		log.Errorf("%s for %s, %s rule create\n",
			err.Error(), "iptables", acl.chain)
		return err
	}
	return nil
}

func iptableCounterRuleStat(acl vpnAclRule) (types.PktStats, error) {
	var stat types.PktStats
	if acl.chain == "" || acl.proto == "" {
		err := errors.New("Invalid counter acl")
		log.Errorf("%s for %s, %s rule counter\n",
			err.Error(), "iptables", acl.chain)
		return stat, err
	}
	var cmd []string
	if acl.table != "" {
		cmd = append(cmd, "--t")
		cmd = append(cmd, acl.table)
	}
	cmd = append(cmd, "-S")
	cmd = append(cmd, acl.chain)
	cmd = append(cmd, "-v")

	out, err := iptables.IptableCmdOut(false, cmd...)
	if err != nil {
		log.Errorf("%s for %s, %s rule counter\n",
			err.Error(), "iptables", acl.chain)
		return stat, err
	}
	outLines := strings.Split(out, "\n")
	for _, outLine := range outLines {
		if !strings.Contains(outLine, acl.proto) ||
			(acl.intf != "" && !strings.Contains(outLine, acl.intf)) ||
			(acl.sport != "" && !strings.Contains(outLine, "--sport "+acl.sport+" ")) ||
			(acl.dport != "" && !strings.Contains(outLine, "--dport "+acl.dport+" ")) {
			continue
		}
		outArr := strings.Fields(outLine)
		for idx, field := range outArr {
			if field == "-c" {
				if pkts, err := strconv.ParseUint(outArr[idx+1], 10, 64); err == nil {
					stat.Pkts = pkts
				}
				if bytes, err := strconv.ParseUint(outArr[idx+2], 10, 64); err == nil {
					stat.Bytes = bytes
				}
				return stat, nil
			}
		}
	}
	return stat, nil
}

// check iptables rule status
func ipTablesRuleCheck(vpnConfig types.VpnConfig) error {
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
	case AzureVpnClient:
		log.Infof("ipTable(%s) check OK\n", tunnelConfig.Name)
	case OnPremVpnClient:
		log.Infof("ipTable(%s) check OK\n", tunnelConfig.Name)
	case OnPremVpnServer:
		log.Infof("ipTable(%s) check OK\n", tunnelConfig.Name)
	}
	return nil
}

func ipTablesChainMatch(tableName string, chainName string,
	matchString string) error {

	// XXX as long as zedagent also calls iptables we need to
	// wait for the lock with -w 5
	cmd := exec.Command("iptables", "-w", "5", "-S", chainName)
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
func ipRouteCreate(vpnConfig types.VpnConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	gatewayConfig := vpnConfig.GatewayConfig

	// for client config setup, create server subnet block route
	if vpnConfig.IsClient {
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
	} else {
		// for server config, create all client subnet block routes
		for _, clientConfig := range vpnConfig.ClientConfigList {
			tunnelConfig := vpnConfig.ClientConfigList[0].TunnelConfig
			cmd := exec.Command("ip", "route", "add", clientConfig.SubnetBlock,
				"dev", tunnelConfig.Name, "metric", tunnelConfig.Metric)
			if _, err := cmd.Output(); err != nil {
				log.Errorf("%s for %s %s add\n",
					err.Error(), "iproute", clientConfig.SubnetBlock)
				return err
			}
			log.Infof("ipRoute(%s) %s add OK\n",
				tunnelConfig.Name, clientConfig.SubnetBlock)
		}
	}
	return nil
}

func ipRouteDelete(vpnConfig types.VpnConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	gatewayConfig := vpnConfig.GatewayConfig

	// for client config setup, create server subnet route
	if vpnConfig.IsClient {
		if len(vpnConfig.ClientConfigList) > 0 {
			tunnelConfig := vpnConfig.ClientConfigList[0].TunnelConfig
			cmd := exec.Command("ip", "route", "delete", gatewayConfig.SubnetBlock)
			if _, err := cmd.Output(); err != nil {
				log.Errorf("%s for %s %s add\n",
					err.Error(), "iproute", gatewayConfig.SubnetBlock)
				return err
			}
			log.Infof("ipRoute(%s) %s delete OK\n", tunnelConfig.Name,
				gatewayConfig.SubnetBlock)
		}
	} else {
		// for server config, remove all client routes
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
	}
	return nil
}

func ipRouteCheck(vpnConfig types.VpnConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	gatewayConfig := vpnConfig.GatewayConfig
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	// for client configs, check server subnet block route
	if vpnConfig.IsClient {
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
	} else {
		// for server config, check all client subnet block routes
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
	}
	return nil
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

func ipLinkTunnelCreate(vpnConfig types.VpnConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	gatewayConfig := vpnConfig.GatewayConfig
	clientConfig := vpnConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig
	portConfig := vpnConfig.PortConfig

	log.Infof("%s: %s %s %s\n", tunnelConfig.Name, "ip link add",
		portConfig.IpAddr, gatewayConfig.IpAddr)
	if vpnConfig.IsClient {
		cmd := exec.Command("ip", "link", "add",
			tunnelConfig.Name, "type", "vti", "local", portConfig.IpAddr,
			"remote", gatewayConfig.IpAddr, "key", tunnelConfig.Key)
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s %s add on %s %s\n", err.Error(), "ip link",
				tunnelConfig.Name, portConfig.IpAddr, gatewayConfig.IpAddr)
			return err
		}
	} else {
		// for server, create remote any
		cmd := exec.Command("ip", "link", "add",
			tunnelConfig.Name, "type", "vti", "local", portConfig.IpAddr,
			"remote", "0.0.0.0")
		if _, err := cmd.Output(); err != nil {
			log.Errorf("%s for %s %s add on %s %s\n", err.Error(), "ip link",
				tunnelConfig.Name, portConfig.IpAddr, gatewayConfig.IpAddr)
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
			log.Errorf("%s for ip addr add %s remote %s dev %s\n",
				err.Error(), tunnelConfig.LocalIpAddr,
				tunnelConfig.RemoteIpAddr, tunnelConfig.Name)
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

func ipLinkTunnelDelete(vpnConfig types.VpnConfig) error {

	if vpnConfig.PolicyBased {
		return nil
	}
	if len(vpnConfig.ClientConfigList) == 0 {
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

func ipSecConfigCreate(vpnConfig types.VpnConfig) error {

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

	case AzureVpnClient:
		clientConfig := clientConfigList[0]
		tunnelConfig := clientConfig.TunnelConfig
		writeStr = writeStr + ipSecTunHdrStr + tunnelConfig.Name
		writeStr = writeStr + azureIpSecLeftTunAttribSpecStr + clientConfig.SubnetBlock
		writeStr = writeStr + azureIpSecRightTunAttribSpecStr + gatewayConfig.IpAddr
		writeStr = writeStr + azureIpSecRightSubnetSpecStr
		writeStr = writeStr + gatewayConfig.SubnetBlock
		writeStr = writeStr + ipSecClientTunDpdSpecStr
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
		writeStr = writeStr + "\n"

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
			writeStr = writeStr + ipSecSvrTunRightAttribSpecStr + "\n"
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

func ipSecConfigDelete() error {
	writeStr := ipSecConfHdrStr
	filename := "/etc/ipsec.conf"
	return ipSecConfigFileWrite(filename, writeStr)
}

func ipSecSecretConfigCreate(vpnConfig types.VpnConfig) error {

	clientConfigList := vpnConfig.ClientConfigList
	gatewayConfig := vpnConfig.GatewayConfig

	writeStr := ipSecSecretHdrStr
	wildMatch := false
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
		secretStr := ""
		if vpnConfig.IsClient {
			secretStr = clientConfig.IpAddr + " " + gatewayConfig.IpAddr
		} else {
			secretStr = gatewayConfig.IpAddr + " " + clientConfig.IpAddr
		}
		secretStr = secretStr + " : PSK " + "\"" + clientConfig.PreSharedKey + "\""
		secretStr = secretStr + "\n"
		writeStr = writeStr + secretStr
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

func sysctlConfigCreate(vpnConfig types.VpnConfig) error {

	portConfig := vpnConfig.PortConfig
	log.Infof("%s: %s config\n", portConfig.IfName, "sysctl")

	writeStr := ""
	if vpnConfig.PolicyBased {
		writeStr = writeStr + "\n net.ipv4.conf." + portConfig.IfName + ".disable_xfrm=0"
		writeStr = writeStr + "\n net.ipv4.conf." + portConfig.IfName + ".disable_policy=0\n"
	} else {
		writeStr = writeStr + "\n net.ipv4.conf." + portConfig.IfName + ".disable_xfrm=1"
		writeStr = writeStr + "\n net.ipv4.conf." + portConfig.IfName + ".disable_policy=1\n"
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

func sysctlConfigReset(vpnConfig types.VpnConfig) error {
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
	if err := fileutils.WriteRename(filename, data); err != nil {
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

func checkIpSecStatusCmd(tunnelName string) error {
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
