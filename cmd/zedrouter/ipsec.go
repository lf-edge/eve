// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// ipsec tunnel management routines

package zedrouter

import (
	"errors"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"log"
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

	ipSecClientTunAttribSpecStr = "\n\trightid=%any" +
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

	ipSecSvrTunHdrSpecStr = "\nconfig setup" + "\n" +
		"\nconn %default" +
		"\n\tikelifetime=60m" +
		"\n\tkeylife=20m" +
		"\n\trekeymargin=3m" +
		"\n\tkeyingtries=1" +
		"\n\tkeyexchange=ikev1" +
		"\n\tauthby=secret" +
		"\n"

	ipSecSvrTunLeftHdrSpecStr = "\nconn roadWarrior" +
		"\n\tleftid=%any" + "\n\tleft="

	ipSecSvrTunLeftAttribSpecStr = "\n\tleftfirewall=yes" +
		"\n\tleftsubnet=0.0.0.0/0" +
		"\n"

	ipSecSvrTunRightHdrSpecStr = "\nconn roadWarrior-"
	ipSecSvrTunRightSpecStr    = "\n\tauto=add" +
		"\n\talso=roadWarrior" +
		"\n\tright="
	ipSecSvrTunRightAttribSpecStr = "\n\tauto=add" +
		"\n\trightsubnet=0.0.0.0/0" +
		"\n"
)

func ipSecServiceActivate(vpnLocalConfig types.VpnServiceLocalConfig) error {
	tunnelConfig := vpnLocalConfig.ClientConfigList[0].TunnelConfig
	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		cmd := exec.Command("ipsec", "start")
		if _, err := cmd.Output(); err != nil {
			log.Printf("%s for %s start\n", err.Error(), "ipsec")
			return err
		}
	case "onPremStrongSwanVpnClient":
		cmd := exec.Command("ipsec", "start")
		if _, err := cmd.Output(); err != nil {
			log.Printf("%s for %s start\n", err.Error(), "ipsec")
			return err
		}
	case "onPremStrongSwanVpnServer":
		cmd := exec.Command("ipsec", "start")
		if _, err := cmd.Output(); err != nil {
			log.Printf("%s for %s start\n", err.Error(), "ipsec")
			return err
		}
	}
	log.Printf("ipSecService(%s) start OK\n", tunnelConfig.Name)
	return nil
}

func ipSecServiceInactivate(vpnLocalConfig types.VpnServiceLocalConfig) error {
	tunnelConfig := vpnLocalConfig.ClientConfigList[0].TunnelConfig
	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		cmd := exec.Command("ipsec", "stop")
		if _, err := cmd.Output(); err != nil {
			log.Printf("%s for %s stop\n", err.Error(), "ipsec")
			return err
		}
	case "onPremStrongSwanVpnClient":
		cmd := exec.Command("ipsec", "stop")
		if _, err := cmd.Output(); err != nil {
			log.Printf("%s for %s stop\n", err.Error(), "ipsec")
			return err
		}
	case "onPremStrongSwanVpnServer":
		cmd := exec.Command("ipsec", "stop")
		if _, err := cmd.Output(); err != nil {
			log.Printf("%s for %s stop\n", err.Error(), "ipsec")
			return err
		}
	}
	log.Printf("ipSecService(%s) stop OK\n", tunnelConfig.Name)
	return nil
}

func ipSecServiceStatus() (string, error) {
	cmd := exec.Command("ipsec", "status")
	out, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s status\n", err.Error(), "ipsec")
		return "", err
	}
	log.Printf("ipSecService() status %s\n", string(out))
	return string(out), nil
}

func ipSecTunnelStateCheck(vpnRole string, tunnelName string) error {
	// check whether ipsec tunnel is up
	// if not, do ipsec restart
	if err := checkIpSecServiceStatusCmd(tunnelName); err != nil {
		return err
	}
	log.Printf("%s IpSec Tunnel State OK\n", tunnelName)
	return nil
}

func ipTablesRuleCreate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		return ipTablesAwsClientRulesSet(tunnelConfig.Name, gatewayConfig.IpAddr,
			tunnelConfig.Key)

	case "onPremStrongSwanVpnClient":
		return ipTablesSSClientRulesSet(tunnelConfig.Name, gatewayConfig.IpAddr)

	case "onPremStrongSwanVpnServer":
		return ipTablesSSServerRulesSet(tunnelConfig.Name, gatewayConfig.IpAddr)
	}

	return nil
}

func ipTablesRulesDelete(vpnLocalConfig types.VpnServiceLocalConfig) error {
	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		return ipTablesAwsClientRulesReset(tunnelConfig.Name, gatewayConfig.IpAddr,
			tunnelConfig.Key)

	case "onPremStrongSwanVpnClient":
		return ipTablesSSClientRulesReset(tunnelConfig.Name, gatewayConfig.IpAddr)

	case "onPremStrongSwanVpnServer":
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
		log.Printf("%s for %s, %s forward rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// input rule
	cmd = exec.Command("iptables", "-t", ipTableName,
		"-I", "INPUT", "1", "-p", "esp", "-s", gatewayIpAddr,
		"-j", "MARK", "--set-xmark", tunnelKey)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s input rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}
	log.Printf("ipTablesRuleSet(%s) succesful\n", tunnelName)
	return nil
}

func ipTablesSSClientRulesSet(tunnelName string, gatewayIpAddr string) error {
	// set the iptable rules
	// forward rule
	cmd := exec.Command("iptables",
		"-I", "FORWARD", "1", "--match", "policy",
		"--pol", "ipsec", "--dir", "out", "--proto", "esp",
		"-s", "0.0.0.0/0", "-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s forward rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// input rule
	cmd = exec.Command("iptables",
		"-I", "INPUT", "1", "-p", "udp", "--dport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s input rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// output rule
	cmd = exec.Command("iptables",
		"-I", "OUTPUT", "1", "-p", "udp", "--sport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s output rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}
	log.Printf("ipTablesRuleSet(%s) succesful\n", tunnelName)
	return nil
}

func ipTablesSSServerRulesSet(tunnelName string, gatewayIpAddr string) error {

	// setup the iptable rules
	// forward rule
	cmd := exec.Command("iptables",
		"-I", "FORWARD", "1", "--match", "policy",
		"--pol", "ipsec", "--dir", "out", "--proto", "esp",
		"-s", "0.0.0.0/0", "-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s forward rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// input rule
	cmd = exec.Command("iptables",
		"-I", "INPUT", "1", "-p", "udp", "--dport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s input rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// output rule
	cmd = exec.Command("iptables",
		"-I", "OUTPUT", "1", "-p", "udp", "--sport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s output rule create\n",
			err.Error(), "iptables", tunnelName)
		return err
	}
	log.Printf("ipTablesRuleSet(%s) successful\n", tunnelName)
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
		log.Printf("%s for %s, %s forward rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// input rule
	cmd = exec.Command("iptables", "-t", ipTableName,
		"-D", "INPUT", "-p", "esp", "-s", gatewayIpAddr,
		"-j", "MARK", "--set-xmark", tunnelKey)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s input rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}
	log.Printf("ipTablesRuleReset(%s) successful\n", tunnelName)
	return nil
}

func ipTablesSSClientRulesReset(tunnelName string, vpnGateway string) error {

	// delete the iptable rules
	// forward rule
	cmd := exec.Command("iptables",
		"-D", "FORWARD", "--match", "policy",
		"--pol", "ipsec", "--dir", "out", "--proto", "esp",
		"-s", "0.0.0.0/0", "-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s forward rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// input rule
	cmd = exec.Command("iptables",
		"-D", "INPUT", "-p", "udp", "--dport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s input rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// output rule
	cmd = exec.Command("iptables",
		"-D", "OUTPUT", "-p", "udp", "--sport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s output rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	log.Printf("ipTablesRuleReset(%s) successful\n", tunnelName)
	return nil
}

func ipTablesSSServerRulesReset(tunnelName string, gatewayIpAddr string) error {

	// delete the iptable rules
	// forward rule
	cmd := exec.Command("iptables",
		"-D", "FORWARD", "--match", "policy",
		"--pol", "ipsec", "--dir", "out", "--proto", "esp",
		"-s", "0.0.0.0/0", "-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s forward rule delete\n",
			err.Error(), "iptables")
		return err
	}
	// input rule
	cmd = exec.Command("iptables",
		"-D", "INPUT", "-p", "udp", "--dport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s input rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	// output rule
	cmd = exec.Command("iptables",
		"-D", "OUTPUT", "-p", "udp", "--sport", "500",
		"-j", "ACCEPT")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s, %s output rule delete\n",
			err.Error(), "iptables", tunnelName)
		return err
	}

	log.Printf("ipTablesRule(%s) reset OK\n", tunnelName)
	return nil
}

// check iptables rule status
func ipTablesRuleCheck(vpnLocalConfig types.VpnServiceLocalConfig) error {
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig
	gatewayConfig := vpnLocalConfig.GatewayConfig

	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		tableName := "mangle"
		if err := ipTablesChainMatch(tableName,
			"FORWARD", tunnelConfig.Name); err != nil {
			return err
		}
		if err := ipTablesChainMatch(tableName,
			"INPUT", gatewayConfig.IpAddr+"/32"); err != nil {
			return err
		}
		log.Printf("pTable(%s) check OK\n", tunnelConfig.Name)
	case "onPremStrongSwanVpnClient":
		log.Printf("ipTable(%s) check OK\n", tunnelConfig.Name)
	case "onPremStrongSwanVpnServer":
		log.Printf("ipTable(%s) check OK\n", tunnelConfig.Name)
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
		log.Printf("%s for %s %s %s\n",
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
func ipRouteCreate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	if vpnLocalConfig.VpnRole != "awsStrongSwanVpnClient" {
		return errors.New("invalid operation")
	}

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	cmd := exec.Command("ip", "route", "add", gatewayConfig.SubnetBlock,
		"dev", tunnelConfig.Name, "metric", tunnelConfig.Metric)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s add\n",
			err.Error(), "iproute", gatewayConfig.SubnetBlock)
		return err
	}
	log.Printf("ipRoute(%s) add OK\n", tunnelConfig.Name)
	return nil
}

func ipRouteDelete(vpnLocalConfig types.VpnServiceLocalConfig) error {

	if vpnLocalConfig.VpnRole != "awsStrongSwanVpnClient" {
		return errors.New("invalid operation")
	}
	gatewayConfig := vpnLocalConfig.GatewayConfig
	tunnelConfig := vpnLocalConfig.ClientConfigList[0].TunnelConfig

	cmd := exec.Command("ip", "route", "delete", gatewayConfig.SubnetBlock)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s add\n",
			err.Error(), "iproute", gatewayConfig.SubnetBlock)
		return err
	}
	log.Printf("ipRoute(%s) delete OK\n", tunnelConfig.Name)
	return nil
}

func ipRouteCheck(vpnLocalConfig types.VpnServiceLocalConfig) error {

	if vpnLocalConfig.VpnRole != "awsStrongSwanVpnClient" {
		return errors.New("invalid operation")
	}

	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	cmd := exec.Command("ip", "route", "get", gatewayConfig.SubnetBlock)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s %s check, no route\n",
			err.Error(), "iproute", gatewayConfig.SubnetBlock)
		return err
	}

	if err := ipRouteMatch(string(out), tunnelConfig.Name); err != nil {
		log.Printf("%s for ipRoute(%s) check fail\n", err, tunnelConfig.Name)
		return err
	}
	log.Printf("ipRoute(%s) check OK\n", tunnelConfig.Name)
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

func ipLinkTunnelCreate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	if vpnLocalConfig.VpnRole != "awsStrongSwanVpnClient" {
		return errors.New("invalid operation")
	}
	gatewayConfig := vpnLocalConfig.GatewayConfig
	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig
	upLinkConfig := vpnLocalConfig.UpLinkConfig

	log.Printf("%s: %s %s %s\n", tunnelConfig.Name, "ip link add",
		upLinkConfig.IpAddr, gatewayConfig.IpAddr)
	cmd := exec.Command("ip", "link", "add",
		tunnelConfig.Name, "type", "vti", "local", upLinkConfig.IpAddr,
		"remote", gatewayConfig.IpAddr, "key", tunnelConfig.Key)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s add on %s\n", err.Error(), "ip link",
			tunnelConfig.Name, upLinkConfig.IpAddr, gatewayConfig.IpAddr)
		return err
	}

	log.Printf("%s: %s %s %s\n", tunnelConfig.Name, "ip link addr",
		tunnelConfig.LocalIpAddr, tunnelConfig.RemoteIpAddr)
	cmd = exec.Command("ip", "addr", "add",
		tunnelConfig.LocalIpAddr, "remote", tunnelConfig.RemoteIpAddr,
		"dev", tunnelConfig.Name)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s addr add\n",
			err.Error(), "ip link", tunnelConfig.Name, tunnelConfig.LocalIpAddr,
			tunnelConfig.RemoteIpAddr)
		return err
	}
	log.Printf("%s: %s %s\n", tunnelConfig.Name, "ip link mtu", tunnelConfig.Mtu)
	cmd = exec.Command("ip", "link", "set",
		tunnelConfig.Name, "up", "mtu", tunnelConfig.Mtu)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s set mtu up\n",
			err.Error(), "ip link mtu", tunnelConfig.Name)
		return err
	}

	log.Printf("ipLink(%s) add OK\n", tunnelConfig.Name)
	return nil
}

func ipLinkTunnelDelete(vpnLocalConfig types.VpnServiceLocalConfig) error {

	if vpnLocalConfig.VpnRole != "awsStrongSwanVpnClient" {
		return errors.New("invalid operation")
	}

	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig

	cmd := exec.Command("ip", "link", "delete", tunnelConfig.Name)
	_, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s %s delete\n",
			err.Error(), "ip link", tunnelConfig.Name)
		return err
	}
	log.Printf("ipLink(%s) delete OK\n", tunnelConfig.Name)
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
	log.Printf("ipLink(%s) check OK\n", tunnelName)
	return nil
}

func ipSecServiceConfigCreate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	clientConfigList := vpnLocalConfig.ClientConfigList
	gatewayConfig := vpnLocalConfig.GatewayConfig

	writeStr := ipSecConfHdrStr
	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		// only one client
		tunnelConfig := clientConfigList[0].TunnelConfig
		writeStr = writeStr + ipSecTunHdrStr + tunnelConfig.Name
		writeStr = writeStr + ipSecTunSpecStr + gatewayConfig.IpAddr
		writeStr = writeStr + awsIpSecTunAttribSpecStr + tunnelConfig.Key
		writeStr = writeStr + "\n"

	case "onPremStrongSwanVpnClient":
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

	case "onPremStrongSwanVpnServer":
		// one or more clients
		writeStr = writeStr + ipSecSvrTunHdrSpecStr
		writeStr = writeStr + ipSecSvrTunLeftHdrSpecStr + gatewayConfig.IpAddr
		writeStr = writeStr + ipSecSvrTunLeftAttribSpecStr
		for _, clientConfig := range clientConfigList {
			tunnelConfig := clientConfig.TunnelConfig
			writeStr = writeStr + ipSecSvrTunRightHdrSpecStr + tunnelConfig.Name
			writeStr = writeStr + ipSecSvrTunRightSpecStr + clientConfig.IpAddr
			writeStr = writeStr + ipSecSvrTunRightAttribSpecStr
		}
	}
	writeStr = writeStr + "\n"
	filename := "/etc/ipsec.conf"
	if err := ipSecConfigFileWrite(filename, writeStr); err != nil {
		return err
	}
	cmd := exec.Command("chmod", "600", filename)
	_, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s %s\n", err.Error(), "chmod", filename)
		return err
	}
	log.Printf("ipSecConfigWrite(%s) OK\n", gatewayConfig.IpAddr)
	return nil
}

func ipSecServiceConfigDelete() error {
	writeStr := ipSecConfHdrStr
	filename := "/etc/ipsec.conf"
	return ipSecConfigFileWrite(filename, writeStr)
}

func ipSecSecretConfigCreate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	clientConfigList := vpnLocalConfig.ClientConfigList
	gatewayConfig := vpnLocalConfig.GatewayConfig

	writeStr := ipSecSecretHdrStr
	switch vpnLocalConfig.VpnRole {
	case "awsStrongSwanVpnClient":
		// always one client
		for _, clientConfig := range clientConfigList {
			writeStr = writeStr + clientConfig.IpAddr + " "
			writeStr = writeStr + gatewayConfig.IpAddr
			writeStr = writeStr + " : PSK " + clientConfig.PreSharedKey
			writeStr = writeStr + "\n"
		}

	case "onPremStrongSwanVpnClient":
		// always one client
		for _, clientConfig := range clientConfigList {
			writeStr = writeStr + clientConfig.IpAddr + " "
			writeStr = writeStr + gatewayConfig.IpAddr
			writeStr = writeStr + " : PSK " + clientConfig.PreSharedKey
			writeStr = writeStr + "\n"
		}

	case "onPremStrongSwanVpnServer":
		// one or more client(s)
		for _, clientConfig := range clientConfigList {
			writeStr = writeStr + gatewayConfig.IpAddr + " "
			writeStr = writeStr + clientConfig.IpAddr
			writeStr = writeStr + " : PSK " + clientConfig.PreSharedKey
			writeStr = writeStr + "\n"
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
		log.Printf("%s for %s %s\n", err.Error(), "chmod", filename)
		return err
	}
	log.Printf("ipSecSecretConfigWrite(%s) OK\n", gatewayConfig.IpAddr)
	return nil
}

func ipSecSecretConfigDelete() error {
	writeStr := ipSecSecretHdrStr
	filename := "/etc/ipsec.secrets"
	return ipSecConfigFileWrite(filename, writeStr)
}

func charonNoRouteConfigCreate() error {
	filename := "/etc/strongswan.d/charon.conf"
	return ipSecConfigFileWrite(filename, charonNoRouteConfStr)
}

func charonRouteConfigCreate() error {
	filename := "/etc/strongswan.d/charon.conf"
	return ipSecConfigFileWrite(filename, charonRouteConfStr)
}

func charonConfigReset() error {
	filename := "/etc/strongswan.d/charon.conf"
	return ipSecConfigFileWrite(filename, charonConfStr)
}

func sysctlConfigCreate(vpnLocalConfig types.VpnServiceLocalConfig) error {

	clientConfig := vpnLocalConfig.ClientConfigList[0]
	tunnelConfig := clientConfig.TunnelConfig
	upLinkConfig := vpnLocalConfig.UpLinkConfig
	log.Printf("%s: %s config %s\n", tunnelConfig.Name, "sysctl", upLinkConfig.Name)

	// XXX ip_forward is already set by zedrouter.
	writeStr := "\n net.ipv4.ip_forward = 1"
	if vpnLocalConfig.VpnRole == "awsStrongSwanVpnClient" {
		writeStr = writeStr + "\n net.ipv4.conf." + tunnelConfig.Name + ".rp_filter=2"
		writeStr = writeStr + "\n net.ipv4.conf." + tunnelConfig.Name + ".disable_policy=1"
	}
	writeStr = writeStr + "\n net.ipv4.conf." + upLinkConfig.Name + ".disable_xfrm=1"
	writeStr = writeStr + "\n net.ipv4.conf." + upLinkConfig.Name + ".disable_policy=1\n"
	filename := "/etc/sysctl.conf"
	return ipSecConfigFileWrite(filename, writeStr)
}

func sysctlConfigSet() error {
	cmd := exec.Command("sysctl", "-p")
	_, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s set \n", err.Error(), "sysctl")
		return err
	}
	log.Printf("%s: ConfigSet OK\n", "sysctl")
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
		log.Printf("%s for %s %s status\n",
			err.Error(), "ifconfig", intfName)
		return err
	}
	return nil
}

func checkIntfStateCmd(intfName string) error {
	cmd := exec.Command("ifconfig", intfName)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s %s status\n",
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
		log.Printf("%s for %s %s status\n",
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
		log.Printf("%s for %s %s\n",
			err.Error(), "ifup", tunnelName)
		return err
	}
	return nil
}
