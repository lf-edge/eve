// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// ipsec tunnel management routines

package zedrouter

import (
	"errors"
	"github.com/zededa/go-provision/pubsub"
	"log"
	"os/exec"
	"strings"
)

const (
	charonConfStr     = "# Options for charon IKE daemon\ncharon {\n install_routes = no\n}\n"
	ipSecSecretHdrStr = "# ipsec.secrets - IPSec secrets file\n"
	ipSecConfHdrStr   = "# ipsec.conf - default configuration\nconfig setup" +
		"\n\t uniqueids = no\n"
	ipSecTunHdrStr      = "\nconn "
	ipSecTunLeftSpecStr = "\n\tauto=start" + "\n\tleft=%defaultroute" +
		"\n\tleftid=0.0.0.0"
	ipSecTunRightSpecStr  = "\n\tright="
	ipSecTunSpecStr       = ipSecTunLeftSpecStr + ipSecTunRightSpecStr
	ipSecTunAttribSpecStr = "\n\ttype=tunnel" + "\n\tleftauth=psk" +
		"\n\trightauth=psk" +
		"\n\tkeyexchange=ikev1" +
		"\n\tike=aes128-sha1-modp1024" +
		"\n\tikelifetime=8h" +
		"\n\tesp=aes128-sha1-modp1024" +
		"\n\tlifetime=1h" +
		"\n\tkeyingtries=%forever" +
		"\n\tleftsubnet=0.0.0.0/0" +
		"\n\trightsubnet=0.0.0.0/0" +
		"\n\tdpddelay=10s" +
		"\n\tdpdtimeout=30s" +
		"\n\tdpdaction=restart" +
		"\n\tmark="
)

func ipSecServiceActivate(tunnelName string) error {
	cmd := exec.Command("ipsec", "start")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s start\n", err.Error(), "ipsec")
		return err
	}
	log.Printf("%s for %s start\n", "ipsec", tunnelName)
	return nil
}

func ipSecServiceInactivate(tunnelName string) error {
	cmd := exec.Command("ipsec", "stop")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s stop\n", err.Error(), "ipsec")
		return err
	}
	log.Printf("%s for %s stop\n", "ipsec", tunnelName)
	return nil
}

func ipSecServiceStatus() (string, error) {
	cmd := exec.Command("ipsec", "status")
	out, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s status\n", err.Error(), "ipsec")
		return "", err
	}
	log.Printf("%s for %s status\n", "ipsec", string(out))
	return string(out), nil
}

func ipSecTunnelStateCheck(tunnelName string) error {
	// check whether ipsec tunnel is up
	// if not, do ipsec restart
	if err := checkIpSecServiceStatusCmd(tunnelName); err != nil {
		return err
	}
	log.Printf("%s IpSec Tunnel State OK\n", tunnelName)
	return nil
}

func ipTablesRuleCreate(ipTableName string, tunnelName string,
	vpnGateway string, tunnelKey string) error {

	// setup the iptable rules
	// forward rule
	cmd := exec.Command("iptables", "-t", ipTableName,
		"-A", "FORWARD", "-o", tunnelName,
		"-p", "tcp", "--tcp-flags", "SYN,RST",
		"SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s forward rule\n",
			err.Error(), "iptables", ipTableName)
		return err
	}

	// input rule
	cmd = exec.Command("iptables", "-t", ipTableName,
		"-A", "INPUT", "-p", "esp", "-s", vpnGateway,
		"-j", "MARK", "--set-xmark", tunnelKey)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s input rule\n",
			err.Error(), "iptables", ipTableName)
		return err
	}
	log.Printf("%s: IpTable rule create OK\n", tunnelName)
	return nil
}

func ipTablesRulesDelete(ipTableName string, tunnelName string,
	vpnGateway string, tunnelKey string) error {

	// delete the iptable rules
	// forward rule
	cmd := exec.Command("iptables", "-t", ipTableName,
		"-D", "FORWARD", "-o", tunnelName,
		"-p", "tcp", "--tcp-flags", "SYN,RST",
		"SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s forward rule delete\n",
			err.Error(), "iptables", ipTableName)
		return err
	}

	// input rule
	cmd = exec.Command("iptables", "-t", ipTableName,
		"-D", "INPUT", "-p", "esp", "-s", vpnGateway,
		"-j", "MARK", "--set-xmark", tunnelKey)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s input rule delete\n",
			err.Error(), "iptables", ipTableName)
		return err
	}
	log.Printf("%s IpTable rule delete OK\n", tunnelName)
	return nil
}

// check iptables rule status
func ipTablesRuleCheck(tableName string, tunnelName string,
	vpnGateway string) error {
	if err := ipTablesChainMatch(tableName,
		"FORWARD", tunnelName); err != nil {
		return err
	}
	if err := ipTablesChainMatch(tableName,
		"INPUT", vpnGateway+"/32"); err != nil {
		return err
	}
	log.Printf("%s IpTable rule state OK\n", tunnelName)
	return nil
}

func ipTablesChainMatch(tableName string, chainName string,
	matchString string) error {
	cmd := exec.Command("iptables",
		"-t", tableName, "-S", chainName)
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
func ipRouteCreate(tunnelName string, subNet string, metric string) error {
	cmd := exec.Command("ip", "route", "add", subNet,
		"dev", tunnelName, "metric", metric)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s add\n",
			err.Error(), "iproute", subNet)
		return err
	}
	log.Printf("%s: route create OK\n", tunnelName)
	return nil
}

func ipRouteDelete(tunnelName string, subNet string) error {
	cmd := exec.Command("ip", "route", "delete", subNet)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s add\n",
			err.Error(), "iproute", subNet)
		return err
	}
	log.Printf("%s: route delete OK\n", tunnelName)
	return nil
}

func ipRouteCheck(tunnelName string, subNet string) error {
	cmd := exec.Command("ip", "route", "get", subNet)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s %s check, no route\n",
			err.Error(), "iproute", subNet)
		return err
	}

	if err := ipRouteMatch(string(out), tunnelName); err != nil {
		log.Printf("%s route OK\n", tunnelName)
		return err
	}
	log.Printf("%s: route check OK\n", tunnelName)
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

func ipLinkTunnelCreate(tunnelName string, upLinkIpAddr string,
	vpnGateway string, localIpAddr string, remoteIpAddr string,
	key string, mtu string) error {

	log.Printf("%s: %s %s %s\n", tunnelName, "ip link add",
		upLinkIpAddr, vpnGateway)
	cmd := exec.Command("ip", "link", "add",
		tunnelName, "type", "vti", "local", upLinkIpAddr,
		"remote", vpnGateway, "key", key)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s add\n",
			err.Error(), "ip link", tunnelName, upLinkIpAddr, vpnGateway)
		return err
	}

	log.Printf("%s: %s %s %s\n", tunnelName, "ip link addr",
		localIpAddr, remoteIpAddr)
	cmd = exec.Command("ip", "addr", "add",
		localIpAddr, "remote", remoteIpAddr,
		"dev", tunnelName)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s addr add\n",
			err.Error(), "ip link", tunnelName, localIpAddr, remoteIpAddr)
		return err
	}
	log.Printf("%s: %s %s\n", tunnelName, "ip link mtu", mtu)
	cmd = exec.Command("ip", "link", "set",
		tunnelName, "up", "mtu", mtu)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s set mtu up\n",
			err.Error(), "ip link mtu", tunnelName)
		return err
	}

	log.Printf("%s: %s setup OK\n", tunnelName, "ip link")
	return nil
}

func ipLinkTunnelDelete(tunnelName string) error {
	cmd := exec.Command("ip", "link", "delete", tunnelName)
	_, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s %s delete\n",
			err.Error(), "ip link", tunnelName)
		return err
	}
	log.Printf("%s: %s delete OK\n", tunnelName, "ip link")
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
	log.Printf("%s: %s check State OK\n", tunnelName, "ip link")
	return nil
}

func ipSecServiceConfigCreate(tunnelName string,
	vpnGateway string, tunnelKey string) error {
	writeStr := ipSecConfHdrStr
	writeStr = writeStr + ipSecTunHdrStr + tunnelName
	writeStr = writeStr + ipSecTunSpecStr + vpnGateway
	writeStr = writeStr + ipSecTunAttribSpecStr + tunnelKey
	writeStr = writeStr + "\n"
	filename := "/etc/ipsec.conf"
	if err := ipSecConfigFileWrite(filename, writeStr); err != nil {
		return err
	}
	cmd := exec.Command("chmod", "600", filename)
	_, err := cmd.Output()
	if err != nil {
		log.Printf("%s for %s %s\n",
			err.Error(), "chmod", filename)
		return err
	}
	return nil
}

func ipSecServiceConfigDelete() error {
	writeStr := ipSecConfHdrStr
	filename := "/etc/ipsec.conf"
	return ipSecConfigFileWrite(filename, writeStr)
}

func ipSecSecretConfigCreate(vpnGateway string,
	preSharedKey string) error {
	writeStr := ipSecSecretHdrStr
	writeStr = writeStr + "0.0.0.0 "
	writeStr = writeStr + vpnGateway + " "
	writeStr = writeStr + " : PSK " + "\""
	writeStr = writeStr + preSharedKey + "\""
	writeStr = writeStr + "\n"
	filename := "/etc/ipsec.secrets"
	return ipSecConfigFileWrite(filename, writeStr)
}

func ipSecSecretConfigDelete() error {
	writeStr := ipSecSecretHdrStr
	filename := "/etc/ipsec.secrets"
	return ipSecConfigFileWrite(filename, writeStr)
}

func charonConfigCreate() error {
	filename := "/etc/strongswan.d/charon.conf"
	return ipSecConfigFileWrite(filename, charonConfStr)
}

func sysctlConfigCreate(upLinkName string, tunnelName string) error {
	log.Printf("%s: %s config %s\n", tunnelName, "sysctl", upLinkName)

	// XXX ip_forward is already set by zedrouter.
	writeStr := "\n net.ipv4.ip_forward = 1"
	writeStr = writeStr + "\n net.ipv4.conf." + tunnelName + ".rp_filter=2"
	writeStr = writeStr + "\n net.ipv4.conf." + tunnelName + ".disable_policy=1"
	writeStr = writeStr + "\n net.ipv4.conf." + upLinkName + ".disable_xfrm=1"
	writeStr = writeStr + "\n net.ipv4.conf." + upLinkName + ".disable_policy=1\n"
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
	return errors.New("not configured")
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
