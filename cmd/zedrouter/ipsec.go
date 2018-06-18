// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// ipsec tunnel management routines

package zedrouter

import (
	"github.com/zededa/go-provision/pubsub"
	"log"
	"os/exec"
)

const (
	charonConfStr = "# Options for charon IKE daemon\ncharon {\n install_routes = no\n}\n"
	ipSecSecretHdrStr = "# ipsec.secrets - IPSec secrets file\n"
	ipSecConfHdrStr = "# ipsec.conf - default configuration\nconfig setup" +
	"\n\t uniqueids = no\n"
	ipSecTunHdrStr =  "\nconn "
	ipSecTunLeftSpecStr = "\n\tauto=start" + "\n\tleft=%defaultroute" +
					"\n\tleftid=0.0.0.0"
	ipSecTunRightSpecStr = "\n\tright="
	ipSecTunSpecStr = ipSecTunLeftSpecStr + ipSecTunRightSpecStr
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

func ipSecServiceActivate()  error {
	cmd := exec.Command("ipsec", "start")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s start\n", err.Error(), "ipsec")
		return err
	}
	return nil
}

func ipSecServiceInactivate()  error {
	cmd := exec.Command("ipsec", "stop")
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s stop\n", err.Error(), "ipsec")
		return err
	}
	return nil
}

func ipSecServiceStatus()  (string, error) {
	cmd := exec.Command("ipsec", "status")
	out, err := cmd.Output()
	if  err != nil {
		log.Printf("%s for %s status\n", err.Error(), "ipsec")
		return "", err
	}
	return string(out), nil
}

func ipTablesRuleCreate(ipTableName string,
				ipSecTunnelName string, vpnGateway string,
				tunnelKey string) error {

	// setup the iptable rules
	// forward rule
	cmd := exec.Command("iptables", "-t", ipTableName,
			"-A","FORWARD", "-o", ipSecTunnelName,
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
	return nil
}

func ipTablesRulesDelete(ipTableName string,
		ipSecTunnelName string, vpnGateway string,
		 tunnelKey string) error {

	// setup the iptable rules
	// forward rule
	cmd := exec.Command("iptables", "-t", ipTableName,
			"-D","FORWARD", "-o", ipSecTunnelName,
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
	return nil
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
	return nil
}

func ipRouteDelete(tunnelName string, subNet string) error {
	cmd := exec.Command("ip", "route", "delete", subNet)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s add\n",
			err.Error(), "iproute", subNet)
		return err
	}
	return nil
}

func ipLinkTunnelCreate(tunnelName string,
				upLinkIpAddr string, awsVpnGateway string,
				tunnelLocalIpAddr string, tunnelRemoteIpAddr string,
				tunnelKey string, tunnelMtu string) error {

	cmd := exec.Command("ip", "link", "add",
				tunnelName, "type", "vti", "local", upLinkIpAddr,
				"remote", awsVpnGateway, "key", tunnelKey)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s add\n",
			err.Error(), "ip link", tunnelName)
		return err
	}
	cmd = exec.Command("ip", "addr", "add",
				tunnelLocalIpAddr,
				"remote", tunnelRemoteIpAddr,
				"dev", tunnelName)
	if _, err := cmd.Output();  err != nil {
		log.Printf("%s for %s %s addr add\n",
			err.Error(), "ip link", tunnelName)
		return err
	}
	cmd = exec.Command("ip", "link", "set",
				tunnelName, "up", "mtu", tunnelMtu)
	if _, err := cmd.Output(); err != nil {
		log.Printf("%s for %s %s set up\n",
			err.Error(), "ip link", tunnelName)
		return err
	}
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
	return nil
}

func ipSecServiceConfigCreate(tunnelName string,
			awsVpnGateway string, tunnelKey string) error {
	writeStr := ipSecConfHdrStr
	writeStr = writeStr + ipSecTunHdrStr + tunnelName
	writeStr = writeStr + ipSecTunSpecStr + awsVpnGateway
	writeStr = writeStr + ipSecTunAttribSpecStr + tunnelKey
	writeStr = writeStr + "\n"
	filename := "/etc/ipsec.conf"
	if err :=  ipSecConfigFileWrite(filename, writeStr); err != nil {
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

func ipSecSecretConfigCreate(awsVpnGateway string,
		 preSharedKey string) error {
	writeStr := ipSecSecretHdrStr
	writeStr = writeStr + "0.0.0.0 "
	writeStr = writeStr + awsVpnGateway + " "
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
		log.Printf("%s for %s set \n",
			err.Error(), "sysctl")
		return err
	}
	return nil
}

func ipSecConfigFileWrite(filename string, writeStr string) error {
	data := []byte(writeStr)
	if err := pubsub.WriteRename(filename, data); err != nil {
		return err
	}
	return nil
}
