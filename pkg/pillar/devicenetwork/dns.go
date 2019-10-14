// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/netclone"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"strconv"
	"strings"
)

// GetDhcpInfo gets info from dhcpcd. Updates Gateway and Subnet
// XXX set NtpServer once we know what name it has
// XXX add IPv6 support?
func GetDhcpInfo(us *types.NetworkPortStatus) error {

	log.Infof("GetDhcpInfo(%s)\n", us.IfName)
	if us.Dhcp != types.DT_CLIENT {
		return nil
	}
	if strings.HasPrefix(us.IfName, "wwan") {
		return nil
	}
	// XXX get error -1 unless we have -4
	// XXX add IPv6 support
	log.Infof("Calling dhcpcd -U -4 %s\n", us.IfName)
	cmd := wrap.Command("dhcpcd", "-U", "-4", us.IfName)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("dhcpcd -U failed %s: %s",
			string(stdoutStderr), err)
		log.Errorln(errStr)
		return nil
	}
	log.Debugf("dhcpcd -U got %v\n", string(stdoutStderr))
	lines := strings.Split(string(stdoutStderr), "\n")
	masklen := 0
	var subnet net.IP
	for _, line := range lines {
		items := strings.Split(line, "=")
		if len(items) != 2 {
			continue
		}
		log.Debugf("Got <%s> <%s>\n", items[0], items[1])
		switch items[0] {
		case "routers":
			routers := trimQuotes(items[1])
			log.Infof("GetDhcpInfo(%s) Gateway %s\n", us.IfName,
				routers)
			// XXX multiple? How separated?
			ip := net.ParseIP(routers)
			if ip == nil {
				log.Errorf("Failed to parse %s\n", routers)
				continue
			}
			us.Gateway = ip
		case "network_number":
			network := trimQuotes(items[1])
			log.Infof("GetDhcpInfo(%s) network_number %s\n", us.IfName,
				network)
			ip := net.ParseIP(network)
			if ip == nil {
				log.Errorf("Failed to parse %s\n", network)
				continue
			}
			subnet = ip
		case "subnet_cidr":
			str := trimQuotes(items[1])
			log.Infof("GetDhcpInfo(%s) subnet_cidr %s\n", us.IfName,
				str)
			masklen, err = strconv.Atoi(str)
			if err != nil {
				log.Errorf("Failed to parse masklen %s\n", str)
				continue
			}
		}
	}
	us.Subnet = net.IPNet{IP: subnet, Mask: net.CIDRMask(masklen, 32)}
	return nil
}

// GetDNSInfo gets DNS info from /run files. Updates DomainName and DnsServers
func GetDNSInfo(us *types.NetworkPortStatus) {

	log.Infof("GetDNSInfo(%s)\n", us.IfName)
	if us.Dhcp != types.DT_CLIENT {
		return
	}
	filename := IfnameToResolvConf(us.IfName)
	if filename == "" {
		log.Errorf("No resolv.conf for %s", us.IfName)
		return
	}
	dc := netclone.DnsReadConfig(filename)
	log.Infof("%s servers %v, search %v\n", filename, dc.Servers, dc.Search)
	for _, server := range dc.Servers {
		// Might have port number
		s := strings.Split(server, ":")
		ip := net.ParseIP(s[0])
		if ip == nil {
			log.Errorf("Failed to parse %s\n", server)
			continue
		}
		us.DnsServers = append(us.DnsServers, ip)
	}
	// XXX just pick first since have one DomainName slot
	for _, dn := range dc.Search {
		us.DomainName = dn
		break
	}
}

var resolveConfDirs = []string{"/run/dhcpcd/resolv.conf", "/run/wwan/resolv.conf"}

// IfnameToResolvConf : Look for a file created by dhcpcd
func IfnameToResolvConf(ifname string) string {
	for _, d := range resolveConfDirs {
		filename := fmt.Sprintf("%s/%s.dhcp", d, ifname)
		_, err := os.Stat(filename)
		if err == nil {
			return filename
		}
	}
	return ""
}

// Remove single or double qoutes
func trimQuotes(str string) string {
	if len(str) < 2 {
		return str
	}
	c := str[len(str)-1]
	if (c == '"' || c == '\'') && str[0] == c {
		return str[1 : len(str)-1]
	} else {
		return str
	}
}
