// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"strings"
)

// Get DNS etc info from dhcpcd. Updates DomainName and DnsServers, Gateway,
// Subnet
// XXX set NtpServer once we know what name it has
// dhcpcd -U eth0 | grep domain_name=
// dhcpcd -U eth0 | grep domain_name_servers=
// dhcpcd -U eth0 | grep routers=
// XXX add IPv6 support. Where do we put if different DomainName?
// dhcp6_domain_search='attlocal.net'
// dhcp6_name_servers='2600:1700:daa0:cfb0::1'
func GetDhcpInfo(us *types.NetworkPortStatus) error {

	log.Infof("getDnsInfo(%s)\n", us.IfName)
	if us.Dhcp != types.DT_CLIENT {
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
		// If we have no lease we get an error. Don't store those
		us.DomainName = ""
		us.DnsServers = []net.IP{}
		return nil
	}
	log.Debugf("dhcpcd -U got %v\n", string(stdoutStderr))
	lines := strings.Split(string(stdoutStderr), "\n")
	us.DomainName = ""
	us.DnsServers = []net.IP{}
	masklen := 0
	var subnet net.IP
	for _, line := range lines {
		items := strings.Split(line, "=")
		if len(items) != 2 {
			continue
		}
		log.Debugf("Got <%s> <%s>\n", items[0], items[1])
		switch items[0] {
		case "domain_name":
			dn := trimQuotes(items[1])
			log.Infof("getDnsInfo(%s) DomainName %s\n", us.IfName,
				dn)
			us.DomainName = dn
		case "domain_name_servers":
			servers := trimQuotes(items[1])
			log.Infof("getDnsInfo(%s) DnsServers %s\n", us.IfName,
				servers)
			// XXX multiple? How separated?
			for _, server := range strings.Split(servers, " ") {
				ip := net.ParseIP(server)
				if ip == nil {
					log.Errorf("Failed to parse %s\n", server)
					continue
				}
				us.DnsServers = append(us.DnsServers, ip)
			}
		case "routers":
			routers := trimQuotes(items[1])
			log.Infof("getDnsInfo(%s) Gateway %s\n", us.IfName,
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
			log.Infof("getDnsInfo(%s) network_number %s\n", us.IfName,
				network)
			ip := net.ParseIP(network)
			if ip == nil {
				log.Errorf("Failed to parse %s\n", network)
				continue
			}
			subnet = ip
		case "subnet_cidr":
			str := trimQuotes(items[1])
			log.Infof("getDnsInfo(%s) subnet_cidr %s\n", us.IfName,
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
