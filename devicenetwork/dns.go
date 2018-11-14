// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"net"
	"strings"
)

// Get DNS info from dhcpcd. Updates DomainName and DnsServers
// dhcpcd -U eth0 | grep domain_name=
// dhcpcd -U eth0 | grep domain_name_servers=
// XXX add IPv6 support. Where do we put if different DomainName?
// dhcp6_domain_search='attlocal.net'
// dhcp6_name_servers='2600:1700:daa0:cfb0::1'
func GetDnsInfo(us *types.NetworkUplink) error {

	log.Infof("getDnsInfo(%s)\n", us.IfName)
	log.Infof("Calling dhcpcd -U -4 %s\n", us.IfName)
	cmd := wrap.Command("dhcpcd", "-U", "-4", us.IfName)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		// XXX get error -1 unless we have -4
		errStr := fmt.Sprintf("dhcpcd -U failed %s: %s",
			string(stdoutStderr), err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Debugf("dhcpcd -U got %v\n", string(stdoutStderr))
	lines := strings.Split(string(stdoutStderr), "\n")
	us.DomainName = ""
	us.DnsServers = []net.IP{}
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
			ip := net.ParseIP(servers)
			if ip == nil {
				log.Errorf("Failed to parse %s\n", servers)
				continue
			}
			us.DnsServers = append(us.DnsServers, ip)
		}
	}
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
