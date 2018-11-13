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

// Parsing the output of and updating NetworkUplink
// dhcpcd -U eth0 | grep domain_name=
// dhcpcd -U eth0 | grep domain_name_servers=
func GetDnsInfo(us *types.NetworkUplink) error {

	log.Infof("getDnsInfo(%s)\n", us.IfName)
	log.Infof("Calling dhcpcd -U -4 %s\n", us.IfName)
	cmd := wrap.Command("dhcpcd", "-U", "-4", us.IfName)
	stdout, err := cmd.Output()
	if err != nil {
		// XXX get error -1 unless we have -4
		errStr := fmt.Sprintf("dhcpcd -U failed ", err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Debugf("dhcpcd -U got %v\n", string(stdout))
	lines := strings.Split(string(stdout), "\n")
	for _, line := range lines {
		items := strings.Split(line, "=")
		if len(items) != 2 {
			continue
		}
		log.Debugf("Got <%s> <%s>\n", items[0], items[1])
		// XXX check with IPv6 as well. Repeat vs. different string?
		switch items[0] {
		case "domain_name":
			dn := trimQuotes(items[1])
			// XXX already set? Multiple calls?
			log.Infof("getDnsInfo(%s) DomainName %s\n", us.IfName,
				dn)
			us.DomainName = dn
		case "domain_name_servers":
			servers := trimQuotes(items[1])
			// XXX already set? Multiple calls?
			log.Infof("getDnsInfo(%s) DnsServers %s\n", us.IfName,
				servers)
			// XXX multiple? How separated?
			ip := net.ParseIP(servers)
			if ip == nil {
				log.Errorf("Failed to parse %s\n", servers)
				continue
			}
			// XXX us.DnsServers = append(us.DnsServers, ip)
			us.DnsServers = []net.IP{ip}
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
