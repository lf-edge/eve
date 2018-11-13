// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

// Parsing the output of and updating NetworkUplink
// dhcpcd -U eth0 | grep domain_name=
// dhcpcd -U eth0 | grep domain_name_servers=
func getDnsInfo(us *types.NetworkUplink) error {

	log.Infof("getDnsInfo(%s)\n", us.IfName)
	tmpfile, err := ioutil.TempFile("/tmp/", "dns")
	if err != nil {
		log.Errorln("TempFile ", err)
		return err
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	log.Infof("Calling dhcpcd -U %s\n", us.IfName)
	cmd := wrap.Command("dhcpcd", "-U", us.IfName)
	stdout, err := cmd.Output()
	if err != nil {
		log.Errorln("dhcpcd -U failed ", err)
	}
	log.Infof("dhcpcd -U got %v\n", string(stdout))
	lines := strings.Split(string(stdout), "\n")
	for _, line := range lines {
		items := strings.Split(line, "=")
		if len(items) != 2 {
			continue
		}
		// XXX check with IPv6 as well. Repeat vs. different string?
		log.Infof("Got <%s> <%s>\n", items[0], items[1])
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
