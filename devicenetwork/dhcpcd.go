// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Manage dhcpcd for uplinks including static
// XXX wwan0? Skip for now

package devicenetwork

import (
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"log"
	"reflect"
)

// Start/modify/delete dhcpcd per interface
func UpdateDhcpClient(newConfig, oldConfig types.DeviceUplinkConfig) {
	// Look for adds or changes
	for _, newU := range newConfig.Uplinks {
		oldU := lookupOnIfname(oldConfig, newU.IfName)
		if false {
			// XXX type check - remove
			*oldU = newU
		}
		if oldU == nil {
			log.Printf("updateDhcpClient: new %s\n", newU.IfName)
			doDhcpClientActivate(newU)
		} else if !reflect.DeepEqual(newU, oldU) {
			log.Printf("updateDhcpClient: changed %s\n",
				newU.IfName)
			doDhcpClientInactivate(*oldU)
			doDhcpClientActivate(newU)
		}
	}
	// Look for deletes from oldConfig to newConfig
	for _, oldU := range newConfig.Uplinks {
		newU := lookupOnIfname(newConfig, oldU.IfName)
		if newU == nil {
			log.Printf("updateDhcpClient: deleted %s\n",
				oldU.IfName)
			doDhcpClientInactivate(oldU)
		}
	}

}

func lookupOnIfname(config types.DeviceUplinkConfig, ifname string) *types.NetworkUplinkConfig {
	for _, c := range config.Uplinks {
		if c.IfName == ifname {
			return &c
		}
	}
	return nil
}

func doDhcpClientActivate(nuc types.NetworkUplinkConfig) {
	log.Printf("doDhcpClientActivate(%s) dhcp %v addr %s gateway %s\n",
		nuc.IfName, nuc.Dhcp, nuc.Addr.String(),
		nuc.Gateway.String())
	if nuc.IfName == "wwan0" {
		log.Printf("doDhcpClientActivate: skipping %s\n",
			nuc.IfName)
		return
	}

	switch nuc.Dhcp {
	case types.DT_CLIENT:
		extras := []string{"-f", "/etc/dhcpcd.conf", "-b", "-K",
			"--noipv4ll"}
		if nuc.Gateway.String() == "0.0.0.0" {
			extras = append(extras, "--nogateway")
		}
		if !dhcpcdCmd("--request", extras, nuc.IfName) {
			log.Printf("doDhcpClientActivate: request failed for %s\n",
				nuc.IfName)
		}
	case types.DT_STATIC:
		// XXX Addr vs. Subnet? Need netmask. --static subnet_mask=255.255.255.0
		args := []string{fmt.Sprintf("ip_address=%s", nuc.Addr.String())}

		extras := []string{"-f", "/etc/dhcpcd.conf", "-b", "-K"}
		if nuc.Gateway.String() == "0.0.0.0" {
			extras = append(extras, "--nogateway")
		} else if nuc.Gateway.String() != "" {
			args = append(args, "--static",
				fmt.Sprintf("routers=%s", nuc.Gateway.String()))
		}
		// XXX is there a "dns"? Not in source
		// XXX do we need to calculate a list for option?
		for _, dns := range nuc.DnsServers {
			args = append(args, "--static",
				fmt.Sprintf("domain_name_servers=%s", dns.String()))
		}
		if nuc.DomainName != "" {
			args = append(args, "--static",
				fmt.Sprintf("domain_name=%s", nuc.DomainName))
		}
		// dhcpcd.conf needs this: #option ntp_servers
		if !nuc.NtpServer.IsUnspecified() {
			args = append(args, "--static",
				fmt.Sprintf("ntp_servers=%s",
					nuc.NtpServer.String()))
		}

		args = append(args, extras...)
		if !dhcpcdCmd("--static", args, nuc.IfName) {
			log.Printf("doDhcpClientActivate: request failed for %s\n",
				nuc.IfName)
		}
	default:
		log.Printf("doDhcpClientActivate: unsupported dhcp %v\n",
			nuc.Dhcp)
	}
}

func doDhcpClientInactivate(nuc types.NetworkUplinkConfig) {
	log.Printf("doDhcpClientInactivate(%s) dhcp %v addr %s gateway %s\n",
		nuc.IfName, nuc.Dhcp, nuc.Addr.String(),
		nuc.Gateway.String())
	if nuc.IfName == "wwan0" {
		log.Printf("doDhcpClientInactivate: skipping %s\n",
			nuc.IfName)
		return
	}
	extras := []string{"-K"}
	if !dhcpcdCmd("--release", extras, nuc.IfName) {
		log.Printf("doDhcpClientInactivate: release failed for %s\n",
			nuc.IfName)
	}
}

func dhcpcdCmd(op string, extras []string, ifname string) bool {
	cmd := "dhcpcd"
	args := append([]string{op}, extras...)
	args = append(args, ifname)
	if _, err := wrap.Command(cmd, args...).Output(); err != nil {
		return false
	}
	return true
}
