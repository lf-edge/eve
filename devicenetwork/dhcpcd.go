// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Manage dhcpcd for uplinks including static
// XXX wwan0? Skip for now

package devicenetwork

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/types"
	"net"
	"os/exec"
	"reflect"
)

// Start/modify/delete dhcpcd per interface
func UpdateDhcpClient(newConfig, oldConfig types.DeviceUplinkConfig) {

	// Look for adds or changes
	log.Infof("updateDhcpClient: new %v old %v\n",
		newConfig, oldConfig)
	for _, newU := range newConfig.Uplinks {
		oldU := lookupOnIfname(oldConfig, newU.IfName)
		if oldU == nil {
			log.Infof("updateDhcpClient: new %s\n", newU.IfName)
			// Inactivate in case a dhcpcd is running
			doDhcpClientActivate(newU)
		} else {
			log.Infof("updateDhcpClient: found old %v\n",
				oldU)
			if !reflect.DeepEqual(newU.DhcpConfig, oldU.DhcpConfig) {
				log.Infof("updateDhcpClient: changed %s\n",
					newU.IfName)
				doDhcpClientInactivate(*oldU)
				doDhcpClientActivate(newU)
			}
		}
	}
	// Look for deletes from oldConfig to newConfig
	for _, oldU := range oldConfig.Uplinks {
		newU := lookupOnIfname(newConfig, oldU.IfName)
		if newU == nil {
			log.Infof("updateDhcpClient: deleted %s\n",
				oldU.IfName)
			doDhcpClientInactivate(oldU)
		} else {
			log.Infof("updateDhcpClient: found new %v\n",
				newU)
		}
	}

}

func doDhcpClientActivate(nuc types.NetworkUplinkConfig) {

	log.Infof("doDhcpClientActivate(%s) dhcp %v addr %s gateway %s\n",
		nuc.IfName, nuc.Dhcp, nuc.AddrSubnet,
		nuc.Gateway.String())
	// XXX skipping wwan0
	if nuc.IfName == "wwan0" {
		log.Infof("doDhcpClientActivate: skipping %s\n",
			nuc.IfName)
		return
	}

	switch nuc.Dhcp {
	case types.DT_CLIENT:
		extras := []string{"-f", "/dhcpcd.conf", "--nobackground",
			"-d", "--noipv4ll"}
		if nuc.Gateway != nil && nuc.Gateway.String() == "0.0.0.0" {
			extras = append(extras, "--nogateway")
		}
		if !dhcpcdCmd("--request", extras, nuc.IfName, true) {
			log.Errorf("doDhcpClientActivate: request failed for %s\n",
				nuc.IfName)
		}
	case types.DT_STATIC:
		if nuc.AddrSubnet == "" {
			log.Errorf("doDhcpClientActivate: missing AddrSubnet for %s\n",
				nuc.IfName)
			// XXX return error?
			return
		}
		// Check that we can parse it
		_, _, err := net.ParseCIDR(nuc.AddrSubnet)
		if err != nil {
			log.Errorf("doDhcpClientActivate: failed to parse %s for %s: %s\n",
				nuc.AddrSubnet, nuc.IfName, err)
			// XXX return error?
			return
		}
		args := []string{fmt.Sprintf("ip_address=%s", nuc.AddrSubnet)}

		extras := []string{"-f", "/dhcpcd.conf", "--nobackground",
			"-d"}
		if nuc.Gateway == nil || nuc.Gateway.String() == "0.0.0.0" {
			extras = append(extras, "--nogateway")
		} else if nuc.Gateway.String() != "" {
			args = append(args, "--static",
				fmt.Sprintf("routers=%s", nuc.Gateway.String()))
		}
		// XXX do we need to calculate a list for option?
		for _, dns := range nuc.DnsServers {
			args = append(args, "--static",
				fmt.Sprintf("domain_name_servers=%s", dns.String()))
		}
		if nuc.DomainName != "" {
			args = append(args, "--static",
				fmt.Sprintf("domain_name=%s", nuc.DomainName))
		}
		if nuc.NtpServer != nil && !nuc.NtpServer.IsUnspecified() {
			args = append(args, "--static",
				fmt.Sprintf("ntp_servers=%s",
					nuc.NtpServer.String()))
		}

		args = append(args, extras...)
		if !dhcpcdCmd("--static", args, nuc.IfName, true) {
			log.Errorf("doDhcpClientActivate: request failed for %s\n",
				nuc.IfName)
		}
	default:
		log.Errorf("doDhcpClientActivate: unsupported dhcp %v\n",
			nuc.Dhcp)
	}
}

func doDhcpClientInactivate(nuc types.NetworkUplinkConfig) {

	log.Infof("doDhcpClientInactivate(%s) dhcp %v addr %s gateway %s\n",
		nuc.IfName, nuc.Dhcp, nuc.AddrSubnet,
		nuc.Gateway.String())
	// XXX skipping wwan0
	if nuc.IfName == "wwan0" {
		log.Infof("doDhcpClientInactivate: skipping %s\n",
			nuc.IfName)
		return
	}
	extras := []string{}
	if !dhcpcdCmd("--release", extras, nuc.IfName, false) {
		log.Errorf("doDhcpClientInactivate: release failed for %s\n",
			nuc.IfName)
	}
}

func dhcpcdCmd(op string, extras []string, ifname string, dolog bool) bool {
	name := "dhcpcd"
	args := append([]string{op}, extras...)
	args = append(args, ifname)
	if dolog {
		logFilename := fmt.Sprintf("dhcpcd.%s", ifname)
		logf, err := agentlog.InitChild(logFilename)
		if err != nil {
			log.Fatalf("agentlog dhcpcdCmd failed: %s\n", err)
		}
		cmd := exec.Command(name, args...)
		cmd.Stdout = logf
		cmd.Stderr = logf
		log.Infof("Background command %s %v\n", name, args)
		go cmd.Run()
	} else {
		log.Infof("Calling command %s %v\n", name, args)
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			errStr := fmt.Sprintf("dhcpcd command %s failed %s output %s",
				args, err, out)
			log.Errorln(errStr)
			return false
		}
	}
	return true
}
