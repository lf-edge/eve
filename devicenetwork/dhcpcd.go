// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Manage dhcpcd for uplinks including static
// XXX wwan0? Skip for now

package devicenetwork

import (
	"fmt"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/types"
	"log"
	"os/exec"
	"reflect"
)

// Start/modify/delete dhcpcd per interface
func UpdateDhcpClient(newConfig, oldConfig types.DeviceUplinkConfig) {
	// Look for adds or changes
	log.Printf("updateDhcpClient: new %v old %v\n",
		newConfig, oldConfig)
	for _, newU := range newConfig.Uplinks {
		oldU := lookupOnIfname(oldConfig, newU.IfName)
		if false {
			// XXX type check - remove
			*oldU = newU
		}
		if oldU == nil {
			log.Printf("updateDhcpClient: new %s\n", newU.IfName)
			// Inactivate in case a dhcpcd is running
			doDhcpClientActivate(newU)
		} else {
			log.Printf("updateDhcpClient: found old %v\n",
				oldU)
			if !reflect.DeepEqual(newU, oldU) {
				log.Printf("updateDhcpClient: changed %s\n",
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
			log.Printf("updateDhcpClient: deleted %s\n",
				oldU.IfName)
			doDhcpClientInactivate(oldU)
		} else {
			log.Printf("updateDhcpClient: found new %v\n",
				newU)
		}
	}

}

func doDhcpClientActivate(nuc types.NetworkUplinkConfig) {
	log.Printf("doDhcpClientActivate(%s) dhcp %v addr %s gateway %s\n",
		nuc.IfName, nuc.Dhcp, nuc.Addr.String(),
		nuc.Gateway.String())
	// XXX skipping wwan0
	if nuc.IfName == "wwan0" {
		log.Printf("doDhcpClientActivate: skipping %s\n",
			nuc.IfName)
		return
	}

	switch nuc.Dhcp {
	case types.DT_CLIENT:
		extras := []string{"-f", "/dhcpcd.conf", "--nobackground",
			"-d", "--noipv4ll"}
		if nuc.Gateway == nil || nuc.Gateway.String() == "0.0.0.0" {
			extras = append(extras, "--nogateway")
		}
		if !dhcpcdCmd("--request", extras, nuc.IfName, true) {
			log.Printf("doDhcpClientActivate: request failed for %s\n",
				nuc.IfName)
		}
	case types.DT_STATIC:
		// Require that Subnet is set and that Addr fits in it
		if !nuc.Subnet.Contains(nuc.Addr) {
			log.Printf("doDhcpClientActivate: failed addr %s not in subnet %s for %s\n",
				nuc.Addr.String(), nuc.Subnet.String(),
				nuc.IfName)
			// XXX return error?
			return
		}
		addrSubnet := nuc.Subnet
		addrSubnet.Mask = nuc.Subnet.Mask
		args := []string{fmt.Sprintf("ip_address=%s",
			addrSubnet.String())}

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
		if nuc.NtpServer == nil || !nuc.NtpServer.IsUnspecified() {
			args = append(args, "--static",
				fmt.Sprintf("ntp_servers=%s",
					nuc.NtpServer.String()))
		}

		args = append(args, extras...)
		if !dhcpcdCmd("--static", args, nuc.IfName, true) {
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
	// XXX skipping wwan0
	if nuc.IfName == "wwan0" {
		log.Printf("doDhcpClientInactivate: skipping %s\n",
			nuc.IfName)
		return
	}
	extras := []string{}
	if !dhcpcdCmd("--release", extras, nuc.IfName, false) {
		log.Printf("doDhcpClientInactivate: release failed for %s\n",
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
		log.Printf("Background command %s %v\n", name, args)
		go cmd.Run()
	} else {
		log.Printf("Calling command %s %v\n", name, args)
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			errStr := fmt.Sprintf("dhcpcd command %s failed %s output %s",
				args, err, out)
			log.Println(errStr)
			return false
		}
	}
	return true
}
