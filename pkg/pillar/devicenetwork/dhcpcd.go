// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage dhcpcd for ports including static
// XXX wwan*? Skip for now since wwan container handles configuring IP

package devicenetwork

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// UpdateDhcpClient starts/modifies/deletes dhcpcd per interface
// Returns an ifname and error if an interface does not yet exist
func UpdateDhcpClient(newConfig, oldConfig types.DevicePortConfig) (string, error) {

	// Look for adds or changes
	log.Infof("updateDhcpClient: new %v old %v\n",
		newConfig, oldConfig)
	// Dry-run to see if we need to ask for retry. Don't change anything
	for _, newU := range newConfig.Ports {
		oldU := lookupOnIfname(oldConfig, newU.IfName)
		if oldU == nil || oldU.Dhcp == types.DT_NONE {
			log.Infof("updateDhcpClient: new %s dryrun", newU.IfName)
			err := doDhcpClientActivate(newU, true)
			if err != nil {
				return newU.IfName, err
			}
		}
	}

	for _, newU := range newConfig.Ports {
		oldU := lookupOnIfname(oldConfig, newU.IfName)
		if oldU == nil || oldU.Dhcp == types.DT_NONE {
			log.Infof("updateDhcpClient: new %s\n", newU.IfName)
			// Inactivate in case a dhcpcd is running
			doDhcpClientActivate(newU, false)
		} else {
			log.Infof("updateDhcpClient: found old %v\n",
				oldU)
			if !reflect.DeepEqual(newU.DhcpConfig, oldU.DhcpConfig) {
				log.Infof("updateDhcpClient: changed %s\n",
					newU.IfName)
				doDhcpClientInactivate(*oldU)
				doDhcpClientActivate(newU, false)
			}
		}
	}
	// Look for deletes from oldConfig to newConfig
	for _, oldU := range oldConfig.Ports {
		newU := lookupOnIfname(newConfig, oldU.IfName)
		if newU == nil || newU.Dhcp == types.DT_NONE {
			log.Infof("updateDhcpClient: deleted %s\n",
				oldU.IfName)
			doDhcpClientInactivate(oldU)
		} else {
			log.Infof("updateDhcpClient: found new %v\n",
				newU)
		}
	}
	return "", nil
}

// doDhcpClientActivate can return an error when dryrun is set.
// That can happen when the interface is missing.
func doDhcpClientActivate(nuc types.NetworkPortConfig, dryrun bool) error {

	log.Infof("doDhcpClientActivate(%s, %t) dhcp %v addr %s gateway %s\n",
		nuc.IfName, dryrun, nuc.Dhcp, nuc.AddrSubnet,
		nuc.Gateway.String())
	if strings.HasPrefix(nuc.IfName, "wwan") {
		log.Infof("doDhcpClientActivate: skipping %s\n",
			nuc.IfName)
		return nil
	}

	// Check the ifname exists
	_, err := IfnameToIndex(nuc.IfName)
	if err != nil {
		log.Warnf("doDhcpClientActivate(%s) failed %s", nuc.IfName, err)
		return err
	}
	if dryrun {
		// No code below can return true
		return nil
	}
	switch nuc.Dhcp {
	case types.DT_NONE:
		log.Infof("doDhcpClientActivate(%s) DT_NONE is a no-op\n",
			nuc.IfName)
		return nil
	case types.DT_CLIENT:
		for dhcpcdExists(nuc.IfName) {
			log.Warnf("dhcpcd %s already exists", nuc.IfName)
			time.Sleep(10 * time.Second)
		}
		log.Infof("dhcpcd %s not running", nuc.IfName)
		extras := []string{"-f", "/dhcpcd.conf", "--noipv4ll", "-b", "-t", "0"}
		if nuc.Gateway != nil && nuc.Gateway.String() == "0.0.0.0" {
			extras = append(extras, "--nogateway")
		}
		if !dhcpcdCmd("--request", extras, nuc.IfName, true) {
			log.Errorf("doDhcpClientActivate: request failed for %s\n",
				nuc.IfName)
		}
		// Wait for a bit then give up
		waitCount := 0
		failed := false
		for !dhcpcdExists(nuc.IfName) {
			log.Warnf("dhcpcd %s not yet running", nuc.IfName)
			waitCount++
			if waitCount >= 3 {
				log.Errorf("dhcpcd %s not yet running", nuc.IfName)
				failed = true
				break
			}
			time.Sleep(10 * time.Second)
		}
		if !failed {
			log.Infof("dhcpcd %s is running", nuc.IfName)
		}

	case types.DT_STATIC:
		if nuc.AddrSubnet == "" {
			log.Errorf("doDhcpClientActivate: missing AddrSubnet for %s\n",
				nuc.IfName)
			// XXX return error?
			return nil
		}
		// Check that we can parse it
		_, _, err := net.ParseCIDR(nuc.AddrSubnet)
		if err != nil {
			log.Errorf("doDhcpClientActivate: failed to parse %s for %s: %s\n",
				nuc.AddrSubnet, nuc.IfName, err)
			// XXX return error?
			return nil
		}
		for dhcpcdExists(nuc.IfName) {
			log.Warnf("dhcpcd %s already exists", nuc.IfName)
			time.Sleep(10 * time.Second)
		}
		log.Infof("dhcpcd %s not running", nuc.IfName)
		args := []string{fmt.Sprintf("ip_address=%s", nuc.AddrSubnet)}

		extras := []string{"-f", "/dhcpcd.conf", "-b", "-t", "0"}
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
		// Wait for a bit then give up
		waitCount := 0
		failed := false
		for !dhcpcdExists(nuc.IfName) {
			log.Warnf("dhcpcd %s not yet running", nuc.IfName)
			waitCount++
			if waitCount >= 3 {
				log.Errorf("dhcpcd %s not yet running", nuc.IfName)
				failed = true
				break
			}
			time.Sleep(10 * time.Second)
		}
		if !failed {
			log.Infof("dhcpcd %s is running", nuc.IfName)
		}
	default:
		log.Errorf("doDhcpClientActivate: unsupported dhcp %v\n",
			nuc.Dhcp)
	}
	return nil
}

func doDhcpClientInactivate(nuc types.NetworkPortConfig) {

	log.Infof("doDhcpClientInactivate(%s) dhcp %v addr %s gateway %s\n",
		nuc.IfName, nuc.Dhcp, nuc.AddrSubnet,
		nuc.Gateway.String())
	if strings.HasPrefix(nuc.IfName, "wwan") {
		log.Infof("doDhcpClientInactivate: skipping %s\n",
			nuc.IfName)
		return
	}
	switch nuc.Dhcp {
	case types.DT_NONE:
		log.Infof("doDhcpClientInactivate(%s) DT_NONE is a no-op\n",
			nuc.IfName)
	case types.DT_STATIC, types.DT_CLIENT:
		extras := []string{}
		if !dhcpcdCmd("--release", extras, nuc.IfName, false) {
			log.Errorf("doDhcpClientInactivate: release failed for %s\n",
				nuc.IfName)
		}
		for dhcpcdExists(nuc.IfName) {
			log.Warnf("dhcpcd %s still running", nuc.IfName)
			time.Sleep(10 * time.Second)
		}
		log.Infof("dhcpcd %s gone", nuc.IfName)
	default:
		log.Errorf("doDhcpClientInactivate: unsupported dhcp %v\n",
			nuc.Dhcp)
	}
}

func dhcpcdCmd(op string, extras []string, ifname string, background bool) bool {
	name := "/sbin/dhcpcd"
	args := append([]string{op}, extras...)
	args = append(args, ifname)
	if background {
		cmd := exec.Command(name, args...)
		cmd.Stdout = os.NewFile(0, os.DevNull)
		cmd.Stderr = os.NewFile(0, os.DevNull)

		log.Infof("Background command %s %v\n", name, args)
		go func() {
			if err := cmd.Run(); err != nil {
				log.Errorf("%s %v: failed: %s",
					name, args, err)
			}
		}()
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

func dhcpcdExists(ifname string) bool {

	log.Infof("dhcpcdExists(%s)", ifname)
	// XXX should we use dhcpcd -P <ifname> to get name of pidfile? Hardcoded path here
	pidfileName := fmt.Sprintf("/run/dhcpcd-%s.pid", ifname)
	val, t := statAndRead(pidfileName)
	if val == "" {
		log.Infof("dhcpcdExists(%s) not exist", ifname)
		return false
	}
	log.Infof("dhcpcdExists(%s) found modtime %v", ifname, t)

	pid, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		log.Errorf("Atoi of %s failed %s; ignored\n", val, err)
		return true // Guess since we dont' know
	}
	// Does the pid exist?
	p, err := os.FindProcess(pid)
	if err != nil {
		log.Infof("dhcpcdExists(%s) pid %d not found: %s", ifname, pid,
			err)
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err != nil {
		log.Errorf("dhcpcdExists(%s) Signal failed %s", ifname, err)
		return false
	}
	log.Infof("dhcpcdExists(%s) Signal 0 OK for %d", ifname, pid)
	return true
}

// Returns content and Modtime
func statAndRead(filename string) (string, time.Time) {
	fi, err := os.Stat(filename)
	if err != nil {
		// File doesn't exist
		return "", time.Time{}
	}
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Errorf("statAndRead failed %s", err)
		return "", fi.ModTime()
	}
	return string(content), fi.ModTime()
}
