// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	dhcpcdStartTimeout = 3 * time.Second
	dhcpcdStopTimeout  = 30 * time.Second
)

// Dhcpcd : DHCP client (https://wiki.archlinux.org/title/dhcpcd).
type Dhcpcd struct {
	// AdapterLL : Adapter's logical label.
	AdapterLL     string
	AdapterIfName string
	DhcpConfig    types.DhcpConfig
}

// Name is based on the adapter interface name (one client per interface).
func (c Dhcpcd) Name() string {
	return c.AdapterIfName
}

// Label is more human-readable than name.
func (c Dhcpcd) Label() string {
	return "dhcpcd for " + c.AdapterLL
}

// Type of the item.
func (c Dhcpcd) Type() string {
	return DhcpcdTypename
}

// Equal is a comparison method for two equally-named Dhcpcd instances.
func (c Dhcpcd) Equal(other depgraph.Item) bool {
	c2 := other.(Dhcpcd)
	return reflect.DeepEqual(c.DhcpConfig, c2.DhcpConfig)
}

// External returns false.
func (c Dhcpcd) External() bool {
	return false
}

// String describes the DHCP client config.
func (c Dhcpcd) String() string {
	return fmt.Sprintf("DHCP Client: %#+v", c)
}

// Dependencies lists the adapter as the only dependency of the DHCP client.
func (c Dhcpcd) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: AdapterTypename,
				ItemName: c.AdapterIfName,
			},
			Description: "Network adapter must exist",
		},
	}
}

// DhcpcdConfigurator implements Configurator interface (libs/reconciler) for dhcpcd.
type DhcpcdConfigurator struct {
	Log *base.LogObject
}

// Create starts dhcpcd.
func (c *DhcpcdConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	done := reconciler.ContinueInBackground(ctx)

	go func() {
		client := item.(Dhcpcd)
		ifName := client.AdapterIfName
		config := client.DhcpConfig

		// Prepare input arguments
		var op string
		var args []string
		switch config.Dhcp {
		case types.DT_NONE:
			done(nil)
			return

		case types.DT_CLIENT:
			op = "--request"
			args = []string{"-f", "/dhcpcd.conf", "--noipv4ll", "-b", "-t", "0"}
			switch config.Type {
			case types.NtIpv4Only:
				args = []string{"-f", "/dhcpcd.conf", "--noipv4ll", "--ipv4only", "-b", "-t", "0"}
			case types.NtIpv6Only:
				args = []string{"-f", "/dhcpcd.conf", "--ipv6only", "-b", "-t", "0"}
			case types.NT_NOOP:
			case types.NT_IPV4:
			case types.NT_IPV6:
			case types.NtDualStack:
			default:
			}
			if config.Gateway != nil && config.Gateway.String() == "0.0.0.0" {
				args = append(args, "--nogateway")
			}

		case types.DT_STATIC:
			if config.AddrSubnet == "" {
				err := fmt.Errorf("DHCP config is missing AddrSubnet for interface %s\n",
					ifName)
				c.Log.Error(err)
				done(err)
				return
			}
			// Check that we can parse it
			_, _, err := net.ParseCIDR(config.AddrSubnet)
			if err != nil {
				err = fmt.Errorf(
					"failed to parse AddrSubnet from DHCP config for interface %s\n",
					ifName)
				c.Log.Error(err)
				done(err)
				return
			}
			op = "--static"
			args = []string{fmt.Sprintf("ip_address=%s", config.AddrSubnet)}
			extras := []string{"-f", "/dhcpcd.conf", "-b", "-t", "0"}
			if config.Gateway == nil || config.Gateway.String() == "0.0.0.0" {
				extras = append(extras, "--nogateway")
			} else if config.Gateway.String() != "" {
				args = append(args, "--static",
					fmt.Sprintf("routers=%s", config.Gateway.String()))
			}
			var dnsServers []string
			for _, dns := range config.DnsServers {
				dnsServers = append(dnsServers, dns.String())
			}
			if len(dnsServers) > 0 {
				// dhcpcd uses a very odd space-separation for multiple DNS servers.
				// For manual invocation one must be very careful to not forget
				// to quote the argument so that the spaces don't make the shell
				// break up the list into multiple args.
				// Here we do not need quotes because we are passing the DNS server
				// list as a single entry of the 'args' slice for exec.Command().
				args = append(args, "--static",
					fmt.Sprintf("domain_name_servers=%s",
						strings.Join(dnsServers, " ")))
			}
			if config.DomainName != "" {
				args = append(args, "--static",
					fmt.Sprintf("domain_name=%s", config.DomainName))
			}
			if config.NtpServer != nil && !config.NtpServer.IsUnspecified() {
				args = append(args, "--static",
					fmt.Sprintf("ntp_servers=%s",
						config.NtpServer.String()))
			}
			args = append(args, extras...)

		default:
			err := fmt.Errorf("unsupported DHCP type: %v", config.Dhcp)
			c.Log.Error(err)
			done(err)
			return
		}

		// Start DHCP client.
		if c.dhcpcdExists(client.AdapterIfName) {
			err := fmt.Errorf("dhcpcd for interface %s is already running", ifName)
			c.Log.Error(err)
			done(err)
			return
		}
		c.Log.Functionf("dhcpcd for interface %s is not running", ifName)
		startTime := time.Now()
		if err := c.dhcpcdCmd(op, args, ifName, true); err != nil {
			c.Log.Error(err)
			done(err)
			return
		}
		// Wait for a bit then give up
		for !c.dhcpcdExists(ifName) {
			if time.Since(startTime) > dhcpcdStartTimeout {
				err := fmt.Errorf("dhcpcd for interface %s failed to start in time",
					ifName)
				c.Log.Error(err)
				done(err)
				return
			}
			time.Sleep(1 * time.Second)
		}
		c.Log.Functionf("dhcpcd for interface %s is running", ifName)
		done(nil)
		return
	}()
	return nil
}

// Modify is not implemented.
func (c *DhcpcdConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete stops dhcpcd.
func (c *DhcpcdConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	done := reconciler.ContinueInBackground(ctx)

	go func() {
		client := item.(Dhcpcd)
		ifName := client.AdapterIfName
		config := client.DhcpConfig

		switch config.Dhcp {
		case types.DT_NONE:
			done(nil)
			return

		case types.DT_STATIC, types.DT_CLIENT:
			startTime := time.Now()
			var extras []string
			// Run release, wait for a bit, then exit and give up.
			failed := false
			for {
				// It waits up to 10 seconds https://github.com/NetworkConfiguration/dhcpcd/blob/dhcpcd-8.1.6/src/dhcpcd.c#L1950-L1957
				if err := c.dhcpcdCmd("--release", extras, ifName, false); err != nil {
					c.Log.Errorf("dhcpcd release failed for interface %s: %v, elapsed time %v",
						ifName, err, time.Since(startTime))
				}
				if !c.dhcpcdExists(ifName) {
					break
				}
				if time.Since(startTime) > dhcpcdStopTimeout {
					c.Log.Errorf("dhcpcd for interface %s is still running, will exit it, elapsed time %v",
						ifName, time.Since(startTime))
					failed = true
					break
				}
				c.Log.Warnf("dhcpcd for interface %s is still running, elapsed time %v",
					ifName, time.Since(startTime))
				time.Sleep(1 * time.Second)
			}
			if !failed {
				c.Log.Functionf("dhcpcd for interface %s is gone, elapsed time %v",
					ifName, time.Since(startTime))
				done(nil)
				return
			}
			// Exit dhcpcd on interface.
			// It waits up to 10 seconds https://github.com/NetworkConfiguration/dhcpcd/blob/dhcpcd-8.1.6/src/dhcpcd.c#L1950-L1957
			if err := c.dhcpcdCmd("--exit", extras, ifName, false); err != nil {
				err = fmt.Errorf("dhcpcd exit failed for interface %s: %v, elapsed time %v",
					ifName, err, time.Since(startTime))
				c.Log.Error(err)
				done(err)
				return
			}
			if !c.dhcpcdExists(ifName) {
				c.Log.Noticef("dhcpcd for interface %s is gone after exit, elapsed time %v",
					ifName, time.Since(startTime))
				done(nil)
				return
			}
			err := fmt.Errorf("exiting dhcpcd for interface %s is still running, elapsed time %v",
				ifName, time.Since(startTime))
			c.Log.Error(err)
			done(err)
			return

		default:
			err := fmt.Errorf("unsupported DHCP type: %v", config.Dhcp)
			c.Log.Error(err)
			done(err)
			return
		}
	}()
	return nil
}

// NeedsRecreate returns true because Modify is not implemented.
func (c *DhcpcdConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}

func (c *DhcpcdConfigurator) dhcpcdCmd(op string, extras []string,
	ifName string, background bool) error {
	name := "/sbin/dhcpcd"
	args := append([]string{op}, extras...)
	args = append(args, ifName)
	if background {
		cmd := exec.Command(name, args...)
		cmd.Stdout = nil
		cmd.Stderr = nil

		c.Log.Functionf("Background command %s %v\n", name, args)
		go func() {
			if err := cmd.Run(); err != nil {
				c.Log.Errorf("%s %v: failed: %s",
					name, args, err)
			}
		}()
	} else {
		c.Log.Functionf("Calling command %s %v\n", name, args)
		out, err := base.Exec(c.Log, name, args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("dhcpcd command %s failed: %s; output: %s",
				args, err, out)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

func (c *DhcpcdConfigurator) dhcpcdExists(ifName string) bool {
	// XXX should we use dhcpcd -P <ifName> to get name of pidfile? Hardcoded path here
	pidfileName := fmt.Sprintf("/run/dhcpcd-%s.pid", ifName)
	val, t := c.statAndRead(pidfileName)
	if val == "" {
		c.Log.Functionf("dhcpcdExists(%s) not exist", ifName)
		return false
	}
	c.Log.Functionf("dhcpcdExists(%s) found modtime %v", ifName, t)
	pid, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		c.Log.Errorf("strconv.Atoi of %s failed %s; ignored\n", val, err)
		return true // Guess since we don't know
	}
	// Does the pid exist?
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err != nil {
		c.Log.Errorf("dhcpcdExists(%s) Signal failed %s", ifName, err)
		return false
	}
	c.Log.Functionf("dhcpcdExists(%s) Signal 0 OK for %d", ifName, pid)
	return true
}

// Returns content and Modtime
func (c *DhcpcdConfigurator) statAndRead(filename string) (string, time.Time) {
	fi, err := os.Stat(filename)
	if err != nil {
		// File doesn't exist
		return "", time.Time{}
	}
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", fi.ModTime()
	}
	return string(content), fi.ModTime()
}
