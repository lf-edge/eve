// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	log "github.com/sirupsen/logrus"
)

const (
	dnsmasqBinary       = "/usr/sbin/dnsmasq"
	dnsmasqStartTimeout = 3 * time.Second
	dnsmasqStopTimeout  = 30 * time.Second
	dnsmasqConfDir      = "/etc/dnsmasq"
	dnsmasqRunDir       = "/run/dnsmasq"

	dhcpSrvNamePrefix = "dhcpsrv-"
)

// DhcpServer : DHCP/DHCPv6 server.
type DhcpServer struct {
	// ServerName : logical name for the DHCP server.
	ServerName string
	// NetNamespace : network namespace where the server should be running.
	NetNamespace string
	// VethName : logical name of the veth pair on which the server operates.
	// (other types of interfaces are currently not supported)
	VethName string
	// VethPeerIfName : interface name of that side of the veth pair on which
	// the server should listen. It should be inside NetNamespace.
	VethPeerIfName string
	// IPv4Subnet : IPv4 network address + netmask.
	// Can be nil (but then IPv6Subnet must be defined).
	// Both IPv4Subnet and IPv6Subnet can be defined (dual-stack is supported).
	IPv4Subnet *net.IPNet
	// IPv6Subnet : IPv6 network address + netmask.
	// Can be nil (but then IPv4Subnet must be defined).
	// Both IPv4Subnet and IPv6Subnet can be defined (dual-stack is supported).
	IPv6Subnet *net.IPNet
	// IPv4Range : a range of IPv4 addresses to allocate from.
	// Should be inside IPv4Subnet.
	// Undefined if entire IPv4Subnet should be used or in the IPv6-only mode.
	IPv4Range IPRange
	// IPv6Range : a range of IPv6 addresses to allocate from.
	// Should be inside IPv6Subnet.
	// Undefined if entire IPv6Subnet should be used or in the IPv6-only mode.
	IPv6Range IPRange
	// StaticEntries : list of MAC->IP entries statically configured for the DHCP server.
	StaticEntries []MACToIP
	// GatewayIPv4 : IPv4 address of the default gateway to advertise (DHCP option 3).
	// Leave undefined in the IPv6-only mode or when the client should not install
	// the default IPv4 route.
	GatewayIPv4 net.IP
	// DomainName : name of the domain assigned to the network.
	// It is propagated to clients using the DHCP option 15 (24 in DHCPv6).
	DomainName string
	// DNSServers : list of IP addresses of DNS servers to announce via DHCP option 6
	// (23 in DHCPv6).
	// The list combines IPv4 and IPv6 DNS servers.
	DNSServers []net.IP
	// NTP server to announce via DHCP option 42 (56 in DHCPv6).
	// Optional argument, leave nil to disable.
	IPv4NTPServer string
	// NTP server to announce via DHCPv6 option 56.
	// Optional argument, leave nil to disable.
	IPv6NTPServer string
	// WPAD : URL with a location of a PAC file, announced using the Web Proxy Auto-Discovery
	// Protocol (WPAD) and DHCP.
	// The client will learn the PAC file location using the DHCP option 252.
	// Optional argument, leave empty to disable.
	WPAD string
	// IPv4LeaseTime : DHCPv4 lease duration advertised to clients. Zero uses the default (1 hour).
	// Set to a short value in tests that switch the SDN model mid-test so that clients
	// holding stale leases will re-DHCP quickly after the switch.
	IPv4LeaseTime time.Duration
	// IPv6LeaseTime : DHCPv6 lease duration advertised to clients. Zero uses the default (1 hour).
	IPv6LeaseTime time.Duration

	//nolint:godox
	// TODO: Netboot
	//  Example dnsmasq.conf for Netboot:
	//    # use custom tftp-server instead machine running dnsmasq
	//    dhcp-boot=pxelinux,server.name,192.168.1.100
	//    # Boot for iPXE. The idea is to send two different
	//    # filenames, the first loads iPXE, and the second tells iPXE what to
	//    # load. The dhcp-match sets the ipxe tag for requests from iPXE.
	//    dhcp-boot=undionly.kpxe
	//    dhcp-match=set:ipxe,175 # iPXE sends a 175 option.
	//    dhcp-boot=tag:ipxe,http://boot.ipxe.org/demo/boot.php
}

// IPRange : a range of IP addresses.
type IPRange struct {
	// FromIP : start of the range (includes the address itself).
	FromIP net.IP
	// ToIP : end of the range (includes the address itself).
	ToIP net.IP
}

// MACToIP maps MAC address to IP address.
type MACToIP struct {
	MAC net.HardwareAddr
	IP  net.IP
}

func equalMACToIPs(entry1, entry2 MACToIP) bool {
	return bytes.Equal(entry1.MAC, entry2.MAC) && entry1.IP.Equal(entry2.IP)
}

// Name returns the name of the DHCP server item.
func (s DhcpServer) Name() string {
	return s.ServerName
}

// Label returns the label of the DHCP server item.
func (s DhcpServer) Label() string {
	return s.ServerName + " (DHCP server)"
}

// Type returns the typename of the DHCP server item.
func (s DhcpServer) Type() string {
	return DhcpServerTypename
}

// Equal is a comparison method for two equally-named DhcpServer instances.
func (s DhcpServer) Equal(other depgraph.Item) bool {
	s2 := other.(DhcpServer)
	return s.NetNamespace == s2.NetNamespace &&
		s.VethName == s2.VethName &&
		s.VethPeerIfName == s2.VethPeerIfName &&
		netutils.EqualIPNets(s.IPv4Subnet, s2.IPv4Subnet) &&
		netutils.EqualIPNets(s.IPv6Subnet, s2.IPv6Subnet) &&
		generics.EqualSetsFn(s.StaticEntries, s2.StaticEntries, equalMACToIPs) &&
		s.IPv4Range.FromIP.Equal(s2.IPv4Range.FromIP) &&
		s.IPv4Range.ToIP.Equal(s2.IPv4Range.ToIP) &&
		s.IPv6Range.FromIP.Equal(s2.IPv6Range.FromIP) &&
		s.IPv6Range.ToIP.Equal(s2.IPv6Range.ToIP) &&
		s.GatewayIPv4.Equal(s2.GatewayIPv4) &&
		s.DomainName == s2.DomainName &&
		generics.EqualSetsFn(s.DNSServers, s2.DNSServers, netutils.EqualIPs) &&
		s.IPv4NTPServer == s2.IPv4NTPServer &&
		s.IPv6NTPServer == s2.IPv6NTPServer &&
		s.WPAD == s2.WPAD
}

// External returns false.
func (s DhcpServer) External() bool {
	return false
}

// String describes the DHCP server config.
func (s DhcpServer) String() string {
	return fmt.Sprintf("DHCP Server: %#+v", s)
}

// Dependencies lists the veth and network namespace as dependencies.
func (s DhcpServer) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: NetNamespaceTypename,
				ItemName: normNetNsName(s.NetNamespace),
			},
			Description: "Network namespace must exist",
		},
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: VethTypename,
				ItemName: s.VethName,
			},
			Description: "veth interface must exist",
		},
	}
}

// DhcpServerConfigurator implements Configurator interface for DhcpServer.
type DhcpServerConfigurator struct{}

// Create starts dnsmasq (in DHCP-only mode).
func (c *DhcpServerConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	config := item.(DhcpServer)
	if err := c.createDnsmasqConfFile(config); err != nil {
		return err
	}
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		err := startDnsmasq(dhcpSrvNamePrefix+config.ServerName, config.NetNamespace)
		done(err)
	}()
	return nil
}

func (c *DhcpServerConfigurator) createDnsmasqConfFile(server DhcpServer) error {
	if err := ensureDir(dnsmasqConfDir); err != nil {
		return err
	}
	srvName := dhcpSrvNamePrefix + server.ServerName
	cfgPath := dnsmasqConfigPath(srvName)
	f, err := os.Create(cfgPath)
	if err != nil {
		err = fmt.Errorf("failed to create config file %s: %w", cfgPath, err)
		log.Error(err)
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warnf("Failed to close config file %s: %v", cfgPath, cerr)
		}
	}()

	writeLine := func(format string, args ...interface{}) error {
		if _, err := fmt.Fprintf(f, format, args...); err != nil {
			err = fmt.Errorf("failed to write config file %s: %w", cfgPath, err)
			log.Error(err)
			return err
		}
		return nil
	}

	// Base configuration
	if err := writeLine("pid-file=%s\n", dnsmasqPidFile(srvName)); err != nil {
		return err
	}
	if err := writeLine("dhcp-leasefile=%s\n", dnsmasqLeaseFile(srvName)); err != nil {
		return err
	}
	if err := writeLine("log-dhcp\n"); err != nil {
		return err
	}
	if err := writeLine("log-facility=%s\n", dnsmasqLogFile(srvName)); err != nil {
		return err
	}
	// To disable dnsmasq's DNS server functionality.
	if err := writeLine("port=0\n"); err != nil {
		return err
	}
	if err := writeLine("interface=%s\n", server.VethPeerIfName); err != nil {
		return err
	}

	// IPv4 DHCP range
	if server.IPv4Subnet != nil {
		start4 := server.IPv4Range.FromIP.String()
		end4 := server.IPv4Range.ToIP.String()
		leaseTime := "1h"
		if server.IPv4LeaseTime > 0 {
			leaseTime = fmt.Sprintf("%ds", int(server.IPv4LeaseTime.Seconds()))
		}
		if err := writeLine("dhcp-range=%s,%s,%s\n", start4, end4, leaseTime); err != nil {
			return err
		}

		if server.GatewayIPv4 != nil {
			// DHCP option 3.
			if err := writeLine("dhcp-option=option:router,%s\n", server.GatewayIPv4.String()); err != nil {
				return err
			}
		}
		if server.DomainName != "" {
			// DHCP option 15.
			if err := writeLine("dhcp-option=option:domain-name,%s\n", server.DomainName); err != nil {
				return err
			}
		}
		if server.IPv4NTPServer != "" {
			// DHCP option 42.
			if err := writeLine("dhcp-option=option:ntp-server,%s\n", server.IPv4NTPServer); err != nil {
				return err
			}
		}
		if server.WPAD != "" {
			// DHCP option 252: WPAD.
			if err := writeLine("dhcp-option=252,%s\n", server.WPAD); err != nil {
				return err
			}
		}
	}

	// IPv6 DHCP range
	if server.IPv6Subnet != nil {
		start6 := server.IPv6Range.FromIP.String()
		end6 := server.IPv6Range.ToIP.String()
		prefixLen, _ := server.IPv6Subnet.Mask.Size()
		leaseTime6 := "1h"
		if server.IPv6LeaseTime > 0 {
			leaseTime6 = fmt.Sprintf("%ds", int(server.IPv6LeaseTime.Seconds()))
		}
		if err := writeLine("dhcp-range=%s,%s,%d,%s\n", start6, end6, prefixLen, leaseTime6); err != nil {
			return err
		}

		if server.DomainName != "" {
			// DHCPv6 option 24.
			if err := writeLine("dhcp-option=option6:domain-search,%s\n", server.DomainName); err != nil {
				return err
			}
		}
		if server.IPv6NTPServer != "" {
			// DHCPv6 option 56.
			if err := writeLine("dhcp-option=option6:ntp-server,[%s]\n", server.IPv6NTPServer); err != nil {
				return err
			}
		}
	}

	// DNS servers
	var dns4 []string
	var dns6 []string
	for _, dns := range server.DNSServers {
		if dns.To4() != nil {
			dns4 = append(dns4, dns.String())
		} else {
			dns6 = append(dns6, fmt.Sprintf("[%s]", dns.String()))
		}
	}
	if len(dns4) > 0 && server.IPv4Subnet != nil {
		// DHCP option 6.
		if err := writeLine("dhcp-option=option:dns-server,%s\n", strings.Join(dns4, ",")); err != nil {
			return err
		}
	}
	if len(dns6) > 0 && server.IPv6Subnet != nil {
		// DHCPv6 option 23.
		if err := writeLine("dhcp-option=option6:dns-server,%s\n", strings.Join(dns6, ",")); err != nil {
			return err
		}
	}

	// Static host entries
	for _, entry := range server.StaticEntries {
		mac := entry.MAC.String()
		ip := entry.IP.String()
		if entry.IP.To4() != nil {
			if err := writeLine("dhcp-host=%s,%s\n", mac, ip); err != nil {
				return err
			}
		} else {
			if err := writeLine("dhcp-host=%s,[%s]\n", mac, ip); err != nil {
				return err
			}
		}
	}

	if err = f.Sync(); err != nil {
		err = fmt.Errorf("failed to sync config file %s: %w", cfgPath, err)
		log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented.
func (c *DhcpServerConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete stops dnsmasq.
func (c *DhcpServerConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	config := item.(DhcpServer)
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		srvName := dhcpSrvNamePrefix + config.ServerName
		err := stopDnsmasq(srvName)
		if err == nil {
			// ignore errors from here
			_ = removeDnsmasqConfFile(srvName)
			_ = removeDnsmasqLeaseFile(srvName)
			_ = removeDnsmasqLogFile(srvName)
			_ = removeDnsmasqPidFile(srvName)
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *DhcpServerConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}

func dnsmasqConfigPath(srvName string) string {
	return filepath.Join(dnsmasqConfDir, srvName+".conf")
}

func dnsmasqPidFile(srvName string) string {
	return filepath.Join(dnsmasqRunDir, srvName+".pid")
}

func dnsmasqLogFile(srvName string) string {
	return filepath.Join(dnsmasqRunDir, srvName+".log")
}

func dnsmasqLeaseFile(srvName string) string {
	return filepath.Join(dnsmasqRunDir, srvName+".leases")
}

func startDnsmasq(srvName, netNamespace string) error {
	if err := ensureDir(dnsmasqRunDir); err != nil {
		return err
	}
	cmd := "nohup"
	cfgPath := dnsmasqConfigPath(srvName)
	args := []string{
		dnsmasqBinary,
		"-C",
		cfgPath,
	}
	pidFile := dnsmasqPidFile(srvName)
	// Do not run in background - dnsmasq will detach itself.
	return startProcess(netNamespace, cmd, args, pidFile, "", dnsmasqStartTimeout,
		false, false)
}

func startProcess(netNamespace, cmd string, args []string, pidFile string,
	outputFile string, timeout time.Duration, makePIDFile, background bool) error {

	startTime := time.Now()
	execCmd := namespacedCmd(netNamespace, cmd, args...)

	if background {
		// Redirect output if requested
		if outputFile != "" {
			if err := ensureDir(filepath.Dir(outputFile)); err != nil {
				return err
			}
			f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				return fmt.Errorf("failed to open output file %s: %w", outputFile, err)
			}
			// Do not defer Close(): process owns the FD now
			execCmd.Stdout = f
			execCmd.Stderr = f
		}

		if err := execCmd.Start(); err != nil {
			err = fmt.Errorf("failed to start command %s (args: %v): %w",
				cmd, args, err)
			log.Error(err)
			return err
		}

		if makePIDFile {
			if err := ensureDir(filepath.Dir(pidFile)); err != nil {
				return err
			}
			pid := fmt.Sprintf("%d\n", execCmd.Process.Pid)
			if err := os.WriteFile(pidFile, []byte(pid), 0o644); err != nil {
				return fmt.Errorf("failed to write pidfile %s: %w", pidFile, err)
			}
		}
	} else {
		// Run in the foreground (used for self-daemonizing processes)
		if makePIDFile {
			return errors.New(
				"cannot create PID file: process daemonizes itself; " +
					"PID must be provided by the process",
			)
		}
		if outputFile != "" {
			return errors.New(
				"outputFile is not supported for foreground execution",
			)
		}

		out, err := execCmd.CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to start command %s (args: %v): %s",
				cmd, args, out)
			log.Error(err)
			return err
		}
	}

	// Wait for the process to start
	for !isProcessRunning(pidFile) {
		if time.Since(startTime) > timeout {
			err := fmt.Errorf("command %s (args: %v) failed to start in time",
				cmd, args)
			log.Error(err)
			return err
		}
		time.Sleep(1 * time.Second)
	}

	return nil
}

func removeDnsmasqConfFile(srvName string) error {
	cfgPath := dnsmasqConfigPath(srvName)
	if err := os.Remove(cfgPath); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq config %s: %w",
			cfgPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeDnsmasqPidFile(srvName string) error {
	pidPath := dnsmasqPidFile(srvName)
	if err := os.Remove(pidPath); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq PID file %s: %w",
			pidPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeDnsmasqLogFile(srvName string) error {
	logPath := dnsmasqLogFile(srvName)
	if err := os.Remove(logPath); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq log file %s: %w",
			logPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeDnsmasqLeaseFile(srvName string) error {
	leasePath := dnsmasqLeaseFile(srvName)
	if err := os.Remove(leasePath); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq lease file %s: %w",
			leasePath, err)
		log.Error(err)
		return err
	}
	return nil
}

func stopDnsmasq(srvName string) error {
	pidFile := dnsmasqPidFile(srvName)
	return stopProcess(pidFile, dnsmasqStopTimeout)
}

func stopProcess(pidFile string, timeout time.Duration) error {
	process := getProcess(pidFile)
	if process == nil {
		err := fmt.Errorf("process pid-file=%s is not running", pidFile)
		log.Error(err)
		return err
	}
	stopTime := time.Now()
	err := process.Signal(syscall.SIGTERM)
	if err != nil {
		err := fmt.Errorf("SIGTERM signal sent to process pid-file=%s failed: %w",
			pidFile, err)
		log.Error(err)
		return err
	}
	// Wait for the process to stop.
	for isProcessRunning(pidFile) {
		if time.Since(stopTime) > timeout {
			err := fmt.Errorf("process pid-file=%s failed to stop in time", pidFile)
			log.Error(err)
			return err
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

func isProcessRunning(pidFile string) bool {
	process := getProcess(pidFile)
	if process == nil {
		return false
	}
	err := process.Signal(syscall.Signal(0))
	if err != nil {
		log.Errorf("isProcessRunning(%s): signal failed %s", pidFile, err)
		return false
	}
	return true
}

func getProcess(pidFile string) (process *os.Process) {
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		// Not running, return nil.
		return nil
	}
	pidStr := strings.TrimSpace(string(pidBytes))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		log.Errorf("getProcess(%s): strconv.Atoi of %s failed: %v",
			pidFile, pidStr, err)
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		log.Errorf("getProcess(%s): process PID=%d not found: %v",
			pidFile, pid, err)
		return nil
	}
	return p
}
