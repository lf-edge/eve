// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// Put config and PID files into the run directory of zedrouter.
const zedrouterRunDir = "/run/zedrouter"

// Dnsmasq : DNS and DHCP server (https://thekelleys.org.uk/dnsmasq/doc.html).
type Dnsmasq struct {
	// ForNI : UUID of the Network Instance for which this Dnsmasq instance is created.
	// Mostly used just to force re-start of Dnsmasq when one NI is being deleted
	// and subsequently another is created with the same ListenIf + DNS/DHCP parameters
	// (ForNI will differ in such case).
	ForNI uuid.UUID
	// ListenIf : interface on which dnsmasq should listen.
	ListenIf NetworkIf
	// DHCPServer : part of the dnsmasq config specific to DHCP server.
	DHCPServer DHCPServer
	// DNSServer : part of the dnsmasq config specific to DNS server.
	DNSServer DNSServer
}

// DHCPServer : part of the dnsmasq config specific to DHCP server.
type DHCPServer struct {
	// Subnet : network address + netmask (IPv4 or IPv6).
	Subnet *net.IPNet
	// AllOnesNetmask : if enabled, DHCP server will advertise netmask with all bits
	// set to one (e.g. /32 for IPv4) instead of using the actual netmask from Subnet.
	// This together with Classless routes (routing traffic for the actual Subnet)
	// can be used to force all traffic to go through the configured GatewayIP
	// (where ACLs could be applied).
	AllOnesNetmask bool
	// IPRange : a range of IP addresses to allocate from.
	// Not applicable for IPv6 (SLAAC is used instead).
	IPRange IPRange
	// GatewayIP : address of the default gateway to advertise (DHCP option 3).
	// Optional argument, leave empty to disable.
	GatewayIP net.IP
	// DomainName : name of the domain assigned to the network.
	// It is propagated to clients using the DHCP option 15 (24 in DHCPv6).
	DomainName string
	// DNSServers : list of IP addresses of DNS servers to announce via DHCP option 6.
	// dnsmasq itself may or may not be part of this list. If empty, dnsmasq will not
	// announce itself as a DNS server!
	DNSServers []net.IP
	// NTP servers to announce via DHCP option 42 (56 in DHCPv6).
	NTPServers []net.IP
	// StaticEntries : list of MAC->(IP,hostname) entries statically configured
	// for the DHCP server.
	StaticEntries []MACToIP
}

// String describes DHCPServer config.
func (d DHCPServer) String() string {
	return fmt.Sprintf("DHCPServer: {subnet: %s, allOnesNetmask: %t, ipRange: <%s-%s>, "+
		"gatewayIP: %s, domainName: %s, dnsServers: %v, ntpServers: %v, staticEntries: %v}",
		d.Subnet, d.AllOnesNetmask, d.IPRange.FromIP, d.IPRange.ToIP, d.GatewayIP,
		d.DomainName, d.DNSServers, d.NTPServers, d.StaticEntries)
}

// Equal compares two DHCPServer instances
func (d DHCPServer) Equal(d2 DHCPServer, withStaticEntries bool) bool {
	return netutils.EqualIPNets(d.Subnet, d2.Subnet) &&
		d.AllOnesNetmask == d2.AllOnesNetmask &&
		netutils.EqualIPs(d.IPRange.FromIP, d2.IPRange.FromIP) &&
		netutils.EqualIPs(d.IPRange.ToIP, d2.IPRange.ToIP) &&
		netutils.EqualIPs(d.GatewayIP, d2.GatewayIP) &&
		d.DomainName == d2.DomainName &&
		generics.EqualSetsFn(d.DNSServers, d2.DNSServers, netutils.EqualIPs) &&
		generics.EqualSetsFn(d.NTPServers, d2.NTPServers, netutils.EqualIPs) &&
		(!withStaticEntries ||
			generics.EqualSetsFn(d.StaticEntries, d2.StaticEntries, equalMACToIP))
}

// DNSServer : part of the dnsmasq config specific to DNS server.
type DNSServer struct {
	// ListenIP : IP address (assigned to Dnsmasq.ListenIf) on which the DNS server
	// should listen.
	ListenIP net.IP
	// UplinkIf : uplink interface used to contact UpstreamServers.
	// Optional argument, leave zero value for NI without uplink.
	UplinkIf NetworkIf
	// UpstreamServers : list of IP addresses of public DNS servers to forward
	// requests to (unless there is a static entry).
	UpstreamServers []net.IP
	// StaticEntries : list of hostname->IP entries statically configured
	// for the DNS server.
	StaticEntries []HostnameToIP
	// LinuxIPSets : netfilter ipsets which dnsmasq will automatically fill with
	// resolved IPs.
	// Feature specific to Linux network stack. In zedrouter used for ACLs with hostnames.
	// For different network stacks we are likely going to need to come up with a different
	// way of implementing hostname-referencing ACLs.
	LinuxIPSets []LinuxIPSet
}

// String describes DNSServer config.
func (d DNSServer) String() string {
	return fmt.Sprintf("DNSServer: {listenIP: %s, uplinkIf: %s, upstreamServers: %v, "+
		"staticEntries: %v, linuxIPSets: %v}",
		d.ListenIP, d.UplinkIf.IfName, d.UpstreamServers, d.StaticEntries, d.LinuxIPSets)
}

// Equal compares two DNSServer instances
func (d DNSServer) Equal(d2 DNSServer, withStaticEntries bool) bool {
	return netutils.EqualIPs(d.ListenIP, d2.ListenIP) &&
		d.UplinkIf == d2.UplinkIf &&
		generics.EqualSetsFn(d.UpstreamServers, d2.UpstreamServers, netutils.EqualIPs) &&
		generics.EqualSetsFn(d.LinuxIPSets, d2.LinuxIPSets, equalLinuxIPSet) &&
		(!withStaticEntries ||
			generics.EqualSetsFn(d.StaticEntries, d2.StaticEntries, equalHostnameToIP))
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
	MAC      net.HardwareAddr
	IP       net.IP
	Hostname string
}

func equalMACToIP(a, b MACToIP) bool {
	return bytes.Equal(a.MAC, b.MAC) &&
		netutils.EqualIPs(a.IP, b.IP) &&
		a.Hostname == b.Hostname
}

// HostnameToIP maps hostname to IP address.
type HostnameToIP struct {
	Hostname string
	IP       net.IP
}

func equalHostnameToIP(a, b HostnameToIP) bool {
	return a.Hostname == b.Hostname &&
		netutils.EqualIPs(a.IP, b.IP)
}

// LinuxIPSet : see https://www.netfilter.org/projects/ipset/index.html
type LinuxIPSet struct {
	// Domains : list of domains whose resolved IPs will be added to Sets.
	Domains []string
	// Sets : ipsets where IPs of Domains will be put into.
	Sets []string
}

func equalLinuxIPSet(a, b LinuxIPSet) bool {
	return generics.EqualSets(a.Domains, b.Domains) &&
		generics.EqualSets(a.Sets, b.Sets)
}

// NetworkIf : network interface used by dnsmasq.
type NetworkIf struct {
	// IfName : name of the interface in the network stack.
	IfName string
	// ItemRef : reference to config item representing the interface.
	ItemRef dg.ItemRef
}

// NetworkIfWithIP should be implemented by the item representing network interface
// on which dnsmasq is supposed to listen.
type NetworkIfWithIP interface {
	// GetAssignedIPs : return IP addresses with subnets currently assigned to the network
	// interface.
	GetAssignedIPs() []*net.IPNet
}

// Name returns the interface name on which Dnsmasq listens.
// This ensures that there cannot be two different Dnsmasq instances
// that would attempt to listen on the same interface at the same time.
func (d Dnsmasq) Name() string {
	return d.ListenIf.IfName
}

// Label for the dnsmasq instance.
func (d Dnsmasq) Label() string {
	return "dnsmasq for " + d.ListenIf.IfName
}

// Type of the item.
func (d Dnsmasq) Type() string {
	return DnsmasqTypename
}

// Equal compares two Dnsmasq instances
func (d Dnsmasq) Equal(other dg.Item) bool {
	d2 := other.(Dnsmasq)
	return d.ForNI == d2.ForNI &&
		d.ListenIf == d2.ListenIf &&
		d.DNSServer.Equal(d2.DNSServer, true) &&
		d.DHCPServer.Equal(d2.DHCPServer, true)
}

// External returns false.
func (d Dnsmasq) External() bool {
	return false
}

// String describes the dnsmasq instance.
func (d Dnsmasq) String() string {
	return fmt.Sprintf("Dnsmasq: {NI: %s, listenIf: %s, %s, %s}",
		d.ForNI.String(), d.ListenIf.IfName, d.DHCPServer, d.DNSServer)
}

// Dependencies returns:
//   - the (downlink) interface and the IP on which the dnsmasq listens
//   - the (uplink) interface used by dnsmasq to contact upstream DNS servers (if any)
//   - every referenced ipset
func (d Dnsmasq) Dependencies() (deps []dg.Dependency) {
	deps = append(deps, dg.Dependency{
		RequiredItem: d.ListenIf.ItemRef,
		Description: "interface on which dnsmasq listens must exist " +
			"and have ListenIP assigned",
		MustSatisfy: func(item dg.Item) bool {
			netIfWithIP, isNetIfWithIP := item.(NetworkIfWithIP)
			if !isNetIfWithIP {
				// Should be unreachable.
				return false
			}
			ips := netIfWithIP.GetAssignedIPs()
			for _, ip := range ips {
				if d.DNSServer.ListenIP.Equal(ip.IP) {
					return true
				}
			}
			return false
		},
	})
	if d.DNSServer.UplinkIf.IfName != "" {
		deps = append(deps, dg.Dependency{
			RequiredItem: d.DNSServer.UplinkIf.ItemRef,
			Description: "interface used by dnsmasq to contact upstream " +
				"DNS servers must exist",
		})
	}
	for _, ipset := range d.DNSServer.LinuxIPSets {
		for _, setName := range ipset.Sets {
			deps = append(deps, dg.Dependency{
				RequiredItem: dg.ItemRef{
					ItemType: IPSetTypename,
					ItemName: setName,
				},
				Description: "ipset must exist",
			})
		}
	}
	return deps
}

const (
	dnsmasqBinary       = "/opt/zededa/bin/dnsmasq"
	dnsmasqStartTimeout = 3 * time.Second
	dnsmasqStopTimeout  = 30 * time.Second
)

const (
	dnsmasqStaticConfig = `
# Automatically generated by zedrouter
except-interface=lo
bind-interfaces
quiet-dhcp
quiet-dhcp6
no-hosts
no-ping
bogus-priv
neg-ttl=10
dhcp-ttl=600
`
)

// DnsmasqConfigurator implements Configurator interface (libs/reconciler) for dnsmasq.
type DnsmasqConfigurator struct {
	Log    *base.LogObject
	Logger *logrus.Logger
}

// Create starts dnsmasq.
func (c *DnsmasqConfigurator) Create(ctx context.Context, item dg.Item) error {
	dnsmasq, isDnsmasq := item.(Dnsmasq)
	if !isDnsmasq {
		return fmt.Errorf("invalid item type %T, expected Dnsmasq", item)
	}
	if err := c.createDnsmasqConfigFile(dnsmasq); err != nil {
		return err
	}
	if err := ensureDir(c.Log, c.dnsmasqDHCPHostsDir(dnsmasq.Name())); err != nil {
		return err
	}
	if err := ensureDir(c.Log, c.dnsmasqDNSHostsDir(dnsmasq.Name())); err != nil {
		return err
	}
	if err := ensureDir(c.Log, devicenetwork.DnsmasqLeaseDir); err != nil {
		return err
	}
	for _, host := range dnsmasq.DHCPServer.StaticEntries {
		if err := c.addDHCPHostFile(dnsmasq.Name(), host); err != nil {
			return err
		}
	}
	for _, host := range dnsmasq.DNSServer.StaticEntries {
		if err := c.addDNSHostFile(dnsmasq.Name(), host); err != nil {
			return err
		}
	}
	// TODO: cleanup obsolete leases?
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		err := c.startDnsmasq(ctx, dnsmasq.Name())
		done(err)
	}()
	return nil
}

// Modify is able to update DHCP/DNS hosts files and apply the changes simply by sending
// the SIGHUP signal, i.e. without having to restart the dnsmasq process.
func (c *DnsmasqConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	oldDnsmasq, isDnsmasq := oldItem.(Dnsmasq)
	if !isDnsmasq {
		return fmt.Errorf("invalid item type %T, expected Dnsmasq", oldItem)
	}
	newDnsmasq, isDnsmasq := newItem.(Dnsmasq)
	if !isDnsmasq {
		return fmt.Errorf("invalid item type %T, expected Dnsmasq", newItem)
	}
	obsoleteDHCPHosts, newDHCPHosts := generics.DiffSetsFn(
		oldDnsmasq.DHCPServer.StaticEntries, newDnsmasq.DHCPServer.StaticEntries,
		equalMACToIP)
	for _, host := range obsoleteDHCPHosts {
		if err := c.delDHCPHostFile(oldDnsmasq.Name(), host); err != nil {
			return err
		}
	}
	for _, host := range newDHCPHosts {
		if err := c.addDHCPHostFile(newDnsmasq.Name(), host); err != nil {
			return err
		}
	}
	obsoleteDNSHosts, newDNSHosts := generics.DiffSetsFn(
		oldDnsmasq.DNSServer.StaticEntries, newDnsmasq.DNSServer.StaticEntries,
		equalHostnameToIP)
	for _, host := range obsoleteDNSHosts {
		if err := c.delDNSHostFile(oldDnsmasq.Name(), host); err != nil {
			return err
		}
	}
	for _, host := range newDNSHosts {
		if err := c.addDNSHostFile(newDnsmasq.Name(), host); err != nil {
			return err
		}
	}
	pidFile := c.dnsmasqPidFile(newDnsmasq.Name())
	return sendSignalToProcess(c.Log, pidFile, syscall.SIGHUP)
}

// Delete stops dnsmasq.
func (c *DnsmasqConfigurator) Delete(ctx context.Context, item dg.Item) error {
	dnsmasq, isDnsmasq := item.(Dnsmasq)
	if !isDnsmasq {
		return fmt.Errorf("invalid item type %T, expected Dnsmasq", item)
	}
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		err := c.stopDnsmasq(ctx, dnsmasq.Name())
		if err == nil {
			// Ignore errors from here.
			_ = c.removeDnsmasqConfigFile(dnsmasq.Name())
			_ = c.removeDnsmasqLeaseFile(dnsmasq.ListenIf.IfName)
			_ = c.removeDnsmasqPidFile(dnsmasq.Name())
			_ = c.removeDnsmasqDHCPHostDir(dnsmasq.Name())
			_ = c.removeDnsmasqDNSHostDir(dnsmasq.Name())
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate returns false if only DHCP/DNS hosts files have changed.
func (c *DnsmasqConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	oldDnsmasq, isDnsmasq := oldItem.(Dnsmasq)
	if !isDnsmasq {
		return false
	}
	newDnsmasq, isDnsmasq := newItem.(Dnsmasq)
	if !isDnsmasq {
		return false
	}
	return oldDnsmasq.ForNI != newDnsmasq.ForNI ||
		oldDnsmasq.ListenIf != newDnsmasq.ListenIf ||
		!oldDnsmasq.DNSServer.Equal(newDnsmasq.DNSServer, false) ||
		!oldDnsmasq.DHCPServer.Equal(newDnsmasq.DHCPServer, false)
}

func (c *DnsmasqConfigurator) dnsmasqConfigPath(instanceName string) string {
	return filepath.Join(zedrouterRunDir, "dnsmasq."+instanceName+".conf")
}

func (c *DnsmasqConfigurator) dnsmasqPidFile(instanceName string) string {
	return filepath.Join(zedrouterRunDir, "dnsmasq."+instanceName+".pid")
}

func (c *DnsmasqConfigurator) dnsmasqDHCPHostsDir(instanceName string) string {
	return filepath.Join(zedrouterRunDir, "dhcp-hosts."+instanceName)
}

func (c *DnsmasqConfigurator) dnsmasqDNSHostsDir(instanceName string) string {
	return filepath.Join(zedrouterRunDir, "hosts."+instanceName)
}

func (c *DnsmasqConfigurator) createDnsmasqConfigFile(dnsmasq Dnsmasq) error {
	cfgFilename := c.dnsmasqConfigPath(dnsmasq.Name())
	file, err := os.Create(cfgFilename)
	if err != nil {
		err = fmt.Errorf("failed to create dnsmasq config file %s: %w", cfgFilename, err)
		c.Log.Error(err)
		return err
	}
	defer file.Close()
	return c.CreateDnsmasqConfig(file, dnsmasq)
}

// CreateDnsmasqConfig builds configuration for dnsmasq and writes it to the given buffer.
// The method is exported just to be exercised by unit tests.
func (c *DnsmasqConfigurator) CreateDnsmasqConfig(buffer io.Writer, dnsmasq Dnsmasq) error {
	writeErr := func(err error) error {
		err = fmt.Errorf("failed to write dnsmasq config: %w", err)
		c.Log.Error(err)
		return err
	}
	if _, err := io.WriteString(buffer, dnsmasqStaticConfig); err != nil {
		return writeErr(err)
	}
	// XXX Have a look at zedrouter's loglevel.
	// Perhaps we should introduce a separate logger for dnsmasq or per bridge
	// to have more fine-grained control.
	switch c.Logger.GetLevel() {
	case logrus.TraceLevel:
		if _, err := io.WriteString(buffer, "log-queries\n"); err != nil {
			return writeErr(err)
		}
		if _, err := io.WriteString(buffer, "log-dhcp\n"); err != nil {
			return writeErr(err)
		}
	case logrus.DebugLevel:
		if _, err := io.WriteString(buffer, "log-dhcp\n"); err != nil {
			return writeErr(err)
		}
	}

	leaseFilepath := devicenetwork.DnsmasqLeaseFilePath(dnsmasq.ListenIf.IfName)
	if _, err := io.WriteString(buffer,
		fmt.Sprintf("dhcp-leasefile=%s\n", leaseFilepath)); err != nil {
		return writeErr(err)
	}

	// Decide where dnsmasq should send DNS requests upstream.
	// If we have no uplink for the associated network instance then this is nowhere.
	// If we have an uplink but no UpstreamServers for it, then we let
	// dnsmasq use the host's /etc/resolv.conf
	uplink := dnsmasq.DNSServer.UplinkIf.IfName
	if uplink == "" {
		if _, err := io.WriteString(buffer, "no-resolv\n"); err != nil {
			return writeErr(err)
		}
	} else if len(dnsmasq.DNSServer.UpstreamServers) != 0 {
		for _, s := range dnsmasq.DNSServer.UpstreamServers {
			_, err := io.WriteString(buffer, fmt.Sprintf("server=%s@%s\n", s, uplink))
			if err != nil {
				return writeErr(err)
			}
		}
		if _, err := io.WriteString(buffer, "no-resolv\n"); err != nil {
			return writeErr(err)
		}
	}

	for _, ipset := range dnsmasq.DNSServer.LinuxIPSets {
		if _, err := io.WriteString(buffer,
			fmt.Sprintf("ipset=/%s/%s\n",
				strings.Join(ipset.Domains, "/"),
				strings.Join(ipset.Sets, ","))); err != nil {
			return writeErr(err)
		}
	}

	pidFile := c.dnsmasqPidFile(dnsmasq.Name())
	if _, err := io.WriteString(buffer,
		fmt.Sprintf("pid-file=%s\n", pidFile)); err != nil {
		return writeErr(err)
	}

	if _, err := io.WriteString(buffer,
		fmt.Sprintf("interface=%s\n", dnsmasq.ListenIf.IfName)); err != nil {
		return writeErr(err)
	}
	isIPv6 := false
	listenIP := dnsmasq.DNSServer.ListenIP
	if listenIP != nil {
		isIPv6 = listenIP.To4() == nil
		if _, err := io.WriteString(buffer,
			fmt.Sprintf("listen-address=%s\n", listenIP)); err != nil {
			return writeErr(err)
		}
	} else {
		// XXX Error if there is no ListenIP?
	}

	hostsDir := c.dnsmasqDNSHostsDir(dnsmasq.Name())
	if _, err := io.WriteString(buffer,
		fmt.Sprintf("hostsdir=%s\n", hostsDir)); err != nil {
		return writeErr(err)
	}
	hostsDir = c.dnsmasqDHCPHostsDir(dnsmasq.Name())
	if _, err := io.WriteString(buffer,
		fmt.Sprintf("dhcp-hostsdir=%s\n", hostsDir)); err != nil {
		return writeErr(err)
	}

	if dnsmasq.DHCPServer.DomainName != "" {
		if isIPv6 {
			if _, err := io.WriteString(buffer,
				fmt.Sprintf("dhcp-option=option:domain-search,%s\n",
					dnsmasq.DHCPServer.DomainName)); err != nil {
				return writeErr(err)
			}
		} else {
			if _, err := io.WriteString(buffer,
				fmt.Sprintf("dhcp-option=option:domain-name,%s\n",
					dnsmasq.DHCPServer.DomainName)); err != nil {
				return writeErr(err)
			}
		}
	}

	var dnsSrvList []string
	for _, srvIP := range dnsmasq.DHCPServer.DNSServers {
		dnsSrvList = append(dnsSrvList, srvIP.String())
	}
	if len(dnsSrvList) > 0 {
		if _, err := io.WriteString(buffer,
			fmt.Sprintf("dhcp-option=option:dns-server,%s\n",
				strings.Join(dnsSrvList, ","))); err != nil {
			return writeErr(err)
		}
	}

	var ntpSrvList []string
	for _, srvIP := range dnsmasq.DHCPServer.NTPServers {
		ntpSrvList = append(ntpSrvList, srvIP.String())
	}
	if len(ntpSrvList) != 0 {
		if _, err := io.WriteString(buffer,
			fmt.Sprintf("dhcp-option=option:ntp-server,%s\n",
				strings.Join(ntpSrvList, ","))); err != nil {
			return writeErr(err)
		}
	}

	var router string
	if dnsmasq.DHCPServer.GatewayIP != nil {
		router = dnsmasq.DHCPServer.GatewayIP.String()
	}

	hvTypeKube := base.IsHVTypeKube()
	ipv4Netmask := "255.255.255.0" // Default unless there is a Subnet
	subnet := dnsmasq.DHCPServer.Subnet
	if subnet != nil {
		ipv4Netmask = net.IP(subnet.Mask).String()
		altIPv4Netmask := ipv4Netmask
		if router != "" && dnsmasq.DHCPServer.AllOnesNetmask && !hvTypeKube {
			// Network prefix "255.255.255.255" will force packets to go through
			// dom0 virtual router that makes the packets pass through ACLs and flow log.
			altIPv4Netmask = "255.255.255.255"
		}
		if _, err := io.WriteString(buffer,
			fmt.Sprintf("dhcp-option=option:netmask,%s\n", altIPv4Netmask)); err != nil {
			return writeErr(err)
		}
	}

	if router != "" {
		// XXX IPv6 needs to be handled in radvd.
		if !isIPv6 {
			if _, err := io.WriteString(buffer,
				fmt.Sprintf("dhcp-option=option:router,%s\n",
					dnsmasq.DHCPServer.GatewayIP)); err != nil {
				return writeErr(err)
			}
			if dnsmasq.DHCPServer.AllOnesNetmask && !hvTypeKube {
				if _, err := io.WriteString(buffer,
					fmt.Sprintf(
						"dhcp-option=option:classless-static-route,%s/32,%s,%s,%s,%s,%s\n",
						router, "0.0.0.0",
						"0.0.0.0/0", router,
						subnet, router)); err != nil {
					return writeErr(err)
				}
			}
		}
	} else {
		if !isIPv6 {
			if _, err := io.WriteString(buffer,
				fmt.Sprintf("dhcp-option=option:router\n")); err != nil {
				return writeErr(err)
			}
		}
		if len(dnsSrvList) == 0 {
			// Handle isolated network by making sure we are not a DNS server.
			// Can be overridden with the DNSServers option processed above.
			if _, err := io.WriteString(buffer,
				fmt.Sprintf("dhcp-option=option:dns-server\n")); err != nil {
				return writeErr(err)
			}
		}
	}

	if isIPv6 {
		if _, err := io.WriteString(buffer, "dhcp-range=::static,0,60m\n"); err != nil {
			return writeErr(err)
		}
	} else {
		dhcpRange, err := c.CreateDHCPv4RangeConfig(
			dnsmasq.DHCPServer.IPRange.FromIP, dnsmasq.DHCPServer.IPRange.ToIP)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(buffer, fmt.Sprintf("dhcp-range=%s,%s,60m\n",
			dhcpRange, ipv4Netmask)); err != nil {
			return writeErr(err)
		}
	}
	return nil
}

// CreateDHCPv4RangeConfig prepares a DHCPv4 range config line.
// The method is exported just to be exercised by unit tests.
func (c *DnsmasqConfigurator) CreateDHCPv4RangeConfig(start, end net.IP) (string, error) {
	if start == nil {
		return "", nil
	}
	var dhcpRange string
	if end == nil {
		dhcpRange = fmt.Sprintf("%s,static", start.String())
	} else {
		if bytes.Compare(start, end) > 0 {
			err := fmt.Errorf("invalid DHCPv4 IP range: <%s,%s>", start, end)
			c.Log.Error(err)
			return "", err
		}
		// Full dhcp-range is not possible with static,
		// see https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
		dhcpRange = fmt.Sprintf("%s,%s", start, end)
	}
	return dhcpRange, nil
}

func (c *DnsmasqConfigurator) addDNSHostFile(instanceName string,
	entry HostnameToIP) error {
	hostFilename := filepath.Join(c.dnsmasqDNSHostsDir(instanceName), entry.Hostname)
	file, err := os.Create(hostFilename)
	if err != nil {
		err = fmt.Errorf("failed to create DNS host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	defer file.Close()
	_, err = file.WriteString(fmt.Sprintf("%s	%s\n", entry.IP, entry.Hostname))
	if err != nil {
		err = fmt.Errorf("failed to write into DNS host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) delDNSHostFile(instanceName string,
	entry HostnameToIP) error {
	hostFilename := filepath.Join(c.dnsmasqDNSHostsDir(instanceName), entry.Hostname)
	if err := os.Remove(hostFilename); err != nil {
		err = fmt.Errorf("failed to remove DNS host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) addDHCPHostFile(instanceName string,
	entry MACToIP) error {
	isIPv6 := entry.IP.To4() == nil
	suffix := ".inet"
	if isIPv6 {
		suffix += "6"
	}
	hostFilename := filepath.Join(c.dnsmasqDHCPHostsDir(instanceName),
		entry.MAC.String()+suffix)
	file, err := os.Create(hostFilename)
	if err != nil {
		err = fmt.Errorf("failed to create DHCP host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	defer file.Close()
	if isIPv6 {
		_, err = file.WriteString(fmt.Sprintf("%s,[%s],%s\n",
			entry.MAC, entry.IP, entry.Hostname))
	} else {
		_, err = file.WriteString(fmt.Sprintf("%s,id:*,%s,%s\n",
			entry.MAC, entry.IP, entry.Hostname))
	}
	if err != nil {
		err = fmt.Errorf("failed to write into DHCP host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) delDHCPHostFile(instanceName string,
	entry MACToIP) error {
	isIPv6 := entry.IP.To4() == nil
	suffix := ".inet"
	if isIPv6 {
		suffix += "6"
	}
	hostFilename := filepath.Join(c.dnsmasqDHCPHostsDir(instanceName),
		entry.MAC.String()+suffix)
	if err := os.Remove(hostFilename); err != nil {
		err = fmt.Errorf("failed to remove DHCP host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) startDnsmasq(ctx context.Context, instanceName string) error {
	cmd := "nohup"
	pidFile := c.dnsmasqPidFile(instanceName)
	cfgPath := c.dnsmasqConfigPath(instanceName)
	args := []string{
		dnsmasqBinary,
		"-C",
		cfgPath,
	}
	return startProcess(ctx, c.Log, cmd, args, pidFile, dnsmasqStartTimeout, true)
}

func (c *DnsmasqConfigurator) stopDnsmasq(ctx context.Context, instanceName string) error {
	pidFile := c.dnsmasqPidFile(instanceName)
	return stopProcess(ctx, c.Log, pidFile, dnsmasqStopTimeout)
}

func (c *DnsmasqConfigurator) removeDnsmasqConfigFile(instanceName string) error {
	cfgPath := c.dnsmasqConfigPath(instanceName)
	if err := os.Remove(cfgPath); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq config %s: %w",
			cfgPath, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) removeDnsmasqPidFile(instanceName string) error {
	pidPath := c.dnsmasqPidFile(instanceName)
	if err := os.Remove(pidPath); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq PID file %s: %w",
			pidPath, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) removeDnsmasqLeaseFile(listenIfName string) error {
	leaseFilepath := devicenetwork.DnsmasqLeaseFilePath(listenIfName)
	if err := os.Remove(leaseFilepath); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq lease file %s: %w",
			leaseFilepath, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) removeDnsmasqDHCPHostDir(instanceName string) error {
	hostDir := c.dnsmasqDHCPHostsDir(instanceName)
	if err := os.RemoveAll(hostDir); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq DHCP-host directory %s: %w",
			hostDir, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) removeDnsmasqDNSHostDir(instanceName string) error {
	hostDir := c.dnsmasqDNSHostsDir(instanceName)
	if err := os.RemoveAll(hostDir); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq DNS-host directory %s: %w",
			hostDir, err)
		c.Log.Error(err)
		return err
	}
	return nil
}
