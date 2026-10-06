// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	"github.com/lf-edge/eve/pkg/pillar/utils/proc"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// Put config and PID files into the run directory of zedrouter.
const zedrouterRunDir = "/run/zedrouter"

const (
	// Tag used for applications that, within a given NI, act as endpoints
	// from the IP routing perspective (i.e. not routing any traffic further).
	endpointTag = "endpoint"
	// Tag prefix used for applications that, within a given NI, serve as IP routing
	// gateways (i.e. routing some traffic between apps and external endpoints).
	gatewayTagPrefix = "gateway-"
)

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
	// IPRange : a range of IP addresses to allocate from.
	// Not applicable for IPv6 (SLAAC is used instead).
	IPRange IPRange
	// GatewayIP : address of the default gateway to advertise (DHCP option 3).
	// Optional argument, leave empty to disable.
	GatewayIP net.IP
	// WithDefaultRoute : if enabled, default route is propagated to applications.
	WithDefaultRoute bool
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
	// PropagateRoutes : IP routes to propagate to applications using the DHCP option 121
	// (classless route option).
	PropagateRoutes []IPRoute
	// MTU : Maximum transmission unit size to propagate to applications using the DHCP
	// option 26.
	MTU uint16
}

// String describes DHCPServer config.
func (d DHCPServer) String() string {
	return fmt.Sprintf("DHCPServer: {subnet: %s, ipRange: <%s-%s>, "+
		"gatewayIP: %s, withDefaultRoute: %t, domainName: %s, dnsServers: %v, ntpServers: %v, "+
		"staticEntries: %v, propagateRoutes: %v, MTU: %d}",
		d.Subnet, d.IPRange.FromIP, d.IPRange.ToIP, d.GatewayIP,
		d.WithDefaultRoute, d.DomainName, d.DNSServers, d.NTPServers, d.StaticEntries,
		d.PropagateRoutes, d.MTU)
}

// Equal compares two DHCPServer instances.
func (d DHCPServer) Equal(d2 DHCPServer, withStaticEntries, withDHCPOptions bool) bool {
	return netutils.EqualIPNets(d.Subnet, d2.Subnet) &&
		netutils.EqualIPs(d.IPRange.FromIP, d2.IPRange.FromIP) &&
		netutils.EqualIPs(d.IPRange.ToIP, d2.IPRange.ToIP) &&
		(!withDHCPOptions || d.equalDHCPOptions(d2)) &&
		(!withStaticEntries ||
			generics.EqualSetsFn(d.StaticEntries, d2.StaticEntries, equalMACToIP))
}

// equalDHCPOptions compares the fields gated by Equal's withDHCPOptions.
func (d DHCPServer) equalDHCPOptions(d2 DHCPServer) bool {
	return netutils.EqualIPs(d.GatewayIP, d2.GatewayIP) &&
		d.WithDefaultRoute == d2.WithDefaultRoute &&
		d.DomainName == d2.DomainName &&
		generics.EqualSetsFn(d.DNSServers, d2.DNSServers, netutils.EqualIPs) &&
		generics.EqualSetsFn(d.NTPServers, d2.NTPServers, netutils.EqualIPs) &&
		generics.EqualSetsFn(d.PropagateRoutes, d2.PropagateRoutes, EqualIPRoutes) &&
		d.MTU == d2.MTU
}

// DNSServer : part of the dnsmasq config specific to DNS server.
type DNSServer struct {
	// ListenIP : IP address (assigned to Dnsmasq.ListenIf) on which the DNS server
	// should listen.
	ListenIP net.IP
	// UpstreamServers : list of external DNS servers to forward requests to
	// (unless there is a static or cached entry).
	UpstreamServers []UpstreamDNSServer
	// StaticEntries : list of hostname->IPs entries statically configured
	// for the DNS server.
	StaticEntries []HostnameToIPs
	// LinuxIPSets : netfilter ipsets which dnsmasq will automatically fill with
	// resolved IPs.
	// Feature specific to Linux network stack. In zedrouter used for ACLs with hostnames.
	// For different network stacks we are likely going to need to come up with a different
	// way of implementing hostname-referencing ACLs.
	LinuxIPSets []LinuxIPSet
}

// UpstreamDNSServer : DNS server to which dnsmasq will forward queries that it is unable
// to handle (from its cache or from the list of static entries).
type UpstreamDNSServer struct {
	// IP address of the upstream DNS server.
	IPAddress net.IP
	// Port to use to contact the upstream DNS server.
	Port NetworkIf
}

func equalUpstreamDNSServer(a, b UpstreamDNSServer) bool {
	return netutils.EqualIPs(a.IPAddress, b.IPAddress) &&
		a.Port == b.Port
}

// String describes DNSServer config.
func (d DNSServer) String() string {
	return fmt.Sprintf("DNSServer: {listenIP: %s, upstreamServers: %v, "+
		"staticEntries: %v, linuxIPSets: %v}",
		d.ListenIP, d.UpstreamServers, d.StaticEntries, d.LinuxIPSets)
}

// Equal compares two DNSServer instances.
func (d DNSServer) Equal(d2 DNSServer, withStaticEntries, withUpstreamServers bool) bool {
	return netutils.EqualIPs(d.ListenIP, d2.ListenIP) &&
		(!withUpstreamServers ||
			generics.EqualSetsFn(d.UpstreamServers, d2.UpstreamServers, equalUpstreamDNSServer)) &&
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

// IPRoute : single IP route entry.
type IPRoute struct {
	// Destination network.
	// Cannot be nil.
	DstNetwork *net.IPNet
	// Gateway IP address.
	// Cannot be nil.
	Gateway net.IP
}

// EqualIPRoutes compares two instances of IPRoute for equality.
func EqualIPRoutes(a, b IPRoute) bool {
	return netutils.EqualIPNets(a.DstNetwork, b.DstNetwork) &&
		netutils.EqualIPs(a.Gateway, b.Gateway)
}

// HostnameToIPs maps hostname to one or more IP addresses.
type HostnameToIPs struct {
	Hostname string
	IPs      []net.IP
}

func equalHostnameToIP(a, b HostnameToIPs) bool {
	return a.Hostname == b.Hostname &&
		generics.EqualSetsFn(a.IPs, b.IPs, netutils.EqualIPs)
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
		d.DNSServer.Equal(d2.DNSServer, true, true) &&
		d.DHCPServer.Equal(d2.DHCPServer, true, true)
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
//   - the (bridge) interface and the IP on which the dnsmasq listens
//   - the (device port) interface used by dnsmasq to contact upstream DNS servers (if any)
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
	var ports []NetworkIf
	for _, upstreamSrv := range d.DNSServer.UpstreamServers {
		ports = append(ports, upstreamSrv.Port)
	}
	ports = generics.FilterDuplicates(ports)
	for _, port := range ports {
		deps = append(deps, dg.Dependency{
			RequiredItem: port.ItemRef,
			Description: "port used by dnsmasq to contact upstream " +
				"DNS server must exist",
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
	dnsmasqBinary       = "/usr/sbin/dnsmasq"
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
	if err := c.writeDnsmasqServersFile(dnsmasq); err != nil {
		return err
	}
	if err := c.writeDnsmasqOptsFile(dnsmasq); err != nil {
		return err
	}
	if err := fileutils.EnsureDir(c.dnsmasqDHCPHostsDir(dnsmasq.Name())); err != nil {
		c.Log.Error(err)
		return err
	}
	if err := fileutils.EnsureDir(c.dnsmasqDNSHostsDir(dnsmasq.Name())); err != nil {
		c.Log.Error(err)
		return err
	}
	if err := fileutils.EnsureDir(types.DnsmasqLeaseDir); err != nil {
		c.Log.Error(err)
		return err
	}
	for _, host := range dnsmasq.DHCPServer.StaticEntries {
		if err := c.addDHCPHostFile(dnsmasq, host); err != nil {
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

// Modify rewrites the servers file (upstream DNS servers, e.g. after a port's
// DNS servers changed), the dhcp-optsfile (e.g. after a port's default route
// appeared/disappeared) and applies host-file changes. Pure additions (new
// app, no app removed and no app re-assigned a different IP) are reloaded
// with SIGHUP. If any DHCP host disappeared or changed IP we must also evict
// the matching lease from dnsmasq's in-memory state, otherwise the IP stays
// reserved for the old MAC and a future app trying to take that IP gets a
// "not using configured address" fallback. SIGHUP does not reload leases (it
// only reloads dhcp-host files and updates hostnames on existing leases), and
// dhcp_release cannot reach our dnsmasq from the host netns (see
// restartToPruneLeases), so in that case we rewrite the lease file without
// the stale entries and restart dnsmasq.
func (c *DnsmasqConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	oldDnsmasq, isDnsmasq := oldItem.(Dnsmasq)
	if !isDnsmasq {
		return fmt.Errorf("invalid item type %T, expected Dnsmasq", oldItem)
	}
	newDnsmasq, isDnsmasq := newItem.(Dnsmasq)
	if !isDnsmasq {
		return fmt.Errorf("invalid item type %T, expected Dnsmasq", newItem)
	}
	if !generics.EqualSetsFn(oldDnsmasq.DNSServer.UpstreamServers,
		newDnsmasq.DNSServer.UpstreamServers, equalUpstreamDNSServer) {
		if err := c.writeDnsmasqServersFile(newDnsmasq); err != nil {
			return err
		}
	}
	if !oldDnsmasq.DHCPServer.equalDHCPOptions(newDnsmasq.DHCPServer) {
		if err := c.writeDnsmasqOptsFile(newDnsmasq); err != nil {
			return err
		}
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
		if err := c.addDHCPHostFile(newDnsmasq, host); err != nil {
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
	if len(obsoleteDHCPHosts) > 0 {
		return c.restartToPruneLeases(ctx, newDnsmasq, obsoleteDHCPHosts)
	}
	pm := c.initProcessManager(newDnsmasq.Name())
	return pm.SendSignal(syscall.SIGHUP)
}

// restartToPruneLeases stops dnsmasq, rewrites the lease file with the entries
// for the supplied (now-obsolete) MACs removed, and starts dnsmasq back up.
// dhcp_release(8) is not usable here: it only delivers reliably on loopback,
// and our dnsmasq runs with SO_BINDTODEVICE on the bridge interface (one
// DHCP interface per NI), so DHCPRELEASE packets do not reach it. A cleaner
// long-term option would be dnsmasq's DBus DeleteDhcpLease method, but the
// pillar container has no DBus daemon today; that becomes viable once
// pillar moves to systemd.
func (c *DnsmasqConfigurator) restartToPruneLeases(
	ctx context.Context, dnsmasq Dnsmasq, obsolete []MACToIP) error {
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		if err := c.stopDnsmasq(ctx, dnsmasq.Name()); err != nil {
			done(err)
			return
		}
		if err := c.pruneDnsmasqLeases(dnsmasq.ListenIf.IfName, obsolete); err != nil {
			done(err)
			return
		}
		done(c.startDnsmasq(ctx, dnsmasq.Name()))
	}()
	return nil
}

// pruneDnsmasqLeases atomically rewrites the dnsmasq leases file for the given
// bridge, dropping any line whose MAC matches one of the supplied entries.
// Must only be called while dnsmasq is stopped, otherwise dnsmasq's open file
// descriptor would overwrite our cleaned copy on the next lease change.
//
// Lease line format (from man dnsmasq):
//
//	<expire-time> <mac> <ip> <hostname> <client-id>
func (c *DnsmasqConfigurator) pruneDnsmasqLeases(
	bridgeIfName string, obsolete []MACToIP) error {
	if len(obsolete) == 0 {
		return nil
	}
	leasePath := types.DnsmasqLeaseFilePath(bridgeIfName)
	content, err := os.ReadFile(leasePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read lease file %s: %w", leasePath, err)
	}
	macsToDrop := make(map[string]struct{}, len(obsolete))
	for _, h := range obsolete {
		macsToDrop[strings.ToLower(h.MAC.String())] = struct{}{}
	}
	var out bytes.Buffer
	changed := false
	for _, line := range strings.Split(string(content), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, " ", 3)
		if len(fields) >= 2 {
			if _, drop := macsToDrop[strings.ToLower(fields[1])]; drop {
				changed = true
				continue
			}
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if !changed {
		return nil
	}
	tmpPath := leasePath + ".tmp"
	if err := os.WriteFile(tmpPath, out.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, leasePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename %s to %s: %w", tmpPath, leasePath, err)
	}
	return nil
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
			_ = c.removeDnsmasqServersFile(dnsmasq.Name())
			_ = c.removeDnsmasqOptsFile(dnsmasq.Name())
			_ = c.removeDnsmasqLeaseFile(dnsmasq.ListenIf.IfName)
			_ = c.removeDnsmasqPidFile(dnsmasq.Name())
			_ = c.removeDnsmasqDHCPHostDir(dnsmasq.Name())
			_ = c.removeDnsmasqDNSHostDir(dnsmasq.Name())
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate returns false if only DHCP/DNS hosts files, the upstream DNS
// server list (UpstreamServers, written to a separate servers file re-read
// on SIGHUP) or the DHCP options gated by DHCPServer.Equal's withDHCPOptions
// (written to a separate dhcp-optsfile re-read on SIGHUP) have changed.
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
		!oldDnsmasq.DNSServer.Equal(newDnsmasq.DNSServer, false, false) ||
		!oldDnsmasq.DHCPServer.Equal(newDnsmasq.DHCPServer, false, false)
}

func (c *DnsmasqConfigurator) dnsmasqConfigPath(instanceName string) string {
	return filepath.Join(zedrouterRunDir, "dnsmasq."+instanceName+".conf")
}

func (c *DnsmasqConfigurator) dnsmasqPidFile(instanceName string) string {
	return filepath.Join(zedrouterRunDir, "dnsmasq."+instanceName+".pid")
}

// dnsmasqServersFile returns the path to the --servers-file, which contains
// all server= entries and is re-read on SIGHUP, allowing the upstream DNS
// server list to change without restarting dnsmasq.
func (c *DnsmasqConfigurator) dnsmasqServersFile(instanceName string) string {
	return filepath.Join(zedrouterRunDir, "dnsmasq."+instanceName+".servers")
}

// dnsmasqOptsFile returns the path to the --dhcp-optsfile, which contains
// all dhcp-option= entries and is re-read on SIGHUP, allowing DHCP options
// (e.g. the router/classless-static-route options, which depend on whether
// the port currently has a default route) to change without restarting
// dnsmasq.
func (c *DnsmasqConfigurator) dnsmasqOptsFile(instanceName string) string {
	return filepath.Join(zedrouterRunDir, "dnsmasq."+instanceName+".opts")
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

// dnsmasqIsIPv6AndNetmask returns whether dnsmasq listens on an IPv6
// address, and the IPv4 netmask string derived from DHCPServer.Subnet
// (defaulting to a /24 when Subnet is unset). Shared by CreateDnsmasqConfig
// (dhcp-range) and CreateDnsmasqOptsFile (the netmask option and static
// route building).
func (c *DnsmasqConfigurator) dnsmasqIsIPv6AndNetmask(dnsmasq Dnsmasq) (isIPv6 bool, ipv4Netmask string) {
	ipv4Netmask = "255.255.255.0" // Default unless there is a Subnet
	if listenIP := dnsmasq.DNSServer.ListenIP; listenIP != nil {
		isIPv6 = listenIP.To4() == nil
	}
	if subnet := dnsmasq.DHCPServer.Subnet; subnet != nil {
		ipv4Netmask = net.IP(subnet.Mask).String()
	}
	return isIPv6, ipv4Netmask
}

// CreateDnsmasqConfig builds the dnsmasq directives that can only take
// effect by (re)starting the process: interface/listen binding, file paths
// and dhcp-range (the IP pool, fixed by Subnet/IPRange). Per-client DHCP
// options (dhcp-option=...) go into a separate dhcp-optsfile instead,
// re-read on SIGHUP; see CreateDnsmasqOptsFile.
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

	leaseFilepath := types.DnsmasqLeaseFilePath(dnsmasq.ListenIf.IfName)
	if _, err := io.WriteString(buffer,
		fmt.Sprintf("dhcp-leasefile=%s\n", leaseFilepath)); err != nil {
		return writeErr(err)
	}

	// Upstream DNS servers (server= entries) are in a separate file re-read
	// on SIGHUP; see writeDnsmasqServersFile.
	if _, err := io.WriteString(buffer,
		fmt.Sprintf("servers-file=%s\n", c.dnsmasqServersFile(dnsmasq.Name()))); err != nil {
		return writeErr(err)
	}
	if _, err := io.WriteString(buffer, "no-resolv\n"); err != nil {
		return writeErr(err)
	}

	for _, ipset := range dnsmasq.DNSServer.LinuxIPSets {
		if _, err := io.WriteString(buffer,
			fmt.Sprintf("ipset=/%s/%s\n",
				strings.Join(ipset.Domains, "/"),
				strings.Join(ipset.Sets, ","))); err != nil {
			return writeErr(err)
		}
	}

	// Per-client DHCP options (dhcp-option=...) are in a separate file
	// re-read on SIGHUP; see writeDnsmasqOptsFile.
	if _, err := io.WriteString(buffer,
		fmt.Sprintf("dhcp-optsfile=%s\n", c.dnsmasqOptsFile(dnsmasq.Name()))); err != nil {
		return writeErr(err)
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
	if listenIP := dnsmasq.DNSServer.ListenIP; listenIP != nil {
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

	isIPv6, ipv4Netmask := c.dnsmasqIsIPv6AndNetmask(dnsmasq)
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

// CreateDnsmasqOptsFile builds the per-client DHCP options (domain name,
// DNS/NTP servers announced via DHCP, netmask, router/classless-static-route,
// MTU) read from --dhcp-optsfile. Unlike CreateDnsmasqConfig, this file is
// re-read by dnsmasq on SIGHUP, so e.g. a port's default route
// appearing/disappearing (DHCPServer.WithDefaultRoute) does not require
// restarting dnsmasq. Each line has the same format as the value of a
// dhcp-option= directive, without the "dhcp-option=" prefix.
// The method is exported just to be exercised by unit tests.
func (c *DnsmasqConfigurator) CreateDnsmasqOptsFile(buffer io.Writer, dnsmasq Dnsmasq) error {
	writeErr := func(err error) error {
		err = fmt.Errorf("failed to write dnsmasq opts file: %w", err)
		c.Log.Error(err)
		return err
	}
	isIPv6, ipv4Netmask := c.dnsmasqIsIPv6AndNetmask(dnsmasq)

	if dnsmasq.DHCPServer.DomainName != "" {
		if isIPv6 {
			if _, err := io.WriteString(buffer,
				fmt.Sprintf("option:domain-search,%s\n",
					dnsmasq.DHCPServer.DomainName)); err != nil {
				return writeErr(err)
			}
		} else {
			if _, err := io.WriteString(buffer,
				fmt.Sprintf("option:domain-name,%s\n",
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
			fmt.Sprintf("option:dns-server,%s\n",
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
			fmt.Sprintf("option:ntp-server,%s\n",
				strings.Join(ntpSrvList, ","))); err != nil {
			return writeErr(err)
		}
	}

	gatewayIP := dnsmasq.DHCPServer.GatewayIP
	subnet := dnsmasq.DHCPServer.Subnet
	if subnet != nil {
		if _, err := io.WriteString(buffer,
			fmt.Sprintf("option:netmask,%s\n", ipv4Netmask)); err != nil {
			return writeErr(err)
		}
	}

	// Prepare the set of all static routes to propagate to applications.
	var staticRoutes []IPRoute
	if !isIPv6 {
		// Use L2-forwarding between apps on the same NI.
		if subnet != nil {
			staticRoutes = append(staticRoutes, IPRoute{
				DstNetwork: subnet,
				Gateway:    net.IP{0, 0, 0, 0},
			})
		}
		staticRoutes = append(staticRoutes, dnsmasq.DHCPServer.PropagateRoutes...)
	}

	if gatewayIP != nil && dnsmasq.DHCPServer.WithDefaultRoute {
		// XXX IPv6 needs to be handled in radvd.
		if !isIPv6 {
			if _, err := io.WriteString(buffer,
				fmt.Sprintf("option:router,%s\n",
					dnsmasq.DHCPServer.GatewayIP)); err != nil {
				return writeErr(err)
			}
			// From RFC 3442:
			// If the DHCP server returns both a Classless Static Routes option and
			// a Router option, the DHCP client MUST ignore the Router option.
			//
			// This means that we have to include a default "classless" route
			// even though the Router option is provided.
			// We keep the Router option for clients that do not support the Classless
			// Static Routes option.
			_, ipv4Any, _ := net.ParseCIDR("0.0.0.0/0")
			staticRoutes = append(staticRoutes, IPRoute{
				DstNetwork: ipv4Any,
				Gateway:    gatewayIP,
			})
		}
	} else {
		if !isIPv6 {
			if _, err := io.WriteString(buffer, "option:router\n"); err != nil {
				return writeErr(err)
			}
		}
		if len(dnsSrvList) == 0 {
			// Handle isolated network by making sure we are not a DNS server.
			// Can be overridden with the DNSServers option processed above.
			if _, err := io.WriteString(buffer, "option:dns-server\n"); err != nil {
				return writeErr(err)
			}
		}
	}

	// Apply static routes to all endpoints and separately to individual gateways.
	// This is to make sure that gateway-app will not receive route that uses app's
	// own local IP as the gateway.
	var appGateways []net.IP
	for _, ipRoute := range staticRoutes {
		if subnet != nil && subnet.Contains(ipRoute.Gateway) &&
			!netutils.EqualIPs(ipRoute.Gateway, gatewayIP) {
			appGateways = append(appGateways, ipRoute.Gateway)
		}
	}
	appGateways = generics.FilterDuplicatesFn(appGateways, netutils.EqualIPs)
	if len(staticRoutes) > 0 {
		if _, err := io.WriteString(buffer,
			fmt.Sprintf("tag:%s,option:classless-static-route,%s\n",
				endpointTag, c.formatRoutesForConfig(staticRoutes))); err != nil {
			return writeErr(err)
		}
	}
	for _, appGatewayIP := range appGateways {
		tag := c.getAppGatewayTag(appGatewayIP)
		isRouteValid := func(route IPRoute) bool {
			return !netutils.EqualIPs(route.Gateway, appGatewayIP)
		}
		gwRoutes := generics.FilterList(staticRoutes, isRouteValid)
		if len(gwRoutes) > 0 {
			if _, err := io.WriteString(buffer,
				fmt.Sprintf("tag:%s,option:classless-static-route,%s\n",
					tag, c.formatRoutesForConfig(gwRoutes))); err != nil {
				return writeErr(err)
			}
		}
	}

	// Propagate MTU to applications.
	if dnsmasq.DHCPServer.MTU != 0 {
		_, err := io.WriteString(buffer,
			fmt.Sprintf("26,%d\n", dnsmasq.DHCPServer.MTU))
		if err != nil {
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

// writeDnsmasqServersFile writes all server= entries listing the upstream
// DNS servers. dnsmasq re-reads this file on SIGHUP, so a change to the
// upstream server list (e.g. a port's DNS servers changing after a DHCP
// renewal) does not require restarting dnsmasq; see NeedsRecreate.
func (c *DnsmasqConfigurator) writeDnsmasqServersFile(dnsmasq Dnsmasq) error {
	var b strings.Builder
	for _, srv := range dnsmasq.DNSServer.UpstreamServers {
		fmt.Fprintf(&b, "server=%s@%s\n", srv.IPAddress, srv.Port.IfName)
	}
	serversPath := c.dnsmasqServersFile(dnsmasq.Name())
	if err := fileutils.WriteRename(serversPath, []byte(b.String())); err != nil {
		err = fmt.Errorf("failed to write dnsmasq servers file %s: %w", serversPath, err)
		c.Log.Error(err)
		return err
	}
	// WriteRename's temp file is created with mode 0600, but dnsmasq for a NI
	// runs as nobody:nobody, so it needs the file to be world-readable to open
	// it on start or SIGHUP.
	if err := os.Chmod(serversPath, 0644); err != nil {
		err = fmt.Errorf("failed to chmod dnsmasq servers file %s: %w", serversPath, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// writeDnsmasqOptsFile writes the dhcp-optsfile content (see
// CreateDnsmasqOptsFile); dnsmasq re-reads it on SIGHUP.
func (c *DnsmasqConfigurator) writeDnsmasqOptsFile(dnsmasq Dnsmasq) error {
	var b bytes.Buffer
	if err := c.CreateDnsmasqOptsFile(&b, dnsmasq); err != nil {
		return err
	}
	optsPath := c.dnsmasqOptsFile(dnsmasq.Name())
	if err := fileutils.WriteRename(optsPath, b.Bytes()); err != nil {
		err = fmt.Errorf("failed to write dnsmasq opts file %s: %w", optsPath, err)
		c.Log.Error(err)
		return err
	}
	// Same reasoning as in writeDnsmasqServersFile: dnsmasq for a NI runs as
	// nobody:nobody, so the file must be made world-readable.
	if err := os.Chmod(optsPath, 0644); err != nil {
		err = fmt.Errorf("failed to chmod dnsmasq opts file %s: %w", optsPath, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) addDNSHostFile(instanceName string,
	entry HostnameToIPs) error {
	hostFilename := filepath.Join(c.dnsmasqDNSHostsDir(instanceName), entry.Hostname)
	file, err := os.Create(hostFilename)
	if err != nil {
		err = fmt.Errorf("failed to create DNS host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	defer file.Close()
	for _, ip := range entry.IPs {
		_, err = file.WriteString(fmt.Sprintf("%s\t%s\n", ip, entry.Hostname))
		if err != nil {
			err = fmt.Errorf("failed to write into DNS host file %s: %w",
				hostFilename, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

func (c *DnsmasqConfigurator) delDNSHostFile(instanceName string,
	entry HostnameToIPs) error {
	hostFilename := filepath.Join(c.dnsmasqDNSHostsDir(instanceName), entry.Hostname)
	if err := os.Remove(hostFilename); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.Log.Warnf("DNS host file %s not found (nothing to remove)", hostFilename)
			return nil
		}
		err = fmt.Errorf("failed to remove DNS host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) addDHCPHostFile(dnsmasq Dnsmasq, entry MACToIP) error {
	isIPv6 := entry.IP.To4() == nil
	suffix := ".inet"
	if isIPv6 {
		suffix += "6"
	}
	tag := c.dhcpTagForHost(dnsmasq.DHCPServer, entry.IP)
	hostFilename := filepath.Join(c.dnsmasqDHCPHostsDir(dnsmasq.Name()),
		entry.MAC.String()+suffix)
	file, err := os.Create(hostFilename)
	if err != nil {
		err = fmt.Errorf("failed to create DHCP host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	defer file.Close()
	if isIPv6 {
		_, err = file.WriteString(fmt.Sprintf("%s,set:%s,[%s],%s\n",
			entry.MAC, tag, entry.IP, entry.Hostname))
	} else {
		_, err = file.WriteString(fmt.Sprintf("%s,id:*,set:%s,%s,%s\n",
			entry.MAC, tag, entry.IP, entry.Hostname))
	}
	if err != nil {
		err = fmt.Errorf("failed to write into DHCP host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) dhcpTagForHost(dhcpSrv DHCPServer, hostIP net.IP) string {
	for _, ipRoute := range dhcpSrv.PropagateRoutes {
		if hostIP.Equal(ipRoute.Gateway) {
			return c.getAppGatewayTag(hostIP)
		}
	}
	return endpointTag
}

func (c *DnsmasqConfigurator) getAppGatewayTag(hostIP net.IP) string {
	ipStr := hostIP.String()
	ipStr = strings.ReplaceAll(ipStr, ":", "-")
	ipStr = strings.ReplaceAll(ipStr, ".", "-")
	return gatewayTagPrefix + ipStr
}

// Routes should be written to the dnsmasq config in one line, with comma separated
// entries formatted as [<dst-net>,<gw>]
func (c *DnsmasqConfigurator) formatRoutesForConfig(routes []IPRoute) string {
	var cfgEntries []string
	for _, route := range routes {
		entry := fmt.Sprintf("%s,%s", route.DstNetwork, route.Gateway)
		cfgEntries = append(cfgEntries, entry)
	}
	return strings.Join(cfgEntries, ",")
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
		if errors.Is(err, os.ErrNotExist) {
			c.Log.Warnf("DHCP host file %s not found (nothing to remove)", hostFilename)
			return nil
		}
		err = fmt.Errorf("failed to remove DHCP host file %s: %w", hostFilename, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) initProcessManager(instanceName string) proc.ProcessManager {
	return proc.ProcessManager{
		Log:       c.Log,
		PidFile:   c.dnsmasqPidFile(instanceName),
		Cmd:       dnsmasqBinary,
		Args:      []string{"-u", "nobody", "-g", "nobody", "-C", c.dnsmasqConfigPath(instanceName)},
		WithNohup: true,
		WillFork:  true,
	}
}

func (c *DnsmasqConfigurator) startDnsmasq(ctx context.Context, instanceName string) error {
	pm := c.initProcessManager(instanceName)
	ctx, cancel := context.WithTimeout(ctx, dnsmasqStartTimeout)
	defer cancel()
	return pm.Start(ctx)
}

func (c *DnsmasqConfigurator) stopDnsmasq(ctx context.Context, instanceName string) error {
	pm := c.initProcessManager(instanceName)
	ctx, cancel := context.WithTimeout(ctx, dnsmasqStopTimeout)
	defer cancel()
	return pm.Stop(ctx)
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

func (c *DnsmasqConfigurator) removeDnsmasqServersFile(instanceName string) error {
	serversPath := c.dnsmasqServersFile(instanceName)
	if err := os.Remove(serversPath); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq servers file %s: %w",
			serversPath, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) removeDnsmasqOptsFile(instanceName string) error {
	optsPath := c.dnsmasqOptsFile(instanceName)
	if err := os.Remove(optsPath); err != nil {
		err = fmt.Errorf("failed to remove dnsmasq opts file %s: %w",
			optsPath, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *DnsmasqConfigurator) removeDnsmasqLeaseFile(listenIfName string) error {
	leaseFilepath := types.DnsmasqLeaseFilePath(listenIfName)
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
