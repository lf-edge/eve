// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	log "github.com/sirupsen/logrus"
)

const dnsSrvNamePrefix = "dnssrv-"

// DNSServer : DNS server.
type DNSServer struct {
	// ServerName : logical name for the DNS server.
	ServerName string
	// NetNamespace : network namespace where the server should be running.
	NetNamespace string
	// VethName : logical name of the veth pair on which the server operates.
	// (other types of interfaces are currently not supported)
	VethName string
	// VethPeerIfName : interface name of that side of the veth pair on which
	// the server should listen. It should be inside NetNamespace.
	VethPeerIfName string
	// StaticEntries : list of FQDN->IP entries statically configured for the server.
	StaticEntries []DNSEntry
	// UpstreamServers : list of IP addresses of public DNS servers to forward
	// requests to (unless there is a static entry).
	UpstreamServers []net.IP
	// StaticEntriesTTL : TTL in seconds for static (address=) entries.
	// When 0, dnsmasq defaults to 0s (not cached by querying resolvers).
	StaticEntriesTTL uint32
}

// DNSEntry : Mapping between FQDN and an IP address.
type DNSEntry struct {
	FQDN string
	IP   net.IP
}

// Name returns the name of the DNS server item.
func (s DNSServer) Name() string {
	return s.ServerName
}

// Label returns the label of the DNS server item.
func (s DNSServer) Label() string {
	return s.ServerName + " (DNS server)"
}

// Type returns the typename of the DNS server item.
func (s DNSServer) Type() string {
	return DNSServerTypename
}

// Equal is a comparison method for two equally-named DNSServer instances.
func (s DNSServer) Equal(other depgraph.Item) bool {
	s2 := other.(DNSServer)
	if len(s.UpstreamServers) != len(s2.UpstreamServers) {
		return false
	}
	for i := range s.UpstreamServers {
		if !s.UpstreamServers[i].Equal(s2.UpstreamServers[i]) {
			return false
		}
	}
	if len(s.StaticEntries) != len(s2.StaticEntries) {
		return false
	}
	for i := range s.StaticEntries {
		if !s.StaticEntries[i].IP.Equal(s2.StaticEntries[i].IP) ||
			s.StaticEntries[i].FQDN != s2.StaticEntries[i].FQDN {
			return false
		}
	}
	return s.NetNamespace == s2.NetNamespace &&
		s.VethName == s2.VethName &&
		s.VethPeerIfName == s2.VethPeerIfName &&
		s.StaticEntriesTTL == s2.StaticEntriesTTL
}

// External returns false.
func (s DNSServer) External() bool {
	return false
}

// String describes the DNS server.
func (s DNSServer) String() string {
	return fmt.Sprintf("DNS Server: %#+v", s)
}

// Dependencies lists the veth and network namespace as dependencies.
func (s DNSServer) Dependencies() (deps []depgraph.Dependency) {
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

// DNSServerConfigurator implements Configurator interface for DNSServer.
type DNSServerConfigurator struct{}

// Create starts dnsmasq (in DNS-only mode).
func (c *DNSServerConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	config := item.(DNSServer)
	if err := c.createDnsmasqConfFile(config); err != nil {
		return err
	}
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		err := startDnsmasq(dnsSrvNamePrefix+config.ServerName, config.NetNamespace)
		done(err)
	}()
	return nil
}

func (c *DNSServerConfigurator) createDnsmasqConfFile(server DNSServer) error {
	if err := ensureDir(dnsmasqConfDir); err != nil {
		return err
	}
	srvName := dnsSrvNamePrefix + server.ServerName
	cfgPath := dnsmasqConfigPath(srvName)
	file, err := os.Create(cfgPath)
	if err != nil {
		err = fmt.Errorf("failed to create config file %s: %w", cfgPath, err)
		log.Error(err)
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			log.Warnf("Failed to close config file %s: %v", cfgPath, cerr)
		}
	}()

	writeLine := func(format string, args ...interface{}) error {
		if _, err := fmt.Fprintf(file, format, args...); err != nil {
			err = fmt.Errorf("failed to write config file %s: %w", cfgPath, err)
			log.Error(err)
			return err
		}
		return nil
	}

	// PID file is also used by Delete method.
	if err := writeLine("pid-file=%s\n", dnsmasqPidFile(srvName)); err != nil {
		return err
	}
	// Set the interface on which dnsmasq operates.
	if err := writeLine("interface=%s\n", server.VethPeerIfName); err != nil {
		return err
	}
	// Disable DHCP.
	if err := writeLine("no-dhcp-interface=%s\n", server.VethPeerIfName); err != nil {
		return err
	}
	// Logging.
	if err := writeLine("log-queries\n"); err != nil {
		return err
	}
	if err := writeLine("log-facility=%s\n", dnsmasqLogFile(srvName)); err != nil {
		return err
	}
	// Upstream DNS servers.
	for _, upstreamSrv := range server.UpstreamServers {
		if err := writeLine("server=%s\n", upstreamSrv); err != nil {
			return err
		}
	}
	if err := writeLine("no-resolv\n"); err != nil {
		return err
	}
	// Static DNS entries.
	if len(server.StaticEntries) > 0 && server.StaticEntriesTTL > 0 {
		if err := writeLine("local-ttl=%d\n", server.StaticEntriesTTL); err != nil {
			return err
		}
	}
	// Collect unique FQDNs for local= directives written below.
	seenFQDNs := make(map[string]bool)
	for _, entry := range server.StaticEntries {
		if err := writeLine("address=/%s/%s\n", entry.FQDN, entry.IP.String()); err != nil {
			return err
		}
		seenFQDNs[entry.FQDN] = true
	}
	// For each statically configured FQDN, add a local= directive so that
	// dnsmasq returns NXDOMAIN (not REFUSED) for query types that have no
	// matching address= entry (e.g., A query when only AAAA is configured).
	// Without this, dnsmasq would try to forward the unsatisfied query to an
	// upstream server; with no upstream configured it returns REFUSED, and
	// upstream dnsmasq instances treat REFUSED identically to a timeout --
	// retrying indefinitely and blocking Go's DNS resolver goroutine.
	for fqdn := range seenFQDNs {
		if err := writeLine("local=/%s/\n", fqdn); err != nil {
			return err
		}
	}
	if err := writeLine("no-hosts\n"); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		err = fmt.Errorf("failed to sync config file %s: %w", cfgPath, err)
		log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented.
func (c *DNSServerConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete stops dnsmasq.
func (c *DNSServerConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	config := item.(DNSServer)
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		srvName := dnsSrvNamePrefix + config.ServerName
		err := stopDnsmasq(srvName)
		if err == nil {
			// ignore errors from here
			_ = removeDnsmasqConfFile(srvName)
			_ = removeDnsmasqLogFile(srvName)
			_ = removeDnsmasqPidFile(srvName)
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *DNSServerConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
