// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	"github.com/lf-edge/eve/pkg/pillar/utils/proc"
)

const (
	mgmtDnsmasqBinary       = "/usr/sbin/dnsmasq"
	mgmtDnsmasqRunDir       = "/run/nim"
	mgmtDnsmasqInstName     = "mgmt" // singleton item
	mgmtDnsmasqStartTimeout = 3 * time.Second
	mgmtDnsmasqStopTimeout  = 30 * time.Second
)

// MgmtDNSPort holds per-port DNS configuration used when generating the mgmt dnsmasq
// config.
type MgmtDNSPort struct {
	// IfName is the network interface name (e.g. "eth0").
	IfName string
	// DNSServers are the upstream DNS servers for this port.
	DNSServers []net.IP
	// SearchDomains are the DHCP-provided search domains for this port.
	SearchDomains []string
}

// Equal returns true if two MgmtDNSPort values have identical configuration.
// DNS server and search domain order within a port does not matter.
func (p MgmtDNSPort) Equal(other MgmtDNSPort) bool {
	return p.IfName == other.IfName &&
		generics.EqualSetsFn(p.DNSServers, other.DNSServers, netutils.EqualIPs) &&
		generics.EqualSets(p.SearchDomains, other.SearchDomains)
}

// MgmtDnsmasq is a singleton dep-graph item representing the management dnsmasq
// instance that provides DNS forwarding for pillar and other EVE management processes.
// It listens on 127.0.0.1:53, strictly bound to the loopback interface,
// and forwards queries to upstream DNS servers of management ports,
// preferring lower-cost ports via strict-order.
type MgmtDnsmasq struct {
	// Ports lists management ports in cost-ascending order.
	// Config-file insertion order equals cost order, so dnsmasq's strict-order
	// naturally tries lower-cost port DNS servers first.
	Ports []MgmtDNSPort
	// CacheClearCounter is incremented by DpcManager to declaratively trigger
	// a DNS cache flush (SIGHUP) before each DPC verification pass.
	// When the counter changes, Equal() returns false → Modify() is called →
	// SIGHUP is sent, which clears dnsmasq's in-memory cache.
	CacheClearCounter int
	// LogDNSQueries enables dnsmasq log-queries, causing DNS queries and
	// forwarding attempts (including failures) to appear in device logs.
	// Set when NIM runs at debug/trace log level.
	LogDNSQueries bool
}

// Name returns the singleton instance name used in the dep-graph.
func (m MgmtDnsmasq) Name() string {
	return mgmtDnsmasqInstName
}

// Label returns a human-readable label used in the dependency graph visualisation.
func (m MgmtDnsmasq) Label() string {
	return "Mgmt dnsmasq"
}

// Type returns the dep-graph item type name.
func (m MgmtDnsmasq) Type() string {
	return MgmtDnsmasqTypename
}

// External returns false.
func (m MgmtDnsmasq) External() bool {
	return false
}

// String returns a human-readable summary.
func (m MgmtDnsmasq) String() string {
	parts := make([]string, 0, len(m.Ports))
	for _, port := range m.Ports {
		parts = append(parts, fmt.Sprintf("%s:{dns:%v, search:%v}",
			port.IfName, port.DNSServers, port.SearchDomains))
	}
	return fmt.Sprintf("MgmtDnsmasq{ports: %s}", strings.Join(parts, ", "))
}

// Equal returns true if the two items have identical configuration.
func (m MgmtDnsmasq) Equal(other dg.Item) bool {
	m2, ok := other.(MgmtDnsmasq)
	if !ok {
		return false
	}
	return generics.EqualListsFn(m.Ports, m2.Ports, MgmtDNSPort.Equal) &&
		m.CacheClearCounter == m2.CacheClearCounter &&
		m.LogDNSQueries == m2.LogDNSQueries
}

// Dependencies returns nil — the mgmt dnsmasq has no dep-graph dependencies.
// It listens on loopback and needs no managed interfaces to be up first.
func (m MgmtDnsmasq) Dependencies() (deps []dg.Dependency) {
	return nil
}

// MgmtDnsmasqConfigurator implements reconciler.Configurator for MgmtDnsmasq.
type MgmtDnsmasqConfigurator struct {
	Log *base.LogObject
}

// Create writes the config file and starts the mgmt dnsmasq process.
// 127.0.0.1 is always assigned to lo, so bind-interfaces works without
// any additional address setup.
func (c *MgmtDnsmasqConfigurator) Create(ctx context.Context, item dg.Item) error {
	m, ok := item.(MgmtDnsmasq)
	if !ok {
		return fmt.Errorf("invalid item type %T, expected MgmtDnsmasq", item)
	}
	if err := c.writeConfig(m); err != nil {
		c.Log.Error(err)
		return err
	}
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		startCtx, cancel := context.WithTimeout(ctx, mgmtDnsmasqStartTimeout)
		defer cancel()
		pm := c.pm()
		err := pm.Start(startCtx)
		done(err)
	}()
	return nil
}

// Modify rewrites the config file and sends SIGHUP to reload config and clear
// the DNS cache.
func (c *MgmtDnsmasqConfigurator) Modify(_ context.Context, _, newItem dg.Item) error {
	m, ok := newItem.(MgmtDnsmasq)
	if !ok {
		return fmt.Errorf("invalid item type %T, expected MgmtDnsmasq", newItem)
	}
	if err := c.writeConfig(m); err != nil {
		c.Log.Error(err)
		return err
	}
	pm := c.pm()
	return pm.SendSignal(syscall.SIGHUP)
}

// Delete stops the mgmt dnsmasq process and removes its files.
func (c *MgmtDnsmasqConfigurator) Delete(ctx context.Context, _ dg.Item) error {
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		stopCtx, cancel := context.WithTimeout(ctx, mgmtDnsmasqStopTimeout)
		defer cancel()
		pm := c.pm()
		err := pm.Stop(stopCtx)
		if err == nil {
			_ = os.Remove(c.configPath())
			_ = os.Remove(c.serversPath())
			_ = os.Remove(c.pidPath())
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate returns true only when LogDNSQueries changes, because
// log-queries is in the main config file and is not re-read on SIGHUP.
// Upstream server list changes (Ports) are handled by Modify() + SIGHUP
// because servers are kept in a separate --servers-file that dnsmasq
// does re-read on SIGHUP.
func (c *MgmtDnsmasqConfigurator) NeedsRecreate(oldItem, newItem dg.Item) bool {
	oldM, ok := oldItem.(MgmtDnsmasq)
	if !ok {
		return false
	}
	newM, ok := newItem.(MgmtDnsmasq)
	if !ok {
		return false
	}
	return oldM.LogDNSQueries != newM.LogDNSQueries
}

func (c *MgmtDnsmasqConfigurator) pm() proc.ProcessManager {
	return proc.ProcessManager{
		Log:     c.Log,
		PidFile: c.pidPath(),
		Cmd:     mgmtDnsmasqBinary,
		// Run as root so dnsmasq can read the servers file from /run/nim/
		// (drwx------) both at startup and on SIGHUP reload. Without -u/-g,
		// dnsmasq drops to its compiled-in default user which also cannot
		// traverse /run/nim/.
		Args:      []string{"-u", "root", "-g", "root", "-C", c.configPath()},
		WithNohup: true,
		WillFork:  true,
	}
}

func (c *MgmtDnsmasqConfigurator) configPath() string {
	return filepath.Join(mgmtDnsmasqRunDir, "dnsmasq."+mgmtDnsmasqInstName+".conf")
}

func (c *MgmtDnsmasqConfigurator) pidPath() string {
	return filepath.Join(mgmtDnsmasqRunDir, "dnsmasq."+mgmtDnsmasqInstName+".pid")
}

// serversPath returns the path to the --servers-file.
// This file contains all server= entries and is re-read on SIGHUP, allowing
// upstream server list changes without restarting dnsmasq.
func (c *MgmtDnsmasqConfigurator) serversPath() string {
	return filepath.Join(mgmtDnsmasqRunDir, "dnsmasq."+mgmtDnsmasqInstName+".servers")
}

func (c *MgmtDnsmasqConfigurator) writeConfig(m MgmtDnsmasq) error {
	if err := os.MkdirAll(mgmtDnsmasqRunDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", mgmtDnsmasqRunDir, err)
	}
	if err := c.writeMainConfig(m); err != nil {
		return err
	}
	return c.writeServersFile(m)
}

// writeMainConfig writes the static dnsmasq options. These are only re-read
// on process restart (not on SIGHUP), so they change rarely.
func (c *MgmtDnsmasqConfigurator) writeMainConfig(m MgmtDnsmasq) error {
	f, err := os.Create(c.configPath())
	if err != nil {
		return fmt.Errorf("failed to create dnsmasq config %s: %w", c.configPath(), err)
	}
	defer f.Close()

	staticLines := []string{
		"# Generated by nim",
		"# Do not edit",
		"no-resolv",
		"bind-interfaces",
		"interface=lo",
		"strict-order",
		fmt.Sprintf("pid-file=%s", c.pidPath()),
		// server= entries are in a separate file re-read on SIGHUP.
		fmt.Sprintf("servers-file=%s", c.serversPath()),
	}
	if m.LogDNSQueries {
		staticLines = append(staticLines, "log-queries")
	}
	for _, line := range staticLines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			return err
		}
	}
	return f.Sync()
}

// writeServersFile writes all server= entries. dnsmasq re-reads this file
// on SIGHUP, so upstream server list changes take effect without a restart.
// strict-order (set in the main config) applies globally to all entries here.
func (c *MgmtDnsmasqConfigurator) writeServersFile(m MgmtDnsmasq) error {
	f, err := os.Create(c.serversPath())
	if err != nil {
		return fmt.Errorf("failed to create dnsmasq servers file %s: %w",
			c.serversPath(), err)
	}
	defer f.Close()

	// Pass 1: split-horizon entries for per-port search domains.
	for _, port := range m.Ports {
		for _, server := range port.DNSServers {
			for _, domain := range port.SearchDomains {
				_, err = fmt.Fprintf(f, "server=/%s/%s@%s\n",
					domain, server, port.IfName)
				if err != nil {
					return err
				}
			}
		}
	}

	// Pass 2: default upstream servers in cost-ascending order.
	for _, port := range m.Ports {
		for _, server := range port.DNSServers {
			_, err = fmt.Fprintf(f, "server=%s@%s\n", server, port.IfName)
			if err != nil {
				return err
			}
		}
	}

	return f.Sync()
}
