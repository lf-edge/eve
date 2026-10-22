// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	log "github.com/sirupsen/logrus"
)

const (
	radvdBinary  = "/usr/sbin/radvd"
	radvdConfDir = "/etc/radvd"
	radvdRunDir  = "/run/radvd"

	radvdStartTimeout = 3 * time.Second
	radvdStopTimeout  = 10 * time.Second
)

// Radvd : router advertisement daemon (https://linux.die.net/man/5/radvd.conf).
type Radvd struct {
	// DaemonName : logical name for the Radvd daemon.
	DaemonName string
	// NetNamespace : network namespace where the daemon should be running.
	NetNamespace string
	// VethName : logical name of the veth pair on which the daemon operates.
	// (other types of interfaces are currently not supported)
	VethName string
	// VethPeerIfName : interface name of that side of the veth pair on which
	// the daemon should listen. It should be inside NetNamespace.
	VethPeerIfName string
	// Subnet to advertise.
	Subnet *net.IPNet
	// MTU : Maximum transmission unit size to advertise.
	MTU uint16
	// When set, hosts use the administered (stateful) protocol for address
	// autoconfiguration in addition to any addresses autoconfigured using
	// stateless address autoconfiguration. The use of this flag is described in RFC 4862.
	AdvManagedFlag bool
	// When set, hosts use the administered (stateful) protocol for autoconfiguration
	// of other (non-address) information. The use of this flag is described in RFC 4862.
	AdvOtherConfigFlag bool
	// When set, indicates that this prefix can be used for autonomous address configuration
	// as specified in RFC 4862.
	AdvAutonomous bool
	// DNSServers : list of IP addresses of DNS servers to advertise.
	DNSServers []net.IP
	// WithoutDefaultRoute : do not advertise default route.
	WithoutDefaultRoute bool
}

// Name returns the logical name of the radvd daemon.
func (r Radvd) Name() string {
	return r.DaemonName
}

// Label for the radvd instance.
func (r Radvd) Label() string {
	return r.DaemonName + " (radvd)"
}

// Type of the item.
func (r Radvd) Type() string {
	return RadvdTypename
}

// Equal compares two Radvd instances
func (r Radvd) Equal(other depgraph.Item) bool {
	r2, isRadvd := other.(Radvd)
	if !isRadvd {
		return false
	}
	return r.NetNamespace == r2.NetNamespace &&
		r.VethName == r2.VethName &&
		r.VethPeerIfName == r2.VethPeerIfName &&
		netutils.EqualIPNets(r.Subnet, r2.Subnet) &&
		r.MTU == r2.MTU &&
		r.AdvManagedFlag == r2.AdvManagedFlag &&
		r.AdvOtherConfigFlag == r2.AdvOtherConfigFlag &&
		r.AdvAutonomous == r2.AdvAutonomous &&
		generics.EqualSetsFn(r.DNSServers, r2.DNSServers, netutils.EqualIPs) &&
		r.WithoutDefaultRoute == r2.WithoutDefaultRoute
}

// External returns false.
func (r Radvd) External() bool {
	return false
}

// String describes the radvd instance.
func (r Radvd) String() string {
	return fmt.Sprintf("Router Advertisement Daemon: %#+v", r)
}

// Dependencies lists the veth and network namespace as dependencies.
func (r Radvd) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: NetNamespaceTypename,
				ItemName: normNetNsName(r.NetNamespace),
			},
			Description: "Network namespace must exist",
		},
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: VethTypename,
				ItemName: r.VethName,
			},
			Description: "veth interface must exist",
		},
	}
}

// RadvdConfigurator implements Configurator interface for Radvd.
type RadvdConfigurator struct{}

// Create starts radvd.
func (c *RadvdConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	config := item.(Radvd)
	if err := c.createRadvdConfFile(config); err != nil {
		return err
	}
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		err := startRadvd(config.DaemonName, config.NetNamespace)
		done(err)
	}()
	return nil
}

func (c *RadvdConfigurator) createRadvdConfFile(radvd Radvd) error {
	if err := ensureDir(radvdConfDir); err != nil {
		return err
	}
	filePath := radvdConfigPath(radvd.DaemonName)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create radvd config file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			log.Warnf("Failed to close radvd config file %s: %v", filePath, cerr)
		}
	}()

	var b strings.Builder

	b.WriteString("interface ")
	b.WriteString(radvd.VethPeerIfName)
	b.WriteString(" {\n")
	b.WriteString("    AdvSendAdvert on;\n")

	if radvd.AdvManagedFlag {
		b.WriteString("    AdvManagedFlag on;\n")
	}
	if radvd.AdvOtherConfigFlag {
		b.WriteString("    AdvOtherConfigFlag on;\n")
	}
	if radvd.MTU > 0 {
		// strings.Builder.Write never returns a non-nil error.
		_, _ = fmt.Fprintf(&b, "    AdvLinkMTU %d;\n", radvd.MTU)
	}

	b.WriteString("    prefix ")
	b.WriteString(radvd.Subnet.String())
	b.WriteString(" {\n")
	b.WriteString("        AdvOnLink on;\n")
	if !radvd.AdvAutonomous {
		b.WriteString("        AdvAutonomous off;\n")
	}
	if radvd.WithoutDefaultRoute {
		b.WriteString("        AdvDefaultLifetime 0;\n")
	}
	b.WriteString("    };\n")

	if len(radvd.DNSServers) > 0 {
		b.WriteString("    RDNSS")
		for _, ip := range radvd.DNSServers {
			b.WriteString(" ")
			b.WriteString(ip.String())
		}
		b.WriteString(" {\n")
		b.WriteString("        AdvRDNSSLifetime 3600;\n")
		b.WriteString("    };\n")
	}

	b.WriteString("};\n")

	_, err = file.WriteString(b.String())
	if err != nil {
		return fmt.Errorf("failed to write radvd config content: %w", err)
	}

	return nil
}

// Modify is not implemented.
func (c *RadvdConfigurator) Modify(_ context.Context, _, _ depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete stops radvd.
func (c *RadvdConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	config := item.(Radvd)
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		err := stopRadvd(config.DaemonName)
		if err == nil {
			// ignore errors from here
			_ = removeRadvdConfFile(config.DaemonName)
			_ = removeRadvdLogFile(config.DaemonName)
			_ = removeRadvdPidFile(config.DaemonName)
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *RadvdConfigurator) NeedsRecreate(_, _ depgraph.Item) (recreate bool) {
	return true
}

func radvdConfigPath(daemonName string) string {
	return filepath.Join(radvdConfDir, daemonName+".conf")
}

func radvdPidFile(daemonName string) string {
	return filepath.Join(radvdRunDir, daemonName+".pid")
}

func radvdLogFile(daemonName string) string {
	return filepath.Join(radvdRunDir, daemonName+".log")
}

func removeRadvdConfFile(daemonName string) error {
	cfgPath := radvdConfigPath(daemonName)
	if err := os.Remove(cfgPath); err != nil {
		err = fmt.Errorf("failed to remove radvd config %s: %w",
			cfgPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeRadvdPidFile(daemonName string) error {
	pidPath := radvdPidFile(daemonName)
	if err := os.Remove(pidPath); err != nil {
		err = fmt.Errorf("failed to remove radvd PID file %s: %w",
			pidPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeRadvdLogFile(daemonName string) error {
	logPath := radvdLogFile(daemonName)
	if err := os.Remove(logPath); err != nil {
		err = fmt.Errorf("failed to remove radvd log file %s: %w",
			logPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func startRadvd(daemonName, netNamespace string) error {
	if err := ensureDir(radvdRunDir); err != nil {
		return err
	}
	cfgPath := radvdConfigPath(daemonName)
	pidPath := radvdPidFile(daemonName)
	logPath := radvdLogFile(daemonName)
	cmd := radvdBinary
	args := []string{
		"--config", cfgPath,
		"--pidfile", pidPath,
		"--logfile", logPath,
		"--logmethod", "logfile",
		"--debug", "5",
	}
	pidFile := radvdPidFile(daemonName)
	// Process will "daemonize" itself by forking and intentionally becoming orphaned.
	// We can therefore start the command as a foreground process.
	return startProcess(netNamespace, cmd, args, pidFile, "", radvdStartTimeout,
		false, false)
}

func stopRadvd(daemonName string) error {
	pidFile := radvdPidFile(daemonName)
	return stopProcess(pidFile, radvdStopTimeout)
}
