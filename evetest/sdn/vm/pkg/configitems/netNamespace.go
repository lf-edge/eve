// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"

	"github.com/lf-edge/eve-libs/depgraph"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	// MainNsName : symbolic name for the main network namespace (where SDN agent operates).
	MainNsName = "main"

	// Directory with references to named network namespaces.
	namedNsDir = "/run/netns"
)

func normNetNsName(name string) string {
	if name == "" {
		name = MainNsName
	}
	return name
}

func namespacedCmd(netNs string, cmd string, args ...string) *exec.Cmd {
	netNs = normNetNsName(netNs)
	if netNs == MainNsName {
		return exec.Command(cmd, args...)
	}
	var newArgs []string
	newArgs = append(newArgs, "netns", "exec", normNetNsName(netNs))
	newArgs = append(newArgs, cmd)
	newArgs = append(newArgs, args...)
	return exec.Command("ip", newArgs...)
}

func moveLinkToNamespace(link netlink.Link, netNs string) (err error) {
	nsHandle, err := netns.GetFromName(netNs)
	if err != nil {
		return err
	}
	return netlink.LinkSetNsFd(link, int(nsHandle))
}

func switchToNamespace(netNs string) (revert func(), err error) {
	// Save the current network namespace.
	origNs, err := netns.Get()
	if err != nil {
		return func() {}, err
	}
	closeNs := func(ns netns.NsHandle) {
		if err := ns.Close(); err != nil {
			log.Warnf("closing NsHandle (%v) failed: %v", ns, err)
		}
	}
	// Get network namespace file descriptor.
	nsHandle, err := netns.GetFromName(netNs)
	if err != nil {
		closeNs(origNs)
		return func() {}, err
	}
	defer closeNs(nsHandle)

	// Lock the OS Thread so we don't accidentally switch namespaces later.
	runtime.LockOSThread()

	// Switch the namespace.
	if err := netns.Set(nsHandle); err != nil {
		runtime.UnlockOSThread()
		closeNs(origNs)
		return func() {}, err
	}

	return func() {
		if err := netns.Set(origNs); err != nil {
			log.Errorf("Failed to switch to original Linux network namespace: %v", err)
		}
		closeNs(origNs)
		runtime.UnlockOSThread()
	}, nil
}

func getNetNsConfigDir(netNs string) string {
	netNs = normNetNsName(netNs)
	if netNs == MainNsName {
		return "/etc/"
	}
	// "ip netns exec" automatically creates a mount namespace for the running
	// process and bind mounts all well-known config files found in /etc/netns/<NS-NAME>/
	// into their traditional location in /etc.
	return fmt.Sprintf("/etc/netns/%s/", netNs)
}

// NetNamespace : an item representing named network namespace.
type NetNamespace struct {
	// NsName : name of the network namespace.
	NsName     string
	ResolvConf ResolvConf
}

// ResolvConf - config for resolv.conf
type ResolvConf struct {
	// Create resolv.conf specifically for this network namespace
	// with the DNS server entries listed below.
	// Otherwise the namespace will use the global resolv.conf.
	Create     bool
	DNSServers []net.IP
}

// Name returns the name of the network namespace item.
func (n NetNamespace) Name() string {
	return normNetNsName(n.NsName)
}

// Label returns the label of the network namespace item.
func (n NetNamespace) Label() string {
	return normNetNsName(n.NsName) + " (net namespace)"
}

// Type returns the typename of the network namespace item.
func (n NetNamespace) Type() string {
	return NetNamespaceTypename
}

// Equal compares resolv.conf entries.
func (n NetNamespace) Equal(other depgraph.Item) bool {
	n2 := other.(NetNamespace)
	if n.ResolvConf.Create != n2.ResolvConf.Create {
		return false
	}
	if len(n.ResolvConf.DNSServers) != len(n2.ResolvConf.DNSServers) {
		return false
	}
	for i := range n.ResolvConf.DNSServers {
		if !n.ResolvConf.DNSServers[i].Equal(n2.ResolvConf.DNSServers[i]) {
			return false
		}
	}
	return true
}

// External returns false.
func (n NetNamespace) External() bool {
	return false
}

// String describes the namespace.
func (n NetNamespace) String() string {
	description := fmt.Sprintf("Network Namespace \"%s\"", n.NsName)
	if n.ResolvConf.Create {
		if len(n.ResolvConf.DNSServers) == 0 {
			description += " with empty resolv.conf"
		} else {
			description += " with resolv.conf containing entries:"
		}
		for _, dnsServer := range n.ResolvConf.DNSServers {
			description += fmt.Sprintf("\n  * %v", dnsServer)
		}
	}
	return description
}

// Dependencies returns nothing.
func (n NetNamespace) Dependencies() (deps []depgraph.Dependency) {
	return nil
}

// NetNamespaceConfigurator implements Configurator interface for NetNamespace.
type NetNamespaceConfigurator struct{}

// Create adds network namespace.
func (c *NetNamespaceConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	ns := item.(NetNamespace)
	nsName := normNetNsName(ns.NsName)
	// Create directory where network namespace FDs are symlinked.
	if err := ensureDir(namedNsDir); err != nil {
		return err
	}
	// Create a directory for namespace-specific config files.
	nsConfigDir := getNetNsConfigDir(nsName)
	if nsName != MainNsName {
		// Clean any previous content.
		_ = os.RemoveAll(nsConfigDir)
	}
	if err := ensureDir(nsConfigDir); err != nil {
		return err
	}
	// Create network-namespace specific resolv.conf file if requested.
	if ns.ResolvConf.Create {
		err := c.generateResolvConf(nsConfigDir+"resolv.conf", ns.ResolvConf)
		if err != nil {
			err = fmt.Errorf("failed to create resolv.conf: %s", err)
			log.Error(err)
			return err
		}
	}
	// Create named network namespace.
	if nsName == MainNsName {
		// Nothing to do, already exists.
		return nil
	}
	out, err := exec.Command("ip", "netns", "add", nsName).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to add net namespace %s: %s", nsName, out)
		log.Error(err)
		return err
	}
	// By default, the loopback interface is down.
	loUpArgs := []string{"link", "set", "dev", "lo", "up"}
	out, err = namespacedCmd(nsName, "ip", loUpArgs...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to set IPv4 forwarding: %s", out)
		log.Error(err)
		return err
	}
	return nil
}

func (c *NetNamespaceConfigurator) generateResolvConf(path string, config ResolvConf) error {
	destfile, err := os.Create(path)
	if err != nil {
		err = fmt.Errorf("failed to create resolv.conf: %v", err)
		return err
	}
	defer func() {
		if cerr := destfile.Close(); cerr != nil {
			log.Warnf("Failed to close resolv.conf: %v", cerr)
		}
	}()
	if _, err = destfile.WriteString("# Generated by SDN agent\n"); err != nil {
		return err
	}
	if _, err = destfile.WriteString("# Do not edit\n"); err != nil {
		return err
	}
	for _, dnsServer := range config.DNSServers {
		_, err = fmt.Fprintf(destfile, "nameserver %s\n", dnsServer)
		if err != nil {
			return err
		}
	}
	return destfile.Sync()
}

// Modify is able to update resolv.conf content.
func (c *NetNamespaceConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	ns := newItem.(NetNamespace)
	nsConfigDir := getNetNsConfigDir(ns.NsName)
	err = c.generateResolvConf(nsConfigDir+"resolv.conf", ns.ResolvConf)
	if err != nil {
		err = fmt.Errorf("failed to modify resolv.conf: %s", err)
		log.Error(err)
		return err
	}
	return nil
}

// Delete removes network namespace.
func (c *NetNamespaceConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	ns, isNetNs := item.(NetNamespace)
	if !isNetNs {
		err := fmt.Errorf("unexpected item type: %T", item)
		log.Error(err)
		return err
	}
	nsName := normNetNsName(ns.NsName)
	if nsName == MainNsName {
		// Main network namespace cannot be deleted.
		return errors.New("not supported")
	}
	out, err := exec.Command("ip", "netns", "del", nsName).CombinedOutput()
	if err != nil {
		errMsg := fmt.Errorf("failed to del net namespace %s: %s", nsName, out)
		log.Error(errMsg)
		return err
	}
	nsConfigDir := getNetNsConfigDir(nsName)
	_ = os.RemoveAll(nsConfigDir)
	return nil
}

// NeedsRecreate returns false - Modify is able to handle changes (in the resolv.conf content).
func (c *NetNamespaceConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}

func ensureDir(dirname string) error {
	err := os.MkdirAll(dirname, 0755)
	if err != nil {
		err = fmt.Errorf("failed to create directory %s: %w", dirname, err)
		log.Error(err)
		return err
	}
	return nil
}
