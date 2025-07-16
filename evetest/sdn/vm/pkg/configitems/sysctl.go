// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"fmt"

	"github.com/lf-edge/eve-libs/depgraph"
	log "github.com/sirupsen/logrus"
)

const (
	ipv4ForwardingKey   = "net.ipv4.ip_forward"
	ipv6ForwardingKey   = "net.ipv6.conf.all.forwarding"
	bridgeIptablesKey   = "net.bridge.bridge-nf-call-iptables"
	bridgeIP6tablesKey  = "net.bridge.bridge-nf-call-ip6tables"
	ipv6AcceptDadAllKey = "net.ipv6.conf.all.accept_dad"
	ipv6AcceptDadDefKey = "net.ipv6.conf.default.accept_dad"
)

// Sysctl : item representing kernel parameters set using sysctl.
type Sysctl struct {
	// NetNamespace : network namespace name
	NetNamespace          string
	EnableIPv4Forwarding  bool
	EnableIPv6Forwarding  bool
	BridgeNfCallIptables  bool
	BridgeNfCallIP6tables bool
	// DisableIPv6DAD disables IPv6 Duplicate Address Detection in this
	// namespace. When set, newly created interfaces skip the ~1s tentative
	// period and their addresses are immediately bindable. Use this for
	// endpoint namespaces where addresses are known to be unique.
	DisableIPv6DAD bool
}

// Name returns the name of the sysctl item.
func (f Sysctl) Name() string {
	return normNetNsName(f.NetNamespace)
}

// Label returns the label of the sysctl item.
func (f Sysctl) Label() string {
	return fmt.Sprintf("sysctl for %s ns", normNetNsName(f.NetNamespace))
}

// Type returns the typename of the sysctl item.
func (f Sysctl) Type() string {
	return SysctlTypename
}

// Equal compares sysctl settings.
func (f Sysctl) Equal(other depgraph.Item) bool {
	f2 := other.(Sysctl)
	return f == f2
}

// External returns false.
func (f Sysctl) External() bool {
	return false
}

// String prints sysctl settings.
func (f Sysctl) String() string {
	return fmt.Sprintf("Namespace: %s\nIPv4 Forwarding: %v\nIPv6 Forwarding: %v\n"+
		"Bridge uses Iptables: %v\nBridge uses Ip6tables: %v\nDisable IPv6 DAD: %v",
		normNetNsName(f.NetNamespace), f.EnableIPv4Forwarding, f.EnableIPv6Forwarding,
		f.BridgeNfCallIptables, f.BridgeNfCallIP6tables, f.DisableIPv6DAD)
}

// Dependencies returns dependency on the network namespace.
func (f Sysctl) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: NetNamespaceTypename,
				ItemName: normNetNsName(f.NetNamespace),
			},
			Description: "Network namespace must exist",
		},
	}
}

// SysctlConfigurator implements Configurator for sysctl settings.
type SysctlConfigurator struct{}

// Create applies sysctl settings.
func (c *SysctlConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	f := item.(Sysctl)
	if err := c.setIPForwarding(f.NetNamespace, f.EnableIPv4Forwarding, f.EnableIPv6Forwarding); err != nil {
		return err
	}
	if err := c.setBridgeIptables(f.NetNamespace, f.BridgeNfCallIptables, f.BridgeNfCallIP6tables); err != nil {
		return err
	}
	return c.setIPv6DAD(f.NetNamespace, !f.DisableIPv6DAD)
}

// Modify updates sysctl settings.
func (c *SysctlConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) error {
	f := newItem.(Sysctl)
	if err := c.setIPForwarding(f.NetNamespace, f.EnableIPv4Forwarding, f.EnableIPv6Forwarding); err != nil {
		return err
	}
	if err := c.setBridgeIptables(f.NetNamespace, f.BridgeNfCallIptables, f.BridgeNfCallIP6tables); err != nil {
		return err
	}
	return c.setIPv6DAD(f.NetNamespace, !f.DisableIPv6DAD)
}

// Delete sets default sysctl settings.
func (c *SysctlConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	f := item.(Sysctl)
	if err := c.setIPForwarding(f.NetNamespace, false, false); err != nil {
		return err
	}
	if err := c.setBridgeIptables(f.NetNamespace, true, true); err != nil {
		return err
	}
	return c.setIPv6DAD(f.NetNamespace, true)
}

func (c *SysctlConfigurator) setIPForwarding(netNs string, v4, v6 bool) error {
	sysctlKV := fmt.Sprintf("%s=%s", ipv4ForwardingKey, c.boolValueToStr(v4))
	out, err := namespacedCmd(netNs, "sysctl", "-w", sysctlKV).CombinedOutput()
	if err != nil {
		errMsg := fmt.Errorf("failed to set IPv4 forwarding: %s", out)
		log.Error(errMsg)
		return err
	}
	sysctlKV = fmt.Sprintf("%s=%s", ipv6ForwardingKey, c.boolValueToStr(v6))
	out, err = namespacedCmd(netNs, "sysctl", "-w", sysctlKV).CombinedOutput()
	if err != nil {
		errMsg := fmt.Errorf("failed to set IPv6 forwarding: %s", out)
		log.Error(errMsg)
		return err
	}
	return nil
}

func (c *SysctlConfigurator) setBridgeIptables(netNs string, v4, v6 bool) error {
	sysctlKV := fmt.Sprintf("%s=%s", bridgeIptablesKey, c.boolValueToStr(v4))
	out, err := namespacedCmd(netNs, "sysctl", "-w", sysctlKV).CombinedOutput()
	if err != nil {
		errMsg := fmt.Errorf("failed to set BridgeNfCallIptables: %s", out)
		log.Error(errMsg)
		return err
	}
	sysctlKV = fmt.Sprintf("%s=%s", bridgeIP6tablesKey, c.boolValueToStr(v6))
	out, err = namespacedCmd(netNs, "sysctl", "-w", sysctlKV).CombinedOutput()
	if err != nil {
		errMsg := fmt.Errorf("failed to set BridgeNfCallIP6tables: %s", out)
		log.Error(errMsg)
		return err
	}
	return nil
}

func (c *SysctlConfigurator) setIPv6DAD(netNs string, enable bool) error {
	val := c.boolValueToStr(enable)
	for _, key := range []string{ipv6AcceptDadAllKey, ipv6AcceptDadDefKey} {
		out, err := namespacedCmd(netNs, "sysctl", "-w", key+"="+val).CombinedOutput()
		if err != nil {
			log.Errorf("failed to set %s: %s", key, out)
			return err
		}
	}
	return nil
}

// NeedsRecreate returns false - Modify is able to apply any change.
func (c *SysctlConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}

func (c *SysctlConfigurator) boolValueToStr(enable bool) string {
	if enable {
		return "1"
	}
	return "0"
}
