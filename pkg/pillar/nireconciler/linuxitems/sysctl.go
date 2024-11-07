// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"fmt"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	uuid "github.com/satori/go.uuid"
)

var emptyUUID = uuid.UUID{} // used as a constant

// Sysctl : item representing kernel parameters set for a network interface using sysctl.
type Sysctl struct {
	// ForApp : if defined, apply these kernel parameters for a (container) app
	// (and not for the host).
	ForApp ContainerApp
	// NetIf : network interface for which parameters are applied.
	// Leave empty if these are global settings not corresponding to any particular
	// interface.
	NetIf genericitems.NetworkIf

	// Leave nil value for undefined options.
	// SysctlConfigurator will not touch them.

	// EnableDAD : enable duplicate address detection (IPv6).
	// This is a per-interface option.
	EnableDAD *bool
	// EnableARPNotify : generate gratuitous arp requests when device is brought up
	// or hardware address changes
	// This is a per-interface option.
	EnableARPNotify *bool
	// BridgeCallIptables enables processing of IPv4 packets traversing a Linux bridge
	// by iptables rules.
	// This is a global option.
	BridgeCallIptables *bool
	// BridgeCallIp6tables enables processing of IPv6 packets traversing a Linux bridge
	// by ip6tables rules.
	// This is a global option.
	BridgeCallIp6tables *bool
}

// Name of the item instance.
func (s Sysctl) Name() string {
	var forIfName string
	if s.NetIf.IfName != "" {
		forIfName = "-" + s.NetIf.IfName
	}
	if s.ForApp.ID == emptyUUID {
		return fmt.Sprintf("sysctl-host%s", forIfName)
	}
	return fmt.Sprintf("sysctl-%s%s", s.ForApp.ID, forIfName)
}

// Label is not defined.
func (s Sysctl) Label() string {
	return ""
}

// Type of the item.
func (s Sysctl) Type() string {
	return SysctlTypename
}

// Equal compares sysctl settings.
func (s Sysctl) Equal(other dg.Item) bool {
	s2, isSysctl := other.(Sysctl)
	if !isSysctl {
		return false
	}
	return equalBoolPtr(s.EnableDAD, s2.EnableDAD) &&
		equalBoolPtr(s.EnableARPNotify, s2.EnableARPNotify) &&
		equalBoolPtr(s.BridgeCallIptables, s2.BridgeCallIptables) &&
		equalBoolPtr(s.BridgeCallIp6tables, s2.BridgeCallIp6tables)
}

// External returns false.
func (s Sysctl) External() bool {
	return false
}

// String prints sysctl settings.
func (s Sysctl) String() string {
	var prefix string
	if s.ForApp.ID == emptyUUID {
		prefix = "Host"
	} else {
		prefix = fmt.Sprintf("App %s", s.ForApp)
	}
	var forIfName string
	if s.NetIf.IfName != "" {
		forIfName = fmt.Sprintf(" for interface '%s'", s.NetIf.IfName)
	}
	return fmt.Sprintf(
		"%s Sysctl%s: {enableDAD: %s, enableARPNotify: %s, "+
			"bridgeCallIptables: %s, bridgeCallIp6tables: %s}",
		prefix, forIfName, boolPtrToString(s.EnableDAD),
		boolPtrToString(s.EnableARPNotify), boolPtrToString(s.BridgeCallIptables),
		boolPtrToString(s.BridgeCallIp6tables))
}

// Dependencies returns the target interface as the only dependency.
func (s Sysctl) Dependencies() (deps []dg.Dependency) {
	if s.NetIf.IfName != "" {
		deps = append(deps, dg.Dependency{
			RequiredItem: s.NetIf.ItemRef,
			Description:  "interface referenced by sysctl config must exist",
		})
	}
	return deps
}

func equalBoolPtr(value1, value2 *bool) bool {
	if value1 == nil || value2 == nil {
		return value1 == value2
	}
	return *value1 == *value2
}

func boolPtrToString(value *bool) string {
	if value == nil {
		return "undefined"
	}
	if *value {
		return "true"
	}
	return "false"
}

func boolToDigitString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// SysctlConfigurator implements Configurator for sysctl settings.
type SysctlConfigurator struct {
	Log *base.LogObject
}

// Create applies sysctl settings.
func (c *SysctlConfigurator) Create(ctx context.Context, item dg.Item) error {
	sysctl, isSysctl := item.(Sysctl)
	if !isSysctl {
		return fmt.Errorf("invalid item type %T, expected Sysctl", item)
	}
	return c.apply(sysctl)
}

// Modify updates sysctl settings.
func (c *SysctlConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) error {
	sysctl, isSysctl := newItem.(Sysctl)
	if !isSysctl {
		return fmt.Errorf("invalid item type %T, expected Sysctl", newItem)
	}
	return c.apply(sysctl)
}

// Delete sets default sysctl settings.
func (c *SysctlConfigurator) Delete(ctx context.Context, item dg.Item) error {
	sysctl, isSysctl := item.(Sysctl)
	if !isSysctl {
		return fmt.Errorf("invalid item type %T, expected Sysctl", item)
	}
	defaultSysctl := Sysctl{
		ForApp: sysctl.ForApp,
		NetIf:  sysctl.NetIf,
	}
	if sysctl.EnableDAD != nil {
		defaultDAD := true
		defaultSysctl.EnableDAD = &defaultDAD
	}
	if sysctl.EnableARPNotify != nil {
		defaultARPNotify := false
		defaultSysctl.EnableARPNotify = &defaultARPNotify
	}
	if sysctl.BridgeCallIptables != nil {
		defaultBridgeCallIptables := true
		defaultSysctl.BridgeCallIptables = &defaultBridgeCallIptables
	}
	if sysctl.BridgeCallIp6tables != nil {
		defaultBridgeCallIp6tables := true
		defaultSysctl.BridgeCallIp6tables = &defaultBridgeCallIp6tables
	}
	return c.apply(defaultSysctl)
}

func (c *SysctlConfigurator) apply(sysctl Sysctl) error {
	if sysctl.EnableDAD != nil {
		err := c.setOption(sysctl.ForApp.NetNsName, sysctl.NetIf.IfName,
			"net/ipv6/conf/%s/accept_dad", *sysctl.EnableDAD)
		if err != nil {
			return err
		}
	}
	if sysctl.EnableARPNotify != nil {
		err := c.setOption(sysctl.ForApp.NetNsName, sysctl.NetIf.IfName,
			"net/ipv4/conf/%s/arp_notify", *sysctl.EnableARPNotify)
		if err != nil {
			return err
		}
	}
	if sysctl.BridgeCallIptables != nil {
		err := c.setOption(sysctl.ForApp.NetNsName, "",
			"net.bridge.bridge-nf-call-iptables", *sysctl.BridgeCallIptables)
		if err != nil {
			return err
		}
	}
	if sysctl.BridgeCallIp6tables != nil {
		err := c.setOption(sysctl.ForApp.NetNsName, "",
			"net.bridge.bridge-nf-call-ip6tables", *sysctl.BridgeCallIp6tables)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *SysctlConfigurator) setOption(
	netNs, ifName, keyTemplate string, enable bool) error {
	var sysctlKey string
	if ifName == "" {
		// Global option.
		sysctlKey = keyTemplate
	} else {
		sysctlKey = fmt.Sprintf(keyTemplate, ifName)
	}
	sysctlKV := sysctlKey + "=" + boolToDigitString(enable)
	out, err := namespacedCmd(netNs, "sysctl", "-w", sysctlKV).CombinedOutput()
	if err != nil {
		action := "enable"
		if !enable {
			action = "disable"
		}
		var forInterface string
		if ifName != "" {
			forInterface = " for interface " + ifName
		}
		errMsg := fmt.Errorf("failed to %s option %s%s: %s",
			action, sysctlKey, forInterface, out)
		c.Log.Error(errMsg)
		return err
	}
	return nil
}

// NeedsRecreate returns false - Modify is able to apply any change.
func (c *SysctlConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return false
}
