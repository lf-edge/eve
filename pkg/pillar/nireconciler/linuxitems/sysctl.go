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
	NetIf genericitems.NetworkIf
	// EnableDAD : enable duplicate address detection (IPv6).
	EnableDAD bool
	// EnableARPNotify : generate gratuitous arp requests when device is brought up
	// or hardware address changes
	EnableARPNotify bool
}

// Name of the item instance.
func (s Sysctl) Name() string {
	if s.ForApp.ID == emptyUUID {
		return fmt.Sprintf("sysctl-host-%s", s.NetIf.IfName)
	}
	return fmt.Sprintf("sysctl-%s-%s", s.ForApp.ID, s.NetIf.IfName)
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
	return s == s2
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
	return fmt.Sprintf(
		"%s Sysctl: {ifName: %s, enableDAD: %t, enableARPNotify: %t}",
		prefix, s.NetIf.IfName, s.EnableDAD, s.EnableARPNotify)
}

// Dependencies returns the target interface as the only dependency.
func (s Sysctl) Dependencies() (deps []dg.Dependency) {
	deps = append(deps, dg.Dependency{
		RequiredItem: s.NetIf.ItemRef,
		Description:  "interface referenced by sysctl config must exist",
	})
	return deps
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
	err := c.setDAD(sysctl.ForApp.NetNsName, sysctl.NetIf.IfName, sysctl.EnableDAD)
	if err != nil {
		return err
	}
	return c.setArpNotify(sysctl.ForApp.NetNsName, sysctl.NetIf.IfName, sysctl.EnableARPNotify)
}

// Modify updates sysctl settings.
func (c *SysctlConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) error {
	sysctl, isSysctl := newItem.(Sysctl)
	if !isSysctl {
		return fmt.Errorf("invalid item type %T, expected Sysctl", newItem)
	}
	err := c.setDAD(sysctl.ForApp.NetNsName, sysctl.NetIf.IfName, sysctl.EnableDAD)
	if err != nil {
		return err
	}
	return c.setArpNotify(sysctl.ForApp.NetNsName, sysctl.NetIf.IfName, sysctl.EnableARPNotify)
}

// Delete sets default sysctl settings.
func (c *SysctlConfigurator) Delete(ctx context.Context, item dg.Item) error {
	sysctl, isSysctl := item.(Sysctl)
	if !isSysctl {
		return fmt.Errorf("invalid item type %T, expected Sysctl", item)
	}
	err := c.setDAD(sysctl.ForApp.NetNsName, sysctl.NetIf.IfName, true)
	if err != nil {
		return err
	}
	return c.setArpNotify(sysctl.ForApp.NetNsName, sysctl.NetIf.IfName, false)
}

func (c *SysctlConfigurator) setDAD(netNs string, ifName string, enable bool) error {
	value := c.boolValueToStr(enable)
	sysctlKV := fmt.Sprintf("net/ipv6/conf/%s/accept_dad=%s", ifName, value)
	out, err := namespacedCmd(netNs, "sysctl", "-w", sysctlKV).CombinedOutput()
	if err != nil {
		errMsg := fmt.Errorf("failed to set DAD for interface %s: %s", ifName, out)
		c.Log.Error(errMsg)
		return err
	}
	return nil
}

func (c *SysctlConfigurator) setArpNotify(netNs string, ifName string, enable bool) error {
	value := c.boolValueToStr(enable)
	sysctlKV := fmt.Sprintf("net/ipv4/conf/%s/arp_notify=%s", ifName, value)
	out, err := namespacedCmd(netNs, "sysctl", "-w", sysctlKV).CombinedOutput()
	if err != nil {
		errMsg := fmt.Errorf("failed to set ARP-notify for interface %s: %s", ifName, out)
		c.Log.Error(errMsg)
		return err
	}
	return nil
}

// NeedsRecreate returns false - Modify is able to apply any change.
func (c *SysctlConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return false
}

func (c *SysctlConfigurator) boolValueToStr(enable bool) string {
	if enable {
		return "1"
	}
	return "0"
}
