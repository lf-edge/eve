// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
)

// TCIngress : enable ingress traffic control (tc) qdisc for a network interface.
// See: https://tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.adv-qdisc.ingress.html
type TCIngress struct {
	// NetIf : network interface which will have ingress qdisc enabled.
	NetIf genericitems.NetworkIf
}

// Name returns the interface name on which tc-ingress qdisc is enabled.
// This ensures that there cannot be two different TCIngress instances
// that would attempt to enable tc-ingress on the same interface at the same time.
func (tc TCIngress) Name() string {
	return tc.NetIf.IfName
}

// Label for the TCIngress instance.
func (tc TCIngress) Label() string {
	return "TC-Ingress for " + tc.NetIf.IfName
}

// Type of the item.
func (tc TCIngress) Type() string {
	return TCIngressTypename
}

// Equal compares two TCIngress instances.
func (tc TCIngress) Equal(other dg.Item) bool {
	tc2, isTCIngress := other.(TCIngress)
	if !isTCIngress {
		return false
	}
	return tc == tc2
}

// External returns false.
func (tc TCIngress) External() bool {
	return false
}

// String describes TCIngress.
func (tc TCIngress) String() string {
	return fmt.Sprintf("TC-Ingress qdisc for interface: %s", tc.NetIf.IfName)
}

// Dependencies returns the interface on which the tc-ingress qdisc should be enabled.
func (tc TCIngress) Dependencies() (deps []dg.Dependency) {
	deps = append(deps, dg.Dependency{
		RequiredItem: tc.NetIf.ItemRef,
		Description:  "interface on which tc-ingress should be enabled must exist",
		Attributes: dg.DependencyAttributes{
			AutoDeletedByExternal: true,
		},
	})
	return deps
}

// TCIngressConfigurator implements Configurator interface (libs/reconciler)
// for enabling TC-Ingress qdisc.
type TCIngressConfigurator struct {
	Log *base.LogObject
}

// Create enables tc-ingress qdisc on an interface.
func (c *TCIngressConfigurator) Create(ctx context.Context, item dg.Item) error {
	tcIngress, isTCIngress := item.(TCIngress)
	if !isTCIngress {
		return fmt.Errorf("invalid item type %T, expected TCIngress", item)
	}
	var args []string
	args = append(args, "qdisc", "add", "dev", tcIngress.NetIf.IfName, "ingress")
	output, err := exec.Command("tc", args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to add tc-ingress qdisc for interface %s: %s (%w)",
			tcIngress.NetIf.IfName, output, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented.
func (c *TCIngressConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete disabled tc-ingress qdisc on an interface.
func (c *TCIngressConfigurator) Delete(ctx context.Context, item dg.Item) error {
	tcIngress, isTCIngress := item.(TCIngress)
	if !isTCIngress {
		return fmt.Errorf("invalid item type %T, expected TCIngress", item)
	}
	var args []string
	args = append(args, "qdisc", "delete", "dev", tcIngress.NetIf.IfName, "ingress")
	output, err := exec.Command("tc", args...).CombinedOutput()
	if err != nil {
		isDevNotFound := strings.Contains(string(output),
			fmt.Sprintf("Cannot find device \"%s\"", tcIngress.NetIf.IfName))
		if isDevNotFound {
			// Ignore if interface was already deleted and therefore Linux has
			// automatically removed the tc-filter rule.
			c.Log.Warn(err)
			err = nil
		} else {
			err = fmt.Errorf("failed to delete tc-ingress qdisc from interface %s: %s (%w)",
				tcIngress.NetIf.IfName, output, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *TCIngressConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
