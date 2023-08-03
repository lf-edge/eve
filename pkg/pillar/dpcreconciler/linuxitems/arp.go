// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
)

// Arp : static ARP entry.
type Arp struct {
	// AdapterLL : logical label of the associated adapter.
	AdapterLL     string
	AdapterIfName string
	IPAddr        net.IP
	HwAddr        net.HardwareAddr
}

// Name combines interface name with the IP address to create
// a unique arp entry identifier.
func (a Arp) Name() string {
	return fmt.Sprintf("%s/%v", a.AdapterIfName, a.IPAddr)
}

// Label is more human-readable than name.
func (a Arp) Label() string {
	return fmt.Sprintf("ARP entry %v / %v for %s",
		a.IPAddr, a.HwAddr, a.AdapterLL)
}

// Type of the item.
func (a Arp) Type() string {
	return genericitems.ArpTypename
}

// Equal is a comparison method for two equally-named Arp instances.
func (a Arp) Equal(other depgraph.Item) bool {
	a2 := other.(Arp)
	return bytes.Equal(a.HwAddr, a2.HwAddr)
}

// External returns false.
func (a Arp) External() bool {
	return false
}

// String describes ARP entry.
func (a Arp) String() string {
	return fmt.Sprintf("ARP entry for adapter %s; IP: %v; MAC: %v",
		a.AdapterLL, a.IPAddr, a.HwAddr)
}

// Dependencies returns the underlying adapter as the only dependency.
func (a Arp) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: genericitems.AdapterTypename,
				ItemName: a.AdapterIfName,
			},
			Description: "The associated adapter must exist (and be UP)",
		},
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: genericitems.AdapterAddrsTypename,
				ItemName: a.AdapterIfName,
			},
			MustSatisfy: func(item depgraph.Item) bool {
				addrs := item.(genericitems.AdapterAddrs)
				return len(addrs.IPAddrs) > 0
			},
			Attributes: depgraph.DependencyAttributes{
				// Linux automatically removes ARP entry when the interface
				// looses all IP addresses.
				AutoDeletedByExternal: true,
			},
			Description: "The associated adapter must have at least one IP address assigned",
		},
	}
}

// ArpConfigurator implements Configurator interface (libs/reconciler) for static ARP entries.
type ArpConfigurator struct {
	Log *base.LogObject
}

// Create configures a new ARP entry.
func (c *ArpConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	arp := item.(Arp)
	return c.arpCmd(arp.AdapterIfName, true,
		[]string{arp.IPAddr.String(), arp.HwAddr.String()}...)
}

// Modify is not implemented.
func (c *ArpConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes ARP entry.
func (c *ArpConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	arp := item.(Arp)
	return c.arpCmd(arp.AdapterIfName, false,
		[]string{arp.IPAddr.String()}...)
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *ArpConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	// Modify is not implemented
	return true
}

func (c *ArpConfigurator) arpCmd(ifName string, add bool, args ...string) error {
	var out []byte
	var err error

	cmd := "arp"
	cmdArgs := []string{"-i", ifName, "-d"}
	if add {
		cmdArgs[2] = "-s"
	}
	cmdArgs = append(cmdArgs, args...)
	c.Log.Functionf("Calling command %s %v\n", cmd, args)
	out, err = base.Exec(c.Log, cmd, cmdArgs...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("arp command \"%s\" failed: %s; output: %s",
			args, err, out)
		c.Log.Error(err)
		return err
	}
	return nil
}
