// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/maclookup"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// TunDescriptors is a thread-safe map storing tunnel file descriptors.
// Key: client ID
// Value: *os.File
var TunDescriptors sync.Map

// Tun : Linux TUN interface.
type Tun struct {
	// IfName : name of the Tun in the OS.
	IfName string
	// ClientID : ID of a gRPC client that opened this tunnel with SDN.
	ClientID string
	// MTU : Maximum transmission unit size.
	MTU uint16
	// IPAddresses : IP addresses to assign to the TUN interface.
	IPAddresses []*net.IPNet
}

// Name of the TUN instance.
func (t Tun) Name() string {
	return t.IfName
}

// Label of the TUN instance.
func (t Tun) Label() string {
	return t.IfName + " (tun)"
}

// Type assigned to TUN instances.
func (t Tun) Type() string {
	return TunTypename
}

// Equal is a comparison method for two equally-named TUN instances.
func (t Tun) Equal(other depgraph.Item) bool {
	t2 := other.(Tun)
	return t.MTU == t2.MTU &&
		t.ClientID == t2.ClientID &&
		generics.EqualSetsFn(t.IPAddresses, t2.IPAddresses, netutils.EqualIPNets)
}

// External returns false.
func (t Tun) External() bool {
	return false
}

// String describes TUN interface.
func (t Tun) String() string {
	return fmt.Sprintf("TUN: %#+v", t)
}

// Dependencies returns nothing (no dependencies).
func (t Tun) Dependencies() []depgraph.Dependency {
	return nil
}

// TunConfigurator implements Configurator interface for TUN interfaces.
type TunConfigurator struct {
	MacLookup *maclookup.MacLookup
}

// Create adds new TUN interface.
func (c *TunConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	tunCfg := item.(Tun)
	tunFile, err := utils.CreateTUN(tunCfg.IfName)
	if err != nil {
		err = fmt.Errorf("failed to create TUN %q: %w", tunCfg.IfName, err)
		log.Error(err)
		return err
	}
	TunDescriptors.Store(tunCfg.ClientID, tunFile)

	cleanupOnFailure := func() {
		TunDescriptors.Delete(tunCfg.ClientID)
		err = tunFile.Close()
		if err != nil {
			log.Warnf("Failed to close descriptor for tunnel interface %q",
				tunFile.Name())
		}
		if link, err := netlink.LinkByName(tunFile.Name()); err == nil {
			err = netlink.LinkDel(link)
			if err != nil {
				log.Warnf("Failed to remove tunnel interface %q", tunFile.Name())
			}
		}
	}

	// Get netlink TUN reference.
	link, err := netlink.LinkByName(tunCfg.IfName)
	if err != nil {
		cleanupOnFailure()
		err = fmt.Errorf("failed to get link for %q: %w", tunCfg.IfName, err)
		log.Error(err)
		return err
	}

	// Configure MTU.
	if tunCfg.MTU > 0 {
		if err := netlink.LinkSetMTU(link, int(tunCfg.MTU)); err != nil {
			cleanupOnFailure()
			err = fmt.Errorf("failed to set MTU %d on %q: %w",
				tunCfg.MTU, tunCfg.IfName, err)
			log.Error(err)
			return err
		}
	}

	// Configure IP addresses.
	for _, ipNet := range tunCfg.IPAddresses {
		addr := &netlink.Addr{IPNet: ipNet}
		if err = netlink.AddrAdd(link, addr); err != nil && !os.IsExist(err) {
			cleanupOnFailure()
			err = fmt.Errorf("failed to add IP %s to %q: %w", ipNet, tunCfg.IfName, err)
			log.Error(err)
			return err
		}
	}

	// Bring interface up
	if err = netlink.LinkSetUp(link); err != nil {
		cleanupOnFailure()
		err = fmt.Errorf("failed to bring up interface %q: %w", tunCfg.IfName, err)
		log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented (TUN is recreated on change).
func (c *TunConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes TUN interface.
func (c *TunConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	tunCfg := item.(Tun)

	// Close and remove TUN file descriptor.
	tunFileVal, ok := TunDescriptors.Load(tunCfg.ClientID)
	if !ok {
		log.Warnf("missing tunnel file descriptor for client %q", tunCfg.ClientID)
	} else {
		tunFile := tunFileVal.(*os.File)
		err := tunFile.Close()
		if err != nil {
			log.Warnf("Failed to close descriptor for tunnel interface %q",
				tunFile.Name())
		}
		TunDescriptors.Delete(tunCfg.ClientID)
	}

	link, err := netlink.LinkByName(tunCfg.IfName)
	if err != nil {
		err = fmt.Errorf("failed to select TUN %q for removal: %v",
			tunCfg.IfName, err)
		log.Error(err)
		return err
	}
	err = netlink.LinkDel(link)
	if err != nil {
		err = fmt.Errorf("failed to delete TUN %q: %v", tunCfg.IfName, err)
		log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate returns true. Modify is not implemented.
func (c *TunConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
