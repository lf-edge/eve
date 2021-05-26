// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"fmt"
	"net"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

// UpdateBridge ensures that all of the Ethernet interfaces
// which will be used are in the form of a bridge, and all unused/pciback
// Ethernet interfaces have no bridge
// Assumes that the caller has checked that the interfaces exist
// We therefore skip any interfaces which do not exist
func UpdateBridge(log *base.LogObject, newConfig, oldConfig types.DevicePortConfig) {

	// Look for adds
	for _, newU := range newConfig.Ports {
		oldU := lookupOnIfname(oldConfig, newU.IfName)
		if oldU == nil {
			addBridge(log, newU.IfName)
		} else {
			log.Functionf("UpdateBridge: found old %v", oldU)
		}
	}
	// Look for deletes from oldConfig to newConfig
	for _, oldU := range oldConfig.Ports {
		newU := lookupOnIfname(newConfig, oldU.IfName)
		if newU == nil {
			removeBridge(log, oldU.IfName)
		} else {
			log.Functionf("UpdateBridge: found new %v", newU)
		}
	}
}

// Check if the name is an Ethernet and not a bridge
// If so rename it to kethN and create a bridge and name it ethN
// and move the MAC address
func addBridge(log *base.LogObject, ifname string) error {
	log.Noticef("addBridge(%s)", ifname)
	if !strings.HasPrefix(ifname, "eth") {
		log.Functionf("addBridge: skipping %s", ifname)
		return nil
	}
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		// Caller should have checked
		err = fmt.Errorf("addBridge LinkByName(%s) failed: %v",
			ifname, err)
		log.Error(err)
		return err
	}
	linkType := link.Type()
	if linkType != "device" {
		log.Noticef("addBridge: skipping %s type %s",
			ifname, linkType)
		return nil
	}
	kernIfname := "k" + ifname
	_, err = netlink.LinkByName(kernIfname)
	if err == nil {
		err = fmt.Errorf("addBridge new name %s already exists",
			kernIfname)
		log.Error(err)
		return err
	}

	// get macaddr and create the alternate with the group bit toggled
	macAddr := link.Attrs().HardwareAddr
	var altMacAddr net.HardwareAddr
	if len(macAddr) != 0 {
		altMacAddr = make([]byte, len(macAddr))
		copy(altMacAddr, macAddr)
		altMacAddr[0] = altMacAddr[0] ^ 2
		log.Noticef("macAddr %s altMacAddr %s", macAddr, altMacAddr)

		// Toggle macaddr on ifname - set to altMacAddr
		if err := netlink.LinkSetHardwareAddr(link, altMacAddr); err != nil {
			err = fmt.Errorf("addBridge LinkSetHardwareAddr(%s, %s) failed: %v",
				ifname, altMacAddr, err)
			log.Error(err)
			return err
		}
	}
	if err := types.IfRename(log, ifname, kernIfname); err != nil {
		err = fmt.Errorf("addBridge IfRename(%s, %s) failed: %v",
			ifname, kernIfname, err)
		log.Error(err)
		return err
	}

	// create bridge and name it ethN use macAddr
	attrs := netlink.NewLinkAttrs()
	attrs.Name = ifname
	attrs.HardwareAddr = macAddr
	bridge := &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(bridge); err != nil {
		err = fmt.Errorf("addBridge LinkAdd(%s) failed: %v",
			ifname, err)
		log.Error(err)
		return err
	}
	// Look up again after rename
	kernLink, err := netlink.LinkByName(kernIfname)
	if err != nil {
		err = fmt.Errorf("addBridge LinkByName(%s) failed: %v",
			kernIfname, err)
		log.Error(err)
		return err
	}
	// ip link set kethN master ethN
	if err := netlink.LinkSetMaster(kernLink, bridge); err != nil {
		err = fmt.Errorf("addBridge LinkSetMaster(%s, %s) failed: %v",
			kernIfname, ifname, err)
		log.Error(err)
		return err
	}
	if err := netlink.LinkSetUp(bridge); err != nil {
		err = fmt.Errorf("addBridge LinkSetUp(%s) failed: %v",
			ifname, err)
		log.Error(err)
		return err
	}
	// update cached ifindex
	_, err = UpdateIfnameToIndex(log, ifname)
	if err != nil {
		log.Errorf("addBridge: UpdateIfnameToIndex failed: %v", err)
	}
	return nil
}

// Check if the name is ethN and a bridge
// If so delete it and find kethN and rename it back to ethN.
// Also restore the Mac address on ethN
func removeBridge(log *base.LogObject, ifname string) error {
	log.Noticef("removeBridge(%s)", ifname)
	if !strings.HasPrefix(ifname, "eth") {
		log.Functionf("removeBridge: skipping %s", ifname)
		return nil
	}
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		// Caller should have checked
		err = fmt.Errorf("removeBridge LinkByName(%s) failed: %v",
			ifname, err)
		log.Error(err)
		return err
	}
	linkType := link.Type()
	if linkType != "bridge" {
		log.Noticef("removeBridge: skipping %s type %s",
			ifname, linkType)
		return nil
	}
	kernIfname := "k" + ifname
	kernLink, err := netlink.LinkByName(kernIfname)
	if err != nil {
		err = fmt.Errorf("removeBridge LinkByName(%s) failed: %v",
			kernIfname, err)
		log.Error(err)
		return err
	}
	// get macaddr and create the alternate with the group bit toggled
	macAddr := kernLink.Attrs().HardwareAddr
	var altMacAddr net.HardwareAddr
	if len(macAddr) != 0 {
		altMacAddr = make([]byte, len(macAddr))
		copy(altMacAddr, macAddr)
		altMacAddr[0] = altMacAddr[0] ^ 2
		log.Noticef("macAddr %s altMacAddr %s", macAddr, altMacAddr)
	}
	// ip link set kethN nomaster
	if err := netlink.LinkSetNoMaster(kernLink); err != nil {
		err = fmt.Errorf("removeBridge LinkSetNoMaster(%s) failed: %v",
			kernIfname, err)
		log.Error(err)
		return err
	}
	// delete bridge link
	attrs := netlink.NewLinkAttrs()
	attrs.Name = ifname
	bridge := &netlink.Bridge{LinkAttrs: attrs}
	netlink.LinkDel(bridge)

	if len(altMacAddr) != 0 {
		// Toggle macaddr on kernIfname - set to altMacAddr
		if err := netlink.LinkSetHardwareAddr(kernLink, altMacAddr); err != nil {
			err = fmt.Errorf("removeBridge LinkSetHardwareAddr(%s, %s) failed: %v",
				kernIfname, altMacAddr, err)
			log.Error(err)
			return err
		}
	}
	if err := types.IfRename(log, kernIfname, ifname); err != nil {
		err = fmt.Errorf("removeBridge IfRename(%s, %s) failed: %v",
			kernIfname, ifname, err)
		log.Error(err)
		return err
	}
	// update cached ifindex
	_, err = UpdateIfnameToIndex(log, ifname)
	if err != nil {
		log.Errorf("removeBridge: UpdateIfnameToIndex failed: %v", err)
	}
	return nil
}
