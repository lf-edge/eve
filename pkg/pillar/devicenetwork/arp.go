// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// This structure contains name of interface and it's corresponding mac address, IP and subnet
type arpPort struct {
	ifName  string
	macAddr string
	addr    net.IP
	subnet  net.IPNet
}

// This structure contains name of interface on which the arp entry is programmed and
// the mac address, IP address and subnet of the destination interface.
type arpEntry struct {
	outIntf string
	macAddr string
	addr    net.IP
	subnet  net.IPNet
}

func makeArpGroups(dns types.DeviceNetworkStatus) map[string][]arpPort {
	arpGroups := map[string][]arpPort{}
	for _, port := range dns.Ports {
		// Get the IP address that belongs to given subnet
		for _, addrInfo := range port.AddrInfoList {
			subnet := &port.Subnet
			if HostFamily(addrInfo.Addr) != syscall.AF_INET {
				continue
			}
			if !subnet.Contains(addrInfo.Addr) {
				continue
			}
			port := arpPort{
				ifName:  port.IfName,
				macAddr: port.MacAddr,
				addr:    addrInfo.Addr,
				subnet:  *subnet,
			}
			if group, ok := arpGroups[subnet.String()]; ok {
				arpGroups[subnet.String()] = append(group, port)
			} else {
				arpGroups[subnet.String()] = []arpPort{port}
			}
			break
		}
	}
	return arpGroups
}

func makeArpEntries(log *base.LogObject, arpGroups map[string][]arpPort) []arpEntry {
	arpEntries := []arpEntry{}
	for key, group := range arpGroups {
		if len(group) <= 1 {
			// No ARP entries to be programmed
			continue
		}

		_, subnet, err := net.ParseCIDR(key)
		if err != nil {
			log.Errorf("makeArpEntries: Failed ParseCIDR for subnet %s", key)
			continue
		}
		for i := 0; i < len(group); i++ {
			from := group[i]
			for j := i + 1; j < len(group); j++ {
				to := group[j]
				entry := makeArpEntry(from.ifName, to.macAddr, to.addr, *subnet)
				arpEntries = append(arpEntries, entry)

				// Create reverse entry at the same time
				entry = makeArpEntry(to.ifName, from.macAddr, from.addr, *subnet)
				arpEntries = append(arpEntries, entry)
			}
		}
	}
	return arpEntries
}

func (my arpEntry) Equal(your arpEntry) bool {
	if my.outIntf != your.outIntf ||
		my.macAddr != your.macAddr ||
		my.subnet.String() != your.subnet.String() ||
		my.addr.String() != your.addr.String() {
		return false
	}
	return true
}

func makeArpEntry(outIntf string, macAddr string, addr net.IP, subnet net.IPNet) arpEntry {
	return arpEntry{
		outIntf: outIntf,
		macAddr: macAddr,
		addr:    addr,
		subnet:  subnet,
	}
}

func arpEntriesDifferent(oldEntries []arpEntry, newEntries []arpEntry) bool {
	if len(oldEntries) != len(newEntries) {
		return true
	}

	for i := 0; i < len(oldEntries); i++ {
		oldEntry := oldEntries[i]
		newEntry := newEntries[i]

		if !oldEntry.Equal(newEntry) {
			return true
		}
	}
	return false
}

func printArpEntries(log *base.LogObject, entries []arpEntry) {
	for _, e := range entries {
		log.Noticef("ARP entry - Out interface: %s, mac: %s, addr: %s, subnet: %s",
			e.outIntf, e.macAddr, e.addr.String(), e.subnet.String())
	}
}

func arpCmd(log *base.LogObject, ifname string, add bool, args ...string) (string, error) {
	var out []byte
	var err error

	cmd := "arp"
	cmdArgs := []string{"-i", ifname, "-d"}
	if add {
		cmdArgs[2] = "-s"
	}
	cmdArgs = append(cmdArgs, args...)
	if log != nil {
		log.Functionf("Calling command %s %v\n", cmd, args)
		out, err = base.Exec(log, cmd, cmdArgs...).CombinedOutput()
	} else {
		out, err = base.Exec(log, cmd, cmdArgs...).Output()
	}
	if err != nil {
		errStr := fmt.Sprintf("arp command %s failed %s output %s",
			args, err, out)
		if log != nil {
			log.Errorln(errStr)
		}
		return "", errors.New(errStr)
	}
	return string(out), nil
}

// UpdateStaticArpEntries - Update static ARP entries between interfaces in same subnet
func UpdateStaticArpEntries(ctx *DeviceNetworkContext, status types.DeviceNetworkStatus) {
	log := ctx.Log
	newArpEntries := makeArpEntries(log, makeArpGroups(status))
	item, err := ctx.PubDeviceNetworkStatus.Get("global")
	if err != nil {
		// This might be the first DeviceNetworkStatus that we are publishing
		// Add new ARP entries
		printArpEntries(log, newArpEntries)
		for _, e := range newArpEntries {
			_, err := arpCmd(log, e.outIntf, true, []string{e.addr.String(), e.macAddr}...)
			if err != nil {
				log.Errorf("UpdateStaticArpEntries: Programming ARP entry %v failed with error: %s", e, err)
			}
		}
		return
	}
	oldDNS := item.(types.DeviceNetworkStatus)

	oldArpEntries := makeArpEntries(log, makeArpGroups(oldDNS))
	if !arpEntriesDifferent(oldArpEntries, newArpEntries) {
		log.Functionf("UpdateStaticArpEntries: No change in ARP entries")
		return
	}

	// Delete old ARP entries
	for _, e := range oldArpEntries {
		_, err := arpCmd(log, e.outIntf, false, []string{e.addr.String()}...)
		if err != nil {
			log.Errorf("UpdateStaticArpEntries: Deleting ARP entry %v failed with error: %s", e, err)
		}
	}
	// Add new ARP entries
	printArpEntries(log, newArpEntries)
	for _, e := range newArpEntries {
		_, err := arpCmd(log, e.outIntf, true, []string{e.addr.String(), e.macAddr}...)
		if err != nil {
			log.Errorf("UpdateStaticArpEntries: Programming ARP %v failed with error: %s", e, err)
		}
	}
	return
}
