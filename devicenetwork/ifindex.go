// Copyright (c) 2017-2019 Zededa, Inc.
// All rights reserved.

// Track ifindex to name plus IP addresses

package devicenetwork

import (
	"errors"
	"fmt"
	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
	"net"
)

// ===== map from ifindex to ifname

type linkNameType struct {
	linkName string
	linkType string
	lastFlag bool // Set for interfaces which are deemed interesting by caller
}

var ifindexToName map[int]linkNameType

func IfindexToNameInit() {
	ifindexToName = make(map[int]linkNameType)
}

// Returns true if added or if last flag changed.
func IfindexToNameAdd(index int, linkName string, linkType string, last bool) bool {
	m, ok := ifindexToName[index]
	if !ok {
		// Note that we get RTM_NEWLINK even for link changes
		// hence we don't print unless the entry is new
		log.Infof("IfindexToNameAdd index %d name %s type %s\n",
			index, linkName, linkType)
		ifindexToName[index] = linkNameType{
			linkName: linkName,
			linkType: linkType,
			lastFlag: last,
		}
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return true
	} else if m.linkName != linkName {
		// We get this when the vifs are created with "vif*" names
		// and then changed to "bu*" etc.
		log.Infof("IfindexToNameAdd name mismatch %s vs %s for %d\n",
			m.linkName, linkName, index)
		ifindexToName[index] = linkNameType{
			linkName: linkName,
			linkType: linkType,
			lastFlag: last,
		}
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return false
	} else if m.lastFlag != last {
		log.Infof("IfindexToNameAdd lastFlag changed to %v for %s\n",
			last, linkName)
		ifindexToName[index] = linkNameType{
			linkName: linkName,
			linkType: linkType,
			lastFlag: last,
		}
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return true
	} else {
		return false
	}
}

// Returns true if deleted
func IfindexToNameDel(index int, linkName string) bool {
	m, ok := ifindexToName[index]
	if !ok {
		log.Errorf("IfindexToNameDel unknown index %d\n", index)
		return false
	} else if m.linkName != linkName {
		log.Errorf("IfindexToNameDel name mismatch %s vs %s for %d\n",
			m.linkName, linkName, index)
		delete(ifindexToName, index)
		// log.Debugf("ifindexToName post delete %v\n", ifindexToName)
		return true
	} else {
		log.Debugf("IfindexToNameDel index %d name %s\n",
			index, linkName)
		delete(ifindexToName, index)
		// log.Debugf("ifindexToName post delete %v\n", ifindexToName)
		return true
	}
}

// Returns linkName, linkType
func IfindexToName(index int) (string, string, error) {
	n, ok := ifindexToName[index]
	if ok {
		return n.linkName, n.linkType, nil
	}
	// Try a lookup to handle race
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return "", "", errors.New(fmt.Sprintf("Unknown ifindex %d", index))
	}
	linkName := link.Attrs().Name
	linkType := link.Type()
	log.Warnf("IfindexToName(%d) fallback lookup done: %s, %s\n",
		index, linkName, linkType)
	lastFlag := RelevantLastResort(link)
	IfindexToNameAdd(index, linkName, linkType, lastFlag)
	return linkName, linkType, nil
}

func IfnameToIndex(ifname string) (int, error) {
	for i, lnt := range ifindexToName {
		if lnt.linkName == ifname {
			return i, nil
		}
	}
	// Try a lookup to handle race
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return -1, errors.New(fmt.Sprintf("Unknown ifname %s", ifname))
	}
	index := link.Attrs().Index
	linkType := link.Type()
	log.Warnf("IfnameToIndex(%s) fallback lookup done: %d, %s\n",
		ifname, index, linkType)
	lastFlag := RelevantLastResort(link)
	IfindexToNameAdd(index, ifname, linkType, lastFlag)
	return index, nil
}

// We skip things not considered to be device links, loopback, non-broadcast,
// and children of a bridge master.
func RelevantLastResort(link netlink.Link) bool {
	attrs := link.Attrs()
	ifname := attrs.Name
	linkType := link.Type()
	linkFlags := attrs.Flags
	loopbackFlag := (linkFlags & net.FlagLoopback) != 0
	broadcastFlag := (linkFlags & net.FlagBroadcast) != 0
	upFlag := (attrs.OperState == netlink.OperUp)
	if linkType == "device" && !loopbackFlag && broadcastFlag &&
		attrs.MasterIndex == 0 {

		log.Infof("Relevant %s up %t operState %s\n",
			ifname, upFlag, attrs.OperState.String())
		return true
	} else {
		return false
	}
}

func IfindexGetLastResort() []string {
	var ifs []string
	for _, lnt := range ifindexToName {
		if lnt.lastFlag {
			ifs = append(ifs, lnt.linkName)
		}
	}
	return ifs
}

// ===== map from ifindex to list of IP addresses

var ifindexToAddrs map[int][]net.IPNet

func IfindexToAddrsInit() {
	ifindexToAddrs = make(map[int][]net.IPNet)
}

// Returns true if added
func IfindexToAddrsAdd(index int, addr net.IPNet) bool {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		log.Debugf("IfindexToAddrsAdd add %v for %d\n", addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Debugf("ifindexToAddrs post add %v\n", ifindexToAddrs)
		return true
	}
	found := false
	for _, a := range addrs {
		// Equal if containment in both directions?
		if a.IP.Equal(addr.IP) &&
			a.Contains(addr.IP) && addr.Contains(a.IP) {
			found = true
			break
		}
	}
	if !found {
		log.Debugf("IfindexToAddrsAdd add %v for %d\n", addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Debugf("ifindexToAddrs post add %v\n", ifindexToAddrs)
	}
	return !found
}

// Returns true if deleted
func IfindexToAddrsDel(index int, addr net.IPNet) bool {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		log.Warnf("IfindexToAddrsDel unknown index %d\n", index)
		return false
	}
	for i, a := range addrs {
		// Equal if containment in both directions?
		if a.IP.Equal(addr.IP) &&
			a.Contains(addr.IP) && addr.Contains(a.IP) {
			log.Debugf("IfindexToAddrsDel del %v for %d\n",
				addr, index)
			ifindexToAddrs[index] = append(ifindexToAddrs[index][:i],
				ifindexToAddrs[index][i+1:]...)
			// log.Debugf("ifindexToAddrs post remove %v\n", ifindexToAddrs)
			// XXX should we check for zero and remove ifindex?
			return true
		}
	}
	log.Warnf("IfindexToAddrsDel address %v not found for %d in %+v\n",
		addr, index, addrs)
	return false
}

func IfindexToAddrs(index int) ([]net.IPNet, error) {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Unknown ifindex %d", index))
	}
	return addrs, nil
}
