// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Track ifindex to name plus IP addresses

package devicenetwork

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// ===== map from ifindex to ifname

type linkNameType struct {
	linkName     string
	linkType     string
	relevantFlag bool // Set for interfaces which are deemed interesting by caller
	upFlag       bool // last resort and up
}

var ifindexToName map[int]linkNameType = make(map[int]linkNameType)

// Returns true if added or if last flag changed.
func IfindexToNameAdd(log *base.LogObject, index int, linkName string, linkType string, relevantFlag bool, upFlag bool) bool {
	m, ok := ifindexToName[index]
	if !ok {
		// Note that we get RTM_NEWLINK even for link changes
		// hence we don't print unless the entry is new
		log.Infof("IfindexToNameAdd index %d name %s type %s\n",
			index, linkName, linkType)
		ifindexToName[index] = linkNameType{
			linkName:     linkName,
			linkType:     linkType,
			relevantFlag: relevantFlag,
			upFlag:       upFlag,
		}
		ifindexMaybeRemoveOld(log, index, linkName)
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return true
	} else if m.linkName != linkName {
		// We get this when the vifs are created with "vif*" names
		// and then changed to "bu*" etc.
		log.Infof("IfindexToNameAdd name mismatch %s vs %s for %d\n",
			m.linkName, linkName, index)
		ifindexToName[index] = linkNameType{
			linkName:     linkName,
			linkType:     linkType,
			relevantFlag: relevantFlag,
			upFlag:       upFlag,
		}
		ifindexMaybeRemoveOld(log, index, linkName)
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return false
	} else if m.relevantFlag != relevantFlag || m.upFlag != upFlag {
		log.Infof("IfindexToNameAdd flag(s) changed to %v/%v for %s\n",
			relevantFlag, upFlag, linkName)
		ifindexToName[index] = linkNameType{
			linkName:     linkName,
			linkType:     linkType,
			relevantFlag: relevantFlag,
			upFlag:       upFlag,
		}
		ifindexMaybeRemoveOld(log, index, linkName)
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return true
	} else {
		return false
	}
}

// If the linkName exists under another index then remove it
func ifindexMaybeRemoveOld(log *base.LogObject, newIndex int, ifname string) {
	for index, lnt := range ifindexToName {
		if lnt.linkName == ifname && index != newIndex {
			log.Infof("Found old ifindex %d for new %d for %s",
				index, newIndex, ifname)
			delete(ifindexToName, index)
			return
		}
	}
}

// Returns true if deleted
func IfindexToNameDel(log *base.LogObject, index int, linkName string) bool {
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
func IfindexToName(log *base.LogObject, index int) (string, string, error) {
	n, ok := ifindexToName[index]
	if ok {
		return n.linkName, n.linkType, nil
	}
	// Try a lookup to handle race
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return "", "", errors.New(fmt.Sprintf("Unknown kernel ifindex %d", index))
	}
	linkName := link.Attrs().Name
	linkType := link.Type()
	log.Warnf("IfindexToName(%d) fallback lookup done: %s, %s\n",
		index, linkName, linkType)
	relevantFlag, upFlag := RelevantLastResort(log, link)
	IfindexToNameAdd(log, index, linkName, linkType, relevantFlag, upFlag)
	return linkName, linkType, nil
}

func IfnameToIndex(log *base.LogObject, ifname string) (int, error) {
	for i, lnt := range ifindexToName {
		if lnt.linkName == ifname {
			return i, nil
		}
	}
	// Try a lookup to handle race
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return -1, errors.New(fmt.Sprintf("Unknown kernel ifname %s", ifname))
	}
	index := link.Attrs().Index
	linkType := link.Type()
	log.Warnf("IfnameToIndex(%s) fallback lookup done: %d, %s\n",
		ifname, index, linkType)
	relevantFlag, upFlag := RelevantLastResort(log, link)
	IfindexToNameAdd(log, index, ifname, linkType, relevantFlag, upFlag)
	return index, nil
}

// We skip things not considered to be device links, loopback, non-broadcast,
// and children of a bridge master.
// Match "vif.*" and "nbu.*" for name and skip those as well.
// Returns (relevant, up)
func RelevantLastResort(log *base.LogObject, link netlink.Link) (bool, bool) {
	attrs := link.Attrs()
	ifname := attrs.Name
	linkType := link.Type()
	linkFlags := attrs.Flags
	loopbackFlag := (linkFlags & net.FlagLoopback) != 0
	broadcastFlag := (linkFlags & net.FlagBroadcast) != 0
	adminUpFlag := (linkFlags & net.FlagUp) != 0
	upFlag := (attrs.OperState == netlink.OperUp)
	isVif := strings.HasPrefix(ifname, "vif") || strings.HasPrefix(ifname, "nbu") || strings.HasPrefix(ifname, "nbo")
	if linkType == "device" && !loopbackFlag && broadcastFlag &&
		attrs.MasterIndex == 0 && !isVif {

		log.Infof("Relevant %s adminUp %t operState %s\n",
			ifname, adminUpFlag, attrs.OperState.String())
		return true, upFlag
	} else {
		return false, false
	}
}

// Return map[string] bool up
func IfindexGetLastResortMap() map[string]bool {
	ifs := make(map[string]bool, len(ifindexToName))
	for _, lnt := range ifindexToName {
		if lnt.relevantFlag {
			ifs[lnt.linkName] = lnt.upFlag
		}
	}
	return ifs
}

// ===== map from ifindex to list of IP addresses

var ifindexToAddrs = make(map[int][]net.IP)

// Returns true if added
func IfindexToAddrsAdd(log *base.LogObject, index int, addr net.IP) bool {
	log.Debugf("IfindexToAddrsAdd(%d, %s)", index, addr.String())
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		log.Debugf("IfindexToAddrsAdd add %v for %d\n", addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Debugf("ifindexToAddrs post add %v\n", ifindexToAddrs)
		return true
	}
	found := false
	for _, a := range addrs {
		if a.Equal(addr) {
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
func IfindexToAddrsDel(log *base.LogObject, index int, addr net.IP) bool {
	log.Debugf("IfindexToAddrsDel(%d, %s)", index, addr.String())
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		log.Warnf("IfindexToAddrsDel unknown index %d\n", index)
		return false
	}
	for i, a := range addrs {
		if a.Equal(addr) {
			log.Debugf("IfindexToAddrsDel del %v for %d\n",
				addr, index)
			if i+1 == len(addrs) {
				ifindexToAddrs[index] = ifindexToAddrs[index][:i]
			} else {
				ifindexToAddrs[index] = append(ifindexToAddrs[index][:i],
					ifindexToAddrs[index][i+1:]...)
			}
			// log.Debugf("ifindexToAddrs post remove %v\n", ifindexToAddrs)
			// XXX should we check for zero and remove ifindex?
			return true
		}
	}
	log.Warnf("IfindexToAddrsDel address %v not found for %d in %+v\n",
		addr, index, addrs)
	return false
}

func IfindexToAddrs(log *base.LogObject, index int) ([]net.IP, error) {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Unknown ifindex %d", index))
	}
	return addrs, nil
}

func IfindexToAddrsFlush(log *base.LogObject, index int) {
	_, ok := ifindexToAddrs[index]
	if !ok {
		log.Warnf("IfindexToAddrsFlush: Unknown ifindex %d", index)
		return
	}
	log.Infof("IfindexToAddrsFlush(%d) removing %v",
		index, ifindexToAddrs[index])
	var addrs []net.IP
	ifindexToAddrs[index] = addrs
}

func IfnameToAddrsFlush(log *base.LogObject, ifname string) {
	log.Infof("IfNameToAddrsFlush(%s)", ifname)
	index, err := IfnameToIndex(log, ifname)
	if err != nil {
		log.Warnf("IfnameToAddrsFlush: Unknown ifname %s: %s", ifname, err)
		return
	}
	IfindexToAddrsFlush(log, index)
}
