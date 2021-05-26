// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Track ifindex to name plus IP addresses

package zedrouter

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/vishvananda/netlink"
)

// ===== map from ifindex to ifname

type linkNameType struct {
	linkName string
	linkType string
}

var ifindexToName = make(map[int]linkNameType)

// IfindexToNameAdd adds to the map
// Returns true if added or if last flag changed.
func IfindexToNameAdd(log *base.LogObject, index int, linkName string, linkType string) bool {
	m, ok := ifindexToName[index]
	if !ok {
		// Note that we get RTM_NEWLINK even for link changes
		// hence we don't print unless the entry is new
		log.Functionf("IfindexToNameAdd index %d name %s type %s\n",
			index, linkName, linkType)
		ifindexToName[index] = linkNameType{
			linkName: linkName,
			linkType: linkType,
		}
		ifindexMaybeRemoveOld(log, index, linkName)
		// log.Tracef("ifindexToName post add %v\n", ifindexToName)
		return true
	} else if m.linkName != linkName {
		// We get this when the vifs are created with "vif*" names
		// and then changed to "bu*" etc.
		log.Functionf("IfindexToNameAdd name mismatch %s vs %s for %d\n",
			m.linkName, linkName, index)
		ifindexToName[index] = linkNameType{
			linkName: linkName,
			linkType: linkType,
		}
		ifindexMaybeRemoveOld(log, index, linkName)
		// log.Tracef("ifindexToName post add %v\n", ifindexToName)
		return false
	} else {
		return false
	}
}

// If the linkName exists under another index then remove it
func ifindexMaybeRemoveOld(log *base.LogObject, newIndex int, ifname string) {
	for index, lnt := range ifindexToName {
		if lnt.linkName == ifname && index != newIndex {
			log.Functionf("Found old ifindex %d for new %d for %s",
				index, newIndex, ifname)
			delete(ifindexToName, index)
			return
		}
	}
}

// IfindexToNameDel removes from the map
// Logs if the linkName does not match.
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
		// log.Tracef("ifindexToName post delete %v\n", ifindexToName)
		return true
	} else {
		log.Tracef("IfindexToNameDel index %d name %s\n",
			index, linkName)
		delete(ifindexToName, index)
		// log.Tracef("ifindexToName post delete %v\n", ifindexToName)
		return true
	}
}

// IfindexToName looks up the name to find the index.
// If not found in the map it checks if the kernel has it and if so
// logs and adds it to the map.
// Returns linkName, linkType
func IfindexToName(log *base.LogObject, index int) (string, string, error) {
	n, ok := ifindexToName[index]
	if ok {
		return n.linkName, n.linkType, nil
	}
	// Try a lookup to handle race
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return "", "", fmt.Errorf("Unknown kernel ifindex %d", index)
	}
	linkName := link.Attrs().Name
	linkType := link.Type()
	log.Warnf("IfindexToName(%d) fallback lookup done: %s, %s\n",
		index, linkName, linkType)
	IfindexToNameAdd(log, index, linkName, linkType)
	return linkName, linkType, nil
}

// IfnameToIndex looks up the index to find the name
// If not found in the map it checks if the kernel has it and if so
// logs and adds it to the map.
// XXX in theory this can be subject to the apparent ifindex change due to ethN to kethN
// rename, but that happens at boot and not during runtime (except moving things in and
// out of app-direct). But PbrLinkChange will update ifindexToName in that case.
func IfnameToIndex(log *base.LogObject, ifname string) (int, error) {
	for i, lnt := range ifindexToName {
		if lnt.linkName == ifname {
			return i, nil
		}
	}
	return UpdateIfnameToIndex(log, ifname)
}

// UpdateIfnameToIndex ensures that we have current info for the name and index
func UpdateIfnameToIndex(log *base.LogObject, ifname string) (int, error) {
	// Try a lookup to handle race
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		err = fmt.Errorf("Unknown kernel ifname %s: %v", ifname, err)
		log.Error(err)
		// Make sure we do not have anything stale for this ifname.
		// Could have a stale ifindex for that name due to the rename in nim.
		ifindexMaybeRemoveOld(log, -1, ifname)
		return -1, err
	}
	index := link.Attrs().Index
	linkType := link.Type()
	log.Warnf("IfnameToIndex(%s) fallback lookup done: %d, %s\n",
		ifname, index, linkType)
	IfindexToNameAdd(log, index, ifname, linkType)
	return index, nil
}
