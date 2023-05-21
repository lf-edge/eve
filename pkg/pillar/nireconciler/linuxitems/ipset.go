// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"strings"

	dg "github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/vishvananda/netlink"
)

// IPSet : Linux ipset (https://ipset.netfilter.org/index.html).
type IPSet struct {
	// SetName : name of the IPSet.
	// See "SETNAME" in https://ipset.netfilter.org/ipset.man.html.
	SetName string
	// TypeName : type of the IPSet.
	// See "TYPENAME" in https://ipset.netfilter.org/ipset.man.html.
	// See "SET TYPES" on that website for the summary of available types.
	TypeName string
	// AddrFamily should be either AF_INET or AF_INET6.
	AddrFamily int
	// Entries : set of entries added to the IPSet.
	// Entry syntax depends on the type, for example "192.168.1.1,udp:53"
	// would be valid for typename "hash:ip,port".
	Entries []string
}

// Name returns the IPSet name.
func (s IPSet) Name() string {
	return s.SetName
}

// Label is not provided.
func (s IPSet) Label() string {
	return ""
}

// Type of the item.
func (s IPSet) Type() string {
	return generic.IPSetTypename
}

// Equal compares two IPSet instances.
func (s IPSet) Equal(other dg.Item) bool {
	s2, isIPSet := other.(IPSet)
	if !isIPSet {
		return false
	}
	return s.SetName == s2.SetName &&
		s.TypeName == s2.TypeName &&
		utils.EqualSets(s.Entries, s2.Entries)
}

// External returns false.
func (s IPSet) External() bool {
	return false
}

// String describes IPSet.
func (s IPSet) String() string {
	return fmt.Sprintf("IPSet: {setName: %s, typeName: %s, "+
		"addrFamily: %d, entries: %v}", s.SetName, s.TypeName,
		s.AddrFamily, s.Entries)
}

// Dependencies returns no dependencies.
func (s IPSet) Dependencies() (deps []dg.Dependency) {
	return nil
}

// IPSetConfigurator implements Configurator interface (libs/reconciler)
// for Linux ipset (from netfilter).
type IPSetConfigurator struct {
	Log *base.LogObject
}

const ipsetCmd = "ipset"

// Create adds new ipset.
func (c *IPSetConfigurator) Create(ctx context.Context, item dg.Item) error {
	ipset, isIPSet := item.(IPSet)
	if !isIPSet {
		return fmt.Errorf("invalid item type %T, expected IPSet", item)
	}
	var family string
	switch ipset.AddrFamily {
	case netlink.FAMILY_V4:
		family = "inet"
	case netlink.FAMILY_V6:
		family = "inet6"
	default:
		return fmt.Errorf("unsupported ipset address type: %d", ipset.AddrFamily)
	}
	args := []string{"create", ipset.SetName, ipset.TypeName, "family", family}
	if output, err := base.Exec(c.Log, ipsetCmd, args...).CombinedOutput(); err != nil {
		outputStr := strings.TrimSpace(string(output))
		err = fmt.Errorf("failed to create ipset %+v: %s (err: %w)",
			ipset, outputStr, err)
		c.Log.Error(err)
		return err
	}
	for _, entry := range ipset.Entries {
		args = []string{"add", ipset.SetName, entry}
		if output, err := base.Exec(c.Log, ipsetCmd, args...).CombinedOutput(); err != nil {
			outputStr := strings.TrimSpace(string(output))
			err = fmt.Errorf("failed to add entry %s into ipset %s: %s (err: %w)",
				entry, ipset.SetName, outputStr, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// Modify is not implemented.
// Note that zedrouter does not need to ever modify Entries - they are either static
// or dynamically managed by dnsmasq, i.e. outside zedrouter.
func (c *IPSetConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes ipset.
func (c *IPSetConfigurator) Delete(ctx context.Context, item dg.Item) error {
	ipset, isIPSet := item.(IPSet)
	if !isIPSet {
		return fmt.Errorf("invalid item type %T, expected IPSet", item)
	}
	args := []string{"destroy", ipset.SetName}
	if _, err := base.Exec(c.Log, ipsetCmd, args...).CombinedOutput(); err != nil {
		err = fmt.Errorf("failed to remove ipset %+v: %w", ipset, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *IPSetConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
