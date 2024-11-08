// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
)

// TCMirror : tc-filter rule mirroring matching packets (using tc-u32) from ingress qdisc
// of one network interface to egress qdisc of another network interface.
// See: https://man7.org/linux/man-pages/man8/tc-mirred.8.html
type TCMirror struct {
	// Rule priority, should be unique among TCMirror rules of the same FromNetIf.
	// Lower numbers indicate higher priority. For example, a rule with a priority of 1
	// will be processed before a rule with a priority of 10.
	RulePriority uint16
	// FromNetIf : network interface from which the matched traffic should be mirrored.
	FromNetIf genericitems.NetworkIf
	// ToNetIf : network interface to which the matched traffic should be mirrorer.
	ToNetIf genericitems.NetworkIf
	// L2 or L3 layer protocol to which this rule applies.
	Protocol TCMatchProtocol
	// IANA protocol number of the transport protocol to match.
	// Only valid if Protocol is either IPv4 or IPv6.
	// Use nil to disable matching by the transport protocol number.
	TransportProtocol *uint8
	// ICMP type to match.
	// Use nil to disable matching by the ICMP type number.
	// Only valid if Protocol is either IPv4 or IPv6 and TransportProtocol
	// is either 1 (ICMP) or 58 (ICMPv6).
	ICMPType *uint8
	// Transport protocol source port to match.
	// Use zero to disable matching by the transport protocol source port.
	// Only valid if Protocol is either IPv4 or IPv6.
	TransportSrcPort uint16
	// Transport protocol destination port to match.
	// Use zero to disable matching by the transport protocol destination port.
	// Only valid if Protocol is either IPv4 or IPv6.
	TransportDstPort uint16
}

// TCMatchProtocol : protocol to match by TCMirror rule.
type TCMatchProtocol uint8

const (
	// TCMatchProtoUndefined : protocol is undefined. Rule will apply to any protocol.
	TCMatchProtoUndefined TCMatchProtocol = iota
	// TCMatchProtoIPv4 : TC-Mirror rule applies to IPv4 packets.
	TCMatchProtoIPv4
	// TCMatchProtoIPv6 : TC-Mirror rule applies to IPv6 packets.
	TCMatchProtoIPv6
	// TCMatchProtoARP : TC-Mirror rule applies to ARP packets.
	TCMatchProtoARP
)

// String returns string representation of the protocol matched by a TCMirror rule.
func (p TCMatchProtocol) String() string {
	switch p {
	case TCMatchProtoUndefined:
		return "all"
	case TCMatchProtoIPv4:
		return "ip"
	case TCMatchProtoIPv6:
		return "ipv6"
	case TCMatchProtoARP:
		return "arp"
	}
	return ""
}

// Name returns unique identifier for a TC-Mirror rule.
func (tc TCMirror) Name() string {
	return fmt.Sprintf("tc-mirror/%s/%d", tc.FromNetIf.IfName, tc.RulePriority)
}

// Label for the TCMirror instance.
func (tc TCMirror) Label() string {
	return fmt.Sprintf("tc-mirror from %s to %s prio %d",
		tc.FromNetIf.IfName, tc.ToNetIf.IfName, tc.RulePriority)
}

// Type of the item.
func (tc TCMirror) Type() string {
	return TCMirrorTypename
}

// Equal compares two TCMirror instances.
func (tc TCMirror) Equal(other dg.Item) bool {
	tc2, isTCMirror := other.(TCMirror)
	if !isTCMirror {
		return false
	}
	return tc.ToNetIf == tc2.ToNetIf &&
		tc.Protocol == tc2.Protocol &&
		equalUint8Ptr(tc.TransportProtocol, tc2.TransportProtocol) &&
		equalUint8Ptr(tc.ICMPType, tc2.ICMPType) &&
		tc.TransportSrcPort == tc2.TransportSrcPort &&
		tc.TransportDstPort == tc2.TransportDstPort
}

// External returns false.
func (tc TCMirror) External() bool {
	return false
}

// String describes TCMirror.
func (tc TCMirror) String() string {
	var matchRules []string
	matchRules = append(matchRules, "protocol="+tc.Protocol.String())
	if tc.TransportProtocol != nil {
		matchRules = append(matchRules,
			fmt.Sprintf("transport-protocol=%d", *tc.TransportProtocol))
	}
	if tc.ICMPType != nil {
		matchRules = append(matchRules,
			fmt.Sprintf("ICMP-type=%d", *tc.ICMPType))
	}
	if tc.TransportSrcPort != 0 {
		matchRules = append(matchRules,
			fmt.Sprintf("transport-src-port=%d", tc.TransportSrcPort))
	}
	if tc.TransportDstPort != 0 {
		matchRules = append(matchRules,
			fmt.Sprintf("transport-dst-port=%d", tc.TransportDstPort))
	}
	return fmt.Sprintf("TC-Mirror rule from interface %s to interface %s priority %d, "+
		"matching: %v", tc.FromNetIf.IfName, tc.ToNetIf.IfName, tc.RulePriority,
		strings.Join(matchRules, ", "))
}

// Dependencies returns the source interface with ingress qdisc enabled and the destination
// interface as dependencies.
func (tc TCMirror) Dependencies() (deps []dg.Dependency) {
	deps = append(deps, dg.Dependency{
		RequiredItem: dg.Reference(TCIngress{NetIf: tc.FromNetIf}),
		Description: "interface from which packets are mirrored should exist " +
			"and have tc-ingress qdisc enabled",
		Attributes: dg.DependencyAttributes{
			AutoDeletedByExternal: true,
		},
	})
	deps = append(deps, dg.Dependency{
		RequiredItem: tc.ToNetIf.ItemRef,
		Description:  "interface to which packets are mirrored should exist",
		Attributes: dg.DependencyAttributes{
			AutoDeletedByExternal: true,
		},
	})
	return deps
}

func equalUint8Ptr(value1, value2 *uint8) bool {
	if value1 == nil || value2 == nil {
		return value1 == value2
	}
	return *value1 == *value2
}

// TCMirrorConfigurator implements Configurator interface (libs/reconciler)
// for configuring tc-filter rules mirroring selected packets.
type TCMirrorConfigurator struct {
	Log *base.LogObject
}

// Create adds tc-filter rule mirroring selected packets.
func (c *TCMirrorConfigurator) Create(ctx context.Context, item dg.Item) error {
	tcMirror, isTCMirror := item.(TCMirror)
	if !isTCMirror {
		return fmt.Errorf("invalid item type %T, expected TCMirror", item)
	}
	var args []string
	args = append(args, "filter", "add")
	args = append(args, "dev", tcMirror.FromNetIf.IfName)
	args = append(args, "parent", "ffff:") // ingress qdisc
	args = append(args, "protocol", tcMirror.Protocol.String())
	args = append(args, "prio", strconv.Itoa(int(tcMirror.RulePriority)))
	args = append(args, "u32")
	matchAll := true
	if tcMirror.TransportProtocol != nil {
		matchAll = false
		selectorName, err := c.getU32SelectorName(tcMirror)
		if err != nil {
			return err
		}
		args = append(args, "match", selectorName, "protocol",
			strconv.Itoa(int(*tcMirror.TransportProtocol)), "0xff")
	}
	if tcMirror.ICMPType != nil {
		matchAll = false
		selectorName, err := c.getU32SelectorName(tcMirror)
		if err != nil {
			return err
		}
		args = append(args, "match", selectorName, "icmp_type",
			strconv.Itoa(int(*tcMirror.ICMPType)), "0xff")
	}
	if tcMirror.TransportSrcPort != 0 {
		matchAll = false
		selectorName, err := c.getU32SelectorName(tcMirror)
		if err != nil {
			return err
		}
		args = append(args, "match", selectorName, "sport",
			strconv.Itoa(int(tcMirror.TransportSrcPort)), "0xffff")
	}
	if tcMirror.TransportDstPort != 0 {
		matchAll = false
		selectorName, err := c.getU32SelectorName(tcMirror)
		if err != nil {
			return err
		}
		args = append(args, "match", selectorName, "dport",
			strconv.Itoa(int(tcMirror.TransportDstPort)), "0xffff")
	}
	if matchAll {
		// The u32 classifier requires at least one match statement, even if the intention
		// is to match all packets of a specific protocol type (like ARP).
		// "match u32 0 0" fulfills this requirement by acting as a wildcard match,
		// allowing to capture all packets that satisfy the Protocol condition.
		args = append(args, "match", "u32", "0", "0")
	}
	args = append(args, "action", "mirred", "egress", "mirror", "dev",
		tcMirror.ToNetIf.IfName)
	output, err := exec.Command("tc", args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to add tc-rule mirroring traffic from %s to %s: %s (%w)",
			tcMirror.FromNetIf.IfName, tcMirror.ToNetIf.IfName, output, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented.
func (c *TCMirrorConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes tc-filter rule mirroring selected packets.
func (c *TCMirrorConfigurator) Delete(ctx context.Context, item dg.Item) error {
	tcMirror, isTCMirror := item.(TCMirror)
	if !isTCMirror {
		return fmt.Errorf("invalid item type %T, expected TCMirror", item)
	}
	var args []string
	args = append(args, "filter", "delete")
	args = append(args, "dev", tcMirror.FromNetIf.IfName)
	args = append(args, "parent", "ffff:") // ingress qdisc
	args = append(args, "prio", strconv.Itoa(int(tcMirror.RulePriority)))
	output, err := exec.Command("tc", args...).CombinedOutput()
	if err != nil {
		isDevNotFound := strings.Contains(string(output),
			fmt.Sprintf("Cannot find device \"%s\"", tcMirror.FromNetIf.IfName))
		if isDevNotFound {
			// Ignore if interface was already deleted and therefore Linux has
			// automatically removed the tc-filter rule.
			c.Log.Warn(err)
			err = nil
		} else {
			err = fmt.Errorf(
				"failed to delete tc-rule mirroring traffic from %s to %s: %s (%w)",
				tcMirror.FromNetIf.IfName, tcMirror.ToNetIf.IfName, output, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *TCMirrorConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}

// Get name of the selector to use for the given L2/L3 protocol.
// See SELECTOR in https://man7.org/linux/man-pages/man8/tc-u32.8.html
func (c *TCMirrorConfigurator) getU32SelectorName(tcMirror TCMirror) (string, error) {
	switch tcMirror.Protocol {
	case TCMatchProtoIPv4:
		return "ip", nil
	case TCMatchProtoIPv6:
		return "ip6", nil
	case TCMatchProtoARP:
		return "", errors.New("cannot use u32 selector for ARP protocol")
	}
	return "", errors.New("cannot use u32 selector for an undefined L2/L3 protocol")
}
