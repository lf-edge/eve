// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"net"

	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

// BondMode specifies the policy indicating how bonding members are used
// during network transmissions.
type BondMode uint8

const (
	// BondModeUnspecified : default is Round-Robin
	BondModeUnspecified BondMode = iota
	// BondModeBalanceRR : Round-Robin
	BondModeBalanceRR
	// BondModeActiveBackup : Active/Backup
	BondModeActiveBackup
	// BondModeBalanceXOR : select member for a packet using a hash function
	BondModeBalanceXOR
	// BondModeBroadcast : send every packet on all members
	BondModeBroadcast
	// BondMode802Dot3AD : IEEE 802.3ad Dynamic link aggregation
	BondMode802Dot3AD
	// BondModeBalanceTLB : Adaptive transmit load balancing
	BondModeBalanceTLB
	// BondModeBalanceALB : Adaptive load balancing
	BondModeBalanceALB
)

// LacpRate specifies the rate in which EVE will ask LACP link partners
// to transmit LACPDU packets in 802.3ad mode.
type LacpRate uint8

const (
	// LacpRateUnspecified : default is Slow.
	LacpRateUnspecified LacpRate = iota
	// LacpRateSlow : Request partner to transmit LACPDUs every 30 seconds.
	LacpRateSlow
	// LacpRateFast : Request partner to transmit LACPDUs every 1 second.
	LacpRateFast
)

// BondConfig - Bond (LAG) interface configuration.
type BondConfig struct {
	// Logical names of PhysicalIO network adapters aggregated by this bond.
	AggregatedPorts []string `json:",omitempty"`

	// Bonding policy.
	Mode BondMode `json:",omitempty"`

	// LACPDU packets transmission rate.
	// Applicable for BondMode802Dot3AD only.
	LacpRate LacpRate `json:",omitempty"`

	// Link monitoring is either disabled or one of the monitors
	// is enabled, never both at the same time.
	MIIMonitor BondMIIMonitor `json:",omitempty"`
	ARPMonitor BondArpMonitor `json:",omitempty"`
}

// BondMIIMonitor : MII link monitoring parameters (see devmodel.proto for description).
type BondMIIMonitor struct {
	Enabled   bool   `json:",omitempty"`
	Interval  uint32 `json:",omitempty"`
	UpDelay   uint32 `json:",omitempty"`
	DownDelay uint32 `json:",omitempty"`
}

// BondArpMonitor : ARP-based link monitoring parameters (see devmodel.proto for description).
type BondArpMonitor struct {
	Enabled   bool     `json:",omitempty"`
	Interval  uint32   `json:",omitempty"`
	IPTargets []net.IP `json:",omitempty"`
}

// Equal compares two BondConfig values for equality.
func (b BondConfig) Equal(b2 BondConfig) bool {
	return b.Mode == b2.Mode &&
		b.LacpRate == b2.LacpRate &&
		generics.EqualSets(b.AggregatedPorts, b2.AggregatedPorts) &&
		b.MIIMonitor == b2.MIIMonitor &&
		b.ARPMonitor.Equal(b2.ARPMonitor)
}

// Equal compares two BondArpMonitor configs for equality.
func (m BondArpMonitor) Equal(m2 BondArpMonitor) bool {
	return m.Enabled == m2.Enabled &&
		m.Interval == m2.Interval &&
		generics.EqualSetsFn(m.IPTargets, m2.IPTargets, netutils.EqualIPs)
}

// BondStatus : runtime status of a bond adapter.
// Only meaningful when L2Type == L2LinkTypeBond.
type BondStatus struct {
	// Mode is the bonding mode currently applied.
	Mode BondMode
	// ActiveMember is the logical label of the currently active member interface.
	// Applicable for active-backup, balance-tlb and balance-alb modes.
	ActiveMember string
	// MIIMonitor reports MII link monitoring parameters (if enabled).
	MIIMonitor BondMIIMonitorStatus
	// ARPMonitor reports ARP link monitoring parameters (if enabled).
	ARPMonitor BondARPMonitorStatus
	// LACP reports 802.3ad LACP status (only for BondMode802Dot3AD).
	LACP BondLACPStatus
	// Members contains per-member runtime status.
	Members []BondMemberStatus
}

// BondMemberStatus : per-member runtime status within a bond.
type BondMemberStatus struct {
	// Logicallabel of the member port.
	Logicallabel string
	// MIIUp indicates whether the member's MII link is up.
	MIIUp bool
	// LACP contains LACP-specific status (802.3ad only).
	LACP *BondMemberLACPStatus
}

// BondMIIMonitorStatus : MII monitoring status as applied by the bond driver.
type BondMIIMonitorStatus struct {
	Enabled         bool
	PollingInterval uint32 // in milliseconds
	UpDelay         uint32 // in milliseconds
	DownDelay       uint32 // in milliseconds
}

// BondARPMonitorStatus : ARP monitoring status as applied by the bond driver.
type BondARPMonitorStatus struct {
	Enabled         bool
	PollingInterval uint32 // in milliseconds
	IPTargets       []net.IP
	MissedMax       uint32
}

// BondLACPStatus : 802.3ad LACP status.
type BondLACPStatus struct {
	Enabled            bool
	LACPRate           LacpRate
	ActiveAggregatorID uint16
	PartnerMAC         net.HardwareAddr
	ActorKey           uint16
	PartnerKey         uint16
}

// BondMemberLACPStatus : per-member LACP status.
type BondMemberLACPStatus struct {
	// AggregatorID to which this member is assigned.
	AggregatorID uint16
	// ActorChurnState for this member.
	ActorChurnState BondLACPChurnState
	// PartnerChurnState for this member.
	PartnerChurnState BondLACPChurnState
}

// BondLACPChurnState represents the LACP churn detection state.
type BondLACPChurnState uint8

const (
	// BondLACPChurnNone means no churn detected — LACP negotiation is stable.
	BondLACPChurnNone BondLACPChurnState = iota
	// BondLACPChurnMonitoring means waiting to confirm stability.
	BondLACPChurnMonitoring
	// BondLACPChurnChurned means the partner is frequently changing parameters.
	BondLACPChurnChurned
)

// Equal compares two BondStatus values.
func (s BondStatus) Equal(s2 BondStatus) bool {
	return s.Mode == s2.Mode &&
		s.ActiveMember == s2.ActiveMember &&
		s.MIIMonitor == s2.MIIMonitor &&
		s.ARPMonitor.Equal(s2.ARPMonitor) &&
		s.LACP.Equal(s2.LACP) &&
		generics.EqualSetsFn(s.Members, s2.Members, func(a, b BondMemberStatus) bool {
			return a.Equal(b)
		})
}

// Equal compares two BondMemberStatus values.
func (s BondMemberStatus) Equal(s2 BondMemberStatus) bool {
	if s.Logicallabel != s2.Logicallabel || s.MIIUp != s2.MIIUp {
		return false
	}
	if (s.LACP == nil) != (s2.LACP == nil) {
		return false
	}
	if s.LACP != nil && *s.LACP != *s2.LACP {
		return false
	}
	return true
}

// Equal compares two BondARPMonitorStatus values.
func (m BondARPMonitorStatus) Equal(m2 BondARPMonitorStatus) bool {
	return m.Enabled == m2.Enabled &&
		m.PollingInterval == m2.PollingInterval &&
		m.MissedMax == m2.MissedMax &&
		generics.EqualSetsFn(m.IPTargets, m2.IPTargets, netutils.EqualIPs)
}

// Equal compares two BondLACPStatus values.
func (l BondLACPStatus) Equal(l2 BondLACPStatus) bool {
	return l.Enabled == l2.Enabled &&
		l.LACPRate == l2.LACPRate &&
		l.ActiveAggregatorID == l2.ActiveAggregatorID &&
		bytes.Equal(l.PartnerMAC, l2.PartnerMAC) &&
		l.ActorKey == l2.ActorKey &&
		l.PartnerKey == l2.PartnerKey
}

// BondMetricsList is published by nim and consumed by zedagent.
type BondMetricsList struct {
	Bonds []BondMetrics
}

// Key returns the pubsub message key for BondMetricsList.
func (b BondMetricsList) Key() string {
	return "global"
}

// BondMetrics contains metrics for a single bond adapter.
type BondMetrics struct {
	// LogicalLabel of the bond adapter.
	LogicalLabel string
	// Members contains per-member metrics.
	Members []BondMemberMetrics
}

// BondMemberMetrics contains metrics for a single member within a bond.
type BondMemberMetrics struct {
	// LogicalLabel of the member port.
	LogicalLabel string
	// IfName of the member interface.
	IfName string
	// LinkFailureCount is the cumulative number of link failures detected.
	LinkFailureCount uint64
	// LACP contains LACP-specific counters (802.3ad mode only).
	LACP *BondMemberLACPMetrics
}

// BondMemberLACPMetrics contains LACP (802.3ad) counters for a bond member.
type BondMemberLACPMetrics struct {
	// ActorChurnedCount is the number of times the actor detected churn.
	ActorChurnedCount uint64
	// PartnerChurnedCount is the number of times the partner detected churn.
	PartnerChurnedCount uint64
}
