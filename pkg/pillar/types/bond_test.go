// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// BondStatus.Equal

func TestBondStatusEqual(t *testing.T) {
	s1 := BondStatus{Mode: BondModeActiveBackup, ActiveMember: "eth0"}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	s2.Mode = BondModeBalanceRR
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.ActiveMember = "eth1"
	assert.False(t, s1.Equal(s2))
}

// BondMemberStatus.Equal

func TestBondMemberStatusEqual(t *testing.T) {
	s1 := BondMemberStatus{Logicallabel: "eth0", MIIUp: true}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	s2.MIIUp = false
	assert.False(t, s1.Equal(s2))

	// One with LACP, one without
	s2 = s1
	s2.LACP = &BondMemberLACPStatus{}
	assert.False(t, s1.Equal(s2))

	// Both with LACP equal
	s1.LACP = &BondMemberLACPStatus{}
	assert.True(t, s1.Equal(s2))

	// Both with different LACP
	s2.LACP = &BondMemberLACPStatus{AggregatorID: 5}
	assert.False(t, s1.Equal(s2))
}

// BondARPMonitorStatus.Equal

func TestBondARPMonitorStatusEqual(t *testing.T) {
	m1 := BondARPMonitorStatus{Enabled: true, PollingInterval: 1000, MissedMax: 3}
	m2 := m1
	assert.True(t, m1.Equal(m2))

	m2.Enabled = false
	assert.False(t, m1.Equal(m2))

	m2 = m1
	m2.IPTargets = []net.IP{net.ParseIP("10.0.0.1")}
	assert.False(t, m1.Equal(m2))
}

// BondLACPStatus.Equal

func TestBondLACPStatusEqual(t *testing.T) {
	l1 := BondLACPStatus{Enabled: true, LACPRate: LacpRateFast, ActiveAggregatorID: 1}
	l2 := l1
	assert.True(t, l1.Equal(l2))

	l2.LACPRate = LacpRateSlow
	assert.False(t, l1.Equal(l2))

	l2 = l1
	l2.ActorKey = 7
	assert.False(t, l1.Equal(l2))
}

// BondStatus.Equal - with Members comparison

func TestBondStatusEqualWithMembers(t *testing.T) {
	mem1 := BondMemberStatus{Logicallabel: "eth0", MIIUp: true}
	mem2 := BondMemberStatus{Logicallabel: "eth1", MIIUp: true}
	s1 := BondStatus{
		Mode:    BondModeActiveBackup,
		Members: []BondMemberStatus{mem1, mem2},
	}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	// Different member set
	s2.Members = []BondMemberStatus{mem1}
	assert.False(t, s1.Equal(s2))

	// Different MIIMonitor
	s2 = s1
	s2.MIIMonitor = BondMIIMonitorStatus{PollingInterval: 100}
	assert.False(t, s1.Equal(s2))
}

// BondMetricsList.Key

func TestBondMetricsListKey(t *testing.T) {
	assert.Equal(t, "global", BondMetricsList{}.Key())
}
