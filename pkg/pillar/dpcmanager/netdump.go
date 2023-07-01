// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// Topic for netdumps of successful connectivity tests.
func (m *DpcManager) netDumpOKTopic() string {
	return m.AgentName + "-ok"
}

// Topic for netdumps of failed connectivity tests.
func (m *DpcManager) netDumpFailTopic() string {
	return m.AgentName + "-fail"
}

// Function decides if the next call to TestConnectivity should be traced
// and netdump published at the end (see libs/nettrace and pkg/pillar/netdump).
func (m *DpcManager) traceNextConnTest() bool {
	if m.netDumper == nil || m.netdumpInterval == 0 {
		return false
	}
	// Trace only if the highest priority DPC is currently being used.
	// Traces are used for troubleshooting purposes and there is no point
	// in troubleshooting obsolete DPCs.
	if len(m.dpcList.PortConfigList) == 0 || m.dpcList.CurrentIndex != 0 {
		return false
	}
	if m.lastNetdumpPub.IsZero() {
		// No netdump published yet for DPC testing.
		return true
	}
	uptime := time.Since(m.startTime)
	lastNetdumpAge := time.Since(m.lastNetdumpPub)
	// Ensure we get at least one netdump for the currently tested EVE upgrade.
	if zboot.IsCurrentPartitionStateInProgress() && lastNetdumpAge > uptime {
		return true
	}
	return lastNetdumpAge >= m.netdumpInterval
}

// Publish netdump containing traces of executed connectivity probes.
func (m *DpcManager) publishNetdump(
	cloudConnWorks bool, tracedConnProbes []netdump.TracedNetRequest) {
	netDumper := m.netDumper
	if netDumper == nil {
		return
	}
	var topic string
	if cloudConnWorks {
		topic = m.netDumpOKTopic()
	} else {
		topic = m.netDumpFailTopic()
	}
	filename, err := netDumper.Publish(topic, tracedConnProbes...)
	if err != nil {
		m.Log.Warnf("Failed to publish netdump for topic %s: %v", topic, err)
	} else {
		m.Log.Noticef("Published netdump for topic %s: %s", topic, filename)
	}
	m.lastNetdumpPub = time.Now()
}
