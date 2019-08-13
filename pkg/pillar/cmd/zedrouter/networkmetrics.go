// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

// Grab both interface counters and acl counters.
// Does it for all interfaces; caller can filter
// XXX Should we skip some class of network interfaces?

import (
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
	psutilnet "github.com/shirou/gopsutil/net"
	log "github.com/sirupsen/logrus"
	"strings"
)

func getNetworkMetrics(ctx *zedrouterContext) types.NetworkMetrics {
	metrics := []types.NetworkMetric{}
	network, err := psutilnet.IOCounters(true)
	if err != nil {
		log.Errorln(err)
		return types.NetworkMetrics{}
	}
	// Call iptables once to get counters
	ac := iptables.FetchIprulesCounters()

	for _, ni := range network {
		metric := types.NetworkMetric{
			IfName:   ni.Name,
			TxPkts:   ni.PacketsSent,
			RxPkts:   ni.PacketsRecv,
			TxBytes:  ni.BytesSent,
			RxBytes:  ni.BytesRecv,
			TxDrops:  ni.Dropout,
			RxDrops:  ni.Dropin,
			TxErrors: ni.Errout,
			RxErrors: ni.Errin,
		}
		bridgeName := ni.Name
		vifName := ""
		inout := true
		ipVer := 4
		if strings.HasPrefix(ni.Name, "dbo") {
			// XXX IPv4 EIDs?
			// Special check for dbo1x0 goes away when disagg
			ipVer = 6
			inout = false // Swapped in and out counters
		} else {
			// If this a vif in a bridge?
			bn := vifNameToBridgeName(ctx, ni.Name)
			if bn != "" {
				ipVer = networkInstanceAddressType(ctx, bn)
				if ipVer != 0 {
					vifName = ni.Name
					bridgeName = bn
				}
			} else {
				ipVer = networkInstanceAddressType(ctx, ni.Name)
				if ipVer != 0 {
					bridgeName = ni.Name
				}
			}
		}
		if ipVer == 0 {
			ipVer = 4
		}

		// DROP action is used in two case.
		// 1. DROP rule for the packets exceeding rate-limiter.
		// 2. Default DROP rule in the end.
		// With flow-monitoring support, we cannot have the default DROP rule
		// in the end of rule list. This is to avoid conntrack from deleting
		// connections matching the default rule. Just before the default DROP
		// rule, we add a LOG rule for logging packets that are being forwarded
		// to dummy interface.
		// Packets matching the default DROP rule also match the default LOG rule.
		// Since we will not have the default DROP rule, we can copy statistics
		// from default LOG rule as DROP statistics.
		metric.TxAclDrops = iptables.GetIPRuleAclDrop(ac, bridgeName, vifName,
			ipVer, inout)
		metric.TxAclDrops += iptables.GetIPRuleACLLog(ac, bridgeName, vifName,
			ipVer, inout)
		metric.RxAclDrops = iptables.GetIPRuleAclDrop(ac, bridgeName, vifName,
			ipVer, !inout)
		metric.RxAclDrops += iptables.GetIPRuleACLLog(ac, bridgeName, vifName,
			ipVer, !inout)
		metric.TxAclRateLimitDrops = iptables.GetIPRuleAclRateLimitDrop(ac,
			bridgeName, vifName, ipVer, inout)
		metric.RxAclRateLimitDrops = iptables.GetIPRuleAclRateLimitDrop(ac,
			bridgeName, vifName, ipVer, !inout)
		metrics = append(metrics, metric)
	}
	return types.NetworkMetrics{MetricList: metrics}
}
