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
	ac := iptables.FetchIprulesCounters(log)

	// If we have both ethN and kethN then rename ethN to eethN ('e' for EVE)
	// and kethN to ethN (the actual port)
	// This ensures that ethN has the total counters for the actual port
	// The eethN counters are currently not used/reported, but could be
	// used to indicate how much EVE is doing. However, we wouldn't have
	// that separation for wlan and wwan interfaces.
	for i := range network {
		if !strings.HasPrefix(network[i].Name, "eth") {
			continue
		}
		kernIfname := "k" + network[i].Name
		for j := range network {
			if network[j].Name != kernIfname {
				continue
			}
			log.Functionf("getNetworkMetrics swapping %d and %d: %s and %s",
				i, j, network[i].Name, network[j].Name)
			network[j].Name = network[i].Name
			network[i].Name = "e" + network[i].Name
			break
		}
	}
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
		metric.TxAclDrops = iptables.GetIPRuleACLDrop(log, ac, bridgeName, vifName,
			ipVer, inout)
		metric.TxAclDrops += iptables.GetIPRuleACLLog(log, ac, bridgeName, vifName,
			ipVer, inout)
		metric.RxAclDrops = iptables.GetIPRuleACLDrop(log, ac, bridgeName, vifName,
			ipVer, !inout)
		metric.RxAclDrops += iptables.GetIPRuleACLLog(log, ac, bridgeName, vifName,
			ipVer, !inout)
		metric.TxAclRateLimitDrops = iptables.GetIPRuleACLRateLimitDrop(log, ac,
			bridgeName, vifName, ipVer, inout)
		metric.RxAclRateLimitDrops = iptables.GetIPRuleACLRateLimitDrop(log, ac,
			bridgeName, vifName, ipVer, !inout)
		metrics = append(metrics, metric)
	}
	return types.NetworkMetrics{MetricList: metrics, TotalRuleCount: uint64(len(ac))}
}
