// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

// Grab both interface counters and acl counters.
// Does it for all interfaces; caller can filter
// XXX Should we skip some class of network interfaces?

import (
	psutilnet "github.com/shirou/gopsutil/net"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/iptables"
	"github.com/zededa/go-provision/types"
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
		metric.TxAclDrops = iptables.GetIpRuleAclDrop(ac, bridgeName, vifName,
			ipVer, inout)
		metric.RxAclDrops = iptables.GetIpRuleAclDrop(ac, bridgeName, vifName,
			ipVer, !inout)
		metric.TxAclRateLimitDrops = iptables.GetIpRuleAclRateLimitDrop(ac,
			bridgeName, vifName, ipVer, inout)
		metric.RxAclRateLimitDrops = iptables.GetIpRuleAclRateLimitDrop(ac,
			bridgeName, vifName, ipVer, !inout)
		metrics = append(metrics, metric)
	}
	return types.NetworkMetrics{MetricList: metrics}
}
