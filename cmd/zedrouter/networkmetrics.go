// Copyright (c) 2019 Zededa, Inc.
// All rights reserved.

package zedrouter

// Grab both interface counters and acl counters.
// Does it for all interfaces; caller can filter
// XXX Should we skip some class of network interfaces?

import (
	psutilnet "github.com/shirou/gopsutil/net"
	"github.com/zededa/go-provision/types"
	"log"
)

func getNetworkMetrics() types.NetworkMetrics {
	metrics := []types.NetworkMetric{}
	network, err := psutilnet.IOCounters(true)
	if err != nil {
		log.Println(err)
		return types.NetworkMetrics{}
	}
	// Call iptables once to get counters
	ac := fetchIprulesCounters()

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
		// Note that Tx is transmitted to bu/bo interface
		metric.TxAclDrops = getIpRuleAclDrop(ac, ni.Name, false)
		metric.RxAclDrops = getIpRuleAclDrop(ac, ni.Name, true)
		metric.TxAclRateLimitDrops = getIpRuleAclRateLimitDrop(ac, ni.Name, false)
		metric.RxAclRateLimitDrops = getIpRuleAclRateLimitDrop(ac, ni.Name, true)
		metrics = append(metrics, metric)
	}
	return types.NetworkMetrics{MetricList: metrics}
}
