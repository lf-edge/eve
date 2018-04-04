// Copyright (c) 2019 Zededa, Inc.
// All rights reserved.

package main

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
	// XXX call iptables once to get counters

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
		// XXX extract iptables counters
		// XXX note that Tx is transmitted to bu/bo interface
		metric.TxAclDrops = 0
		metric.RxAclDrops = 0
		metric.TxAclRateLimitDrops = 0
		metric.RxAclRateLimitDrops = 0
		metrics = append(metrics, metric)
	}
	return types.NetworkMetrics{MetricList: metrics}
}
