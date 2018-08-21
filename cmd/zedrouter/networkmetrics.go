// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package zedrouter

// Grab both interface counters and acl counters.
// Does it for all interfaces; caller can filter
// XXX Should we skip some class of network interfaces?

import (
	psutilnet "github.com/shirou/gopsutil/net"
	"github.com/zededa/go-provision/types"
	"log"
	"strings"
)

func getNetworkMetrics(ctx *zedrouterContext) types.NetworkMetrics {
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
		// XXX vifName?
		// Match either as bridgeName or vifName?
		// XXX lookup bridgeName to find whether IPv4 or IPv6?
		// XXX how do we do lookups on the the vifName?
		// XXX dbo1x0 check
		var ntype types.NetworkType
		bridgeName := ni.Name
		vifName := ""
		if strings.HasPrefix(ni.Name, "dbo") {
			// Special check for dbo1x0 goes away when disagg
			ntype = types.NT_CryptoEID
		} else {
			// If this a vif in a bridge?
			bn := vifNameToBridgeName(ctx, ni.Name)
			if bn != "" {
				ntype = networkObjectType(ctx, bn)
				if ntype != 0 {
					vifName = ni.Name
					bridgeName = bn
					log.Printf("vif %s bridge %s type %d\n",
						vifName, bridgeName, ntype)
				}
			} else {
				ntype = networkObjectType(ctx, ni.Name)
				if ntype != 0 {
					bridgeName = ni.Name
					log.Printf("bridge %s type %d\n",
						ni.Name, ntype)
				}
			}
		}
		var ipVer int = 4
		switch ntype {
		case types.NT_IPV4:
			ipVer = 4
		case types.NT_IPV6, types.NT_CryptoEID:
			// XXX IPv4 EIDs?
			ipVer = 6
		}
		metric.TxAclDrops = getIpRuleAclDrop(ac, bridgeName, vifName,
			ipVer, false)
		metric.RxAclDrops = getIpRuleAclDrop(ac, bridgeName, vifName,
			ipVer, true)
		metric.TxAclRateLimitDrops = getIpRuleAclRateLimitDrop(ac,
			bridgeName, vifName, ipVer, false)
		metric.RxAclRateLimitDrops = getIpRuleAclRateLimitDrop(ac,
			bridgeName, vifName, ipVer, true)
		metrics = append(metrics, metric)
	}
	return types.NetworkMetrics{MetricList: metrics}
}
