// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

const (
	// IPtablesChainTypename : typename for a single iptables chain (IPv4).
	IPtablesChainTypename = "Iptables-Chain"
	// IP6tablesChainTypename : typename for a single ip6tables chain (IPv6).
	IP6tablesChainTypename = "Ip6tables-Chain"
	// LocalIPRuleTypename : typename for singleton item representing IP rule for local RT.
	LocalIPRuleTypename = "Local-IP-Rule"
	// SrcIPRuleTypename : typename for source-based IP rules.
	SrcIPRuleTypename = "Src-IP-Rule"
)
