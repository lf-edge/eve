// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nistate

import (
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

type aclCounters struct {
	table  string
	chain  string
	ipVer  int
	inIf   string
	pInIf  string // --physdev-in
	outIf  string
	pOutIf string // --physdev-out
	log    bool
	drop   bool
	limit  bool
	more   bool // Has fields we didn't explicitly parse; user specified.
	accept bool
	dest   string
	bytes  uint64
	pkts   uint64
}

func addrTypeToIPVer(addrType types.AddressType) int {
	switch addrType {
	case types.AddressTypeIPV4:
		return 4
	case types.AddressTypeIPV6:
		return 6
	}
	return 0
}

func (lc *LinuxCollector) fetchIptablesCounters() []aclCounters {
	// Get for IPv4 and IPv6 from filter and raw tables.
	chainsWithCounters := map[string][]string{ // table -> chains
		"filter": {"FORWARD"},
		"raw":    {"PREROUTING"},
	}
	var counters []aclCounters
	for table, chains := range chainsWithCounters {
		for _, chain := range chains {
			output, err := iptables.IptableCmdOut(
				nil, "-t", table, "-S", chain+iptables.AppChainSuffix, "-v")
			if err != nil {
				lc.log.Errorf("%s: fetchIptablesCounters: iptables -S failed: %v",
					LogAndErrPrefix, err)
			} else {
				c := lc.parseIptablesCounters(output, table, 4)
				if c != nil {
					counters = append(counters, c...)
				}
			}
		}
	}
	return counters
}

// Parse the output of iptables -S -v
func (lc *LinuxCollector) parseIptablesCounters(
	output string, table string, ipVer int) (counters []aclCounters) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		ac, skip := lc.parseIptablesLine(line, table, ipVer)
		if !skip {
			counters = append(counters, ac)
		}
	}
	return counters
}

func (lc *LinuxCollector) parseIptablesLine(
	line string, table string, ipVer int) (ac aclCounters, skip bool) {
	items := strings.Split(line, " ")
	if len(items) < 4 {
		// log.Tracef("Too short: %s\n", line)
		return ac, true
	}
	if items[0] != "-A" {
		return ac, true
	}
	chain := strings.TrimSuffix(items[1], iptables.AppChainSuffix)
	forward := chain == "FORWARD"
	ac = aclCounters{table: table, chain: chain, ipVer: ipVer}
	i := 2
	for i < len(items) {
		// Ignore any xen-related entries.
		if items[i] == "--physdev-is-bridged" {
			return ac, true
		}
		// Skip things which are normal in the entries such as physdev
		// and the destination match
		if items[i] == "-m" && items[i+1] == "physdev" {
			i += 2
			continue
		}
		// Mark RateLimit flag
		if items[i] == "-m" && items[i+1] == "limit" {
			ac.limit = true
			i += 2
			continue
		}
		// Need to allow -A FORWARD -d 10.0.1.11/32 -o bn1
		// without setting More.
		if forward && items[i] == "-d" && i == 2 {
			ac.dest = items[i+1]
			i += 2
			continue
		}
		// Ignore any log-prefix and log-level if present
		if items[i] == "--log-prefix" || items[i] == "--log-level" {
			i += 2
			continue
		}

		// Extract interface information
		if items[i] == "-i" {
			ac.inIf = items[i+1]
			i += 2
			continue
		}
		if items[i] == "--physdev-in" {
			ac.pInIf = items[i+1]
			i += 2
			continue
		}
		if items[i] == "-o" {
			ac.outIf = items[i+1]
			i += 2
			continue
		}
		if items[i] == "--physdev-out" {
			ac.pOutIf = items[i+1]
			i += 2
			continue
		}
		if items[i] == "-j" {
			switch items[i+1] {
			case "DROP":
				ac.drop = true
			case "LOG":
				ac.log = true
			case "ACCEPT":
				ac.accept = true
			}
			i += 2
			continue
		}
		if items[i] == "-c" {
			u, err := strconv.ParseUint(items[i+1], 10, 64)
			if err != nil {
				lc.log.Errorf("%s: parseIptablesLine: Bad counter value %s in line %s",
					LogAndErrPrefix, items[i+1], line)
			} else {
				ac.pkts = u
			}
			u, err = strconv.ParseUint(items[i+2], 10, 64)
			if err != nil {
				lc.log.Errorf("%s: parseIptablesLine: Bad counter value %s in line %s",
					LogAndErrPrefix, items[i+2], line)
			} else {
				ac.bytes = u
			}
			i += 3
			continue
		}

		ac.more = true
		i += 1
	}
	return ac, false
}

func (lc *LinuxCollector) getIptablesCounters(
	counters []aclCounters, match aclCounters) aclCounters {
	for i, c := range counters {
		if c.ipVer != match.ipVer || c.log != match.log ||
			c.drop != match.drop || c.limit != match.limit {
			continue
		}
		if c.inIf != match.inIf || c.outIf != match.outIf {
			continue
		}
		if c.pInIf != match.pInIf || c.pOutIf != match.pOutIf {
			continue
		}
		// accumulate counter across matching ACLs
		match.bytes += counters[i].bytes
		match.pkts += counters[i].pkts
	}
	return match
}

func (lc *LinuxCollector) makeIptablesCountersMatcher(
	bridgeName string, vifName string, ipVer int, brInput bool) aclCounters {
	var inIf string
	var pInIf string
	var outIf string
	if brInput {
		inIf = bridgeName
		if vifName != "" {
			pInIf = vifName + "+"
		}
	} else {
		outIf = bridgeName
		// TODO what about pOutIf = vifName + "+" ?
	}
	return aclCounters{inIf: inIf, pInIf: pInIf, outIf: outIf, ipVer: ipVer}
}

// Look for a LOG entry without More; we don't have those for rate limits
// zedrouter appends a '+' to the vifname to handle PV/qemu which for some
// reason have a second <vifname>-emu bridge interface. Need to match that here.
func (lc *LinuxCollector) getIptablesACLDrop(counters []aclCounters,
	bridgeName string, vifName string, ipVer int, brInput bool) uint64 {
	matcher := lc.makeIptablesCountersMatcher(bridgeName, vifName, ipVer, brInput)
	matcher.drop = true
	c := lc.getIptablesCounters(counters, matcher)
	return c.pkts
}

// Get the packet/byte count of logged packets.
func (lc *LinuxCollector) getIptablesACLLog(counters []aclCounters,
	bridgeName string, vifName string, ipVer int, brInput bool) uint64 {
	matcher := lc.makeIptablesCountersMatcher(bridgeName, vifName, ipVer, brInput)
	matcher.log = true
	c := lc.getIptablesCounters(counters, matcher)
	return c.pkts
}

// Look for a DROP entry with More set.
// zedrouter appends a '+' to the vifname to handle PV/qemu which for some
// reason have a second <vifname>-emu bridge interface. Need to match that here.
func (lc *LinuxCollector) getIptablesACLRateLimitDrop(counters []aclCounters,
	bridgeName string, vifName string, ipVer int, brInput bool) uint64 {
	matcher := lc.makeIptablesCountersMatcher(bridgeName, vifName, ipVer, brInput)
	matcher.limit = true
	c := lc.getIptablesCounters(counters, matcher)
	return c.pkts
}
