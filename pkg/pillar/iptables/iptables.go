// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// iptables support code

package iptables

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

const (
	// DeviceChainSuffix : suffix added to the name of a chain,
	// which is configured by NIM for device-wide access control.
	DeviceChainSuffix = "-device"
	// AppChainSuffix : suffix added to the name of a chain,
	// which is configured by Zedrouter for app-scoped access control.
	AppChainSuffix = "-apps"
)

const (
	iptablesCmd  = "iptables"
	ip6tablesCmd = "ip6tables"
)

type iptablesFnType func(log *base.LogObject, args ...string) error

var iptablesFn = map[string]iptablesFnType{
	iptablesCmd:  IptableCmd,
	ip6tablesCmd: Ip6tableCmd,
}

// IptableCmdOut logs the command string if log is set
func IptableCmdOut(log *base.LogObject, args ...string) (string, error) {
	var out []byte
	var err error
	// XXX as long as zedagent also calls iptables we need to
	// wait for the lock with -w 5
	args = append(args, "a", "b")
	copy(args[2:], args[0:])
	args[0] = "-w"
	args[1] = "5"
	if log != nil {
		log.Functionf("Calling command %s %v\n", iptablesCmd, args)
		out, err = base.Exec(log, iptablesCmd, args...).CombinedOutput()
	} else {
		out, err = base.Exec(log, iptablesCmd, args...).Output()
	}
	if err != nil {
		errStr := fmt.Sprintf("iptables command %s failed %s output %s",
			args, err, out)
		if log != nil {
			log.Errorln(errStr)
		}
		return "", errors.New(errStr)
	}
	return string(out), nil
}

// IptableCmd logs the command string if log is set
func IptableCmd(log *base.LogObject, args ...string) error {
	_, err := IptableCmdOut(log, args...)
	return err
}

// Ip6tableCmdOut logs the command string if log is set
func Ip6tableCmdOut(log *base.LogObject, args ...string) (string, error) {
	var out []byte
	var err error
	// XXX as long as zedagent also calls iptables we need to
	// wait for the lock with -w 5
	args = append(args, "a", "b")
	copy(args[2:], args[0:])
	args[0] = "-w"
	args[1] = "5"
	if log != nil {
		log.Functionf("Calling command %s %v\n", ip6tablesCmd, args)
		out, err = base.Exec(log, ip6tablesCmd, args...).CombinedOutput()
	} else {
		out, err = base.Exec(log, ip6tablesCmd, args...).Output()
	}
	if err != nil {
		errStr := fmt.Sprintf("ip6tables command %s failed %s output %s",
			args, err, out)
		if log != nil {
			log.Errorln(errStr)
		}
		return "", errors.New(errStr)
	}
	return string(out), nil
}

// Ip6tableCmd logs the command string if log is set
func Ip6tableCmd(log *base.LogObject, args ...string) error {
	_, err := Ip6tableCmdOut(log, args...)
	return err
}

// XXX : Everything below is zedrouter-specific, consider moving to pillar/cmd/zedrouter

func FetchIprulesCounters(log *base.LogObject) []AclCounters {
	// Get for IPv4 and IPv6 from filter and raw tables.
	chainsWithCounters := map[string][]string{ // table -> chains
		"filter": {"FORWARD", "OUTPUT"},
		"raw":    {"PREROUTING"},
	}
	var counters []AclCounters
	for table, chains := range chainsWithCounters {
		for _, chain := range chains {
			out, err := IptableCmdOut(
				nil, "-t", table, "-S", chain+AppChainSuffix, "-v")
			if err != nil {
				log.Errorf("FetchIprulesCounters: iptables -S failed %s\n", err)
			} else {
				c := parseCounters(log, out, "filter", 4)
				if c != nil {
					counters = append(counters, c...)
				}
			}
		}
	}
	return counters
}

func getIpRuleCounters(log *base.LogObject, counters []AclCounters, match *AclCounters) *AclCounters {
	for i, c := range counters {
		if c.IpVer != match.IpVer || c.Log != match.Log ||
			c.Drop != match.Drop || c.Limit != match.Limit {
			continue
		}
		if c.IIf != match.IIf || c.OIf != match.OIf {
			continue
		}
		if c.Piif != match.Piif || c.Poif != match.Poif {
			continue
		}
		log.Tracef("getIpRuleCounters: matched counters %+v\n",
			&counters[i])
		// accumulate counter across matching ACLs
		match.Bytes += counters[i].Bytes
		match.Pkts += counters[i].Pkts
	}
	return match
}

// GetIPRuleACLDrop :
// Look for a LOG entry without More; we don't have those for rate limits
// acl.go appends a '+' to the vifname to handle PV/qemu which for some
// reason have a second <vifname>-emu bridge interface. Need to match that here.
func GetIPRuleACLDrop(log *base.LogObject, counters []AclCounters, bridgeName string, vifName string,
	ipVer int, input bool) uint64 {

	var iif string
	var piif string
	var oif string
	if input {
		iif = bridgeName
		if vifName != "" {
			piif = vifName + "+"
		}
	} else {
		oif = bridgeName
	}
	match := AclCounters{IIf: iif, Piif: piif, OIf: oif, IpVer: ipVer,
		Drop: true, Limit: false}
	c := getIpRuleCounters(log, counters, &match)
	if c == nil {
		return 0
	}
	return c.Pkts
}

// GetIPRuleACLLog : Get the packet/byte count of logged packets
func GetIPRuleACLLog(log *base.LogObject, counters []AclCounters, bridgeName string, vifName string,
	ipVer int, input bool) uint64 {

	var iif string
	var piif string
	var oif string
	if input {
		iif = bridgeName
		if vifName != "" {
			piif = vifName + "+"
		}
	} else {
		oif = bridgeName
	}
	match := AclCounters{IIf: iif, Piif: piif, OIf: oif, IpVer: ipVer,
		Drop: false, Limit: false, Log: true}
	c := getIpRuleCounters(log, counters, &match)
	if c == nil {
		return 0
	}
	return c.Pkts
}

// GetIPRuleACLRateLimitDrop :
// Look for a DROP entry with More set.
// acl.go appends a '+' to the vifname to handle PV/qemu which for some
// reason have a second <vifname>-emu bridge interface. Need to match that here.
func GetIPRuleACLRateLimitDrop(log *base.LogObject, counters []AclCounters, bridgeName string,
	vifName string, ipVer int, input bool) uint64 {

	var iif string
	var piif string
	var oif string
	if input {
		iif = bridgeName
		if vifName != "" {
			piif = vifName + "+"
		}
	} else {
		oif = bridgeName
	}
	// for RateLimit Drops, the Drop is false
	match := AclCounters{IIf: iif, Piif: piif, OIf: oif, IpVer: ipVer,
		Drop: false, Limit: true}
	c := getIpRuleCounters(log, counters, &match)
	if c == nil {
		return 0
	}
	return c.Pkts
}

// Parse the output of iptables -S -v
func parseCounters(log *base.LogObject, out string, table string, ipVer int) []AclCounters {
	var counters []AclCounters

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		ac := parseline(log, line, table, ipVer)
		if ac != nil {
			counters = append(counters, *ac)
		}
	}
	return counters
}

type AclCounters struct {
	Table  string
	Chain  string
	IpVer  int
	IIf    string
	Piif   string
	OIf    string
	Poif   string
	Log    bool
	Drop   bool
	Limit  bool
	More   bool // Has fields we didn't explicitly parse; user specified
	Accept bool
	Dest   string
	Bytes  uint64
	Pkts   uint64
}

func parseline(log *base.LogObject, line string, table string, ipVer int) *AclCounters {
	items := strings.Split(line, " ")
	if len(items) < 4 {
		// log.Tracef("Too short: %s\n", line)
		return nil
	}
	if items[0] != "-A" {
		return nil
	}
	chain := strings.TrimSuffix(items[1], AppChainSuffix)
	forward := chain == "FORWARD"
	ac := AclCounters{Table: table, Chain: chain, IpVer: ipVer}
	i := 2
	for i < len(items) {
		// Ignore any xen-related entries.
		if items[i] == "--physdev-is-bridged" {
			return nil
		}
		// Skip things which are normal in the entries such as physdev
		// and the destination match
		if items[i] == "-m" && items[i+1] == "physdev" {
			i += 2
			continue
		}
		// Mark RateLimit flag
		if items[i] == "-m" && items[i+1] == "limit" {
			// log.Tracef("Marking RateLimit: true\n")
			ac.Limit = true
			i += 2
			continue
		}
		// Need to allow -A FORWARD -d 10.0.1.11/32 -o bn1
		// without setting More.
		if forward && items[i] == "-d" && i == 2 {
			ac.Dest = items[i+1]
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
			ac.IIf = items[i+1]
			i += 2
			continue
		}
		if items[i] == "--physdev-in" {
			ac.Piif = items[i+1]
			i += 2
			continue
		}
		if items[i] == "-o" {
			ac.OIf = items[i+1]
			i += 2
			continue
		}
		if items[i] == "--physdev-out" {
			ac.Poif = items[i+1]
			i += 2
			continue
		}
		if items[i] == "-j" {
			switch items[i+1] {
			case "DROP":
				ac.Drop = true
			case "LOG":
				ac.Log = true
			case "ACCEPT":
				ac.Accept = true
			}
			i += 2
			continue
		}
		if items[i] == "-c" {
			u, err := strconv.ParseUint(items[i+1], 10, 64)
			if err != nil {
				log.Errorf("Bad counter value %s in line %s\n",
					items[i+1], line)
			} else {
				ac.Pkts = u
			}
			u, err = strconv.ParseUint(items[i+2], 10, 64)
			if err != nil {
				log.Errorf("Bad counter value %s in line %s\n",
					items[i+2], line)
			} else {
				ac.Bytes = u
			}
			i += 3
			continue
		}

		// log.Tracef("Got more items %d %s\n", i, items[i])
		ac.More = true
		i += 1
	}
	return &ac
}
