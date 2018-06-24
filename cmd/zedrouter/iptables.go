// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// iptables support code

package zedrouter

import (
	"github.com/zededa/go-provision/wrap"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

func iptableCmdOut(dolog bool, args ...string) (string, error) {
	cmd := "iptables"
	var out []byte
	var err error
	if dolog {
		out, err = wrap.Command(cmd, args...).Output()
	} else {
		out, err = exec.Command(cmd, args...).Output()
	}
	if err != nil {
		log.Println("iptables command failed: ", args, err)
		return "", err
	}
	return string(out), nil
}

func iptableCmd(args ...string) error {
	_, err := iptableCmdOut(true, args...)
	return err
}

func ip6tableCmdOut(dolog bool, args ...string) (string, error) {
	cmd := "ip6tables"
	var out []byte
	var err error
	if dolog {
		out, err = wrap.Command(cmd, args...).Output()
	} else {
		out, err = exec.Command(cmd, args...).Output()
	}
	if err != nil {
		log.Println("ip6tables command failed: ", args, err)
		return "", err
	}
	return string(out), nil
}

func ip6tableCmd(args ...string) error {
	_, err := ip6tableCmdOut(true, args...)
	return err
}

func iptablesInit() {
	// Avoid adding nat rule multiple times as we restart by flushing first
	iptableCmd("-t", "nat", "-F", "POSTROUTING")

	// Flush IPv6 mangle rules from previous run
	ip6tableCmd("-F", "PREROUTING", "-t", "mangle")

	// Add mangle rules for IPv6 packets from dom0 overlay
	// since netfront/netback thinks there is checksum offload
	// XXX not needed once we have disaggregated dom0
	iptableCmd("-F", "POSTROUTING", "-t", "mangle")
	iptableCmd("-A", "POSTROUTING", "-t", "mangle", "-p", "tcp",
		"-j", "CHECKSUM", "--checksum-fill")
	iptableCmd("-A", "POSTROUTING", "-t", "mangle", "-p", "udp",
		"-j", "CHECKSUM", "--checksum-fill")
	ip6tableCmd("-F", "POSTROUTING", "-t", "mangle")
	ip6tableCmd("-A", "POSTROUTING", "-t", "mangle", "-p", "tcp",
		"-j", "CHECKSUM", "--checksum-fill")
	ip6tableCmd("-A", "POSTROUTING", "-t", "mangle", "-p", "udp",
		"-j", "CHECKSUM", "--checksum-fill")
}

func fetchIprulesCounters() []AclCounters {
	var counters []AclCounters
	// get for IPv4 filter, IPv6 filter, and IPv6 raw
	out, err := iptableCmdOut(false, "-t", "filter", "-S", "FORWARD", "-v")
	if err != nil {
		log.Printf("fetchIprulesCounters: iptables -S failed %s\n", err)
	} else {
		c := parseCounters(out, "filter", false)
		if c != nil {
			counters = append(counters, c...)
		}
	}
	// XXX Only needed to get dbo1x0 stats
	out, err = ip6tableCmdOut(false, "-t", "filter", "-S", "OUTPUT", "-v")
	if err != nil {
		log.Printf("fetchIprulesCounters: iptables -S failed %s\n", err)
	} else {
		c := parseCounters(out, "filter", true)
		if c != nil {
			counters = append(counters, c...)
		}
	}
	out, err = ip6tableCmdOut(false, "-t", "filter", "-S", "FORWARD", "-v")
	if err != nil {
		log.Printf("fetchIprulesCounters: ip6tables failed %s\n", err)
	} else {
		c := parseCounters(out, "filter", true)
		if c != nil {
			counters = append(counters, c...)
		}
	}
	out, err = ip6tableCmdOut(false, "-t", "raw", "-S", "PREROUTING", "-v")
	if err != nil {
		log.Printf("fetchIprulesCounters: ip6tables -S failed %s\n", err)
	} else {
		c := parseCounters(out, "filter", true)
		if c != nil {
			counters = append(counters, c...)
		}
	}
	return counters
}

func getIpRuleCounters(counters []AclCounters, match AclCounters) *AclCounters {
	for i, c := range counters {
		if c.Overlay != match.Overlay || c.Log != match.Log ||
			c.Drop != match.Drop || c.More != match.More {
			continue
		}
		if c.IIf != match.IIf || c.OIf != match.OIf {
			continue
		}
		return &counters[i]
	}
	return nil
}

// Look for a LOG entry without More; we don't have those for rate limits
func getIpRuleAclDrop(counters []AclCounters, ifname string, input bool) uint64 {
	overlay := strings.HasPrefix(ifname, "bo") ||
		strings.HasPrefix(ifname, "dbo")
	var iif string
	var oif string
	if input {
		iif = ifname
	} else {
		oif = ifname
	}
	match := AclCounters{IIf: iif, OIf: oif, Overlay: overlay, Drop: true}
	c := getIpRuleCounters(counters, match)
	if c == nil {
		return 0
	}
	return c.Pkts
}

// Look for a DROP entry with More set.
func getIpRuleAclRateLimitDrop(counters []AclCounters, ifname string, input bool) uint64 {
	overlay := strings.HasPrefix(ifname, "bo") ||
		strings.HasPrefix(ifname, "dbo")
	var iif string
	var oif string
	if input {
		iif = ifname
	} else {
		oif = ifname
	}
	match := AclCounters{IIf: iif, OIf: oif, Overlay: overlay, Drop: true,
		More: true}
	c := getIpRuleCounters(counters, match)
	if c == nil {
		return 0
	}
	return c.Pkts
}

// Parse the output of iptables -S -v
func parseCounters(out string, table string, overlay bool) []AclCounters {
	var counters []AclCounters

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		ac := parseline(line, table, overlay)
		if ac != nil {
			// XXX log.Printf("ACL counters %v\n", *ac)
			counters = append(counters, *ac)
		}
	}
	return counters
}

type AclCounters struct {
	Table   string
	Chain   string
	Overlay bool
	IIf     string
	OIf     string
	Log     bool
	Drop    bool
	More    bool // Has fields we didn't explicitly parse
	Bytes   uint64
	Pkts    uint64
}

func parseline(line string, table string, overlay bool) *AclCounters {
	items := strings.Split(line, " ")
	if len(items) < 4 {
		// log.Printf("Too short: %s\n", line)
		return nil
	}
	if items[0] != "-A" {
		return nil
	}
	ac := AclCounters{Table: table, Chain: items[1], Overlay: overlay}
	i := 2
	for i < len(items) {
		if items[i] == "-i" {
			ac.IIf = items[i+1]
			i += 2
			continue
		}
		if items[i] == "-o" {
			ac.OIf = items[i+1]
			i += 2
			continue
		}
		if items[i] == "-j" {
			switch items[i+1] {
			case "DROP":
				ac.Drop = true
			case "LOG":
				ac.Log = true
			}
			i += 2
			continue
		}
		if items[i] == "-c" {
			u, err := strconv.ParseUint(items[i+1], 10, 64)
			if err != nil {
				log.Printf("Bad counter value %s in line %s\n",
					items[i+1], line)
			} else {
				ac.Pkts = u
			}
			u, err = strconv.ParseUint(items[i+2], 10, 64)
			if err != nil {
				log.Printf("Bad counter value %s in line %s\n",
					items[i+2], line)
			} else {
				ac.Bytes = u
			}
			i += 3
			continue
		}

		/// log.Printf("Got %d %s\n", i, items[i])
		ac.More = true
		i += 1
	}
	return &ac
}
