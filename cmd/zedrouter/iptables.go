// Copyright (c) 2017,2018 Zededa, Inc.
// All rights reserved.

// iptables support code

package zedrouter

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/wrap"
	"os/exec"
	"strconv"
	"strings"
)

func iptableCmdOut(dolog bool, args ...string) (string, error) {
	cmd := "iptables"
	var out []byte
	var err error
	if dolog {
		out, err = wrap.Command(cmd, args...).CombinedOutput()
	} else {
		out, err = exec.Command(cmd, args...).Output()
	}
	if err != nil {
		errStr := fmt.Sprintf("iptables command %s failed %s output %s",
			args, err, out)
		log.Errorln(errStr)
		return "", errors.New(errStr)
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
		out, err = wrap.Command(cmd, args...).CombinedOutput()
	} else {
		out, err = exec.Command(cmd, args...).Output()
	}
	if err != nil {
		errStr := fmt.Sprintf("ip6tables command %s failed %s output %s",
			args, err, out)
		log.Errorln(errStr)
		return "", errors.New(errStr)
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
		log.Errorf("fetchIprulesCounters: iptables -S failed %s\n", err)
	} else {
		c := parseCounters(out, "filter", 4)
		if c != nil {
			counters = append(counters, c...)
		}
	}

	out, err = iptableCmdOut(false, "-t", "raw", "-S", "PREROUTING", "-v")
	if err != nil {
		log.Errorf("fetchIprulesCounters: iptables -S failed %s\n", err)
	} else {
		c := parseCounters(out, "filter", 4)
		if c != nil {
			counters = append(counters, c...)
		}
	}

	// Only needed to get dbo1x0 stats
	out, err = ip6tableCmdOut(false, "-t", "filter", "-S", "OUTPUT", "-v")
	if err != nil {
		log.Errorf("fetchIprulesCounters: iptables -S failed %s\n", err)
	} else {
		c := parseCounters(out, "filter", 6)
		if c != nil {
			counters = append(counters, c...)
		}
	}
	out, err = ip6tableCmdOut(false, "-t", "filter", "-S", "FORWARD", "-v")
	if err != nil {
		log.Errorf("fetchIprulesCounters: ip6tables failed %s\n", err)
	} else {
		c := parseCounters(out, "filter", 6)
		if c != nil {
			counters = append(counters, c...)
		}
	}
	out, err = ip6tableCmdOut(false, "-t", "raw", "-S", "PREROUTING", "-v")
	if err != nil {
		log.Errorf("fetchIprulesCounters: ip6tables -S failed %s\n", err)
	} else {
		c := parseCounters(out, "filter", 6)
		if c != nil {
			counters = append(counters, c...)
		}
	}
	return counters
}

func getIpRuleCounters(counters []AclCounters, match AclCounters) *AclCounters {
	for i, c := range counters {
		if c.IpVer != match.IpVer || c.Log != match.Log ||
			c.Drop != match.Drop || c.More != match.More {
			continue
		}
		if c.IIf != match.IIf || c.OIf != match.OIf {
			continue
		}
		if c.Piif != match.Piif || c.Poif != match.Poif {
			continue
		}
		log.Debugf("getIpRuleCounters: matched counters %+v\n",
			&counters[i])
		return &counters[i]
	}
	return nil
}

// Look for a LOG entry without More; we don't have those for rate limits
// acl.go appends a '+' to the vifname to handle PV/qemu which for some
// reason have a second <vifname>-emu bridge interface. Need to match that here.
func getIpRuleAclDrop(counters []AclCounters, bridgeName string, vifName string,
	ipVer int, input bool) uint64 {

	var iif string
	var piif string
	var oif string
	if input {
		iif = bridgeName
		piif = vifName + "+"
	} else {
		oif = bridgeName
	}
	match := AclCounters{IIf: iif, Piif: piif, OIf: oif, IpVer: ipVer,
		Drop: true, More: false}
	c := getIpRuleCounters(counters, match)
	if c == nil {
		return 0
	}
	return c.Pkts
}

// Look for a DROP entry with More set.
// acl.go appends a '+' to the vifname to handle PV/qemu which for some
// reason have a second <vifname>-emu bridge interface. Need to match that here.
func getIpRuleAclRateLimitDrop(counters []AclCounters, bridgeName string,
	vifName string, ipVer int, input bool) uint64 {

	var iif string
	var piif string
	var oif string
	if input {
		iif = bridgeName
		piif = vifName + "+"
	} else {
		oif = bridgeName
	}
	match := AclCounters{IIf: iif, Piif: piif, OIf: oif, IpVer: ipVer,
		Drop: true, More: true}
	c := getIpRuleCounters(counters, match)
	if c == nil {
		return 0
	}
	return c.Pkts
}

// Parse the output of iptables -S -v
func parseCounters(out string, table string, ipVer int) []AclCounters {
	var counters []AclCounters

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		ac := parseline(line, table, ipVer)
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
	More   bool // Has fields we didn't explicitly parse; user specified
	Accept bool
	Dest   string
	Bytes  uint64
	Pkts   uint64
}

func parseline(line string, table string, ipVer int) *AclCounters {
	items := strings.Split(line, " ")
	if len(items) < 4 {
		// log.Debugf("Too short: %s\n", line)
		return nil
	}
	if items[0] != "-A" {
		return nil
	}
	forward := items[1] == "FORWARD"
	ac := AclCounters{Table: table, Chain: items[1], IpVer: ipVer}
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

		// log.Debugf("Got more items %d %s\n", i, items[i])
		ac.More = true
		i += 1
	}
	return &ac
}
