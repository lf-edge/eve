// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// ACL configlet for overlay and underlay interface towards domU

package main

import (
	"fmt"       
	"log"
	"strconv"
	"github.com/zededa/go-provision/types"
)

// XXX add a function which returns a list of commands, witout the initial
// "-A FORWARD". Use for all/modify/delete

// XXX would be more polite to return an error then to Fatal
func createACLConfiglet(ifname string, ACLs []types.ACE, ipVer int) {
	fmt.Printf("createACLConfiglet: ifname %s, ACLs %v\n", ifname, ACLs)
	for _, acl := range ACLs {
		outArgs := []string{"-A", "FORWARD", "-i", ifname}
		inArgs := []string{"-A", "FORWARD", "-o", ifname}
		for _, match := range acl.Matches {
			addOut := []string{}
			addIn := []string{}
			switch match.Type {
			case "ip":
				addOut = []string{"-d", match.Value}
				addIn = []string{"-s", match.Value}
			case "protocol":
				addOut = []string{"-p", match.Value}
				addIn = []string{"-p", match.Value}
			case "fport":
				addOut = []string{"-m", "--dport", match.Value}
				addIn = []string{"-m", "--sport", match.Value}
			case "lport":
				addOut = []string{"-m", "--sport", match.Value}
				addIn = []string{"-m", "--dport", match.Value}
			case "host":
				// XXX assumes set has already been created!
				var ipsetName string
				if ipVer == 4 {
					ipsetName = "ipv4." + match.Value
				} else if ipVer == 6 {
					ipsetName = "ipv6." + match.Value
				}
				addOut = []string{"-m", "set", "--match-set",
					ipsetName, "dst"}
				addIn = []string{"-m", "set", "--match-set",
					ipsetName, "src"}
			case "eidset":
				// XXX only applies to IPv6 overlay
				ipsetName := "eids." + ifname	
				addOut = []string{"-m", "set", "--match-set",
					ipsetName, "dst"}
				addIn = []string{"-m", "set", "--match-set",
					ipsetName, "src"}
			default:
				// XXX add more types; error if unknown.
				log.Println("Unsupported ACL match type: ",
					match.Type)
			}
			outArgs = append(outArgs, addOut...)
			inArgs = append(inArgs, addIn...)
		}
		foundDrop := false
		for _, action := range acl.Actions {
			if action.Drop {
				foundDrop = true
			} else if action.Limit {
				// -m limit --limit 4/s --limit-burst 4
				limit := strconv.Itoa(action.LimitRate) + "/" +
				      action.LimitUnit
				burst := strconv.Itoa(action.LimitBurst)
				add := []string{"-m", "limit", "--limit", limit,
					"--limit-burst", burst}
				outArgs = append(outArgs, add...)
				inArgs = append(inArgs, add...)
			}
		}
		if foundDrop {
			outArgs = append(outArgs, []string{"-j", "DROP"}...)
			inArgs = append(inArgs, []string{"-j", "DROP"}...)
		} else {
			// Default
			outArgs = append(outArgs, []string{"-j", "ACCEPT"}...)
			inArgs = append(inArgs, []string{"-j", "ACCEPT"}...)
		}
		fmt.Printf("outArgs %v\n", outArgs)
		fmt.Printf("inArgs %v\n", inArgs)
		// XXX issue iptables cmds
		if ipVer == 4 {
			iptableCmd(outArgs...)
			iptableCmd(inArgs...)
		} else if ipVer == 6 {
			ip6tableCmd(outArgs...)
			ip6tableCmd(inArgs...)
		}
	}
	// Implicit drop
	outArgs := []string{"-A", "FORWARD", "-i", ifname, "-j", "DROP"}
	inArgs := []string{"-A", "FORWARD", "-o", ifname, "-j", "DROP"}
	if ipVer == 4 {
		iptableCmd(outArgs...)
		iptableCmd(inArgs...)
	} else if ipVer == 6 {
		ip6tableCmd(outArgs...)
		ip6tableCmd(inArgs...)
	}
}

func updateACLConfiglet(ifname string, oldACLs []types.ACE, newACLs []types.ACE,
     ipVer int) {
	fmt.Printf("updateACLConfiglet: ifname %s, oldACLs %v newACLs %v\n",
		ifname, oldACLs, newACLs)
	// XXX implement
}

// XXX can we find/flush just based on the ifname?
// XXX use separate chain??
func deleteACLConfiglet(ifname string, ACLs []types.ACE, ipVer int) {
	fmt.Printf("deleteACLConfiglet: ifname %s ACLs %v\n", ifname, ACLs)
	// XXX implement
}
