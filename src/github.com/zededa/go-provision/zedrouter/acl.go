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

// iptablesRule is the list of parmeters after the "-A", "FORWARD"
type IptablesRuleList []IptablesRule
type IptablesRule []string

func createACLConfiglet(ifname string, ACLs []types.ACE, ipVer int) {
	fmt.Printf("createACLConfiglet: ifname %s, ACLs %v\n", ifname, ACLs)
	rules := aclToRules(ifname, ACLs, ipVer)
	for _, rule := range rules {
		fmt.Printf("createACLConfiglet: rule %v\n", rule)
		args := []string{"-A", "FORWARD"}
		args = append(args, rule...)
		if ipVer == 4 {
			iptableCmd(args...)
		} else if ipVer == 6 {
			ip6tableCmd(args...)
		}
	}
}

// Returns a list of iptables commands, witout the initial "-A FORWARD"
func aclToRules(ifname string, ACLs []types.ACE, ipVer int) IptablesRuleList {
	rulesList := IptablesRuleList{}
	for _, ace := range ACLs {
		rules := aceToRules(ifname, ace, ipVer)
		rulesList = append(rulesList, rules...)
	}
	// Implicit drop at the end
	outArgs := []string{"-i", ifname, "-j", "DROP"}
	inArgs := []string{"-o", ifname, "-j", "DROP"}
	rulesList = append(rulesList, outArgs, inArgs)
	return rulesList
}

func aceToRules(ifname string, ace types.ACE, ipVer int) IptablesRuleList {
	outArgs := []string{"-i", ifname}
	inArgs := []string{"-o", ifname}
	for _, match := range ace.Matches {
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
			// Ensure the sets exists; create if not
			// XXX need to feed it into dnsmasq as well; restart
			// dnsmasq. SIGHUP?
			// XXX want created bool to determine whether to restart
			if err := ipsetCreatePair(match.Value); err != nil {
				log.Println("ipset create for ",
					match.Value, err)
			}

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
			// The eidset only applies to IPv6 overlay
			ipsetName := "eids." + ifname	
			addOut = []string{"-m", "set", "--match-set",
				ipsetName, "dst"}
			addIn = []string{"-m", "set", "--match-set",
				ipsetName, "src"}
		default:
			// XXX add more types; error if unknown.
			log.Println("Unsupported ACE match type: ",
				match.Type)
		}
		outArgs = append(outArgs, addOut...)
		inArgs = append(inArgs, addIn...)
	}
	foundDrop := false
	for _, action := range ace.Actions {
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
	rulesList := IptablesRuleList{}
	rulesList = append(rulesList, outArgs, inArgs)
	return rulesList
}

func equalRule(r1 IptablesRule, r2 IptablesRule) bool {
	if len(r1) != len(r2) {
		return false
	}
	for i, _ := range r1 {
		if r1[i] != r2[i] {
			return false
		}
	}
	return true
}

func containsRule(set IptablesRuleList, member IptablesRule) bool {
	for _, r := range set {
		if equalRule(r, member) {
			return true
		}
	}
	return false
}

func updateACLConfiglet(ifname string, oldACLs []types.ACE, newACLs []types.ACE,
     ipVer int) {
	fmt.Printf("updateACLConfiglet: ifname %s, oldACLs %v newACLs %v\n",
		ifname, oldACLs, newACLs)
	oldRules := aclToRules(ifname, oldACLs, ipVer)
	newRules := aclToRules(ifname, newACLs, ipVer)
	// Look for old which should be deleted
	for _, rule := range oldRules {
		if containsRule(newRules, rule) {
			continue
		}
		fmt.Printf("modifyACLConfiglet: delete rule %v\n", rule)
		args := []string{"-D", "FORWARD"}
		args = append(args, rule...)
		if ipVer == 4 {
			iptableCmd(args...)
		} else if ipVer == 6 {
			ip6tableCmd(args...)
		}
	}
	// Look for new which should be inserted
	for _, rule := range newRules {
		if containsRule(oldRules, rule) {
			continue
		}
		fmt.Printf("modifyACLConfiglet: add rule %v\n", rule)
		args := []string{"-I", "FORWARD"}
		args = append(args, rule...)
		if ipVer == 4 {
			iptableCmd(args...)
		} else if ipVer == 6 {
			ip6tableCmd(args...)
		}
	}
}

func deleteACLConfiglet(ifname string, ACLs []types.ACE, ipVer int) {
	fmt.Printf("deleteACLConfiglet: ifname %s ACLs %v\n", ifname, ACLs)
	rules := aclToRules(ifname, ACLs, ipVer)
	for _, rule := range rules {
		fmt.Printf("deleteACLConfiglet: rule %v\n", rule)
		args := []string{"-D", "FORWARD"}
		args = append(args, rule...)
		if ipVer == 4 {
			iptableCmd(args...)
		} else if ipVer == 6 {
			ip6tableCmd(args...)
		}
	}
}
