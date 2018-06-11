// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// ACL configlet for overlay and underlay interface towards domU

package zedrouter

import (
	"fmt"
	"github.com/zededa/go-provision/types"
	"log"
	"strconv"
)

// iptablesRule is the list of parmeters after the "-A", "FORWARD"
type IptablesRuleList []IptablesRule
type IptablesRule []string

// Go through the list of ACEs and create dnsmasq ipset configuration
// lines required for host matches
func compileAceIpsets(ACLs []types.ACE) []string {
	ipsets := []string{}

	for _, ace := range ACLs {
		for _, match := range ace.Matches {
			if match.Type == "host" {
				ipsets = append(ipsets, match.Value)
			}
		}
	}
	return ipsets
}

func compileOverlayIpsets(ollist []types.OverlayNetworkConfig) []string {
	ipsets := []string{}
	for _, olConfig := range ollist {
		ipsets = append(ipsets, compileAceIpsets(olConfig.ACLs)...)
	}
	return ipsets
}

func compileUnderlayIpsets(ullist []types.UnderlayNetworkConfig) []string {
	ipsets := []string{}
	for _, ulConfig := range ullist {
		ipsets = append(ipsets, compileAceIpsets(ulConfig.ACLs)...)
	}
	return ipsets
}

func compileAppInstanceIpsets(ollist []types.OverlayNetworkConfig,
	ullist []types.UnderlayNetworkConfig) []string {
	ipsets := []string{}

	ipsets = append(ipsets, compileOverlayIpsets(ollist)...)
	ipsets = append(ipsets, compileUnderlayIpsets(ullist)...)
	return ipsets
}

func compileOldOverlayIpsets(ollist []types.OverlayNetworkStatus) []string {
	ipsets := []string{}
	for _, olConfig := range ollist {
		ipsets = append(ipsets, compileAceIpsets(olConfig.ACLs)...)
	}
	return ipsets
}

func compileOldUnderlayIpsets(ullist []types.UnderlayNetworkStatus) []string {
	ipsets := []string{}
	for _, ulConfig := range ullist {
		ipsets = append(ipsets, compileAceIpsets(ulConfig.ACLs)...)
	}
	return ipsets
}

func compileOldAppInstanceIpsets(ollist []types.OverlayNetworkStatus,
	ullist []types.UnderlayNetworkStatus) []string {
	ipsets := []string{}

	ipsets = append(ipsets, compileOldOverlayIpsets(ollist)...)
	ipsets = append(ipsets, compileOldUnderlayIpsets(ullist)...)
	return ipsets
}

func createACLConfiglet(ifname string, isMgmt bool, ACLs []types.ACE,
	ipVer int, myIP string, appIP string, underlaySshPortMap uint) {
	if debug {
		log.Printf("createACLConfiglet: ifname %s, ACLs %v, IP %s/%s, ssh %d\n",
			ifname, ACLs, myIP, appIP, underlaySshPortMap)
	}
	rules := aclToRules(ifname, ACLs, ipVer, myIP, appIP,
		underlaySshPortMap)
	for _, rule := range rules {
		if debug {
			log.Printf("createACLConfiglet: rule %v\n", rule)
		}
		args := rulePrefix("-A", isMgmt, ipVer, rule)
		if args == nil {
			if debug {
				log.Printf("createACLConfiglet: skipping rule %v\n",
					rule)
			}
			continue
		}
		args = append(args, rule...)
		if ipVer == 4 {
			iptableCmd(args...)
		} else if ipVer == 6 {
			ip6tableCmd(args...)
		}
	}
	if !isMgmt {
		// Add mangle rules for IPv6 packets from the domU (overlay or
		// underlay) since netfront/netback thinks there is checksum
		// offload
		ip6tableCmd("-t", "mangle", "-A", "PREROUTING", "-i", ifname,
			"-p", "tcp", "-j", "CHECKSUM", "--checksum-fill")
		ip6tableCmd("-t", "mangle", "-A", "PREROUTING", "-i", ifname,
			"-p", "udp", "-j", "CHECKSUM", "--checksum-fill")
	}
	// XXX isMgmt is painful; related to commenting out eidset accepts
	// XXX won't need this when zedmanager is in a separate domU
	// Commenting out for now
	if false && ipVer == 6 && !isMgmt {
		// Manually add rules so that lispers.net doesn't see and drop
		// the packet on dbo1x0
		ip6tableCmd("-A", "FORWARD", "-i", ifname, "-o", "dbo1x0",
			"-j", "DROP")
	}
}

// Returns a list of iptables commands, witout the initial "-A FORWARD"
func aclToRules(ifname string, ACLs []types.ACE, ipVer int,
	myIP string, appIP string, underlaySshPortMap uint) IptablesRuleList {
	rulesList := IptablesRuleList{}
	// XXX should we check isMgmt instead of myIP?
	if ipVer == 6 && myIP != "" {
		// Need to allow local communication */
		// Note that sufficient for src or dst to be local
		rule1 := []string{"-i", ifname, "-m", "set", "--match-set",
			"local.ipv6", "dst", "-j", "ACCEPT"}
		rule2 := []string{"-i", ifname, "-m", "set", "--match-set",
			"local.ipv6", "src", "-j", "ACCEPT"}
		rule3 := []string{"-i", ifname, "-d", myIP, "-j", "ACCEPT"}
		rule4 := []string{"-i", ifname, "-s", myIP, "-j", "ACCEPT"}
		rulesList = append(rulesList, rule1, rule2, rule3, rule4)
	}
	if underlaySshPortMap != 0 {
		port := fmt.Sprintf("%d", underlaySshPortMap)
		dest := fmt.Sprintf("%s:22", appIP)
		// These rules should only apply on the uplink interfaces
		// but for now we just compare the TCP port number.
		rule1 := []string{"PREROUTING",
			"-p", "tcp", "--dport", port, "-j", "DNAT",
			"--to-destination", dest}
		// Make sure packets are returned to zedrouter and not e.g.,
		// out a directly attached interface in the domU
		rule2 := []string{"POSTROUTING",
			"-p", "tcp", "-o", ifname, "--dport", "22", "-j", "SNAT",
			"--to-source", myIP}
		rule3 := []string{"-o", ifname, "-p", "tcp", "--dport", "22",
			"-j", "ACCEPT"}
		rule4 := []string{"-i", ifname, "-p", "tcp", "--sport", "22",
			"-j", "ACCEPT"}
		rulesList = append(rulesList, rule1, rule2, rule3, rule4)
	}
	for _, ace := range ACLs {
		rules := aceToRules(ifname, ace, ipVer)
		rulesList = append(rulesList, rules...)
	}
	// Implicit drop at the end with log before it
	outArgs1 := []string{"-i", ifname, "-j", "LOG", "--log-prefix",
		"FORWARD:FROM:", "--log-level", "3"}
	inArgs1 := []string{"-o", ifname, "-j", "LOG", "--log-prefix",
		"FORWARD:TO:", "--log-level", "3"}
	outArgs2 := []string{"-i", ifname, "-j", "DROP"}
	inArgs2 := []string{"-o", ifname, "-j", "DROP"}
	rulesList = append(rulesList, outArgs1, inArgs1, outArgs2, inArgs2)
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
		// XXX add "interface" match? How does devops know whether eth0 or
		// eth1? Should it be implicit in the underlay in use (with
		// a special case for "uplink")
		case "fport":
			// XXX TCP and UDP implicitly? required by iptables
			// XXX need to add error checks and return to status
			addOut = []string{"--dport", match.Value}
			addIn = []string{"--sport", match.Value}
		case "lport":
			// XXX TCP and UDP implicitly? required
			addOut = []string{"--sport", match.Value}
			addIn = []string{"--dport", match.Value}
		case "host":
			// Ensure the sets exists; create if not
			// need to feed it into dnsmasq as well; restart
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
			// Caller adds local EID to set
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
	foundLimit := false
	unlimitedInArgs := inArgs
	unlimitedOutArgs := outArgs
	for _, action := range ace.Actions {
		if action.Drop {
			foundDrop = true
		} else if action.Limit {
			foundLimit = true
			// -m limit --limit 4/s --limit-burst 4
			add := []string{"-m", "limit"}
			// iptables doesn't limit --limit 0
			if action.LimitRate != 0 {
				limit := strconv.Itoa(action.LimitRate) + "/" +
					action.LimitUnit
				add = append(add, "--limit", limit)
			}
			if action.LimitBurst != 0 {
				burst := strconv.Itoa(action.LimitBurst)
				add = append(add, "--limit-burst", burst)
			}
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
	if debug {
		log.Printf("outArgs %v\n", outArgs)
		log.Printf("inArgs %v\n", inArgs)
	}
	rulesList := IptablesRuleList{}
	rulesList = append(rulesList, outArgs, inArgs)
	if foundLimit {
		// Add separate DROP without the limit to count the excess
		unlimitedOutArgs = append(unlimitedOutArgs,
			[]string{"-j", "DROP"}...)
		unlimitedInArgs = append(unlimitedInArgs,
			[]string{"-j", "DROP"}...)
		if debug {
			log.Printf("unlimitedOutArgs %v\n", unlimitedOutArgs)
			log.Printf("unlimitedInArgs %v\n", unlimitedInArgs)
		}
		rulesList = append(rulesList, unlimitedOutArgs, unlimitedInArgs)
	}
	return rulesList
}

// Determine which rules to skip and what prefix/table to use
func rulePrefix(operation string, isMgmt bool, ipVer int,
	rule IptablesRule) IptablesRule {
	prefix := []string{}
	if isMgmt {
		// Enforcing sending on OUTPUT. Enforcing receiving
		// using FORWARD since packet FORWARDED from lispers.net
		// interface.
		if rule[0] == "-o" {
			// XXX since domU traffic is forwarded out dbo1x0
			// we can't have the forward rule (unless we create a
			// set for all the EIDs)
			// This special handling will go away when ZedManager
			// is in a domU
			// prefix = []string{operation, "FORWARD"}
			return nil
		} else if rule[0] == "-i" {
			prefix = []string{operation, "OUTPUT"}
			rule[0] = "-o"
		} else {
			return nil
		}
	} else if ipVer == 6 {
		// The input rules (from domU are applied to raw to intercept
		// before lisp/pcap can pick them up.
		// The output rules (to domU) are applied in forwarding path
		// since packets are forwarded from lispers.net interface after
		// decap.
		// Note that the counter parsing code assumes this.
		if rule[0] == "-i" {
			prefix = []string{"-t", "raw", operation, "PREROUTING"}
		} else if rule[0] == "-o" {
			prefix = []string{operation, "FORWARD"}
		} else {
			return nil
		}
	} else {
		// Underlay
		if rule[0] == "PREROUTING" || rule[0] == "POSTROUTING" {
			// NAT verbatim rule
			prefix = []string{"-t", "nat", operation}
		} else {
			prefix = []string{operation, "FORWARD"}
		}
	}
	return prefix
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

func updateAppInstanceIpsets(newolConfig []types.OverlayNetworkConfig,
	newulConfig []types.UnderlayNetworkConfig,
	oldolConfig []types.OverlayNetworkStatus,
	oldulConfig []types.UnderlayNetworkStatus) ([]string, []string, bool) {
	staleIpsets := []string{}
	newIpsetMap := make(map[string]bool)
	restartDnsmasq := false

	newIpsets := compileAppInstanceIpsets(newolConfig, newulConfig)
	oldIpsets := compileOldAppInstanceIpsets(oldolConfig, oldulConfig)

	// Add all new ipsets in a map
	for _, ipset := range newIpsets {
		newIpsetMap[ipset] = true
	}

	// Check which of the old ipsets need to be removed
	for _, ipset := range oldIpsets {

		_, ok := newIpsetMap[ipset]
		if !ok {
			staleIpsets = append(staleIpsets, ipset)
		}
	}

	// When the ipset did not change, lenghts of old and new ipsets should
	// be same and then stale ipsets list should be empty.

	// In case if the ipset has changed but the lengh remained same, there
	// will atleast be one stale entry in the old ipset that needs to be removed.
	if (len(newIpsets) != len(oldIpsets)) || (len(staleIpsets) != 0) {
		restartDnsmasq = true
	}
	return newIpsets, staleIpsets, restartDnsmasq
}

func updateACLConfiglet(ifname string, isMgmt bool, oldACLs []types.ACE,
	newACLs []types.ACE, ipVer int, myIP string, appIP string,
	underlaySshPortMap uint) {
	if debug {
		log.Printf("updateACLConfiglet: ifname %s, oldACLs %v newACLs %v\n",
			ifname, oldACLs, newACLs)
	}
	oldRules := aclToRules(ifname, oldACLs, ipVer, myIP, appIP,
		underlaySshPortMap)
	newRules := aclToRules(ifname, newACLs, ipVer, myIP, appIP,
		underlaySshPortMap)
	// Look for old which should be deleted
	for _, rule := range oldRules {
		if containsRule(newRules, rule) {
			continue
		}
		if debug {
			log.Printf("modifyACLConfiglet: delete rule %v\n", rule)
		}
		args := rulePrefix("-D", isMgmt, ipVer, rule)
		if args == nil {
			if debug {
				log.Printf("modifyACLConfiglet: skipping delete rule %v\n",
					rule)
			}
			continue
		}
		args = append(args, rule...)
		if ipVer == 4 {
			iptableCmd(args...)
		} else if ipVer == 6 {
			ip6tableCmd(args...)
		}
	}
	// Look for new which should be inserted
	// We insert at the top in reverse order so that the relative order of the new rules
	// is preserved. Note that they are all added before any existing rules.
	numRules := len(newRules)
	for numRules > 0 {
		numRules--
		rule := newRules[numRules]
		if containsRule(oldRules, rule) {
			continue
		}
		if debug {
			log.Printf("modifyACLConfiglet: add rule %v\n", rule)
		}
		args := rulePrefix("-I", isMgmt, ipVer, rule)
		if args == nil {
			if debug {
				log.Printf("modifyACLConfiglet: skipping insert rule %v\n",
					rule)
			}
			continue
		}
		args = append(args, rule...)
		if ipVer == 4 {
			iptableCmd(args...)
		} else if ipVer == 6 {
			ip6tableCmd(args...)
		}
	}
}

func deleteACLConfiglet(ifname string, isMgmt bool, ACLs []types.ACE,
	ipVer int, myIP string, appIP string, underlaySshPortMap uint) {
	if debug {
		log.Printf("deleteACLConfiglet: ifname %s ACLs %v\n",
			ifname, ACLs)
	}
	rules := aclToRules(ifname, ACLs, ipVer, myIP, appIP,
		underlaySshPortMap)
	for _, rule := range rules {
		if debug {
			log.Printf("deleteACLConfiglet: rule %v\n", rule)
		}
		args := rulePrefix("-D", isMgmt, ipVer, rule)
		if args == nil {
			if debug {
				log.Printf("deleteACLConfiglet: skipping rule %v\n",
					rule)
			}
			continue
		}
		args = append(args, rule...)
		if ipVer == 4 {
			iptableCmd(args...)
		} else if ipVer == 6 {
			ip6tableCmd(args...)
		}
	}
	if !isMgmt {
		// Remove mangle rules for IPv6 packets added above
		ip6tableCmd("-t", "mangle", "-D", "PREROUTING", "-i", ifname,
			"-p", "tcp", "-j", "CHECKSUM", "--checksum-fill")
		ip6tableCmd("-t", "mangle", "-D", "PREROUTING", "-i", ifname,
			"-p", "udp", "-j", "CHECKSUM", "--checksum-fill")
	}
	// XXX see above
	if false && ipVer == 6 && !isMgmt {
		// Manually delete the manual add above
		ip6tableCmd("-D", "FORWARD", "-i", ifname, "-j", "DROP")
	}
}
