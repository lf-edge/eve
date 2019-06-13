// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// ACL configlet for overlay and underlay interface towards domU

package zedrouter

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// IpSet routines
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

func compileOverlayIpsets(ctx *zedrouterContext,
	ollist []types.OverlayNetworkConfig) []string {

	ipsets := []string{}
	for _, olConfig := range ollist {
		netconfig := lookupNetworkInstanceConfig(ctx,
			olConfig.Network.String())
		if netconfig != nil {
			// All ipsets from everybody on this network
			ipsets = append(ipsets, compileNetworkIpsetsConfig(ctx,
				netconfig)...)
		} else {
			log.Errorf("No NetworkInstanceConfig for %s",
				olConfig.Network.String())
		}
	}
	return ipsets
}

func compileUnderlayIpsets(ctx *zedrouterContext,
	ullist []types.UnderlayNetworkConfig) []string {

	ipsets := []string{}
	for _, ulConfig := range ullist {
		netconfig := lookupNetworkInstanceConfig(ctx,
			ulConfig.Network.String())
		if netconfig != nil {
			// All ipsets from everybody on this network
			ipsets = append(ipsets, compileNetworkIpsetsConfig(ctx,
				netconfig)...)
		} else {
			log.Errorf("No NetworkInstanceConfig for %s",
				ulConfig.Network.String())
		}
	}
	return ipsets
}

func compileAppInstanceIpsets(ctx *zedrouterContext,
	ollist []types.OverlayNetworkConfig,
	ullist []types.UnderlayNetworkConfig) []string {

	ipsets := []string{}
	ipsets = append(ipsets, compileOverlayIpsets(ctx, ollist)...)
	ipsets = append(ipsets, compileUnderlayIpsets(ctx, ullist)...)
	return ipsets
}

// If skipKey is set ignore any AppNetworkConfig with that key
func compileNetworkIpsetsStatus(ctx *zedrouterContext,
	netconfig *types.NetworkInstanceConfig, skipKey string) []string {

	ipsets := []string{}
	if netconfig == nil {
		return ipsets
	}
	// walk all of netconfig - find all hosts which use this network
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for key, st := range items {
		status := cast.CastAppNetworkStatus(st)
		if status.Key() != key {
			log.Errorf("compileNetworkIpsetsStatus key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		if skipKey != "" && status.Key() == skipKey {
			log.Debugf("compileNetworkIpsetsStatus skipping %s\n",
				skipKey)
			continue
		}

		for _, olStatus := range status.OverlayNetworkList {
			if olStatus.Network != netconfig.UUID {
				continue
			}
			ipsets = append(ipsets,
				compileAceIpsets(olStatus.ACLs)...)
		}
		for _, ulStatus := range status.UnderlayNetworkList {
			if ulStatus.Network != netconfig.UUID {
				continue
			}
			ipsets = append(ipsets,
				compileAceIpsets(ulStatus.ACLs)...)
		}
	}
	return ipsets
}

func compileNetworkIpsetsConfig(ctx *zedrouterContext,
	netconfig *types.NetworkInstanceConfig) []string {

	ipsets := []string{}
	if netconfig == nil {
		return ipsets
	}
	// walk all of netconfig - find all hosts which use this network
	sub := ctx.subAppNetworkConfig
	items := sub.GetAll()
	for key, c := range items {
		config := cast.CastAppNetworkConfig(c)
		if config.Key() != key {
			log.Errorf("compileNetworkIpsetsConfig key/UUID mismatch %s vs %s; ignored %+v\n",
				key, config.Key(), config)
			continue
		}
		for _, olConfig := range config.OverlayNetworkList {
			if olConfig.Network != netconfig.UUID {
				continue
			}
			ipsets = append(ipsets,
				compileAceIpsets(olConfig.ACLs)...)
		}
		for _, ulConfig := range config.UnderlayNetworkList {
			if ulConfig.Network != netconfig.UUID {
				continue
			}
			ipsets = append(ipsets,
				compileAceIpsets(ulConfig.ACLs)...)
		}
	}
	return ipsets
}

// If skipKey is set ignore any AppNetworkStatus with that key
func compileOldOverlayIpsets(ctx *zedrouterContext,
	ollist []types.OverlayNetworkStatus, skipKey string) []string {

	ipsets := []string{}
	for _, olStatus := range ollist {
		netconfig := lookupNetworkInstanceConfig(ctx,
			olStatus.Network.String())
		if netconfig != nil {
			// All ipsets from everybody on this network
			ipsets = append(ipsets, compileNetworkIpsetsStatus(ctx,
				netconfig, skipKey)...)
		} else {
			log.Errorf("No NetworkInstanceConfig for %s",
				olStatus.Network.String())
		}
	}
	return ipsets
}

// If skipKey is set ignore any AppNetworkStatus with that key
func compileOldUnderlayIpsets(ctx *zedrouterContext,
	ullist []types.UnderlayNetworkStatus, skipKey string) []string {

	ipsets := []string{}
	for _, ulStatus := range ullist {
		netconfig := lookupNetworkInstanceConfig(ctx,
			ulStatus.Network.String())
		if netconfig != nil {
			// All ipsets from everybody on this network
			ipsets = append(ipsets, compileNetworkIpsetsStatus(ctx,
				netconfig, skipKey)...)
		} else {
			log.Errorf("No NetworkInstanceConfig for %s",
				ulStatus.Network.String())
		}
	}
	return ipsets
}

// If skipKey is set ignore any AppNetworkStatus with that key
func compileOldAppInstanceIpsets(ctx *zedrouterContext,
	ollist []types.OverlayNetworkStatus,
	ullist []types.UnderlayNetworkStatus, skipKey string) []string {

	ipsets := []string{}
	ipsets = append(ipsets, compileOldOverlayIpsets(ctx, ollist, skipKey)...)
	ipsets = append(ipsets, compileOldUnderlayIpsets(ctx, ullist, skipKey)...)
	return ipsets
}

// Application Network Level ACL rule handling routines

// For a shared bridge call aclToRules for each ifname, then aclDropRules,
// then concat all the rules and pass to applyACLrules
// Note that only bridgeName is set with ifMgmt
func createACLConfiglet(aclArgs types.AppNetworkACLArgs,
	ACLs []types.ACE) (types.IPTablesRuleList, error) {

	log.Infof("createACLConfiglet: ifname %s, vifName %s, IP %s/%s, ACLs %v\n",
		aclArgs.BridgeName, aclArgs.VifName, aclArgs.BridgeIP, aclArgs.AppIP, ACLs)
	aclArgs.IPVer = determineIPVer(aclArgs.IsMgmt, aclArgs.BridgeIP)
	rules, err := aclToRules(aclArgs, ACLs)
	if err != nil {
		return rules, err
	}
	dropRules, err := aclDropRules(aclArgs)
	if err != nil {
		return rules, err
	}
	rules = append(rules, dropRules...)
	return applyACLRules(aclArgs, rules)
}

// If no valid bridgeIP we assume IPv4
func determineIPVer(isMgmt bool, bridgeIP string) int {
	if isMgmt {
		return 6
	}
	if bridgeIP == "" {
		return 4
	}
	ip := net.ParseIP(bridgeIP)
	if ip == nil {
		log.Fatalf("determineIPVer: ParseIP %s failed\n",
			bridgeIP)
	}
	if ip.To4() == nil {
		return 6
	} else {
		return 4
	}
}

func applyACLRules(aclArgs types.AppNetworkACLArgs,
	rules types.IPTablesRuleList) (types.IPTablesRuleList, error) {
	var err error
	var activeRules types.IPTablesRuleList
	log.Debugf("applyACLRules: ipVer %d, bridgeName %s appIP %s with %d rules\n",
		aclArgs.IPVer, aclArgs.BridgeName, aclArgs.AppIP, len(rules))
	numRules := len(rules)
	for numRules > 0 {
		numRules--
		rule := rules[numRules]
		log.Debugf("createACLConfiglet: add rule %v\n", rule)
		if err := rulePrefix(aclArgs, &rule); err != nil {
			log.Debugf("createACLConfiglet: skipping rule %v\n", rule)
			continue
		}
		err = executeIPTablesRule("-I", rule)
		if err == nil {
			activeRules = append(activeRules, rule)
		} else {
			return activeRules, err
		}
	}
	return activeRules, err
}

// Returns a list of iptables commands, witout the initial "-A FORWARD"
func aclToRules(aclArgs types.AppNetworkACLArgs, ACLs []types.ACE) (types.IPTablesRuleList, error) {

	var rulesList types.IPTablesRuleList
	log.Debugf("aclToRules(%s, %s, %d, %s, %s, %v\n",
		aclArgs.BridgeName, aclArgs.VifName, aclArgs.IPVer,
		aclArgs.BridgeIP, aclArgs.AppIP, ACLs)

	var aclRule1, aclRule2, aclRule3, aclRule4 types.IPTablesRule
	aclRule1.IPVer = aclArgs.IPVer
	aclRule2.IPVer = aclArgs.IPVer
	aclRule3.IPVer = aclArgs.IPVer
	aclRule4.IPVer = aclArgs.IPVer
	// XXX should we check isMgmt instead of bridgeIP?
	if aclArgs.IPVer == 6 && aclArgs.BridgeIP != "" {
		// Need to allow local communication */
		// Only allow dhcp, dns (tcp/udp), and icmp6/nd
		// Note that sufficient for src or dst to be local
		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv6.local", "dst", "-p", "ipv6-icmp", "-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv6.local", "src", "-p", "ipv6-icmp", "-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d",
			aclArgs.BridgeIP, "-p", "ipv6-icmp", "-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s",
			aclArgs.BridgeIP, "-p", "ipv6-icmp", "-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv6.local", "dst", "-p", "udp", "--dport", "dhcpv6-server",
			"-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv6.local", "src", "-p", "udp", "--sport", "dhcpv6-server",
			"-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "udp", "--dport", "dhcpv6-server", "-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "udp", "--sport", "dhcpv6-server", "-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "udp", "--dport", "domain", "-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "udp", "--sport", "domain", "-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "tcp", "--dport", "domain", "-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "tcp", "--sport", "domain", "-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)
	}
	// The same rules as above for IPv4.
	// If we have a bridge service then bridgeIP might be "".
	if aclArgs.IPVer == 4 && aclArgs.BridgeIP != "" {
		// Need to allow local communication */
		// Only allow dhcp and dns (tcp/udp)
		// Note that sufficient for src or dst to be local
		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv4.local", "dst", "-p", "udp", "--dport", "bootps",
			"-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv4.local", "src", "-p", "udp", "--sport", "bootps",
			"-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "udp", "--dport", "bootps", "-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "udp", "--sport", "bootps", "-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "udp", "--dport", "domain", "-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "udp", "--sport", "domain", "-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "tcp", "--dport", "domain", "-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "tcp", "--sport", "domain", "-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)
	}

	// XXX isMgmt is painful; related to commenting out eidset accepts
	// XXX won't need this when zedmanager is in a separate domU
	// Commenting out for now
	if false && aclArgs.IsMgmt && aclArgs.IPVer == 6 {
		aclRule1.IPVer = 6
		aclRule1.Table = "mangle"
		aclRule1.Chain = "FORWARD"
		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-o", "dbo1x0",
			"-j", "DROP"}
		rulesList = append(rulesList, aclRule1)
	}

	for _, ace := range ACLs {
		rules, err := aceToRules(aclArgs, ace)
		if err != nil {
			return nil, err
		}
		rulesList = append(rulesList, rules...)
	}
	log.Debugf("aclToRules(%v)\n", rulesList)
	return rulesList, nil
}

func aclDropRules(aclArgs types.AppNetworkACLArgs) (types.IPTablesRuleList, error) {

	var rulesList types.IPTablesRuleList
	var aclRule1, aclRule2, aclRule3, aclRule4 types.IPTablesRule
	aclRule1.IPVer = aclArgs.IPVer
	aclRule2.IPVer = aclArgs.IPVer
	aclRule3.IPVer = aclArgs.IPVer
	aclRule4.IPVer = aclArgs.IPVer

	log.Debugf("aclDropRules: bridgeName %s, vifName %s\n",
		aclArgs.BridgeName, aclArgs.VifName)

	// Always match on interface. Note that rulePrefix adds physdev-in
	// Implicit drop at the end with log before it
	aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-j", "LOG", "--log-prefix",
		"FORWARD:FROM:", "--log-level", "3"}
	aclRule2.Rule = []string{"-o", aclArgs.BridgeName, "-j", "LOG", "--log-prefix",
		"FORWARD:TO:", "--log-level", "3"}
	aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-j", "DROP"}
	aclRule4.Rule = []string{"-o", aclArgs.BridgeName, "-j", "DROP"}
	rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)
	return rulesList, nil
}

func aceToRules(aclArgs types.AppNetworkACLArgs, ace types.ACE) (types.IPTablesRuleList, error) {
	var rulesList types.IPTablesRuleList

	// Extract lport and protocol from the Matches to use for PortMap
	// Keep others to make sure we put the protocol before the port
	// number(s)
	var ip string
	var ipsetName string
	var protocol string
	var lport string
	var fport string

	// max six rules, (2 port map rule,  2 accept rules, 2 limit drop rules)
	var aclRule1, aclRule2, aclRule3, aclRule4, aclRule5, aclRule6 types.IPTablesRule
	aclRule1.IPVer = aclArgs.IPVer
	aclRule2.IPVer = aclArgs.IPVer
	aclRule3.IPVer = aclArgs.IPVer
	aclRule4.IPVer = aclArgs.IPVer
	aclRule5.IPVer = aclArgs.IPVer
	aclRule6.IPVer = aclArgs.IPVer

	// Always match on interface. Note that rulePrefix adds physdev-in
	inArgs := []string{"-o", aclArgs.BridgeName}
	outArgs := []string{"-i", aclArgs.BridgeName}

	for _, match := range ace.Matches {
		switch match.Type {
		case "ip":
			ip = match.Value
		case "protocol":
			protocol = match.Value
		case "fport":
			// Need a protocol as well. Checked below.
			fport = match.Value
		case "lport":
			// Need a protocol as well. Checked below.
			lport = match.Value
		case "host":
			// Check if this should really be an "ip" ACL
			if isIPorCIDR(match.Value) {
				log.Warnf("Found host ACL with IP/CIDR %s; treating as ip ACL",
					match.Value)
				ip = match.Value
				break
			}
			if ipsetName != "" {
				errStr := fmt.Sprintf("ACE with eidset and host not supported: %+v",
					ace)
				log.Errorln(errStr)
				return nil, errors.New(errStr)
			}
			// Ensure the sets exists; create if not
			// need to feed it into dnsmasq as well; restart
			err := ipsetCreatePair(match.Value, "hash:ip")
			if err != nil {
				log.Errorln("ipset create for ",
					match.Value, err)
			}
			switch aclArgs.IPVer {
			case 4:
				ipsetName = "ipv4." + match.Value
			case 6:
				ipsetName = "ipv6." + match.Value
			}
		case "eidset":
			if ipsetName != "" {
				errStr := fmt.Sprintf("ACE with eidset and host not supported: %+v",
					ace)
				log.Errorln(errStr)
				return nil, errors.New(errStr)
			}
			// Caller adds any EIDs/IPs to set
			switch aclArgs.IPVer {
			case 4:
				ipsetName = "ipv4.eids." + aclArgs.VifName
			case 6:
				ipsetName = "ipv6.eids." + aclArgs.VifName
			}
		default:
			errStr := fmt.Sprintf("Unsupported ACE match type: %s",
				match.Type)
			log.Errorln(errStr)
			return nil, errors.New(errStr)
		}
	}
	// Consistency checks
	if fport != "" && protocol == "" {
		errStr := fmt.Sprintf("ACE with fport %s and no protocol match: %+v",
			fport, ace)
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}
	if lport != "" && protocol == "" {
		errStr := fmt.Sprintf("ACE with lport %s and no protocol match: %+v",
			lport, ace)
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}

	if ip != "" {
		outArgs = append(outArgs, "-d", ip)
		inArgs = append(inArgs, "-s", ip)
	}
	// Make sure we put the protocol before any port numbers
	if protocol != "" {
		outArgs = append(outArgs, "-p", protocol)
		inArgs = append(inArgs, "-p", protocol)
	}
	if fport != "" {
		outArgs = append(outArgs, "--dport", fport)
		inArgs = append(inArgs, "--sport", fport)
	}
	if lport != "" {
		outArgs = append(outArgs, "--sport", lport)
		inArgs = append(inArgs, "--dport", lport)
	}
	if ipsetName != "" {
		outArgs = append(outArgs, "-m", "set", "--match-set",
			ipsetName, "dst")
		inArgs = append(inArgs, "-m", "set", "--match-set",
			ipsetName, "src")
	}

	foundDrop := false
	foundLimit := false
	unlimitedInArgs := inArgs
	unlimitedOutArgs := outArgs
	actionCount := 0
	for _, action := range ace.Actions {
		// We check and reject combinations of Drop, Limit, and PortMap
		// At most one allowed
		if action.Drop {
			actionCount += 1
			foundDrop = true
		}
		if action.Limit {
			actionCount += 1
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
		if action.PortMap {
			actionCount += 1
			// Generate NAT and ACCEPT rules based on protocol,
			// lport, and TargetPort
			if lport == "" || protocol == "" {
				errStr := fmt.Sprintf("PortMap without lport %s or protocol %s: %+v",
					lport, protocol, ace)
				log.Errorln(errStr)
				return nil, errors.New(errStr)
			}
			if aclArgs.AppIP == "" {
				errStr := fmt.Sprintf("PortMap without appIP for lport %s/protocol %s: %+v",
					lport, protocol, ace)
				log.Errorln(errStr)
				return nil, errors.New(errStr)
			}
			targetPort := fmt.Sprintf("%d", action.TargetPort)
			target := fmt.Sprintf("%s:%d", aclArgs.AppIP, action.TargetPort)
			// These rules are applied on the upLink interfaces and port number.
			// loop through the uplink interfaces
			for _, upLink := range aclArgs.UpLinks {
				log.Debugf("PortMap - upLink %s\n", upLink)
				// The DNAT/SNAT rules do not compare fport and ipset
				// Make sure packets are returned to zedrouter and not
				// e.g., out a directly attached interface in the domU
				aclRule1.Table = "nat"
				aclRule1.Chain = "PREROUTING"
				aclRule1.Rule = []string{"-i", upLink, "-p", protocol,
					"--dport", lport, "-j", "DNAT",
					"--to-destination", target}
				rulesList = append(rulesList, aclRule1)
			}
			// add the outgoing port-map translation rule to bridge port
			aclRule2.Table = "nat"
			aclRule2.Chain = "POSTROUTING"
			aclRule2.Rule = []string{"-o", aclArgs.BridgeName, "-p", protocol,
				"--dport", targetPort, "-j", "SNAT",
				"--to-source", aclArgs.BridgeIP}
			rulesList = append(rulesList, aclRule2)

			// Below we make sure the mapped packets get through
			// Note that port/targetport change relative
			// no normal ACL above.
			outArgs = []string{"-i", aclArgs.BridgeName}
			inArgs = []string{"-o", aclArgs.BridgeName}

			if ip != "" {
				outArgs = append(outArgs, "-d", ip)
				inArgs = append(inArgs, "-s", ip)
			}
			// Make sure we put the protocol before any port numbers
			outArgs = append(outArgs, "-p", protocol)
			inArgs = append(inArgs, "-p", protocol)
			if fport != "" {
				outArgs = append(outArgs, "--dport", fport)
				inArgs = append(inArgs, "--sport", fport)
			}
			outArgs = append(outArgs, "--sport", targetPort)
			inArgs = append(inArgs, "--dport", targetPort)
			if ipsetName != "" {
				outArgs = append(outArgs, []string{"-m", "set",
					"--match-set", ipsetName, "dst"}...)
				inArgs = append(inArgs, []string{"-m", "set",
					"--match-set", ipsetName, "src"}...)
			}
		}
		if actionCount > 1 {
			errStr := fmt.Sprintf("ACL with combination of Drop, Limit and/or PortMap rejected: %+v",
				ace)
			log.Errorln(errStr)
			return nil, errors.New(errStr)
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
	aclRule3.Rule = inArgs
	aclRule4.Rule = outArgs
	rulesList = append(rulesList, aclRule4, aclRule3)
	if foundLimit {
		// Add separate DROP without the limit to count the excess
		unlimitedOutArgs = append(unlimitedOutArgs,
			[]string{"-j", "DROP"}...)
		unlimitedInArgs = append(unlimitedInArgs,
			[]string{"-j", "DROP"}...)
		log.Debugf("unlimitedOutArgs %v\n", unlimitedOutArgs)
		log.Debugf("unlimitedInArgs %v\n", unlimitedInArgs)
		aclRule5.Rule = unlimitedInArgs
		aclRule6.Rule = unlimitedOutArgs
		rulesList = append(rulesList, aclRule5, aclRule6)
	}
	log.Infof("rulesList %v\n", rulesList)
	return rulesList, nil
}

func isIPorCIDR(str string) bool {
	if net.ParseIP(str) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(str)
	return err == nil
}

// Determine which rules to skip and what prefix/table to use
// We append a '+' to the vifname to handle PV/qemu which for some
// reason have a second <vifname>-emu bridge interface.
func rulePrefix(aclArgs types.AppNetworkACLArgs, rule *types.IPTablesRule) error {

	vifName := aclArgs.VifName

	if vifName != "" {
		vifName += "+"
	}
	if aclArgs.IsMgmt {
		// Enforcing sending on OUTPUT. Enforcing receiving
		// using FORWARD since packet FORWARDED from lispers.net
		// interface.
		if rule.Rule[0] == "-o" {
			// XXX since domU traffic is forwarded out dbo1x0
			// we can't have the forward rule (unless we create a
			// set for all the EIDs)
			// This special handling will go away when ZedManager
			// is in a domU
			// prefix = []string{"FORWARD"}
			errStr := fmt.Sprintf("ACL: skipping over %v", rule.Rule)
			return errors.New(errStr)
		}
		if rule.Rule[0] == "-i" {
			rule.Chain = "OUTPUT"
			rule.Rule[0] = "-o"
		}
		return nil
	}

	if aclArgs.IPVer == 6 {
		// The input rules (from domU are applied to raw to intercept
		// before lisp/pcap can pick them up.
		// The output rules (to domU) are applied in forwarding path
		// since packets are forwarded from lispers.net interface after
		// decap.
		// Note that the counter parsing code assumes this.
		if rule.Rule[0] == "-i" {
			rule.Table = "raw"
			rule.Chain = "PREROUTING"
			rule.Prefix = []string{"-m", "physdev", "--physdev-in", vifName}
		} else if rule.Rule[0] == "-o" {
			rule.Chain = "FORWARD"
			if aclArgs.AppIP != "" {
				rule.Prefix = []string{"-d", aclArgs.AppIP}
			}
		}
		return nil
	}

	// table, chain are already set, nothing extra need to be done
	if rule.Table != "" || rule.Chain != "" {
		// NAT verbatim rule, already set
		// MANGLE verbatim rule, already set
		return nil
	}

	// Underlay; we have NAT rules and otherwise the same as
	// for IPv6
	if rule.Rule[0] == "-i" {
		rule.Table = "raw"
		rule.Chain = "PREROUTING"
		rule.Prefix = []string{"-m", "physdev", "--physdev-in", vifName}
		return nil
	}
	if rule.Rule[0] == "-o" {
		rule.Table = ""
		rule.Chain = "FORWARD"
		if aclArgs.AppIP != "" {
			rule.Prefix = []string{"-d", aclArgs.AppIP}
		}
		return nil
	}
	errStr := fmt.Sprintf("ACL: Invalid Rule %v", rule.Rule)
	return errors.New(errStr)
}

func equalRule(r1 types.IPTablesRule, r2 types.IPTablesRule) bool {
	if r1.IPVer != r2.IPVer || r1.Table != r2.Table ||
		r1.Chain != r2.Chain || len(r1.Rule) != len(r2.Rule) {
		return false
	}
	for i := range r1.Rule {
		if r1.Rule[i] != r2.Rule[i] {
			return false
		}
	}
	return true
}

func containsRule(set types.IPTablesRuleList, member types.IPTablesRule) bool {
	for _, r := range set {
		if equalRule(r, member) {
			return true
		}
	}
	return false
}

func diffIpsets(newIpsets, oldIpsets []string) ([]string, []string, bool) {

	staleIpsets := []string{}
	newIpsetMap := make(map[string]bool)
	restartDnsmasq := false

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
	log.Infof("diffIpsets: restart %v, new %v, stale %v",
		restartDnsmasq, newIpsets, staleIpsets)
	return newIpsets, staleIpsets, restartDnsmasq
}

// it will be difficult the maintain the precedence/order of the iptables
// rules, across multiple app instance modules
// apply rules as a block
// lets just delete the existing ACL iptables rules block
// and add the new ACL rules, for the appNetwork.
func updateACLConfiglet(aclArgs types.AppNetworkACLArgs, oldACLs []types.ACE, ACLs []types.ACE,
	oldRules types.IPTablesRuleList) (types.IPTablesRuleList, error) {

	log.Infof("updateACLConfiglet: bridgeName %s, vifName %s, appIP %s\n",
		aclArgs.BridgeName, aclArgs.VifName, aclArgs.AppIP)

	aclArgs.IPVer = determineIPVer(aclArgs.IsMgmt, aclArgs.BridgeIP)
	if compareACLs(oldACLs, ACLs) == true {
		log.Infof("updateACLConfiglet: bridgeName %s, vifName %s, appIP %s: no change\n",
			aclArgs.BridgeName, aclArgs.VifName, aclArgs.AppIP)
		return oldRules, nil
	}
	rules, err := deleteACLConfiglet(aclArgs, oldRules)
	if err != nil {
		log.Infof("updateACLConfiglet: bridgeName %s, vifName %s, appIP %s: delete fail\n",
			aclArgs.BridgeName, aclArgs.VifName, aclArgs.AppIP)
		return rules, err
	}
	return createACLConfiglet(aclArgs, ACLs)
}

func deleteACLConfiglet(aclArgs types.AppNetworkACLArgs,
	rules types.IPTablesRuleList) (types.IPTablesRuleList, error) {
	var err error
	var activeRules types.IPTablesRuleList
	log.Infof("deleteACLConfiglet: ifname %s vifName %s ACLs %v\n",
		aclArgs.BridgeName, aclArgs.VifName, rules)

	for _, rule := range rules {
		log.Debugf("deleteACLConfiglet: rule %v\n", rule)
		if err != nil {
			activeRules = append(activeRules, rule)
		} else {
			err = executeIPTablesRule("-D", rule)
		}
	}
	return activeRules, err
}

// utility routines for ACLs
func compareACLs(ACL0 []types.ACE, ACL1 []types.ACE) bool {
	if len(ACL0) != len(ACL1) {
		return false
	}
	for idx, ACE0 := range ACL0 {
		ACE1 := ACL1[idx]
		if !compareACE(ACE0, ACE1) {
			return false
		}
	}
	return true
}

func compareACE(ACE0 types.ACE, ACE1 types.ACE) bool {
	if len(ACE0.Matches) != len(ACE1.Matches) ||
		len(ACE0.Actions) != len(ACE1.Actions) {
		return false
	}
	for idx, match0 := range ACE0.Matches {
		match1 := ACE1.Matches[idx]
		if match0.Type != match1.Type ||
			match0.Value != match1.Value {
			return false
		}
	}
	for idx, action0 := range ACE0.Actions {
		action1 := ACE1.Actions[idx]
		if action0.Drop != action1.Drop ||
			action0.Limit != action1.Limit ||
			action0.PortMap != action1.PortMap {
			return false
		}
		if action0.PortMap {
			if action0.TargetPort != action1.TargetPort {
				return false
			}
		}
		if action0.Limit {
			if action0.LimitRate != action1.LimitRate ||
				action0.LimitUnit != action1.LimitUnit ||
				action0.LimitBurst != action1.LimitBurst {
				return false
			}
		}
	}
	return true
}

// check for portmap Acl overlap
func matchACLsForPortMap(ACLs []types.ACE, ACLs1 []types.ACE) bool {
	matchTypes := []string{"protocol", "lport"}
	for _, ace := range ACLs {
		for _, action := range ace.Actions {
			// not a portmap rule
			if !action.PortMap {
				continue
			}
			for _, ace1 := range ACLs1 {
				for _, action1 := range ace1.Actions {
					// not a portmap rule
					if !action1.PortMap {
						continue
					}
					// check for ingress protocol/port
					if checkForMatchCondition(ace, ace1, matchTypes) {
						return true
					}
				}
			}
		}
	}
	return false
}

// generic comparision routine for ACL match conditions
func checkForMatchCondition(ace types.ACE, ace1 types.ACE, matchTypes []string) bool {
	valueList := make([]string, len(matchTypes))
	valueList1 := make([]string, len(matchTypes))

	for idx, matchType := range matchTypes {
		for _, match := range ace.Matches {
			if matchType == match.Type {
				valueList[idx] = match.Value
			}
		}
		for _, match := range ace1.Matches {
			if matchType == match.Type {
				valueList1[idx] = match.Value
			}
		}
	}
	for idx, value := range valueList {
		value1 := valueList1[idx]
		if value == "" || value1 == "" ||
			value != value1 {
			return false
		}
	}
	return true
}

// utility routines for IpTables Rules
func executeIPTablesRule(operation string, rule types.IPTablesRule) error {
	var err error
	ruleStr := []string{}
	if rule.Table != "" {
		ruleStr = append(ruleStr, "-t")
		ruleStr = append(ruleStr, rule.Table)
	}
	ruleStr = append(ruleStr, operation)
	ruleStr = append(ruleStr, rule.Chain)
	ruleStr = append(ruleStr, rule.Prefix...)
	ruleStr = append(ruleStr, rule.Rule...)
	if rule.IPVer == 4 {
		err = iptables.IptableCmd(ruleStr...)
	} else if rule.IPVer == 6 {
		err = iptables.Ip6tableCmd(ruleStr...)
	} else {
		errStr := fmt.Sprintf("ACL: Unknown IP version %d", rule.IPVer)
		err = errors.New(errStr)
	}
	return err
}

// handle network instance level ACL rules
// Network Instance Level ACL rule handling routines
func handleNetworkInstanceACLConfiglet(op string, aclArgs types.AppNetworkACLArgs) error {

	log.Infof("bridge(%s, %v) iptables op: %v\n", aclArgs.BridgeName, aclArgs.BridgeIP, op)
	rulesList := networkInstanceBridgeRules(aclArgs)
	for _, rule := range rulesList {
		if err := executeIPTablesRule(op, rule); err != nil {
			return err
		}
	}
	return nil
}

func networkInstanceBridgeRules(aclArgs types.AppNetworkACLArgs) types.IPTablesRuleList {
	var rulesList types.IPTablesRuleList
	var aclRule1, aclRule2 types.IPTablesRule

	// not for dom0
	if aclArgs.IsMgmt {
		return rulesList
	}
	aclArgs.IPVer = determineIPVer(aclArgs.IsMgmt, aclArgs.BridgeIP)
	// two rules for ipv4
	aclRule1.IPVer = 4
	aclRule1.Table = "mangle"
	aclRule1.Chain = "PREROUTING"
	aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-p", "tcp",
		"-j", "CHECKSUM", "--checksum-fill"}
	aclRule2.IPVer = 4
	aclRule2.Table = "mangle"
	aclRule2.Chain = "PREROUTING"
	aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-p", "udp",
		"-j", "CHECKSUM", "--checksum-fill"}
	rulesList = append(rulesList, aclRule1, aclRule2)

	// two rules for ipv6
	aclRule1.IPVer = 6
	aclRule1.Table = "mangle"
	aclRule1.Chain = "PREROUTING"
	aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-p", "tcp",
		"-j", "CHECKSUM", "--checksum-fill"}
	aclRule2.IPVer = 6
	aclRule2.Table = "mangle"
	aclRule2.Chain = "PREROUTING"
	aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-p", "udp",
		"-j", "CHECKSUM", "--checksum-fill"}
	rulesList = append(rulesList, aclRule1, aclRule2)

	aclRule1.IPVer = aclArgs.IPVer
	aclRule1.Table = ""
	aclRule1.Chain = "FORWARD"
	aclRule1.Rule = []string{"-o", aclArgs.BridgeName, "-j", "LOG", "--log-prefix",
		"FORWARD:TO:", "--log-level", "3"}
	aclRule2.IPVer = aclArgs.IPVer
	aclRule2.Table = ""
	aclRule2.Chain = "FORWARD"
	aclRule2.Rule = []string{"-o", aclArgs.BridgeName, "-j", "DROP"}
	rulesList = append(rulesList, aclRule1, aclRule2)
	log.Infof("bridge(%s, %v) attach iptable rules:%v\n",
		aclArgs.BridgeName, aclArgs.BridgeIP, rulesList)
	return rulesList
}
