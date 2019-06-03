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

// For a shared bridge call aclToRules for each ifname, then aclDropRules,
// then concat all the rules and pass to applyACLrules
// Note that only bridgeName is set with ifMgmt
func createACLConfiglet(appNetInfo types.AppNetworkInfo, ACLs []types.ACE) error {

	log.Infof("createACLConfiglet: ifname %s, vifName %s, IP %s/%s, ACLs %v\n",
		appNetInfo.BridgeName, appNetInfo.VifName, appNetInfo.BridgeIP, appNetInfo.AppIP, ACLs)
	appNetInfo.IpVer = determineIpVer(appNetInfo.IsMgmt, appNetInfo.BridgeIP)
	rules, err := aclToRules(appNetInfo, ACLs)
	if err != nil {
		return err
	}
	dropRules, err := aclDropRules(appNetInfo.BridgeName, appNetInfo.VifName)
	if err != nil {
		return err
	}
	rules = append(rules, dropRules...)
	return applyACLRules(rules, appNetInfo.BridgeName, appNetInfo.VifName,
		appNetInfo.IsMgmt, appNetInfo.IpVer, appNetInfo.AppIP)
}

// If no valid bridgeIP we assume IPv4
func determineIpVer(isMgmt bool, bridgeIP string) int {
	if isMgmt {
		return 6
	}
	if bridgeIP == "" {
		return 4
	}
	ip := net.ParseIP(bridgeIP)
	if ip == nil {
		log.Fatalf("determineIpVer: ParseIP %s failed\n",
			bridgeIP)
	}
	if ip.To4() == nil {
		return 6
	} else {
		return 4
	}
}

func applyACLRules(rules IptablesRuleList, bridgeName string, vifName string,
	isMgmt bool, ipVer int, appIP string) error {

	log.Debugf("applyACLRules: bridgeName %s ipVer %d appIP %s with %d rules\n",
		bridgeName, ipVer, appIP, len(rules))
	var err error
	for _, rule := range rules {
		log.Debugf("createACLConfiglet: rule %v\n", rule)
		args := rulePrefix("-A", isMgmt, ipVer, vifName, appIP, rule)
		if args == nil {
			log.Debugf("createACLConfiglet: skipping rule %v\n",
				rule)
			continue
		}
		args = append(args, rule...)
		if ipVer == 4 {
			err = iptables.IptableCmd(args...)
		} else if ipVer == 6 {
			err = iptables.Ip6tableCmd(args...)
		} else {
			err = errors.New(fmt.Sprintf("ACL: Unknown IP version %d", ipVer))
		}
		if err != nil {
			return err
		}
	}
	if !isMgmt {
		// Add mangle rules for IPv6 packets from the domU (overlay or
		// underlay) since netfront/netback thinks there is checksum
		// offload
		// XXX add error checks?
		iptables.Ip6tableCmd("-t", "mangle", "-A", "PREROUTING", "-i", bridgeName,
			"-p", "tcp", "-j", "CHECKSUM", "--checksum-fill")
		iptables.Ip6tableCmd("-t", "mangle", "-A", "PREROUTING", "-i", bridgeName,
			"-p", "udp", "-j", "CHECKSUM", "--checksum-fill")
		iptables.IptableCmd("-t", "mangle", "-A", "PREROUTING", "-i", bridgeName,
			"-p", "tcp", "-j", "CHECKSUM", "--checksum-fill")
		iptables.IptableCmd("-t", "mangle", "-A", "PREROUTING", "-i", bridgeName,
			"-p", "udp", "-j", "CHECKSUM", "--checksum-fill")
	}
	// XXX isMgmt is painful; related to commenting out eidset accepts
	// XXX won't need this when zedmanager is in a separate domU
	// Commenting out for now
	if false && ipVer == 6 && !isMgmt {
		// Manually add rules so that lispers.net doesn't see and drop
		// the packet on dbo1x0
		// XXX add error checks?
		iptables.Ip6tableCmd("-A", "FORWARD", "-i", bridgeName, "-o", "dbo1x0",
			"-j", "DROP")
	}
	return nil
}

// Returns a list of iptables commands, witout the initial "-A FORWARD"
func aclToRules(appNetInfo types.AppNetworkInfo, ACLs []types.ACE) (IptablesRuleList, error) {

	rulesList := IptablesRuleList{}
	log.Debugf("aclToRules(%s, %s, %d, %s, %s, %v\n",
		appNetInfo.BridgeName, appNetInfo.VifName, appNetInfo.IpVer, appNetInfo.BridgeIP, appNetInfo.AppIP, ACLs)

	// XXX should we check isMgmt instead of bridgeIP?
	if appNetInfo.IpVer == 6 && appNetInfo.BridgeIP != "" {
		// Need to allow local communication */
		// Only allow dhcp, dns (tcp/udp), and icmp6/nd
		// Note that sufficient for src or dst to be local
		rule1 := []string{"-i", appNetInfo.BridgeName, "-m", "set", "--match-set",
			"ipv6.local", "dst", "-p", "ipv6-icmp", "-j", "ACCEPT"}
		rule2 := []string{"-i", appNetInfo.BridgeName, "-m", "set", "--match-set",
			"ipv6.local", "src", "-p", "ipv6-icmp", "-j", "ACCEPT"}
		rule3 := []string{"-i", appNetInfo.BridgeName, "-d", appNetInfo.BridgeIP,
			"-p", "ipv6-icmp", "-j", "ACCEPT"}
		rule4 := []string{"-i", appNetInfo.BridgeName, "-s", appNetInfo.BridgeIP,
			"-p", "ipv6-icmp", "-j", "ACCEPT"}
		rulesList = append(rulesList, rule1, rule2, rule3, rule4)
		rule1 = []string{"-i", appNetInfo.BridgeName, "-m", "set", "--match-set",
			"ipv6.local", "dst", "-p", "udp", "--dport", "dhcpv6-server",
			"-j", "ACCEPT"}
		rule2 = []string{"-i", appNetInfo.BridgeName, "-m", "set", "--match-set",
			"ipv6.local", "src", "-p", "udp", "--sport", "dhcpv6-server",
			"-j", "ACCEPT"}
		rule3 = []string{"-i", appNetInfo.BridgeName, "-d", appNetInfo.BridgeIP,
			"-p", "udp", "--dport", "dhcpv6-server", "-j", "ACCEPT"}
		rule4 = []string{"-i", appNetInfo.BridgeName, "-s", appNetInfo.BridgeIP,
			"-p", "udp", "--sport", "dhcpv6-server", "-j", "ACCEPT"}
		rulesList = append(rulesList, rule1, rule2, rule3, rule4)
		rule1 = []string{"-i", appNetInfo.BridgeName, "-d", appNetInfo.BridgeIP,
			"-p", "udp", "--dport", "domain", "-j", "ACCEPT"}
		rule2 = []string{"-i", appNetInfo.BridgeName, "-s", appNetInfo.BridgeIP,
			"-p", "udp", "--sport", "domain", "-j", "ACCEPT"}
		rule3 = []string{"-i", appNetInfo.BridgeName, "-d", appNetInfo.BridgeIP,
			"-p", "tcp", "--dport", "domain", "-j", "ACCEPT"}
		rule4 = []string{"-i", appNetInfo.BridgeName, "-s", appNetInfo.BridgeIP,
			"-p", "tcp", "--sport", "domain", "-j", "ACCEPT"}
		rulesList = append(rulesList, rule1, rule2, rule3, rule4)
	}
	// The same rules as above for IPv4.
	// If we have a bridge service then bridgeIP might be "".
	if appNetInfo.IpVer == 4 && appNetInfo.BridgeIP != "" {
		// Need to allow local communication */
		// Only allow dhcp and dns (tcp/udp)
		// Note that sufficient for src or dst to be local
		rule1 := []string{"-i", appNetInfo.BridgeName, "-m", "set", "--match-set",
			"ipv4.local", "dst", "-p", "udp", "--dport", "bootps",
			"-j", "ACCEPT"}
		rule2 := []string{"-i", appNetInfo.BridgeName, "-m", "set", "--match-set",
			"ipv4.local", "src", "-p", "udp", "--sport", "bootps",
			"-j", "ACCEPT"}
		rule3 := []string{"-i", appNetInfo.BridgeName, "-d", appNetInfo.BridgeIP,
			"-p", "udp", "--dport", "bootps", "-j", "ACCEPT"}
		rule4 := []string{"-i", appNetInfo.BridgeName, "-s", appNetInfo.BridgeIP,
			"-p", "udp", "--sport", "bootps", "-j", "ACCEPT"}
		rulesList = append(rulesList, rule1, rule2, rule3, rule4)
		rule1 = []string{"-i", appNetInfo.BridgeName, "-d", appNetInfo.BridgeIP,
			"-p", "udp", "--dport", "domain", "-j", "ACCEPT"}
		rule2 = []string{"-i", appNetInfo.BridgeName, "-s", appNetInfo.BridgeIP,
			"-p", "udp", "--sport", "domain", "-j", "ACCEPT"}
		rule3 = []string{"-i", appNetInfo.BridgeName, "-d", appNetInfo.BridgeIP,
			"-p", "tcp", "--dport", "domain", "-j", "ACCEPT"}
		rule4 = []string{"-i", appNetInfo.BridgeName, "-s", appNetInfo.BridgeIP,
			"-p", "tcp", "--sport", "domain", "-j", "ACCEPT"}
		rulesList = append(rulesList, rule1, rule2, rule3, rule4)
	}

	for _, ace := range ACLs {
		rules, err := aceToRules(appNetInfo, ace)
		if err != nil {
			return nil, err
		}
		rulesList = append(rulesList, rules...)
	}
	log.Debugf("aclToRules(%s)\n", rulesList)
	return rulesList, nil
}

func aclDropRules(bridgeName, vifName string) (IptablesRuleList, error) {

	log.Debugf("aclDropRules: bridgeName %s, vifName %s\n",
		bridgeName, vifName)

	// Always match on interface. Note that rulesPrefix adds physdev-in
	rulesList := IptablesRuleList{}
	// Implicit drop at the end with log before it
	outArgs1 := []string{"-i", bridgeName, "-j", "LOG", "--log-prefix",
		"FORWARD:FROM:", "--log-level", "3"}
	inArgs1 := []string{"-o", bridgeName, "-j", "LOG", "--log-prefix",
		"FORWARD:TO:", "--log-level", "3"}
	outArgs2 := []string{"-i", bridgeName, "-j", "DROP"}
	inArgs2 := []string{"-o", bridgeName, "-j", "DROP"}
	rulesList = append(rulesList, outArgs1, inArgs1, outArgs2, inArgs2)
	return rulesList, nil
}

func aceToRules(appNetInfo types.AppNetworkInfo, ace types.ACE) (IptablesRuleList, error) {
	rulesList := IptablesRuleList{}

	// Extract lport and protocol from the Matches to use for PortMap
	// Keep others to make sure we put the protocol before the port
	// number(s)
	var ip string
	var ipsetName string
	var protocol string
	var lport string
	var fport string

	// Always match on interface. Note that rulesPrefix adds physdev-in
	inArgs := []string{"-o", appNetInfo.BridgeName}
	outArgs := []string{"-i", appNetInfo.BridgeName}

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
			switch appNetInfo.IpVer {
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
			switch appNetInfo.IpVer {
			case 4:
				ipsetName = "ipv4.eids." + appNetInfo.VifName
			case 6:
				ipsetName = "ipv6.eids." + appNetInfo.VifName
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
			if appNetInfo.AppIP == "" {
				errStr := fmt.Sprintf("PortMap without appIP for lport %s/protocol %s: %+v",
					lport, protocol, ace)
				log.Errorln(errStr)
				return nil, errors.New(errStr)
			}
			targetPort := fmt.Sprintf("%d", action.TargetPort)
			target := fmt.Sprintf("%s:%d", appNetInfo.AppIP, action.TargetPort)
			// These rules are applied on the upLink
			// interfaces and port number.
			// loop through the uplink interfaces
			for _, upLink := range appNetInfo.UpLinks {
				log.Infof("upLink %s\n", upLink)
				// The DNAT/SNAT rules do not compare fport and ipset
				// Make sure packets are returned to zedrouter and not
				// e.g., out a directly attached interface in the domU
				rule1 := []string{"PREROUTING",
					"-i", upLink, "-p", protocol,
					"--dport", lport, "-j", "DNAT",
					"--to-destination", target}
				rule2 := []string{"POSTROUTING",
					"-o", upLink, "-p", protocol,
					"--dport", targetPort, "-j", "SNAT",
					"--to-source", appNetInfo.BridgeIP}
				rulesList = append(rulesList, rule1, rule2)
			}

			// Below we make sure the mapped packets get through
			// Note that port/targetport change relative
			// no normal ACL above.
			outArgs = []string{"-i", appNetInfo.BridgeName}
			inArgs = []string{"-o", appNetInfo.BridgeName}

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
				outArgs = append(outArgs, "-m", "set",
					"--match-set", ipsetName, "dst")
				inArgs = append(inArgs, "-m", "set",
					"--match-set", ipsetName, "src")
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
	rulesList = append(rulesList, outArgs, inArgs)
	if foundLimit {
		// Add separate DROP without the limit to count the excess
		unlimitedOutArgs = append(unlimitedOutArgs,
			[]string{"-j", "DROP"}...)
		unlimitedInArgs = append(unlimitedInArgs,
			[]string{"-j", "DROP"}...)
		log.Debugf("unlimitedOutArgs %v\n", unlimitedOutArgs)
		log.Debugf("unlimitedInArgs %v\n", unlimitedInArgs)
		rulesList = append(rulesList, unlimitedOutArgs, unlimitedInArgs)
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
func rulePrefix(operation string, isMgmt bool, ipVer int, vifName string,
	appIP string, rule IptablesRule) IptablesRule {

	vifName += "+"
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
			prefix = []string{"-t", "raw", operation, "PREROUTING",
				"-m", "physdev", "--physdev-in", vifName}
		} else if rule[0] == "-o" {
			if appIP != "" {
				prefix = []string{operation, "FORWARD",
					"-d", appIP}
			} else {
				prefix = []string{operation, "FORWARD"}
			}
		} else {
			return nil
		}
	} else {
		// Underlay; we have NAT rules and otherwise the same as
		// for IPv6
		if rule[0] == "PREROUTING" || rule[0] == "POSTROUTING" {
			// NAT verbatim rule
			prefix = []string{"-t", "nat", operation}
		} else if rule[0] == "-i" {
			prefix = []string{"-t", "raw", operation, "PREROUTING",
				"-m", "physdev", "--physdev-in", vifName}
		} else if rule[0] == "-o" {
			if appIP != "" {
				prefix = []string{operation, "FORWARD",
					"-d", appIP}
			} else {
				prefix = []string{operation, "FORWARD"}
			}
		} else {
			return nil
		}
	}
	return prefix
}

func equalRule(r1 IptablesRule, r2 IptablesRule) bool {
	if len(r1) != len(r2) {
		return false
	}
	for i := range r1 {
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

func updateACLConfiglet(appNetInfo types.AppNetworkInfo, OldACLs []types.ACE, ACLs []types.ACE) error {

	log.Infof("updateACLConfiglet: bridgeName %s, vifName %s, appIP %s, oldACLs %v newACLs %v\n",
		appNetInfo.BridgeName, appNetInfo.VifName, appNetInfo.AppIP, OldACLs, ACLs)

	appNetInfo.IpVer = determineIpVer(appNetInfo.IsMgmt, appNetInfo.BridgeIP)
	oldRules, err := aclToRules(appNetInfo, OldACLs)
	if err != nil {
		return err
	}

	newRules, err := aclToRules(appNetInfo, ACLs)
	if err != nil {
		return err
	}
	return applyACLUpdate(appNetInfo, oldRules, newRules)
}

func applyACLUpdate(appNetInfo types.AppNetworkInfo, oldRules IptablesRuleList,
	newRules IptablesRuleList) error {

	log.Debugf("applyACLUpdate: isMgmt %v ipVer %d vifName %s appIP %s oldRules %v newRules %v\n",
		appNetInfo.IsMgmt, appNetInfo.IpVer, appNetInfo.VifName,
		appNetInfo.AppIP, oldRules, newRules)

	var err error
	// Look for old which should be deleted
	for _, rule := range oldRules {
		if containsRule(newRules, rule) {
			continue
		}
		log.Debugf("applyACLUpdate: delete rule %v\n", rule)
		args := rulePrefix("-D", appNetInfo.IsMgmt, appNetInfo.IpVer,
			appNetInfo.VifName, appNetInfo.AppIP, rule)
		if args == nil {
			log.Debugf("applyACLUpdate: skipping delete rule %v\n",
				rule)
			continue
		}
		args = append(args, rule...)
		if appNetInfo.IpVer == 4 {
			err = iptables.IptableCmd(args...)
		} else if appNetInfo.IpVer == 6 {
			err = iptables.Ip6tableCmd(args...)
		} else {
			err = errors.New(fmt.Sprintf("ACL: Unknown IP version %d", appNetInfo.IpVer))
		}
		if err != nil {
			return err
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
		log.Debugf("applyACLUpdate: add rule %v\n", rule)
		args := rulePrefix("-I", appNetInfo.IsMgmt, appNetInfo.IpVer,
			appNetInfo.VifName, appNetInfo.AppIP, rule)
		if args == nil {
			log.Debugf("applyACLUpdate: skipping insert rule %v\n",
				rule)
			continue
		}
		args = append(args, rule...)
		if appNetInfo.IpVer == 4 {
			err = iptables.IptableCmd(args...)
		} else if appNetInfo.IpVer == 6 {
			err = iptables.Ip6tableCmd(args...)
		} else {
			err = errors.New(fmt.Sprintf("ACL: Unknown IP version %d", appNetInfo.IpVer))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteACLConfiglet(appNetInfo types.AppNetworkInfo, ACLs []types.ACE) error {

	log.Infof("deleteACLConfiglet: ifname %s vifName %s ACLs %v\n",
		appNetInfo.BridgeName, appNetInfo.VifName, ACLs)

	appNetInfo.IpVer = determineIpVer(appNetInfo.IsMgmt, appNetInfo.BridgeIP)
	rules, err := aclToRules(appNetInfo, ACLs)
	if err != nil {
		return err
	}
	dropRules, err := aclDropRules(appNetInfo.BridgeName, appNetInfo.VifName)
	if err != nil {
		return err
	}
	rules = append(rules, dropRules...)
	for _, rule := range rules {
		log.Debugf("deleteACLConfiglet: rule %v\n", rule)
		args := rulePrefix("-D", appNetInfo.IsMgmt, appNetInfo.IpVer,
			appNetInfo.VifName, appNetInfo.AppIP, rule)
		if args == nil {
			log.Debugf("deleteACLConfiglet: skipping rule %v\n",
				rule)
			continue
		}
		args = append(args, rule...)
		if appNetInfo.IpVer == 4 {
			err = iptables.IptableCmd(args...)
		} else if appNetInfo.IpVer == 6 {
			err = iptables.Ip6tableCmd(args...)
		} else {
			err = errors.New(fmt.Sprintf("ACL: Unknown IP version %d", appNetInfo.IpVer))
		}
		if err != nil {
			return err
		}
	}
	if !appNetInfo.IsMgmt {
		// Remove mangle rules for IPv6 packets added above
		// XXX error checks?
		iptables.Ip6tableCmd("-t", "mangle", "-D", "PREROUTING", "-i", appNetInfo.BridgeName,
			"-p", "tcp", "-j", "CHECKSUM", "--checksum-fill")
		iptables.Ip6tableCmd("-t", "mangle", "-D", "PREROUTING", "-i", appNetInfo.BridgeName,
			"-p", "udp", "-j", "CHECKSUM", "--checksum-fill")
	}
	// XXX see above
	if false && appNetInfo.IpVer == 6 && !appNetInfo.IsMgmt {
		// Manually delete the manual add above
		// XXX error checks?
		iptables.Ip6tableCmd("-D", "FORWARD", "-i", appNetInfo.BridgeName, "-o", "dbo1x0",
			"-j", "DROP")
	}
	return nil
}
