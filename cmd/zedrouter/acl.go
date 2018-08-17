// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// ACL configlet for overlay and underlay interface towards domU

package zedrouter

import (
	"errors"
	"fmt"
	"github.com/zededa/go-provision/cast"
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

func compileOverlayIpsets(ctx *zedrouterContext,
	ollist []types.OverlayNetworkConfig) []string {

	ipsets := []string{}
	for _, olConfig := range ollist {
		netconfig := lookupNetworkObjectConfig(ctx,
			olConfig.Network.String())
		if netconfig != nil {
			// All ipsets from everybody on this network
			ipsets = append(ipsets, compileNetworkIpsetsConfig(ctx,
				netconfig)...)
		} else {
			ipsets = append(ipsets, compileAceIpsets(olConfig.ACLs)...)
		}
	}
	return ipsets
}

func compileUnderlayIpsets(ctx *zedrouterContext,
	ullist []types.UnderlayNetworkConfig) []string {

	ipsets := []string{}
	for _, ulConfig := range ullist {
		netconfig := lookupNetworkObjectConfig(ctx,
			ulConfig.Network.String())
		if netconfig != nil {
			// All ipsets from everybody on this network
			ipsets = append(ipsets, compileNetworkIpsetsConfig(ctx,
				netconfig)...)
		} else {
			ipsets = append(ipsets, compileAceIpsets(ulConfig.ACLs)...)
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

func compileNetworkIpsetsStatus(ctx *zedrouterContext,
	netconfig *types.NetworkObjectConfig) []string {

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
			log.Printf("compileNetworkIpsetsStatus key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
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
	netconfig *types.NetworkObjectConfig) []string {

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
			log.Printf("compileNetworkIpsetsConfig key/UUID mismatch %s vs %s; ignored %+v\n",
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

func compileOldOverlayIpsets(ctx *zedrouterContext,
	ollist []types.OverlayNetworkStatus) []string {

	ipsets := []string{}
	for _, olStatus := range ollist {
		netconfig := lookupNetworkObjectConfig(ctx,
			olStatus.Network.String())
		if netconfig != nil {
			// All ipsets from everybody on this network
			ipsets = append(ipsets, compileNetworkIpsetsStatus(ctx,
				netconfig)...)
		} else {
			ipsets = append(ipsets, compileAceIpsets(olStatus.ACLs)...)
		}
	}
	return ipsets
}

func compileOldUnderlayIpsets(ctx *zedrouterContext,
	ullist []types.UnderlayNetworkStatus) []string {

	ipsets := []string{}
	for _, ulStatus := range ullist {
		netconfig := lookupNetworkObjectConfig(ctx,
			ulStatus.Network.String())
		if netconfig != nil {
			// All ipsets from everybody on this network
			ipsets = append(ipsets, compileNetworkIpsetsStatus(ctx,
				netconfig)...)
		} else {
			ipsets = append(ipsets, compileAceIpsets(ulStatus.ACLs)...)
		}
	}
	return ipsets
}

func compileOldAppInstanceIpsets(ctx *zedrouterContext,
	ollist []types.OverlayNetworkStatus,
	ullist []types.UnderlayNetworkStatus) []string {

	ipsets := []string{}
	ipsets = append(ipsets, compileOldOverlayIpsets(ctx, ollist)...)
	ipsets = append(ipsets, compileOldUnderlayIpsets(ctx, ullist)...)
	return ipsets
}

// XXX old function when the bridge is not shared.
// For a shared bridge call aclToRules for each ifname, then aclDropRules,
// then concat all the rules and pass to applyACLrules
func createACLConfiglet(ifname string, isMgmt bool, ACLs []types.ACE,
	ipVer int, myIP string, appIP string, underlaySshPortMap uint,
	netconfig *types.NetworkObjectConfig) error {
	if debug {
		log.Printf("createACLConfiglet: ifname %s, ACLs %v, IP %s/%s, ssh %d\n",
			ifname, ACLs, myIP, appIP, underlaySshPortMap)
	}
	rules, err := aclToRules(ifname, ACLs, ipVer, myIP, appIP,
		underlaySshPortMap)
	if err != nil {
		return err
	}
	dropRules, err := aclDropRules(ifname)
	if err != nil {
		return err
	}
	rules = append(rules, dropRules...)
	return applyACLRules(rules, ifname, isMgmt, ipVer)
}

func applyACLRules(rules IptablesRuleList, ifname string, isMgmt bool,
	ipVer int) error {

	if debug {
		log.Printf("applyACLRules: ifname %s ipVer %d with %d rules\n",
			ifname, ipVer, len(rules))
	}
	var err error
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
			err = iptableCmd(args...)
		} else if ipVer == 6 {
			err = ip6tableCmd(args...)
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
		// XXX add error checks?
		ip6tableCmd("-A", "FORWARD", "-i", ifname, "-o", "dbo1x0",
			"-j", "DROP")
	}
	return nil
}

// Returns a list of iptables commands, witout the initial "-A FORWARD"
// XXX rename myIP to bridgeIP
// XXX need bridgeName + vifName?
func aclToRules(ifname string, ACLs []types.ACE, ipVer int,
	myIP string, appIP string, underlaySshPortMap uint) (IptablesRuleList, error) {
	rulesList := IptablesRuleList{}

	if debug {
		log.Printf("aclToRules(%s, %v, %d, %s, %s, %d\n",
			ifname, ACLs, ipVer, myIP, appIP, underlaySshPortMap)
	}

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
	// XXX do the same rules as above for IPv4.
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
		rules, err := aceToRules(ifname, ace, ipVer, myIP, appIP)
		if err != nil {
			return nil, err
		}
		rulesList = append(rulesList, rules...)
	}
	return rulesList, nil
}

func aclDropRules(ifname string) (IptablesRuleList, error) {
	if debug {
		log.Printf("aclDropRules: ifname %s\n", ifname)
	}
	rulesList := IptablesRuleList{}
	// Implicit drop at the end with log before it
	outArgs1 := []string{"-i", ifname, "-j", "LOG", "--log-prefix",
		"FORWARD:FROM:", "--log-level", "3"}
	inArgs1 := []string{"-o", ifname, "-j", "LOG", "--log-prefix",
		"FORWARD:TO:", "--log-level", "3"}
	outArgs2 := []string{"-i", ifname, "-j", "DROP"}
	inArgs2 := []string{"-o", ifname, "-j", "DROP"}
	rulesList = append(rulesList, outArgs1, inArgs1, outArgs2, inArgs2)
	return rulesList, nil
}

// XXX Pass uplinkIf as argument? Caller sets if specific interface.
// Handling "uplink" and "freeuplink" is TBD
// XXX could we create/maintain ... some uplink rule
func aceToRules(ifname string, ace types.ACE, ipVer int, myIP string, appIP string) (IptablesRuleList, error) {
	rulesList := IptablesRuleList{}

	// Extract lport and protocol from the Matches to use for PortMap
	// Keep others to make sure we put the protocol before the port
	// number(s)
	var ip string
	var ipsetName string
	var protocol string
	var lport string
	var fport string

	// Always match on interface
	// XXX move to bridge port!
	outArgs := []string{"-i", ifname}
	inArgs := []string{"-o", ifname}

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
			if ipsetName != "" {
				errStr := fmt.Sprintf("ACE with eidset and host not supported: %+v",
					ace)
				log.Println(errStr)
				return nil, errors.New(errStr)
			}
			// Ensure the sets exists; create if not
			// need to feed it into dnsmasq as well; restart
			if err := ipsetCreatePair(match.Value); err != nil {
				log.Println("ipset create for ",
					match.Value, err)
			}
			if ipVer == 4 {
				ipsetName = "ipv4." + match.Value
			} else if ipVer == 6 {
				ipsetName = "ipv6." + match.Value
			}
		case "eidset":
			if ipsetName != "" {
				errStr := fmt.Sprintf("ACE with eidset and host not supported: %+v",
					ace)
				log.Println(errStr)
				return nil, errors.New(errStr)
			}
			// The eidset only applies to IPv6 overlay
			// Caller adds local EID to set
			ipsetName = "eids." + ifname
		default:
			errStr := fmt.Sprintf("Unsupported ACE match type: %s",
				match.Type)
			log.Println(errStr)
			return nil, errors.New(errStr)
		}
	}
	// Consistency checks
	if fport != "" && protocol == "" {
		errStr := fmt.Sprintf("ACE with fport %s and no protocol match: %+v",
			fport, ace)
		log.Println(errStr)
		return nil, errors.New(errStr)
	}
	if lport != "" && protocol == "" {
		errStr := fmt.Sprintf("ACE with lport %s and no protocol match: %+v",
			lport, ace)
		log.Println(errStr)
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
		} else if action.PortMap {
			// Generate NAT and ACCEPT rules based on protocol,
			// lport, and TargetPort
			if lport == "" || protocol == "" {
				errStr := fmt.Sprintf("PortMap without lport %s/protocol %d: %s",
					lport, protocol)
				log.Println(errStr)
				return nil, errors.New(errStr)
			}
			targetPort := fmt.Sprintf("%d", action.TargetPort)
			target := fmt.Sprintf("%s:%d", appIP, action.TargetPort)
			// These rules should only apply on the uplink
			// interfaces but for now we just compare the protocol
			// and port number.
			// The DNAT/SNAT rules do not compare fport and ipset
			rule1 := []string{"PREROUTING",
				"-p", protocol, "--dport", lport,
				"-j", "DNAT", "--to-destination", target}
			// Make sure packets are returned to zedrouter and not
			// e.g., out a directly attached interface in the domU
			rule2 := []string{"POSTROUTING",
				"-p", protocol, "-o", ifname,
				"--dport", targetPort, "-j", "SNAT",
				"--to-source", myIP}
			// Below we make sure the mapped packets get through
			// Note that port/targetport change relative
			// no normal ACL above.
			outArgs = []string{"-i", ifname}
			inArgs = []string{"-o", ifname}
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
			rulesList = append(rulesList, rule1, rule2)
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
		if debug {
			log.Printf("unlimitedOutArgs %v\n", unlimitedOutArgs)
			log.Printf("unlimitedInArgs %v\n", unlimitedInArgs)
		}
		rulesList = append(rulesList, unlimitedOutArgs, unlimitedInArgs)
	}
	if debug {
		log.Printf("rulesList %v\n", rulesList)
	}
	return rulesList, nil
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
			// XXX do same as IPv6
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

func updateAppInstanceIpsets(ctx *zedrouterContext,
	newolConfig []types.OverlayNetworkConfig,
	newulConfig []types.UnderlayNetworkConfig,
	oldolConfig []types.OverlayNetworkStatus,
	oldulConfig []types.UnderlayNetworkStatus) ([]string, []string, bool) {
	staleIpsets := []string{}
	newIpsetMap := make(map[string]bool)
	restartDnsmasq := false

	newIpsets := compileAppInstanceIpsets(ctx, newolConfig, newulConfig)
	oldIpsets := compileOldAppInstanceIpsets(ctx, oldolConfig, oldulConfig)

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

// XXX separate out getNetworkOverlayApps() function?
// Perform an update across all of the bridge aka NetworkObjectStatus
// XXX put ACLs on bridge and revert to old structure with ACLs for each
// AppNetworkConfig. Means we can do the sshPortMap as well.
func updateNetworkACLConfiglet(ctx *zedrouterContext,
	netstatus *types.NetworkObjectStatus, ulStatusArg *types.UnderlayNetworkStatus) error {

	if debug {
		log.Printf("updateNetworkACLConfiglet: ifname %s IP %s\n",
			netstatus.BridgeName, netstatus.BridgeIPAddr)
	}
	newRules := IptablesRuleList{}
	oldRules := IptablesRuleList{}
	ifname := netstatus.BridgeName
	bridgeIPAddr := netstatus.BridgeIPAddr

	pub := ctx.pubAppNetworkStatus
	statusItems := pub.GetAll()
	sub := ctx.subAppNetworkConfig
	configItems := sub.GetAll()

	// Walk overlay/IPv6 first
	ipVer := 6
	for key, st := range statusItems {
		status := cast.CastAppNetworkStatus(st)
		if status.Key() != key {
			log.Printf("updateNetworkACLConfiglet key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		for _, olStatus := range status.OverlayNetworkList {
			if olStatus.Network != netstatus.UUID {
				if debug {
					log.Printf("updateNetworkACLConfiglet different network %s vs %s\n",
						olStatus.Network.String(),
						netstatus.UUID.String())
				}
				continue
			}
			// XXX where can we get olAddr2 := olStatus.AssignedIPv6Addr
			olAddr2 := ""
			rules, err := aclToRules(ifname, olStatus.ACLs, ipVer,
				bridgeIPAddr, olAddr2, 0)
			if err != nil {
				return err
			}
			oldRules = append(oldRules, rules...)
		}
	}
	if len(oldRules) != 0 {
		dropRules, err := aclDropRules(ifname)
		if err != nil {
			return err
		}
		oldRules = append(oldRules, dropRules...)
	}

	for key, c := range configItems {
		config := cast.CastAppNetworkConfig(c)
		if config.Key() != key {
			log.Printf("updateNetworkACLConfiglet key/UUID mismatch %s vs %s; ignored %+v\n",
				key, config.Key(), config)
			continue
		}
		for _, olConfig := range config.OverlayNetworkList {
			if olConfig.Network != netstatus.UUID {
				if debug {
					log.Printf("updateNetworkACLConfiglet different network %s vs %s\n",
						olConfig.Network.String(),
						netstatus.UUID.String())
				}
				continue
			}
			// XXX where can we get olAddr2 := olStatus.AssignedIPv6Addr
			olAddr2 := ""
			rules, err := aclToRules(ifname, olConfig.ACLs, ipVer,
				bridgeIPAddr, olAddr2, 0)
			if err != nil {
				return err
			}
			newRules = append(newRules, rules...)
		}
	}
	if len(newRules) != 0 {
		dropRules, err := aclDropRules(ifname)
		if err != nil {
			return err
		}
		newRules = append(newRules, dropRules...)
	}
	err := applyACLUpdate(false, ipVer, oldRules, newRules)
	if err != nil {
		return nil
	}
	newRules = IptablesRuleList{}
	oldRules = IptablesRuleList{}
	ipVer = 4

	for key, st := range statusItems {
		status := cast.CastAppNetworkStatus(st)
		if status.Key() != key {
			log.Printf("updateNetworkACLConfiglet key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		for _, ulStatus := range status.UnderlayNetworkList {
			if ulStatus.Network != netstatus.UUID {
				if debug {
					log.Printf("updateNetworkACLConfiglet different network %s vs %s\n",
						ulStatus.Network.String(),
						netstatus.UUID.String())
				}
				continue
			}
			var ulAddr2 string
			if ulStatusArg != nil {
				ulAddr2 = ulStatusArg.AssignedIPAddr
			} else {
				ulAddr2 = ulStatus.AssignedIPAddr
			}
			var sshPort uint
			// XXX disable this?
			if false && ulStatus.SshPortMap {
				sshPort = 8022 + 100*uint(status.AppNum)
			}
			rules, err := aclToRules(ifname, ulStatus.ACLs, ipVer,
				bridgeIPAddr, ulAddr2, sshPort)
			if err != nil {
				return err
			}
			oldRules = append(oldRules, rules...)
		}
	}
	if len(oldRules) != 0 {
		dropRules, err := aclDropRules(ifname)
		if err != nil {
			return err
		}
		oldRules = append(oldRules, dropRules...)
	}

	for key, c := range configItems {
		config := cast.CastAppNetworkConfig(c)
		if config.Key() != key {
			log.Printf("updateNetworkACLConfiglet key/UUID mismatch %s vs %s; ignored %+v\n",
				key, config.Key(), config)
			continue
		}
		for ulNum, ulConfig := range config.UnderlayNetworkList {
			if ulConfig.Network != netstatus.UUID {
				if debug {
					log.Printf("updateNetworkACLConfiglet different network %s vs %s\n",
						ulConfig.Network.String(),
						netstatus.UUID.String())
				}
				continue
			}
			// XXX need the new ulAddr2. This is the old. Could it have changed?
			var ulAddr2 string
			if ulStatusArg != nil {
				ulAddr2 = ulStatusArg.AssignedIPAddr
			} else {
				ulAddr2 = getIPAddrFromStatus(statusItems, key, ulNum)
			}
			var sshPort uint
			// XXX disable this?
			if false && ulConfig.SshPortMap {
				status := lookupAppNetworkStatus(ctx, config.Key())
				if status != nil {
					sshPort = 8022 + 100*uint(status.AppNum)
				}
			}
			rules, err := aclToRules(ifname, ulConfig.ACLs, ipVer,
				bridgeIPAddr, ulAddr2, sshPort)
			if err != nil {
				return err
			}
			newRules = append(newRules, rules...)
		}
	}
	if newRules != nil {
		dropRules, err := aclDropRules(ifname)
		if err != nil {
			return err
		}
		newRules = append(newRules, dropRules...)
	}
	return applyACLUpdate(false, ipVer, oldRules, newRules)
}

func getIPAddrFromStatus(statusItems map[string]interface{}, key string,
	ulNum int) string {

	if debug {
		log.Printf("getIPAddrFromStatus(len %d, %s, %d)\n",
			len(statusItems), key, ulNum)
	}
	for _, st := range statusItems {
		status := cast.CastAppNetworkStatus(st)
		if status.Key() != key {
			continue
		}
		if len(status.UnderlayNetworkList) <= ulNum {
			log.Printf("getIPAddrFromStatus: too few uls %d vs %d\n",
				len(status.UnderlayNetworkList), ulNum)
			return ""
		}
		ulStatus := &status.UnderlayNetworkList[ulNum]
		log.Printf("getIPAddrFromStatus: got %s for %s\n",
			ulStatus.AssignedIPAddr, key)
		return ulStatus.AssignedIPAddr
	}
	log.Printf("getIPAddrFromStatus: no matching status for %s\n", key)
	return ""

}

// XXX old update function
// Keep and move to bridge
func updateACLConfiglet(ifname string, isMgmt bool, oldACLs []types.ACE,
	newACLs []types.ACE, ipVer int, myIP string, appIP string,
	underlaySshPortMap uint, netconfig *types.NetworkObjectConfig) error {
	if debug {
		log.Printf("updateACLConfiglet: ifname %s, oldACLs %v newACLs %v\n",
			ifname, oldACLs, newACLs)
	}
	oldRules, err := aclToRules(ifname, oldACLs, ipVer, myIP, appIP,
		underlaySshPortMap)
	if err != nil {
		return err
	}
	newRules, err := aclToRules(ifname, newACLs, ipVer, myIP, appIP,
		underlaySshPortMap)
	if err != nil {
		return err
	}
	return applyACLUpdate(isMgmt, ipVer, oldRules, newRules)
}

func applyACLUpdate(isMgmt bool, ipVer int,
	oldRules IptablesRuleList, newRules IptablesRuleList) error {

	if debug {
		log.Printf("applyACLUpdate: isMgmt %v ipVer %d oldRules %v newRules %v\n",
			isMgmt, ipVer, oldRules, newRules)
	}
	var err error
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
			err = iptableCmd(args...)
		} else if ipVer == 6 {
			err = ip6tableCmd(args...)
		} else {
			err = errors.New(fmt.Sprintf("ACL: Unknown IP version %d", ipVer))
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
			err = iptableCmd(args...)
		} else if ipVer == 6 {
			err = ip6tableCmd(args...)
		} else {
			err = errors.New(fmt.Sprintf("ACL: Unknown IP version %d", ipVer))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteACLConfiglet(ifname string, isMgmt bool, ACLs []types.ACE,
	ipVer int, myIP string, appIP string, underlaySshPortMap uint,
	netconfig *types.NetworkObjectConfig) error {

	if debug {
		log.Printf("deleteACLConfiglet: ifname %s ACLs %v\n",
			ifname, ACLs)
	}
	rules, err := aclToRules(ifname, ACLs, ipVer, myIP, appIP,
		underlaySshPortMap)
	if err != nil {
		return err
	}
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
			err = iptableCmd(args...)
		} else if ipVer == 6 {
			err = ip6tableCmd(args...)
		} else {
			err = errors.New(fmt.Sprintf("ACL: Unknown IP version %d", ipVer))
		}
		if err != nil {
			return err
		}
	}
	if !isMgmt {
		// Remove mangle rules for IPv6 packets added above
		// XXX error checks?
		ip6tableCmd("-t", "mangle", "-D", "PREROUTING", "-i", ifname,
			"-p", "tcp", "-j", "CHECKSUM", "--checksum-fill")
		ip6tableCmd("-t", "mangle", "-D", "PREROUTING", "-i", ifname,
			"-p", "udp", "-j", "CHECKSUM", "--checksum-fill")
	}
	// XXX see above
	if false && ipVer == 6 && !isMgmt {
		// Manually delete the manual add above
		// XXX error checks?
		ip6tableCmd("-D", "FORWARD", "-i", ifname, "-j", "DROP")
	}
	return nil
}
