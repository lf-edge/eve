// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// ACL configlet for overlay and underlay interface towards domU

package zedrouter

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// XXX Stop gap allocator copied from zedrouter/appnumallocator.go
// XXX The below ACL id allocation code should get removed when cloud
// starts allocating the ACL id per ACL rule and send to device as part
// of configuration.

// MAXACEID : Keeps 64K bits indexed by 0 to (64K - 1).
const MAXACEID = 65535

// MINACEID : IDs till 100 are reserverd for internal usage.
const MINACEID = 101

var lastAllocatedAceID int32 = -1
var numFreeAceIDs int32 = MAXACEID - MINACEID + 1

// ACLBitmap : size = MAXACEID/8 + 1
type ACLBitmap [MAXACEID/8 + 1]byte

// IsSet : Check if bit at a given index in ACLBitmap byte array is SET to binary 1
func (bits *ACLBitmap) IsSet(i int32) bool { return bits[i/8]&(1<<uint(7-i%8)) != 0 }

// Set : Set bit at a given index in ACLBitmap to binary 1
func (bits *ACLBitmap) Set(i int32) { bits[i/8] |= 1 << uint(7-i%8) }

// Clear : Clears bit at a given index in ACLBitmap
func (bits *ACLBitmap) Clear(i int32) { bits[i/8] &^= 1 << uint(7-i%8) }

// AllocACEId : Bit map array for reserving ACE IDs.
var AllocACEId ACLBitmap

func getNextACEId(candidate int32) int32 {
	if candidate == MAXACEID {
		// wrap around
		return MINACEID
	}
	return (candidate + 1)
}

func allocACEId() int32 {
	if numFreeAceIDs <= 0 {
		log.Errorf("allocACEId: All ACE ids alread allocated")
		return -1
	}
	if lastAllocatedAceID == -1 {
		// This is the first allocation that we are doing.
		AllocACEId.Set(MINACEID)
		lastAllocatedAceID = MINACEID
		numFreeAceIDs--
		return MINACEID
	}

	aclIDSpaceSize := MAXACEID - MINACEID + 1
	candidate := getNextACEId(lastAllocatedAceID)
	for i := 0; i < aclIDSpaceSize; i++ {
		if AllocACEId.IsSet(candidate) {
			// Try the next ID
			candidate = getNextACEId(candidate)
			continue
		}
		AllocACEId.Set(candidate)
		lastAllocatedAceID = candidate
		numFreeAceIDs--
		return candidate
	}
	log.Errorf("allocACEId: ACE id space full")
	return -1
}

func freeACEId(candidate int32) {
	if AllocACEId.IsSet(candidate) {
		if numFreeAceIDs >= (MAXACEID - MINACEID + 1) {
			// All IDs must be free. Nothing to be cleared.
			// Something must have gone terribly wrong.
			log.Errorf("freeACEId: All ACE IDs are already free.")
			return
		}
		AllocACEId.Clear(candidate)
		numFreeAceIDs++
	} else {
		log.Errorf("freeACEId: ID %v was not previously allocated\n", candidate)
	}
}

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

	// the catch all log/drop rules are towards the end of the rule list
	// hance we are inserting the rule in reverse order at
	// the top of a target chain, to ensure the drop rules
	// will be at the end of the rule stack, and the acl match
	// rules will be at the top of the rule stack for an app
	// network instance
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

	var aclRule1, aclRule2, aclRule3, aclRule4, aclRule5 types.IPTablesRule
	aclRule1.IPVer = aclArgs.IPVer
	aclRule2.IPVer = aclArgs.IPVer
	aclRule3.IPVer = aclArgs.IPVer
	aclRule4.IPVer = aclArgs.IPVer
	aclRule5.IPVer = aclArgs.IPVer
	// XXX should we check isMgmt instead of bridgeIP?
	if aclArgs.IPVer == 6 && aclArgs.BridgeIP != "" {
		// Need to allow local communication */
		// Only allow dhcp, dns (tcp/udp), and icmp6/nd
		// Note that sufficient for src or dst to be local
		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv6.local", "dst", "-p", "ipv6-icmp"}
		aclRule1.Action = []string{"-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv6.local", "src", "-p", "ipv6-icmp"}
		aclRule2.Action = []string{"-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d",
			aclArgs.BridgeIP, "-p", "ipv6-icmp"}
		aclRule3.Action = []string{"-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s",
			aclArgs.BridgeIP, "-p", "ipv6-icmp"}
		aclRule4.Action = []string{"-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv6.local", "dst", "-p", "udp", "--dport", "dhcpv6-server"}
		aclRule1.Action = []string{"-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv6.local", "src", "-p", "udp", "--sport", "dhcpv6-server"}
		aclRule2.Action = []string{"-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "udp", "--dport", "dhcpv6-server"}
		aclRule3.Action = []string{"-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "udp", "--sport", "dhcpv6-server"}
		aclRule4.Action = []string{"-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "udp", "--dport", "domain"}
		aclRule1.Action = []string{"-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "udp", "--sport", "domain"}
		aclRule2.Action = []string{"-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "tcp", "--dport", "domain"}
		aclRule3.Action = []string{"-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "tcp", "--sport", "domain"}
		aclRule4.Action = []string{"-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)
	}
	// The same rules as above for IPv4.
	// If we have a bridge service then bridgeIP might be "".
	if aclArgs.IPVer == 4 && aclArgs.BridgeIP != "" {
		// Need to allow local communication */
		// Only allow dhcp and dns (tcp/udp)
		// Note that sufficient for src or dst to be local
		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv4.local", "dst", "-p", "udp", "--dport", "bootps"}
		aclRule1.Action = []string{"-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
			"--match-set", "ipv4.local", "src", "-p", "udp", "--sport", "bootps"}
		aclRule2.Action = []string{"-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "udp", "--dport", "bootps"}
		aclRule3.Action = []string{"-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "udp", "--sport", "bootps"}
		aclRule4.Action = []string{"-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "udp", "--dport", "domain"}
		aclRule1.Action = []string{"-j", "ACCEPT"}
		aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "udp", "--sport", "domain"}
		aclRule2.Action = []string{"-j", "ACCEPT"}
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "tcp", "--dport", "domain"}
		aclRule3.Action = []string{"-j", "ACCEPT"}
		aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", aclArgs.BridgeIP,
			"-p", "tcp", "--sport", "domain"}
		aclRule4.Action = []string{"-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

		aclRule5.Table = "mangle"
		aclRule5.Chain = "PREROUTING"
		aclRule5.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "udp", "-m", "multiport", "--dports", "bootps,domain"}
		chainName := fmt.Sprintf("%s-%s-%d",
			aclArgs.BridgeName, aclArgs.VifName, 6)
		createMarkAndAcceptChain(aclArgs, chainName, 6)
		aclRule5.Action = []string{"-j", chainName}
		aclRule5.ActionChainName = chainName
		rulesList = append(rulesList, aclRule5)

		aclRule5.Rule = []string{"-i", aclArgs.BridgeName, "-d", aclArgs.BridgeIP,
			"-p", "tcp", "--dport", "domain"}
		chainName = fmt.Sprintf("%s-%s-%d",
			aclArgs.BridgeName, aclArgs.VifName, 7)
		createMarkAndAcceptChain(aclArgs, chainName, 7)
		aclRule5.Action = []string{"-j", chainName}
		aclRule5.ActionChainName = chainName
		rulesList = append(rulesList, aclRule5)
	}

	// XXX isMgmt is painful; related to commenting out eidset accepts
	// XXX won't need this when zedmanager is in a separate domU
	// Commenting out for now
	if false && aclArgs.IsMgmt && aclArgs.IPVer == 6 {
		aclRule1.IPVer = 6
		aclRule1.Table = "mangle"
		aclRule1.Chain = "FORWARD"
		aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-o", "dbo1x0"}
		aclRule1.Action = []string{"-j", "DROP"}
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
	aclRule1.Rule = []string{"-i", aclArgs.BridgeName}
	aclRule1.Action = []string{"-j", "LOG", "--log-prefix",
		"FORWARD:FROM:", "--log-level", "3"}
	aclRule2.Rule = []string{"-o", aclArgs.BridgeName}
	aclRule2.Action = []string{"-j", "LOG", "--log-prefix",
		"FORWARD:TO:", "--log-level", "3"}

	// For flow monitoring, we need a rule that marks packet with
	// a reserved drop/reject marking at the end of rule set in mangle table
	// for this application instance.
	switch aclArgs.NIType {
	case types.NetworkInstanceTypeLocal:
		aclRule3.Table = "mangle"
		aclRule3.Chain = "PREROUTING"
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName}
		chainName := fmt.Sprintf("drop-all-%s-%s",
			aclArgs.BridgeName, aclArgs.VifName)
		aclRule3.ActionChainName = chainName
		// XXX Passing 0xffffffff as int32 make golang give overflow error.
		// Instead pass "-1" as the marking value and make createMarkAndAcceptChain
		// handle this case separately.
		marking := (aclArgs.AppNum << 24) | 0xffffff
		createMarkAndAcceptChain(aclArgs, chainName, marking)
		aclRule3.Action = []string{"-j", chainName}
		aclRule3.RuleID = 0xffffff
		aclRule3.IsDefaultDrop = true
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3)
	default:
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName}
		aclRule3.Action = []string{"-j", "DROP"}
		aclRule4.Rule = []string{"-o", aclArgs.BridgeName}
		aclRule4.Action = []string{"-j", "DROP"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)
	}
	return rulesList, nil
}

func aceToRules(aclArgs types.AppNetworkACLArgs, ace types.ACE) (types.IPTablesRuleList,
	error) {
	var rulesList types.IPTablesRuleList

	// Sanity check for old/incorrect controller
	if ace.RuleID == 0 {
		errStr := fmt.Sprintf("ACE with zero RuleID not supported: %+v",
			ace)
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}
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
	inActions := []string{}
	outActions := []string{}

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
				aclRule1.RuleID = ace.RuleID
				aclRule1.ActionChainName = ""
				aclRule1.Rule = []string{"-i", upLink, "-p", protocol,
					"--dport", lport}
				aclRule1.Action = []string{"-j", "DNAT",
					"--to-destination", target}
				aclRule1.IsPortMapRule = true
				aclRule1.IsUserConfigured = true
				rulesList = append(rulesList, aclRule1)

				// XXX Are port map rules only valid for Local network instance?
				// Create a copy of this rule in mangle table to mark/accept
				// port mapping connections from outside.
				if aclRule1.RuleID != -1 {
					aclRule1.Table = "mangle"
					aclRule1.IsMarkingRule = true
					chainName := fmt.Sprintf("%s-%s-%d",
						aclArgs.BridgeName, aclArgs.VifName, aclRule1.RuleID)

					// Embed App id in marking value
					markingValue := (aclArgs.AppNum << 24) | aclRule1.RuleID
					createMarkAndAcceptChain(aclArgs, chainName, markingValue)
					aclRule1.Action = []string{"-j", chainName}
					aclRule1.ActionChainName = chainName
					rulesList = append(rulesList, aclRule1)
				} else {
					log.Errorf("Table: %s, Chain: %s, Rule: %s, Action: %s - cannot be"+
						" programmed due to ACL ID allocation failure",
						aclRule1.Table, aclRule1.Chain, aclRule1.Rule, aclRule1.Action)
				}
			}
			// add the outgoing port-map translation rule to bridge port
			aclRule2.Table = "nat"
			aclRule2.Chain = "POSTROUTING"
			aclRule2.Rule = []string{"-o", aclArgs.BridgeName, "-p", protocol,
				"--dport", targetPort}
			aclRule2.Action = []string{"-j", "SNAT", "--to-source", aclArgs.BridgeIP}
			aclRule2.IsPortMapRule = true
			aclRule2.IsUserConfigured = true
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
			// XXX Port map rule is shown as inbound rule from UI.
			// UI does not provide a way for user to configure ip, fport, ipset
			// matches along with port mapping. Not sure if we will need mangle
			// table for marking these connections.
		}
		if actionCount > 1 {
			errStr := fmt.Sprintf("ACL with combination of Drop, Limit and/or PortMap rejected: %+v",
				ace)
			log.Errorln(errStr)
			return nil, errors.New(errStr)
		}
	}
	if foundDrop {
		outActions = append(outActions, []string{"-j", "DROP"}...)
		inActions = append(inActions, []string{"-j", "DROP"}...)
	} else {
		// Default
		outActions = append(outActions, []string{"-j", "ACCEPT"}...)
		inActions = append(inActions, []string{"-j", "ACCEPT"}...)
	}

	aclRule3.Rule = inArgs
	aclRule3.Action = inActions
	aclRule3.IsUserConfigured = true
	aclRule3.RuleID = ace.RuleID

	aclRule4.Rule = outArgs
	aclRule4.Action = outActions
	aclRule4.RuleID = ace.RuleID
	aclRule4.IsUserConfigured = true
	rulesList = append(rulesList, aclRule4, aclRule3)

	switch aclArgs.NIType {
	case types.NetworkInstanceTypeLocal:
		if aclRule4.RuleID != -1 {
			aclRule4.Table = "mangle"
			aclRule4.Chain = "PREROUTING"
			aclRule4.IsMarkingRule = true
			chainName := fmt.Sprintf("%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, aclRule4.RuleID)

			// Embed App id in marking value
			markingValue := (aclArgs.AppNum << 24) | aclRule4.RuleID
			createMarkAndAcceptChain(aclArgs, chainName, markingValue)
			aclRule4.Action = []string{"-j", chainName}
			aclRule4.ActionChainName = chainName
			rulesList = append(rulesList, aclRule4)
		} else {
			log.Errorf("Table: %s, Chain: %s, Rule: %s, Action: %s - cannot be"+
				" programmed due to ACL ID allocation failure",
				aclRule4.Table, aclRule4.Chain, aclRule4.Rule, aclRule4.Action)
		}
	case types.NetworkInstanceTypeCloud:
		fallthrough
	case types.NetworkInstanceTypeSwitch:
		if aclRule4.RuleID != -1 {
			aclRule4.Table = "mangle"
			aclRule4.Chain = "PREROUTING"
			aclRule4.IsMarkingRule = true
			chainName := fmt.Sprintf("%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, aclRule4.RuleID)

			// Embed App id in marking value
			markingValue := (aclArgs.AppNum << 24) | aclRule4.RuleID
			createMarkAndAcceptChain(aclArgs, chainName, markingValue)
			aclRule4.Action = []string{"-j", chainName}
			aclRule4.ActionChainName = chainName
			rulesList = append(rulesList, aclRule4)
		} else {
			log.Errorf("Table: %s, Chain: %s, Rule: %s, Action: %s - cannot be"+
				" programmed due to ACL ID allocation failure",
				aclRule4.Table, aclRule4.Chain, aclRule4.Rule, aclRule4.Action)
		}

		if aclRule3.RuleID != -1 {
			for _, uplink := range aclArgs.UpLinks {
				aclRule3.Table = "mangle"
				aclRule3.Chain = "PREROUTING"
				if aclArgs.NIType == types.NetworkInstanceTypeSwitch {
					aclRule3.Rule = append(aclRule3.Rule, "-m", "physdev",
						"--physdev-in", uplink)
				}
				aclRule3.IsMarkingRule = true
				chainName := fmt.Sprintf("%s-%s-%d",
					aclArgs.BridgeName, aclArgs.VifName, aclRule3.RuleID)

				// Embed App id in marking value
				markingValue := (aclArgs.AppNum << 24) | aclRule3.RuleID
				createMarkAndAcceptChain(aclArgs, chainName, markingValue)
				aclRule3.Action = []string{"-j", chainName}
				aclRule3.ActionChainName = chainName
				rulesList = append(rulesList, aclRule3)
			}
		} else {
			log.Errorf("Table: %s, Chain: %s, Rule: %s, Action: %s - cannot be"+
				" programmed due to ACL ID allocation failure",
				aclRule3.Table, aclRule3.Chain, aclRule3.Rule, aclRule3.Action)
		}
	default:
	}

	if foundLimit {
		// Add separate DROP without the limit to count the excess
		unlimitedOutActions := []string{"-j", "DROP"}
		unlimitedInActions := []string{"-j", "DROP"}
		log.Debugf("unlimitedOutArgs %v\n", unlimitedOutArgs)
		log.Debugf("unlimitedInArgs %v\n", unlimitedInArgs)
		aclRule5.Rule = unlimitedInArgs
		aclRule5.Action = unlimitedInActions
		aclRule5.IsLimitDropRule = true
		aclRule5.IsUserConfigured = true

		aclRule6.Rule = unlimitedOutArgs
		aclRule6.Action = unlimitedOutActions
		aclRule6.IsLimitDropRule = true
		aclRule6.IsUserConfigured = true
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

		// To monitor flows we install marking rule in mangle table.
		// 1. For packets coming into device from internet we match
		//    on the destination address in PREROUTING mangle instead of
		//    output interface.
		// 2. For the packets originating from App and going to internet
		//    we we have to include the physdev match rule to differentiate
		//    between application instances.
		if rule.Table == "mangle" {
			if rule.Rule[0] == "-o" {
				rule.Rule = rule.Rule[2:]
				if aclArgs.AppIP != "" {
					rule.Prefix = []string{"-d", aclArgs.AppIP}
				}
			} else if rule.Rule[0] == "-i" && !rule.IsPortMapRule {
				rule.Prefix = []string{"-m", "physdev", "--physdev-in", vifName}
			}
		}
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

	// Before adding new rules, clear flows if any created matching the old rules
	var family netlink.InetFamily = syscall.AF_INET
	if aclArgs.IPVer == 4 {
		family = syscall.AF_INET
	} else {
		family = syscall.AF_INET6
	}
	srcIP := net.ParseIP(aclArgs.AppIP)
	mark := uint32(aclArgs.AppNum << 24)
	mask := uint32(0xff << 24)
	number, err := netlink.ConntrackDeleteIPSrc(netlink.ConntrackTable, family,
		srcIP, 0, 0, mark, mask, false)
	if err != nil {
		log.Errorf("updateACLConfiglet: Error clearing flows before update - %s", err)
	} else {
		log.Infof("updateACLConfiglet: Cleared %d flows before updating ACLs for app num %d",
			number, aclArgs.AppNum)
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

// whether the list contains a portmap rule
func containsPortMapACE(ACLs []types.ACE) bool {
	for _, ace := range ACLs {
		for _, action := range ace.Actions {
			if action.PortMap {
				return true
			}
		}
	}
	return false
}

// check for duplicate portmap rules in same set of ACLs
// for this, we will match either the protocol/target port or
// the ingress protocol/lport being same
func matchACLForPortMap(ACLs []types.ACE) bool {
	matchTypes := []string{"protocol"}
	matchTypes1 := []string{"protocol", "lport"}
	idx := 0
	ruleNum := len(ACLs)
	for idx < ruleNum-1 {
		ace := ACLs[idx]
		for _, action := range ace.Actions {
			if !action.PortMap {
				continue
			}
			idx1 := idx + 1
			for idx1 < ruleNum {
				ace1 := ACLs[idx1]
				for _, action1 := range ace1.Actions {
					if !action1.PortMap {
						continue
					}
					// check for protocol/TargetPort
					if action.TargetPort == action1.TargetPort &&
						checkForMatchCondition(ace, ace1, matchTypes) {
						log.Errorf("match found for %d %d: ace %v ace1 %v", idx, idx1, ace, ace1)
						return true
					}
					// check for protocol/lport
					if checkForMatchCondition(ace, ace1, matchTypes1) {
						log.Errorf("match found for %d %d: ace %v ace1 %v", idx, idx1, ace, ace1)
						return true
					}
				}
				idx1++
			}
		}
		idx++
	}
	return false
}

// check for duplicate portmap rules in between two set of ACLs
// for this, we will match the protocol/lport being same
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
					// match for protocol/lport
					if checkForMatchCondition(ace, ace1, matchTypes) {
						log.Errorf("match found for ace %v ace1 %v", ace, ace1)
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
			log.Infof("difference for %d: value %s value1 %s",
				idx, value, value1)
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
	if len(rule.Action) > 0 {
		ruleStr = append(ruleStr, rule.Action...)
	}
	if rule.IPVer == 4 {
		err = iptables.IptableCmd(ruleStr...)
		if operation == "-D" && rule.Table == "mangle" {
			if rule.ActionChainName != "" {
				chainFlush := []string{"-t", "mangle", "--flush", rule.ActionChainName}
				chainDelete := []string{"-t", "mangle", "-X", rule.ActionChainName}
				err = iptables.IptableCmd(chainFlush...)
				if err == nil {
					iptables.IptableCmd(chainDelete...)
				}
			}
		}
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
	// For Network instance, we are going to do a "-A" operation
	// so that, the rules, will at the end of the rule chain
	// for the specific table
	// For App Network ACLs, we are doing "-I" opration, they
	// will be always above these Network Instance log/drop rules.
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

	// XXX To monitor flows (Local/Switch instances) we should
	// add connection tracking rules to mangle table at PREROUTING hook.
	switch aclArgs.NIType {
	case types.NetworkInstanceTypeLocal:
		rules := createFlowMatchRules(aclArgs)
		rulesList = append(rulesList, rules...)
	case types.NetworkInstanceTypeSwitch:
		rules := createFlowMatchRules(aclArgs)
		rulesList = append(rulesList, rules...)
		// XXX May be add the extra matches rules copied from filter FORWARD
	default:
	}

	log.Debugf("bridge(%s, %v) attach iptable rules:%v\n",
		aclArgs.BridgeName, aclArgs.BridgeIP, rulesList)
	return rulesList
}

func createFlowMonDummyInterface(fwmark uint32) {
	// Check if our dummy interface already exits.
	dummyIntfName := "flow-mon-dummy"
	link, err := netlink.LinkByName(dummyIntfName)
	if link != nil {
		log.Infof("createFlowMonDummyInterface: %s already present", dummyIntfName)
		return
	}

	sattrs := netlink.NewLinkAttrs()
	sattrs.Name = dummyIntfName

	// 1280 gives us a comfortable buffer for lisp encapsulation
	sattrs.MTU = 1280
	slink := &netlink.Dummy{LinkAttrs: sattrs}
	if err := netlink.LinkAdd(slink); err != nil {
		errStr := fmt.Sprintf("createFlowMonDummyInterface: LinkAdd on %s failed: %s",
			dummyIntfName, err)
		log.Errorf(errStr)
		return
	}

	// ip link set ${dummy-interface} up
	if err := netlink.LinkSetUp(slink); err != nil {
		errStr := fmt.Sprintf("createFlowMonDummyInterface: LinkSetUp on %s failed: %s",
			dummyIntfName, err)
		log.Errorf(errStr)
		return
	}

	// Turn ARP off on our dummy link
	if err := netlink.LinkSetARPOff(slink); err != nil {
		errStr := fmt.Sprintf("createFlowMonDummyInterface: LinkSetARPOff on %s failed: %s",
			dummyIntfName, err)
		log.Errorf(errStr)
		return
	}

	iifIndex := slink.Attrs().Index
	err = AddFwMarkRuleToDummy(fwmark, iifIndex)
	if err != nil {
		log.Errorf("createFlowMonDummyInterface: FwMark rule for %s failed: %s",
			dummyIntfName, err)
	}
}

func createFlowMatchRules(aclArgs types.AppNetworkACLArgs) types.IPTablesRuleList {
	var rulesList types.IPTablesRuleList
	var aclRule types.IPTablesRule

	// not for dom0
	if aclArgs.IsMgmt {
		return rulesList
	}
	aclArgs.IPVer = determineIPVer(aclArgs.IsMgmt, aclArgs.BridgeIP)
	for _, uplink := range aclArgs.UpLinks {
		aclRule.IPVer = 4
		aclRule.Table = "mangle"
		aclRule.Chain = "PREROUTING"
		aclRule.Rule = []string{"-i", uplink}
		// Restore marking from connection into packet
		aclRule.Action = []string{"-j", "CONNMARK", "--restore-mark"}
		rulesList = append(rulesList, aclRule)

		aclRule.IPVer = 4
		aclRule.Table = "mangle"
		aclRule.Chain = "PREROUTING"
		// Check if packet has non-zero marking and ACCEPT if Yes.
		aclRule.Rule = []string{"-i", uplink, "-m", "mark", "!", "--mark", "0"}
		aclRule.Action = []string{"-j", "ACCEPT"}
		rulesList = append(rulesList, aclRule)

		aclRule.IPVer = 4
		aclRule.Table = "mangle"
		aclRule.Chain = "PREROUTING"
		aclRule.Rule = []string{"-i", uplink}
		// XXX Use 0x00FFFFFF for DROP/REJECT? Might change later.
		// These flows do not match any app instance
		aclRule.Action = []string{"-j", "MARK", "--set-mark", "0x00FFFFFF"}
		rulesList = append(rulesList, aclRule)

		aclRule.IPVer = 4
		aclRule.Table = "mangle"
		aclRule.Chain = "PREROUTING"
		aclRule.Rule = []string{"-i", uplink}
		// Save packet mark into connection
		aclRule.Action = []string{"-j", "CONNMARK", "--save-mark"}
		rulesList = append(rulesList, aclRule)
	}
	return rulesList
}

func createMarkAndAcceptChain(aclArgs types.AppNetworkACLArgs,
	name string, marking int32) error {

	// not for dom0
	if aclArgs.IsMgmt {
		return errors.New("Invalid chain creation")
	}

	newChain := []string{"-t", "mangle", "-N", name}
	log.Infof("createMarkAndAcceptChain: Creating new chain (%s)", name)
	err := iptables.IptableCmd(newChain...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New chain (%s) creation failed: %s",
			name, err)
		return err
	}

	rule1 := []string{"-A", name, "-t", "mangle", "-j", "CONNMARK", "--restore-mark"}
	rule2 := []string{"-A", name, "-t", "mangle", "-m", "mark", "!", "--mark", "0",
		"-j", "ACCEPT"}

	rule3 := []string{}
	if marking == -1 {
		rule3 = []string{"-A", name, "-t", "mangle", "-j", "CONNMARK", "--set-mark",
			"0xffffffff"}
	} else {
		rule3 = []string{"-A", name, "-t", "mangle", "-j", "CONNMARK", "--set-mark",
			strconv.FormatInt(int64(marking), 10)}
	}
	rule4 := []string{"-A", name, "-t", "mangle", "-j", "CONNMARK", "--restore-mark"}
	rule5 := []string{"-A", name, "-t", "mangle", "-j", "ACCEPT"}

	chainFlush := []string{"-t", "mangle", "--flush", name}
	chainDelete := []string{"-t", "mangle", "-X", name}

	err = iptables.IptableCmd(rule1...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule1, err)
		iptables.IptableCmd(chainFlush...)
		iptables.IptableCmd(chainDelete...)
		return err
	}
	err = iptables.IptableCmd(rule2...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule2, err)
		iptables.IptableCmd(chainFlush...)
		iptables.IptableCmd(chainDelete...)
		return err
	}
	err = iptables.IptableCmd(rule3...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule3, err)
		iptables.IptableCmd(chainFlush...)
		iptables.IptableCmd(chainDelete...)
		return err
	}
	err = iptables.IptableCmd(rule4...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule4, err)
		iptables.IptableCmd(chainFlush...)
		iptables.IptableCmd(chainDelete...)
		return err
	}
	err = iptables.IptableCmd(rule5...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule5, err)
		iptables.IptableCmd(chainFlush...)
		iptables.IptableCmd(chainDelete...)
		return err
	}
	return nil
}
