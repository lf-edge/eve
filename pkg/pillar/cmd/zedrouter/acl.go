// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// ACL configlet for underlay interface towards domU

package zedrouter

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/conntrack"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

// UDPProtocol : UDP protocol match in ACL
const UDPProtocol = "udp"

// XXX Stop gap allocator copied from zedrouter/appnumallocator.go
// XXX The below ACL id allocation code should get removed when cloud
// starts allocating the ACL id per ACL rule and send to device as part
// of configuration.

// MAXACEID : Keeps 64K bits indexed by 0 to (64K - 1).
const MAXACEID = 65535

// MINACEID : IDs till 100 are reserved for internal usage.
const MINACEID = 101

// Dummy interface used as a blackhole for packets marked for dropping by ACLs.
const dummyIntfName = "flow-mon-dummy"

func appChain(chain string) string {
	return chain + iptables.AppChainSuffix
}

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
		log.Errorf("allocACEId: All ACE ids already allocated")
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

// Returns basename (without the "ipvX." prefix) to use for ipset matching
// a given domain name (ACE match of type "host").
// Needs to ensure that the ipset name doesn't exceed the length
// limit of 31 characters imposed by netfilter.
func hostIpsetBasename(hostname string) string {
	maxLen := ipsetNameLenLimit - 5 // leave 5 characters for "ipvX."
	if len(hostname) <= maxLen {
		return hostname
	}
	const (
		// Minimum number of characters the hash should contain
		// to bring the probability of collision down to an acceptable level.
		hashMinLen = 8
		// Separator between a hostname suffix and a hash-generated prefix.
		sep = "#"
	)
	// Function tries to keep some suffix from the original host name
	// (to keep the ipset name human-readable and traceable to its source)
	// and replaces only the remaining subdomains with a hash value.
	labels := strings.Split(hostname, ".")
	var suffixLen, i int
	for i = len(labels); i > 0; i-- {
		if suffixLen+len(labels[i-1])+1+hashMinLen > maxLen {
			break
		}
		suffixLen += len(labels[i-1]) + 1
	}
	labels = labels[i:]
	suffix := strings.Join(labels, ".")
	// Prepend (very likely unique) prefix generated as a BASE64-encoded
	// hash calculated using SHA-256 from the full host name.
	h := sha256.New()
	h.Write([]byte(hostname))
	prefix := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return prefix[:maxLen-1-len(suffix)] + sep + suffix
}

// IpSet routines
// Go through the list of ACEs and create dnsmasq ipset configuration
// lines required for host matches.
// Returns full domain names, even if the corresponding ipsets use names
// shortened by a hash function.
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
	ullist []types.UnderlayNetworkConfig) []string {

	ipsets := []string{}
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
	// walk all app instances to find all which use this network
	sub := ctx.subAppNetworkConfig
	items := sub.GetAll()
	for _, c := range items {
		config := c.(types.AppNetworkConfig)
		if skipKey != "" && config.Key() == skipKey {
			log.Tracef("compileNetworkIpsetsStatus skipping %s\n",
				skipKey)
			continue
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

func compileNetworkIpsetsConfig(ctx *zedrouterContext,
	netconfig *types.NetworkInstanceConfig) []string {

	ipsets := []string{}
	if netconfig == nil {
		return ipsets
	}
	// walk all of netconfig - find all hosts which use this network
	sub := ctx.subAppNetworkConfig
	items := sub.GetAll()
	for _, c := range items {
		config := c.(types.AppNetworkConfig)
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
	ullist []types.UnderlayNetworkStatus, skipKey string) []string {

	ipsets := []string{}
	ipsets = append(ipsets, compileOldUnderlayIpsets(ctx, ullist, skipKey)...)
	return ipsets
}

// Application Network Level ACL rule handling routines

// For a shared bridge call aclToRules for each ifname, then aclDropRules,
// then concat all the rules and pass to applyACLrules
// Note that only bridgeName is set with ifMgmt
func createACLConfiglet(ctx *zedrouterContext, aclArgs types.AppNetworkACLArgs,
	ACLs []types.ACE) (types.IPTablesRuleList, []types.ACLDepend, error) {

	log.Functionf("createACLConfiglet: ifname %s, vifName %s, IP %s/%s, ACLs %v\n",
		aclArgs.BridgeName, aclArgs.VifName, aclArgs.BridgeIP, aclArgs.AppIP, ACLs)
	aclArgs.IPVer = determineIPVer(aclArgs.IsMgmt, aclArgs.BridgeIP)
	rules, depend, err := aclToRules(ctx, aclArgs, ACLs)
	if err != nil {
		return rules, depend, err
	}
	dropRules, err := aclDropRules(aclArgs)
	if err != nil {
		return rules, depend, err
	}
	rules = append(rules, dropRules...)
	rules, err = applyACLRules(aclArgs, rules)
	clearUDPFlows(aclArgs, ACLs)
	return rules, depend, err
}

// This function looks for any UDP port map rules among the ACLs and if so clears
// any only sessions corresponding to them.
func clearUDPFlows(aclArgs types.AppNetworkACLArgs, ACLs []types.ACE) {
	for _, ace := range ACLs {
		var protocol, port string
		for _, match := range ace.Matches {
			switch match.Type {
			case "protocol":
				protocol = match.Value
			case "lport":
				port = match.Value
			}
		}
		if protocol == "" && port != "" {
			// malformed rule.
			continue
		}
		// Not interested in non-UDP sessions
		if protocol != UDPProtocol {
			continue
		}
		for _, action := range ace.Actions {
			if action.PortMap != true {
				continue
			}
			var family netlink.InetFamily = syscall.AF_INET
			if aclArgs.IPVer != 4 {
				family = syscall.AF_INET6
			}
			dport, err := strconv.ParseInt(port, 10, 32)
			if err != nil {
				log.Errorf("clearUDPFlows: Port number %s cannot be parsed to integer", port)
				continue
			}
			targetPort := uint16(action.TargetPort)
			filter := conntrack.PortMapFilter{
				Protocol:     17, // UDP
				ExternalPort: uint16(dport),
				InternalPort: targetPort,
			}
			flowsDeleted, err := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, family, filter)
			if err != nil {
				log.Errorf("clearUDPFlows: Failed clearing UDP flows for lport: %v, target port: %v",
					dport, targetPort)
				continue
			}
			log.Functionf("clearUDPFlows: Cleared %v UDP flows for lport: %v and target port: %v",
				flowsDeleted, dport, targetPort)
		}
	}
}

// If no valid bridgeIP we assume IPv4
func determineIPVer(isMgmt bool, bridgeIP net.IP) int {
	if isMgmt {
		return 6
	}
	if isEmptyIP(bridgeIP) {
		return 4
	}
	if bridgeIP.To4() == nil {
		return 6
	} else {
		return 4
	}
}

func applyACLRules(aclArgs types.AppNetworkACLArgs,
	rules types.IPTablesRuleList) (types.IPTablesRuleList, error) {
	var err error
	var activeRules types.IPTablesRuleList
	log.Tracef("applyACLRules: ipVer %d, bridgeName %s appIP %s with %d rules\n",
		aclArgs.IPVer, aclArgs.BridgeName, aclArgs.AppIP, len(rules))

	// the catch all log/drop rules are towards the end of the rule list
	// hence we are inserting the rule in reverse order at
	// the top of a target chain, to ensure the drop rules
	// will be at the end of the rule stack, and the acl match
	// rules will be at the top of the rule stack for an app
	// network instance
	numRules := len(rules)
	for numRules > 0 {
		numRules--
		rule := rules[numRules]
		log.Tracef("createACLConfiglet: add rule %v\n", rule)
		if err := rulePrefix(aclArgs, &rule); err != nil {
			log.Tracef("createACLConfiglet: skipping rule %v\n", rule)
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

// Returns a list of iptables commands, without the initial "-A FORWARD"
func aclToRules(ctx *zedrouterContext, aclArgs types.AppNetworkACLArgs, ACLs []types.ACE) (types.IPTablesRuleList, []types.ACLDepend, error) {

	var rulesList types.IPTablesRuleList
	var dependList []types.ACLDepend
	log.Tracef("aclToRules(%s, %s, %d, %s, %s, %v\n",
		aclArgs.BridgeName, aclArgs.VifName, aclArgs.IPVer,
		aclArgs.BridgeIP, aclArgs.AppIP, ACLs)

	var aclRule1, aclRule2, aclRule3, aclRule4, aclRule5 types.IPTablesRule
	aclRule1.IPVer = aclArgs.IPVer
	aclRule2.IPVer = aclArgs.IPVer
	aclRule3.IPVer = aclArgs.IPVer
	aclRule4.IPVer = aclArgs.IPVer
	aclRule5.IPVer = aclArgs.IPVer
	var bridgeIP string
	if !isEmptyIP(aclArgs.BridgeIP) {
		bridgeIP = aclArgs.BridgeIP.String()
	}
	// XXX should we check isMgmt instead of bridgeIP?
	if aclArgs.IPVer == 6 {
		if bridgeIP != "" && aclArgs.NIType != types.NetworkInstanceTypeSwitch {
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
				bridgeIP, "-p", "ipv6-icmp"}
			aclRule3.Action = []string{"-j", "ACCEPT"}
			aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s",
				bridgeIP, "-p", "ipv6-icmp"}
			aclRule4.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv6.local", "dst", "-p", "udp", "--dport", "dhcpv6-server"}
			aclRule1.Action = []string{"-j", "ACCEPT"}
			aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv6.local", "src", "-p", "udp", "--sport", "dhcpv6-server"}
			aclRule2.Action = []string{"-j", "ACCEPT"}
			aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", bridgeIP,
				"-p", "udp", "--dport", "dhcpv6-server"}
			aclRule3.Action = []string{"-j", "ACCEPT"}
			aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", bridgeIP,
				"-p", "udp", "--sport", "dhcpv6-server"}
			aclRule4.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-d", bridgeIP,
				"-p", "udp", "--dport", "domain"}
			aclRule1.Action = []string{"-j", "ACCEPT"}
			aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-s", bridgeIP,
				"-p", "udp", "--sport", "domain"}
			aclRule2.Action = []string{"-j", "ACCEPT"}
			aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", bridgeIP,
				"-p", "tcp", "--dport", "domain"}
			aclRule3.Action = []string{"-j", "ACCEPT"}
			aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", bridgeIP,
				"-p", "tcp", "--sport", "domain"}
			aclRule4.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-d", "169.254.169.254",
				"-p", "tcp", "--dport", "http"}
			aclRule1.Action = []string{"-j", "ACCEPT"}
			aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-s", "169.254.169.254",
				"-p", "tcp", "--sport", "http"}
			aclRule2.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2)
		} else if aclArgs.NIType == types.NetworkInstanceTypeSwitch {
			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv6.local", "dst", "-p", "ipv6-icmp"}
			aclRule1.Action = []string{"-j", "ACCEPT"}

			aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv6.local", "src", "-p", "ipv6-icmp"}
			aclRule2.Action = []string{"-j", "ACCEPT"}

			rulesList = append(rulesList, aclRule1, aclRule2)

			// Allow DHCP
			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv6.local", "dst", "-p", "udp", "--dport", "dhcpv6-server"}
			aclRule1.Action = []string{"-j", "ACCEPT"}

			aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv6.local", "src", "-p", "udp", "--sport", "dhcpv6-server"}
			aclRule2.Action = []string{"-j", "ACCEPT"}

			aclRule3.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "udp", "--dport", "dhcpv6-server"}
			aclRule3.Action = []string{"-j", "ACCEPT"}
			aclRule4.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "udp", "--sport", "dhcpv6-server", "-m", "physdev",
				"--physdev-out", aclArgs.VifName}
			aclRule4.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

			// Allow DNS
			aclRule1.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "udp", "--dport", "domain"}
			aclRule1.Action = []string{"-j", "ACCEPT"}

			aclRule2.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "udp", "--sport", "domain", "-m", "physdev",
				"--physdev-out", aclArgs.VifName}
			aclRule2.Action = []string{"-j", "ACCEPT"}

			aclRule3.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "tcp", "--dport", "domain"}
			aclRule3.Action = []string{"-j", "ACCEPT"}

			aclRule4.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "tcp", "--sport", "domain", "-m", "physdev",
				"--physdev-out", aclArgs.VifName}
			aclRule4.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)
			aclRule1.Rule = []string{"-i", aclArgs.BridgeName,
				"-d", "169.254.169.254",
				"-p", "tcp", "--dport", "http"}
			aclRule1.Action = []string{"-j", "ACCEPT"}
			aclRule2.Rule = []string{"-i", aclArgs.BridgeName,
				"-s", "169.254.169.254",
				"-p", "tcp", "--sport", "http"}
			aclRule2.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2)
		}
	}
	// The same rules as above for IPv4.
	// If we have a bridge service then bridgeIP might be "".
	if aclArgs.IPVer == 4 {
		if aclArgs.NIType != types.NetworkInstanceTypeSwitch &&
			bridgeIP != "" {
			// Need to allow local communication */
			// Only allow dhcp and dns (tcp/udp)
			// Note that sufficient for src or dst to be local
			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv4.local", "dst", "-p", "udp", "--dport", "bootps"}
			aclRule1.Action = []string{"-j", "ACCEPT"}
			aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv4.local", "src", "-p", "udp", "--sport", "bootps"}
			aclRule2.Action = []string{"-j", "ACCEPT"}
			aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", bridgeIP,
				"-p", "udp", "--dport", "bootps"}
			aclRule3.Action = []string{"-j", "ACCEPT"}
			aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", bridgeIP,
				"-p", "udp", "--sport", "bootps"}
			aclRule4.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-d", bridgeIP,
				"-p", "udp", "--dport", "domain"}
			aclRule1.Action = []string{"-j", "ACCEPT"}
			aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-s", bridgeIP,
				"-p", "udp", "--sport", "domain"}
			aclRule2.Action = []string{"-j", "ACCEPT"}
			aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-d", bridgeIP,
				"-p", "tcp", "--dport", "domain"}
			aclRule3.Action = []string{"-j", "ACCEPT"}
			aclRule4.Rule = []string{"-i", aclArgs.BridgeName, "-s", bridgeIP,
				"-p", "tcp", "--sport", "domain"}
			aclRule4.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-d", "169.254.169.254",
				"-p", "tcp", "--dport", "http"}
			aclRule1.Action = []string{"-j", "ACCEPT"}
			aclRule2.Rule = []string{"-i", aclArgs.BridgeName, "-s", "169.254.169.254",
				"-p", "tcp", "--sport", "http"}
			aclRule2.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2)

			aclRule5.Table = "mangle"
			aclRule5.Chain = "PREROUTING"
			aclRule5.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "udp", "--dport", "bootps"}
			chainName := fmt.Sprintf("proto-%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, 6)
			createMarkAndAcceptChain(aclArgs, chainName, 6)
			aclRule5.Action = []string{"-j", chainName}
			aclRule5.ActionChainName = chainName
			rulesList = append(rulesList, aclRule5)

			aclRule5.Rule = []string{"-i", aclArgs.BridgeName, "-d", bridgeIP,
				"-p", "udp", "--dport", "domain"}
			chainName = fmt.Sprintf("proto-%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, 7)
			createMarkAndAcceptChain(aclArgs, chainName, 7)
			aclRule5.Action = []string{"-j", chainName}
			aclRule5.ActionChainName = chainName
			rulesList = append(rulesList, aclRule5)

			aclRule5.Rule = []string{"-i", aclArgs.BridgeName, "-d", bridgeIP,
				"-p", "tcp", "--dport", "domain"}
			chainName = fmt.Sprintf("proto-%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, 7)
			aclRule5.Action = []string{"-j", chainName}
			aclRule5.ActionChainName = chainName
			rulesList = append(rulesList, aclRule5)

			aclRule5.Rule = []string{"-i", aclArgs.BridgeName,
				"-d", "169.254.169.254",
				"-p", "tcp", "--dport", "http"}
			chainName = fmt.Sprintf("proto-%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, 8)
			createMarkAndAcceptChain(aclArgs, chainName, 8)
			aclRule5.Action = []string{"-j", chainName}
			aclRule5.ActionChainName = chainName
			rulesList = append(rulesList, aclRule5)
		} else if aclArgs.NIType == types.NetworkInstanceTypeSwitch {
			// Switch network instance case
			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv4.local", "dst", "-p", "udp", "--dport", "bootps"}
			aclRule1.Action = []string{"-j", "ACCEPT"}
			aclRule2.Rule = []string{"-o", aclArgs.BridgeName, "-m", "set",
				"--match-set", "ipv4.local", "src", "-p", "udp", "--sport", "bootps",
				"-m", "physdev", "--physdev-out", aclArgs.VifName}

			aclRule2.Action = []string{"-j", "ACCEPT"}
			aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-p", "udp", "--dport", "bootps"}
			aclRule3.Action = []string{"-j", "ACCEPT"}
			aclRule4.Rule = []string{"-o", aclArgs.BridgeName, "-p", "udp", "--sport", "bootps",
				"-m", "physdev", "--physdev-out", aclArgs.VifName}
			aclRule4.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

			aclRule1.Rule = []string{"-i", aclArgs.BridgeName, "-p", "udp", "--dport", "domain"}
			aclRule1.Action = []string{"-j", "ACCEPT"}
			aclRule2.Rule = []string{"-o", aclArgs.BridgeName, "-p", "udp", "--sport", "domain",
				"-m", "physdev", "--physdev-out", aclArgs.VifName}
			aclRule2.Action = []string{"-j", "ACCEPT"}
			aclRule3.Rule = []string{"-i", aclArgs.BridgeName, "-p", "tcp", "--dport", "domain"}
			aclRule3.Action = []string{"-j", "ACCEPT"}
			aclRule4.Rule = []string{"-o", aclArgs.BridgeName, "-p", "tcp", "--sport", "domain",
				"-m", "physdev", "--physdev-out", aclArgs.VifName}
			aclRule4.Action = []string{"-j", "ACCEPT"}
			rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)

			aclRule5.Table = "mangle"
			aclRule5.Chain = "PREROUTING"
			aclRule5.AnyPhysdev = true
			aclRule5.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "udp", "--dport", "bootps:bootpc"}
			chainName := fmt.Sprintf("proto-%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, 6)
			createMarkAndAcceptChain(aclArgs, chainName, 6)
			aclRule5.Action = []string{"-j", chainName}
			aclRule5.ActionChainName = chainName
			rulesList = append(rulesList, aclRule5)

			aclRule5.AnyPhysdev = false
			aclRule5.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "udp", "--dport", "domain"}
			chainName = fmt.Sprintf("proto-%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, 7)
			createMarkAndAcceptChain(aclArgs, chainName, 7)
			aclRule5.Action = []string{"-j", chainName}
			aclRule5.ActionChainName = chainName
			rulesList = append(rulesList, aclRule5)

			aclRule5.Rule = []string{"-i", aclArgs.BridgeName,
				"-p", "tcp", "--dport", "domain"}
			chainName = fmt.Sprintf("proto-%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, 7)
			aclRule5.Action = []string{"-j", chainName}
			aclRule5.ActionChainName = chainName
			rulesList = append(rulesList, aclRule5)

			aclRule5.Rule = []string{"-i", aclArgs.BridgeName,
				"-d", "169.254.169.254",
				"-p", "tcp", "--dport", "http"}
			chainName = fmt.Sprintf("proto-%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, 8)
			createMarkAndAcceptChain(aclArgs, chainName, 8)
			aclRule5.Action = []string{"-j", chainName}
			aclRule5.ActionChainName = chainName
			rulesList = append(rulesList, aclRule5)
		}
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
		rules, depend, err := aceToRules(ctx, aclArgs, ace)
		if err != nil {
			return nil, nil, err
		}
		rulesList = append(rulesList, rules...)
		dependList = append(dependList, depend...)
	}
	log.Tracef("aclToRules(%v)\n", rulesList)
	return rulesList, dependList, nil
}

func aclDropRules(aclArgs types.AppNetworkACLArgs) (types.IPTablesRuleList, error) {

	var rulesList types.IPTablesRuleList
	var aclRule1, aclRule2, aclRule3, aclRule4 types.IPTablesRule
	aclRule1.IPVer = aclArgs.IPVer
	aclRule2.IPVer = aclArgs.IPVer
	aclRule3.IPVer = aclArgs.IPVer
	aclRule4.IPVer = aclArgs.IPVer

	log.Tracef("aclDropRules: bridgeName %s, vifName %s\n",
		aclArgs.BridgeName, aclArgs.VifName)

	// Always match on interface. Note that rulePrefix adds physdev-in
	// Implicit drop at the end with log before it
	aclRule1.Rule = []string{"-i", aclArgs.BridgeName}
	aclRule1.Action = []string{"-j", "LOG", "--log-prefix",
		"FORWARD:FROM:", "--log-level", "3"}
	aclRule2.Rule = []string{"-o", aclArgs.BridgeName, "-m", "physdev",
		"--physdev-out", aclArgs.VifName}
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
		marking := iptables.GetConnmark(
			uint8(aclArgs.AppNum), iptables.DefaultDropAceID, true)
		createMarkAndAcceptChain(aclArgs, chainName, marking)
		aclRule3.Action = []string{"-j", chainName}
		aclRule3.RuleID = iptables.DefaultDropAceID
		aclRule3.IsDefaultDrop = true
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3)
	default:
		// --prefix-in match is implicitly added for this rule inside
		// rulePrefix function
		aclRule3.Rule = []string{"-i", aclArgs.BridgeName}
		aclRule3.Action = []string{"-j", "DROP"}

		aclRule4.Rule = []string{"-o", aclArgs.BridgeName, "-m", "physdev",
			"--physdev-out", aclArgs.VifName}
		aclRule4.Action = []string{"-j", "DROP"}
		rulesList = append(rulesList, aclRule1, aclRule2, aclRule3, aclRule4)
	}
	return rulesList, nil
}

func aceToRules(ctx *zedrouterContext, aclArgs types.AppNetworkACLArgs,
	ace types.ACE) (types.IPTablesRuleList, []types.ACLDepend, error) {

	var rulesList types.IPTablesRuleList
	var dependList []types.ACLDepend

	// Sanity check for old/incorrect controller
	if ace.RuleID == 0 && !aclArgs.IsMgmt {
		errStr := fmt.Sprintf("ACE with zero RuleID not supported: %+v",
			ace)
		log.Errorln(errStr)
		return nil, nil, errors.New(errStr)
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

	// Always match on interface. Note that rulePrefix adds "-d AppIP".
	inArgs := []string{"-o", aclArgs.BridgeName}
	if aclArgs.NIType == types.NetworkInstanceTypeSwitch {
		inArgs = append(inArgs, "-i", aclArgs.BridgeName)
	}
	// Note that rulePrefix adds physdev-in.
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
			if aclArgs.NIType == types.NetworkInstanceTypeSwitch {
				errStr := fmt.Sprintf("ACE with host not supported on switch network instance: %+v",
					ace)
				log.Errorln(errStr)
				return nil, nil, errors.New(errStr)
			}
			if ipsetName != "" {
				errStr := fmt.Sprintf("ACE with eidset and host not supported: %+v",
					ace)
				log.Errorln(errStr)
				return nil, nil, errors.New(errStr)
			}
			// Ensure the sets exists; create if not
			// need to feed it into dnsmasq as well; restart
			ipsetBasename := hostIpsetBasename(match.Value)
			err := ipsetCreatePair(ipsetBasename, "hash:ip")
			if err != nil {
				log.Errorln("ipset create for ",
					match.Value, err)
			}
			switch aclArgs.IPVer {
			case 4:
				ipsetName = "ipv4." + ipsetBasename
			case 6:
				ipsetName = "ipv6." + ipsetBasename
			}
		case "eidset":
			if aclArgs.NIType == types.NetworkInstanceTypeSwitch {
				errStr := fmt.Sprintf("ACE with host not supported on switch network instance: %+v",
					ace)
				log.Errorln(errStr)
				return nil, nil, errors.New(errStr)
			}
			if ipsetName != "" {
				errStr := fmt.Sprintf("ACE with eidset and host not supported: %+v",
					ace)
				log.Errorln(errStr)
				return nil, nil, errors.New(errStr)
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
			return nil, nil, errors.New(errStr)
		}
	}
	// Consistency checks
	if fport != "" && protocol == "" {
		errStr := fmt.Sprintf("ACE with fport %s and no protocol match: %+v",
			fport, ace)
		log.Errorln(errStr)
		return nil, nil, errors.New(errStr)
	}
	if lport != "" && protocol == "" {
		errStr := fmt.Sprintf("ACE with lport %s and no protocol match: %+v",
			lport, ace)
		log.Errorln(errStr)
		return nil, nil, errors.New(errStr)
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
			if aclArgs.NIType == types.NetworkInstanceTypeSwitch {
				errStr := fmt.Sprintf("PortMap not supported on switch network instance: %+v",
					ace)
				log.Errorln(errStr)
				return nil, nil, errors.New(errStr)
			}
			actionCount += 1
			// Generate NAT and ACCEPT rules based on protocol,
			// lport, and TargetPort
			if lport == "" || protocol == "" {
				errStr := fmt.Sprintf("PortMap without lport %s or protocol %s: %+v",
					lport, protocol, ace)
				log.Errorln(errStr)
				return nil, nil, errors.New(errStr)
			}
			if aclArgs.AppIP == "" {
				errStr := fmt.Sprintf("PortMap without appIP for lport %s/protocol %s: %+v",
					lport, protocol, ace)
				log.Errorln(errStr)
				return nil, nil, errors.New(errStr)
			}
			targetPort := fmt.Sprintf("%d", action.TargetPort)
			target := fmt.Sprintf("%s:%d", aclArgs.AppIP, action.TargetPort)
			// These rules are applied on the upLink interfaces,
			// the uplink IP address, and port number.
			// We add those to the dependList we return
			for _, upLink := range aclArgs.UpLinks {
				log.Tracef("PortMap - upLink %s\n", upLink)

				// Check that we have an IP address on the uplink
				// XXX need to handle multiple with IPv6
				extIPs, err := types.GetLocalAddrList(*ctx.deviceNetworkStatus, upLink)
				if err != nil {
					log.Errorf("Can't add hairpin rule for %s: %v", upLink, err)
					depend := types.ACLDepend{Ifname: upLink}
					dependList = append(dependList, depend)
					continue
				}
				// Pick first IPv4 address
				var extIP net.IP
				for _, ip := range extIPs {
					if ip.To4() != nil {
						extIP = ip
						break
					}
				}
				if len(extIP) == 0 {
					log.Errorf("Can't add hairpin rule for %s: no IPv4 address", upLink)
					depend := types.ACLDepend{Ifname: upLink}
					dependList = append(dependList, depend)
					continue
				}
				depend := types.ACLDepend{
					Ifname: upLink,
					IPAddr: extIP,
				}
				dependList = append(dependList, depend)

				// The DNAT/SNAT rules do not compare fport and ipset
				aclRule1.Table = "nat"
				aclRule1.Chain = "PREROUTING"
				aclRule1.RuleID = ace.RuleID
				aclRule1.ActionChainName = ""
				aclRule1.Rule = []string{"-i", upLink, "-p", protocol,
					"-d", extIP.String(), "--dport", lport}
				aclRule1.Action = []string{"-j", "DNAT",
					"--to-destination", target}
				aclRule1.IsPortMapRule = true
				aclRule1.IsUserConfigured = true
				rulesList = append(rulesList, aclRule1)

				// Create a copy of this rule in mangle table to mark/accept
				// port mapping connections from outside.
				if aclRule1.RuleID != -1 {
					aclRule1.Table = "mangle"
					aclRule1.IsMarkingRule = true
					chainName := fmt.Sprintf("%s-%s-%d",
						aclArgs.BridgeName, aclArgs.VifName, aclRule1.RuleID)

					// Embed App id in marking value
					markingValue := iptables.GetConnmark(
						uint8(aclArgs.AppNum), uint32(aclRule1.RuleID), false)
					createMarkAndAcceptChain(aclArgs, chainName, markingValue)
					aclRule1.Action = []string{"-j", chainName}
					aclRule1.ActionChainName = chainName
					rulesList = append(rulesList, aclRule1)
				} else {
					log.Errorf("Table: %s, Chain: %s, Rule: %s, Action: %s - cannot be"+
						" programmed due to ACL ID allocation failure",
						aclRule1.Table, aclRule1.Chain, aclRule1.Rule, aclRule1.Action)
				}

				// Add a hairpin DNAT rule
				var aclRuleH types.IPTablesRule
				aclRuleH.IPVer = aclArgs.IPVer
				aclRuleH.Table = "nat"
				aclRuleH.Chain = "PREROUTING"
				aclRuleH.RuleID = ace.RuleID
				aclRuleH.ActionChainName = ""
				aclRuleH.Rule = []string{"-i", aclArgs.BridgeName, "-p", protocol,
					"-d", extIP.String(), "--dport", lport}
				aclRuleH.Action = []string{"-j", "DNAT",
					"--to-destination", target}
				aclRuleH.IsPortMapRule = true
				aclRuleH.IsUserConfigured = true
				rulesList = append(rulesList, aclRuleH)

				// Create a copy of this rule in mangle table to mark/accept
				// port mapping connections from other app instances
				if aclRuleH.RuleID != -1 {
					aclRuleH.Table = "mangle"
					aclRuleH.IsMarkingRule = true
					chainName := fmt.Sprintf("%s-%s-%d",
						aclArgs.BridgeName, aclArgs.VifName, aclRuleH.RuleID)

					// Embed App id in marking value
					markingValue := iptables.GetConnmark(
						uint8(aclArgs.AppNum), uint32(aclRuleH.RuleID), false)
					createMarkAndAcceptChain(aclArgs, chainName, markingValue)
					aclRuleH.Action = []string{"-j", chainName}
					aclRuleH.ActionChainName = chainName
					rulesList = append(rulesList, aclRuleH)
				} else {
					log.Errorf("Table: %s, Chain: %s, Rule: %s, Action: %s - cannot be"+
						" programmed due to ACL ID allocation failure",
						aclRuleH.Table, aclRuleH.Chain, aclRuleH.Rule, aclRuleH.Action)
				}
			}

			// add the outgoing port-map translation rule to bridge port
			// to make sure packets are returned to zedrouter and not
			// e.g., out a directly attached interface in the domU
			aclRule2.Table = "nat"
			aclRule2.Chain = "POSTROUTING"
			aclRule2.Rule = []string{"-o", aclArgs.BridgeName, "-p", protocol,
				"--dport", targetPort, "-m", "physdev", "!", "--physdev-is-bridged"}
			aclRule2.Action = []string{"-j", "SNAT", "--to-source", aclArgs.BridgeIP.String()}
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
			return nil, nil, errors.New(errStr)
		}
	}

	aclRule3.Rule = inArgs
	aclRule3.RuleID = ace.RuleID
	aclRule3.IsUserConfigured = true
	if aclArgs.NIType == types.NetworkInstanceTypeSwitch {
		// Applied for filter/FORWARD (not for mangle/PREROUTING)
		aclRule3.Rule = append(aclRule3.Rule, []string{"-m", "physdev",
			"--physdev-out", aclArgs.VifName}...)
	}

	aclRule4.Rule = outArgs
	aclRule4.RuleID = ace.RuleID
	aclRule4.IsUserConfigured = true

	if foundDrop {
		inLog := []string{"-j", "LOG", "--log-prefix",
			"FORWARD:TO:", "--log-level", "3"}
		outLog := []string{"-j", "LOG", "--log-prefix",
			"FORWARD:FROM:", "--log-level", "3"}
		if aclArgs.NIType == types.NetworkInstanceTypeSwitch {
			// Log before dropping packets.
			aclRule3.Action = append(inActions, inLog...)
			aclRule4.Action = append(outActions, outLog...)
			rulesList = append(rulesList, aclRule4, aclRule3)
			// Drop without leaving conntrack (i.e. it will not be flow-logged).
			outActions = append(outActions, []string{"-j", "DROP"}...)
			inActions = append(inActions, []string{"-j", "DROP"}...)
		} else {
			// Local NI.
			// Log but do not drop. Instead, it will be routed to a dummy
			// interface to leave conntrack behind for flow-logging.
			inActions = append(inActions, inLog...)
			outActions = append(outActions, outLog...)
		}
	} else {
		// Default ACE action
		outActions = append(outActions, []string{"-j", "ACCEPT"}...)
		inActions = append(inActions, []string{"-j", "ACCEPT"}...)
	}
	aclRule3.Action = inActions
	aclRule4.Action = outActions
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
			markingValue := iptables.GetConnmark(
				uint8(aclArgs.AppNum), uint32(aclRule4.RuleID), foundDrop)
			createMarkAndAcceptChain(aclArgs, chainName, markingValue)
			aclRule4.Action = []string{"-j", chainName}
			aclRule4.ActionChainName = chainName
			rulesList = append(rulesList, aclRule4)
		} else {
			log.Errorf("Table: %s, Chain: %s, Rule: %s, Action: %s - cannot be"+
				" programmed due to ACL ID allocation failure",
				aclRule4.Table, aclRule4.Chain, aclRule4.Rule, aclRule4.Action)
		}
	case types.NetworkInstanceTypeSwitch:
		if aclRule4.RuleID != -1 {
			aclRule4.Table = "mangle"
			aclRule4.Chain = "PREROUTING"
			aclRule4.IsMarkingRule = true
			chainName := fmt.Sprintf("%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, aclRule4.RuleID)

			// Embed App id in marking value
			markingValue := iptables.GetConnmark(
				uint8(aclArgs.AppNum), uint32(aclRule4.RuleID), foundDrop)
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
			aclRule3.Table = "mangle"
			aclRule3.Chain = "PREROUTING"
			aclRule3.Rule = inArgs
			aclRule3.IsMarkingRule = true
			chainName := fmt.Sprintf("%s-%s-%d",
				aclArgs.BridgeName, aclArgs.VifName, aclRule3.RuleID)

			// Embed App id in marking value
			markingValue := iptables.GetConnmark(uint8(aclArgs.AppNum), uint32(aclRule3.RuleID), foundDrop)
			createMarkAndAcceptChain(aclArgs, chainName, markingValue)
			aclRule3.Action = []string{"-j", chainName}
			aclRule3.ActionChainName = chainName
			rulesList = append(rulesList, aclRule3)
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
		log.Tracef("unlimitedOutArgs %v\n", unlimitedOutArgs)
		log.Tracef("unlimitedInArgs %v\n", unlimitedInArgs)
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
	log.Functionf("rulesList %v, dependList %v", rulesList, dependList)
	return rulesList, dependList, nil
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
			if !rule.AnyPhysdev {
				rule.Prefix = []string{"-m", "physdev", "--physdev-in", vifName}
			}
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
			} else if rule.Rule[0] == "-i" && !rule.IsPortMapRule && !rule.AnyPhysdev {
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
		if !rule.AnyPhysdev {
			rule.Prefix = []string{"-m", "physdev", "--physdev-in", vifName}
		}
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

	// When the ipset did not change, lengths of old and new ipsets should
	// be same and then stale ipsets list should be empty.

	// In case if the ipset has changed but the length remained same, there
	// will at least be one stale entry in the old ipset that needs to be removed.
	if (len(newIpsets) != len(oldIpsets)) || (len(staleIpsets) != 0) {
		restartDnsmasq = true
	}
	log.Functionf("diffIpsets: restart %v, new %v, stale %v",
		restartDnsmasq, newIpsets, staleIpsets)
	return newIpsets, staleIpsets, restartDnsmasq
}

// it will be difficult the maintain the precedence/order of the iptables
// rules, across multiple app instance modules
// apply rules as a block
// lets just delete the existing ACL iptables rules block
// and add the new ACL rules, for the appNetwork.
func updateACLConfiglet(ctx *zedrouterContext, aclArgs types.AppNetworkACLArgs, oldACLs []types.ACE, ACLs []types.ACE,
	oldRules types.IPTablesRuleList, oldDepend []types.ACLDepend, force bool) (types.IPTablesRuleList, []types.ACLDepend, error) {

	log.Functionf("updateACLConfiglet: bridgeName %s, vifName %s, appIP %s\n",
		aclArgs.BridgeName, aclArgs.VifName, aclArgs.AppIP)

	aclArgs.IPVer = determineIPVer(aclArgs.IsMgmt, aclArgs.BridgeIP)
	if !force && compareACLs(oldACLs, ACLs) {
		log.Functionf("updateACLConfiglet: bridgeName %s, vifName %s, appIP %s: no change\n",
			aclArgs.BridgeName, aclArgs.VifName, aclArgs.AppIP)
		return oldRules, oldDepend, nil
	}

	rules, err := deleteACLConfiglet(aclArgs, oldRules)
	if err != nil {
		log.Functionf("updateACLConfiglet: bridgeName %s, vifName %s, appIP %s: delete fail\n",
			aclArgs.BridgeName, aclArgs.VifName, aclArgs.AppIP)
		return rules, nil, err
	}

	rulesList, dependList, err := createACLConfiglet(ctx, aclArgs, ACLs)

	// Before adding new rules, clear flows if any created matching the old rules
	var family netlink.InetFamily = syscall.AF_INET
	if aclArgs.IPVer == 4 {
		family = syscall.AF_INET
	} else {
		family = syscall.AF_INET6
	}
	var srcIP net.IP
	if aclArgs.AppIP == "0.0.0.0" || aclArgs.AppIP == "" {
		srcIP = net.ParseIP("0.0.0.0")
	} else {
		srcIP = net.ParseIP(aclArgs.AppIP)
	}
	if srcIP == nil {
		log.Errorf("updateACLConfiglet: App IP (%s) parse failed", aclArgs.AppIP)
	} else {
		mark := iptables.GetConnmark(uint8(aclArgs.AppNum), 0, false)
		number, err := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, family,
			conntrack.SrcIPFilter{
				Log:      log,
				SrcIP:    srcIP,
				Mark:     mark,
				MarkMask: iptables.AppIDMask})
		if err != nil {
			log.Errorf("updateACLConfiglet: Error clearing flows before update - %s", err)
		} else {
			log.Functionf("updateACLConfiglet: Cleared %d flows before updating ACLs for app num %d",
				number, aclArgs.AppNum)
		}
	}

	return rulesList, dependList, err
}

func deleteACLConfiglet(aclArgs types.AppNetworkACLArgs,
	rules types.IPTablesRuleList) (types.IPTablesRuleList, error) {
	var err error
	var activeRules types.IPTablesRuleList
	log.Functionf("deleteACLConfiglet: ifname %s vifName %s ACLs %v\n",
		aclArgs.BridgeName, aclArgs.VifName, rules)

	for _, rule := range rules {
		log.Tracef("deleteACLConfiglet: rule %v\n", rule)
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

// generic comparison routine for ACL match conditions
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
			log.Functionf("difference for %d: value %s value1 %s",
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
	ruleStr = append(ruleStr, appChain(rule.Chain))
	ruleStr = append(ruleStr, rule.Prefix...)
	ruleStr = append(ruleStr, rule.Rule...)
	if len(rule.Action) > 0 {
		ruleStr = append(ruleStr, rule.Action...)
	}
	if rule.IPVer == 4 {
		err = iptables.IptableCmd(log, ruleStr...)
		if operation == "-D" && rule.Table == "mangle" {
			if rule.ActionChainName != "" {
				chainFlush := []string{"-t", "mangle", "--flush", rule.ActionChainName}
				chainDelete := []string{"-t", "mangle", "-X", rule.ActionChainName}
				err = iptables.IptableCmd(log, chainFlush...)
				if err == nil {
					iptables.IptableCmd(log, chainDelete...)
				}
			}
		}
	} else if rule.IPVer == 6 {
		err = iptables.Ip6tableCmd(log, ruleStr...)
	} else {
		errStr := fmt.Sprintf("ACL: Unknown IP version %d", rule.IPVer)
		err = errors.New(errStr)
	}
	return err
}

func createFlowMonDummyInterface(ctx *zedrouterContext) {
	// Check if our dummy interface already exits.
	_, exists, _ := ctx.networkMonitor.GetInterfaceIndex(dummyIntfName)
	if exists {
		log.Functionf("createFlowMonDummyInterface: %s already present", dummyIntfName)
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
	err := AddFwMarkRuleToDummy(ctx, iifIndex)
	if err != nil {
		log.Errorf("createFlowMonDummyInterface: FwMark rule for %s failed: %s",
			dummyIntfName, err)
	}
}

func createMarkAndAcceptChain(aclArgs types.AppNetworkACLArgs,
	name string, marking uint32) error {

	// not for dom0
	if aclArgs.IsMgmt {
		return errors.New("invalid chain creation")
	}

	chainFlush := []string{"-t", "mangle", "--flush", name}

	newChain := []string{"-t", "mangle", "-N", name}
	log.Functionf("createMarkAndAcceptChain: Creating new chain (%s)", name)
	err := iptables.IptableCmd(log, newChain...)
	if err != nil {
		// if chain already exists, we can skip this error
		if !strings.Contains(err.Error(), "Chain already exists") {
			log.Errorf("createMarkAndAcceptChain: New chain (%s) creation failed: %s",
				name, err)
			return err
		}
		log.Functionf("createMarkAndAcceptChain: Chain (%s) flushing and recreating of rules: %s",
			name, err)
		if err := iptables.IptableCmd(log, chainFlush...); err != nil {
			log.Errorf("createMarkAndAcceptChain: Flush exists chain (%s) failed: %s",
				name, err)
			return err
		}
	}

	rule1 := []string{"-A", name, "-t", "mangle", "-j", "CONNMARK", "--restore-mark"}
	rule2 := []string{"-A", name, "-t", "mangle", "-m", "mark", "!", "--mark", "0",
		"-j", "ACCEPT"}

	rule3 := []string{"-A", name, "-t", "mangle", "-j", "CONNMARK", "--set-mark",
		strconv.FormatUint(uint64(marking), 10)}
	rule4 := []string{"-A", name, "-t", "mangle", "-j", "CONNMARK", "--restore-mark"}
	rule5 := []string{"-A", name, "-t", "mangle", "-j", "ACCEPT"}

	chainDelete := []string{"-t", "mangle", "-X", name}

	err = iptables.IptableCmd(log, rule1...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule1, err)
		iptables.IptableCmd(log, chainFlush...)
		iptables.IptableCmd(log, chainDelete...)
		return err
	}
	err = iptables.IptableCmd(log, rule2...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule2, err)
		iptables.IptableCmd(log, chainFlush...)
		iptables.IptableCmd(log, chainDelete...)
		return err
	}
	err = iptables.IptableCmd(log, rule3...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule3, err)
		iptables.IptableCmd(log, chainFlush...)
		iptables.IptableCmd(log, chainDelete...)
		return err
	}
	err = iptables.IptableCmd(log, rule4...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule4, err)
		iptables.IptableCmd(log, chainFlush...)
		iptables.IptableCmd(log, chainDelete...)
		return err
	}
	err = iptables.IptableCmd(log, rule5...)
	if err != nil {
		log.Errorf("createMarkAndAcceptChain: New rule (%s) creation failed: %s",
			rule5, err)
		iptables.IptableCmd(log, chainFlush...)
		iptables.IptableCmd(log, chainDelete...)
		return err
	}
	return nil
}

// insert or remove the App Container API endpoint blocking ACL
func appConfigContainerStatsACL(appIPAddr net.IP, isRemove bool) {
	var err error
	action := "-I"
	// install or remove the App Container Stats blocking ACL
	// This ACL blocks the other Apps accessing through the same subnet to 'appIPAddr:DOCKERAPIPORT'
	// in TCP protocol, and only allow the Dom0 process to query the App's docker stats
	// - this blocking is only possible in the 'raw' table and 'PREROUTING' chain due to the marking
	//   is done in the 'mangle' of 'PREROUTING'. Install to the front of the 'PREROUTING' list
	// - this blocking ACL does not block the Dom0 access to the above TCP endpoint on the same
	//   subnet. This is due to the IP packets from Dom0 to the internal bridge entering the linux
	//   forwarding through the 'OUTPUT' chain
	// - this blocking does not seem to work if further matching to the '--physdev', so the drop action
	//   needs to be at network layer3
	// - XXX currently the 'drop' mark (0x800000) on the flow of internal traffic on bridge does not work,
	//   later it may be possible to change below '-j DROP' to '-j MARK' action
	if isRemove {
		action = "-D"
		err = iptables.IptableCmd(log, "-t", "raw", action, appChain("PREROUTING"),
			"-d", appIPAddr.String(), "-p", "tcp",
			"--dport", strconv.Itoa(DOCKERAPIPORT), "-j", "DROP")
	} else {
		err = iptables.IptableCmd(log, "-t", "raw", action, appChain("PREROUTING"), "1",
			"-d", appIPAddr.String(), "-p", "tcp",
			"--dport", strconv.Itoa(DOCKERAPIPORT), "-j", "DROP")
	}
	if err != nil {
		log.Errorf("appCheckContainerStatsACL: iptableCmd err %v", err)
	} else {
		log.Functionf("appCheckContainerStatsACL: iptableCmd %s for %s", action, appIPAddr.String())
	}
}

// Install iptables rule to ensure that packets marked with the drop action are indeed dropped and never
// sent out via downlink or uplink interfaces. Whereas routed packets marked by drop ACEs are blackholed into a dummy
// interface using a high-priority IP rule, packets which are only bridged and not routed by EVE escape this IP rule
// and would otherwise continue in their path even if marked for dropping.
func dropEscapedFlows() {
	err := iptables.IptableCmd(log, "-t", "mangle", "-I", appChain("POSTROUTING"),
		"--match", "connmark", "--mark",
		fmt.Sprintf("%d/%d", iptables.AceDropAction, iptables.AceActionMask),
		"!", "-o", dummyIntfName,
		"-j", "DROP")
	if err != nil {
		log.Errorf("dropEscapedFlows: iptableCmd err %v", err)
	}
}
