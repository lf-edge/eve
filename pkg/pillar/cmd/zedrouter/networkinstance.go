// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle NetworkInstance setup

package zedrouter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

// isSharedPortLabel
// port names "uplink" and "freeuplink" are actually built in labels
//	we used for ports used by Dom0 itself to reach the cloud. But
//      these can also be shared by the applications.
func isSharedPortLabel(label string) bool {
	// XXX - I think we can get rid of these built-in labels (uplink/freeuplink).
	//	This will be cleaned up as part of support for deviceConfig
	//	from cloud.
	if strings.EqualFold(label, "uplink") {
		return true
	}
	if strings.EqualFold(label, "freeuplink") {
		return true
	}
	return false
}

// checkPortAvailable
//	A port can be used for NetworkInstance if the following are satisfied:
//	a) Port should be part of Device Port Config
//	b) For type switch, port should not be part of any other
// 			Network Instance
// Any device, which is not a port, cannot be used in network instance
//	and can only be assigned as a directAttach device.
func checkPortAvailable(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("NetworkInstance(%s-%s), logicallabel: %s, currentUplinkIntf: %s",
		status.DisplayName, status.UUID, status.Logicallabel,
		status.CurrentUplinkIntf)

	if status.CurrentUplinkIntf == "" {
		log.Functionf("CurrentUplinkIntf not specified\n")
		return nil
	}

	if isSharedPortLabel(status.CurrentUplinkIntf) {
		return nil
	}
	portStatus := ctx.deviceNetworkStatus.GetPortByIfName(status.CurrentUplinkIntf)
	if portStatus == nil {
		errStr := fmt.Sprintf("PortStatus for %s not found for network instance %s-%s\n",
			status.CurrentUplinkIntf, status.Key(), status.DisplayName)
		return errors.New(errStr)
	}
	return nil
}

func disableIcmpRedirects(bridgeName string) {
	sysctlSetting := fmt.Sprintf("net.ipv4.conf.%s.send_redirects=0", bridgeName)
	args := []string{"-w", sysctlSetting}
	log.Functionf("Calling command %s %v\n", "sysctl", args)
	out, err := base.Exec(log, "sysctl", args...).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("sysctl command %s failed %s output %s",
			args, err, out)
		log.Errorln(errStr)
	}
}

// doCreateBridge
//		returns (error, bridgeMac-string)
func doCreateBridge(bridgeName string, bridgeNum int,
	status *types.NetworkInstanceStatus) (error, string) {

	if !strings.HasPrefix(status.BridgeName, "bn") {
		log.Fatalf("bridgeCreate(%s) %s not possible",
			status.DisplayName, status.BridgeName)
	}
	// Start clean
	// delete the bridge
	attrs := netlink.NewLinkAttrs()
	attrs.Name = bridgeName
	link := &netlink.Bridge{LinkAttrs: attrs}
	netlink.LinkDel(link)

	//    ip link add ${bridgeName} type bridge
	attrs = netlink.NewLinkAttrs()
	attrs.Name = bridgeName
	bridgeMac := fmt.Sprintf("00:16:3e:06:00:%02x", bridgeNum)
	hw, err := net.ParseMAC(bridgeMac)
	if err != nil {
		log.Fatal("ParseMAC failed: ", bridgeMac, err)
	}
	attrs.HardwareAddr = hw
	link = &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(link); err != nil {
		errStr := fmt.Sprintf("LinkAdd on %s failed: %s",
			bridgeName, err)
		return errors.New(errStr), ""
	}
	//    ip link set ${bridgeName} up
	if err := netlink.LinkSetUp(link); err != nil {
		errStr := fmt.Sprintf("LinkSetUp on %s failed: %s",
			bridgeName, err)
		return errors.New(errStr), ""
	}
	disableIcmpRedirects(bridgeName)

	// Get Ifindex of bridge and store it in network instance status
	bridgeLink, err := netlink.LinkByName(bridgeName)
	if err != nil {
		errStr := fmt.Sprintf("doCreateBridge: LinkByName(%s) failed: %s",
			bridgeName, err)
		log.Errorln(errStr)
		return errors.New(errStr), ""
	}
	index := bridgeLink.Attrs().Index
	status.BridgeIfindex = index
	return err, bridgeMac
}

// doLookupBridge is used for switch network instance where nim
// has created the bridge. All such NIs have an external port.
//	returns (bridgeName, bridgeMac-string, error)
func doLookupBridge(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) (string, string, error) {

	ifNameList := getIfNameListForLLOrIfname(ctx, status.Logicallabel)
	if len(ifNameList) == 0 {
		err := fmt.Errorf("doLookupBridge IfNameList empty for %s",
			status.Key())
		log.Error(err)
		return "", "", err
	}
	ifname := ifNameList[0]
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		err = fmt.Errorf("doLookupBridge LinkByName(%s) failed: %v",
			ifname, err)
		log.Error(err)
		return "", "", err
	}
	linkType := link.Type()
	if linkType != "bridge" {
		err = fmt.Errorf("doLookupBridge(%s) not a bridge", ifname)
		log.Error(err)
		return "", "", err
	}
	var macAddrStr string
	macAddr := link.Attrs().HardwareAddr
	if len(macAddr) != 0 {
		macAddrStr = macAddr.String()
	}
	log.Noticef("doLookupBridge found %s, %s", ifname, macAddrStr)
	return ifname, macAddrStr, nil
}

func networkInstanceBridgeDelete(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {
	// Here we explicitly delete the iptables rules which are tied to the Linux bridge
	// itself and not the rules for specific domU vifs.

	aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: status.BridgeName,
		BridgeIP: status.BridgeIPAddr, NIType: status.Type, UpLinks: status.IfNameList}
	handleNetworkInstanceACLConfiglet("-D", aclArgs)

	if !strings.HasPrefix(status.BridgeName, "bn") {
		log.Noticef("networkInstanceBridgeDelete(%s) %s ignored",
			status.DisplayName, status.BridgeName)
	} else {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = status.BridgeName
		link := &netlink.Bridge{LinkAttrs: attrs}
		// Remove link and associated addresses
		netlink.LinkDel(link)
	}

	if status.BridgeNum != 0 {
		status.BridgeName = ""
		status.BridgeNum = 0
		bridgeNumFree(ctx, status.UUID)
	}
}

func doBridgeAclsDelete(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	// Delete ACLs attached to this network aka linux bridge
	items := ctx.pubAppNetworkStatus.GetAll()
	for _, ans := range items {
		appNetStatus := ans.(types.AppNetworkStatus)
		appID := appNetStatus.UUIDandVersion.UUID
		for _, ulStatus := range appNetStatus.UnderlayNetworkList {
			if ulStatus.Network != status.UUID {
				continue
			}
			if ulStatus.Bridge == "" {
				continue
			}
			log.Functionf("NetworkInstance - deleting Acls for UL Interface(%s)",
				ulStatus.Name)
			appIP := ulStatus.AllocatedIPv4Addr
			aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: ulStatus.Bridge,
				VifName: ulStatus.Vif, BridgeIP: ulStatus.BridgeIPAddr, AppIP: appIP,
				UpLinks: status.IfNameList}
			rules := getNetworkACLRules(ctx, appID, ulStatus.Name)
			ruleList, err := deleteACLConfiglet(aclArgs, rules.ACLRules)
			if err != nil {
				log.Errorf("NetworkInstance DeleteACL failed: %s\n",
					err)
			}
			setNetworkACLRules(ctx, appID, ulStatus.Name, ruleList)
		}
	}
	return
}

func getNetworkACLRules(ctx *zedrouterContext, appID uuid.UUID, intf string) types.ULNetworkACLs {
	tmpMap := ctx.NLaclMap[appID]
	if tmpMap == nil {
		ctx.NLaclMap[appID] = make(map[string]types.ULNetworkACLs)
	}

	if _, ok := ctx.NLaclMap[appID][intf]; !ok {
		ctx.NLaclMap[appID][intf] = types.ULNetworkACLs{}
	}
	return ctx.NLaclMap[appID][intf]
}

func setNetworkACLRules(ctx *zedrouterContext, appID uuid.UUID, intf string, rulelist types.IPTablesRuleList) {
	tmpMap := ctx.NLaclMap[appID]
	if tmpMap == nil {
		ctx.NLaclMap[appID] = make(map[string]types.ULNetworkACLs)
	}

	if len(rulelist) == 0 {
		delete(ctx.NLaclMap[appID], intf)
	} else {
		rlist := types.ULNetworkACLs{ACLRules: rulelist}
		ctx.NLaclMap[appID][intf] = rlist
	}
}

func handleNetworkInstanceModify(
	ctxArg interface{},
	key string,
	configArg interface{},
	oldConfigArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	config := configArg.(types.NetworkInstanceConfig)
	status := lookupNetworkInstanceStatus(ctx, key)
	if status != nil {
		log.Functionf("handleNetworkInstanceModify(%s)\n", key)
		status.ChangeInProgress = types.ChangeInProgressTypeModify
		// Any error from parser?
		if config.HasError() {
			log.Errorf("handleNetworkInstanceModify(%s) returning parse error %s",
				key, config.Error)
			status.SetError(config.Error, config.ErrorTime)
			status.ChangeInProgress = types.ChangeInProgressTypeNone
			publishNetworkInstanceStatus(ctx, status)
			log.Functionf("handleNetworkInstanceModify(%s) done\n", key)
			return
		}
		publishNetworkInstanceStatus(ctx, status)
		doNetworkInstanceModify(ctx, config, status)
		niUpdateNIprobing(ctx, status)
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		publishNetworkInstanceStatus(ctx, status)
		log.Functionf("handleNetworkInstanceModify(%s) done\n", key)
	} else {
		log.Fatalf("handleNetworkInstanceModify(%s) no status", key)
	}
}

func handleNetworkInstanceCreate(
	ctxArg interface{},
	key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	config := configArg.(types.NetworkInstanceConfig)

	log.Functionf("handleNetworkInstanceCreate: (UUID: %s, name:%s)\n",
		key, config.DisplayName)

	status := types.NetworkInstanceStatus{
		NetworkInstanceConfig: config,
		NetworkInstanceInfo: types.NetworkInstanceInfo{
			IPAssignments: make(map[string]types.AssignedAddrs),
			VifMetricMap:  make(map[string]types.NetworkMetric),
			VlanMap:       make(map[uint32]uint32),
		},
	}
	appNumOnUNetBaseCreate(status.UUID)
	status.ChangeInProgress = types.ChangeInProgressTypeCreate

	// Any error from parser?
	if config.HasError() {
		log.Errorf("handleNetworkInstanceCreate(%s) returning parse error %s",
			key, config.Error)
		status.SetError(config.Error, config.ErrorTime)
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		publishNetworkInstanceStatus(ctx, &status)
		log.Functionf("handleNetworkInstanceCreate(%s) done\n", key)
		return
	}

	ctx.networkInstanceStatusMap.Store(status.UUID, &status)
	publishNetworkInstanceStatus(ctx, &status)

	status.PInfo = make(map[string]types.ProbeInfo)
	niUpdateNIprobing(ctx, &status)

	err := doNetworkInstanceCreate(ctx, &status)
	if err != nil {
		log.Errorf("doNetworkInstanceCreate(%s) failed: %s\n",
			key, err)
		log.Error(err)
		status.SetErrorNow(err.Error())
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		publishNetworkInstanceStatus(ctx, &status)
		return
	}
	publishNetworkInstanceStatus(ctx, &status)

	if config.Activate {
		log.Functionf("handleNetworkInstanceCreate: Activating network instance")
		err := doNetworkInstanceActivate(ctx, &status)
		if err != nil {
			log.Errorf("doNetworkInstanceActivate(%s) failed: %s\n", key, err)
			log.Error(err)
			status.SetErrorNow(err.Error())
		} else {
			log.Functionf("Activated network instance %s %s", status.UUID, status.DisplayName)
			status.Activated = true
		}
	}

	status.ChangeInProgress = types.ChangeInProgressTypeNone
	publishNetworkInstanceStatus(ctx, &status)
	// Hooks for updating dependent objects
	checkAndRecreateAppNetwork(ctx, status)
	log.Functionf("handleNetworkInstanceCreate(%s) done\n", key)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleNetworkInstanceDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkInstanceStatus
	status := lookupNetworkInstanceStatus(ctx, key)
	if status == nil {
		log.Functionf("handleNetworkInstanceDelete: unknown %s\n", key)
		return
	}
	status.ChangeInProgress = types.ChangeInProgressTypeDelete
	pub.Publish(status.Key(), *status)
	if status.Activated {
		doNetworkInstanceInactivate(ctx, status)
		status.Activated = false
		publishNetworkInstanceStatus(ctx, status)
	}
	done := maybeNetworkInstanceDelete(ctx, status)
	log.Functionf("handleNetworkInstanceDelete(%s) done %t", key, done)
}

// maybeNetworkInstanceDelete checks if the Vifs are gone and if so delete
func maybeNetworkInstanceDelete(ctx *zedrouterContext, status *types.NetworkInstanceStatus) bool {
	if lookupNetworkInstanceConfig(ctx, status.Key()) != nil {
		log.Noticef("maybeNetworkInstanceDelete(%s) still config",
			status.Key())
		return false
	}

	// Any remaining appNumOnUNet references?
	count := appNumOnUNetRefCount(ctx, status.UUID)
	log.Noticef("maybeNetworkInstanceDelete(%s) refcount %d Vifs: %+v",
		status.Key(), count, status.Vifs)
	if count != 0 {
		return false
	}
	doNetworkInstanceDelete(ctx, status)
	ctx.networkInstanceStatusMap.Delete(status.UUID)
	ctx.pubNetworkInstanceStatus.Unpublish(status.Key())

	deleteNetworkInstanceMetrics(ctx, status.Key())
	log.Noticef("maybeNetworkInstanceDelete(%s) done", status.Key())
	return true
}

func doNetworkInstanceCreate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("NetworkInstance(%s-%s): NetworkType: %d, IpType: %d\n",
		status.DisplayName, status.Key(), status.Type, status.IpType)

	if err := doNetworkInstanceSanityCheck(ctx, status); err != nil {
		log.Errorf("NetworkInstance(%s-%s): Sanity Check failed: %s",
			status.DisplayName, status.Key(), err)
		return err
	}

	// Allocate bridgeNum.
	bridgeNum := bridgeNumAllocate(ctx, status.UUID)
	status.BridgeNum = bridgeNum
	bridgeMac := ""
	var bridgeName string
	var err error

	switch status.Type {
	case types.NetworkInstanceTypeLocal, types.NetworkInstanceTypeCloud:
		bridgeName = fmt.Sprintf("bn%d", bridgeNum)
		status.BridgeName = bridgeName
		if err, bridgeMac = doCreateBridge(bridgeName, bridgeNum, status); err != nil {
			return err
		}

	case types.NetworkInstanceTypeSwitch:
		if status.CurrentUplinkIntf == "" {
			// Create a local-only bridge
			bridgeName = fmt.Sprintf("bn%d", bridgeNum)
			status.BridgeName = bridgeName
			if err, bridgeMac = doCreateBridge(bridgeName, bridgeNum, status); err != nil {
				return err
			}
		} else {
			// Find bridge created by nim
			if bridgeName, bridgeMac, err = doLookupBridge(ctx, status); err != nil {
				// We will retry later
				return err
			}
			status.BridgeName = bridgeName
		}
	}

	// Get Ifindex of bridge and store it in network instance status
	bridgeLink, err := netlink.LinkByName(bridgeName)
	if err != nil {
		err = fmt.Errorf("doNetworkInstanceCreate: LinkByName(%s) failed: %v",
			bridgeName, err)
		log.Error(err)
		return err
	}
	status.BridgeIfindex = bridgeLink.Attrs().Index

	status.BridgeMac = bridgeMac
	publishNetworkInstanceStatus(ctx, status)

	log.Functionf("bridge created. BridgeMac: %s\n", bridgeMac)

	if err := setBridgeIPAddr(ctx, status); err != nil {
		return err
	}
	log.Functionf("IpAddress set for bridge\n")

	// Create a hosts directory for the new bridge
	// Directory is /run/zedrouter/hosts.${BRIDGENAME}
	hostsDirpath := runDirname + "/hosts." + bridgeName
	deleteHostsConfiglet(hostsDirpath, false)
	createHostsConfiglet(hostsDirpath,
		status.DnsNameToIPList)

	if status.BridgeIPAddr != "" {
		// XXX arbitrary name "router"!!
		addToHostsConfiglet(hostsDirpath, "router",
			[]string{status.BridgeIPAddr})
	}

	// Start clean
	deleteDnsmasqConfiglet(bridgeName)
	stopDnsmasq(bridgeName, false, false)

	if status.BridgeIPAddr != "" {
		dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
			status.CurrentUplinkIntf)
		ntpServers := types.GetNTPServers(*ctx.deviceNetworkStatus,
			status.CurrentUplinkIntf)
		createDnsmasqConfiglet(ctx, bridgeName,
			status.BridgeIPAddr, status,
			hostsDirpath, status.BridgeIPSets,
			status.CurrentUplinkIntf, dnsServers, ntpServers)
		startDnsmasq(bridgeName)
	}

	// monitor the DNS and DHCP information
	log.Functionf("Creating %s at %s", "DNSDhcpMonitor", agentlog.GetMyStack())
	go DNSDhcpMonitor(bridgeName, bridgeNum, ctx, status)

	if status.IsIPv6() {
		// XXX do we need same logic as for IPv4 dnsmasq to not
		// advertize as default router? Might we need lower
		// radvd preference if isolated local network?
		restartRadvdWithNewConfig(bridgeName)
	}

	switch status.Type {
	case types.NetworkInstanceTypeCloud:
		err := vpnCreate(ctx, status)
		if err != nil {
			return err
		}
	default:
	}
	return nil
}

func doNetworkInstanceSanityCheck(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("Sanity Checking NetworkInstance(%s-%s): type:%d, IpType:%d\n",
		status.DisplayName, status.UUID, status.Type, status.IpType)

	err := checkNIphysicalPort(ctx, status)
	if err != nil {
		log.Error(err)
		return err
	}

	//  Check NetworkInstanceType
	switch status.Type {
	case types.NetworkInstanceTypeLocal:
		// Do nothing
	case types.NetworkInstanceTypeSwitch:
		// Do nothing
	case types.NetworkInstanceTypeCloud:
		// Do nothing
	default:
		err := fmt.Sprintf("Instance type %d not supported", status.Type)
		return errors.New(err)
	}

	if status.Logicallabel != "" {
		if err := checkPortAvailable(ctx, status); err != nil {
			log.Errorf("checkPortAvailable failed: Port: %s, err:%s",
				status.CurrentUplinkIntf, err)
			return err
		}
	}

	// IpType - Check for valid types
	switch status.IpType {
	case types.AddressTypeNone:
		// Do nothing
	case types.AddressTypeIPV4, types.AddressTypeIPV6,
		types.AddressTypeCryptoIPV4, types.AddressTypeCryptoIPV6:

		err := doNetworkInstanceSubnetSanityCheck(ctx, status)
		if err != nil {
			return err
		}

		if status.Gateway.IsUnspecified() {
			err := fmt.Sprintf("Gateway Unspecified: %+v\n",
				status.Gateway)
			return errors.New(err)
		}
		err = doNetworkInstanceStatusDhcpRangeSanityCheck(status)
		if err != nil {
			return err
		}

	default:
		err := fmt.Sprintf("IpType %d not supported\n", status.IpType)
		return errors.New(err)
	}

	return nil
}

func doNetworkInstanceSubnetSanityCheck(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	// Mesh network instance with crypto V6 addressing will not need any
	// subnet specific configuration
	if (status.Subnet.IP == nil || status.Subnet.IP.IsUnspecified()) &&
		(status.IpType != types.AddressTypeCryptoIPV6) {
		err := fmt.Sprintf("Subnet Unspecified for %s-%s: %+v\n",
			status.Key(), status.DisplayName, status.Subnet)
		return errors.New(err)
	}

	var err error
	ctx.networkInstanceStatusMap.Range(func(key, value interface{}) bool {
		iterStatusEntry := value.(*types.NetworkInstanceStatus)
		if status == iterStatusEntry {
			return true
		}

		// We check for overlapping subnets by checking the
		// SubnetAddr ( first address ) is not contained in the subnet of
		// any other NI and vice-versa ( Other NI Subnet addrs are not
		// contained in the current NI subnet)

		// Check if status.Subnet is contained in iterStatusEntry.Subnet
		if iterStatusEntry.Subnet.Contains(status.Subnet.IP) {
			errStr := fmt.Sprintf("Subnet(%s) SubnetAddr(%s) overlaps with another "+
				"network instance(%s-%s) Subnet(%s)\n",
				status.Subnet.String(), status.Subnet.IP.String(),
				iterStatusEntry.DisplayName, iterStatusEntry.UUID,
				iterStatusEntry.Subnet.String())
			err = errors.New(errStr)
			return false
		}

		// Reverse check..Check if iterStatusEntry.Subnet is contained in status.subnet
		if status.Subnet.Contains(iterStatusEntry.Subnet.IP) {
			errStr := fmt.Sprintf("Another network instance(%s-%s) Subnet(%s) "+
				"overlaps with Subnet(%s)",
				iterStatusEntry.DisplayName, iterStatusEntry.UUID,
				iterStatusEntry.Subnet.String(),
				status.Subnet.String())
			err = errors.New(errStr)
			return false
		}
		return true
	})
	return err
}

// doNetworkInstanceStatusDhcpRangeSanityCheck
// 1) Must always be Unspecified
// 2) It should be a subset of Subnet
func doNetworkInstanceStatusDhcpRangeSanityCheck(
	status *types.NetworkInstanceStatus) error {
	// For Mesh type network instance with Crypto V6 addressing, no dhcp-range
	// will be specified.
	if status.DhcpRange.Start == nil || status.DhcpRange.Start.IsUnspecified() {
		err := fmt.Sprintf("DhcpRange Start Unspecified: %+v\n",
			status.DhcpRange.Start)
		return errors.New(err)
	}
	if !status.Subnet.Contains(status.DhcpRange.Start) {
		err := fmt.Sprintf("DhcpRange Start(%s) not within Subnet(%s)\n",
			status.DhcpRange.Start.String(), status.Subnet.String())
		return errors.New(err)
	}
	if status.DhcpRange.End == nil || status.DhcpRange.End.IsUnspecified() {
		err := fmt.Sprintf("DhcpRange End Unspecified: %+v\n",
			status.DhcpRange.Start)
		return errors.New(err)
	}
	if !status.Subnet.Contains(status.DhcpRange.End) {
		err := fmt.Sprintf("DhcpRange End(%s) not within Subnet(%s)\n",
			status.DhcpRange.End.String(), status.Subnet.String())
		return errors.New(err)
	}
	return nil
}

func doNetworkInstanceModify(ctx *zedrouterContext,
	config types.NetworkInstanceConfig,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("doNetworkInstanceModify: key %s\n", config.UUID)
	if config.Type != status.Type {
		log.Functionf("doNetworkInstanceModify: key %s\n", config.UUID)
		// We do not allow Type to change.

		err := fmt.Errorf("Changing Type of NetworkInstance from %d to %d is not supported", status.Type, config.Type)
		log.Error(err)
		status.SetErrorNow(err.Error())
		return err
	}

	err := checkNIphysicalPort(ctx, status)
	if err != nil {
		log.Error(err)
		status.SetErrorNow(err.Error())
		return err
	}

	if config.Logicallabel != status.Logicallabel {
		err := fmt.Errorf("Changing Logicallabel in NetworkInstance is not yet supported: from %s to %s",
			status.Logicallabel, config.Logicallabel)
		log.Error(err)
		status.SetErrorNow(err.Error())
		return err
	}

	if config.Activate && !status.Activated {
		err := doNetworkInstanceActivate(ctx, status)
		if err != nil {
			log.Errorf("doNetworkInstanceActivate(%s) failed: %s\n",
				config.Key(), err)
			log.Error(err)
			status.SetErrorNow(err.Error())
			return err
		}
		status.Activated = true
	} else if status.Activated && !config.Activate {
		doNetworkInstanceInactivate(ctx, status)
		status.Activated = false
	}
	return nil
}

func checkNIphysicalPort(ctx *zedrouterContext, status *types.NetworkInstanceStatus) error {
	// check the NI have the valid physical port binding to
	label := status.Logicallabel
	if label != "" && !strings.EqualFold(label, "uplink") &&
		!strings.EqualFold(label, "freeuplink") {
		ifname := types.LogicallabelToIfName(ctx.deviceNetworkStatus, label)
		devPort := ctx.deviceNetworkStatus.GetPortByIfName(ifname)
		if devPort == nil {
			err := fmt.Sprintf("Network Instance port %s ifname %s does not exist", label, ifname)
			return errors.New(err)
		}
	}
	return nil
}

// getSwitchNetworkInstanceListByIfname returns all
// network instances of type SWITCH using the ifname
func getSwitchNetworkInstanceListByIfname(
	ctx *zedrouterContext,
	ifname string) (statusList []*types.NetworkInstanceStatus) {

	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()

	for _, st := range items {
		status := st.(types.NetworkInstanceStatus)
		ifname2 := types.LogicallabelToIfName(ctx.deviceNetworkStatus,
			status.Logicallabel)
		if ifname2 != ifname {
			log.Functionf("getSwitchNetworkInstanceListByIfname: NI (%s) not using %s; using %s",
				status.DisplayName, ifname, ifname2)
			continue
		}

		if status.Type != types.NetworkInstanceTypeSwitch {
			log.Functionf("getSwitchNetworkInstanceListByIfname: networkInstance (%s) "+
				"not of type (%d) switch\n",
				status.DisplayName, status.Type)
			continue
		}
		// Found Status using the Port.
		log.Functionf("getSwitchNetworkInstanceListByIfname: networkInstance (%s) using "+
			"logicallabel: %s, ifname: %s, type: %d\n",
			status.DisplayName, status.Logicallabel, ifname, status.Type)

		statusList = append(statusList, &status)
	}
	return statusList
}

// haveSwitchNetworkInstances returns true if we have one or more switch
// network instances
func haveSwitchNetworkInstances(ctx *zedrouterContext) bool {
	sub := ctx.subNetworkInstanceConfig
	items := sub.GetAll()

	for _, c := range items {
		config := c.(types.NetworkInstanceConfig)
		if config.Type == types.NetworkInstanceTypeSwitch {
			return true
		}
	}
	return false
}

func restartDnsmasq(ctx *zedrouterContext, status *types.NetworkInstanceStatus) {

	log.Functionf("restartDnsmasq(%s) ipsets %v\n",
		status.BridgeName, status.BridgeIPSets)
	bridgeName := status.BridgeName
	stopDnsmasq(bridgeName, false, true)

	hostsDirpath := runDirname + "/hosts." + bridgeName
	// XXX arbitrary name "router"!!
	addToHostsConfiglet(hostsDirpath, "router",
		[]string{status.BridgeIPAddr})

	// Use existing BridgeIPSets
	dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
		status.CurrentUplinkIntf)
	ntpServers := types.GetNTPServers(*ctx.deviceNetworkStatus,
		status.CurrentUplinkIntf)
	createDnsmasqConfiglet(ctx, bridgeName, status.BridgeIPAddr,
		status, hostsDirpath, status.BridgeIPSets,
		status.CurrentUplinkIntf, dnsServers, ntpServers)
	createHostDnsmasqFile(ctx, bridgeName)
	startDnsmasq(bridgeName)
}

func createHostDnsmasqFile(ctx *zedrouterContext, bridge string) {
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		for _, ulStatus := range status.UnderlayNetworkList {
			if strings.Compare(bridge, ulStatus.Bridge) != 0 {
				continue
			}
			addhostDnsmasq(bridge, ulStatus.Mac,
				ulStatus.AllocatedIPv4Addr, status.UUIDandVersion.UUID.String())
			log.Functionf("createHostDnsmasqFile:(%s) mac=%s, IP=%s\n", bridge, ulStatus.Mac, ulStatus.AllocatedIPv4Addr)
		}
	}
}

// Returns an IP address as a string, or "" for switch networks or, on error
func lookupOrAllocateIPv4(status *types.NetworkInstanceStatus,
	appID uuid.UUID, appNum int, mac net.HardwareAddr) (string, error) {
	log.Functionf("lookupOrAllocateIPv4(%s-%s): appNum:%d\n",
		status.DisplayName, status.Key(), appNum)

	log.Functionf("lookupOrAllocateIPv4(%s-%s): mac:%s\n",
		status.DisplayName, status.Key(), mac.String())
	// Lookup to see if it exists
	if addrs, ok := status.IPAssignments[mac.String()]; ok {
		log.Functionf("found Ip addr ( %s) for mac(%s)\n",
			addrs.IPv4Addr, mac.String())
		if !isEmptyIP(addrs.IPv4Addr) {
			return addrs.IPv4Addr.String(), nil
		}
	}
	if status.DhcpRange.Start == nil {
		if status.Type == types.NetworkInstanceTypeSwitch {
			log.Functionf("%s-%s switch means no IPAddr",
				status.DisplayName, status.Key())
			return "", nil
		}
		log.Fatalf("%s-%s: nil DhcpRange.Start",
			status.DisplayName, status.Key())
	}

	// get ip address
	a := types.AddToIP(status.DhcpRange.Start, appNum)

	networkID := status.UUID
	// the address does not fall in the Dhcp Range
	if !status.DhcpRange.Contains(a) {
		errStr := fmt.Sprintf("no free IP addresses in DHCP range(%s, %s)",
			status.DhcpRange.Start.String(),
			status.DhcpRange.End.String())
		log.Errorf("lookupOrAllocateIPv4(%s, %s): fail: %s",
			networkID.String(), appID.String(), errStr)
		return "", errors.New(errStr)
	}
	log.Functionf("lookupOrAllocateIPv4(%s-%s): allocated %s for %s\n",
		networkID.String(), appID.String(), mac.String(), a.String())
	return a.String(), nil
}

// recordIPAssigment updates status and publishes the result
func recordIPAssignment(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus, ip net.IP, mac string) {

	addrs := types.AssignedAddrs{IPv4Addr: ip}
	status.IPAssignments[mac] = addrs
	// Publish the allocation
	publishNetworkInstanceStatus(ctx, status)
}

// releaseIPv4
//	XXX TODO - This should be a method in NetworkInstanceSm
func releaseIPv4FromNetworkInstance(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus,
	mac net.HardwareAddr) error {

	log.Functionf("releaseIPv4(%s)\n", mac.String())
	// Lookup to see if it exists
	if _, ok := status.IPAssignments[mac.String()]; !ok {
		errStr := fmt.Sprintf("releaseIPv4: not found %s for %s",
			mac.String(), status.Key())
		log.Error(errStr)
		return errors.New(errStr)
	}
	delete(status.IPAssignments, mac.String())
	publishNetworkInstanceStatus(ctx, status)
	return nil
}

func getPrefixLenForBridgeIP(
	status *types.NetworkInstanceStatus) int {
	var prefixLen int
	if status.Subnet.IP != nil {
		prefixLen, _ = status.Subnet.Mask.Size()
	} else if status.IsIPv6() {
		prefixLen = 128
	} else {
		prefixLen = 24
	}
	return prefixLen
}

func doConfigureIpAddrOnInterface(
	ipAddr string,
	prefixLen int,
	link netlink.Link) error {

	ipAddr = fmt.Sprintf("%s/%d", ipAddr, prefixLen)

	//    ip addr add ${ipAddr}/N dev ${bridgeName}
	addr, err := netlink.ParseAddr(ipAddr)
	if err != nil {
		errStr := fmt.Sprintf("ParseAddr %s failed: %s", ipAddr, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		errStr := fmt.Sprintf("AddrAdd %s failed: %s", ipAddr, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	return nil
}

func setBridgeIPAddr(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("setBridgeIPAddr(%s-%s)\n",
		status.DisplayName, status.Key())

	if status.BridgeName == "" {
		// Called too early
		log.Functionf("setBridgeIPAddr: don't yet have a bridgeName for %s\n",
			status.UUID)
		return nil
	}

	status.BridgeIPAddr = ""
	if status.Subnet.IP == nil || status.DhcpRange.Start == nil ||
		status.Gateway == nil {
		log.Functionf("setBridgeIPAddr: Don't have a IP address for %s\n",
			status.Key())
		return nil
	}
	ipAddr := status.Gateway.String()
	if ipAddr == "" {
		log.Functionf("setBridgeIPAddr: Don't have a IP address for %s\n",
			status.Key())
		return nil
	}

	// Get the linux interface with the attributes.
	// This is used to add an IP Address below.
	link, _ := netlink.LinkByName(status.BridgeName)
	if link == nil {
		// XXX..Why would this fail? Should this be Fatal instead??
		errStr := fmt.Sprintf("Failed to get link for Bridge %s", status.BridgeName)
		return errors.New(errStr)
	}
	log.Functionf("Bridge: %s, Link: %+v\n", status.BridgeName, link)

	var err error

	// Assign the gateway Address as the bridge IP address
	var bridgeMac net.HardwareAddr

	switch link.(type) {
	case *netlink.Bridge:
		// XXX always true?
		bridgeLink := link.(*netlink.Bridge)
		bridgeMac = bridgeLink.HardwareAddr
	default:
		// XXX - Same here.. Should be Fatal??
		errStr := fmt.Sprintf("Not a bridge %s",
			status.BridgeName)
		return errors.New(errStr)
	}
	if status.Gateway != nil {
		ipAddr = status.Gateway.String()
		addrs := types.AssignedAddrs{IPv4Addr: status.Gateway}
		status.IPAssignments[bridgeMac.String()] = addrs
	}
	log.Functionf("BridgeMac: %s, ipAddr: %s\n",
		bridgeMac.String(), ipAddr)

	// outside of subnet, flag it
	if !status.Subnet.Contains(status.Gateway) {
		errStr := fmt.Sprintf("Bridge IP(%s) is not in Subnet", ipAddr)
		log.Errorf("setBridgeIPAddr(%s): fail: %s",
			status.UUID.String(), errStr)
		return errors.New(errStr)
	}
	// if inside of DhcpRange, flag it
	if status.DhcpRange.Contains(status.Gateway) {
		errStr := fmt.Sprintf("Gateway(%s) is in Dhcp Range(%s,%s)",
			ipAddr, status.DhcpRange.Start.String(),
			status.DhcpRange.End.String())
		return errors.New(errStr)
	}

	prefixLen := getPrefixLenForBridgeIP(status)
	if err = doConfigureIpAddrOnInterface(ipAddr, prefixLen, link); err != nil {
		log.Errorf("Failed to configure IPAddr on Interface\n")
		return err
	}

	status.BridgeIPAddr = ipAddr
	addr := net.ParseIP(ipAddr)
	recordIPAssignment(ctx, status, addr, bridgeMac.String())
	log.Functionf("Published NetworkStatus. BridgeIpAddr: %s\n",
		status.BridgeIPAddr)
	// Create new radvd configuration and restart radvd if ipv6
	if status.IsIPv6() {
		log.Functionf("Restart Radvd\n")
		restartRadvdWithNewConfig(status.BridgeName)
	}
	return nil
}

// updateBridgeIPAddr
// 	Called a bridge service has been added/updated/deleted
func updateBridgeIPAddr(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Functionf("updateBridgeIPAddr(%s)\n", status.Key())

	old := status.BridgeIPAddr
	err := setBridgeIPAddr(ctx, status)
	if err != nil {
		log.Functionf("updateBridgeIPAddr: %s\n", err)
		return
	}
	if status.BridgeIPAddr != old && status.BridgeIPAddr != "" {
		log.Functionf("updateBridgeIPAddr(%s) restarting dnsmasq\n",
			status.Key())
		restartDnsmasq(ctx, status)
	}
	// TBD:XXX if no ip Addr, we may need to stop the dns
}

// maybeUpdateBridgeIPAddr
// 	Find ifname as a bridge Port and see if it can be updated
func maybeUpdateBridgeIPAddr(
	ctx *zedrouterContext,
	ifname string) {

	statusList := getSwitchNetworkInstanceListByIfname(ctx, ifname)

	for _, status := range statusList {
		log.Functionf("maybeUpdateBridgeIPAddr: found "+
			"NetworkInstance %s", status.DisplayName)

		if !status.Activated {
			log.Errorf("maybeUpdateBridgeIPAddr: network instance %s not activated",
				status.DisplayName)
			continue
		}
		updateBridgeIPAddr(ctx, status)
	}
}

func handleMetaDataServerChange(ctx *zedrouterContext, dnstatus *types.DeviceNetworkStatus) {
	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.NetworkInstanceStatus)
		if status.Type != types.NetworkInstanceTypeSwitch {
			continue
		}
		addr, err := types.GetLocalAddrAnyNoLinkLocal(*dnstatus, 0, status.BridgeName)
		if addr.String() == status.MetaDataServerIP {
			continue
		}
		if (err != nil || (addr.String() == "" && status.MetaDataServerIP != "")) &&
			status.Server4Running == true {
			// Bridge had a valid IP and it is gone now
			deleteServer4(ctx, status.MetaDataServerIP, status.BridgeName)
			status.Server4Running = false
			status.MetaDataServerIP = ""
			log.Functionf("Deleted meta data server with IP %s on bridge %s",
				status.MetaDataServerIP, status.BridgeName)
			ctx.pubNetworkInstanceStatus.Publish(status.Key(), status)
			continue
		}
		if status.MetaDataServerIP != "" && status.Server4Running == true {
			// Stop any currently running meta-data server
			deleteServer4(ctx, status.MetaDataServerIP, status.BridgeName)
			status.MetaDataServerIP = ""
			log.Functionf("Deleted meta data server with IP %s on bridge %s",
				status.MetaDataServerIP, status.BridgeName)
			status.Server4Running = false
		}
		if addr.String() != "" {
			// Start new meta-data server
			status.MetaDataServerIP = addr.String()
			err := createServer4(ctx, status.MetaDataServerIP, status.BridgeName)
			if err == nil {
				status.Server4Running = true
				log.Functionf("Created meta data server with IP %s on bridge %s",
					status.MetaDataServerIP, status.BridgeName)
			}
		}
		ctx.pubNetworkInstanceStatus.Publish(status.Key(), status)
	}
}

// maybeRetryNetworkInstances retries for all
func maybeRetryNetworkInstances(ctx *zedrouterContext) {

	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.NetworkInstanceStatus)
		retryNetworkInstance(ctx, &status)
	}
}

// retryNetworkInstance handles redoing an activate after an error
// Clears the error if it succeeds.
// Also will discover new errors like ports which have disappeared.
func retryNetworkInstance(ctx *zedrouterContext, status *types.NetworkInstanceStatus) {

	config := lookupNetworkInstanceConfig(ctx, status.Key())
	if config == nil {
		log.Functionf("retryNetworkInstance(%s) no config",
			status.DisplayName)
		return
	}
	if !config.Activate {
		return
	}
	// Leave ant parse errors in place
	if config.HasError() {
		log.Functionf("retryNetworkInstance(%s) has parse error",
			status.DisplayName)
		return
	}

	// Could an error have been cleared or a port disappeared resulting
	// in a new error?
	if status.HasError() {
		if err := ensurePortName(ctx, status); err != nil {
			log.Errorf("retryNetworkInstance(%s) failed: %v",
				status.DisplayName, err)
			return
		}
		err := doNetworkInstanceModify(ctx, *config, status)
		if err == nil {
			log.Noticef("retryNetworkInstance(%s) clearing error %v",
				status.DisplayName, status.Error)
			status.ClearError()
			niUpdateNIprobing(ctx, status)
		} else {
			log.Noticef("retryNetworkInstance(%s) still has error %v",
				status.DisplayName, status.Error)
		}
	} else {
		if err := ensurePortName(ctx, status); err != nil {
			log.Errorf("retryNetworkInstance(%s) failed: %v",
				status.DisplayName, err)
			return
		}

		err := doNetworkInstanceModify(ctx, *config, status)
		if err != nil {
			log.Noticef("retryNetworkInstance(%s) set error %v",
				status.DisplayName, status.Error)
			niUpdateNIprobing(ctx, status)
			status.Activated = false
		}
	}
	publishNetworkInstanceStatus(ctx, status)
}

func ensurePortName(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	if status.BridgeName != "" {
		return nil
	}
	// Find bridge created by nim
	bridgeName, bridgeMac, err := doLookupBridge(ctx, status)
	if err != nil {
		log.Errorf("retryNetworkInstance(%s) failed: %s",
			status.DisplayName, err.Error())
		return err
	}
	status.BridgeName = bridgeName

	// Get Ifindex of bridge and store it in network instance status
	bridgeLink, err := netlink.LinkByName(bridgeName)
	if err != nil {
		log.Errorf("retryNetworkInstance(%s) failed: %s",
			status.DisplayName, err.Error())
		log.Error(err)
		return err
	}
	status.BridgeIfindex = bridgeLink.Attrs().Index

	status.BridgeMac = bridgeMac
	publishNetworkInstanceStatus(ctx, status)
	return nil
}

// doNetworkInstanceActivate
func doNetworkInstanceActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("doNetworkInstanceActivate NetworkInstance key %s type %d\n",
		status.UUID, status.Type)

	// Check that Port is either "uplink", "freeuplink", or
	// an existing port name assigned to domO/zedrouter.
	// A Bridge only works with a single logicallabel interface.
	// Management ports are not allowed to be part of Switch networks.
	err := checkPortAvailable(ctx, status)
	if err != nil {
		log.Errorf("checkPortAvailable failed: CurrentUplinkIntf: %s, err:%s",
			status.CurrentUplinkIntf, err)
		return err
	}

	// Get a list of IfNames to the ones we have an ifIndex for.
	if status.Type == types.NetworkInstanceTypeSwitch {
		// switched NI is not probed and does not have a CurrentUplinkIntf
		status.IfNameList = getIfNameListForLLOrIfname(ctx, status.Logicallabel)
	} else {
		status.IfNameList = getIfNameListForLLOrIfname(ctx, status.CurrentUplinkIntf)
	}
	log.Functionf("IfNameList: %+v", status.IfNameList)
	switch status.Type {
	case types.NetworkInstanceTypeSwitch:
		err = bridgeActivate(ctx, status)
		if err != nil {
			updateBridgeIPAddr(ctx, status)
		}
		// Drop external connection request to meta-data server
		portName := "k" + status.BridgeName
		link, _ := netlink.LinkByName(portName)
		if link != nil {
			err = iptables.IptableCmd(log, "-t", "filter",
				"-A", "INPUT", "-i", status.BridgeName,
				"-p", "tcp", "--dport", "80", "-m", "physdev",
				"--physdev-in", portName, "-j", "DROP")
			if err != nil {
				log.Errorf("doNetworkInstanceActivate: Failed adding Iptables command that rejects external connections to meta-data store: %s", err)
			}
		}
	case types.NetworkInstanceTypeLocal:
		err = natActivate(ctx, status)

	case types.NetworkInstanceTypeCloud:
		err = vpnActivate(ctx, status)

	default:
		errStr := fmt.Sprintf("doNetworkInstanceActivate: NetworkInstance %d not yet supported",
			status.Type)
		err = errors.New(errStr)
	}
	if err == nil && !status.Server4Running {
		switch status.IpType {
		case types.AddressTypeIPV4:
			status.MetaDataServerIP = status.BridgeIPAddr
			log.Errorf("Creating Meta data server on bridge %s with IP %s",
				status.BridgeName, status.MetaDataServerIP)
			err = createServer4(ctx, status.MetaDataServerIP, status.BridgeName)
			if err == nil {
				status.Server4Running = true
			}
		case types.AddressTypeNone:
			if status.Type == types.NetworkInstanceTypeSwitch {
				// Start meta-data server if the bridge corresponding
				// to switch network instance has a valid IPv4 address
				bridgeAddr, found := getSwitchIPv4Addr(status.BridgeIfindex)
				if found {
					status.MetaDataServerIP = bridgeAddr
					err = createServer4(ctx, bridgeAddr, status.BridgeName)
					if err == nil {
						status.Server4Running = true
						log.Errorf("Created Meta data server on bridge %s with IP %s",
							status.BridgeName, bridgeAddr)
					}
				} else {
					log.Warnf("No valid IPv4 address found on bridge %s to start meta-data server",
						status.BridgeName)
				}
			}
		}
	}

	status.ProgUplinkIntf = status.CurrentUplinkIntf
	// setup the ACLs for the bridge
	// Here we explicitly adding the iptables rules, to the bottom of the
	// rule chains, which are tied to the Linux bridge itself and not the
	//  rules for any specific domU vifs.
	aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: status.BridgeName,
		BridgeIP: status.BridgeIPAddr, NIType: status.Type, UpLinks: status.IfNameList}
	handleNetworkInstanceACLConfiglet("-A", aclArgs)
	return err
}

func getSwitchIPv4Addr(bridgeIndex int) (string, bool) {
	addrs, _, _, err := devicenetwork.GetIPAddrs(log, bridgeIndex)
	if err == nil {
		for _, addr := range addrs {
			if addr.IsLinkLocalUnicast() {
				continue
			}
			return addr.String(), true
		}
	}
	return "", false
}

// getIfNameListForLLorIfname takes a logicallabel or a ifname
// Get a list of IfNames to the ones we have an ifIndex for.
// In the case where the port maps to multiple underlying ports
// (For Ex: uplink), only include ports that have an ifindex.
//	If there is no such port with ifindex, then retain the whole list.
//	NetworkInstance creation will fail when programming default routes
//  and iptable rules in that case - and that should be fine.
func getIfNameListForLLOrIfname(
	ctx *zedrouterContext,
	llOrIfname string) []string {

	ifNameList := labelToIfNames(ctx, llOrIfname)
	log.Functionf("ifNameList: %+v", ifNameList)

	filteredList := make([]string, 0)
	for _, ifName := range ifNameList {
		dnsPort := ctx.deviceNetworkStatus.GetPortByIfName(ifName)
		if dnsPort != nil {
			// XXX - We have a bug in MakeDeviceNetworkStatus where we are allowing
			//	a device without the corresponding linux interface. We can
			//	remove this check for ifindex here when the MakeDeviceStatus
			//	is fixed.
			// XXX That bug has been fixed. Retest without this code?
			ifIndex, err := IfnameToIndex(log, ifName)
			if err == nil {
				log.Functionf("ifName %s, ifindex: %d added to filteredList",
					ifName, ifIndex)
				filteredList = append(filteredList, ifName)
			} else {
				log.Functionf("ifIndex not found for ifName(%s) - err: %s",
					ifName, err.Error())
			}
		} else {
			log.Functionf("DeviceNetworkStatus not found for ifName(%s)",
				ifName)
		}
	}
	if len(filteredList) > 0 {
		log.Functionf("filteredList: %+v", filteredList)
		return filteredList
	}
	log.Functionf("ifname or ifindex not found for any interface for logicallabel(%s)."+
		"Returning the unfiltered list: %+v", llOrIfname, ifNameList)
	return ifNameList
}

func doNetworkInstanceInactivate(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Functionf("doNetworkInstanceInactivate NetworkInstance key %s type %d\n",
		status.UUID, status.Type)

	bridgeInactivateforNetworkInstance(ctx, status)
	switch status.Type {
	case types.NetworkInstanceTypeLocal:
		natInactivate(ctx, status, false)
	case types.NetworkInstanceTypeCloud:
		vpnInactivate(ctx, status)
	case types.NetworkInstanceTypeSwitch:
		portName := "k" + status.BridgeName
		link, _ := netlink.LinkByName(portName)
		if link != nil {
			err := iptables.IptableCmd(log, "-t", "filter",
				"-D", "INPUT", "-i", status.BridgeName,
				"-p", "tcp", "--dport", "80", "-m", "physdev",
				"--physdev-in", portName, "-j", "DROP")
			if err != nil {
				log.Errorf("doNetworkInstanceInactivate: Failed deleting Iptables command that rejects external connections to meta-data store: %s", err)
			}
		}
	}

	return
}

func doNetworkInstanceDelete(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Functionf("doNetworkInstanceDelete NetworkInstance key %s type %d\n",
		status.UUID, status.Type)

	// Anything to do except the inactivate already done?
	switch status.Type {
	case types.NetworkInstanceTypeSwitch:
		// Nothing to do.
	case types.NetworkInstanceTypeLocal:
		natDelete(status)
	case types.NetworkInstanceTypeCloud:
		vpnDelete(ctx, status)
	default:
		log.Errorf("NetworkInstance(%s-%s): Type %d not yet supported",
			status.DisplayName, status.UUID, status.Type)
	}
	if status.Server4Running {
		deleteServer4(ctx, status.MetaDataServerIP, status.BridgeName)
		status.MetaDataServerIP = ""
		status.Server4Running = false
	}
	doBridgeAclsDelete(ctx, status)
	if status.BridgeName != "" {
		stopDnsmasq(status.BridgeName, false, false)

		if status.IsIPv6() {
			stopRadvd(status.BridgeName, true)
		}
		DNSStopMonitor(status.BridgeNum)
	}
	if status.BridgeMac != "" {
		mac, err := net.ParseMAC(status.BridgeMac)
		if err != nil {
			log.Fatal("ParseMAC failed: ", status.BridgeMac, err)
		}
		if status.BridgeIPAddr != "" {
			releaseIPv4FromNetworkInstance(ctx, status, mac)
		}
	}
	networkInstanceBridgeDelete(ctx, status)
	appNumOnUNetBaseDelete(ctx, status.UUID)
}

func lookupNetworkInstanceConfig(ctx *zedrouterContext, key string) *types.NetworkInstanceConfig {

	sub := ctx.subNetworkInstanceConfig
	c, _ := sub.Get(key)
	if c == nil {
		return nil
	}
	config := c.(types.NetworkInstanceConfig)
	return &config
}

func lookupNetworkInstanceStatus(ctx *zedrouterContext, key string) *types.NetworkInstanceStatus {
	pub := ctx.pubNetworkInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := st.(types.NetworkInstanceStatus)
	return &status
}

func lookupNetworkInstanceMetrics(ctx *zedrouterContext, key string) *types.NetworkInstanceMetrics {
	pub := ctx.pubNetworkInstanceMetrics
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := st.(types.NetworkInstanceMetrics)
	return &status
}

func createNetworkInstanceMetrics(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus,
	nms *types.NetworkMetrics) *types.NetworkInstanceMetrics {

	niMetrics := types.NetworkInstanceMetrics{
		UUIDandVersion: status.UUIDandVersion,
		DisplayName:    status.DisplayName,
		Type:           status.Type,
	}
	netMetrics := types.NetworkMetrics{}
	netMetric := status.UpdateNetworkMetrics(log, nms)
	status.UpdateBridgeMetrics(log, nms, netMetric)

	netMetrics.MetricList = []types.NetworkMetric{*netMetric}
	niMetrics.NetworkMetrics = netMetrics
	niMetrics.ProbeMetrics = getNIProbeMetric(ctx, status)

	niMetrics.VlanMetrics.NumTrunkPorts = status.NumTrunkPorts
	niMetrics.VlanMetrics.VlanCounts = status.VlanMap
	switch status.Type {
	case types.NetworkInstanceTypeCloud:
		if strongSwanVpnStatusGet(ctx, status, &niMetrics) {
			publishNetworkInstanceStatus(ctx, status)
		}
	default:
	}

	return &niMetrics
}

// this is periodic metrics handler
func publishNetworkInstanceMetricsAll(ctx *zedrouterContext) {
	pub := ctx.pubNetworkInstanceStatus
	niList := pub.GetAll()
	if niList == nil {
		return
	}
	nms := getNetworkMetrics(ctx)
	for _, ni := range niList {
		status := ni.(types.NetworkInstanceStatus)
		netMetrics := createNetworkInstanceMetrics(ctx, &status, &nms)
		publishNetworkInstanceMetrics(ctx, netMetrics)
	}
}

func deleteNetworkInstanceMetrics(ctx *zedrouterContext, key string) {
	pub := ctx.pubNetworkInstanceMetrics
	if metrics := lookupNetworkInstanceMetrics(ctx, key); metrics != nil {
		pub.Unpublish(metrics.Key())
	}
}

func publishNetworkInstanceStatus(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	copyProbeStats(ctx, status)
	ctx.networkInstanceStatusMap.Store(status.UUID, status)
	pub := ctx.pubNetworkInstanceStatus
	pub.Publish(status.Key(), *status)
}

func publishNetworkInstanceMetrics(ctx *zedrouterContext,
	status *types.NetworkInstanceMetrics) {

	pub := ctx.pubNetworkInstanceMetrics
	pub.Publish(status.Key(), *status)
}

// ==== Bridge

func bridgeActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("bridgeActivate(%s)\n", status.DisplayName)
	if !strings.HasPrefix(status.BridgeName, "bn") {
		log.Noticef("bridgeActivate(%s) %s ignored",
			status.DisplayName, status.BridgeName)
		return nil
	}
	// Do we have any external port?
	if status.Logicallabel == "" {
		log.Noticef("bridgeActivate(%s) no logicallabel",
			status.DisplayName)
		return nil
	}
	bridgeLink, err := findBridge(status.BridgeName)
	if err != nil {
		errStr := fmt.Sprintf("findBridge(%s) failed %s",
			status.BridgeName, err)
		return errors.New(errStr)
	}
	// Find logicallabel for first in list
	if len(status.IfNameList) == 0 {
		errStr := fmt.Sprintf("IfNameList empty for %s",
			status.BridgeName)
		return errors.New(errStr)
	}
	ifname := status.IfNameList[0]
	alink, _ := netlink.LinkByName(ifname)
	if alink == nil {
		errStr := fmt.Sprintf("Unknown Logicallabel %s, %s",
			status.Logicallabel, ifname)
		return errors.New(errStr)
	}
	// Make sure it is up
	//    ip link set ${logicallabel} up
	if err := netlink.LinkSetUp(alink); err != nil {
		errStr := fmt.Sprintf("LinkSetUp on %s ifname %s failed: %s",
			status.Logicallabel, ifname, err)
		return errors.New(errStr)
	}
	// ip link set ${logicallabel} master ${bridge_name}
	if err := netlink.LinkSetMaster(alink, bridgeLink); err != nil {
		errStr := fmt.Sprintf("LinkSetMaster %s ifname %s bridge %s failed: %s",
			status.Logicallabel, ifname, status.BridgeName, err)
		return errors.New(errStr)
	}
	log.Functionf("bridgeActivate: added %s ifname %s to bridge %s\n",
		status.Logicallabel, ifname, status.BridgeName)
	return nil
}

// bridgeInactivateforNetworkInstance deletes any bnX bridge but not
// others created by nim
func bridgeInactivateforNetworkInstance(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Functionf("bridgeInactivateforNetworkInstance(%s) %s",
		status.DisplayName, status.BridgeName)
	if !strings.HasPrefix(status.BridgeName, "bn") {
		log.Noticef("bridgeInactivateforNetworkInstance(%s) %s ignored",
			status.DisplayName, status.BridgeName)
		return
	}
	// Do we have any external port?
	if status.Logicallabel == "" {
		log.Noticef("bridgeInactivateforNetworkInstance(%s) no logicallabel",
			status.DisplayName)
		return
	}
	// Find logicallabel
	if len(status.IfNameList) == 0 {
		errStr := fmt.Sprintf("IfNameList empty for %s",
			status.BridgeName)
		log.Errorln(errStr)
		return
	}
	ifname := status.IfNameList[0]
	alink, _ := netlink.LinkByName(ifname)
	if alink == nil {
		errStr := fmt.Sprintf("Unknown logicallabel %s, %s",
			status.Logicallabel, ifname)
		log.Errorln(errStr)
		return
	}
	// ip link set ${logicallabel} nomaster
	if err := netlink.LinkSetNoMaster(alink); err != nil {
		errStr := fmt.Sprintf("LinkSetNoMaster %s ifname %s failed: %s",
			status.Logicallabel, ifname, err)
		log.Functionln(errStr)
		return
	}
	log.Functionf("bridgeInactivateforNetworkInstance: removed %s ifname %s from bridge\n",
		status.Logicallabel, ifname)
}

// ==== Nat

// When the uplink port changes, doNetworkInstanceFallback will redo
// this function.
func natActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("natActivate(%s)\n", status.DisplayName)
	subnetStr := status.Subnet.String()

	// status.IfNameList should not have more than one interface name.
	// Put a check anyway.
	// XXX Remove the loop below in future when we have reasonable stability in code.
	if len(status.IfNameList) > 1 {
		errStr := fmt.Sprintf("Network instance can have ONE interface active at the most,"+
			" but we have %d active interfaces.", len(status.IfNameList))
		log.Errorf(errStr)
		err := errors.New(errStr)
		return err
	}
	for _, a := range status.IfNameList {
		log.Functionf("Adding iptables rules for %s \n", a)
		err := iptables.IptableCmd(log, "-t", "nat", "-A", "POSTROUTING", "-o", a,
			"-s", subnetStr, "-j", "MASQUERADE")
		if err != nil {
			log.Errorf("IptableCmd failed: %s", err)
			return err
		}
		err = PbrRouteAddAll(status.BridgeName, a)
		if err != nil {
			log.Errorf("PbrRouteAddAll for Bridge(%s) and interface %s failed. "+
				"Err: %s", status.BridgeName, a, err)
			return err
		}
		devicenetwork.AddGatewaySourceRule(log, status.Subnet,
			net.ParseIP(status.BridgeIPAddr), devicenetwork.PbrNatOutGatewayPrio)
		devicenetwork.AddSourceRule(log, status.BridgeIfindex, status.Subnet, true, devicenetwork.PbrNatOutPrio)
		devicenetwork.AddInwardSourceRule(log, status.BridgeIfindex, status.Subnet, true, devicenetwork.PbrNatInPrio)
	}
	return nil
}

func natInactivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus, inActivateOld bool) {

	log.Functionf("natInactivate(%s)\n", status.DisplayName)
	subnetStr := status.Subnet.String()
	var oldUplinkIntf string
	if inActivateOld {
		// XXX Should we instead use status.ProgUplinkIntf
		oldUplinkIntf = status.PrevUplinkIntf
	} else {
		oldUplinkIntf = status.CurrentUplinkIntf
	}
	err := iptables.IptableCmd(log, "-t", "nat", "-D", "POSTROUTING", "-o", oldUplinkIntf,
		"-s", subnetStr, "-j", "MASQUERADE")
	if err != nil {
		log.Errorf("natInactivate: iptableCmd failed %s\n", err)
	}
	devicenetwork.DelGatewaySourceRule(log, status.Subnet,
		net.ParseIP(status.BridgeIPAddr), devicenetwork.PbrNatOutGatewayPrio)
	devicenetwork.DelSourceRule(log, status.BridgeIfindex, status.Subnet, true, devicenetwork.PbrNatOutPrio)
	devicenetwork.DelInwardSourceRule(log, status.BridgeIfindex, status.Subnet, true, devicenetwork.PbrNatInPrio)
	err = PbrRouteDeleteAll(status.BridgeName, oldUplinkIntf)
	if err != nil {
		log.Errorf("natInactivate: PbrRouteDeleteAll failed %s\n", err)
	}
}

func natDelete(status *types.NetworkInstanceStatus) {

	log.Functionf("natDelete(%s)\n", status.DisplayName)
}

func lookupNetworkInstanceStatusByBridgeName(ctx *zedrouterContext,
	bridgeName string) *types.NetworkInstanceStatus {

	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.NetworkInstanceStatus)
		if status.BridgeName == bridgeName {
			return &status
		}
	}
	return nil
}

func networkInstanceAddressType(ctx *zedrouterContext, bridgeName string) int {
	ipVer := 0
	instanceStatus := lookupNetworkInstanceStatusByBridgeName(ctx, bridgeName)
	if instanceStatus != nil {
		switch instanceStatus.IpType {
		case types.AddressTypeIPV4, types.AddressTypeCryptoIPV4:
			ipVer = 4
		case types.AddressTypeIPV6, types.AddressTypeCryptoIPV6:
			ipVer = 6
		}
		return ipVer
	}
	return ipVer
}

func lookupNetworkInstanceStatusByAppIP(ctx *zedrouterContext,
	ip net.IP) *types.NetworkInstanceStatus {

	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.NetworkInstanceStatus)
		for _, addrs := range status.IPAssignments {
			if ip.Equal(addrs.IPv4Addr) {
				return &status
			}
			if len(addrs.IPv6Addrs) == 0 {
				continue
			}
			for _, nip := range addrs.IPv6Addrs {
				if ip.Equal(nip) {
					return &status
				}
			}
		}
	}
	return nil
}

// ==== Vpn
func vpnCreate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {
	if status.OpaqueConfig == "" {
		return errors.New("Vpn network instance create, invalid config")
	}
	return strongswanNetworkInstanceCreate(ctx, status)
}

func vpnActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {
	if status.OpaqueConfig == "" {
		return errors.New("Vpn network instance activate, invalid config")
	}
	return strongswanNetworkInstanceActivate(ctx, status)
}

func vpnInactivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	strongswanNetworkInstanceInactivate(ctx, status)
}

func vpnDelete(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	strongswanNetworkInstanceDestroy(ctx, status)
}

func strongswanNetworkInstanceCreate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("Vpn network instance create: %s\n", status.DisplayName)

	// parse and structure the config
	vpnConfig, err := strongSwanConfigGet(ctx, status)
	if err != nil {
		log.Warnf("Vpn network instance create: %v\n", err.Error())
		return err
	}

	// stringify and store in status
	bytes, err := json.Marshal(vpnConfig)
	if err != nil {
		log.Errorf("Vpn network instance create: %v\n", err.Error())
		return err
	}

	status.OpaqueStatus = string(bytes)
	if err := strongSwanVpnCreate(vpnConfig); err != nil {
		log.Errorf("Vpn network instance create: %v\n", err.Error())
		return err
	}
	return nil
}

func strongswanNetworkInstanceDestroy(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Functionf("Vpn network instance delete: %s\n", status.DisplayName)
	vpnConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Warnf("Vpn network instance delete: %v\n", err.Error())
	}

	if err := strongSwanVpnDelete(vpnConfig); err != nil {
		log.Warnf("Vpn network instance delete: %v\n", err.Error())
	}
}

func strongswanNetworkInstanceActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("Vpn network instance activate: %s\n", status.DisplayName)
	vpnConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Warnf("Vpn network instance activate: %v\n", err.Error())
		return err
	}

	if err := strongSwanVpnActivate(vpnConfig); err != nil {
		log.Errorf("Vpn network instance activate: %v\n", err.Error())
		return err
	}
	return nil
}

func strongswanNetworkInstanceInactivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Functionf("Vpn network instance inactivate: %s\n", status.DisplayName)
	vpnConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Warnf("Vpn network instance inactivate: %v\n", err.Error())
	}

	if err := strongSwanVpnInactivate(vpnConfig); err != nil {
		log.Warnf("Vpn network instance inactivate: %v\n", err.Error())
	}
}

// labelToIfNames
//	XXX - Probably should move this to ZedRouter.go as a method
//		of zedRouterContext
// Expand the generic names, and return the interface names.
// Does not verify the existence of the logicallabels/interfaces
func labelToIfNames(ctx *zedrouterContext, llOrIfname string) []string {
	if strings.EqualFold(llOrIfname, "uplink") {
		return types.GetMgmtPortsSortedCost(*ctx.deviceNetworkStatus, 0)
	}
	if strings.EqualFold(llOrIfname, "freeuplink") {
		return types.GetMgmtPortsByCost(*ctx.deviceNetworkStatus, 0)
	}
	ifname := types.LogicallabelToIfName(ctx.deviceNetworkStatus, llOrIfname)
	if len(ifname) == 0 {
		return []string{}
	}
	return []string{ifname}
}

func vifNameToBridgeName(ctx *zedrouterContext, vifName string) string {

	pub := ctx.pubNetworkInstanceStatus
	instanceItems := pub.GetAll()
	for _, st := range instanceItems {
		status := st.(types.NetworkInstanceStatus)
		if status.IsVifInBridge(vifName) {
			return status.BridgeName
		}
	}
	return ""
}

// Get All ifindices for the Network Instances which are using ifname
func getAllNIindices(ctx *zedrouterContext, ifname string) []int {

	var indicies []int
	pub := ctx.pubNetworkInstanceStatus
	if pub == nil {
		return indicies
	}
	instanceItems := pub.GetAll()
	for _, st := range instanceItems {
		status := st.(types.NetworkInstanceStatus)
		if !status.IsUsingIfName(ifname) {
			continue
		}
		if status.BridgeName == "" {
			continue
		}
		link, err := netlink.LinkByName(status.BridgeName)
		if err != nil {
			errStr := fmt.Sprintf("LinkByName(%s) failed: %s",
				status.BridgeName, err)
			log.Errorln(errStr)
			continue
		}
		indicies = append(indicies, link.Attrs().Index)
	}
	return indicies
}

// checkAndReprogramNetworkInstances handles changes to CurrentUplinkIntf
// when NeedIntfUpdate is set.
func checkAndReprogramNetworkInstances(ctx *zedrouterContext) {
	pub := ctx.pubNetworkInstanceStatus
	instanceItems := pub.GetAll()

	for _, instance := range instanceItems {
		status := instance.(types.NetworkInstanceStatus)

		if !status.NeedIntfUpdate {
			continue
		}
		if status.ProgUplinkIntf == status.CurrentUplinkIntf {
			log.Functionf("checkAndReprogramNetworkInstances: Uplink (%s) has not changed"+
				" for network instance %s",
				status.CurrentUplinkIntf, status.DisplayName)
			continue
		}

		log.Functionf("checkAndReprogramNetworkInstances: Changing Uplink to %s from %s for "+
			"network instance %s", status.CurrentUplinkIntf, status.PrevUplinkIntf,
			status.DisplayName)
		doNetworkInstanceFallback(ctx, &status)
	}
}

// propagateNetworkInstToAppNetwork handles clearing/updating of error propagation to
// the AppNetworkStatus
func propagateNetworkInstToAppNetwork(ctx *zedrouterContext) {
	pub := ctx.pubNetworkInstanceStatus
	instanceItems := pub.GetAll()

	for _, instance := range instanceItems {
		status := instance.(types.NetworkInstanceStatus)
		checkAndRecreateAppNetwork(ctx, status)
	}
}

func doNetworkInstanceFallback(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Functionf("doNetworkInstanceFallback NetworkInstance key %s type %d\n",
		status.UUID, status.Type)

	var err error
	// Get a list of IfNames to the ones we have an ifIndex for.
	status.IfNameList = getIfNameListForLLOrIfname(ctx, status.CurrentUplinkIntf)
	publishNetworkInstanceStatus(ctx, status)
	log.Functionf("IfNameList: %+v", status.IfNameList)

	switch status.Type {
	case types.NetworkInstanceTypeLocal:
		if !status.Activated {
			return nil
		}
		natInactivate(ctx, status, true)
		err = natActivate(ctx, status)
		if err != nil {
			log.Errorf("doNetworkInstanceFallback: %s", err)
		}
		status.ProgUplinkIntf = status.CurrentUplinkIntf

		// Use dns server received from DHCP for the current uplink
		bridgeName := status.BridgeName
		hostsDirpath := runDirname + "/hosts." + bridgeName
		deleteOnlyDnsmasqConfiglet(bridgeName)
		stopDnsmasq(bridgeName, false, false)

		if status.BridgeIPAddr != "" {
			dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
				status.CurrentUplinkIntf)
			ntpServers := types.GetNTPServers(*ctx.deviceNetworkStatus,
				status.CurrentUplinkIntf)
			createDnsmasqConfiglet(ctx, bridgeName,
				status.BridgeIPAddr, status,
				hostsDirpath, status.BridgeIPSets,
				status.CurrentUplinkIntf, dnsServers, ntpServers)
			startDnsmasq(bridgeName)
		}

		// Go through the list of all application connected to this network instance
		// and clear conntrack flows corresponding to them.
		apps := ctx.pubAppNetworkStatus.GetAll()
		// Find all app instances that use this network and purge flows
		// that correspond to these applications.
		for _, app := range apps {
			appNetworkStatus := app.(types.AppNetworkStatus)
			for i := range appNetworkStatus.UnderlayNetworkList {
				ulStatus := &appNetworkStatus.UnderlayNetworkList[i]
				if uuid.Equal(ulStatus.Network, status.UUID) {
					config := lookupAppNetworkConfig(ctx, appNetworkStatus.Key())
					ipsets := compileAppInstanceIpsets(ctx, config.UnderlayNetworkList)
					ulConfig := &config.UnderlayNetworkList[i]
					// This should take care of re-programming any ACL rules that
					// use input match on uplinks.
					// XXX no change in config
					// XXX forcing a change
					doAppNetworkModifyUNetAcls(ctx, &appNetworkStatus,
						ulConfig, ulConfig, ulStatus, ipsets, true)
				}
			}
			publishAppNetworkStatus(ctx, &appNetworkStatus)
		}
	case types.NetworkInstanceTypeSwitch:
		// NA for switch network instance.
	case types.NetworkInstanceTypeCloud:
		// XXX Add support for Cloud network instance
		if status.Activated {
			vpnInactivate(ctx, status)
		}
		vpnDelete(ctx, status)
		vpnCreate(ctx, status)
		if status.Activated {
			vpnActivate(ctx, status)
		}
		status.ProgUplinkIntf = status.CurrentUplinkIntf

		// Use dns server received from DHCP for the current uplink
		bridgeName := status.BridgeName
		hostsDirpath := runDirname + "/hosts." + bridgeName
		deleteOnlyDnsmasqConfiglet(bridgeName)
		stopDnsmasq(bridgeName, false, false)

		if status.BridgeIPAddr != "" {
			dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
				status.CurrentUplinkIntf)
			ntpServers := types.GetNTPServers(*ctx.deviceNetworkStatus,
				status.CurrentUplinkIntf)
			createDnsmasqConfiglet(ctx, bridgeName,
				status.BridgeIPAddr, status,
				hostsDirpath, status.BridgeIPSets,
				status.CurrentUplinkIntf, dnsServers, ntpServers)
			startDnsmasq(bridgeName)
		}

		// Go through the list of all application connected to this network instance
		// and clear conntrack flows corresponding to them.
		apps := ctx.pubAppNetworkStatus.GetAll()
		// Find all app instances that use this network and purge flows
		// that correspond to these applications.
		for _, app := range apps {
			appNetworkStatus := app.(types.AppNetworkStatus)
			for i := range appNetworkStatus.UnderlayNetworkList {
				ulStatus := &appNetworkStatus.UnderlayNetworkList[i]
				if uuid.Equal(ulStatus.Network, status.UUID) {
					config := lookupAppNetworkConfig(ctx, appNetworkStatus.Key())
					ipsets := compileAppInstanceIpsets(ctx, config.UnderlayNetworkList)
					ulConfig := &config.UnderlayNetworkList[i]
					// This should take care of re-programming any ACL rules that
					// use input match on uplinks.
					// XXX no change in config
					doAppNetworkModifyUNetAcls(ctx, &appNetworkStatus,
						ulConfig, ulConfig, ulStatus, ipsets, true)
				}
			}
			publishAppNetworkStatus(ctx, &appNetworkStatus)
		}
	}
	status.NeedIntfUpdate = false
	publishNetworkInstanceStatus(ctx, status)
	return err
}

// uplinkToPhysdev checks if the ifname is a bridge and if so it
// prepends a "k" to the name (assuming that ifname exists)
// If any issues it returns the argument ifname
func uplinkToPhysdev(ifname string) string {

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		err = fmt.Errorf("uplinkToPhysdev LinkByName(%s) failed: %v",
			ifname, err)
		log.Error(err)
		return ifname
	}
	linkType := link.Type()
	if linkType != "bridge" {
		log.Functionf("uplinkToPhysdev(%s) not a bridge", ifname)
		return ifname
	}

	kernIfname := "k" + ifname
	_, err = netlink.LinkByName(kernIfname)
	if err != nil {
		err = fmt.Errorf("uplinkToPhysdev(%s) %s does not exist: %v",
			ifname, kernIfname, err)
		log.Error(err)
		return ifname
	}
	log.Functionf("uplinkToPhysdev found %s", kernIfname)
	return kernIfname
}
