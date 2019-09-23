// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle NetworkInstance setup

package zedrouter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func allowSharedPort(status *types.NetworkInstanceStatus) bool {
	return status.Type != types.NetworkInstanceTypeSwitch
}

// isSharedPortLabel
// port names "uplink" and "freeuplink" are actually built in labels
//	we used for ports used by Dom0 itself to reach the cloud. But
//  these can also be shared as L3 ports by the applications ie.,
//	NI of kind Local can use them as well. Infact, except
//  NetworkInstanceTypeSwitch, all other current types of network instance
//  can share the port. Whether such ports can be used by network instance
//  can be checked  using allowSharedPort() function
func isSharedPortLabel(port string) bool {
	// XXX - I think we can get rid of these built-in labels (uplink/freeuplink).
	//	This will be cleaned up as part of support for deviceConfig
	//	from cloud.
	if strings.EqualFold(port, "uplink") {
		return true
	}
	if strings.EqualFold(port, "freeuplink") {
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

	if status.CurrentUplinkIntf == "" {
		log.Infof("Port not specified\n")
		return nil
	}
	log.Infof("NetworkInstance(%s-%s), port: %s\n",
		status.DisplayName, status.UUID, status.CurrentUplinkIntf)

	if allowSharedPort(status) {
		if isSharedPortLabel(status.CurrentUplinkIntf) {
			log.Infof("allowSharedPort: %t, isSharedPortLabel:%t",
				allowSharedPort(status), isSharedPortLabel(status.CurrentUplinkIntf))
			return nil
		}
	} else {
		if isSharedPortLabel(status.CurrentUplinkIntf) {
			errStr := fmt.Sprintf("SharedPortLabel %s not allowed for exclusive network instance %s-%s\n",
				status.CurrentUplinkIntf, status.Key(), status.DisplayName)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
	}
	portStatus := ctx.deviceNetworkStatus.GetPortByName(status.CurrentUplinkIntf)
	if portStatus == nil {
		// XXX Fallback until we have complete Name support in UI
		portStatus = ctx.deviceNetworkStatus.GetPortByIfName(status.CurrentUplinkIntf)
		if portStatus == nil {
			errStr := fmt.Sprintf("PortStatus for %s not found for network instance %s-%s\n",
				status.CurrentUplinkIntf, status.Key(), status.DisplayName)
			return errors.New(errStr)
		}
	}

	if allowSharedPort(status) {
		// Make sure it is configured for IP or will be
		if portStatus.Dhcp == types.DT_NONE {
			errStr := fmt.Sprintf("Port %s not configured for shared use. "+
				"Cannot be used by non-Switch Network Instance %s-%s\n",
				status.CurrentUplinkIntf, status.UUID, status.DisplayName)
			return errors.New(errStr)
		}
		// Make sure it is not used by a NetworkInstance of type Switch
		for _, iterStatusEntry := range ctx.networkInstanceStatusMap {
			if status == iterStatusEntry {
				continue
			}
			if !iterStatusEntry.IsUsingPort(status.CurrentUplinkIntf) {
				continue
			}
			if !allowSharedPort(iterStatusEntry) {
				errStr := fmt.Sprintf("Port %s already used by "+
					"Switch NetworkInstance %s-%s. It cannot be used by "+
					"any other Network Instance such as %s-%s\n",
					status.CurrentUplinkIntf, iterStatusEntry.UUID,
					iterStatusEntry.DisplayName,
					status.UUID, status.DisplayName)
				return errors.New(errStr)
			}
		}
	} else {
		// Make sure it will not be configured for IP
		if portStatus.Dhcp != types.DT_NONE {
			errStr := fmt.Sprintf("Port %s configured for shared use with DHCP type %d. "+
				"Cannot be used by Switch Network Instance %s-%s\n",
				status.CurrentUplinkIntf, portStatus.Dhcp, status.UUID, status.DisplayName)
			return errors.New(errStr)
		}
		// Make sure it is not used by any other NetworkInstance
		for _, iterStatusEntry := range ctx.networkInstanceStatusMap {
			if status == iterStatusEntry {
				continue
			}
			if iterStatusEntry.IsUsingPort(status.CurrentUplinkIntf) {
				errStr := fmt.Sprintf("Port %s already used by NetworkInstance %s-%s. "+
					"Cannot be used by Switch Network Instance %s-%s\n",
					status.CurrentUplinkIntf, iterStatusEntry.UUID, iterStatusEntry.DisplayName,
					status.UUID, status.DisplayName)
				return errors.New(errStr)
			}
		}
	}
	return nil
}

func isOverlay(netType types.NetworkInstanceType) bool {
	if netType == types.NetworkInstanceTypeMesh {
		return true
	}
	return false
}

// doCreateBridge
//		returns (error, bridgeMac-string)
func doCreateBridge(bridgeName string, bridgeNum int,
	status *types.NetworkInstanceStatus) (error, string) {
	Ipv4Eid := false
	if isOverlay(status.Type) && status.Subnet.IP != nil {
		Ipv4Eid = (status.Subnet.IP.To4() != nil)
		status.Ipv4Eid = Ipv4Eid
	}

	// Start clean
	// delete the bridge
	attrs := netlink.NewLinkAttrs()
	attrs.Name = bridgeName
	link := &netlink.Bridge{LinkAttrs: attrs}
	netlink.LinkDel(link)

	// Delete the sister dummy interface also, if any
	if status.HasEncap {
		deleteDummyInterface(status)
	}

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

	// For the case of Lisp/Vpn networks, we route all traffic coming from
	// the bridge to a dummy interface with MTU 1280. This is done to
	// get bigger packets fragmented and also to have the kernel generate
	// ICMP packet too big for path MTU discovery before being captured by
	// lisp dataplane/other network elements
	if status.HasEncap {
		err = createDummyInterface(status)
	}
	return err, bridgeMac
}

func networkInstanceBridgeDelete(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {
	// When bridge and sister interfaces are deleted, code in pbr.go
	// takes care of deleting the corresponding route tables and ip rules.
	// Here we explicitly delete the iptables rules which are tied to the Linux bridge
	// itself and not the rules for specific domU vifs.

	aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: status.BridgeName,
		BridgeIP: status.BridgeIPAddr, NIType: status.Type, UpLinks: status.IfNameList}
	handleNetworkInstanceACLConfiglet("-D", aclArgs)

	// delete the sister interface
	if status.HasEncap {
		deleteDummyInterface(status)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = status.BridgeName
	link := &netlink.Bridge{LinkAttrs: attrs}
	// Remove link and associated addresses
	netlink.LinkDel(link)

	if status.BridgeNum != 0 {
		status.BridgeName = ""
		status.BridgeNum = 0
		bridgeNumFree(ctx, status.UUID)
	}
}

func isNetworkInstanceCloud(status *types.NetworkInstanceStatus) bool {
	if status.Type == types.NetworkInstanceTypeCloud {
		return true
	}
	return false
}

func createDummyInterface(status *types.NetworkInstanceStatus) error {

	bridgeName := status.BridgeName
	bridgeNum := status.BridgeNum

	sattrs := netlink.NewLinkAttrs()
	// "s" for sister
	dummyIntfName := "s" + bridgeName
	sattrs.Name = dummyIntfName

	slinkMac := fmt.Sprintf("00:16:3e:06:01:%02x", bridgeNum)
	hw, err := net.ParseMAC(slinkMac)
	if err != nil {
		log.Fatal("doNetworkCreate: ParseMAC failed: ", slinkMac, err)
	}
	sattrs.HardwareAddr = hw
	// 1280 gives us a comfortable buffer for lisp encapsulation
	sattrs.MTU = 1280
	slink := &netlink.Dummy{LinkAttrs: sattrs}
	if err := netlink.LinkAdd(slink); err != nil {
		errStr := fmt.Sprintf("doNetworkCreate: LinkAdd on %s failed: %s",
			dummyIntfName, err)
		return errors.New(errStr)
	}

	// ip link set ${dummy-interface} up
	if err := netlink.LinkSetUp(slink); err != nil {
		errStr := fmt.Sprintf("doNetworkCreate: LinkSetUp on %s failed: %s",
			dummyIntfName, err)
		return errors.New(errStr)
	}

	// Turn ARP off on our dummy link
	if err := netlink.LinkSetARPOff(slink); err != nil {
		errStr := fmt.Sprintf("doNetworkCreate: LinkSetARPOff on %s failed: %s",
			dummyIntfName, err)
		return errors.New(errStr)
	}

	var destAddr string
	if status.Ipv4Eid || isNetworkInstanceCloud(status) {
		destAddr = status.Subnet.String()
	} else {
		destAddr = "fd00::/8"
	}
	_, ipnet, err := net.ParseCIDR(destAddr)
	if err != nil {
		errStr := fmt.Sprintf("doNetworkCreate: ParseCIDR of %s failed",
			status.Subnet.String())
		return errors.New(errStr)
	}

	// get bridge index
	attrs := netlink.NewLinkAttrs()
	attrs.Name = bridgeName
	link := &netlink.Bridge{LinkAttrs: attrs}
	iifIndex := link.Attrs().Index

	// get link index
	oifIndex := slink.Attrs().Index
	err = AddOverlayRuleAndRoute(bridgeName, iifIndex, oifIndex, ipnet)
	if err != nil {
		errStr := fmt.Sprintf(
			"doNetworkCreate: Lisp IP rule and route addition failed for bridge %s: %s",
			bridgeName, err)
		return errors.New(errStr)
	}
	return nil
}

func deleteDummyInterface(status *types.NetworkInstanceStatus) {

	bridgeName := status.BridgeName
	// "s" for sister
	dummyIntfName := "s" + bridgeName

	// Delete the sister dummy interface also
	sattrs := netlink.NewLinkAttrs()
	sattrs.Name = dummyIntfName
	sLink := &netlink.Dummy{LinkAttrs: sattrs}
	netlink.LinkDel(sLink)
}

func doBridgeAclsDelete(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	// Delete ACLs attached to this network aka linux bridge
	items := ctx.pubAppNetworkStatus.GetAll()
	for _, ans := range items {
		appNetStatus := cast.CastAppNetworkStatus(ans)

		for _, olStatus := range appNetStatus.OverlayNetworkList {
			if olStatus.Network != status.UUID {
				continue
			}
			if olStatus.Bridge == "" {
				continue
			}
			log.Infof("NetworkInstance - deleting Acls for OL Interface(%s)",
				olStatus.Name)
			aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: olStatus.Bridge,
				VifName: olStatus.Vif, BridgeIP: olStatus.BridgeIPAddr, AppIP: olStatus.EID.String(),
				UpLinks: status.IfNameList}
			ruleList, err := deleteACLConfiglet(aclArgs, olStatus.ACLRules)
			if err != nil {
				log.Errorf("doNetworkDelete ACL failed: %s\n",
					err)
			}
			olStatus.ACLRules = ruleList
		}
		for _, ulStatus := range appNetStatus.UnderlayNetworkList {
			if ulStatus.Network != status.UUID {
				continue
			}
			if ulStatus.Bridge == "" {
				continue
			}
			log.Infof("NetworkInstance - deleting Acls for UL Interface(%s)",
				ulStatus.Name)
			aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: ulStatus.Bridge,
				VifName: ulStatus.Vif, BridgeIP: ulStatus.BridgeIPAddr, AppIP: ulStatus.AllocatedIPAddr,
				UpLinks: status.IfNameList}
			ruleList, err := deleteACLConfiglet(aclArgs, ulStatus.ACLRules)
			if err != nil {
				log.Errorf("NetworkInstance DeleteACL failed: %s\n",
					err)
			}
			ulStatus.ACLRules = ruleList
		}
	}
	return
}

func handleNetworkInstanceModify(
	ctxArg interface{},
	key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkInstanceStatus
	config := cast.CastNetworkInstanceConfig(configArg)
	status := lookupNetworkInstanceStatus(ctx, key)
	if status != nil {
		log.Infof("handleNetworkInstanceModify(%s)\n", key)
		status.ChangeInProgress = types.ChangeInProgressTypeModify
		pub.Publish(status.Key(), *status)
		doNetworkInstanceModify(ctx, config, status)
		niUpdateNIprobing(ctx, status)
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		publishNetworkInstanceStatus(ctx, status)
		log.Infof("handleNetworkInstanceModify(%s) done\n", key)
	} else {
		handleNetworkInstanceCreate(ctx, key, config)
	}
}

func handleNetworkInstanceCreate(
	ctx *zedrouterContext,
	key string,
	config types.NetworkInstanceConfig) {

	log.Infof("handleNetworkInstanceCreate: (UUID: %s, name:%s)\n",
		key, config.DisplayName)

	pub := ctx.pubNetworkInstanceStatus
	status := types.NetworkInstanceStatus{
		NetworkInstanceConfig: config,
		NetworkInstanceInfo: types.NetworkInstanceInfo{
			IPAssignments: make(map[string]net.IP),
			VifMetricMap:  make(map[string]types.NetworkMetric),
		},
	}

	status.ChangeInProgress = types.ChangeInProgressTypeCreate
	ctx.networkInstanceStatusMap[status.UUID] = &status
	pub.Publish(status.Key(), status)

	err := doNetworkInstanceCreate(ctx, &status)
	if err != nil {
		log.Errorf("doNetworkInstanceCreate(%s) failed: %s\n",
			key, err)
		status.SetError(err)
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		publishNetworkInstanceStatus(ctx, &status)
		return
	}
	pub.Publish(status.Key(), status)

	status.PInfo = make(map[string]types.ProbeInfo)
	niUpdateNIprobing(ctx, &status)

	if config.Activate {
		log.Infof("handleNetworkInstanceCreate: Activating network instance")
		err := doNetworkInstanceActivate(ctx, &status)
		if err != nil {
			log.Errorf("doNetworkInstanceActivate(%s) failed: %s\n", key, err)
			status.SetError(err)
		} else {
			log.Infof("Activated network instance %s %s", status.UUID, status.DisplayName)
			status.Activated = true
		}
	}

	status.ChangeInProgress = types.ChangeInProgressTypeNone
	publishNetworkInstanceStatus(ctx, &status)
	// Hooks for updating dependent objects
	checkAndRecreateAppNetwork(ctx, config.UUID)
	log.Infof("handleNetworkInstanceCreate(%s) done\n", key)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleNetworkInstanceDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkInstanceStatus
	status := lookupNetworkInstanceStatus(ctx, key)
	if status == nil {
		log.Infof("handleNetworkInstanceDelete: unknown %s\n", key)
		return
	}
	status.ChangeInProgress = types.ChangeInProgressTypeDelete
	pub.Publish(status.Key(), status)
	if status.Activated {
		doNetworkInstanceInactivate(ctx, status)
	}
	doNetworkInstanceDelete(ctx, status)
	delete(ctx.networkInstanceStatusMap, status.UUID)
	pub.Unpublish(status.Key())

	deleteNetworkInstanceMetrics(ctx, status.Key())
	log.Infof("handleNetworkInstanceDelete(%s) done\n", key)
}

func doNetworkInstanceCreate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("NetworkInstance(%s-%s): NetworkType: %d, IpType: %d\n",
		status.DisplayName, status.UUID, status.Type, status.IpType)

	if err := doNetworkInstanceSanityCheck(ctx, status); err != nil {
		log.Errorf("NetworkInstance(%s-%s): Sanity Check failed: %s",
			status.DisplayName, status.UUID, err)
		return err
	}

	// Allocate bridgeNum.
	bridgeNum := bridgeNumAllocate(ctx, status.UUID)
	bridgeName := fmt.Sprintf("bn%d", bridgeNum)
	status.BridgeNum = bridgeNum
	status.BridgeName = bridgeName

	// Create bridge
	var err error
	bridgeMac := ""
	if err, bridgeMac = doCreateBridge(bridgeName, bridgeNum, status); err != nil {
		return err
	}
	status.BridgeMac = bridgeMac
	publishNetworkInstanceStatus(ctx, status)

	log.Infof("bridge created. BridgeMac: %s\n", bridgeMac)

	if err := setBridgeIPAddr(ctx, status); err != nil {
		return err
	}
	log.Infof("IpAddress set for bridge\n")

	// Create a hosts directory for the new bridge
	// Directory is /var/run/zedrouter/hosts.${BRIDGENAME}
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
		createDnsmasqConfiglet(bridgeName,
			status.BridgeIPAddr, &status.NetworkInstanceConfig,
			hostsDirpath, status.BridgeIPSets, status.Ipv4Eid)
		startDnsmasq(bridgeName)
	}

	// monitor the DNS and DHCP information
	go DNSMonitor(bridgeName, bridgeNum, ctx, status)

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

	log.Infof("Sanity Checking NetworkInstance(%s-%s): type:%d, IpType:%d\n",
		status.DisplayName, status.UUID, status.Type, status.IpType)

	//  Check NetworkInstanceType
	switch status.Type {
	case types.NetworkInstanceTypeLocal:
		// Do nothing
	case types.NetworkInstanceTypeSwitch:
		// Do nothing
	case types.NetworkInstanceTypeCloud:
		// Do nothing
	case types.NetworkInstanceTypeMesh:
		// Do nothing
	default:
		err := fmt.Sprintf("Instance type %d not supported", status.Type)
		return errors.New(err)
	}

	if err := checkPortAvailable(ctx, status); err != nil {
		log.Errorf("checkPortAvailable failed: Port: %s, err:%s",
			status.CurrentUplinkIntf, err)
		return err
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
		err = DoNetworkInstanceStatusDhcpRangeSanityCheck(status)
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

	// Verify Subnet doesn't overlap with other network instances
	for _, iterStatusEntry := range ctx.networkInstanceStatusMap {
		if status == iterStatusEntry {
			continue
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
			return errors.New(errStr)
		}

		// Reverse check..Check if iterStatusEntry.Subnet is contained in status.subnet
		if status.Subnet.Contains(iterStatusEntry.Subnet.IP) {
			errStr := fmt.Sprintf("Another network instance(%s-%s) Subnet(%s) "+
				"overlaps with Subnet(%s)",
				iterStatusEntry.DisplayName, iterStatusEntry.UUID,
				iterStatusEntry.Subnet.String(),
				status.Subnet.String())
			return errors.New(errStr)
		}
	}
	return nil
}

// DoDhcpRangeSanityCheck
// 1) Must always be Unspecified
// 2) It should be a subset of Subnet
func DoNetworkInstanceStatusDhcpRangeSanityCheck(
	status *types.NetworkInstanceStatus) error {
	// For Mesh type network instance with Crypto V6 addressing, no dhcp-range
	// will be specified.
	if status.Type == types.NetworkInstanceTypeMesh &&
		status.IpType == types.AddressTypeCryptoIPV6 {
		return nil
	}
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
	status *types.NetworkInstanceStatus) {

	log.Infof("doNetworkInstanceModify: key %s\n", config.UUID)
	if config.Type != status.Type {
		log.Infof("doNetworkInstanceModify: key %s\n", config.UUID)
		// We do not allow Type to change.
		status.SetError(
			errors.New("Changing Type of NetworkInstance is not supported"))
	}

	if config.Port != status.Port {
		status.SetError(
			errors.New("Changing Port in NetworkInstance is not yet supported"))
		return
	}

	if config.Activate && !status.Activated {
		err := doNetworkInstanceActivate(ctx, status)
		if err != nil {
			log.Errorf("doNetworkInstanceActivate(%s) failed: %s\n",
				config.Key(), err)
			status.SetError(err)
		} else {
			status.Activated = true
		}
	} else if status.Activated && !config.Activate {
		doNetworkInstanceInactivate(ctx, status)
		status.Activated = false
	}
}

// getSwitchNetworkInstanceUsingPort
//		This function assumes if a port used by networkInstance of type SWITCH
//		is not shared ie., is not used by any other network instance.
func getSwitchNetworkInstanceUsingPort(
	ctx *zedrouterContext,
	ifname string) (status *types.NetworkInstanceStatus) {

	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()

	for _, st := range items {
		status := cast.CastNetworkInstanceStatus(st)
		ifname2 := types.AdapterToIfName(ctx.deviceNetworkStatus,
			status.Port)
		if ifname2 != ifname {
			log.Infof("maybeUpdateBridgeIPAddr - NI (%s) not using %s\n",
				status.DisplayName, ifname)
			continue
		}

		// Found Status using the Port.
		log.Infof("getSwitchNetworkInstanceUsingPort: networkInstance (%s) using "+
			"port %s, ifname: %s, type: %d\n",
			status.DisplayName, status.Port, ifname, status.Type)

		if status.Type == types.NetworkInstanceTypeSwitch {
			return &status
		}
		log.Infof("getSwitchNetworkInstanceUsingPort: networkInstance (%s) "+
			"not of type (%d) switch\n",
			status.DisplayName, status.Type)
		break
	}
	return nil
}

func restartDnsmasq(ctx *zedrouterContext, status *types.NetworkInstanceStatus) {

	log.Infof("restartDnsmasq(%s) ipsets %v\n",
		status.BridgeName, status.BridgeIPSets)
	bridgeName := status.BridgeName
	stopDnsmasq(bridgeName, false, true)

	hostsDirpath := runDirname + "/hosts." + bridgeName
	// XXX arbitrary name "router"!!
	addToHostsConfiglet(hostsDirpath, "router",
		[]string{status.BridgeIPAddr})

	// Use existing BridgeIPSets
	createDnsmasqConfiglet(bridgeName, status.BridgeIPAddr,
		&status.NetworkInstanceConfig, hostsDirpath, status.BridgeIPSets,
		status.Ipv4Eid)
	createHostDnsmasqFile(ctx, bridgeName)
	startDnsmasq(bridgeName)
}

func createHostDnsmasqFile(ctx *zedrouterContext, bridge string) {
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := cast.CastAppNetworkStatus(st)
		for _, ulStatus := range status.UnderlayNetworkList {
			if strings.Compare(bridge, ulStatus.Bridge) != 0 {
				continue
			}
			addhostDnsmasq(bridge, ulStatus.Mac,
				ulStatus.AllocatedIPAddr, status.UUIDandVersion.UUID.String())
			log.Infof("createHostDnsmasqFile:(%s) mac=%s, IP=%s\n", bridge, ulStatus.Mac, ulStatus.AllocatedIPAddr)
		}
	}
}

// Returns an IP address as a string, or "" if not found.
func lookupOrAllocateIPv4(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus,
	mac net.HardwareAddr) (string, error) {

	log.Infof("lookupOrAllocateIPv4(%s-%s): mac:%s\n",
		status.DisplayName, status.Key(), mac.String())
	// Lookup to see if it exists
	if ip, ok := status.IPAssignments[mac.String()]; ok {
		log.Infof("found Ip addr ( %s) for mac(%s)\n",
			ip.String(), mac.String())
		return ip.String(), nil
	}

	log.Infof("bridgeName %s Subnet %v range %v-%v\n",
		status.BridgeName, status.Subnet,
		status.DhcpRange.Start, status.DhcpRange.End)

	if status.DhcpRange.Start == nil {
		if status.Type == types.NetworkInstanceTypeSwitch {
			log.Infof("%s-%s switch means no bridgeIpAddr",
				status.DisplayName, status.Key())
			return "", nil
		}
		log.Fatalf("%s-%s: nil DhcpRange.Start",
			status.DisplayName, status.Key())
	}

	// Starting guess based on number allocated
	allocated := uint(len(status.IPAssignments))
	a := addToIP(status.DhcpRange.Start, allocated)
	for status.DhcpRange.End == nil ||
		bytes.Compare(a, status.DhcpRange.End) < 0 {

		log.Infof("lookupOrAllocateIPv4(%s) testing %s\n",
			mac.String(), a.String())
		if status.IsIpAssigned(a) {
			a = addToIP(a, 1)
			continue
		}
		log.Infof("lookupOrAllocateIPv4(%s) found free %s\n",
			mac.String(), a.String())
		status.IPAssignments[mac.String()] = a
		// Publish the allocation
		publishNetworkInstanceStatus(ctx, status)
		return a.String(), nil
	}
	errStr := fmt.Sprintf("lookupOrAllocateIPv4(%s) no free address in DhcpRange",
		status.Key())
	return "", errors.New(errStr)
}

// Add to an IPv4 address
func addToIP(ip net.IP, addition uint) net.IP {
	addr := ip.To4()
	if addr == nil {
		log.Fatalf("addIP: not an IPv4 address %s", ip.String())
	}
	val := uint(addr[0])<<24 + uint(addr[1])<<16 +
		uint(addr[2])<<8 + uint(addr[3])
	val += addition
	val0 := byte((val >> 24) & 0xFF)
	val1 := byte((val >> 16) & 0xFF)
	val2 := byte((val >> 8) & 0xFF)
	val3 := byte(val & 0xFF)
	return net.IPv4(val0, val1, val2, val3)
}

// releaseIPv4
//	XXX TODO - This should be a method in NetworkInstanceSm
func releaseIPv4FromNetworkInstance(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus,
	mac net.HardwareAddr) error {

	log.Infof("releaseIPv4(%s)\n", mac.String())
	// Lookup to see if it exists
	if _, ok := status.IPAssignments[mac.String()]; !ok {
		errStr := fmt.Sprintf("releaseIPv4: not found %s for %s",
			mac.String(), status.Key())
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	delete(status.IPAssignments, mac.String())
	publishNetworkInstanceStatus(ctx, status)
	return nil
}

func getPrefixLenForBridgeIP(
	status *types.NetworkInstanceStatus) int {
	var prefixLen int
	if status.Ipv4Eid {
		prefixLen = 32
	} else if status.Subnet.IP != nil {
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

// getPortIPv4Addr
//	To be used only for NI type Switch
func getPortIPv4Addr(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) (string, error) {
	// Find any service which is associated with the appLink UUID
	log.Infof("NetworkInstance UUID:%s, Name: %s, Port: %s\n",
		status.UUID, status.DisplayName, status.Port)

	if status.Port == "" {
		log.Infof("no Port\n")
		return "", nil
	}

	// Get IP address from adapter
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, status.Port)
	ifindex, err := devicenetwork.IfnameToIndex(ifname)
	if err != nil {
		return "", err
	}
	// XXX Add IPv6 underlay; ignore link-locals.
	addrs, err := devicenetwork.IfindexToAddrs(ifindex)
	if err != nil {
		log.Warnf("IfIndexToAddrs failed: %s\n", err)
		addrs = nil
	}
	for _, addr := range addrs {
		log.Infof("found addr %s\n", addr.String())
		if addr.To4() != nil {
			return addr.String(), nil
		}
	}
	log.Infof("No IPv4 address on %s yet\n", status.Port)
	return "", nil
}

func setBridgeIPAddr(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("setBridgeIPAddr(%s-%s)\n",
		status.DisplayName, status.Key())

	if status.BridgeName == "" {
		// Called too early
		log.Infof("setBridgeIPAddr: don't yet have a bridgeName for %s\n",
			status.UUID)
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
	log.Infof("Bridge: %s, Link: %+v\n", status.BridgeName, link)

	var ipAddr string
	var err error

	switch status.Type {
	case types.NetworkInstanceTypeSwitch:
		ipAddr, err = getPortIPv4Addr(ctx, status)
		if err != nil {
			log.Errorf("setBridgeIPAddr: getPortIPv4Addr failed: %s\n",
				err)
			return err
		}
		log.Infof("Bridge: %s, Link: %s, ipAddr: %s\n",
			status.BridgeName, link, ipAddr)
	case types.NetworkInstanceTypeMesh:
		status.Ipv4Eid = (status.Subnet.IP != nil && status.Subnet.IP.To4() != nil)
		if status.Ipv4Eid {
			// Require an IPv4 gateway
			if status.Gateway == nil {
				errStr := fmt.Sprintf("No IPv4 gateway for bridge %s network %s subnet %s",
					status.BridgeName, status.Key(),
					status.Subnet.String())
				return errors.New(errStr)
			}
			ipAddr = status.Gateway.String()
			log.Infof("setBridgeIPAddr: Bridge %s assigned IPv4 EID %s",
				status.BridgeName, ipAddr)
		} else {
			ipAddr = "fd00::" + strconv.FormatInt(int64(status.BridgeNum), 16)
			log.Infof("setBridgeIPAddr: Bridge %s assigned IPv6 EID %s",
				status.BridgeName, ipAddr)
		}
	}

	// If not we do a local allocation
	// Assign the gateway Address as the bridge IP address
	if ipAddr == "" {
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
			status.IPAssignments[bridgeMac.String()] = status.Gateway
		}
		log.Infof("BridgeMac: %s, ipAddr: %s\n",
			bridgeMac.String(), ipAddr)
	}
	status.BridgeIPAddr = ipAddr
	publishNetworkInstanceStatus(ctx, status)
	log.Infof("Published NetworkStatus. BridgeIpAddr: %s\n",
		status.BridgeIPAddr)

	if status.BridgeIPAddr == "" {
		log.Infof("Does not yet have a bridge IP address for %s\n",
			status.Key())
		return nil
	}

	prefixLen := getPrefixLenForBridgeIP(status)
	if err = doConfigureIpAddrOnInterface(ipAddr, prefixLen, link); err != nil {
		log.Errorf("Failed to configure IPAddr on Interface\n")
		return err
	}

	// Create new radvd configuration and restart radvd if ipv6
	if status.IsIPv6() {
		log.Infof("Restart Radvd\n")
		restartRadvdWithNewConfig(status.BridgeName)
	}
	return nil
}

// updateBridgeIPAddr
// 	Called a bridge service has been added/updated/deleted
func updateBridgeIPAddr(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Infof("updateBridgeIPAddr(%s)\n", status.Key())

	old := status.BridgeIPAddr
	err := setBridgeIPAddr(ctx, status)
	if err != nil {
		log.Infof("updateBridgeIPAddr: %s\n", err)
		return
	}
	if status.BridgeIPAddr != old && status.BridgeIPAddr != "" {
		log.Infof("updateBridgeIPAddr(%s) restarting dnsmasq\n",
			status.Key())
		restartDnsmasq(ctx, status)
	}
}

// maybeUpdateBridgeIPAddr
// 	Find ifname as a bridge Port and see if it can be updated
func maybeUpdateBridgeIPAddr(
	ctx *zedrouterContext,
	ifname string) {

	status := getSwitchNetworkInstanceUsingPort(ctx, ifname)
	if status == nil {
		return
	}
	log.Infof("maybeUpdateBridgeIPAddr: found "+
		"NetworkInstance %s", status.DisplayName)

	if !status.Activated {
		log.Errorf("maybeUpdateBridgeIPAddr: "+
			"network instance %s not activated\n", status.DisplayName)
		return
	}
	updateBridgeIPAddr(ctx, status)
	return
}

// doNetworkInstanceActivate
func doNetworkInstanceActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("doNetworkInstanceActivate NetworkInstance key %s type %d\n",
		status.UUID, status.Type)

	// Check that Port is either "uplink", "freeuplink", or
	// an existing port name assigned to domO/zedrouter.
	// A Bridge only works with a single adapter interface.
	// Management ports are not allowed to be part of Switch networks.
	err := checkPortAvailable(ctx, status)
	if err != nil {
		log.Errorf("checkPortAvailable failed: Port: %s, err:%s",
			status.CurrentUplinkIntf, err)
		return err
	}

	// Get a list of IfNames to the ones we have an ifIndex for.
	status.IfNameList = getIfNameListForPort(ctx, status.CurrentUplinkIntf)
	log.Infof("IfNameList: %+v", status.IfNameList)

	switch status.Type {
	case types.NetworkInstanceTypeSwitch:
		err = bridgeActivate(ctx, status)
		if err != nil {
			updateBridgeIPAddr(ctx, status)
		}
	case types.NetworkInstanceTypeLocal:
		err = natActivate(ctx, status)
	case types.NetworkInstanceTypeCloud:
		err = vpnActivate(ctx, status)
	case types.NetworkInstanceTypeMesh:
		err = lispActivate(ctx, status)
	default:
		errStr := fmt.Sprintf("doNetworkInstanceActivate: NetworkInstance %d not yet supported",
			status.Type)
		err = errors.New(errStr)
	}
	// setup the ACLs for the bridge
	// Here we explicitly adding the iptables rules, to the bottom of the
	// rule chains, which are tied to the Linux bridge itself and not the
	//  rules for any specific domU vifs.
	aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: status.BridgeName,
		BridgeIP: status.BridgeIPAddr, NIType: status.Type, UpLinks: status.IfNameList}
	handleNetworkInstanceACLConfiglet("-A", aclArgs)
	return err
}

// getIfNameListForPort
// Get a list of IfNames to the ones we have an ifIndex for.
// In the case where the port maps to multiple underlying ports
// (For Ex: uplink), only include ports that have an ifindex.
//	If there is no such port with ifindex, then retain the whole list.
//	NetworkInstance creation will fail when programming default routes
//  and iptable rules in that case - and that should be fine.
func getIfNameListForPort(
	ctx *zedrouterContext,
	port string) []string {

	ifNameList := adapterToIfNames(ctx, port)
	log.Infof("ifNameList: %+v", ifNameList)

	filteredList := make([]string, 0)
	for _, ifName := range ifNameList {
		dnsPort := ctx.deviceNetworkStatus.GetPortByIfName(ifName)
		if dnsPort != nil {
			// XXX - We have a bug in MakeDeviceNetworkStatus where we are allowing
			//	a device without the corresponding linux interface. We can
			//	remove this check for ifindex here when the MakeDeviceStatus
			//	is fixed.
			// XXX That bug has been fixed. Retest without this code?
			ifIndex, err := devicenetwork.IfnameToIndex(ifName)
			if err == nil {
				log.Infof("ifName %s, ifindex: %d added to filteredList",
					ifName, ifIndex)
				filteredList = append(filteredList, ifName)
			} else {
				log.Infof("ifIndex not found for ifName(%s) - err: %s",
					ifName, err.Error())
			}
		} else {
			log.Infof("DeviceNetworkStatus not found for port(%s)", port)
		}
	}
	if len(filteredList) > 0 {
		log.Infof("filteredList: %+v", filteredList)
		return filteredList
	}
	log.Infof("ifname or ifindex not found for any interface for port(%s)."+
		"Returning the unfiltered list: %+v", port, ifNameList)
	return ifNameList
}

func doNetworkInstanceInactivate(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Infof("doNetworkInstanceInactivate NetworkInstance key %s type %d\n",
		status.UUID, status.Type)

	bridgeInactivateforNetworkInstance(ctx, status)
	switch status.Type {
	case types.NetworkInstanceTypeLocal:
		natInactivate(ctx, status, false)
	case types.NetworkInstanceTypeCloud:
		vpnInactivate(ctx, status)
	case types.NetworkInstanceTypeMesh:
		lispInactivate(ctx, status)
	}

	return
}

func doNetworkInstanceDelete(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Infof("doNetworkInstanceDelete NetworkInstance key %s type %d\n",
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

	doBridgeAclsDelete(ctx, status)
	if status.BridgeName != "" {
		stopDnsmasq(status.BridgeName, false, false)

		if status.IsIPv6() {
			stopRadvd(status.BridgeName, true)
		}
		DNSStopMonitor(status.BridgeNum)
	}
	networkInstanceBridgeDelete(ctx, status)
}

func lookupNetworkInstanceConfig(ctx *zedrouterContext, key string) *types.NetworkInstanceConfig {

	sub := ctx.subNetworkInstanceConfig
	c, _ := sub.Get(key)
	if c == nil {
		return nil
	}
	config := cast.CastNetworkInstanceConfig(c)
	if config.Key() != key {
		log.Errorf("lookupNetworkInstanceConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func lookupNetworkInstanceStatus(ctx *zedrouterContext, key string) *types.NetworkInstanceStatus {
	pub := ctx.pubNetworkInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := cast.CastNetworkInstanceStatus(st)
	return &status
}

func lookupNetworkInstanceMetrics(ctx *zedrouterContext, key string) *types.NetworkInstanceMetrics {
	pub := ctx.pubNetworkInstanceMetrics
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := cast.CastNetworkInstanceMetrics(st)
	if status.Key() != key {
		log.Errorf("lookupNetworkInstanceMetrics key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
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
	netMetric := status.UpdateNetworkMetrics(nms)
	status.UpdateBridgeMetrics(nms, netMetric)

	netMetrics.MetricList = []types.NetworkMetric{*netMetric}
	niMetrics.NetworkMetrics = netMetrics
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
		status := cast.CastNetworkInstanceStatus(ni)
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

	pub := ctx.pubNetworkInstanceStatus
	pub.Publish(status.Key(), &status)
}

func publishNetworkInstanceMetrics(ctx *zedrouterContext,
	status *types.NetworkInstanceMetrics) {

	pub := ctx.pubNetworkInstanceMetrics
	pub.Publish(status.Key(), &status)
}

// ==== Bridge

func bridgeActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("bridgeActivate(%s)\n", status.DisplayName)

	bridgeLink, err := findBridge(status.BridgeName)
	if err != nil {
		errStr := fmt.Sprintf("findBridge(%s) failed %s",
			status.BridgeName, err)
		return errors.New(errStr)
	}
	// Find adapter
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, status.Port)
	alink, _ := netlink.LinkByName(ifname)
	if alink == nil {
		errStr := fmt.Sprintf("Unknown adapter %s, %s",
			status.Port, ifname)
		return errors.New(errStr)
	}
	// Make sure it is up
	//    ip link set ${adapter} up
	if err := netlink.LinkSetUp(alink); err != nil {
		errStr := fmt.Sprintf("LinkSetUp on %s failed: %s",
			status.Port, err)
		return errors.New(errStr)
	}
	// ip link set ${adapter} master ${bridge_name}
	if err := netlink.LinkSetMaster(alink, bridgeLink); err != nil {
		errStr := fmt.Sprintf("LinkSetMaster %s %s failed: %s",
			status.Port, status.BridgeName, err)
		return errors.New(errStr)
	}
	log.Infof("bridgeActivate: added %s to bridge %s\n",
		status.Port, status.BridgeName)
	return nil
}

func bridgeInactivateforNetworkInstance(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Infof("bridgeInactivateforNetworkInstance(%s)\n", status.DisplayName)
	// Find adapter
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, status.Port)
	alink, _ := netlink.LinkByName(ifname)
	if alink == nil {
		errStr := fmt.Sprintf("Unknown adapter %s, %s",
			status.Port, ifname)
		log.Errorln(errStr)
		return
	}
	// ip link set ${adapter} nomaster
	if err := netlink.LinkSetNoMaster(alink); err != nil {
		errStr := fmt.Sprintf("LinkSetNoMaster %s failed: %s",
			status.Port, err)
		log.Infoln(errStr)
		return
	}
	log.Infof("bridgeInactivateforNetworkInstance: removed %s from bridge\n",
		status.Port)
}

// ==== Lisp

func lispActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("lispActivate(%s)\n", status.DisplayName)

	// Create Lisp IID & map-server configlets
	iid := status.LispConfig.IID
	mapServers := status.LispConfig.MapServers
	cfgPathnameIID := lispRunDirname + "/" +
		strconv.FormatUint(uint64(iid), 10)
	file, err := os.Create(cfgPathnameIID)
	if err != nil {
		log.Errorf("lispActivate failed: %s ", err)
		return err
	}
	defer file.Close()

	// Write map-servers to configlet
	for _, ms := range mapServers {
		msConfigLine := fmt.Sprintf(lispMStemplate, iid,
			ms.NameOrIp, ms.Credential)
		file.WriteString(msConfigLine)
	}

	// Write Lisp IID template
	iidConfig := fmt.Sprintf(lispIIDtemplate, iid)
	file.WriteString(iidConfig)

	if status.Ipv4Eid {
		ipv4Network := status.Subnet.IP.Mask(status.Subnet.Mask)
		maskLen, _ := status.Subnet.Mask.Size()
		subnet := fmt.Sprintf("%s/%d",
			ipv4Network.String(), maskLen)
		file.WriteString(fmt.Sprintf(
			lispIPv4IIDtemplate, iid, subnet))
	}

	log.Infof("lispActivate(%s)\n", status.DisplayName)
	return nil
}

// ==== Nat

// XXX need to redo this when MgmtPorts/FreeMgmtPorts changes?
func natActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("natActivate(%s)\n", status.DisplayName)
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
		log.Infof("Adding iptables rules for %s \n", a)
		err := iptables.IptableCmd("-t", "nat", "-A", "POSTROUTING", "-o", a,
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
	}
	// Add to Pbr table
	err := PbrNATAdd(subnetStr)
	if err != nil {
		log.Errorf("PbrNATAdd failed for port %s - err = %s\n",
			status.CurrentUplinkIntf, err)
		return err
	}
	return nil
}

func lispInactivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {
	// Go through the AppNetworkConfigs and delete Lisp parameters
	// that use this service.
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()

	// When service is deactivated we should delete IID and map-server
	// configuration also
	cfgPathnameIID := lispRunDirname + "/" +
		strconv.FormatUint(uint64(status.LispStatus.IID), 10)
	if err := os.Remove(cfgPathnameIID); err != nil {
		log.Errorln(err)
	}

	for _, ans := range items {
		appNetStatus := cast.CastAppNetworkStatus(ans)
		if len(appNetStatus.OverlayNetworkList) == 0 {
			continue
		}
		for _, olStatus := range appNetStatus.OverlayNetworkList {
			if olStatus.Network == status.UUID {
				// Pass global deviceNetworkStatus
				deleteLispConfiglet(lispRunDirname, false,
					status.LispStatus.IID, olStatus.EID,
					olStatus.AppIPAddr,
					*ctx.deviceNetworkStatus,
					ctx.legacyDataPlane)
			}
		}
	}

	log.Infof("lispInactivate(%s)\n", status.DisplayName)
}

func natInactivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus, inActivateOld bool) {

	log.Infof("natInactivate(%s)\n", status.DisplayName)
	subnetStr := status.Subnet.String()
	var oldUplinkIntf string
	if inActivateOld {
		oldUplinkIntf = status.PrevUplinkIntf
	} else {
		oldUplinkIntf = status.CurrentUplinkIntf
	}
	err := iptables.IptableCmd("-t", "nat", "-D", "POSTROUTING", "-o", oldUplinkIntf,
		"-s", subnetStr, "-j", "MASQUERADE")
	if err != nil {
		log.Errorf("natInactivate: iptableCmd failed %s\n", err)
	}
	err = PbrRouteDeleteAll(status.BridgeName, oldUplinkIntf)
	if err != nil {
		log.Errorf("natInactivate: PbrRouteDeleteAll failed %s\n", err)
	}
	// Remove from Pbr table
	err = PbrNATDel(subnetStr)
	if err != nil {
		log.Errorf("natInactivate: PbrNATDel failed %s\n", err)
	}
}

func natDelete(status *types.NetworkInstanceStatus) {

	log.Infof("natDelete(%s)\n", status.DisplayName)
}

func lookupNetworkInstanceStatusByBridgeName(ctx *zedrouterContext,
	bridgeName string) *types.NetworkInstanceStatus {

	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := cast.CastNetworkInstanceStatus(st)
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

	log.Infof("Vpn network instance create: %s\n", status.DisplayName)

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

	log.Infof("Vpn network instance delete: %s\n", status.DisplayName)
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

	log.Infof("Vpn network instance activate: %s\n", status.DisplayName)
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

	log.Infof("Vpn network instance inactivate: %s\n", status.DisplayName)
	vpnConfig, err := strongSwanVpnStatusParse(status.OpaqueStatus)
	if err != nil {
		log.Warnf("Vpn network instance inactivate: %v\n", err.Error())
	}

	if err := strongSwanVpnInactivate(vpnConfig); err != nil {
		log.Warnf("Vpn network instance inactivate: %v\n", err.Error())
	}
}

// adapterToIfNames
//	XXX - Probably should move this to ZedRouter.go as a method
//		of zedRouterContext
// Expand the generic names, and return the interface name
// Does not verify the existence of the adapters/interfaces
func adapterToIfNames(ctx *zedrouterContext, adapter string) []string {
	if strings.EqualFold(adapter, "uplink") {
		return types.GetMgmtPortsAny(*ctx.deviceNetworkStatus, 0)
	}
	if strings.EqualFold(adapter, "freeuplink") {
		return types.GetMgmtPortsFree(*ctx.deviceNetworkStatus, 0)
	}
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, adapter)
	if len(ifname) == 0 {
		return []string{}
	}
	return []string{ifname}
}

func vifNameToBridgeName(ctx *zedrouterContext, vifName string) string {

	pub := ctx.pubNetworkInstanceStatus
	instanceItems := pub.GetAll()
	for _, st := range instanceItems {
		status := cast.CastNetworkInstanceStatus(st)
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
		status := cast.CastNetworkInstanceStatus(st)
		if !status.IsUsingPort(ifname) {
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

func checkAndReprogramNetworkInstances(ctx *zedrouterContext) {
	pub := ctx.pubNetworkInstanceStatus
	instanceItems := pub.GetAll()

	for _, instance := range instanceItems {
		status := cast.CastNetworkInstanceStatus(instance)

		if !status.NeedIntfUpdate || !status.Activated {
			continue
		}
		log.Infof("checkAndReprogramNetworkInstances: Changing Uplink to %s from %s for "+
			"network instance %s", status.CurrentUplinkIntf, status.PrevUplinkIntf,
			status.DisplayName)
		doNetworkInstanceFallback(ctx, &status)
	}
}

func doNetworkInstanceFallback(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("doNetworkInstanceFallback NetworkInstance key %s type %d\n",
		status.UUID, status.Type)

	// Get a list of IfNames to the ones we have an ifIndex for.
	status.IfNameList = getIfNameListForPort(ctx, status.CurrentUplinkIntf)
	log.Infof("IfNameList: %+v", status.IfNameList)

	switch status.Type {
	case types.NetworkInstanceTypeLocal:
		natInactivate(ctx, status, true)
		err := natActivate(ctx, status)
		status.NeedIntfUpdate = false
		publishNetworkInstanceStatus(ctx, status)
		if err != nil {
			return err
		}
		// Go through the list of all application connected to this network instance
		// and clear conntrack flows corresponding to them.
		apps := ctx.pubAppNetworkStatus.GetAll()
		// Find all app instances that use this network and purge flows
		// that correspond to these applications.
		for _, app := range apps {
			appNetworkStatus := cast.CastAppNetworkStatus(app)
			for i := range appNetworkStatus.UnderlayNetworkList {
				ulStatus := &appNetworkStatus.UnderlayNetworkList[i]
				if uuid.Equal(ulStatus.Network, status.UUID) {
					config := lookupAppNetworkConfig(ctx, appNetworkStatus.Key())
					ipsets := compileAppInstanceIpsets(ctx, config.OverlayNetworkList,
						config.UnderlayNetworkList)
					ulConfig := &config.UnderlayNetworkList[i]
					// This should take care of re-programming any ACL rules that
					// use input match on uplinks.
					doAppNetworkModifyUnderlayNetwork(
						ctx, &appNetworkStatus, ulConfig, ulStatus, ipsets, true)
				}
			}
			publishAppNetworkStatus(ctx, &appNetworkStatus)
		}
	case types.NetworkInstanceTypeCloud:
		// XXX Add support for Cloud network instance
	case types.NetworkInstanceTypeMesh:
		// XXX Add support for Mesh network instance
	}
	return nil
}
