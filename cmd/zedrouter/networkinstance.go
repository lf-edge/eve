// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkInstance setup

package zedrouter

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/iptables"
	"github.com/zededa/go-provision/types"
)

// checkPortAvailableForNetworkInstance
//	A port can be used for NetworkInstance if the following are satisfied:
//	a) Port should be part of Device Port Config
//	b) For type switch, port should not be part of any other
// 			Network Instance
// Any device, which is not a port, can only be assigned as a
// directAttach device.
func checkPortAvailableForNetworkInstance(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	if status.Port == "" {
		log.Infof("Port not specified\n")
		return nil
	}
	log.Infof("NetworkInstance (name: %s), port: %s\n",
		status.DisplayName, status.Port)

	portStatus := ctx.deviceNetworkStatus.GetPortByName(status.Port)
	if portStatus == nil {
		errStr := fmt.Sprintf("PortStatus for %s not found\n", status.Port)
		return errors.New(errStr)
	}

	switch status.Type {
	case types.NetworkInstanceTypeSwitch:
		// Make sure it is not used by any other NetworkInstance
		for _, iterStatusEntry := range ctx.networkInstanceStatusMap {
			if status == iterStatusEntry {
				continue
			}
			if iterStatusEntry.IsUsingPort(status.Port) {
				errStr := fmt.Sprintf("Port %s already used by NetworkInstance %s-%s. "+
					"Cannot be used by Switch Network Instance %s-%s\n",
					status.Port, iterStatusEntry.UUID, iterStatusEntry.DisplayName,
					status.UUID, status.DisplayName)
				return errors.New(errStr)
			}
		}
	case types.NetworkInstanceTypeLocal:
		// Make sure it is not used by a NetworkInstance of type Switch
		for _, iterStatusEntry := range ctx.networkInstanceStatusMap {
			if status == iterStatusEntry {
				continue
			}
			if iterStatusEntry.IsUsingPort(status.Port) {
				if iterStatusEntry.Type == types.NetworkInstanceTypeSwitch {
					errStr := fmt.Sprintf("Port %s already used by "+
						"Switch NetworkInstance %s-%s. It cannot be used by "+
						"any other Network Instance\n",
						status.Port, iterStatusEntry.UUID, iterStatusEntry.DisplayName)
					return errors.New(errStr)
				}
				// Still iterate through all NetworkInstances. This particular one
				//	may have errored out or inactive. Make sure no Switch NI is
				//  using the Port.
			}
		}
	default:
	}
	return nil
}

// doCreateBridge
//		returns (error, bridgeMac-string)
func doCreateBridge(bridgeName string, bridgeNum int) (error, string) {
	// Start clean
	attrs := netlink.NewLinkAttrs()
	attrs.Name = bridgeName
	link := &netlink.Bridge{LinkAttrs: attrs}
	netlink.LinkDel(link)

	// Delete the sister dummy interface also
	sattrs := netlink.NewLinkAttrs()
	// "s" for sister
	dummyIntfName := "s" + bridgeName
	sattrs.Name = dummyIntfName
	sLink := &netlink.Dummy{LinkAttrs: sattrs}
	netlink.LinkDel(sLink)

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

	return nil, bridgeMac
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
	}
	status.IPAssignments = make(map[string]net.IP)

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

	if config.Activate {
		log.Infof("handleNetworkInstanceCreate: Activating network instance")
		err := doNetworkInstanceActivate(ctx, &status)
		if err != nil {
			log.Errorf("doNetworkInstanceActivate(%s) failed: %s\n", key, err)
			status.Error = err.Error()
			status.ErrorTime = time.Now()
		} else {
			log.Infof("Activated network instance %s %s", status.UUID, status.DisplayName)
			status.Activated = true
		}
	}
	status.ChangeInProgress = types.ChangeInProgressTypeNone
	publishNetworkInstanceStatus(ctx, &status)
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

	log.Infof("doNetworkInstanceCreate key %s, NetworkType: %d, IpType: %d\n",
		status.UUID, status.Type, status.IpType)

	//  Check NetworkInstanceType
	switch status.Type {
	case types.NetworkInstanceTypeLocal:
		// Nothing to do
	case types.NetworkInstanceTypeSwitch:
	default:
		err := fmt.Sprintf("Instance type %d not supported", status.Type)
		return errors.New(err)
	}

	// Check for valid types
	switch status.IpType {
	case types.AddressTypeIPV4:
		// Nothing to do
	case types.AddressTypeIPV6:
		// Nothing to do
	case types.AddressTypeCryptoIPV4:
		// Nothing to do
	case types.AddressTypeCryptoIPV6:
		// Nothing to do
	default:
		// This should have been caught in parsestatus.
		err := fmt.Sprintf("IpType %d not supported\n", status.IpType)
		return errors.New(err)
	}
	if err := checkPortAvailableForNetworkInstance(ctx, status); err != nil {
		return err
	}

	// Allocate bridgeNum.
	bridgeNum := bridgeNumAllocate(ctx, status.UUID)
	bridgeName := fmt.Sprintf("bn%d", bridgeNum)
	status.BridgeNum = bridgeNum
	status.BridgeName = bridgeName
	publishNetworkInstanceStatus(ctx, status)

	// Create bridge
	var err error
	bridgeMac := ""
	if err, bridgeMac = doCreateBridge(bridgeName, bridgeNum); err != nil {
		return err
	}
	status.BridgeMac = bridgeMac

	log.Infof("bridge created. BridgeMac: %s\n", bridgeMac)

	// Check if we have a bridge service
	if err := setBridgeIPAddrForNetworkInstance(ctx, status); err != nil {
		return err
	}
	log.Infof("IpAddress set for bridge\n")

	// XXX mov this before set??
	// Create a hosts directory for the new bridge
	// Directory is /var/run/zedrouter/hosts.${BRIDGENAME}
	hostsDirpath := globalRunDirname + "/hosts." + bridgeName
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
	stopDnsmasq(bridgeName, false)

	if status.BridgeIPAddr != "" {
		createDnsmasqConfigletForNetworkInstance(bridgeName,
			status.BridgeIPAddr, &status.NetworkInstanceConfig,
			hostsDirpath, status.BridgeIPSets, status.Ipv4Eid)
		startDnsmasq(bridgeName)
	}

	isIPv6 := false
	switch status.IpType {
	case types.AddressTypeIPV6:
		isIPv6 = true
	default:
		isIPv6 = false
	}

	if isIPv6 {
		// XXX do we need same logic as for IPv4 dnsmasq to not
		// advertize as default router? Might we need lower
		// radvd preference if isolated local network?
		restartRadvdWithNewConfig(status)
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

func restartDnsmasq(status *types.NetworkInstanceStatus) {
	bridgeName := status.BridgeName
	deleteDnsmasqConfiglet(bridgeName)
	stopDnsmasq(bridgeName, false)

	hostsDirpath := globalRunDirname + "/hosts." + bridgeName
	// XXX arbitrary name "router"!!
	addToHostsConfiglet(hostsDirpath, "router",
		[]string{status.BridgeIPAddr})

	// Use existing BridgeIPSets
	createDnsmasqConfigletForNetworkInstance(bridgeName, status.BridgeIPAddr,
		&status.NetworkInstanceConfig, hostsDirpath, status.BridgeIPSets,
		status.Ipv4Eid)
	startDnsmasq(bridgeName)
}

// Returns an IP address as a string, or "" if not found.
func lookupOrAllocateIPv4ForNetworkInstance(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus,
	mac net.HardwareAddr) (string, error) {

	log.Infof("lookupOrAllocateIPv4ForNetworkInstance(%s): mac:%s\n",
		status.DisplayName, mac.String())
	// Lookup to see if it exists
	if ip, ok := status.IPAssignments[mac.String()]; ok {
		log.Infof("lookupOrAllocateIPv4(%s) found %s\n",
			mac.String(), ip.String())
		return ip.String(), nil
	}

	log.Infof("lookupOrAllocateIPv4 status: %s bridgeName %s Subnet %v range %v-%v\n",
		status.Key(), status.BridgeName,
		status.Subnet, status.DhcpRange.Start, status.DhcpRange.End)

	if status.DhcpRange.Start == nil {
		errStr := fmt.Sprintf("no NetworkInstanceStatus DhcpRange for %s",
			status.Key())
		return "", errors.New(errStr)
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

// releaseIPv4ForNetworkInstance
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
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return "", err
	}
	// XXX Add IPv6 underlay; ignore link-locals.
	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		log.Infof("found addr %s\n", addr.IP.String())
		return addr.IP.String(), nil
	}
	log.Infof("IP address on %s yet\n", status.Port)
	return "", nil
}

// Call when we have a network and a service?
func setBridgeIPAddrForNetworkInstance(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("setBridgeIPAddrForNetworkInstance (NI UUIDL:%s, name: %s)\n",
		status.Key(), status.DisplayName)

	if status.BridgeName == "" {
		// Called too early
		log.Infof("setBridgeIPAddrForNetworkInstance: don't yet have a bridgeName for %s\n",
			status.UUID)
		return nil
	}

	link, _ := netlink.LinkByName(status.BridgeName)
	if link == nil {
		errStr := fmt.Sprintf("Unknown adapter %s", status.BridgeName)
		return errors.New(errStr)
	}

	var ipAddr string
	var err error
	switch status.Type {
	case types.NetworkInstanceTypeSwitch:
		ipAddr, err = getPortIPv4Addr(ctx, status)
		if err != nil {
			log.Errorf("setBridgeIPAddrForNetworkInstance: getBridgeServiceIPv4Addr failed: %s\n",
				err)
			return err
		}
	}

	// Unlike bridge service Lisp will not need a service now for
	// generating ip address.
	// So we check the type of the network instead of the type of the
	// service

	//if status.Type == types.NT_CryptoEID {
	//	if status.Subnet.IP != nil && status.Subnet.IP.To4() != nil {
	//		// Require an IPv4 gateway
	//		if status.Gateway == nil {
	//			errStr := fmt.Sprintf("No IPv4 gateway for bridge %s network %s subnet %s",
	//				status.BridgeName, status.Key(),
	//				status.Subnet.String())
	//			return errors.New(errStr)
	//		}
	//		ipAddr = status.Gateway.String()
	//		log.Infof("setBridgeIPAddrForNetworkInstance: Bridge %s assigned IPv4 EID %s\n",
	//			status.BridgeName, ipAddr)
	//		status.Ipv4Eid = true
	//	} else {
	//		ipAddr = "fd00::" + strconv.FormatInt(int64(status.BridgeNum), 16)
	//		log.Infof("setBridgeIPAddrForNetworkInstance: Bridge %s assigned IPv6 EID %s\n",
	//			status.BridgeName, ipAddr)
	//	}
	//}

	// If not we do a local allocation
	if ipAddr == "" {
		var bridgeMac net.HardwareAddr

		switch link.(type) {
		case *netlink.Bridge:
			// XXX always true?
			bridgeLink := link.(*netlink.Bridge)
			bridgeMac = bridgeLink.HardwareAddr
		default:
			errStr := fmt.Sprintf("Not a bridge %s",
				status.BridgeName)
			return errors.New(errStr)
		}
		log.Infof("setBridgeIPAddrForNetworkInstance lookupOrAllocate for %s\n",
			bridgeMac.String())

		ipAddr, err = lookupOrAllocateIPv4ForNetworkInstance(ctx, status, bridgeMac)
		if err != nil {
			errStr := fmt.Sprintf("lookupOrAllocateIPv4 failed: %s",
				err)
			return errors.New(errStr)
		}
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

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		errStr := fmt.Sprintf("setBridgeIPAddrForNetworkInstance ParseIP failed for %s: %s",
			ipAddr, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	isIPv6 := (ip.To4() == nil)
	var prefixLen int
	if status.Ipv4Eid {
		prefixLen = 32
	} else if status.Subnet.IP != nil {
		prefixLen, _ = status.Subnet.Mask.Size()
	} else if isIPv6 {
		prefixLen = 128
	} else {
		prefixLen = 24
	}
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

	// Create new radvd configuration and restart radvd if ipv6
	if isIPv6 {
		restartRadvdWithNewConfig(status)
	}
	return nil
}

// updateBridgeIPAddrForNetworkInstance
// 	Called a bridge service has been added/updated/deleted
func updateBridgeIPAddrForNetworkInstance(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Infof("updateBridgeIPAddrForNetworkInstance(%s)\n", status.Key())

	old := status.BridgeIPAddr
	err := setBridgeIPAddrForNetworkInstance(ctx, status)
	if err != nil {
		log.Infof("updateBridgeIPAddrForNetworkInstance: %s\n", err)
		return
	}
	if status.BridgeIPAddr != old && status.BridgeIPAddr != "" {
		log.Infof("updateBridgeIPAddrForNetworkInstance(%s) restarting dnsmasq\n",
			status.Key())
		restartDnsmasq(status)
	}
}

// maybeUpdateBridgeIPAddrForNetworkInstance
// 	Find ifname as a bridge Port and see if it can be updated
func maybeUpdateBridgeIPAddrForNetworkInstance(
	ctx *zedrouterContext,
	ifname string) {

	status := getSwitchNetworkInstanceUsingPort(ctx, ifname)
	if status == nil {
		return
	}
	log.Infof("maybeUpdateBridgeIPAddrForNetworkInstance: found \n"+
		"NetworkInstance %s", status.DisplayName)

	if !status.Activated {
		log.Errorf("maybeUpdateBridgeIPAddrForNetworkInstance: "+
			"network instance %s not activated\n", status.DisplayName)
		return
	}
	updateBridgeIPAddrForNetworkInstance(ctx, status)
	return
}

func validatePortForNetworkInstance(ctx *zedrouterContext, port string,
	allowMgmtPort bool) error {

	if port == "" {
		log.Fatalf("validatePortForNetworkInstance - port not specified")
	}
	// XXX - I think we can get rid of these built-in labels.
	//	This will be cleaned up as part of support for deviceConfig
	//	from cloud.
	if allowMgmtPort {
		if strings.EqualFold(port, "uplink") {
			return nil
		}
		if strings.EqualFold(port, "freeuplink") {
			return nil
		}
	}

	portStatus := ctx.deviceNetworkStatus.GetPortByName(port)
	if portStatus == nil {
		errStr := fmt.Sprintf("portStatus not found for port %s", port)
		return errors.New(errStr)
	}
	log.Infof("Port %s valid for NetworkInstance", port)
	return nil
}

// doNetworkInstanceActivate
func doNetworkInstanceActivate(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("doNetworkInstanceActivate NetworkInstance key %s type %d\n",
		status.UUID, status.Type)

	// Check that Port is either "uplink", "freeuplink", or
	// an existing port name assigned to domO/zedrouter.
	// A Bridge only works with a single adapter interface.
	// Management ports are not allowed to be part of Bridge networks.
	allowMgmtPort := (status.Type != types.NetworkInstanceTypeSwitch)
	err := validatePortForNetworkInstance(ctx, status.Port, allowMgmtPort)
	if err != nil {
		log.Infof("validateAdaptor failed: Port: %s, err:%s", err, status.Port)
		return err
	}
	status.IfNameList = adapterToIfNames(ctx, status.Port)

	switch status.Type {
	case types.NetworkInstanceTypeSwitch:
		err = bridgeActivateForNetworkInstance(ctx, status)
		if err != nil {
			updateBridgeIPAddrForNetworkInstance(ctx, status)
		}
	case types.NetworkInstanceTypeLocal:
		err = natActivateForNetworkInstance(ctx, status)
	default:
		errStr := fmt.Sprintf("doNetworkInstanceActivate: NetworkInstance %d not yet supported",
			status.Type)
		err = errors.New(errStr)
	}
	return err
}

func doNetworkInstanceInactivate(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Infof("doNetworkInstanceInactivate NetworkInstance key %s type %d\n",
		status.UUID, status.Type)

	switch status.Type {
	case types.NetworkInstanceTypeSwitch:
		bridgeInactivateforNetworkInstance(ctx, status)
		updateBridgeIPAddrForNetworkInstance(ctx, status)
	case types.NetworkInstanceTypeLocal:
		natInactivateForNetworkInstance(ctx, status)
	default:
		errStr := fmt.Sprintf("doNetworkInstanceInactivate NetworkInstance %d not yet supported",
			status.Type)
		log.Infoln(errStr)
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
		natDeleteForNetworkInstance(status)
	default:
		errStr := fmt.Sprintf("doNetworkInstanceDelete NetworkInstance %d not yet supported",
			status.Type)
		log.Errorln(errStr)
	}
	return
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

	niMetrics := types.NetworkInstanceMetrics {
		UUIDandVersion: status.UUIDandVersion,
		DisplayName: status.DisplayName,
		Type: status.Type,
	}
	netMetrics := types.NetworkMetrics{}
	netMetric  := types.NetworkMetric{IfName: status.BridgeName}
	/*
	 * Tx/Rx of bridge is equal to the total of Tx/Rx on all member
	 * virtual interfaces excluding the bridge itself.
	 *
	 * Drops/Errors/AclDrops of bridge is equal to total of Drops/Errors/AclDrops
	 * on all member virtual interface including the bridge.
	 */
	for _, vif := range status.Vifs {
		metric, found := lookupNetworkMetrics(nms, vif.Name)
		if !found {
			log.Debugln("createNetworkInstanceMetrics: No metrics found for interface %s",
				vif.Name)
			continue
		}
		netMetric.TxBytes    += metric.TxBytes
		netMetric.RxBytes    += metric.RxBytes
		netMetric.TxPkts     += metric.TxPkts
		netMetric.RxPkts     += metric.RxPkts
		netMetric.TxErrors   += metric.TxErrors
		netMetric.RxErrors   += metric.RxErrors
		netMetric.TxDrops    += metric.TxDrops
		netMetric.RxDrops    += metric.RxDrops
		netMetric.TxAclDrops += metric.TxAclDrops
		netMetric.RxAclDrops += metric.RxAclDrops
		netMetric.TxAclRateLimitDrops += metric.TxAclRateLimitDrops
		netMetric.RxAclRateLimitDrops += metric.RxAclRateLimitDrops
	}
	// Get bridge metrics
	bridgeMetric, found := lookupNetworkMetrics(nms, status.BridgeName)
	if !found {
		log.Debugln("createNetworkInstanceMetrics: No metrics found for Bridge %s",
			status.BridgeName)
	} else {
		netMetric.TxErrors   += bridgeMetric.TxErrors
		netMetric.RxErrors   += bridgeMetric.RxErrors
		netMetric.TxDrops    += bridgeMetric.TxDrops
		netMetric.RxDrops    += bridgeMetric.RxDrops
		netMetric.TxAclDrops += bridgeMetric.TxAclDrops
		netMetric.RxAclDrops += bridgeMetric.RxAclDrops
		netMetric.TxAclRateLimitDrops += bridgeMetric.TxAclRateLimitDrops
		netMetric.RxAclRateLimitDrops += bridgeMetric.RxAclRateLimitDrops
	}

	netMetrics.MetricList = []types.NetworkMetric{netMetric}
	niMetrics.NetworkMetrics = netMetrics

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

// getBridgeServiceIPv4Addr
//	XXX - Do we need this function??
// 	Entrypoint from networkobject to look for a bridge's IPv4 address
func getBridgeServiceIPv4AddrForNetworkInstance(
	ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) (string, error) {

	log.Infof("getBridgeServiceIPv4Addr(%s)\n", status.DisplayName)

	if status.Type != types.NetworkInstanceTypeSwitch {
		errStr := fmt.Sprintf("getBridgeServiceIPv4AddrForNetworkInstance(%s): "+
			"service not a bridge; type %d",
			status.DisplayName, status.Type)
		return "", errors.New(errStr)
	}
	if status.Port == "" {
		log.Infof("getBridgeServiceIPv4AddrForNetworkInstance(%s): bridge but no Port\n",
			status.DisplayName)
		return "", nil
	}

	// Get IP address from Port
	ifname := types.AdapterToIfName(ctx.deviceNetworkStatus, status.Port)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return "", err
	}
	// XXX - We really should maintain these addresses in our own data structures
	//		and not query netlink. To be cleaned up.
	// XXX Add IPv6 underlay; ignore link-locals.
	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		log.Infof("getBridgeServiceIPv4AddrForNetworkInstance(%s): found addr %s\n",
			status.DisplayName, addr.IP.String())
		return addr.IP.String(), nil
	}
	log.Infof("getBridgeServiceIPv4AddrForNetworkInstance(%s): no IP address on %s yet\n",
		status.DisplayName, status.Port)
	return "", nil
}

func publishNetworkInstanceStatus(
	ctx *zedrouterContext,
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

func bridgeActivateForNetworkInstance(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("bridgeActivateForNetworkInstance(%s)\n", status.DisplayName)

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
	log.Infof("bridgeActivateForNetworkInstance: added %s to bridge %s\n",
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
		errStr := fmt.Sprintf("LinkSetMaster %s failed: %s",
			status.Port, err)
		log.Infoln(errStr)
		return
	}
	log.Infof("bridgeInactivateforNetworkInstance: removed %s from bridge\n",
		status.Port)
}

// ==== Nat

// XXX need to redo this when MgmtPorts/FreeMgmtPorts changes?
func natActivateForNetworkInstance(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) error {

	log.Infof("natActivateForNetworkInstance(%s)\n", status.DisplayName)
	if status.Subnet.IP == nil {
		errStr := fmt.Sprintf("Missing subnet for NAT service for %s",
			status.Key())
		return errors.New(errStr)
	}
	subnetStr := status.Subnet.String()

	for _, a := range status.IfNameList {
		err := iptables.IptableCmd("-t", "nat", "-A", "POSTROUTING", "-o", a,
			"-s", subnetStr, "-j", "MASQUERADE")
		if err != nil {
			return err
		}
		err = PbrRouteAddDefault(status.BridgeName, a)
		if err != nil {
			return err
		}
	}
	// Add to Pbr table
	err := PbrNATAdd(subnetStr)
	if err != nil {
		log.Errorf("PbrNATAdd failed for port %s - err = %s\n", status.Port, err)
		return err
	}
	return nil
}

func natInactivateForNetworkInstance(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) {

	log.Infof("natInactivateForNetworkInstance(%s)\n", status.DisplayName)
	subnetStr := status.Subnet.String()
	for _, a := range status.IfNameList {
		err := iptables.IptableCmd("-t", "nat", "-D", "POSTROUTING", "-o", a,
			"-s", subnetStr, "-j", "MASQUERADE")
		if err != nil {
			log.Errorf("natInactivateForNetworkInstance: iptableCmd failed %s\n", err)
		}
		err = PbrRouteDeleteDefault(status.BridgeName, a)
		if err != nil {
			log.Errorf("natInactivateForNetworkInstance: PbrRouteDeleteDefault failed %s\n", err)
		}
	}
	// Remove from Pbr table
	err := PbrNATDel(subnetStr)
	if err != nil {
		log.Errorf("natInactivateForNetworkInstance: PbrNATDel failed %s\n", err)
	}
}

func natDeleteForNetworkInstance(status *types.NetworkInstanceStatus) {

	log.Infof("natDeleteForNetworkInstance(%s)\n", status.DisplayName)
}
