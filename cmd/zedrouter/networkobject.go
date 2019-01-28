// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkObject

package zedrouter

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/eriknordmark/netlink"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"net"
	"strconv"
	"time"
)

func handleNetworkObjectModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	config := cast.CastNetworkObjectConfig(configArg)
	if config.Key() != key {
		log.Errorf("handleNetworkObjectModify key/UUID mismatch %s vs %s; ignored %+v\n", key, config.Key(), config)
		return
	}
	status := lookupNetworkObjectStatus(ctx, key)
	if status != nil {
		log.Infof("handleNetworkObjectModify(%s)\n", key)
		status.PendingModify = true
		publishNetworkObjectStatus(ctx, status)
		doNetworkModify(ctx, config, status)
		status.PendingModify = false
		publishNetworkObjectStatus(ctx, status)
		log.Infof("handleNetworkObjectModify(%s) done\n", key)
	} else {
		handleNetworkObjectCreate(ctx, key, config)
	}
}

func handleNetworkObjectCreate(ctx *zedrouterContext, key string, config types.NetworkObjectConfig) {
	log.Infof("handleNetworkObjectCreate(%s)\n", key)

	status := types.NetworkObjectStatus{
		NetworkObjectConfig: config,
		IPAssignments:       make(map[string]net.IP),
		DnsNameToIPList:     config.DnsNameToIPList,
	}
	status.PendingAdd = true
	publishNetworkObjectStatus(ctx, &status)
	err := doNetworkCreate(ctx, config, &status)
	if err != nil {
		log.Errorf("doNetworkCreate(%s) failed: %s\n", key, err)
		status.Error = err.Error()
		status.ErrorTime = time.Now()
		status.PendingAdd = false
		publishNetworkObjectStatus(ctx, &status)
		return
	}
	status.PendingAdd = false
	publishNetworkObjectStatus(ctx, &status)
	// Hooks for updating dependent objects
	checkAndRecreateAppNetwork(ctx, config.UUID)
	checkAndRecreateService(ctx, config.UUID)
	log.Infof("handleNetworkObjectCreate(%s) done\n", key)
}

func handleNetworkObjectDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleNetworkObjectDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	status := lookupNetworkObjectStatus(ctx, key)
	if status == nil {
		log.Infof("handleNetworkObjectDelete: unknown %s\n", key)
		return
	}
	status.PendingDelete = true
	publishNetworkObjectStatus(ctx, status)
	doNetworkDelete(ctx, status)
	status.PendingDelete = false
	publishNetworkObjectStatus(ctx, status)
	unpublishNetworkObjectStatus(ctx, status)
	log.Infof("handleNetworkObjectDelete(%s) done\n", key)
}

func doNetworkCreate(ctx *zedrouterContext, config types.NetworkObjectConfig,
	status *types.NetworkObjectStatus) error {

	log.Infof("doNetworkCreate NetworkObjectStatus key %s type %d\n",
		config.UUID, config.Type)

	Ipv4Eid := false
	// Check for valid types
	switch config.Type {
	case types.NT_IPV6:
		// Nothing to do
	case types.NT_IPV4:
		// Nothing to do
	case types.NT_CryptoEID:
		if config.Subnet.IP != nil {
			Ipv4Eid = (config.Subnet.IP.To4() != nil)
		}
	default:
		errStr := fmt.Sprintf("doNetworkCreate type %d not supported",
			config.Type)
		return errors.New(errStr)
	}

	// Allocate bridgeNum.
	bridgeNum := bridgeNumAllocate(ctx, config.UUID)
	bridgeName := fmt.Sprintf("bn%d", bridgeNum)
	status.BridgeNum = bridgeNum
	status.BridgeName = bridgeName
	status.Ipv4Eid = Ipv4Eid
	publishNetworkObjectStatus(ctx, status)

	// Create bridge

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
		return errors.New(errStr)
	}
	//    ip link set ${bridgeName} up
	if err := netlink.LinkSetUp(link); err != nil {
		errStr := fmt.Sprintf("LinkSetUp on %s failed: %s",
			bridgeName, err)
		return errors.New(errStr)
	}

	// Check if we have a bridge service
	if err := setBridgeIPAddr(ctx, status); err != nil {
		return err
	}

	// For the case of Lisp networks, we route all traffic coming from
	// the bridge to a dummy interface with MTU 1280. This is done to
	// get bigger packets fragmented and also to have the kernel generate
	// ICMP packet too big for path MTU discovery before being captured by
	// lisp dataplane.
	if config.Type == types.NT_CryptoEID {
		sattrs = netlink.NewLinkAttrs()
		sattrs.Name = dummyIntfName
		slinkMac := fmt.Sprintf("00:16:3e:06:01:%02x", bridgeNum)
		hw, err = net.ParseMAC(slinkMac)
		if err != nil {
			log.Fatal("doNetworkCreate: ParseMAC failed: ", slinkMac, err)
		}
		sattrs.HardwareAddr = hw
		// 1280 gives us a comfortable buffer to encapsulate
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
		if status.Ipv4Eid {
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
		iifIndex := link.Attrs().Index
		oifIndex := slink.Attrs().Index
		err = AddOverlayRuleAndRoute(bridgeName, iifIndex, oifIndex, ipnet)
		if err != nil {
			errStr := fmt.Sprintf(
				"doNetworkCreate: Lisp IP rule and route addition failed for bridge %s: %s",
				bridgeName, err)
			return errors.New(errStr)
		}
	}

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
		createDnsmasqConfiglet(bridgeName, status.BridgeIPAddr, &config,
			hostsDirpath, status.BridgeIPSets, status.Ipv4Eid)
		startDnsmasq(bridgeName)
	}

	var isIPv6 bool
	switch config.Type {
	case types.NT_IPV4:
		isIPv6 = false
	case types.NT_IPV6:
		isIPv6 = true
	case types.NT_CryptoEID:
		isIPv6 = !status.Ipv4Eid
	}
	if isIPv6 {
		// XXX do we need same logic as for IPv4 dnsmasq to not
		// advertize as default router? Might we need lower
		// radvd preference if isolated local network?

		// Write radvd configlet; start radvd; XXX shared
		cfgFilename := "radvd." + bridgeName + ".conf"
		cfgPathname := runDirname + "/" + cfgFilename

		//    Start clean; kill just in case
		//    pkill -u radvd -f radvd.${BRIDGENAME}.conf
		deleteRadvdConfiglet(cfgPathname)
		stopRadvd(cfgFilename, false)
		createRadvdConfiglet(cfgPathname, bridgeName)
		startRadvd(cfgPathname, bridgeName)
	}
	return nil
}

// Call when we have a network and a service?
func setBridgeIPAddr(ctx *zedrouterContext, status *types.NetworkObjectStatus) error {

	log.Infof("setBridgeIPAddr for %s\n", status.Key())
	if status.BridgeName == "" {
		// Called too early
		log.Infof("setBridgeIPAddr: don't yet have a bridgeName for %s\n",
			status.UUID)
		return nil
	}

	link, _ := netlink.LinkByName(status.BridgeName)
	if link == nil {
		errStr := fmt.Sprintf("Unknown adapter %s", status.BridgeName)
		return errors.New(errStr)
	}
	// Check if we have a bridge service, and if so return error or address
	st, _, err := getServiceInfo(ctx, status.UUID)
	if err != nil {
		// There might not be a service associated with this network
		// or it might not yet have arrived. In either case we
		// don't treat it as a bridge service.
		log.Errorf("setBridgeIPAddr: getServiceInfo failed: %s\n",
			err)
	}
	var ipAddr string
	switch st {
	case types.NST_BRIDGE:
		ipAddr, err = getBridgeServiceIPv4Addr(ctx, status.UUID)
		if err != nil {
			log.Infof("setBridgeIPAddr: getBridgeServiceIPv4Addr failed: %s\n",
				err)
			return err
		}
	}

	// Unlike bridge service Lisp will not need a service now for
	// generating ip address.
	// So we check the type of the network instead of the type of the
	// service

	if status.Type == types.NT_CryptoEID {
		if status.Subnet.IP != nil && status.Subnet.IP.To4() != nil {
			// Require an IPv4 gateway
			if status.Gateway == nil {
				errStr := fmt.Sprintf("No IPv4 gateway for bridge %s network %s subnet %s",
					status.BridgeName, status.Key(),
					status.Subnet.String())
				return errors.New(errStr)
			}
			ipAddr = status.Gateway.String()
			log.Infof("setBridgeIPAddr: Bridge %s assigned IPv4 EID %s\n",
				status.BridgeName, ipAddr)
			status.Ipv4Eid = true
		} else {
			ipAddr = "fd00::" + strconv.FormatInt(int64(status.BridgeNum), 16)
			log.Infof("setBridgeIPAddr: Bridge %s assigned IPv6 EID %s\n",
				status.BridgeName, ipAddr)
		}
	}

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
		log.Infof("setBridgeIPAddr lookupOrAllocate for %s\n",
			bridgeMac.String())

		ipAddr, err = lookupOrAllocateIPv4(ctx, status, bridgeMac)
		if err != nil {
			errStr := fmt.Sprintf("lookupOrAllocateIPv4 failed: %s",
				err)
			return errors.New(errStr)
		}
	}
	status.BridgeIPAddr = ipAddr
	publishNetworkObjectStatus(ctx, status)

	if status.BridgeIPAddr == "" {
		log.Infof("Does not yet have a bridge IP address for %s\n",
			status.Key())
		return nil
	}

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		errStr := fmt.Sprintf("setBridgeIPAddr ParseIP failed for %s: %s",
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
		cfgFilename := "radvd." + status.BridgeName + ".conf"
		cfgPathname := runDirname + "/" + cfgFilename

		// kill existing radvd instance
		deleteRadvdConfiglet(cfgPathname)
		stopRadvd(cfgFilename, false)
		createRadvdConfiglet(cfgPathname, status.BridgeName)
		startRadvd(cfgPathname, status.BridgeName)
	}

	return nil
}

// Returns an IP address as a string, or "" if not found.
func lookupOrAllocateIPv4(ctx *zedrouterContext,
	status *types.NetworkObjectStatus, mac net.HardwareAddr) (string, error) {

	log.Infof("lookupOrAllocateIPv4(%s)\n", mac.String())
	// Lookup to see if it exists
	if ip, ok := status.IPAssignments[mac.String()]; ok {
		log.Infof("lookupOrAllocateIPv4(%s) found %s\n",
			mac.String(), ip.String())
		return ip.String(), nil
	}

	log.Infof("lookupOrAllocateIPv4 status: %s dhcp %d bridgeName %s Subnet %v range %v-%v\n",
		status.Key(), status.Dhcp, status.BridgeName,
		status.Subnet, status.DhcpRange.Start, status.DhcpRange.End)

	if status.Dhcp == types.DT_PASSTHROUGH {
		// XXX do we have a local IP? If so caller would have found it
		// Might appear later
		return "", nil
	}

	if status.Dhcp != types.DT_SERVER {
		errStr := fmt.Sprintf("Unsupported DHCP type %d for %s",
			status.Dhcp, status.Key())
		return "", errors.New(errStr)
	}

	if status.DhcpRange.Start == nil {
		errStr := fmt.Sprintf("no NetworkOjectStatus DhcpRange for %s",
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
		if lookupIP(status, a) {
			a = addToIP(a, 1)
			continue
		}
		log.Infof("lookupOrAllocateIPv4(%s) found free %s\n",
			mac.String(), a.String())
		status.IPAssignments[mac.String()] = a
		// Publish the allocation
		publishNetworkObjectStatus(ctx, status)
		return a.String(), nil
	}
	errStr := fmt.Sprintf("lookupOrAllocateIPv4(%s) no free address in DhcpRange",
		status.Key())
	return "", errors.New(errStr)
}

func releaseIPv4(ctx *zedrouterContext,
	status *types.NetworkObjectStatus, mac net.HardwareAddr) error {

	log.Infof("releaseIPv4(%s)\n", mac.String())
	// Lookup to see if it exists
	if _, ok := status.IPAssignments[mac.String()]; !ok {
		errStr := fmt.Sprintf("releaseIPv4: not found %s for %s",
			mac.String(), status.Key())
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	delete(status.IPAssignments, mac.String())
	publishNetworkObjectStatus(ctx, status)
	return nil
}

// Returns true if found
func lookupIP(status *types.NetworkObjectStatus, ip net.IP) bool {
	for _, a := range status.IPAssignments {
		if ip.Equal(a) {
			return true
		}
	}
	return false
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

func lookupNetworkObjectConfig(ctx *zedrouterContext, key string) *types.NetworkObjectConfig {

	sub := ctx.subNetworkObjectConfig
	c, _ := sub.Get(key)
	if c == nil {
		return nil
	}
	config := cast.CastNetworkObjectConfig(c)
	if config.Key() != key {
		log.Errorf("lookupNetworkObjectConfig: key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func lookupNetworkObjectStatus(ctx *zedrouterContext, key string) *types.NetworkObjectStatus {

	pub := ctx.pubNetworkObjectStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := cast.CastNetworkObjectStatus(st)
	if status.Key() != key {
		log.Errorf("lookupNetworkObjectStatus: key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func lookupNetworkObjectStatusByBridgeName(ctx *zedrouterContext, bridgeName string) *types.NetworkObjectStatus {

	pub := ctx.pubNetworkObjectStatus
	items := pub.GetAll()
	for _, st := range items {
		status := cast.CastNetworkObjectStatus(st)
		if status.BridgeName == bridgeName {
			return &status
		}
	}
	return nil
}

func networkObjectType(ctx *zedrouterContext, bridgeName string) types.NetworkType {
	status := lookupNetworkObjectStatusByBridgeName(ctx, bridgeName)
	if status == nil {
		return 0
	}
	return status.Type
}

// Called from service code when a bridge service has been added/updated/deleted
func updateBridgeIPAddr(ctx *zedrouterContext, status *types.NetworkObjectStatus) {
	log.Infof("updateBridgeIPAddr(%s)\n", status.Key())

	old := status.BridgeIPAddr
	err := setBridgeIPAddr(ctx, status)
	if err != nil {
		log.Infof("updateBridgeIPAddr: %s\n", err)
		return
	}
	if status.BridgeIPAddr != old && status.BridgeIPAddr != "" {
		config := lookupNetworkObjectConfig(ctx, status.Key())
		if config == nil {
			log.Infof("updateBridgeIPAddr: no config for %s\n",
				status.Key())
			return
		}
		log.Infof("updateBridgeIPAddr(%s) restarting dnsmasq\n",
			status.Key())
		bridgeName := status.BridgeName
		deleteDnsmasqConfiglet(bridgeName)
		stopDnsmasq(bridgeName, false)

		hostsDirpath := globalRunDirname + "/hosts." + bridgeName
		// XXX arbitrary name "router"!!
		addToHostsConfiglet(hostsDirpath, "router",
			[]string{status.BridgeIPAddr})

		// Use existing BridgeIPSets
		createDnsmasqConfiglet(bridgeName, status.BridgeIPAddr,
			config, hostsDirpath, status.BridgeIPSets,
			status.Ipv4Eid)
		startDnsmasq(bridgeName)
	}
}

func doNetworkModify(ctx *zedrouterContext, config types.NetworkObjectConfig,
	status *types.NetworkObjectStatus) {

	log.Infof("doNetworkModify NetworkObjectStatus key %s\n", config.UUID)
	if config.Type != status.Type {
		errStr := fmt.Sprintf("doNetworkModify NetworkObjectStatus can't change key %s",
			config.UUID)
		log.Errorln(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		return
	}

	// Update ipsets and dns hosts.

	bridgeName := status.BridgeName
	if bridgeName != "" && status.BridgeIPAddr != "" {
		hostsDirpath := globalRunDirname + "/hosts." + bridgeName
		updateHostsConfiglet(hostsDirpath, status.DnsNameToIPList,
			config.DnsNameToIPList)

		pub := ctx.pubAppNetworkStatus
		items := pub.GetAll()
		for _, ans := range items {
			appNetStatus := cast.CastAppNetworkStatus(ans)
			for _, olStatus := range appNetStatus.OverlayNetworkList {
				if olStatus.Network != status.UUID {
					continue
				}
				updateDefaultIpsetConfiglet(olStatus.Vif,
					status.DnsNameToIPList,
					config.DnsNameToIPList)
			}
			for _, ulStatus := range appNetStatus.UnderlayNetworkList {
				if ulStatus.Network != status.UUID {
					continue
				}
				updateDefaultIpsetConfiglet(ulStatus.Vif,
					status.DnsNameToIPList,
					config.DnsNameToIPList)
			}
		}
	}
	// Update other fields; potentially useful for testing
	status.NetworkObjectConfig = config
	log.Infof("doNetworkModify DONE key %s\n", config.UUID)
}

func doNetworkDelete(ctx *zedrouterContext,
	status *types.NetworkObjectStatus) {
	log.Infof("doNetworkDelete NetworkObjectStatus key %s type %d\n",
		status.UUID, status.Type)

	if status.BridgeName == "" {
		return
	}
	bridgeName := status.BridgeName

	// Delete ACLs attached to this network aka linux bridge
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, ans := range items {
		appNetStatus := cast.CastAppNetworkStatus(ans)
		for _, olStatus := range appNetStatus.OverlayNetworkList {
			if olStatus.Network != status.UUID {
				continue
			}
			err := deleteACLConfiglet(olStatus.Bridge,
				olStatus.Vif, false, olStatus.ACLs,
				olStatus.BridgeIPAddr,
				olStatus.EID.String())
			if err != nil {
				log.Errorf("doNetworkDelete ACL failed: %s\n",
					err)
			}
		}
		for _, ulStatus := range appNetStatus.UnderlayNetworkList {
			if ulStatus.Network != status.UUID {
				continue
			}
			err := deleteACLConfiglet(ulStatus.Bridge,
				ulStatus.Vif, false, ulStatus.ACLs,
				ulStatus.BridgeIPAddr, ulStatus.AssignedIPAddr)
			if err != nil {
				log.Infof("doNetworkDelete ACL failed: %s\n",
					err)
			}
		}
	}

	// When bridge and sister interfaces are deleted, code in pbr.go
	// takes care of deleting the corresponding route tables and ip rules.
	if status.Type == types.NT_CryptoEID {

		// "s" for sister
		dummyIntfName := "s" + bridgeName

		// Delete the sister dummy interface also
		sattrs := netlink.NewLinkAttrs()
		sattrs.Name = dummyIntfName
		sLink := &netlink.Dummy{LinkAttrs: sattrs}
		netlink.LinkDel(sLink)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = bridgeName
	link := &netlink.Bridge{LinkAttrs: attrs}
	// Remove link and associated addresses
	netlink.LinkDel(link)

	deleteDnsmasqConfiglet(bridgeName)
	stopDnsmasq(bridgeName, true)

	// For IPv6 and LISP, but LISP will become a service
	isIPv6 := false
	// BridgeIPAddr might not be set
	if status.BridgeIPAddr != "" {
		ip := net.ParseIP(status.BridgeIPAddr)
		if ip != nil {
			isIPv6 = (ip.To4() == nil)
		}
	}
	if isIPv6 {
		// radvd cleanup
		cfgFilename := "radvd." + bridgeName + ".conf"
		cfgPathname := runDirname + "/" + cfgFilename
		stopRadvd(cfgFilename, true)
		deleteRadvdConfiglet(cfgPathname)
	}

	status.BridgeName = ""
	status.BridgeNum = 0
	bridgeNumFree(ctx, status.UUID)
}

func findVifInBridge(status *types.NetworkObjectStatus, vifName string) bool {
	for _, vif := range status.Vifs {
		if vif.Name == vifName {
			return true
		}
	}
	return false
}

func addVifToBridge(status *types.NetworkObjectStatus, vifName string,
	appMac string, appID uuid.UUID) {

	log.Infof("addVifToBridge(%s, %s, %s, %s)\n",
		status.BridgeName, vifName, appMac, appID.String())
	if findVifInBridge(status, vifName) {
		log.Errorf("addVifToBridge(%s, %s) exists\n",
			status.BridgeName, vifName)
		return
	}
	info := types.VifNameMac{
		Name:    vifName,
		MacAddr: appMac,
		AppID:   appID,
	}
	status.Vifs = append(status.Vifs, info)
}

func removeVifFromBridge(status *types.NetworkObjectStatus, vifName string) {

	log.Infof("removeVifFromBridge(%s, %s)\n", status.BridgeName, vifName)
	if !findVifInBridge(status, vifName) {
		log.Errorf("XXX removeVifFromBridge(%s, %s) not there\n",
			status.BridgeName, vifName)
		return
	}
	var vifs []types.VifNameMac
	for _, vif := range status.Vifs {
		if vif.Name != vifName {
			vifs = append(vifs, vif)
		}
	}
	status.Vifs = vifs
}

func vifNameToBridgeName(ctx *zedrouterContext, vifName string) string {

	pub := ctx.pubNetworkObjectStatus
	items := pub.GetAll()
	for _, st := range items {
		status := cast.CastNetworkObjectStatus(st)
		if findVifInBridge(&status, vifName) {
			return status.BridgeName
		}
	}
	return ""
}
