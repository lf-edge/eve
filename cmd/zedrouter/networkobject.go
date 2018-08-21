// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkObject

package zedrouter

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"log"
	"net"
	"strconv"
	"time"
)

func handleNetworkObjectModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	config := cast.CastNetworkObjectConfig(configArg)
	if config.Key() != key {
		log.Printf("handleNetworkObjectModify key/UUID mismatch %s vs %s; ignored %+v\n", key, config.Key(), config)
		return
	}
	status := lookupNetworkObjectStatus(ctx, key)
	if status != nil {
		log.Printf("handleNetworkObjectModify(%s)\n", key)
		status.PendingModify = true
		publishNetworkObjectStatus(ctx, status)
		doNetworkModify(ctx, config, status)
		status.PendingModify = false
		publishNetworkObjectStatus(ctx, status)
		log.Printf("handleNetworkObjectModify(%s) done\n", key)
	} else {
		handleNetworkObjectCreate(ctx, key, config)
	}
}

func handleNetworkObjectCreate(ctx *zedrouterContext, key string, config types.NetworkObjectConfig) {
	log.Printf("handleNetworkObjectCreate(%s)\n", key)

	status := types.NetworkObjectStatus{
		NetworkObjectConfig: config,
		IPAssignments:       make(map[string]net.IP),
		DnsNameToIPList:     config.ZedServConfig.NameToEidList,
	}
	status.PendingAdd = true
	publishNetworkObjectStatus(ctx, &status)
	err := doNetworkCreate(ctx, config, &status)
	if err != nil {
		log.Printf("doNetworkCreate(%s) failed: %s\n", key, err)
		status.Error = err.Error()
		status.ErrorTime = time.Now()
		status.PendingAdd = false
		publishNetworkObjectStatus(ctx, &status)
		return
	}
	status.PendingAdd = false
	publishNetworkObjectStatus(ctx, &status)
	log.Printf("handleNetworkObjectCreate(%s) done\n", key)
}

func handleNetworkObjectDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Printf("handleNetworkObjectDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	status := lookupNetworkObjectStatus(ctx, key)
	if status == nil {
		log.Printf("handleNetworkObjectDelete: unknown %s\n", key)
		return
	}
	status.PendingDelete = true
	publishNetworkObjectStatus(ctx, status)
	doNetworkDelete(ctx, status)
	status.PendingDelete = false
	publishNetworkObjectStatus(ctx, status)
	unpublishNetworkObjectStatus(ctx, status)
	log.Printf("handleNetworkObjectDelete(%s) done\n", key)
}

func doNetworkCreate(ctx *zedrouterContext, config types.NetworkObjectConfig,
	status *types.NetworkObjectStatus) error {

	log.Printf("doNetworkCreate NetworkObjectStatus key %s type %d\n",
		config.UUID, config.Type)

	// Check for valid types
	switch config.Type {
	case types.NT_IPV6:
		// Nothing to do
	case types.NT_IPV4:
		// Nothing to do
	case types.NT_CryptoEID:
		// Nothing to do
	default:
		errStr := fmt.Sprintf("doNetworkCreate type %d not supported",
			config.Type)
		return errors.New(errStr)
	}

	// Allocate bridgeNum.
	bridgeNum := bridgeNumAllocate(config.UUID)
	bridgeName := fmt.Sprintf("bn%d", bridgeNum)
	status.BridgeNum = bridgeNum
	status.BridgeName = bridgeName
	publishNetworkObjectStatus(ctx, status)

	// Create bridge

	// Start clean
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
	// Should be ensured by setBridgeIPAddr
	if status.BridgeIPAddr == "" {
		errStr := fmt.Sprintf("No BridgeIPAddr on %s",
			bridgeName)
		return errors.New(errStr)
	}

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

	deleteDnsmasqConfiglet(bridgeName)
	stopDnsmasq(bridgeName, false)

	// No need to pass any ipsets, since the network is created before
	// the applications which use it.
	createDnsmasqConfiglet(bridgeName, status.BridgeIPAddr, &config,
		hostsDirpath, nil)
	startDnsmasq(bridgeName)

	// For IPv6 and LISP, but LISP will become a service
	isIPv6 := false
	if config.Subnet.IP != nil {
		isIPv6 = (config.Subnet.IP.To4() == nil)
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

	log.Printf("setBridgeIPAddr for %s\n", status.Key())
	if status.BridgeName == "" {
		// Called too early
		log.Printf("setBridgeIPAddr: don't yet have a bridgeName for %s\n",
			status.UUID)
		return nil
	}

	link, _ := netlink.LinkByName(status.BridgeName)
	if link == nil {
		errStr := fmt.Sprintf("Unknown adapter %s", status.BridgeName)
		return errors.New(errStr)
	}
	// Check if we have a bridge service, and if so return error or address
	// XXX call getServiceInfo first?
	st, _, err := getServiceInfo(ctx, status.UUID)
	if err != nil {
		// There might not be a service associated with this network
		// or it might not yet have arrived. In either case we
		// don't treat it as a bridge service.
		log.Printf("setBridgeIPAddr: getServiceInfo failed: %s\n",
			err)
	}
	var ipAddr string
	switch st {
	case types.NST_BRIDGE:
		ipAddr, err = getBridgeServiceIPv4Addr(ctx, status.UUID)
		if err != nil {
			log.Printf("setBridgeIPAddr: getBridgeServiceIPv4Addr failed: %s\n",
				err)
			return err
		}
	}

	// Unlike bridge service Lisp will not need a service now for generating ip address.
	// Hence, cannot move this check into the previous service type check.
	// We check for network type here.
	if status.Type == types.NT_CryptoEID {
		ipAddr = "fd00::" + strconv.FormatInt(int64(status.BridgeNum), 16)
		ipAddr += "/128"
		log.Printf("setBridgeIPAddr: Bridge %s assigned IPv6 address %s\n",
			status.BridgeName, ipAddr)
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
		log.Printf("setBridgeIPAddr lookupOrAllocate for %s\n",
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
		log.Printf("Does not yet have a bridge IP address for %s\n",
			status.Key())
		return nil
	}

	if status.Type != types.NT_CryptoEID {
		ipAddr += "/24"
	}
	//    ip addr add ${ipAddr}/24 dev ${bridgeName}
	addr, err := netlink.ParseAddr(ipAddr)
	if err != nil {
		errStr := fmt.Sprintf("ParseAddr %s failed: %s", ipAddr, err)
		return errors.New(errStr)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		errStr := fmt.Sprintf("AddrAdd %s failed: %s", ipAddr, err)
		return errors.New(errStr)
	}

	// Create new radvd configuration and restart radvd if ipv6
	// XXX shouldn't do that for IPv4 cryptoEIDs!
	isIPv6 := false
	if status.Subnet.IP != nil {
		isIPv6 = (status.Subnet.IP.To4() == nil)
	}
	if (status.Type == types.NT_CryptoEID) || isIPv6 {
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

	log.Printf("lookupOrAllocateIPv4(%s)\n", mac.String())
	// Lookup to see if it exists
	if ip, ok := status.IPAssignments[mac.String()]; ok {
		log.Printf("lookupOrAllocateIPv4(%s) found %s\n",
			mac.String(), ip.String())
		return ip.String(), nil
	}

	log.Printf("lookupOrAllocateIPv4 status: %s dhcp %d bridgeName %s Subnet %v range %v-%v\n",
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
	// XXX should we fall back to using Subnet?
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

		log.Printf("lookupOrAllocateIPv4(%s) testing %s\n",
			mac.String(), a.String())
		if lookupIP(status, a) {
			a = addToIP(a, 1)
			continue
		}
		log.Printf("lookupOrAllocateIPv4(%s) found free %s\n",
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

	log.Printf("releaseIPv4(%s)\n", mac.String())
	// Lookup to see if it exists
	if _, ok := status.IPAssignments[mac.String()]; !ok {
		errStr := fmt.Sprintf("releaseIPv4: not found %s for %s",
			mac.String(), status.Key())
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
		log.Printf("lookupNetworkObjectConfig: key/UUID mismatch %s vs %s; ignored %+v\n",
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
		log.Printf("lookupNetworkObjectStatus: key/UUID mismatch %s vs %s; ignored %+v\n",
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

// Called from service code when a bridge has been added/updated/deleted
func updateBridgeIPAddr(ctx *zedrouterContext, status *types.NetworkObjectStatus) {
	log.Printf("updateBridgeIPAddr(%s)\n", status.Key())

	err := setBridgeIPAddr(ctx, status)
	if err != nil {
		log.Printf("updateBridgeIPAddr: %s\n", err)
		return
	}
}

func doNetworkModify(ctx *zedrouterContext, config types.NetworkObjectConfig,
	status *types.NetworkObjectStatus) {

	log.Printf("doNetworkModify NetworkObjectStatus key %s\n", config.UUID)
	if config.Type != status.Type {
		errStr := fmt.Sprintf("doNetworkModify NetworkObjectStatus can't change key %s",
			config.UUID)
		log.Println(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		return
	}

	// Update other fields; potentially useful for testing
	status.NetworkObjectConfig = config
}

func doNetworkDelete(ctx *zedrouterContext,
	status *types.NetworkObjectStatus) {
	log.Printf("doNetworkDelete NetworkObjectStatus key %s type %d\n",
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
			// Destroy EID Ipset
			deleteEidIpsetConfiglet(olStatus.Vif, true)

			err := deleteACLConfiglet(olStatus.Bridge,
				olStatus.Vif, false, olStatus.ACLs, 6,
				olStatus.BridgeIPAddr,
				olStatus.EID.String())
			if err != nil {
				log.Printf("doNetworkDelete ACL failed: %s\n",
					err)
			}
		}
		for _, ulStatus := range appNetStatus.UnderlayNetworkList {
			if ulStatus.Network != status.UUID {
				continue
			}
			err := deleteACLConfiglet(ulStatus.Bridge,
				ulStatus.Vif, false, ulStatus.ACLs, 4,
				ulStatus.BridgeIPAddr, ulStatus.AssignedIPAddr)
			if err != nil {
				log.Printf("doNetworkDelete ACL failed: %s\n",
					err)
			}
		}
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = bridgeName
	link := &netlink.Bridge{LinkAttrs: attrs}
	// Remove link and associated addresses
	netlink.LinkDel(link)

	deleteDnsmasqConfiglet(bridgeName)
	stopDnsmasq(bridgeName, true)

	// XXX shared! only delete unused when this app is gone.
	// XXX or leave in place? Ditto in zedrouter.go
	// hostsDirpath := globalRunDirname + "/hosts." + bridgeName
	// deleteHostsConfiglet(hostsDirpath, true)

	// For IPv6 and LISP, but LISP will become a service
	isIPv6 := false
	if status.Subnet.IP != nil {
		isIPv6 = (status.Subnet.IP.To4() == nil)
	}
	if isIPv6 || status.Type == types.NT_CryptoEID {
		// radvd cleanup
		cfgFilename := "radvd." + bridgeName + ".conf"
		cfgPathname := runDirname + "/" + cfgFilename
		stopRadvd(cfgFilename, true)
		deleteRadvdConfiglet(cfgPathname)
	}

	status.BridgeName = ""
	status.BridgeNum = 0
	bridgeNumFree(status.UUID)
}

func findVifInBridge(status *types.NetworkObjectStatus, vifName string) bool {
	for _, vif := range status.VifNames {
		if vif == vifName {
			return true
		}
	}
	return false
}

func addVifToBridge(status *types.NetworkObjectStatus, vifName string) {
	log.Printf("addVifToBridge(%s, %s)\n", status.BridgeName, vifName)
	if findVifInBridge(status, vifName) {
		log.Printf("XXX addVifToBridge(%s, %s) exists\n",
			status.BridgeName, vifName)
		return
	}
	status.VifNames = append(status.VifNames, vifName)
}

func removeVifFromBridge(status *types.NetworkObjectStatus, vifName string) {
	log.Printf("removeVifFromBridge(%s, %s)\n", status.BridgeName, vifName)
	if !findVifInBridge(status, vifName) {
		log.Printf("XXX removeVifFromBridge(%s, %s) not there\n",
			status.BridgeName, vifName)
		return
	}
	vifNames := []string{}
	for _, vif := range status.VifNames {
		if vif != vifName {
			vifNames = append(vifNames, vif)
		}
	}
	status.VifNames = vifNames
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
