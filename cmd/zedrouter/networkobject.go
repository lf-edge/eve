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
	"time"
)

func handleNetworkObjectModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	config := cast.CastNetworkObjectConfig(configArg)
	if config.UUID.String() != key {
		log.Printf("handleNetworkObjectModify key/UUID mismatch %s vs %s; ignored %+v\n", key, config.UUID.String(), config)
		return
	}
	status := lookupNetworkObjectStatus(ctx, key)
	if status != nil {
		log.Printf("handleNetworkObjectModify(%s)\n", key)
		pub := ctx.pubNetworkObjectStatus
		status.PendingModify = true
		pub.Publish(status.UUID.String(), *status)
		doNetworkModify(ctx, config, status)
		status.PendingModify = false
		pub.Publish(status.UUID.String(), *status)
		log.Printf("handleNetworkObjectModify(%s) done\n", key)
	} else {
		handleNetworkObjectCreate(ctx, key, config)
	}
}

func handleNetworkObjectCreate(ctx *zedrouterContext, key string, config types.NetworkObjectConfig) {
	log.Printf("handleNetworkObjectCreate(%s)\n", key)

	pub := ctx.pubNetworkObjectStatus
	status := types.NetworkObjectStatus{
		NetworkObjectConfig: config,
		IPAssignments:       make(map[string]net.IP),
	}
	status.PendingAdd = true
	pub.Publish(status.UUID.String(), status)
	err := doNetworkCreate(ctx, config, &status)
	if err != nil {
		log.Printf("doNetworkCreate(%s) failed: %s\n", key, err)
		status.Error = err.Error()
		status.ErrorTime = time.Now()
		status.PendingAdd = false
		pub.Publish(status.UUID.String(), status)
		return
	}
	status.PendingAdd = false
	pub.Publish(status.UUID.String(), status)
	log.Printf("handleNetworkObjectCreate(%s) done\n", key)
}

func handleNetworkObjectDelete(ctxArg interface{}, key string) {
	log.Printf("handleNetworkObjectDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkObjectStatus
	status := lookupNetworkObjectStatus(ctx, key)
	if status == nil {
		log.Printf("handleNetworkObjectDelete: unknown %s\n", key)
		return
	}
	status.PendingDelete = true
	pub.Publish(status.UUID.String(), *status)
	doNetworkDelete(status)
	status.PendingDelete = false
	pub.Unpublish(status.UUID.String())
	log.Printf("handleNetworkObjectDelete(%s) done\n", key)
}

func doNetworkCreate(ctx *zedrouterContext, config types.NetworkObjectConfig,
	status *types.NetworkObjectStatus) error {

	log.Printf("doNetworkCreate NetworkObjectStatus key %s type %d\n",
		config.UUID, config.Type)

	pub := ctx.pubNetworkObjectStatus

	// Check for valid types
	switch config.Type {
	case types.NT_IPV6:
		// Nothing to do
	case types.NT_IPV4:
		// Nothing to do
	case types.NT_LISP: // XXX turn into a service?
		// Nothing to do
	default:
		errStr := fmt.Sprintf("doNetworkCreate type %d not supported",
			config.Type)
		return errors.New(errStr)
	}

	// Allocate bridgeNum. Note that we reuse appNum even
	// though XXX appNumAllocatorInit doesn't know about
	// these numbers
	bridgeNum := appNumAllocate(config.UUID, false)
	bridgeName := fmt.Sprintf("bn%d", bridgeNum)
	status.BridgeNum = bridgeNum
	status.BridgeName = bridgeName
	pub.Publish(status.UUID.String(), *status)

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

	// Create a hosts file for the new bridge
	// Directory is /var/run/zedrouter/hosts.${BRIDGENAME}
	hostsDirpath := globalRunDirname + "/hosts." + bridgeName
	deleteHostsConfiglet(hostsDirpath, false)
	createHostsConfiglet(hostsDirpath, nil)
	if status.BridgeIPAddr != "" {
		// XXX arbitrary name "router"!!
		addToHostsConfiglet(hostsDirpath, "router",
			[]string{status.BridgeIPAddr})
	}
	return nil
}

// Call when we have a network and a service?
func setBridgeIPAddr(ctx *zedrouterContext, status *types.NetworkObjectStatus) error {

	log.Printf("setBridgeIPAddr for %s\n", status.UUID.String())
	pub := ctx.pubNetworkObjectStatus
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
	if st == types.NST_BRIDGE {
		ipAddr, err = getBridgeServiceIPv4Addr(ctx, status.UUID)
		if err != nil {
			log.Printf("setBridgeIPAddr: getBridgeServiceIPv4Addr failed: %s\n",
				err)
			return err
		}
	}
	// If not we do a local allocation
	if ipAddr == "" {
		// XXX Need IPV6/LISP logic to get IPv6 addresses
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
	pub.Publish(status.UUID.String(), *status)

	if status.BridgeIPAddr == "" {
		log.Printf("Does not yet have a bridge IP address for %s\n",
			status.UUID.String())
		return nil
	}

	//    ip addr add ${ipAddr}/24 dev ${bridgeName}
	addr, err := netlink.ParseAddr(ipAddr + "/24")
	if err != nil {
		errStr := fmt.Sprintf("ParseAddr %s failed: %s", ipAddr, err)
		return errors.New(errStr)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		errStr := fmt.Sprintf("AddrAdd %s failed: %s", ipAddr, err)
		return errors.New(errStr)
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
		status.UUID.String(), status.Dhcp, status.BridgeName,
		status.Subnet, status.DhcpRange.Start, status.DhcpRange.End)
	if status.Dhcp == types.DT_PASSTHROUGH {
		// XXX do we have a local IP? If so caller would have found it
		// Might appear later
		return "", nil
	}

	if status.Dhcp != types.DT_SERVER {
		errStr := fmt.Sprintf("Unsupported DHCP type %d for %s",
			status.Dhcp, status.UUID.String())
		return "", errors.New(errStr)
	}
	// XXX should we fall back to using Subnet?
	if status.DhcpRange.Start == nil {
		errStr := fmt.Sprintf("no NetworkOjectStatus DhcpRange for %s",
			status.UUID.String())
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
		pub := ctx.pubNetworkObjectStatus
		pub.Publish(status.UUID.String(), *status)
		return a.String(), nil
	}
	errStr := fmt.Sprintf("lookupOrAllocateIPv4(%s) no free address in DhcpRange",
		status.UUID.String())
	return "", errors.New(errStr)
}

// Returns true if the last entry was removed
func releaseIPv4(ctx *zedrouterContext,
	status *types.NetworkObjectStatus, mac net.HardwareAddr) (bool, error) {

	log.Printf("releaseIPv4(%s)\n", mac.String())
	pub := ctx.pubNetworkObjectStatus
	// Lookup to see if it exists
	if _, ok := status.IPAssignments[mac.String()]; !ok {
		errStr := fmt.Sprintf("releaseIPv4: not found %s for %s",
			mac.String(), status.UUID.String())
		return false, errors.New(errStr)
	}
	delete(status.IPAssignments, mac.String())
	last := len(status.IPAssignments) == 0
	pub.Publish(status.UUID.String(), *status)
	return last, nil
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
	if config.UUID.String() != key {
		log.Printf("lookupNetworkObjectConfig(%s) got %s; ignored %+v\n",
			key, config.UUID.String(), config)
		return nil
	}
	return &config
}

// XXX Callers must be careful to publish any changes to NetworkObjectStatus
func lookupNetworkObjectStatus(ctx *zedrouterContext, key string) *types.NetworkObjectStatus {

	pub := ctx.pubNetworkObjectStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := cast.CastNetworkObjectStatus(st)
	if status.UUID.String() != key {
		log.Printf("lookupNetworkObjectStatus(%s) got %s; ignored %+v\n",
			key, status.UUID.String(), status)
		return nil
	}
	return &status
}

// Called from service code when a bridge has been added/updated/deleted
// XXX need to re-run this when the eth1 IP address might have been set
func updateBridgeIPAddr(ctx *zedrouterContext, status *types.NetworkObjectStatus) {
	log.Printf("updateBridgeIPAddr(%s)\n", status.UUID.String())

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

func doNetworkDelete(status *types.NetworkObjectStatus) {
	log.Printf("doNetworkDelete NetworkObjectStatus key %s type %d\n",
		status.UUID, status.Type)

	if status.BridgeName == "" {
		return
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = status.BridgeName
	link := &netlink.Bridge{LinkAttrs: attrs}
	// Remove link and associated addresses
	netlink.LinkDel(link)

	status.BridgeName = ""
	status.BridgeNum = 0
	appNumFree(status.UUID)
}
