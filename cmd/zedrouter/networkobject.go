// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkObject

package zedrouter

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"log"
	"net"
	"time"
)

func handleNetworkConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	config := cast.CastNetworkObjectConfig(configArg)
	status := lookupNetworkObjectStatus(ctx, key)
	if status != nil {
		log.Printf("handleNetworkConfigModify(%s)\n", key)
		pub := ctx.pubNetworkObjectStatus
		status.PendingModify = true
		pub.Publish(key, *status)
		doNetworkModify(ctx, config, status)
		status.PendingModify = false
		pub.Publish(key, *status)
	} else {
		handleNetworkConfigCreate(ctx, key, config)
	}
}

func handleNetworkConfigCreate(ctx *zedrouterContext, key string, config types.NetworkObjectConfig) {
	log.Printf("handleNetworkConfigCreate(%s)\n", key)

	pub := ctx.pubNetworkObjectStatus
	status := types.NetworkObjectStatus{
		NetworkObjectConfig: config,
		IPAssignments:       make(map[string]net.IP),
	}
	status.PendingAdd = true
	pub.Publish(key, status)
	err := doNetworkCreate(ctx, config, &status)
	if err != nil {
		log.Printf("doNetworkCreate(%s) failed: %s\n", key, err)
		status.Error = err.Error()
		status.ErrorTime = time.Now()
		status.PendingAdd = false
		pub.Publish(key, status)
		return
	}
	status.PendingAdd = false
	pub.Publish(key, status)
}

func handleNetworkConfigDelete(ctxArg interface{}, key string) {
	log.Printf("handleNetworkConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkObjectStatus
	status := lookupNetworkObjectStatus(ctx, key)
	if status == nil {
		log.Printf("handleNetworkConfigDelete: unknown %s\n", key)
		return
	}
	status.PendingDelete = true
	pub.Publish(key, *status)
	doNetworkDelete(status)
	status.PendingDelete = false
	pub.Unpublish(key)
}

func doNetworkCreate(ctx *zedrouterContext, config types.NetworkObjectConfig,
	status *types.NetworkObjectStatus) error {

	log.Printf("doNetworkCreate NetworkObjectStatus key %s type %d\n",
		config.UUID, config.Type)

	// Check for valid types
	switch config.Type {
	case types.NT_IPV6:
	case types.NT_IPV4:
	case types.NT_LISP: // XXX turn into a service?
		break
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
	if err := setBridgeIPAddr(ctx, config, status); err != nil {
		return err
	}
	return nil
}

// Call when we have a network and a service? XXX also for local?
func setBridgeIPAddr(ctx *zedrouterContext, config types.NetworkObjectConfig,
	status *types.NetworkObjectStatus) error {

	if status.BridgeName == "" {
		// Called too early
		log.Printf("setBridgeIPAddr: don't yet have a bridgeName for %s\n",
			config.UUID)
		return nil
	}

	link, _ := netlink.LinkByName(status.BridgeName)
	if link == nil {
		errStr := fmt.Sprintf("Unknown adapter %s", status.BridgeName)
		return errors.New(errStr)
	}
	// Check if we have a bridge service, and if so return error or address
	ipAddr, err := getBridgeService(ctx, config.UUID)
	if err != nil {
		return err
	}
	// If not we do a local allocation
	if ipAddr == "" {
		// XXX Need IPV6/LISP logic to get IPv6 addresses
		var bridgeMac net.HardwareAddr
		switch link.(type) {
		case *netlink.Bridge:
			bridgeLink := link.(*netlink.Bridge)
			bridgeMac = bridgeLink.HardwareAddr
		default:
			errStr := fmt.Sprintf("Not a bridge %s",
				status.BridgeName)
			return errors.New(errStr)
		}
		ipAddr, err = lookupOrAllocateIPv4(ctx, config, bridgeMac)
		if err != nil {
			errStr := fmt.Sprintf("lookupOrAllocateIPv4 failed: %s",
				err)
			return errors.New(errStr)
		}
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

// XXX or return net.IP??
func lookupOrAllocateIPv4(ctx *zedrouterContext,
	config types.NetworkObjectConfig, mac net.HardwareAddr) (string, error) {

	log.Printf("lookupOrAllocateIPv4(%s)\n", mac.String())
	// Allocation happens in status
	status := lookupNetworkObjectStatus(ctx, config.UUID.String())
	if status == nil {
		errStr := fmt.Sprintf("no NetworkOjectStatus for %s",
			config.UUID.String())
		return "", errors.New(errStr)
	}
	// Lookup to see if it exists
	if ip, ok := status.IPAssignments[mac.String()]; ok {
		log.Printf("lookupOrAllocateIPv4(%s) found %s\n",
			mac.String(), ip.String())
		return ip.String(), nil
	}

	if status.DhcpRange.Start == nil {
		errStr := fmt.Sprintf("no NetworkOjectStatus DhcpRange for %s",
			config.UUID.String())
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
	errStr := fmt.Sprintf("NetworkOjectStatus no free address in DhcpRange for %s",
		config.UUID.String())
	return "", errors.New(errStr)
}

// Returns true if the last entry was removed
func releaseIPv4(ctx *zedrouterContext,
	config types.NetworkObjectConfig, mac net.HardwareAddr) (bool, error) {

	log.Printf("releaseIPv4(%s)\n", mac.String())
	// Allocation happens in status
	status := lookupNetworkObjectStatus(ctx, config.UUID.String())
	if status == nil {
		errStr := fmt.Sprintf("releaseIPv4: no NetworkOjectStatus for %s",
			config.UUID.String())
		return false, errors.New(errStr)
	}
	// Lookup to see if it exists
	if _, ok := status.IPAssignments[mac.String()]; !ok {
		errStr := fmt.Sprintf("releaseIPv4: not found %s for %s",
			mac.String(), config.UUID.String())
		return false, errors.New(errStr)
	}
	delete(status.IPAssignments, mac.String())
	last := len(status.IPAssignments) == 0
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
	return &config
}

func lookupNetworkObjectStatus(ctx *zedrouterContext, key string) *types.NetworkObjectStatus {

	pub := ctx.pubNetworkObjectStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := cast.CastNetworkObjectStatus(st)
	return &status
}

// Called from service code when a bridge has been added/updated/deleted
// XXX need to re-run this when the eth1 IP address might have been set
func updateBridgeIPAddr(ctx *zedrouterContext, id uuid.UUID) {
	log.Printf("updateBridgeIPAddr(%s)\n", id.String())

	config := lookupNetworkObjectConfig(ctx, id.String())
	status := lookupNetworkObjectStatus(ctx, id.String())
	if config == nil || status == nil {
		log.Printf("updateBridgeIPAddr: no config or status\n")
		return
	}

	err := setBridgeIPAddr(ctx, *config, status)
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
