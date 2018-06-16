// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkObject

package zedrouter

import (
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
// XXX for Bridge service need to get address from Adapter ...
// XXX need wrapper for service to call based on our UUID.
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
	ulAddr1, err := getBridgeService(ctx, config.UUID)
	if err != nil {
		return err
	}
	// If not we do a local allocation
	if ulAddr1 == "" {
		ulAddr1, _ = getUlAddrs(status.BridgeNum, nil, nil, &config)
	}

	//    ip addr add ${ulAddr1}/24 dev ${bridgeName}
	addr, err := netlink.ParseAddr(ulAddr1 + "/24")
	if err != nil {
		errStr := fmt.Sprintf("ParseAddr %s failed: %s", ulAddr1, err)
		return errors.New(errStr)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		errStr := fmt.Sprintf("AddrAdd %s failed: %s", ulAddr1, err)
		return errors.New(errStr)
	}
	return nil
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
