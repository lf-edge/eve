// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkService setup

package zedrouter

import (
	"errors"
	"fmt"
	"github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"log"
	"strings"
	"syscall"
	"time"
)

func handleNetworkServiceModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkServiceStatus
	config := cast.CastNetworkServiceConfig(configArg)
	if config.UUID.String() != key {
		log.Printf("handleNetworkServiceModify key/UUID mismatch %s vs %s; ignored %+v\n", key, config.UUID.String(), config)
		return
	}
	status := lookupNetworkServiceStatus(ctx, key)
	if status != nil {
		log.Printf("handleNetworkServiceModify(%s)\n", key)
		status.PendingModify = true
		pub.Publish(status.UUID.String(), *status)
		doServiceModify(ctx, config, status)
		status.PendingModify = false
		pub.Publish(status.UUID.String(), *status)
		log.Printf("handleNetworkServiceModify(%s) done\n", key)
	} else {
		handleNetworkServiceCreate(ctx, key, config)
	}
}

func handleNetworkServiceCreate(ctx *zedrouterContext, key string, config types.NetworkServiceConfig) {
	log.Printf("handleNetworkServiceCreate(%s)\n", key)

	pub := ctx.pubNetworkServiceStatus
	status := types.NetworkServiceStatus{
		UUID:        config.UUID,
		DisplayName: config.DisplayName,
		Type:        config.Type,
		AppLink:     config.AppLink,
		Adapter:     config.Adapter,
	}
	status.PendingAdd = true
	pub.Publish(status.UUID.String(), status)
	err := doServiceCreate(config, &status)
	if err != nil {
		log.Printf("doServiceCreate(%s) failed: %s\n", key, err)
		status.Error = err.Error()
		status.ErrorTime = time.Now()
		status.PendingAdd = false
		pub.Publish(status.UUID.String(), status)
		return
	}
	pub.Publish(status.UUID.String(), status)
	if config.Activate {
		err := doServiceActivate(ctx, config, &status)
		if err != nil {
			log.Printf("doServiceActivate(%s) failed: %s\n", key, err)
			status.Error = err.Error()
			status.ErrorTime = time.Now()
		} else {
			status.Activated = true
		}
	}
	status.PendingAdd = false
	pub.Publish(status.UUID.String(), status)
	log.Printf("handleNetworkServiceCreate(%s) done\n", key)
}

func handleNetworkServiceDelete(ctxArg interface{}, key string) {
	log.Printf("handleNetworkServiceDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkServiceStatus
	status := lookupNetworkServiceStatus(ctx, key)
	if status == nil {
		log.Printf("handleNetworkServiceDelete: unknown %s\n", key)
		return
	}
	status.PendingDelete = true
	pub.Publish(status.UUID.String(), *status)
	if status.Activated {
		doServiceInactivate(ctx, status)
		pub.Publish(status.UUID.String(), *status)
	}
	doServiceDelete(status)
	status.PendingDelete = false
	pub.Unpublish(status.UUID.String())
	log.Printf("handleNetworkServiceDelete(%s) done\n", key)
}

func doServiceCreate(config types.NetworkServiceConfig, status *types.NetworkServiceStatus) error {
	log.Printf("doServiceCreate NetworkService key %s type %d\n",
		config.UUID, config.Type)

	var err error

	switch config.Type {
	case types.NST_STRONGSWAN:
		err = strongswanCreate(config, status)
	case types.NST_LISP:
		err = lispCreate(config, status)
	case types.NST_BRIDGE:
		err = bridgeCreate(config, status)
	case types.NST_NAT:
		err = natCreate(config, status)
	case types.NST_LB:
		errStr := "doServiceCreate NetworkService LB not yet supported"
		err = errors.New(errStr)
	default:
		errStr := fmt.Sprintf("doServiceCreate NetworkService %d not yet supported",
			config.Type)
		err = errors.New(errStr)
	}
	return err
}

func doServiceModify(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) {

	log.Printf("doServiceModify NetworkService key %s\n", config.UUID)
	if config.Type != status.Type ||
		config.AppLink != status.AppLink ||
		config.Adapter != status.Adapter {
		errStr := fmt.Sprintf("doServiceModify NetworkService can't change key %s",
			config.UUID)
		log.Println(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		return
	}

	if config.Activate && !status.Activated {
		err := doServiceActivate(ctx, config, status)
		if err != nil {
			log.Printf("doServiceActivate(%s) failed: %s\n",
				config.UUID.String(), err)
			status.Error = err.Error()
			status.ErrorTime = time.Now()
		} else {
			status.Activated = true
		}
	} else if status.Activated && !config.Activate {
		doServiceInactivate(ctx, status)
		status.Activated = false
	}
}

func doServiceActivate(ctx *zedrouterContext, config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	log.Printf("doServiceActivate NetworkService key %s type %d\n",
		config.UUID, config.Type)

	// We must have an existing AppLink to activate
	netstatus := lookupNetworkObjectStatus(ctx, config.AppLink.String())
	if netstatus == nil {
		return errors.New(fmt.Sprintf("No AppLink for %s", config.UUID))
	}

	log.Printf("doServiceActivate found NetworkObjectStatus %s\n",
		netstatus.UUID.String())

	// Check that Adapter is either "uplink", "freeuplink", or
	// an existing ifname assigned to doServicemO/zedrouter. A Bridge
	// only works with a single adapter interface.
	allowUplink := (config.Type != types.NST_BRIDGE)
	err := validateAdapter(config.Adapter, allowUplink)
	if err != nil {
		return err
	}

	// XXX the Activate code needs NetworkObjectConfig with buN interface...
	switch config.Type {
	case types.NST_STRONGSWAN:
		err = strongswanActivate(config, status)
	case types.NST_LISP:
		err = lispActivate(config, status)
	case types.NST_BRIDGE:
		err = bridgeActivate(config, status, netstatus)
		// XXX also need to call when IP address set/changed
		if err != nil {
			updateBridgeIPAddr(ctx, netstatus)
		}
	case types.NST_NAT:
		err = natActivate(config, status)
	case types.NST_LB:
		errStr := "doServiceActivate NetworkService LB not yet supported"
		err = errors.New(errStr)
	default:
		errStr := fmt.Sprintf("doServiceActivate NetworkService %d not yet supported",
			config.Type)
		err = errors.New(errStr)
	}
	return err
}

func validateAdapter(adapter string, allowUplink bool) error {
	if allowUplink {
		if strings.EqualFold(adapter, "uplink") {
			return nil
		}
		if strings.EqualFold(adapter, "freeuplink") {
			return nil
		}
	}
	// XXX look for ifname; this assumes it exists in dom0/zedrouter
	// and not assigned to pciback
	link, _ := netlink.LinkByName(adapter)
	if link == nil {
		errStr := fmt.Sprintf("Unknown adapter %s", adapter)
		return errors.New(errStr)
	}
	return nil
}

func doServiceInactivate(ctx *zedrouterContext,
	status *types.NetworkServiceStatus) {

	log.Printf("doServiceInactivate NetworkService key %s type %d\n",
		status.UUID, status.Type)
	// We must have an existing AppLink to activate
	netstatus := lookupNetworkObjectStatus(ctx, status.AppLink.String())
	if netstatus == nil {
		// Should have been caught at time of activate
		log.Printf("No AppLink for %s", status.UUID.String())
		return
	}

	log.Printf("doServiceActivate found NetworkObjectStatus %s\n",
		netstatus.UUID.String())

	switch status.Type {
	case types.NST_STRONGSWAN:
		strongswanInactivate(status)
	case types.NST_LISP:
		lispInactivate(status)
	case types.NST_BRIDGE:
		bridgeInactivate(status, netstatus)
		updateBridgeIPAddr(ctx, netstatus)
	case types.NST_NAT:
		natInactivate(status)
	case types.NST_LB:
		errStr := "doServiceInactivate NetworkService LB not yet supported"
		log.Println(errStr)
	default:
		errStr := fmt.Sprintf("doServiceInactivate NetworkService %d not yet supported",
			status.Type)
		log.Println(errStr)
	}
}

func doServiceDelete(status *types.NetworkServiceStatus) {
	log.Printf("doServiceDelete NetworkService key %s type %d\n",
		status.UUID, status.Type)
	// Anything to do except the inactivate already done?
	switch status.Type {
	case types.NST_STRONGSWAN:
		strongswanDelete(status)
	case types.NST_LISP:
		lispDelete(status)
	case types.NST_BRIDGE:
		bridgeDelete(status)
	case types.NST_NAT:
		natDelete(status)
	case types.NST_LB:
		errStr := "doServiceDelete NetworkService LB not yet supported"
		log.Println(errStr)
	default:
		errStr := fmt.Sprintf("doServiceDelete NetworkService %d not yet supported",
			status.Type)
		log.Println(errStr)
	}
}

func lookupNetworkServiceConfig(ctx *zedrouterContext, key string) *types.NetworkServiceConfig {

	sub := ctx.subNetworkServiceConfig
	c, _ := sub.Get(key)
	if c == nil {
		return nil
	}
	config := cast.CastNetworkServiceConfig(c)
	if config.UUID.String() != key {
		log.Printf("lookupNetworkServiceConfig(%s) got %s; ignored %+v\n",
			key, config.UUID.String(), config)
		return nil
	}
	return &config
}

// XXX Callers must be careful to publish any changes to NetworkServiceStatus
func lookupNetworkServiceStatus(ctx *zedrouterContext, key string) *types.NetworkServiceStatus {

	pub := ctx.pubNetworkServiceStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := cast.CastNetworkServiceStatus(st)
	if status.UUID.String() != key {
		log.Printf("lookupNetworkServiceStatus(%s) got %s; ignored %+v\n",
			key, status.UUID.String(), status)
		return nil
	}
	return &status
}

// Entrypoint from networkobject to look for the service type and optional
// adapter
func getServiceInfo(ctx *zedrouterContext, appLink uuid.UUID) (types.NetworkServiceType, string, error) {
	// Find any service which is associated with the appLink UUID
	log.Printf("getServiceInfo(%s)\n", appLink.String())
	status := lookupAppLink(ctx, appLink)
	if status == nil {
		errStr := fmt.Sprintf("getServiceInfo: no NetworkServiceStatus for %s", appLink.String())
		return types.NST_FIRST, "", errors.New(errStr)
	}
	return status.Type, status.Adapter, nil
}

// Entrypoint from networkobject to look for a bridge's IPv4 address
func getBridgeServiceIPv4Addr(ctx *zedrouterContext, appLink uuid.UUID) (string, error) {
	// Find any service which is associated with the appLink UUID
	log.Printf("getBridgeServiceIPv4Addr(%s)\n", appLink.String())
	status := lookupAppLink(ctx, appLink)
	if status == nil {
		errStr := fmt.Sprintf("getBridgeServiceIPv4Addr(%s): no NetworkServiceStatus",
			appLink.String())
		return "", errors.New(errStr)
	}
	if status.Type != types.NST_BRIDGE {
		errStr := fmt.Sprintf("getBridgeServiceIPv4Addr(%s): service not a bridge; type %d",
			status.Type)
		return "", errors.New(errStr)
	}
	if status.Adapter == "" {
		log.Printf("getBridgeServiceIPv4Addr: bridge but no Adapter\n")
		return "", nil
	}

	// Get IP address from adapter
	link, err := netlink.LinkByName(status.Adapter)
	if err != nil {
		return "", err
	}
	// XXX Add IPv6; ignore link-locals.
	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		log.Printf("getBridgeServiceIPv4Addr: found addr %s\n", addr.String())
		return addr.String(), nil
	}
	log.Printf("getBridgeServiceIPv4Addr: no IP address on %s yet\n",
		status.Adapter)
	return "", nil
}

func lookupAppLink(ctx *zedrouterContext, appLink uuid.UUID) *types.NetworkServiceStatus {
	log.Printf("lookupAppLink(%s)\n", appLink.String())
	pub := ctx.pubNetworkServiceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := cast.CastNetworkServiceStatus(st)
		if status.AppLink == appLink {
			log.Printf("lookupAppLink(%s) found %s\n",
				appLink.String(), status.UUID.String())
			return &status
		}
	}
	return nil
}

// ==== Lisp

func lispCreate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	return nil
}

func lispActivate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	return nil
}

func lispInactivate(status *types.NetworkServiceStatus) {
}

func lispDelete(status *types.NetworkServiceStatus) {
}

// ==== Bridge

func bridgeCreate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	log.Printf("bridgeCreate(%s)\n", config.DisplayName)
	return nil
}

func bridgeActivate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) error {

	log.Printf("bridgeActivate(%s)\n", status.DisplayName)
	// For now we only support passthrough
	if netstatus.Dhcp != types.DT_PASSTHROUGH {
		errStr := fmt.Sprintf("Unsupported DHCP type %d for bridge service for %s",
			netstatus.Dhcp, status.UUID.String())
		return errors.New(errStr)
	}

	bridgeLink, err := findBridge(netstatus.BridgeName)
	if err != nil {
		errStr := fmt.Sprintf("findBridge(%s) failed %s",
			netstatus.BridgeName, err)
		return errors.New(errStr)
	}
	// Find adapter
	alink, _ := netlink.LinkByName(status.Adapter)
	if alink == nil {
		errStr := fmt.Sprintf("Unknown adapter %s",
			status.Adapter)
		return errors.New(errStr)
	}
	// Make sure it is up
	//    ip link set ${adapter} up
	if err := netlink.LinkSetUp(alink); err != nil {
		errStr := fmt.Sprintf("LinkSetUp on %s failed: %s",
			status.Adapter, err)
		return errors.New(errStr)
	}
	// ip link set ${adapter} master ${bridge_name}
	if err := netlink.LinkSetMaster(alink, bridgeLink); err != nil {
		errStr := fmt.Sprintf("LinkSetMaster %s %s failed: %s",
			status.Adapter, netstatus.BridgeName, err)
		return errors.New(errStr)
	}
	log.Printf("bridgeActivate: added %s to bridge %s\n",
		status.Adapter, netstatus.BridgeName)
	return nil
}

func bridgeInactivate(status *types.NetworkServiceStatus,
	netstatus *types.NetworkObjectStatus) {

	log.Printf("bridgeInactivate(%s)\n", status.DisplayName)
	// Find adapter
	alink, _ := netlink.LinkByName(status.Adapter)
	if alink == nil {
		errStr := fmt.Sprintf("Unknown adapter %s",
			status.Adapter)
		log.Println(errStr)
		return
	}
	// ip link set ${adapter} nomaster
	if err := netlink.LinkSetNoMaster(alink); err != nil {
		errStr := fmt.Sprintf("LinkSetMaster %s failed: %s",
			status.Adapter, err)
		log.Println(errStr)
		return
	}
	log.Printf("bridgeInactivate: removed %s from bridge\n",
		status.Adapter)
}

func bridgeDelete(status *types.NetworkServiceStatus) {
	log.Printf("bridgeDelete(%s)\n", status.DisplayName)
}

// ==== Nat

func natCreate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	return nil
}

func natActivate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	return nil
}

func natInactivate(status *types.NetworkServiceStatus) {
}

func natDelete(status *types.NetworkServiceStatus) {
}
