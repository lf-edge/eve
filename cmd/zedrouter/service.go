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
	status := lookupNetworkServiceStatus(ctx, key)
	if status != nil {
		log.Printf("handleNetworkServiceModify(%s)\n", key)
		status.PendingModify = true
		pub.Publish(key, *status)
		doServiceModify(ctx, config, status)
		status.PendingModify = false
		pub.Publish(key, *status)
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
	pub.Publish(key, status)
	err := doServiceCreate(config, &status)
	if err != nil {
		log.Printf("doServiceCreate(%s) failed: %s\n", key, err)
		status.Error = err.Error()
		status.ErrorTime = time.Now()
		status.PendingAdd = false
		pub.Publish(key, status)
		return
	}
	pub.Publish(key, status)
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
	pub.Publish(key, status)
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
	pub.Publish(key, *status)
	if status.Activated {
		doServiceInactivate(ctx, status)
		pub.Publish(key, *status)
	}
	doServiceDelete(status)
	status.PendingDelete = false
	pub.Unpublish(key)
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
	// Make sure we have a NetworkObjectConfig if we have a UUID
	// Returns nil if UUID is zero
	netconf, err := getNetworkObjectConfig(ctx, config.AppLink)
	if err != nil {
		// XXX need a fallback/retry!!
		return err
	}
	if netconf == nil {
		return errors.New(fmt.Sprintf("No AppLink for %s", config.UUID))
	}

	// Check that Adapter is either "uplink", "freeuplink", or
	// an existing ifname assigned to doServicemO/zedrouter. A Bridge
	// only works with a single adapter interface.
	allowUplink := (config.Type != types.NST_BRIDGE)
	err = validateAdapter(config.Adapter, allowUplink)
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
		err = bridgeActivate(config, status)
		// XXX also need to call when IP address set/changed
		if err != nil {
			updateBridgeIPAddr(ctx, config.AppLink)
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

	switch status.Type {
	case types.NST_STRONGSWAN:
		strongswanInactivate(status)
	case types.NST_LISP:
		lispInactivate(status)
	case types.NST_BRIDGE:
		bridgeInactivate(status)
		updateBridgeIPAddr(ctx, status.AppLink)
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
	return &config
}

func lookupNetworkServiceStatus(ctx *zedrouterContext, key string) *types.NetworkServiceStatus {

	pub := ctx.pubNetworkServiceStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := cast.CastNetworkServiceStatus(st)
	return &status
}

// Entrypoint from networkobject to look for a bridge's IP address
func getBridgeService(ctx *zedrouterContext, appLink uuid.UUID) (string, error) {
	// Find any service which is associated with the appLink UUID
	log.Printf("getBridgeService(%s)\n", appLink.String())
	status := lookupAppLink(ctx, appLink)
	if status == nil {
		log.Printf("getBridgeService: no NetworkServiceStatus\n")
		return "", nil
	}
	if status.Type != types.NST_BRIDGE {
		log.Printf("getBridgeService: service not a bridge; type %d\n",
			status.Type)
		return "", nil
	}
	if status.Adapter == "" {
		log.Printf("getBridgeService: bridge but no Adapter\n")
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
		log.Printf("getBridgeService: found addr %s\n", addr.String())
		return addr.String(), nil
	}
	log.Printf("getBridgeService: no IP address on %s yet\n",
		status.Adapter)
	return "", nil
}

func lookupAppLink(ctx *zedrouterContext, appLink uuid.UUID) *types.NetworkServiceStatus {
	log.Printf("lookupAppLink(%s)\n", appLink.String())
	pub := ctx.pubNetworkServiceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := cast.CastNetworkServiceStatus(st)
		if status.UUID != appLink {
			return &status
		}
	}
	return nil
}

// ==== StrongSwan

func strongswanCreate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	return nil
}

func strongswanActivate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	return nil
}

func strongswanInactivate(status *types.NetworkServiceStatus) {
}

func strongswanDelete(status *types.NetworkServiceStatus) {
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

	return nil
}

func bridgeActivate(config types.NetworkServiceConfig,
	status *types.NetworkServiceStatus) error {

	return nil
}

func bridgeInactivate(status *types.NetworkServiceStatus) {
}

func bridgeDelete(status *types.NetworkServiceStatus) {
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
