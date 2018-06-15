// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkService setup

package zedrouter

import (
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/types"
	"log"
	"strings"
	"time"
)

func handleNetworkServiceModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkServiceStatus
	config := CastNetworkService(configArg)
	st, err := pub.Get(key)
	if err != nil {
		log.Printf("handleNetworkServiceModify(%s) failed %s\n",
			key, err)
		return
	}
	if st != nil {
		log.Printf("handleNetworkServiceModify(%s)\n", key)
		status := CastNetworkServiceStatus(st)
		status.PendingModify = true
		pub.Publish(key, status)
		doModify(ctx, config, &status)
		status.PendingModify = false
		pub.Publish(key, status)
	} else {
		handleNetworkServiceCreate(ctx, key, config)
	}
}

func handleNetworkServiceCreate(ctx *zedrouterContext, key string, config types.NetworkService) {
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
	err := doCreate(config, &status)
	if err != nil {
		log.Printf("doCreate(%s) failed: %s\n", key, err)
		status.Error = err.Error()
		status.ErrorTime = time.Now()
		status.PendingAdd = false
		pub.Publish(key, status)
		return
	}
	pub.Publish(key, status)
	if config.Activate {
		err := doActivate(ctx, config, &status)
		if err != nil {
			log.Printf("doActivate(%s) failed: %s\n", key, err)
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
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkServiceStatus
	log.Printf("handleNetworkServiceDelete(%s)\n", key)
	st, err := pub.Get(key)
	if err != nil {
		log.Printf("handleNetworkServiceDelete(%s) failed %s\n",
			key, err)
		return
	}
	if st == nil {
		log.Printf("handleNetworkServiceDelete: unknown %s\n", key)
		return
	}
	status := CastNetworkServiceStatus(st)
	status.PendingDelete = true
	pub.Publish(key, status)
	if status.Activated {
		doInactivate(&status)
		pub.Publish(key, status)
	}
	doDelete(&status)
	status.PendingDelete = false
	pub.Unpublish(key)
}

func doCreate(config types.NetworkService, status *types.NetworkServiceStatus) error {
	log.Printf("doCreate NetworkService key %s type %d\n",
		config.UUID, config.Type)

	var err error
	// Validate that the objects exists
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
		errStr := "doCreate NetworkService LB not yet supported"
		err = errors.New(errStr)
	default:
		errStr := fmt.Sprintf("doCreate NetworkService %d not yet supported",
			config.Type)
		err = errors.New(errStr)
	}
	return err
}

func doModify(ctx *zedrouterContext, config types.NetworkService,
	status *types.NetworkServiceStatus) {

	log.Printf("doModify NetworkService key %s\n", config.UUID)
	if config.Type != status.Type ||
		config.AppLink != status.AppLink ||
		config.Adapter != status.Adapter {
		errStr := fmt.Sprintf("doModify NetworkService can't change key %s",
			config.UUID)
		log.Println(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		return
	}

	if config.Activate && !status.Activated {
		err := doActivate(ctx, config, status)
		if err != nil {
			log.Printf("doActivate(%s) failed: %s\n",
				config.UUID.String(), err)
			status.Error = err.Error()
			status.ErrorTime = time.Now()
		} else {
			status.Activated = true
		}
	} else if status.Activated && !config.Activate {
		doInactivate(status)
		status.Activated = false
	}
}

func doActivate(ctx *zedrouterContext, config types.NetworkService,
	status *types.NetworkServiceStatus) error {

	log.Printf("doActivate NetworkService key %s type %d\n",
		config.UUID, config.Type)

	// We must have an existing AppLink to activate
	// Make sure we have a NetworkConfig object if we have a UUID
	// Returns nil if UUID is zero
	netconf, err := getNetworkConfig(ctx.subNetworkConfig,
		config.AppLink)
	if err != nil {
		// XXX need a fallback/retry!!
		return err
	}
	if netconf == nil {
		return errors.New(fmt.Sprintf("No AppLink for %s", config.UUID))
	}

	// Check that Adapter is either "uplink", "freeuplink", or
	// an existing ifname assigned to domO/zedrouter. A Bridge
	// only works with a single adapter interface.
	allowUplink := (config.Type != types.NST_BRIDGE)
	err = validateAdapter(config.Adapter, allowUplink)
	if err != nil {
		return err
	}

	// XXX the Activate code needs NetworkConfig with buN interface...
	switch config.Type {
	case types.NST_STRONGSWAN:
		err = strongswanActivate(config, status)
	case types.NST_LISP:
		err = lispActivate(config, status)
	case types.NST_BRIDGE:
		err = bridgeActivate(config, status)
	case types.NST_NAT:
		err = natActivate(config, status)
	case types.NST_LB:
		errStr := "doActivate NetworkService LB not yet supported"
		err = errors.New(errStr)
	default:
		errStr := fmt.Sprintf("doActivate NetworkService %d not yet supported",
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

func doInactivate(status *types.NetworkServiceStatus) {
	log.Printf("doInactivate NetworkService key %s type %d\n",
		status.UUID, status.Type)

	switch status.Type {
	case types.NST_STRONGSWAN:
		strongswanInactivate(status)
	case types.NST_LISP:
		lispInactivate(status)
	case types.NST_BRIDGE:
		bridgeInactivate(status)
	case types.NST_NAT:
		natInactivate(status)
	case types.NST_LB:
		errStr := "doInactivate NetworkService LB not yet supported"
		log.Println(errStr)
	default:
		errStr := fmt.Sprintf("doInactivate NetworkService %d not yet supported",
			status.Type)
		log.Println(errStr)
	}
}

func doDelete(status *types.NetworkServiceStatus) {
	log.Printf("doDelete NetworkService key %s type %d\n",
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
		errStr := "doDelete NetworkService LB not yet supported"
		log.Println(errStr)
	default:
		errStr := fmt.Sprintf("doDelete NetworkService %d not yet supported",
			status.Type)
		log.Println(errStr)
	}
}

// ==== StrongSwan

func strongswanCreate(config types.NetworkService,
	status *types.NetworkServiceStatus) error {

	return nil
}

func strongswanActivate(config types.NetworkService,
	status *types.NetworkServiceStatus) error {

	return nil
}

func strongswanInactivate(status *types.NetworkServiceStatus) {
}

func strongswanDelete(status *types.NetworkServiceStatus) {
}

// ==== Lisp

func lispCreate(config types.NetworkService,
	status *types.NetworkServiceStatus) error {

	return nil
}

func lispActivate(config types.NetworkService,
	status *types.NetworkServiceStatus) error {

	return nil
}

func lispInactivate(status *types.NetworkServiceStatus) {
}

func lispDelete(status *types.NetworkServiceStatus) {
}

// ==== Bridge

func bridgeCreate(config types.NetworkService,
	status *types.NetworkServiceStatus) error {

	return nil
}

func bridgeActivate(config types.NetworkService,
	status *types.NetworkServiceStatus) error {

	return nil
}

func bridgeInactivate(status *types.NetworkServiceStatus) {
}

func bridgeDelete(status *types.NetworkServiceStatus) {
}

// ==== Nat

func natCreate(config types.NetworkService,
	status *types.NetworkServiceStatus) error {

	return nil
}

func natActivate(config types.NetworkService,
	status *types.NetworkServiceStatus) error {

	return nil
}

func natInactivate(status *types.NetworkServiceStatus) {
}

func natDelete(status *types.NetworkServiceStatus) {
}
