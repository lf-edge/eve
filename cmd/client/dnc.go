// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package client

import (
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/types"
	"log"
	"reflect"
)

func handleDNCModify(ctxArg interface{}, key string, configArg interface{}) {

	config := cast.CastDeviceNetworkConfig(configArg)
	ctx := ctxArg.(*clientContext)

	if key != ctx.manufacturerModel {
		if debug {
			log.Printf("handleDNCModify: ignoring %s - expecting %s\n",
				key, ctx.manufacturerModel)
		}
		return
	}
	log.Printf("handleDNCModify for %s\n", key)

	ctx.deviceNetworkConfig = config
	uplinkConfig := devicenetwork.MakeNetworkUplinkConfig(config)
	dnStatus, _ := devicenetwork.MakeDeviceNetworkStatus(uplinkConfig,
		ctx.deviceNetworkStatus)
	if !reflect.DeepEqual(ctx.deviceNetworkStatus, dnStatus) {
		// XXX We publish uplinkConfig even though it might not change
		// XXX needed for initial conversion? Modify files in build
		// from old format?
		*ctx.deviceUplinkConfig = uplinkConfig
		ctx.pubDeviceUplinkConfig.Publish("global", uplinkConfig)
		log.Printf("DeviceNetworkStatus change from %v to %v\n",
			ctx.deviceNetworkStatus, dnStatus)
		ctx.deviceNetworkStatus = dnStatus
		doDNSUpdate(ctx)
	}
	log.Printf("handleDNCModify done for %s\n", key)
}

func handleDNCDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("handleDNCDelete for %s\n", key)
	ctx := ctxArg.(*clientContext)

	if key != ctx.manufacturerModel {
		log.Printf("handleDNCDelete: ignoring %s\n", key)
		return
	}
	dnStatus := types.DeviceNetworkStatus{}
	if !reflect.DeepEqual(ctx.deviceNetworkStatus, dnStatus) {
		log.Printf("DeviceNetworkStatus change from %v to %v\n",
			ctx.deviceNetworkStatus, dnStatus)
		ctx.deviceNetworkStatus = dnStatus
		doDNSUpdate(ctx)
	}
	log.Printf("handleDNCDelete done for %s\n", key)
}

func doDNSUpdate(ctx *clientContext) {
	// Did we loose all usable addresses or gain the first usable
	// address?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus)
	if newAddrCount == 0 && ctx.usableAddressCount != 0 {
		log.Printf("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.usableAddressCount, newAddrCount)
		// Inform ledmanager that we have no addresses
		types.UpdateLedManagerConfig(1)
	} else if newAddrCount != 0 && ctx.usableAddressCount == 0 {
		log.Printf("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.usableAddressCount, newAddrCount)
		// Inform ledmanager that we have uplink addresses
		types.UpdateLedManagerConfig(2)
	}
	ctx.usableAddressCount = newAddrCount
	// XXX need general callback to use this function in zedrouter
}
