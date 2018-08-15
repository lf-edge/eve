// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedrouter

import (
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/types"
	"log"
	"reflect"
)

func handleDNCModify(ctxArg interface{}, key string, configArg interface{}) {

	config := cast.CastDeviceNetworkConfig(configArg)
	ctx := ctxArg.(*zedrouterContext)

	if key != ctx.manufacturerModel {
		if debug {
			log.Printf("handleDNCModify: ignoring %s - expecting %s\n",
				key, ctx.manufacturerModel)
		}
		return
	}
	log.Printf("handleDNCModify for %s\n", key)
	// Get old value
	var oldConfig types.DeviceUplinkConfig
	c, _ := ctx.pubDeviceUplinkConfig.Get("global")
	if c != nil {
		oldConfig = cast.CastDeviceUplinkConfig(c)
	} else {
		oldConfig = types.DeviceUplinkConfig{}
	}
	*ctx.deviceNetworkConfig = config
	uplinkConfig := devicenetwork.MakeNetworkUplinkConfig(config)
	if !reflect.DeepEqual(oldConfig, uplinkConfig) {
		log.Printf("DeviceUplinkConfig change from %v to %v\n",
			oldConfig, uplinkConfig)
		ctx.pubDeviceUplinkConfig.Publish("global", uplinkConfig)
	}
	log.Printf("handleDNCModify done for %s\n", key)
}

func handleDNCDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("handleDNCDelete for %s\n", key)
	ctx := ctxArg.(*zedrouterContext)

	if key != ctx.manufacturerModel {
		log.Printf("handleDNCDelete: ignoring %s\n", key)
		return
	}
	// Get old value
	var oldConfig types.DeviceUplinkConfig
	c, _ := ctx.pubDeviceUplinkConfig.Get("global")
	if c != nil {
		oldConfig = cast.CastDeviceUplinkConfig(c)
	} else {
		oldConfig = types.DeviceUplinkConfig{}
	}
	// XXX what's the default? eth0 aka default.json? Use empty for now
	*ctx.deviceNetworkConfig = types.DeviceNetworkConfig{}
	uplinkConfig := devicenetwork.MakeNetworkUplinkConfig(*ctx.deviceNetworkConfig)
	if !reflect.DeepEqual(oldConfig, uplinkConfig) {
		log.Printf("DeviceUplinkConfig change from %v to %v\n",
			oldConfig, uplinkConfig)
		ctx.pubDeviceUplinkConfig.Publish("global", uplinkConfig)
	}
	log.Printf("handleDNCDelete done for %s\n", key)
}

// Handle three different sources in this priority order:
// 1. zedagent with any key
// 2. "override" key from build or USB stick file
// 3. "global" key derived from per-platform DeviceNetworkConfig
func handleDUCModify(ctxArg interface{}, key string, configArg interface{}) {

	uplinkConfig := cast.CastDeviceUplinkConfig(configArg)
	ctx := ctxArg.(*zedrouterContext)

	curPriority := ctx.deviceUplinkConfigPrio
	log.Printf("handleDUCModify for %s current priority %d\n",
		key, curPriority)

	var priority int
	switch key {
	case "global":
		priority = 3
	case "override":
		priority = 2
	default:
		priority = 1
	}
	if curPriority != 0 && priority > curPriority {
		log.Printf("handleDUCModify: ignoring lower priority %s\n",
			key)
		return
	}
	ctx.deviceUplinkConfigPrio = priority

	if !reflect.DeepEqual(*ctx.deviceUplinkConfig, uplinkConfig) {
		log.Printf("DeviceUplinkConfig change from %v to %v\n",
			*ctx.deviceUplinkConfig, uplinkConfig)
		devicenetwork.UpdateDhcpClient(uplinkConfig,
			*ctx.deviceUplinkConfig)
		*ctx.deviceUplinkConfig = uplinkConfig
	}
	dnStatus, _ := devicenetwork.MakeDeviceNetworkStatus(uplinkConfig,
		*ctx.deviceNetworkStatus)
	if !reflect.DeepEqual(*ctx.deviceNetworkStatus, dnStatus) {
		log.Printf("DeviceNetworkStatus change from %v to %v\n",
			*ctx.deviceNetworkStatus, dnStatus)
		*ctx.deviceNetworkStatus = dnStatus
		doDNSUpdate(ctx)
	}
	log.Printf("handleDUCModify done for %s\n", key)
}

func handleDUCDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("handleDUCDelete for %s\n", key)
	ctx := ctxArg.(*zedrouterContext)

	curPriority := ctx.deviceUplinkConfigPrio
	log.Printf("handleDUCDelete for %s current priority %d\n",
		key, curPriority)

	var priority int
	switch key {
	case "global":
		priority = 3
	case "override":
		priority = 2
	default:
		priority = 1
	}
	if curPriority != priority {
		log.Printf("handleDUCDelete: not removing current priority %d for %s\n",
			curPriority, key)
		return
	}
	// XXX we have no idea what the next in line priority is; set to zero
	// as if we have none
	ctx.deviceUplinkConfigPrio = 0

	uplinkConfig := types.DeviceUplinkConfig{}
	if !reflect.DeepEqual(*ctx.deviceUplinkConfig, uplinkConfig) {
		log.Printf("DeviceUplinkConfig change from %v to %v\n",
			*ctx.deviceUplinkConfig, uplinkConfig)
		devicenetwork.UpdateDhcpClient(uplinkConfig,
			*ctx.deviceUplinkConfig)
		*ctx.deviceUplinkConfig = uplinkConfig
	}
	dnStatus := types.DeviceNetworkStatus{}
	if !reflect.DeepEqual(*ctx.deviceNetworkStatus, dnStatus) {
		log.Printf("DeviceNetworkStatus change from %v to %v\n",
			*ctx.deviceNetworkStatus, dnStatus)
		*ctx.deviceNetworkStatus = dnStatus
		doDNSUpdate(ctx)
	}
	log.Printf("handleDUCDelete done for %s\n", key)
}

func doDNSUpdate(ctx *zedrouterContext) {
	// Did we loose all usable addresses or gain the first usable
	// address?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)
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
	if !ctx.ready {
		return
	}
	publishDeviceNetworkStatus(ctx)
	updateLispConfiglets(ctx, ctx.separateDataPlane)
	setFreeUplinks(devicenetwork.GetFreeUplinks(*ctx.deviceUplinkConfig))
	// XXX do a NatInactivate/NatActivate if freeuplinks/uplinks changed?
}
