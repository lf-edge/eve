// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"log"
	"reflect"
)

const debug = false

type DeviceNetworkContext struct {
	UsableAddressCount     int
	ManufacturerModel      string
	DeviceNetworkConfig    *types.DeviceNetworkConfig
	DeviceUplinkConfig     *types.DeviceUplinkConfig
	DeviceUplinkConfigPrio int
	DeviceNetworkStatus    *types.DeviceNetworkStatus
	SubDeviceNetworkConfig *pubsub.Subscription
	SubDeviceUplinkConfigA *pubsub.Subscription
	SubDeviceUplinkConfigO *pubsub.Subscription
	SubDeviceUplinkConfigS *pubsub.Subscription
	PubDeviceUplinkConfig  *pubsub.Publication
	PubDeviceNetworkStatus *pubsub.Publication
	Changed                bool
}

func HandleDNCModify(ctxArg interface{}, key string, configArg interface{}) {

	config := cast.CastDeviceNetworkConfig(configArg)
	ctx := ctxArg.(*DeviceNetworkContext)

	if key != ctx.ManufacturerModel {
		if debug {
			log.Printf("HandleDNCModify: ignoring %s - expecting %s\n",
				key, ctx.ManufacturerModel)
		}
		return
	}
	log.Printf("HandleDNCModify for %s\n", key)
	// Get old value
	var oldConfig types.DeviceUplinkConfig
	c, _ := ctx.PubDeviceUplinkConfig.Get("global")
	if c != nil {
		oldConfig = cast.CastDeviceUplinkConfig(c)
	} else {
		oldConfig = types.DeviceUplinkConfig{}
	}
	*ctx.DeviceNetworkConfig = config
	uplinkConfig := MakeNetworkUplinkConfig(config)
	if !reflect.DeepEqual(oldConfig, uplinkConfig) {
		log.Printf("DeviceUplinkConfig change from %v to %v\n",
			oldConfig, uplinkConfig)
		ctx.PubDeviceUplinkConfig.Publish("global", uplinkConfig)
	}
	log.Printf("HandleDNCModify done for %s\n", key)
}

func HandleDNCDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("HandleDNCDelete for %s\n", key)
	ctx := ctxArg.(*DeviceNetworkContext)

	if key != ctx.ManufacturerModel {
		log.Printf("HandleDNCDelete: ignoring %s\n", key)
		return
	}
	// Get old value
	var oldConfig types.DeviceUplinkConfig
	c, _ := ctx.PubDeviceUplinkConfig.Get("global")
	if c != nil {
		oldConfig = cast.CastDeviceUplinkConfig(c)
	} else {
		oldConfig = types.DeviceUplinkConfig{}
	}
	// XXX what's the default? eth0 aka default.json? Use empty for now
	*ctx.DeviceNetworkConfig = types.DeviceNetworkConfig{}
	uplinkConfig := MakeNetworkUplinkConfig(*ctx.DeviceNetworkConfig)
	if !reflect.DeepEqual(oldConfig, uplinkConfig) {
		log.Printf("DeviceUplinkConfig change from %v to %v\n",
			oldConfig, uplinkConfig)
		ctx.PubDeviceUplinkConfig.Publish("global", uplinkConfig)
	}
	log.Printf("HandleDNCDelete done for %s\n", key)
}

// Handle three different sources in this priority order:
// 1. zedagent with any key
// 2. "override" key from build or USB stick file
// 3. "global" key derived from per-platform DeviceNetworkConfig
func HandleDUCModify(ctxArg interface{}, key string, configArg interface{}) {

	uplinkConfig := cast.CastDeviceUplinkConfig(configArg)
	ctx := ctxArg.(*DeviceNetworkContext)

	curPriority := ctx.DeviceUplinkConfigPrio
	log.Printf("HandleDUCModify for %s current priority %d\n",
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
		log.Printf("HandleDUCModify: ignoring lower priority %s\n",
			key)
		return
	}
	ctx.DeviceUplinkConfigPrio = priority

	if !reflect.DeepEqual(*ctx.DeviceUplinkConfig, uplinkConfig) {
		log.Printf("DeviceUplinkConfig change from %v to %v\n",
			*ctx.DeviceUplinkConfig, uplinkConfig)
		UpdateDhcpClient(uplinkConfig,
			*ctx.DeviceUplinkConfig)
		*ctx.DeviceUplinkConfig = uplinkConfig
	}
	dnStatus, _ := MakeDeviceNetworkStatus(uplinkConfig,
		*ctx.DeviceNetworkStatus)
	if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, dnStatus) {
		log.Printf("DeviceNetworkStatus change from %v to %v\n",
			*ctx.DeviceNetworkStatus, dnStatus)
		*ctx.DeviceNetworkStatus = dnStatus
		DoDNSUpdate(ctx)
	}
	log.Printf("HandleDUCModify done for %s\n", key)
}

func HandleDUCDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("HandleDUCDelete for %s\n", key)
	ctx := ctxArg.(*DeviceNetworkContext)

	curPriority := ctx.DeviceUplinkConfigPrio
	log.Printf("HandleDUCDelete for %s current priority %d\n",
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
		log.Printf("HandleDUCDelete: not removing current priority %d for %s\n",
			curPriority, key)
		return
	}
	// XXX we have no idea what the next in line priority is; set to zero
	// as if we have none
	ctx.DeviceUplinkConfigPrio = 0

	uplinkConfig := types.DeviceUplinkConfig{}
	if !reflect.DeepEqual(*ctx.DeviceUplinkConfig, uplinkConfig) {
		log.Printf("DeviceUplinkConfig change from %v to %v\n",
			*ctx.DeviceUplinkConfig, uplinkConfig)
		UpdateDhcpClient(uplinkConfig,
			*ctx.DeviceUplinkConfig)
		*ctx.DeviceUplinkConfig = uplinkConfig
	}
	dnStatus := types.DeviceNetworkStatus{}
	if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, dnStatus) {
		log.Printf("DeviceNetworkStatus change from %v to %v\n",
			*ctx.DeviceNetworkStatus, dnStatus)
		*ctx.DeviceNetworkStatus = dnStatus
		DoDNSUpdate(ctx)
	}
	log.Printf("HandleDUCDelete done for %s\n", key)
}

func DoDNSUpdate(ctx *DeviceNetworkContext) {
	// Did we loose all usable addresses or gain the first usable
	// address?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus)
	if newAddrCount == 0 && ctx.UsableAddressCount != 0 {
		log.Printf("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.UsableAddressCount, newAddrCount)
		// Inform ledmanager that we have no addresses
		types.UpdateLedManagerConfig(1)
	} else if newAddrCount != 0 && ctx.UsableAddressCount == 0 {
		log.Printf("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.UsableAddressCount, newAddrCount)
		// Inform ledmanager that we have uplink addresses
		types.UpdateLedManagerConfig(2)
	}
	ctx.UsableAddressCount = newAddrCount
	ctx.Changed = true
}
