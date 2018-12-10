// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"reflect"
)

type DeviceNetworkContext struct {
	UsableAddressCount     int
	ManufacturerModel      string
	DeviceNetworkConfig    *types.DeviceNetworkConfig
	DevicePortConfig       *types.DevicePortConfig
	DevicePortConfigPrio   int
	DeviceNetworkStatus    *types.DeviceNetworkStatus
	SubDeviceNetworkConfig *pubsub.Subscription
	SubDevicePortConfigA   *pubsub.Subscription
	SubDevicePortConfigO   *pubsub.Subscription
	SubDevicePortConfigS   *pubsub.Subscription
	PubDevicePortConfig    *pubsub.Publication
	PubDeviceNetworkStatus *pubsub.Publication
	Changed                bool
	SubGlobalConfig        *pubsub.Subscription
}

func HandleDNCModify(ctxArg interface{}, key string, configArg interface{}) {

	config := cast.CastDeviceNetworkConfig(configArg)
	ctx := ctxArg.(*DeviceNetworkContext)
	if key != ctx.ManufacturerModel {
		log.Debugf("HandleDNCModify: ignoring %s - expecting %s\n",
			key, ctx.ManufacturerModel)
		return
	}
	log.Infof("HandleDNCModify for %s\n", key)
	// Get old value
	var oldConfig types.DevicePortConfig
	c, _ := ctx.PubDevicePortConfig.Get("global")
	if c != nil {
		oldConfig = cast.CastDevicePortConfig(c)
	} else {
		oldConfig = types.DevicePortConfig{}
	}
	*ctx.DeviceNetworkConfig = config
	uplinkConfig := MakeNetworkPortConfig(config)
	if !reflect.DeepEqual(oldConfig, uplinkConfig) {
		log.Infof("DevicePortConfig change from %v to %v\n",
			oldConfig, uplinkConfig)
		ctx.PubDevicePortConfig.Publish("global", uplinkConfig)
	}
	log.Infof("HandleDNCModify done for %s\n", key)
}

func HandleDNCDelete(ctxArg interface{}, key string, configArg interface{}) {

	ctx := ctxArg.(*DeviceNetworkContext)
	if key != ctx.ManufacturerModel {
		log.Debugf("HandleDNCDelete: ignoring %s\n", key)
		return
	}
	log.Infof("HandleDNCDelete for %s\n", key)
	// Get old value
	var oldConfig types.DevicePortConfig
	c, _ := ctx.PubDevicePortConfig.Get("global")
	if c != nil {
		oldConfig = cast.CastDevicePortConfig(c)
	} else {
		oldConfig = types.DevicePortConfig{}
	}
	// XXX what's the default? eth0 aka default.json? Use empty for now
	*ctx.DeviceNetworkConfig = types.DeviceNetworkConfig{}
	uplinkConfig := MakeNetworkPortConfig(*ctx.DeviceNetworkConfig)
	if !reflect.DeepEqual(oldConfig, uplinkConfig) {
		log.Infof("DevicePortConfig change from %v to %v\n",
			oldConfig, uplinkConfig)
		ctx.PubDevicePortConfig.Publish("global", uplinkConfig)
	}
	log.Infof("HandleDNCDelete done for %s\n", key)
}

// Handle three different sources in this priority order:
// 1. zedagent with any key
// 2. "override" key from build or USB stick file
// 3. "global" key derived from per-platform DeviceNetworkConfig
func HandleDUCModify(ctxArg interface{}, key string, configArg interface{}) {

	uplinkConfig := cast.CastDevicePortConfig(configArg)
	ctx := ctxArg.(*DeviceNetworkContext)

	curPriority := ctx.DevicePortConfigPrio
	log.Infof("HandleDUCModify for %s current priority %d\n",
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
		log.Infof("HandleDUCModify: ignoring lower priority %s\n",
			key)
		return
	}
	ctx.DevicePortConfigPrio = priority

	if !reflect.DeepEqual(*ctx.DevicePortConfig, uplinkConfig) {
		log.Infof("DevicePortConfig change from %v to %v\n",
			*ctx.DevicePortConfig, uplinkConfig)
		UpdateDhcpClient(uplinkConfig,
			*ctx.DevicePortConfig)
		*ctx.DevicePortConfig = uplinkConfig
	}
	dnStatus, _ := MakeDeviceNetworkStatus(uplinkConfig,
		*ctx.DeviceNetworkStatus)
	if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, dnStatus) {
		log.Infof("DeviceNetworkStatus change from %v to %v\n",
			*ctx.DeviceNetworkStatus, dnStatus)
		*ctx.DeviceNetworkStatus = dnStatus
		DoDNSUpdate(ctx)
	}
	log.Infof("HandleDUCModify done for %s\n", key)
}

func HandleDUCDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("HandleDUCDelete for %s\n", key)
	ctx := ctxArg.(*DeviceNetworkContext)

	curPriority := ctx.DevicePortConfigPrio
	log.Infof("HandleDUCDelete for %s current priority %d\n",
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
		log.Infof("HandleDUCDelete: not removing current priority %d for %s\n",
			curPriority, key)
		return
	}
	// XXX we have no idea what the next in line priority is; set to zero
	// as if we have none
	ctx.DevicePortConfigPrio = 0

	uplinkConfig := types.DevicePortConfig{}
	if !reflect.DeepEqual(*ctx.DevicePortConfig, uplinkConfig) {
		log.Infof("DevicePortConfig change from %v to %v\n",
			*ctx.DevicePortConfig, uplinkConfig)
		UpdateDhcpClient(uplinkConfig,
			*ctx.DevicePortConfig)
		*ctx.DevicePortConfig = uplinkConfig
	}
	dnStatus := types.DeviceNetworkStatus{}
	if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, dnStatus) {
		log.Infof("DeviceNetworkStatus change from %v to %v\n",
			*ctx.DeviceNetworkStatus, dnStatus)
		*ctx.DeviceNetworkStatus = dnStatus
		DoDNSUpdate(ctx)
	}
	log.Infof("HandleDUCDelete done for %s\n", key)
}

func DoDNSUpdate(ctx *DeviceNetworkContext) {
	// Did we loose all usable addresses or gain the first usable
	// address?
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus)
	if newAddrCount == 0 && ctx.UsableAddressCount != 0 {
		log.Infof("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.UsableAddressCount, newAddrCount)
		// Inform ledmanager that we have no addresses
		types.UpdateLedManagerConfig(1)
	} else if newAddrCount != 0 && ctx.UsableAddressCount == 0 {
		log.Infof("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.UsableAddressCount, newAddrCount)
		// Inform ledmanager that we have uplink addresses
		types.UpdateLedManagerConfig(2)
	}
	ctx.UsableAddressCount = newAddrCount
	if ctx.PubDeviceNetworkStatus != nil {
		ctx.PubDeviceNetworkStatus.Publish("global", ctx.DeviceNetworkStatus)
	}
	ctx.Changed = true
}
