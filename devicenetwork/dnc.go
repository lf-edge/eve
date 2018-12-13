// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"reflect"
	"time"
)

type DeviceNetworkContext struct {
	UsableAddressCount      int
	ManufacturerModel       string
	DeviceNetworkConfig     *types.DeviceNetworkConfig
	DevicePortConfig        *types.DevicePortConfig // Currently in use
	DevicePortConfigList    *types.DevicePortConfigList
	DevicePortConfigTime    time.Time
	DeviceNetworkStatus     *types.DeviceNetworkStatus
	SubDeviceNetworkConfig  *pubsub.Subscription
	SubDevicePortConfigA    *pubsub.Subscription
	SubDevicePortConfigO    *pubsub.Subscription
	SubDevicePortConfigS    *pubsub.Subscription
	PubDevicePortConfig     *pubsub.Publication // Derived from DeviceNetworkConfig
	PubDevicePortConfigList *pubsub.Publication
	PubDeviceNetworkStatus  *pubsub.Publication
	Changed                 bool
	SubGlobalConfig         *pubsub.Subscription
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
	portConfig := MakeDevicePortConfig(config)
	if !reflect.DeepEqual(oldConfig, portConfig) {
		log.Infof("DevicePortConfig change from %v to %v\n",
			oldConfig, portConfig)
		ctx.PubDevicePortConfig.Publish("global", portConfig)
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
	portConfig := MakeDevicePortConfig(*ctx.DeviceNetworkConfig)
	if !reflect.DeepEqual(oldConfig, portConfig) {
		log.Infof("DevicePortConfig change from %v to %v\n",
			oldConfig, portConfig)
		ctx.PubDevicePortConfig.Publish("global", portConfig)
	}
	log.Infof("HandleDNCDelete done for %s\n", key)
}

// Handle three different sources in this priority order:
// 1. zedagent with any key
// 2. "override" key from build or USB stick file
// 3. "global" key derived from per-platform DeviceNetworkConfig
// We determine the priority from TimePriority in the config.
func HandleDPCModify(ctxArg interface{}, key string, configArg interface{}) {

	portConfig := cast.CastDevicePortConfig(configArg)
	ctx := ctxArg.(*DeviceNetworkContext)

	curTimePriority := ctx.DevicePortConfigTime
	log.Infof("HandleDPCModify for %s current time %v new time %v\n",
		key, curTimePriority, portConfig.TimePriority)

	zeroTime := time.Time{}
	if key == "override" && portConfig.TimePriority == zeroTime {
		// XXX fix input instead?
		portConfig.TimePriority = time.Unix(1, 0)
		log.Infof("HandleDPCModify: Forcing TimePriority to %v\n",
			portConfig.TimePriority)
	}
	// XXX should we for Name == "" to IfName for each?
	for _, port := range portConfig.Ports {
		if port.Name == "" {
			port.Name = port.IfName
		}
	}

	var curConfig *types.DevicePortConfig
	if ctx.DevicePortConfigList != nil &&
		len(ctx.DevicePortConfigList.PortConfigList) != 0 {
		curConfig = &ctx.DevicePortConfigList.PortConfigList[0]
		log.Infof("HandleDPCModify: found curConfig %+v\n", curConfig)
	} else {
		curConfig = &types.DevicePortConfig{}
	}
	// Look up based on timestamp, then content
	oldConfig := lookupPortConfig(ctx, portConfig)
	if oldConfig != nil {
		if reflect.DeepEqual(oldConfig.Ports, portConfig.Ports) {
			log.Infof("HandleDPCModify: no change; timestamps %v %v\n",
				oldConfig.TimePriority, portConfig.TimePriority)
			log.Infof("HandleDPCModify done for %s\n", key)
			return
		}
		log.Infof("HandleDPCModify: change from %+v to %+v\n",
			*oldConfig, portConfig)
		updatePortConfig(ctx, oldConfig, portConfig)
	} else {
		insertPortConfig(ctx, portConfig)
	}
	ctx.PubDevicePortConfigList.Publish("global", ctx.DevicePortConfigList)
	log.Infof("HandleDPCModify: first is %+v\n",
		ctx.DevicePortConfigList.PortConfigList[0])
	portConfig = ctx.DevicePortConfigList.PortConfigList[0]

	if !reflect.DeepEqual(*ctx.DevicePortConfig, portConfig) {
		log.Infof("HandleDPCModify DevicePortConfig change from %v to %v\n",
			*ctx.DevicePortConfig, portConfig)
		UpdateDhcpClient(portConfig, *ctx.DevicePortConfig)
		*ctx.DevicePortConfig = portConfig
	}
	dnStatus, _ := MakeDeviceNetworkStatus(portConfig,
		*ctx.DeviceNetworkStatus)
	// XXX Only test if the uplink configuration comes from zedcloud.
	// We use device certs to build tls config to hit the test Ping URL.
	// NIM starts even before device onboarding finishes. When a device is
	// booting for the first time and does not have its device certs registered
	// with cloud yet, a hit to out Ping URL would fail.
	pass := TestDeviceNetworkStatus(dnStatus, 1)
	if pass {
		log.Infof("XXXXX Connectivity test passed")
	}
	if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, dnStatus) {
		log.Infof("HandleDPCModify DeviceNetworkStatus change from %v to %v\n",
			*ctx.DeviceNetworkStatus, dnStatus)
		*ctx.DeviceNetworkStatus = dnStatus
		DoDNSUpdate(ctx)
	}
	log.Infof("HandleDPCModify done for %s\n", key)
}

func HandleDPCDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("HandleDPCDelete for %s\n", key)
	ctx := ctxArg.(*DeviceNetworkContext)
	portConfig := cast.CastDevicePortConfig(configArg)

	curTimePriority := ctx.DevicePortConfigTime
	log.Infof("HandleDPCDelete for %s current time %v new time %v\n",
		key, curTimePriority, portConfig.TimePriority)

	// Look up based on timestamp, then content
	oldConfig := lookupPortConfig(ctx, portConfig)
	if oldConfig != nil {
		log.Infof("HandleDPCDelete: found %+v\n", *oldConfig)
		removePortConfig(ctx, *oldConfig)
	} else {
		log.Errorf("HandleDPCDelete: not found %+v\n", portConfig)
	}
	ctx.PubDevicePortConfigList.Publish("global", ctx.DevicePortConfigList)
	if len(ctx.DevicePortConfigList.PortConfigList) != 0 {
		log.Infof("HandleDPCDelete: first is %+v\n",
			ctx.DevicePortConfigList.PortConfigList[0])
		portConfig = ctx.DevicePortConfigList.PortConfigList[0]
	} else {
		log.Infof("HandleDPCDelete: none left\n")
		portConfig = types.DevicePortConfig{}
	}

	if !reflect.DeepEqual(*ctx.DevicePortConfig, portConfig) {
		log.Infof("HandleDPCDelete DevicePortConfig change from %v to %v\n",
			*ctx.DevicePortConfig, portConfig)
		UpdateDhcpClient(portConfig, *ctx.DevicePortConfig)
		*ctx.DevicePortConfig = portConfig
	}
	dnStatus := types.DeviceNetworkStatus{}
	if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, dnStatus) {
		log.Infof("HandleDPCDelete DeviceNetworkStatus change from %v to %v\n",
			*ctx.DeviceNetworkStatus, dnStatus)
		*ctx.DeviceNetworkStatus = dnStatus
		DoDNSUpdate(ctx)
	}
	log.Infof("HandleDPCDelete done for %s\n", key)
}

// First look for matching timestamp, then compare for identical content
// This is needed since after a restart zedagent will provide new timestamps
// even if we persisted the DevicePortConfig before the restart.
func lookupPortConfig(ctx *DeviceNetworkContext,
	portConfig types.DevicePortConfig) *types.DevicePortConfig {

	for i, port := range ctx.DevicePortConfigList.PortConfigList {
		if port.TimePriority == portConfig.TimePriority {
			log.Infof("lookupPortConfig timestamp found +%v\n",
				port)
			return &ctx.DevicePortConfigList.PortConfigList[i]
		}
	}
	for i, port := range ctx.DevicePortConfigList.PortConfigList {
		if reflect.DeepEqual(port.Ports, portConfig.Ports) {
			log.Infof("lookupPortConfig deepequal found +%v\n",
				port)
			return &ctx.DevicePortConfigList.PortConfigList[i]
		}
	}
	return nil
}

// Update content and move if the timestamp changed
func updatePortConfig(ctx *DeviceNetworkContext, oldConfig *types.DevicePortConfig, portConfig types.DevicePortConfig) {

	if oldConfig.TimePriority == portConfig.TimePriority {
		log.Infof("updatePortConfig: same time update %+v\n",
			portConfig)
		*oldConfig = portConfig
		return
	}
	log.Infof("updatePortConfig: diff time remove+add  %+v\n",
		portConfig)
	removePortConfig(ctx, *oldConfig)
	insertPortConfig(ctx, portConfig)
}

// Insert in reverse timestamp order
func insertPortConfig(ctx *DeviceNetworkContext, portConfig types.DevicePortConfig) {

	var newConfig []types.DevicePortConfig
	inserted := false
	for _, port := range ctx.DevicePortConfigList.PortConfigList {
		if !inserted && portConfig.TimePriority.After(port.TimePriority) {
			log.Infof("insertPortConfig: %+v before %+v\n",
				portConfig, port)
			newConfig = append(newConfig, portConfig)
			inserted = true
		}
		newConfig = append(newConfig, port)
	}
	if !inserted {
		log.Infof("insertPortConfig: at end %+v\n", portConfig)
		newConfig = append(newConfig, portConfig)
	}
	ctx.DevicePortConfigList.PortConfigList = newConfig
}

// Remove by matching TimePriority
func removePortConfig(ctx *DeviceNetworkContext, portConfig types.DevicePortConfig) {
	var newConfig []types.DevicePortConfig
	removed := false
	for _, port := range ctx.DevicePortConfigList.PortConfigList {
		if !removed && portConfig.TimePriority == port.TimePriority {
			log.Infof("removePortConfig: found %+v\n",
				port)
			removed = true
		} else {
			newConfig = append(newConfig, port)
		}
	}
	if !removed {
		log.Errorf("removePortConfig: not found %+v\n", portConfig)
		return
	}
	ctx.DevicePortConfigList.PortConfigList = newConfig
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
		// Inform ledmanager that we have port addresses
		types.UpdateLedManagerConfig(2)
	}
	ctx.UsableAddressCount = newAddrCount
	if ctx.PubDeviceNetworkStatus != nil {
		ctx.PubDeviceNetworkStatus.Publish("global", ctx.DeviceNetworkStatus)
	}
	ctx.Changed = true
}
