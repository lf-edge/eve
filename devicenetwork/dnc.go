// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"fmt"
	"os"
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
)

const (
	DNSWaitSeconds  = 30
	NetworkTestInterval = 5
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
	SubAssignableAdapters   *pubsub.Subscription
	PubDevicePortConfig     *pubsub.Publication // Derived from DeviceNetworkConfig
	PubDevicePortConfigList *pubsub.Publication
	PubDeviceNetworkStatus  *pubsub.Publication
	Changed                 bool
	SubGlobalConfig         *pubsub.Subscription
	PendDeviceNetworkStatus *types.DeviceNetworkStatus
	ParseDPCList            chan bool
	DNSTimer                *time.Timer
	NetworkTestTimer        *time.Timer
	NextDPCIndex            int
	ReTestCurrentDPC        bool
	DPCBeingUsed            *types.DevicePortConfig
	DPCBeingTested          *types.DevicePortConfig
	CloudConnectivityWorks  bool
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
	*ctx.DeviceNetworkConfig = types.DeviceNetworkConfig{}
	portConfig := MakeDevicePortConfig(*ctx.DeviceNetworkConfig)
	if !reflect.DeepEqual(oldConfig, portConfig) {
		log.Infof("DevicePortConfig change from %v to %v\n",
			oldConfig, portConfig)
		ctx.PubDevicePortConfig.Publish("global", portConfig)
	}
	log.Infof("HandleDNCDelete done for %s\n", key)
}

func RestartVerify(ctx *DeviceNetworkContext, caller string) {
	log.Infof("RestartVerify: Caller %s initialized DPC list verify at", time.Now())
	if ctx.NextDPCIndex >= 0 {
		log.Infof("RestartVerify: Previous instance of Device port configuration " +
		"list verification in progress currently.")
		log.Infof("RestartVerify: Restart DPC verification from index 0 in DPC list")
	}
	ctx.PendDeviceNetworkStatus = nil
	ctx.NextDPCIndex = 0
	ctx.ReTestCurrentDPC = false

	pass := VerifyDevicePortConfig(ctx)
	if pass {
		log.Infof("RestartVerify: Working Device port configuration found at %v",
			time.Now())
	}
}

func VerifyDevicePortConfig(ctx *DeviceNetworkContext) bool {
	var numUsableAddrs int

	// Stop network test timer.
	// It shall be resumed when we find working network configuration.
	ctx.NetworkTestTimer.Stop()

	// Stop DNS timer and re-start if network test fails
	log.Debugln("VerifyDevicePortConfig: Stopping old DNS timer")
	ctx.DNSTimer.Stop()

	log.Debugln("VerifyDevicePortConfig: Verifying DPC at index %d", ctx.NextDPCIndex)
	numDPCs := len(ctx.DevicePortConfigList.PortConfigList)

	dnStatus := ctx.PendDeviceNetworkStatus
	if dnStatus != nil {
		numUsableAddrs = types.CountLocalAddrFreeNoLinkLocal(*dnStatus)
	}
	// XXX Check if there are any usable unicast ip addresses assigned.
	if dnStatus != nil && numUsableAddrs > 0 {
		ctx.ReTestCurrentDPC = false
		// We want connectivity to zedcloud via atleast one Management port.
		pass := VerifyDeviceNetworkStatus(*dnStatus, 1)
		if pass {
			dpcBeingUsed := ctx.DPCBeingUsed.TimePriority
			dpcBeingTested := ctx.DPCBeingTested.TimePriority
			ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex].LastSucceeded = time.Now()
			if ctx.DPCBeingUsed == nil ||
				dpcBeingTested.After(dpcBeingUsed) ||
				dpcBeingTested.Equal(dpcBeingUsed) {
				log.Infof("VerifyDevicePortConfig: Stopping Device Port configuration test"+
					" at index %d of Device port configuration list", ctx.NextDPCIndex)

				// XXX We should stop the network testing now.
				ctx.PendDeviceNetworkStatus = nil
				ctx.NextDPCIndex = -1

				ctx.DeviceNetworkStatus = dnStatus
				DoDNSUpdate(ctx)
				ctx.DPCBeingUsed = ctx.DPCBeingTested
				*ctx.DevicePortConfig = *ctx.DPCBeingUsed
			} else {
				// Should we stop here?
				log.Infof("VerifyDevicePortConfig: Tested configuration %s "+
					"has a timestamp that is earlier than timestapmp of "+
					"configuration being used %s", ctx.DPCBeingTested, ctx.DPCBeingUsed)
				//ctx.PendDeviceNetworkStatus = nil
				//ctx.NextDPCIndex = -1
			}
			// Re-start network test timer
			networkTestDuration := time.Duration(NetworkTestInterval * time.Minute)
			ctx.NetworkTestTimer = time.NewTimer(networkTestDuration)
			ctx.PubDevicePortConfigList.Publish("global", ctx.DevicePortConfigList)
			log.Debugln("VerifyDevicePortConfig: Re-starting network test timer")
			return true
		} else {
			log.Infof("VerifyDevicePortConfig: DPC configuration at DPC list "+
				"index %d did not work, moving to next valid DPC (if present)",
				ctx.NextDPCIndex)
			ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex].LastFailed = time.Now()
			ctx.PubDevicePortConfigList.Publish("global", ctx.DevicePortConfigList)
			ctx.NextDPCIndex += 1
		}
	} else if dnStatus != nil && numUsableAddrs == 0 {
		// We have a pending device network status, but do not yet have any
		// usable IP addresses assigned to ports. We give this pending
		// device network one more chance by waiting till the next test slot.
		// We mark a flag in device network context saying that we have
		// given a second chance to the current DevicePortConfig.
		//
		// If this is the second try already, move ahead in the DPC list.
		if ctx.ReTestCurrentDPC {
			ctx.NextDPCIndex += 1
			ctx.ReTestCurrentDPC = false
		} else {
			ctx.ReTestCurrentDPC = true
			log.Infof("VerifyDevicePortConfig: Waiting till the next test slot of DPC " +
				"at index %d", ctx.NextDPCIndex)
		}
	}

	// Check if we have exhaused all available device port configurations
	if ctx.NextDPCIndex >= numDPCs {
		log.Errorf("VerifyDevicePortConfig: No working device port configuration found. " +
			"Starting Device port configuration list test again.")
		// Start testing the device port configuration list from beginning
		ctx.PendDeviceNetworkStatus = nil
		ctx.NextDPCIndex = 0
		ctx.ReTestCurrentDPC = false
	}
	portConfig := ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex]
	ctx.DevicePortConfigTime = portConfig.TimePriority

	if !reflect.DeepEqual(*ctx.DevicePortConfig, portConfig) {
		log.Infof("VerifyDevicePortConfig: DevicePortConfig change from %v to %v\n",
			*ctx.DevicePortConfig, portConfig)
		UpdateDhcpClient(portConfig, *ctx.DevicePortConfig)
		*ctx.DevicePortConfig = portConfig
		*ctx.DPCBeingTested = portConfig
	}
	status, _ := MakeDeviceNetworkStatus(portConfig,
		*ctx.DeviceNetworkStatus)
	ctx.PendDeviceNetworkStatus = &status

	// Reset DNS verify timer
	ctx.DNSTimer = time.NewTimer(time.Duration(DNSWaitSeconds * time.Second))
	log.Debugln("VerifyDevicePortConfig: Started new DNS timer")

	return false
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
	log.Infof("HandleDPCModify for %s current time %v modified time %v\n",
		key, curTimePriority, portConfig.TimePriority)

	zeroTime := time.Time{}
	if portConfig.TimePriority == zeroTime {
		// If we can stat the file use its modify time
		filename := fmt.Sprintf("/var/tmp/zededa/DevicePortConfig/%s.json",
			key)
		fi, err := os.Stat(filename)
		if err == nil {
			portConfig.TimePriority = fi.ModTime()
		} else {
			portConfig.TimePriority = time.Unix(1, 0)
		}
		log.Infof("HandleDPCModify: Forcing TimePriority for %s to %v\n",
			key, portConfig.TimePriority)
	}
	if portConfig.Key == "" {
		portConfig.Key = key
	}
	// In case Name isn't set we make it match IfName
	// XXX still needed?
	for i, _ := range portConfig.Ports {
		port := &portConfig.Ports[i]
		if port.Name == "" {
			port.Name = port.IfName
		}
	}

	// Look up based on timestamp, then content
	oldConfig := lookupPortConfig(ctx, portConfig)
	if oldConfig != nil {
		// Compare everything but TimePriority since that is
		// modified by zedagent even if there are no changes.

		// XXX Why would the below check be needed?
		// Shouldn't updatePortConfig be called?
		// Even when old and new configurations look the same, we
		// should still remove old config and put latest config
		// in the beginning of device port config list, no?
		if oldConfig.Key == portConfig.Key &&
			oldConfig.Version == portConfig.Version &&
			reflect.DeepEqual(oldConfig.Ports, portConfig.Ports) {

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

	//kickStartDPCListVerify(ctx)
	RestartVerify(ctx, "HandleDPCModify")

	log.Infof("HandleDPCModify done for %s\n", key)
}

//
func HandleDPCDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("HandleDPCDelete for %s\n", key)
	ctx := ctxArg.(*DeviceNetworkContext)
	portConfig := cast.CastDevicePortConfig(configArg)

	curTimePriority := ctx.DevicePortConfigTime
	log.Infof("HandleDPCDelete for %s current time %v deleted time %v\n",
		key, curTimePriority, portConfig.TimePriority)

	if portConfig.Key == "" {
		portConfig.Key = key
	}
	// In case Name isn't set we make it match IfName
	// XXX still needed?
	for i, _ := range portConfig.Ports {
		port := &portConfig.Ports[i]
		if port.Name == "" {
			port.Name = port.IfName
		}
	}

	// Look up based on timestamp, then content
	oldConfig := lookupPortConfig(ctx, portConfig)
	if oldConfig == nil {
		log.Errorf("HandleDPCDelete: not found %+v\n", portConfig)
		return
	}

	log.Infof("HandleDPCDelete: found %+v\n", *oldConfig)
	removePortConfig(ctx, *oldConfig)
	ctx.PubDevicePortConfigList.Publish("global", ctx.DevicePortConfigList)

	//kickStartDPCListVerify(ctx)
	RestartVerify(ctx, "HandleDPCDelete")
	log.Infof("HandleDPCDelete done for %s\n", key)
}

// HandleAssignableAdaptersModify - Handle Assignable Adapter list modifications
func HandleAssignableAdaptersModify(ctxArg interface{}, key string,
	configArg interface{}) {
}

// HandleAssignableAdaptersModify - Handle Assignable Adapter list deletions
func HandleAssignableAdaptersDelete(ctxArg interface{}, key string,
	configArg interface{}) {
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
		if port.Version == portConfig.Version &&
			port.Key == portConfig.Key &&
			reflect.DeepEqual(port.Ports, portConfig.Ports) {

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
