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
	MaxDPCRetestCount = 3
)

type PendDNSStatus uint32
const (
	DPC_FAIL PendDNSStatus = iota
	DPC_SUCCESS
	DPC_WAIT
)

type DPCPending struct {
	Inprogress bool
	PendDPC    types.DevicePortConfig
	OldDPC     types.DevicePortConfig
	PendDNS    types.DeviceNetworkStatus
	PendTimer  *time.Timer
	TestCount  uint
}

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

	Pending                 DPCPending
	NetworkTestTimer        *time.Timer
	NextDPCIndex            int
	CloudConnectivityWorks  bool

	// How long should we wait before testing a pending DPC?
	DPCTestDuration         time.Duration  // In seconds.
	NetworkTestInterval     time.Duration  // Test interval in minutes.
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

func SetupVerify(ctx *DeviceNetworkContext, index int) {
	log.Debugln("SetupVerify: Setting up verification for DPC at index %d", index)
	ctx.NextDPCIndex = index

	pending := &ctx.Pending
	pending.Inprogress = true
	pending.PendDPC    = ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex]
	pending.PendDNS, _ = MakeDeviceNetworkStatus(pending.PendDPC, pending.PendDNS)
	pending.TestCount = 0
	log.Debugln("SetupVerify: Started testing DPC %v",
		ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex])
}

func RestartVerify(ctx *DeviceNetworkContext, caller string) {
	log.Infof("RestartVerify: Caller %s initialized DPC list verify at %v",
		caller, time.Now())

	pending := &ctx.Pending
	if pending.Inprogress {
		log.Infof("RestartVerify: DPC list verification in progress")
		return
	}
	SetupVerify(ctx, 0)
	VerifyDevicePortConfig(ctx)
}

func VerifyPending(pending *DPCPending) PendDNSStatus {
	pending.PendTimer.Stop()

	UpdateDhcpClient(pending.PendDPC, pending.OldDPC)
	pending.OldDPC = pending.PendDPC
	pending.PendDNS, _ = MakeDeviceNetworkStatus(pending.PendDPC,
		pending.PendDNS)
	numUsableAddrs := types.CountLocalAddrFreeNoLinkLocal(pending.PendDNS)
	if numUsableAddrs == 0 {
		if pending.TestCount < MaxDPCRetestCount {
			pending.TestCount += 1
			log.Debugln("VerifyPending: Pending DNS %v does not " +
				"have any usable IP addresses", pending.PendDNS)
			return DPC_WAIT
		} else {
			pending.PendDPC.LastFailed = time.Now()
			log.Debugln("VerifyPending: DHCP could not resolve any usable " +
				"IP addresses for the pending DNS %v", pending.PendDNS)
			return DPC_FAIL
		}
	}
	// Do not entertain re-testing this DPC anymore.
	pending.TestCount = MaxDPCRetestCount

	// We want connectivity to zedcloud via atleast one Management port.
	res := VerifyDeviceNetworkStatus(pending.PendDNS, 1)
	status := DPC_FAIL
	if res {
		pending.PendDPC.LastSucceeded = time.Now()
		status = DPC_SUCCESS
		log.Infof("VerifyPending: DPC %v passed network test", pending.PendDPC)
	} else {
		pending.PendDPC.LastFailed = time.Now()
		log.Infof("VerifyPending: DPC %v failed network test", pending.PendDPC)
	}
	return status
}

func VerifyDevicePortConfig(ctx *DeviceNetworkContext) {
	// Stop network test timer.
	// It shall be resumed when we find working network configuration.
	ctx.NetworkTestTimer.Stop()

	pending := &ctx.Pending

	passed := false
	for !passed {
		res := VerifyPending(&ctx.Pending)
		if ctx.PubDeviceNetworkStatus != nil {
			ctx.PubDeviceNetworkStatus.Publish("global", ctx.Pending.PendDNS)
		}
		switch res {
		case DPC_WAIT:
			// Either addressChange or PendTimer will result in calling us again.
			pending.PendTimer = time.NewTimer(ctx.DPCTestDuration * time.Second)
			return
		case DPC_FAIL:
			ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex] = pending.PendDPC
			if ctx.PubDevicePortConfigList != nil {
				ctx.PubDevicePortConfigList.Publish("global", ctx.DevicePortConfigList)
			}
			// Check if there is an untested DPC configuration at index 0
			// If yes, restart the test process from index 0
			if isDPCUntested(ctx.DevicePortConfigList.PortConfigList[0]) {
				log.Warn("VerifyDevicePortConfig: New DPC arrived while network testing " +
					"was in progress. Restarting DPC verification.")
				SetupVerify(ctx, 0)
				continue
			}

			// Move to next index (including wrap around)
			// Skip entries with LastFailed after LastSucceeded and
			// a recent LastFailed (a minute or less).
			dpcListLen := len(ctx.DevicePortConfigList.PortConfigList)

			// XXX What is a good condition to stop this loop?
			// We want to wrap around, but should not keep looping around.
			// Should we do one loop of the entire list and start from index 0
			// if no suitable test candidate is found?
			found := false
			count := 0
			newIndex := (ctx.NextDPCIndex + 1) % dpcListLen
			for !found && count < dpcListLen {
				count += 1
				ok := isDPCTestable(ctx.DevicePortConfigList.PortConfigList[newIndex])
				if ok {
					break
				}
				log.Debugln("VerifyDevicePortConfig: DPC %v is not testable",
					ctx.DevicePortConfigList.PortConfigList[newIndex])
				newIndex = (newIndex + 1) % dpcListLen
			}
			if count == dpcListLen {
				newIndex = 0
			}
			SetupVerify(ctx, newIndex)
			continue
		case DPC_SUCCESS:
			ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex] = pending.PendDPC
			if ctx.PubDevicePortConfigList != nil {
				ctx.PubDevicePortConfigList.Publish("global", ctx.DevicePortConfigList)
			}
			// Check if there is an untested DPC configuration at index 0
			// If yes, restart the test process from index 0
			if isDPCUntested(ctx.DevicePortConfigList.PortConfigList[0]) {
				log.Warn("VerifyDevicePortConfig: New DPC arrived while network testing " +
					"was in progress. Restarting DPC verification.")
				SetupVerify(ctx, 0)
				continue
			}
			passed = true
			log.Infof("VerifyDevicePortConfig: Working DPC configuration found" +
				"at index %d in DPC list", ctx.NextDPCIndex)
		}
	}
	*ctx.DevicePortConfig = pending.PendDPC
	*ctx.DeviceNetworkStatus = pending.PendDNS
	DoDNSUpdate(ctx)

	pending.Inprogress = false
	pending.OldDPC = getCurrentDPC(ctx)

	// Restart network test timer
	ctx.NetworkTestTimer = time.NewTimer(ctx.NetworkTestInterval * time.Minute)
}

func getCurrentDPC(ctx *DeviceNetworkContext) types.DevicePortConfig {
	if len(ctx.DevicePortConfigList.PortConfigList) == 0 ||
		ctx.NextDPCIndex >= len(ctx.DevicePortConfigList.PortConfigList) {
		return types.DevicePortConfig{}
	}
	return ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex]
}

func isDPCTestable(dpc types.DevicePortConfig) bool {
	// convert time difference in nano seconds to seconds
	timeDiff := int64(time.Now().Sub(dpc.LastFailed)/time.Second)

	if dpc.LastFailed.After(dpc.LastSucceeded) && timeDiff < 60 {
		return false
	}
	return true
}

func isDPCUntested(dpc types.DevicePortConfig) bool {
	if dpc.LastFailed.IsZero() && dpc.LastSucceeded.IsZero() {
		return true
	}
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
