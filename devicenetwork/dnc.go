// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
)

type DeviceNetworkContext struct {
	UsableAddressCount      int
	ManufacturerModel       string
	DeviceNetworkConfig     *types.DeviceNetworkConfig
	DevicePortConfig        *types.DevicePortConfig // Currently in use
	DevicePortConfigList    *types.DevicePortConfigList
	AssignableAdapters      *types.AssignableAdapters
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

func (ctx *DeviceNetworkContext) doApplyDevicePortConfig(delete bool) {
	portConfig := types.DevicePortConfig{}
	if ctx.DevicePortConfigList == nil ||
		len(ctx.DevicePortConfigList.PortConfigList) == 0 {
		if !delete {
			log.Infof("doApplyDevicePortConfig: No config found for the port.\n")
			return
		}
		log.Infof("doApplyDevicePortConfig: no config left\n")
	} else {
		// PortConfigList[0] is the most desirable config to use
		portConfig = ctx.DevicePortConfigList.PortConfigList[0]
		log.Infof("doApplyDevicePortConfig: config to apply %+v\n",
			portConfig)
	}
	log.Infof("doApplyDevicePortConfig: CurrentConfig: %+v, NewConfig: %+v\n",
		ctx.DevicePortConfig, portConfig)

	if !reflect.DeepEqual(*ctx.DevicePortConfig, portConfig) {
		log.Infof("doApplyDevicePortConfig: DevicePortConfig changed. " +
			"update DhcpClient.\n")
		UpdateDhcpClient(portConfig, *ctx.DevicePortConfig)
		*ctx.DevicePortConfig = portConfig
	} else {
		log.Infof("doApplyDevicePortConfig: Current config same as new config.\n")
	}
}

func (ctx *DeviceNetworkContext) doPublishDNSForPortConfig(
	portConfig *types.DevicePortConfig) {
	// XXX if err return means WPAD failed, or port does not exist
	// XXX add test hook for former; try lower priority
	dnStatus, _ := MakeDeviceNetworkStatus(*portConfig,
		*ctx.DeviceNetworkStatus)

	// We use device certs to build tls config to hit the test Ping URL.
	// NIM starts even before device onboarding finishes. When a device is
	// booting for the first time and does not have its device certs registered
	// with cloud yet, a hit to Ping URL would fail.
	if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, dnStatus) {
		log.Infof("HandleDPCModify DeviceNetworkStatus change from %v to %v\n",
			*ctx.DeviceNetworkStatus, dnStatus)
		pass := VerifyDeviceNetworkStatus(dnStatus, 1)
		// XXX Can fail if we don't have a DHCP lease yet
		if true || pass {
			*ctx.DeviceNetworkStatus = dnStatus
			DoDNSUpdate(ctx)
		} else {
			// XXX try lower priority
			// XXX add retry of higher priority in main
		}
	}
	return
}

// doUpdatePortConfigListAndPublish
//		Returns if the current config has actually changed.
func (ctx *DeviceNetworkContext) doUpdatePortConfigListAndPublish(
	portConfig *types.DevicePortConfig, delete bool) bool {
	// Look up based on timestamp, then content
	oldConfig := lookupPortConfig(ctx, *portConfig)
	if delete {
		if oldConfig == nil {
			log.Errorf("doUpdatePortConfigListAndPublish - Delete. "+
				"Config not found: %+v\n", portConfig)
			return false
		}
		log.Infof("doUpdatePortConfigListAndPublish: Delete. "+
			"oldCOnfig found: %+v\n", *oldConfig, portConfig)
		removePortConfig(ctx, *oldConfig)
	} else {
		if oldConfig != nil {
			// Compare everything but TimePriority since that is
			// modified by zedagent even if there are no changes.
			if oldConfig.Key == portConfig.Key &&
				oldConfig.Version == portConfig.Version &&
				reflect.DeepEqual(oldConfig.Ports, portConfig.Ports) {

				log.Infof("HandleDPCModify: no change; timestamps %v %v\n",
					oldConfig.TimePriority, portConfig.TimePriority)
				return false
			}
			log.Infof("HandleDPCModify: change from %+v to %+v\n",
				*oldConfig, portConfig)
			updatePortConfig(ctx, oldConfig, *portConfig)
		} else {
			insertPortConfig(ctx, *portConfig)
		}
	}
	ctx.PubDevicePortConfigList.Publish("global", ctx.DevicePortConfigList)
	return true
}

// Handle three different sources in this priority order:
// 1. zedagent with any key
// 2. "override" key from build or USB stick file
// 3. "global" key derived from per-platform DeviceNetworkConfig
// We determine the priority from TimePriority in the config.
func HandleDPCModify(ctxArg interface{}, key string, configArg interface{}) {

	portConfig := cast.CastDevicePortConfig(configArg)
	ctx := ctxArg.(*DeviceNetworkContext)

	log.Infof("HandleDPCModify: Current Config: %+v, portConfig: %+v\n",
		ctx.DevicePortConfig, portConfig)

	portConfig.DoSanitize(true, true, key, true)

	ctx.doUpdatePortConfigListAndPublish(&portConfig, false)

	portConfig = ctx.DevicePortConfigList.PortConfigList[0]
	log.Infof("HandleDPCModify: first is %+v\n", portConfig)

	// Publish DeviceNetworkStatus
	ctx.doPublishDNSForPortConfig(&portConfig)

	// Check if all the expected ports in the config are out of pciBack.
	// If yes, apply config.
	// If not, wait for the port to come out of PCIBack.
	portInPciBack, portName := portConfig.IsAnyPortInPciBack(ctx.AssignableAdapters)
	if portInPciBack {
		log.Infof("HandleDPCModify: port %+v still in PCIBack. "+
			"wait for it to come out before applying config.\n", portName)
	} else {
		log.Infof("HandleDPCModify: No ports in pciBack. Apply port config\n")
		ctx.doApplyDevicePortConfig(false)
	}
	log.Infof("HandleDPCModify done for %s\n", key)
}

//
func HandleDPCDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("HandleDPCDelete for %s\n", key)
	ctx := ctxArg.(*DeviceNetworkContext)
	portConfig := cast.CastDevicePortConfig(configArg)

	log.Infof("HandleDPCDelete for %s current time %v deleted time %v\n",
		key, ctx.DevicePortConfig.TimePriority, portConfig.TimePriority)

	portConfig.DoSanitize(false, true, key, true)

	// Look up based on timestamp, then content
	configChanged := ctx.doUpdatePortConfigListAndPublish(&portConfig, true)
	if configChanged {
		return
	}

	ctx.doPublishDNSForPortConfig(&portConfig)

	ctx.doApplyDevicePortConfig(true)

	log.Infof("HandleDPCDelete done for %s\n", key)
}

// HandleAssignableAdaptersModify - Handle Assignable Adapter list modifications
func HandleAssignableAdaptersModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	if key != "global" {
		log.Infof("HandleAssignableAdaptersModify: ignoring %s\n", key)
		return
	}
	ctx := ctxArg.(*DeviceNetworkContext)
	newAssignableAdapters := cast.CastAssignableAdapters(statusArg)
	log.Infof("HandleAssignableAdaptersModify() %+v\n", newAssignableAdapters)

	// ctxArg is DeviceNetworkContext
	for _, ioBundle := range newAssignableAdapters.IoBundleList {
		if ioBundle.Type != types.IoEth {
			continue
		}
		if ctx.AssignableAdapters != nil {
			currentIoBundle := types.LookupIoBundle(ctx.AssignableAdapters,
				types.IoEth, ioBundle.Name)
			if currentIoBundle != nil &&
				ioBundle.IsPCIBack == currentIoBundle.IsPCIBack {
				log.Infof("HandleAssignableAdaptersModify(): ioBundle (%+v) "+
					"PCIBack status (%+v) unchanged\n",
					ioBundle.Name, ioBundle.IsPCIBack)
				continue
			}
		} else {
			log.Infof("HandleAssignableAdaptersModify(): " +
				"ctx.AssignableAdapters = nil\n")
		}
		if ioBundle.IsPCIBack {
			log.Infof("HandleAssignableAdaptersModify(): ioBundle (%+v) changed "+
				"to pciBack", ioBundle.Name)
			// Interface put back in pciBack list.
			// Stop dhcp and update DeviceNetworkStatus
			//doDhcpClientInactivate()  KALYAN- FIXTHIS BEFORE MERGE
		} else {
			log.Infof("HandleAssignableAdaptersModify(): ioBundle (%+v) changed "+
				"to pciBack=false", ioBundle.Name)
			// Interface moved out of PciBack mode.
			ctx.doApplyDevicePortConfig(false)
		}
	}
	*ctx.AssignableAdapters = newAssignableAdapters
	log.Infof("handleAAModify() done\n")
}

// HandleAssignableAdaptersModify - Handle Assignable Adapter list deletions
func HandleAssignableAdaptersDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	// this usually happens only at restart - as any changes to assignable
	//   adapters results in domain restart and takes affect only after
	//   the restart.

	// NoUsbAccess can change dynamically - but it is not network device,
	// so can be ignored. Assuming there are no USB based network interfaces.
	log.Infof("HandleAssignableAdaptersDelete done for %s\n", key)
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

// DoDNSUpdate
//	Update the device network status and publish it.
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
