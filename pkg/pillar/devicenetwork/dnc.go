// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"fmt"
	"reflect"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	MaxDPCRetestCount = 3
)

type PendDNSStatus uint32

const (
	DPC_FAIL PendDNSStatus = iota
	DPC_SUCCESS
	DPC_WAIT
	DPC_PCI_WAIT
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

	Pending                DPCPending
	NetworkTestTimer       *time.Timer
	NetworkTestBetterTimer *time.Timer
	NextDPCIndex           int
	CloudConnectivityWorks bool
	DNCInitialized         bool

	// Timers in seconds
	DPCTestDuration           uint32 // Wait for DHCP address
	NetworkTestInterval       uint32 // Test interval in minutes.
	NetworkTestBetterInterval uint32 // Look for lower/better index
	TestSendTimeout           uint32 // Timeout for HTTP/Send
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
	portConfig.Key = key
	if !reflect.DeepEqual(oldConfig, portConfig) {
		log.Infof("DevicePortConfig change from %v to %v\n",
			oldConfig, portConfig)
		ctx.PubDevicePortConfig.Publish("global", portConfig)
	}
	ctx.DNCInitialized = true
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
	portConfig.Key = key
	if !reflect.DeepEqual(oldConfig, portConfig) {
		log.Infof("DevicePortConfig change from %v to %v\n",
			oldConfig, portConfig)
		ctx.PubDevicePortConfig.Publish("global", portConfig)
	}
	log.Infof("HandleDNCDelete done for %s\n", key)
}

func UpdateLastResortPortConfig(ctx *DeviceNetworkContext, ports []string) {
	if ports == nil || len(ports) == 0 {
		return
	}
	config := LastResortDevicePortConfig(ports)
	config.Key = "lastresort"
	ctx.PubDevicePortConfig.Publish("lastresort", config)
}

func RemoveLastResortPortConfig(ctx *DeviceNetworkContext) {
	ctx.PubDevicePortConfig.Unpublish("lastresort")
}

func SetupVerify(ctx *DeviceNetworkContext, index int) {

	log.Infof("SetupVerify: Setting up verification for DPC at index %d",
		index)
	ctx.NextDPCIndex = index
	ctx.DevicePortConfigList.CurrentIndex = ctx.NextDPCIndex

	pending := &ctx.Pending
	pending.Inprogress = true
	pending.PendDPC = ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex]
	pending.PendDNS, _ = MakeDeviceNetworkStatus(pending.PendDPC, pending.PendDNS)
	pending.TestCount = 0
	log.Infof("SetupVerify: Started testing DPC (index %d): %v",
		ctx.NextDPCIndex,
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
	// Restart at index zero, then skip entries with LastFailed after
	// LastSucceeded and a recent LastFailed (a minute or less).
	nextIndex := getNextTestableDPCIndex(ctx, 0)
	if nextIndex == -1 {
		log.Infof("RestartVerify: nothing testable")
		// Need to publish so that other agents see we have initialized
		// even if we have no IPs
		if ctx.PubDeviceNetworkStatus != nil {
			ctx.DeviceNetworkStatus.Testing = false
			log.Infof("PublishDeviceNetworkStatus: %+v\n",
				ctx.DeviceNetworkStatus)
			ctx.PubDeviceNetworkStatus.Publish("global",
				ctx.DeviceNetworkStatus)
		}
		return
	}
	SetupVerify(ctx, nextIndex)

	VerifyDevicePortConfig(ctx)
	*ctx.DevicePortConfigList = compressAndPublishDevicePortConfigList(ctx)
}

func compressAndPublishDevicePortConfigList(ctx *DeviceNetworkContext) types.DevicePortConfigList {

	dpcl := compressDPCL(ctx.DevicePortConfigList)
	if ctx.PubDevicePortConfigList != nil {
		log.Infof("publishing DevicePortConfigList: %+v\n",
			ctx.DevicePortConfigList)
		ctx.PubDevicePortConfigList.Publish("global", dpcl)
	}
	return dpcl
}

// Make DevicePortConfig have at most two zedagent entries;
// 1. the highest priority (whether it has lastSucceeded after lastFailed or not)
// 2. the next priority with lastSucceeded after lastFailed
// and make it have a single item for the other keys
func compressDPCL(dpcl *types.DevicePortConfigList) types.DevicePortConfigList {

	var newConfig []types.DevicePortConfig
	currentIndex := dpcl.CurrentIndex
	moreZedagent := false
	popped := 0
	foundKeys := make(map[string]bool)
	for i, dpc := range dpcl.PortConfigList {
		_, found := foundKeys[dpc.Key]
		if dpc.Key != "zedagent" {
			if !found {
				newConfig = append(newConfig, dpc)
				foundKeys[dpc.Key] = true
			} else {
				log.Infof("Supressing second entry for %s",
					dpc.Key)
			}
			continue
		}
		failed := !dpc.LastFailed.IsZero() && dpc.LastFailed.After(dpc.LastSucceeded)
		if !found {
			newConfig = append(newConfig, dpc)
			foundKeys[dpc.Key] = true
			moreZedagent = true
			continue
		}
		if moreZedagent {
			newConfig = append(newConfig, dpc)
			moreZedagent = failed
			continue
		}
		moreZedagent = failed

		if currentIndex == i {
			// Don't cut off the branch we are sitting on
			newConfig = append(newConfig, dpc)
			continue
		}
		// delete by not appending
		log.Infof("compressDPCL deleting zedagent index %d: %+v",
			i, dpc)
		if i < currentIndex {
			popped++
		}
	}
	return types.DevicePortConfigList{
		CurrentIndex:   currentIndex - popped,
		PortConfigList: newConfig,
	}
}

var nilUUID = uuid.UUID{} // Really a const

func VerifyPending(pending *DPCPending,
	aa *types.AssignableAdapters, timeout uint32) PendDNSStatus {

	log.Infof("VerifyPending()\n")
	// Stop pending timer if its running.
	pending.PendTimer.Stop()

	// Check if all the ports in the config are out of pciBack.
	// If yes, apply config.
	// If not, wait for all the ports to come out of PCIBack.
	portInPciBack, portName, usedByUUID := pending.PendDPC.IsAnyPortInPciBack(aa)
	if portInPciBack {
		if usedByUUID != nilUUID {
			errStr := fmt.Sprintf("port %s in PCIBack "+
				"used by %s", portName, usedByUUID.String())
			log.Errorf("VerifyPending: %s\n", errStr)
			pending.PendDPC.LastError = errStr
			pending.PendDPC.LastFailed = time.Now()
			return DPC_FAIL
		}
		log.Infof("VerifyPending: port %s still in PCIBack. "+
			"wait for it to come out before re-parsing device port config list.\n",
			portName)
		return DPC_PCI_WAIT
	}
	log.Infof("VerifyPending: No required ports held in pciBack. " +
		"parsing device port config list")

	if !reflect.DeepEqual(pending.PendDPC.Ports, pending.OldDPC.Ports) {
		log.Infof("VerifyPending: DPC changed. update DhcpClient.\n")
		UpdateDhcpClient(pending.PendDPC, pending.OldDPC)
		pending.OldDPC = pending.PendDPC
	}
	pending.PendDNS, _ = MakeDeviceNetworkStatus(pending.PendDPC,
		pending.PendDNS)
	// XXX assume we're doing at least IPv4, so count only those to check if DHCP done
	numUsableAddrs := types.CountLocalIPv4AddrAnyNoLinkLocal(pending.PendDNS)
	if numUsableAddrs == 0 {
		var errStr string
		ifs := types.GetExistingInterfaceList(pending.PendDNS)
		if len(ifs) == 0 {
			errStr = "No interfaces exist in the pending network config"
		} else {
			errStr = "DHCP could not resolve any usable " +
				"IP addresses for the pending network config"
		}
		if pending.TestCount < MaxDPCRetestCount {
			pending.TestCount += 1
			log.Infof("VerifyPending: %s for %+v\n",
				errStr, pending.PendDNS)
			return DPC_WAIT
		} else {
			log.Errorf("VerifyPending: %s for %+v\n",
				errStr, pending.PendDNS)
			pending.PendDPC.LastFailed = time.Now()
			pending.PendDPC.LastError = errStr
			return DPC_FAIL
		}
	}
	// Do not entertain re-testing this DPC anymore.
	pending.TestCount = MaxDPCRetestCount

	// We want connectivity to zedcloud via atleast one Management port.
	rtf, err := VerifyDeviceNetworkStatus(pending.PendDNS, 1, timeout)
	status := DPC_FAIL
	if err == nil {
		pending.PendDPC.LastSucceeded = time.Now()
		pending.PendDPC.LastError = ""
		status = DPC_SUCCESS
		log.Infof("VerifyPending: DPC passed network test: %+v",
			pending.PendDPC)
	} else {
		errStr := fmt.Sprintf("Failed network test: %s",
			err)
		if rtf {
			log.Errorf("VerifyPending: remoteTemporaryFailure %s", errStr)
			// NOTE: do not increase TestCount; we retry until e.g., the
			// certificate or ECONNREFUSED is fixed on the server side.
			status = DPC_WAIT
		} else {
			log.Errorf("VerifyPending: %s\n", errStr)
		}
		pending.PendDPC.LastFailed = time.Now()
		pending.PendDPC.LastError = errStr
	}
	return status
}

func VerifyDevicePortConfig(ctx *DeviceNetworkContext) {
	log.Infof("VerifyDevicePortConfig()\n")
	if !ctx.Pending.Inprogress {
		log.Infof("VerifyDevicePortConfig() not Inprogress\n")
		return
	}
	// Stop network test timer.
	// It shall be resumed when we find working network configuration.
	ctx.NetworkTestTimer.Stop()

	ctx.NetworkTestBetterTimer.Stop()
	pending := &ctx.Pending

	passed := false
	for !passed {
		res := VerifyPending(&ctx.Pending, ctx.AssignableAdapters,
			ctx.TestSendTimeout)
		if ctx.PubDeviceNetworkStatus != nil {
			log.Infof("PublishDeviceNetworkStatus: pending %+v\n",
				ctx.Pending.PendDNS)
			ctx.Pending.PendDNS.Testing = true
			ctx.PubDeviceNetworkStatus.Publish("global", ctx.Pending.PendDNS)
		}
		switch res {
		case DPC_PCI_WAIT:
			// We have already published the new DNS for domainmgr.
			// Wait until we hear from domainmgr before applying (dhcp enable/disable)
			// and testing this new configuration.
			log.Infof("VerifyDevicePortConfig: DPC_PCI_WAIT for %d",
				ctx.NextDPCIndex)
			return
		case DPC_WAIT:
			// Either addressChange or PendTimer will result in calling us again.
			duration := time.Duration(ctx.DPCTestDuration) * time.Second
			pending.PendTimer = time.NewTimer(duration)
			log.Infof("VerifyDevicePortConfig: DPC_WAIT for %d",
				ctx.NextDPCIndex)
			return
		case DPC_FAIL:
			log.Infof("VerifyDevicePortConfig: DPC_FAIL for %d",
				ctx.NextDPCIndex)
			// Avoid clobbering wrong entry if insert/remove after verification
			// started
			tested, index := lookupPortConfig(ctx, pending.PendDPC)
			if tested != nil {
				log.Infof("At %d updating PortConfig %d on DPC_FAIL %+v\n",
					ctx.NextDPCIndex, index, tested)
				*tested = pending.PendDPC
			} else {
				log.Warnf("Not updating list on DPC_FAIL due key mismatch %s vs %s\n",
					ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex].Key,
					pending.PendDPC.Key)
			}
			compressAndPublishDevicePortConfigList(ctx)
			if ctx.DevicePortConfigList.PortConfigList[0].IsDPCUntested() {
				log.Warn("VerifyDevicePortConfig DPC_FAIL: New DPC arrived while network testing " +
					"was in progress. Restarting DPC verification.")
				SetupVerify(ctx, 0)
				continue
			}

			// Move to next index (including wrap around)
			// Skip entries with LastFailed after LastSucceeded and
			// a recent LastFailed (a minute or less).
			nextIndex := getNextTestableDPCIndex(ctx,
				ctx.NextDPCIndex+1)
			if nextIndex == -1 {
				log.Infof("VerifyDevicePortConfig: nothing testable")
				return
			}
			SetupVerify(ctx, nextIndex)
			continue

		case DPC_SUCCESS:
			log.Infof("VerifyDevicePortConfig: DPC_SUCCESS for %d",
				ctx.NextDPCIndex)
			// Avoid clobbering wrong entry if insert/remove after verification
			// started
			tested, index := lookupPortConfig(ctx, pending.PendDPC)
			if tested != nil {
				log.Infof("At %d updating PortConfig %d on DPC_SUCCESS %+v\n",
					ctx.NextDPCIndex, index, tested)
				*tested = pending.PendDPC
			} else {
				log.Warnf("Not updating list on DPC_SUCCESS due key mismatch %s vs %s\n",
					ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex].Key,
					pending.PendDPC.Key)
			}
			passed = true
			if ctx.NextDPCIndex == 0 {
				log.Infof("VerifyDevicePortConfig: Working DPC configuration found "+
					"at index %d in DPC list",
					ctx.NextDPCIndex)
			} else {
				log.Warnf("VerifyDevicePortConfig: Working DPC configuration found "+
					"at index %d in DPC list",
					ctx.NextDPCIndex)
				if ctx.NetworkTestBetterInterval != 0 {
					// Look for a better choice in a while
					duration := time.Duration(ctx.NetworkTestBetterInterval) * time.Second
					ctx.NetworkTestBetterTimer = time.NewTimer(duration)
				}
			}
		}
	}
	// Found a working one
	ctx.DevicePortConfigList.CurrentIndex = ctx.NextDPCIndex
	*ctx.DevicePortConfig = pending.PendDPC
	*ctx.DeviceNetworkStatus = pending.PendDNS
	ctx.DeviceNetworkStatus.Testing = false
	*ctx.DevicePortConfigList = compressAndPublishDevicePortConfigList(ctx)
	DoDNSUpdate(ctx)

	pending.Inprogress = false

	// Did we get a new at index zero?
	if ctx.DevicePortConfigList.PortConfigList[0].IsDPCUntested() {
		log.Warn("VerifyDevicePortConfig DPC_SUCCESS: New DPC arrived while network testing " +
			"was in progress. Restarting DPC verification.")
		RestartVerify(ctx, "VerifyDevicePortConfig DPC_SUCCESS")
		return
	}

	// Restart network test timer
	duration := time.Duration(ctx.NetworkTestInterval) * time.Second
	ctx.NetworkTestTimer = time.NewTimer(duration)
}

// Move to next index (including wrap around)
// Skip entries with LastFailed after LastSucceeded and
// a recent LastFailed (a minute or less).
func getNextTestableDPCIndex(ctx *DeviceNetworkContext, start int) int {
	dpcListLen := len(ctx.DevicePortConfigList.PortConfigList)

	log.Infof("getNextTestableDPCIndex: start %d\n", start)
	// We want to wrap around, but should not keep looping around.
	// We do one loop of the entire list searching for a testable candidate.
	// If no suitable test candidate is found, we reset the test index to 0.
	found := false
	count := 0
	newIndex := start % dpcListLen
	for !found && count < dpcListLen {
		count += 1
		ok := ctx.DevicePortConfigList.PortConfigList[newIndex].IsDPCTestable()
		if ok {
			break
		}
		log.Infof("getNextTestableDPCIndex: DPC %v is not testable",
			ctx.DevicePortConfigList.PortConfigList[newIndex])
		newIndex = (newIndex + 1) % dpcListLen
	}
	if count == dpcListLen {
		newIndex = -1
	}
	log.Infof("getNextTestableDPCIndex: current index %d new %d\n", ctx.NextDPCIndex,
		newIndex)
	return newIndex
}

func getCurrentDPC(ctx *DeviceNetworkContext) *types.DevicePortConfig {
	if len(ctx.DevicePortConfigList.PortConfigList) == 0 ||
		ctx.NextDPCIndex < 0 ||
		ctx.NextDPCIndex >= len(ctx.DevicePortConfigList.PortConfigList) {
		return nil
	}
	return &ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex]
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

	configChanged := ctx.doUpdatePortConfigListAndPublish(&portConfig, false)
	// We could have just booted up and not run RestartVerify even once.
	// If we see a DPC configuration that we already have in the persistent
	// DPC list that we load from storage, we will return with out testing it.
	// In such case we end up not having any working DeviceNetworkStatus (no ips).
	// When the current DeviceNetworkStatus does not have any usable IP addresses,
	// we should go ahead and call RestartVerify even when "configChanged" is false.
	// Also if we have no working one (index -1) we restart.
	ipAddrCount := types.CountLocalIPv4AddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus)
	if !configChanged && ipAddrCount > 0 && ctx.DevicePortConfigList.CurrentIndex != -1 {
		log.Infof("HandleDPCModify: Config already current. No changes to process\n")
		return
	}

	RestartVerify(ctx, "HandleDPCModify")
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

	configChanged := ctx.doUpdatePortConfigListAndPublish(&portConfig, true)
	if !configChanged {
		log.Infof("HandleDPCDelete: System current. No change detected.\n")
		return
	}

	RestartVerify(ctx, "HandleDPCDelete")
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
		if !ioBundle.Type.IsNet() {
			continue
		}
		if ctx.AssignableAdapters != nil {
			currentIoBundle := ctx.AssignableAdapters.LookupIoBundle(
				ioBundle.Type, ioBundle.Name)
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
		// XXX this assumes that ioBundle.Name is the ifname known
		// by the kernel/ifconfig
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
		}
	}
	*ctx.AssignableAdapters = newAssignableAdapters
	// In case a verification is in progress and is waiting for return from pciback
	VerifyDevicePortConfig(ctx)
	log.Infof("handleAssignableAdaptersModify() done\n")
}

// HandleAssignableAdaptersModify - Handle Assignable Adapter list deletions
func HandleAssignableAdaptersDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	// this usually happens only at restart - as any changes to assignable
	//   adapters results in domain restart and takes affect only after
	//   the restart.

	// UsbAccess can change dynamically - but it is not network device,
	// so can be ignored. Assuming there are no USB based network interfaces.
	log.Infof("HandleAssignableAdaptersDelete done for %s\n", key)
}

// First look for matching timestamp, then compare for identical content
// This is needed since after a restart zedagent will provide new timestamps
// even if we persisted the DevicePortConfig before the restart.
func lookupPortConfig(ctx *DeviceNetworkContext,
	portConfig types.DevicePortConfig) (*types.DevicePortConfig, int) {

	for i, port := range ctx.DevicePortConfigList.PortConfigList {
		if port.Version == portConfig.Version &&
			port.Key == portConfig.Key &&
			port.TimePriority == portConfig.TimePriority {

			log.Infof("lookupPortConfig timestamp found +%v\n",
				port)
			return &ctx.DevicePortConfigList.PortConfigList[i], i
		}
	}
	for i, port := range ctx.DevicePortConfigList.PortConfigList {
		if port.Version == portConfig.Version &&
			port.Key == portConfig.Key &&
			reflect.DeepEqual(port.Ports, portConfig.Ports) {

			log.Infof("lookupPortConfig deepequal found +%v\n",
				port)
			return &ctx.DevicePortConfigList.PortConfigList[i], i
		}
	}
	return nil, 0
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

	log.Infof("doPublishDNSForPortConfig()")
	dnStatus, _ := MakeDeviceNetworkStatus(*portConfig,
		*ctx.DeviceNetworkStatus)
	if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, dnStatus) {
		log.Infof("doPublishDNSForPortConfig: DeviceNetworkStatus change from %v to %v\n",
			*ctx.DeviceNetworkStatus, dnStatus)
		*ctx.DeviceNetworkStatus = dnStatus
		DoDNSUpdate(ctx)
	} else {
		log.Infof("doPublishDNSForPortConfig: No change in DNS\n")
	}
	return
}

// doUpdatePortConfigListAndPublish
//		Returns if the current config has actually changed.
func (ctx *DeviceNetworkContext) doUpdatePortConfigListAndPublish(
	portConfig *types.DevicePortConfig, delete bool) bool {
	// Look up based on timestamp, then content

	current := getCurrentDPC(ctx) // Used to determine if index needs to change
	currentIndex := ctx.DevicePortConfigList.CurrentIndex
	oldConfig, _ := lookupPortConfig(ctx, *portConfig)
	if delete {
		if oldConfig == nil {
			log.Errorf("doUpdatePortConfigListAndPublish - Delete. "+
				"Config not found: %+v\n", portConfig)
			return false
		}
		log.Infof("doUpdatePortConfigListAndPublish: Delete. "+
			"oldCOnfig %+v found: %+v\n", *oldConfig, portConfig)
		removePortConfig(ctx, *oldConfig)
	} else if oldConfig != nil {
		// Compare everything but TimePriority since that is
		// modified by zedagent even if there are no changes.
		// If we modify the timestamp for other than current
		// then treat as a change since it could have moved up
		// in the list.
		if oldConfig.Key == portConfig.Key &&
			oldConfig.Version == portConfig.Version &&
			reflect.DeepEqual(oldConfig.Ports, portConfig.Ports) {
			log.Infof("doUpdatePortConfigListAndPublish: no change but timestamps %v %v\n",
				oldConfig.TimePriority, portConfig.TimePriority)

			if current != nil &&
				reflect.DeepEqual(current.Ports, oldConfig.Ports) {

				log.Infof("doUpdatePortConfigListAndPublish: no change and same Ports as current\n")
				return false
			}
			log.Infof("doUpdatePortConfigListAndPublish: changed ports from current; reorder\n")
		} else {
			log.Infof("doUpdatePortConfigListAndPublish: change from %+v to %+v\n",
				*oldConfig, portConfig)
		}
		updatePortConfig(ctx, oldConfig, *portConfig)
	} else {
		insertPortConfig(ctx, *portConfig)
	}
	// Check if current moved to a different index or was deleted
	if current == nil {
		// No current index to update
		log.Infof("doUpdatePortConfigListAndPublish: no current %d",
			currentIndex)
		return true
	}
	newplace, newIndex := lookupPortConfig(ctx, *current)
	if newplace == nil {
		if ctx.DevicePortConfigList.PortConfigList[0].WasDPCWorking() {
			ctx.DevicePortConfigList.CurrentIndex = 0
		} else {
			ctx.DevicePortConfigList.CurrentIndex = -1
		}
	} else if newIndex != currentIndex {
		log.Infof("doUpdatePortConfigListAndPublish: current %d moved to %d",
			currentIndex, newIndex)
		if ctx.DevicePortConfigList.PortConfigList[newIndex].WasDPCWorking() {
			ctx.DevicePortConfigList.CurrentIndex = newIndex
		} else {
			ctx.DevicePortConfigList.CurrentIndex = -1
		}
	}
	*ctx.DevicePortConfigList = compressAndPublishDevicePortConfigList(ctx)
	return true
}

// Update content and move if the timestamp changed
func updatePortConfig(ctx *DeviceNetworkContext, oldConfig *types.DevicePortConfig, portConfig types.DevicePortConfig) {

	if oldConfig.TimePriority == portConfig.TimePriority {
		log.Infof("updatePortConfig: same time update %+v\n",
			portConfig)
		*oldConfig = portConfig
		return
	}
	// Preserve Last*
	portConfig.LastFailed = oldConfig.LastFailed
	portConfig.LastError = oldConfig.LastError
	portConfig.LastSucceeded = oldConfig.LastSucceeded
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

// Remove by matching TimePriority and Key
func removePortConfig(ctx *DeviceNetworkContext, portConfig types.DevicePortConfig) {
	var newConfig []types.DevicePortConfig
	removed := false
	for _, port := range ctx.DevicePortConfigList.PortConfigList {
		if !removed && portConfig.TimePriority == port.TimePriority &&
			portConfig.Key == port.Key {
			log.Infof("removePortConfig: found %+v for %+v\n",
				port, portConfig)
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
	newAddrCount := types.CountLocalIPv4AddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus)
	if newAddrCount != ctx.UsableAddressCount {
		log.Infof("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.UsableAddressCount, newAddrCount)
		// ledmanager subscribes to DeviceNetworkStatus to see changes
		ctx.UsableAddressCount = newAddrCount
	}
	if ctx.PubDeviceNetworkStatus != nil {
		ctx.DeviceNetworkStatus.Testing = false
		log.Infof("PublishDeviceNetworkStatus: %+v\n",
			ctx.DeviceNetworkStatus)
		ctx.PubDeviceNetworkStatus.Publish("global",
			ctx.DeviceNetworkStatus)
	}
	ctx.Changed = true
}
