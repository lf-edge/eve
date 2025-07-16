// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"strings"
	"time"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest/controller"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	uuid "github.com/satori/go.uuid"
)

// deviceStateEvent carries a single device state update delivered to
// processDeviceStateEvents via deviceStateCh.
// Exactly one of infoMsg, metricMsg, or reqEvent is non-nil.
type deviceStateEvent struct {
	devName   string
	infoMsg   *eveinfo.ZInfoMsg
	metricMsg *evemetrics.ZMetricMsg
	reqEvent  *controller.ReqEvent
}

// startDeviceStateWatcher subscribes to ZiDevice info messages and API request
// events for a newly onboarded device, and starts forwarding goroutines that
// relay them to deviceStateCh.
func (th *TestHarness) startDeviceStateWatcher(devName string, devUUID uuid.UUID) {
	infoCh := make(chan *eveinfo.ZInfoMsg, 16)
	unsubInfo, err := th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			switch msg.GetZtype() {
			case eveinfo.ZInfoTypes_ZiDevice,
				eveinfo.ZInfoTypes_ZiApp,
				eveinfo.ZInfoTypes_ZiNetworkInstance:
				return true
			}
			return false
		}, infoCh)
	if err != nil {
		th.log.Errorf("Failed to subscribe to device info for %q: %v", devName, err)
		return
	}

	reqCh := make(chan *controller.ReqEvent, 16)
	unsubReq, err := th.adamClient.SubscribeToDeviceRequests(devUUID, reqCh)
	if err != nil {
		unsubInfo()
		th.log.Errorf("Failed to subscribe to device requests for %q: %v", devName, err)
		return
	}

	metricsCh := make(chan *evemetrics.ZMetricMsg, 16)
	unsubMetrics, err := th.adamClient.SubscribeToDeviceMetrics(devUUID, metricsCh)
	if err != nil {
		unsubInfo()
		unsubReq()
		th.log.Errorf("Failed to subscribe to device metrics for %q: %v", devName, err)
		return
	}

	th.devicesM.Lock()
	th.devices[devName].unsubscribeInfo = unsubInfo
	th.devices[devName].unsubscribeReq = unsubReq
	th.devices[devName].unsubscribeMetrics = unsubMetrics
	th.devicesM.Unlock()

	th.wg.Add(3)
	go func() {
		defer th.wg.Done()
		for {
			select {
			case msg, ok := <-infoCh:
				if !ok {
					return
				}
				select {
				case th.deviceStateCh <- deviceStateEvent{devName: devName, infoMsg: msg}:
				case <-th.ctx.Done():
					return
				}
			case <-th.ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer th.wg.Done()
		for {
			select {
			case msg, ok := <-metricsCh:
				if !ok {
					return
				}
				select {
				case th.deviceStateCh <- deviceStateEvent{devName: devName, metricMsg: msg}:
				case <-th.ctx.Done():
					return
				}
			case <-th.ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer th.wg.Done()
		for {
			select {
			case ev, ok := <-reqCh:
				if !ok {
					return
				}
				select {
				case th.deviceStateCh <- deviceStateEvent{devName: devName, reqEvent: ev}:
				case <-th.ctx.Done():
					return
				}
			case <-th.ctx.Done():
				return
			}
		}
	}()
}

// processDeviceStateEvents is a goroutine that processes device info and request events,
// keeping deviceState.state, deviceState.interfaces, and deviceState.lastRequestAt
// up to date for all onboarded devices.
func (th *TestHarness) processDeviceStateEvents() {
	defer th.wg.Done()
	suspectTicker := time.NewTicker(30 * time.Second)
	defer suspectTicker.Stop()

	for {
		select {
		case event := <-th.deviceStateCh:
			switch {
			case event.infoMsg != nil:
				th.handleDeviceInfoEvent(event.devName, event.infoMsg)
			case event.metricMsg != nil:
				th.handleDeviceMetricsEvent(event.devName, event.metricMsg)
			default:
				th.handleDeviceRequestEvent(event.devName, event.reqEvent)
			}
		case <-suspectTicker.C:
			th.checkSuspectDevices()
		case <-th.ctx.Done():
			return
		}
	}
}

func (th *TestHarness) handleDeviceInfoEvent(devName string, msg *eveinfo.ZInfoMsg) {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	dev, ok := th.devices[devName]
	if !ok {
		return
	}

	switch msg.GetZtype() {
	case eveinfo.ZInfoTypes_ZiDevice:
		dinfo := msg.GetDinfo()
		if dinfo == nil {
			return
		}
		newState := zDeviceStateToEVEDeviceState(
			dinfo.GetState(), dinfo.GetSwList(), dev.lastRequestAt)
		if dev.state != newState {
			th.log.Infof("Device %s state changed: %s -> %s",
				devName, shortDeviceState(dev.state), shortDeviceState(newState))
			dev.state = newState
		}
		dev.interfaces = extractInterfacesFromSystemAdapter(dinfo.GetSystemAdapter())
		if ts := dinfo.GetBootTime(); ts != nil {
			bootTime := ts.AsTime()
			if !dev.lastBootTime.IsZero() && !bootTime.Equal(dev.lastBootTime) {
				diff := bootTime.Sub(dev.lastBootTime)
				// bootTime can jitter by ±1s between successive messages during
				// the same boot (gopsutil reads btime differently on each call).
				// Only count a genuine reboot when the change is at least 5 seconds.
				if diff >= 5*time.Second {
					dev.rebootCount++
					th.log.Infof("Device %s rebooted "+
						"(boot time: %s, previous boot time: %s), "+
						"total observed reboots this test: %d",
						devName, bootTime.Format(time.RFC3339),
						dev.lastBootTime.Format(time.RFC3339),
						dev.rebootCount)
				}
			}
			dev.lastBootTime = bootTime
		}

	case eveinfo.ZInfoTypes_ZiApp:
		ainfo := msg.GetAinfo()
		if ainfo == nil {
			return
		}
		if dev.deployedApps == nil {
			dev.deployedApps = make(map[string]eveinfo.ZSwState)
		}
		appID := ainfo.GetAppID()
		state := ainfo.GetState()
		if state == eveinfo.ZSwState_INVALID {
			delete(dev.deployedApps, appID)
		} else {
			dev.deployedApps[appID] = state
		}
		if dev.deployCond != nil {
			dev.deployCond.Broadcast()
		}

	case eveinfo.ZInfoTypes_ZiNetworkInstance:
		niInfo := msg.GetNiinfo()
		if niInfo == nil {
			return
		}
		if dev.deployedNIs == nil {
			dev.deployedNIs = make(map[string]eveinfo.ZNetworkInstanceState)
		}
		niID := niInfo.GetNetworkID()
		state := niInfo.GetState()
		if state == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED {
			delete(dev.deployedNIs, niID)
		} else {
			dev.deployedNIs[niID] = state
		}
		if dev.deployCond != nil {
			dev.deployCond.Broadcast()
		}
	}
}

func (th *TestHarness) handleDeviceRequestEvent(devName string, ev *controller.ReqEvent) {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	dev, ok := th.devices[devName]
	if !ok {
		return
	}
	if ev.Timestamp.After(dev.lastRequestAt) {
		dev.lastRequestAt = ev.Timestamp
	}
}

func (th *TestHarness) handleDeviceMetricsEvent(devName string, msg *evemetrics.ZMetricMsg) {
	dm := msg.GetDm()
	if dm == nil {
		return
	}
	lpc := dm.GetLastProcessedConfig()
	if lpc == nil {
		return
	}
	ts := lpc.AsTime()
	if ts.IsZero() {
		return
	}
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	dev, ok := th.devices[devName]
	if !ok {
		return
	}
	if ts.After(dev.lastProcessedConfigTs) {
		dev.lastProcessedConfigTs = ts
		if dev.configAppliedCond != nil {
			dev.configAppliedCond.Broadcast()
		}
	}
}

// incExpectedRebootCount increments the expected reboot counter for the named device.
func (th *TestHarness) incExpectedRebootCount(devName string) {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	if dev, ok := th.devices[devName]; ok {
		dev.expectedRebootCount++
	}
}

// checkRebootCounts compares the observed reboot count against the expected
// reboot count for every onboarded device. A mismatch indicates either an
// unexpected reboot (device crashed) or a requested reboot that never occurred.
func (th *TestHarness) checkRebootCounts() {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	for devName, dev := range th.devices {
		if dev.ID == uuid.Nil {
			continue
		}
		if dev.rebootCount != dev.expectedRebootCount {
			th.t.Errorf("Device %q: expected %d reboot(s) but observed %d",
				devName, dev.expectedRebootCount, dev.rebootCount)
		}
	}
}

// checkSuspectDevices marks devices as SUSPECT if they have not made a
// controller request in the last 5 minutes.
func (th *TestHarness) checkSuspectDevices() {
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	for devName, dev := range th.devices {
		if dev.ID == uuid.Nil || dev.unsubscribeInfo == nil {
			continue
		}
		if !dev.lastRequestAt.IsZero() && time.Since(dev.lastRequestAt) > 5*time.Minute {
			if dev.state != api.EVEDeviceState_EVE_DEVICE_STATE_SUSPECT {
				th.log.Warnf("Device %s state changed: %s -> SUSPECT",
					devName, shortDeviceState(dev.state))
				dev.state = api.EVEDeviceState_EVE_DEVICE_STATE_SUSPECT
			}
		}
	}
}

func shortDeviceState(s api.EVEDeviceState) string {
	return strings.TrimPrefix(s.String(), "EVE_DEVICE_STATE_")
}

// zDeviceStateToEVEDeviceState maps a ZDeviceState to an EVEDeviceState,
// applying overrides for TESTING (activated SW under update testing) and
// SUSPECT (no controller request in last 5 minutes).
func zDeviceStateToEVEDeviceState(zState eveinfo.ZDeviceState,
	swList []*eveinfo.ZInfoDevSW, lastRequestAt time.Time) api.EVEDeviceState {
	// SUSPECT: no request in last 5 minutes.
	if !lastRequestAt.IsZero() && time.Since(lastRequestAt) > 5*time.Minute {
		return api.EVEDeviceState_EVE_DEVICE_STATE_SUSPECT
	}
	// TESTING: activated SW is under update testing.
	for _, sw := range swList {
		if sw.GetActivated() && sw.GetSubStatus() == eveinfo.BaseOsSubStatus_UPDATE_TESTING {
			return api.EVEDeviceState_EVE_DEVICE_STATE_TESTING
		}
	}
	switch zState {
	case eveinfo.ZDeviceState_ZDEVICE_STATE_ONLINE:
		return api.EVEDeviceState_EVE_DEVICE_STATE_ONLINE
	case eveinfo.ZDeviceState_ZDEVICE_STATE_REBOOTING:
		return api.EVEDeviceState_EVE_DEVICE_STATE_REBOOTING
	case eveinfo.ZDeviceState_ZDEVICE_STATE_MAINTENANCE_MODE:
		return api.EVEDeviceState_EVE_DEVICE_STATE_MAINTENANCE_MODE
	case eveinfo.ZDeviceState_ZDEVICE_STATE_BASEOS_UPDATING:
		return api.EVEDeviceState_EVE_DEVICE_STATE_UPGRADING
	case eveinfo.ZDeviceState_ZDEVICE_STATE_BOOTING:
		return api.EVEDeviceState_EVE_DEVICE_STATE_BOOTING
	case eveinfo.ZDeviceState_ZDEVICE_STATE_PREPARING_POWEROFF:
		return api.EVEDeviceState_EVE_DEVICE_STATE_PREPARING_POWEROFF
	case eveinfo.ZDeviceState_ZDEVICE_STATE_POWERING_OFF:
		return api.EVEDeviceState_EVE_DEVICE_STATE_POWERING_OFF
	case eveinfo.ZDeviceState_ZDEVICE_STATE_PREPARED_POWEROFF:
		return api.EVEDeviceState_EVE_DEVICE_STATE_PREPARED_POWEROFF
	default:
		return api.EVEDeviceState_EVE_DEVICE_STATE_UNDEFINED
	}
}

// extractInterfacesFromSystemAdapter builds the interface status list from
// the active DevicePortStatus (identified by CurrentIndex) in SystemAdapterInfo.
func extractInterfacesFromSystemAdapter(sa *eveinfo.SystemAdapterInfo) []*api.EVEInterfaceStatus {
	if sa == nil {
		return nil
	}
	statuses := sa.GetStatus()
	idx := int(sa.GetCurrentIndex())
	if idx >= len(statuses) {
		return nil
	}
	ports := statuses[idx].GetPorts()
	interfaces := make([]*api.EVEInterfaceStatus, 0, len(ports))
	for _, p := range ports {
		interfaces = append(interfaces, &api.EVEInterfaceStatus{
			LogicalLabel: p.GetName(),
			IpAddresses:  p.GetIPAddrs(),
			MacAddress:   p.GetMacAddr(),
			Up:           p.GetUp(),
		})
	}
	return interfaces
}
