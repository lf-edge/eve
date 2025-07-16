// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveflowlog "github.com/lf-edge/eve-api/go/flowlog"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	evelogs "github.com/lf-edge/eve-api/go/logs"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EdgeDevice represents a single onboarded EVE device and provides
// operations to manage its lifecycle, configuration, applications,
// and runtime state.
type EdgeDevice struct {
	th      *TestHarness
	devName string
	// Set of app UUIDs (strings) for which WaitUntilAppIsRunning is active.
	// Used by WatchAppInfo to suppress duplicate state logging.
	appsBeingWaited sync.Map
}

// GetEdgeDevice returns a handle to an onboarded EdgeDevice identified by devName.
func GetEdgeDevice(devName string) *EdgeDevice {
	th := getTestHarness()
	if !th.isDeviceOnboarded(devName) {
		th.t.Fatalf("Unknown device %q", devName)
	}
	return &EdgeDevice{th: th, devName: devName}
}

// GetAllEdgeDevices returns handles for all EdgeDevices currently known to the
// test th.
func GetAllEdgeDevices() (devices []*EdgeDevice) {
	th := getTestHarness()
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	for _, devState := range th.devices {
		devices = append(devices, &EdgeDevice{th: th, devName: devState.name})
	}
	return devices
}

const (
	// All EdgeDevice.Watch* methods return channels with a buffer size of 100.
	// This reduces the risk of dropping info/metrics notifications even if the
	// test is temporarily not reading from the channel (e.g., while waiting on
	// another condition).
	watchChannelBufSize = 100
)

// LogMsg represents a single log message emitted by the device or an application.
type LogMsg struct {
	Severity  string
	Source    string
	Filename  string
	Message   string
	Timestamp time.Time
}

// LogMsgMatch defines filtering criteria for matching log messages.
type LogMsgMatch struct {
	Severity         string
	Source           string
	Filename         string
	MsgHasSubstring  string
	MsgMatchesRegexp regexp.Regexp
	NotBefore        time.Time
	NotAfter         time.Time
}

// FlowLogMatch defines filtering criteria for matching application flow logs.
type FlowLogMatch struct {
	Flow              *eveflowlog.IpFlow // match every non-zero value from the 5-tuple
	Inbound           bool
	VirtualNetAdapter string // logical label
	NetworkInstance   uuid.UUID
	// NotBefore and NotAfter relates to FlowRecord.startTime
	NotBefore time.Time
	NotAfter  time.Time
}

// DNSLogMatch defines filtering criteria for matching application DNS logs.
type DNSLogMatch struct {
	VirtualNetAdapter string // logical label
	NetworkInstance   uuid.UUID
	// NotBefore and NotAfter relates to DnsRequest.requestTime
	NotBefore time.Time
	NotAfter  time.Time
}

// AuthMethod is a marker interface for application authentication methods.
type AuthMethod interface {
	isAuthMethod()
}

// UsernamePasswordAuth represents username/password authentication.
type UsernamePasswordAuth struct {
	Username string
	Password string
}

func (UsernamePasswordAuth) isAuthMethod() {}

// ClientCertAuth represents client certificate–based authentication.
type ClientCertAuth struct {
	KeyPEM string
}

func (ClientCertAuth) isAuthMethod() {}

// GetState returns the current lifecycle state of the device.
func (d *EdgeDevice) GetState() api.EVEDeviceState {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	devState, found := d.th.devices[d.devName]
	if !found {
		return api.EVEDeviceState_EVE_DEVICE_STATE_UNDEFINED
	}
	return devState.state
}

// ApplyConfig applies a device configuration and optionally waits for
// confirmation that it was received and/or processed by the device.
//
// If waitUntilFetched is true, the function blocks until EVE fetches the new
// config from the controller. This is reliable even when the config changes
// the management port, because EVE downloads the config before activating
// the new port — the wait completes while connectivity is still intact.
//
// If waitUntilConfirmed is true, the function additionally waits until EVE
// reports LastProcessedConfig >= the config's timestamp in device metrics,
// which indicates that zedagent has parsed the config and distributed it to
// other microservices. Do not combine this with configs that change the
// management port: the device may lose controller connectivity right after
// applying the change, delaying the metrics publish indefinitely.
//
// The two flags are evaluated in order: fetch first, then confirm.
func (d *EdgeDevice) ApplyConfig(config *EdgeDeviceConfig, waitUntilFetched bool, waitUntilConfirmed bool) {
	if d.devName != config.DeviceName {
		d.th.t.Fatalf("Device name mismatch: "+
			"EdgeDevice handle is for %q but config is for %q",
			d.devName, config.DeviceName)
	}

	// Get previous config.
	d.th.devicesM.Lock()
	devState, found := d.th.devices[d.devName]
	if !found {
		d.th.t.Fatalf("Unknown device %q", d.devName)
	}
	devUUID := devState.ID
	prevConfig := devState.config
	d.th.devicesM.Unlock()

	// Set config ID.
	configVer := d.th.nextConfigVersion(prevConfig)
	newConfig := config.Clone()
	newConfig.Id = &eveconfig.UUIDandVersion{
		Uuid:    devUUID.String(),
		Version: configVer,
	}

	// Set timestamp.
	newConfig.ConfigTimestamp = timestamppb.New(time.Now())

	// Set default global configuration properties.
	newConfig.setDefaultConfigProperties()

	// Preserve device reboot counter and per-app restart/purge counters from
	// the previous config when the new config does not set them explicitly.
	// This prevents a subsequent RequestReboot or Reboot/PurgeApplication
	// call from re-issuing a command the device has already processed.
	if prevConfig != nil {
		if newConfig.Reboot == nil {
			newConfig.Reboot = prevConfig.GetReboot()
		}
		prevApps := make(map[string]*eveconfig.AppInstanceConfig,
			len(prevConfig.GetApps()))
		for _, app := range prevConfig.GetApps() {
			prevApps[app.GetUuidandversion().GetUuid()] = app
		}
		for _, app := range newConfig.GetApps() {
			prev, ok := prevApps[app.GetUuidandversion().GetUuid()]
			if !ok {
				continue
			}
			if app.Restart == nil {
				app.Restart = prev.GetRestart()
			}
			if app.Purge == nil {
				app.Purge = prev.GetPurge()
			}
		}
	}

	// Always keep a non-nil Reboot command in the config so EVE records a baseline
	// counter on first boot. Without this, the first RequestReboot call lands when
	// EVE has no saved counter (opCfg == nil) and EVE's "first boot" guard skips the
	// reboot, saving the counter but never triggering the operation.
	if newConfig.Reboot == nil {
		newConfig.Reboot = &eveconfig.DeviceOpsCmd{Counter: 0, DesiredState: false}
	}

	// Preserve cipher contexts.
	if prevConfig != nil {
		newConfig.CipherContexts = prevConfig.GetCipherContexts()
	}

	ctx, cancel := context.WithTimeout(d.th.ctx, adamApplyConfigTimeout)
	err := d.th.adamClient.ApplyDeviceConfig(ctx, devUUID, newConfig.EdgeDevConfig)
	cancel()
	if err != nil {
		d.th.t.Fatalf("Failed to apply the new configuration "+
			"(version %s) for device %q: %v", configVer, d.devName, err)
	}

	// Save the applied config.
	d.th.devicesM.Lock()
	d.th.devices[d.devName].config = newConfig
	d.th.devicesM.Unlock()

	if waitUntilFetched {
		d.th.log.Infof(
			"Waiting for device %q to fetch the latest config (version %s)...",
			d.devName, configVer)
		ctx, cancel = context.WithTimeout(d.th.ctx, deviceApplyConfigTimeout)
		err = d.th.adamClient.WaitUntilDevRequest(ctx, devUUID, "/config")
		cancel()
		if err != nil {
			d.th.t.Fatalf(
				"Device %q failed to fetch the latest config (version %s): %v",
				d.devName, configVer, err)
		}
		d.th.log.Infof("Device %q fetched the latest config (version %s)",
			d.devName, configVer)
	}

	if waitUntilConfirmed {
		// Wait for DeviceMetric.LastProcessedConfig >= configTimestamp. EVE sets
		// LastProcessedConfig to the config's own ConfigTimestamp, so the
		// comparison is clock-skew-free.
		configTs := newConfig.ConfigTimestamp.AsTime()
		d.th.log.Infof(
			"Waiting for device %q to confirm the latest config (version %s)...",
			d.devName, configVer)
		ctx, cancel = context.WithTimeout(d.th.ctx, deviceApplyConfigTimeout)
		defer cancel()
		d.th.devicesM.Lock()
		dev := d.th.devices[d.devName]
		if dev.configAppliedCond == nil {
			dev.configAppliedCond = sync.NewCond(&d.th.devicesM)
		}
		// sync.Cond.Wait has no context awareness, so a separate goroutine
		// broadcasts on cancellation/timeout to unblock the loop below.
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				dev.configAppliedCond.Broadcast()
			case <-done:
			}
		}()
		for dev.lastProcessedConfigTs.Before(configTs) {
			if ctx.Err() != nil {
				break
			}
			dev.configAppliedCond.Wait()
		}
		confirmed := !dev.lastProcessedConfigTs.Before(configTs)
		close(done)
		d.th.devicesM.Unlock()
		if !confirmed {
			d.th.t.Fatalf(
				"Device %q failed to confirm the latest config (version %s): "+
					"timed out waiting for LastProcessedConfig >= %v",
				d.devName, configVer, configTs)
		}
		d.th.log.Infof("Device %q confirmed the latest config (version %s)",
			d.devName, configVer)
	}
}

// GetConfig returns the current device configuration.
func (d *EdgeDevice) GetConfig() *EdgeDeviceConfig {
	return d.getConfig(true)
}

func (d *EdgeDevice) getConfig(clone bool) *EdgeDeviceConfig {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	devState, found := d.th.devices[d.devName]
	if !found {
		d.th.t.Fatalf("Unknown device %q", d.devName)
	}
	if !clone {
		return devState.config
	}
	return devState.config.Clone()
}

// GetDeviceIPAddress returns IP addresses assigned to the specified network adapter.
// If netAdapterLogicalLabel is empty, IP addresses from all adapters are returned.
func (d *EdgeDevice) GetDeviceIPAddress(netAdapterLogicalLabel string) []net.IP {
	deviceInfo := d.GetDeviceInfo()
	if deviceInfo == nil {
		return nil
	}
	sysAdapter := deviceInfo.GetSystemAdapter()
	if sysAdapter == nil {
		return nil
	}
	statuses := sysAdapter.GetStatus()
	idx := int(sysAdapter.GetCurrentIndex())
	if idx >= len(statuses) {
		return nil
	}
	var ips []net.IP
	for _, port := range statuses[idx].GetPorts() {
		if netAdapterLogicalLabel != "" && port.GetName() != netAdapterLogicalLabel {
			continue
		}
		for _, ipStr := range port.GetIPAddrs() {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

// UpgradeEVE upgrades the EVE OS to the specified version and optionally
// waits until the upgrade completes.
func (d *EdgeDevice) UpgradeEVE(eveVersion string, waitUntilUpgraded bool) {
	// TODO (do not forget to log progress)
	d.th.t.Fatalf("UpgradeEVE is not implemented")
}

// RequestReboot requests a device reboot via configuration and optionally
// waits until the reboot completes.
func (d *EdgeDevice) RequestReboot(waitUntilRebooted bool) {
	d.th.incExpectedRebootCount(d.devName)
	config := d.getConfig(true)
	reboot := config.GetReboot()
	if reboot == nil {
		config.Reboot = &eveconfig.DeviceOpsCmd{
			Counter: 1, DesiredState: true}
	} else {
		config.Reboot = &eveconfig.DeviceOpsCmd{
			Counter: reboot.GetCounter() + 1, DesiredState: true}
	}
	d.rebootAndWait(waitUntilRebooted, func() {
		d.ApplyConfig(config, false, false)
	})
}

// SoftReboot reboots the device from the console/SSH.
func (d *EdgeDevice) SoftReboot(waitUntilRebooted bool) {
	d.th.incExpectedRebootCount(d.devName)
	d.th.collectCoverageFromDevice(d.th.ctx, d.devName)
	d.rebootAndWait(waitUntilRebooted, func() {
		ctx, cancel := context.WithTimeout(d.th.ctx, quickSSHCommandTimeout)
		err := d.th.runScriptOnEVEOverSSH(ctx, d.devName, "reboot", nil, nil, 0)
		cancel()
		if err != nil {
			d.th.t.Fatalf("SoftReboot: failed to run reboot over SSH: %v", err)
		}
	})
}

// HardReboot triggers device reboot through the broker.
func (d *EdgeDevice) HardReboot(waitUntilRebooted bool) {
	d.th.incExpectedRebootCount(d.devName)
	d.th.collectCoverageFromDevice(d.th.ctx, d.devName)
	d.rebootAndWait(waitUntilRebooted, func() {
		devCtrlReq := &api.DeviceControlRequest{
			ClientId:   d.th.brokerClientID,
			DeviceName: d.devName,
		}
		rebootCtx, rebootCancel := context.WithTimeout(
			d.th.ctx, brokerRebootEVEDeviceTimeout)
		_, err := d.th.brokerClient.RebootDevice(rebootCtx, devCtrlReq)
		rebootCancel()
		if err != nil {
			d.th.t.Fatalf("HardReboot: broker failed to reboot device %q: %v",
				d.devName, err)
		}
	})
}

// rebootAndWait executes triggerFn to initiate a device reboot and, if
// wait is true, blocks until the device confirms the reboot by reporting
// a ZInfoDevice.lastRebootTime strictly after the moment triggerFn was called.
//
// The subscription is established before triggerFn is invoked to avoid
// missing the post-reboot info message. Device and evetest clocks are
// assumed to be in sync.
func (d *EdgeDevice) rebootAndWait(wait bool, triggerFn func()) {
	if !wait {
		triggerFn()
		return
	}

	devUUID := d.getDevUUID()

	// Subscribe before triggering the reboot so we cannot miss the
	// post-reboot info message that arrives after the device comes back.
	infoCh := make(chan *eveinfo.ZInfoMsg, 20)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice
		},
		infoCh,
	)
	if err != nil {
		d.th.t.Fatalf("Failed to subscribe to info messages for device %q: %v",
			d.devName, err)
	}
	defer unsub()

	// Record local time just before issuing the reboot command.
	// lastRebootTime > rebootIssuedAt confirms the device has completed
	// the reboot triggered by this call.
	// Assumes that evetest and device clocks are in-sync.
	rebootIssuedAt := time.Now()
	triggerFn()
	d.th.log.Infof("Waiting for device %q to reboot (issued at: %s)...",
		d.devName, rebootIssuedAt)

	waitCtx, waitCancel := context.WithTimeout(d.th.ctx, deviceRebootTimeout)
	defer waitCancel()

	for {
		select {
		case msg, ok := <-infoCh:
			if !ok {
				d.th.t.Fatalf("Info subscription closed while waiting "+
					"for device %q to reboot", d.devName)
			}
			ts := msg.GetDinfo().GetLastRebootTime()
			if ts != nil && ts.AsTime().After(rebootIssuedAt) {
				d.th.log.Infof("Device %q has rebooted (last reboot time: %s)",
					d.devName, ts.AsTime())
				return
			}
		case <-waitCtx.Done():
			d.th.t.Fatalf("Timed out waiting for device %q to reboot", d.devName)
		}
	}
}

// GetLogs returns device log messages matching the provided criteria.
func (d *EdgeDevice) GetLogs(match LogMsgMatch) []LogMsg {
	devUUID := d.getDevUUID()
	collector := &logMsgCollector{match: match}
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherLogsTimeout)
	err := d.th.adamClient.IterateDeviceLogs(
		ctx, devUUID, collector.toMatcher(), collector, false)
	cancel()
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve logs for device %q: %v", d.devName, err)
	}
	return collector.msgs
}

// GetAppLogs returns application log messages matching the provided criteria.
func (d *EdgeDevice) GetAppLogs(appUUID uuid.UUID, match LogMsgMatch) []LogMsg {
	devUUID := d.getDevUUID()
	collector := &logMsgCollector{match: match}
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherLogsTimeout)
	err := d.th.adamClient.IterateAppLogs(
		ctx, devUUID, appUUID, collector.toMatcher(), collector, false)
	cancel()
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve app logs for device %q app %q: %v",
			d.devName, appUUID, err)
	}
	return collector.msgs
}

// GetAppFlowLogs returns flow records for the specified application
// matching the provided criteria.
func (d *EdgeDevice) GetAppFlowLogs(
	appUUID uuid.UUID, match FlowLogMatch) []eveflowlog.FlowRecord {
	// TODO: implement AdamClient.IterateAppFlowLogs first
	d.th.t.Fatalf("GetAppFlowLogs is not implemented")
	return nil
}

// GetAppDNSLogs returns DNS request logs for the specified application
// matching the provided criteria.
func (d *EdgeDevice) GetAppDNSLogs(
	appUUID uuid.UUID, match DNSLogMatch) []eveflowlog.DnsRequest {
	// TODO: implement AdamClient.IterateAppFlowLogs first
	d.th.t.Fatalf("GetAppDNSLogs is not implemented")
	return nil
}

// waitUntilAppState waits until the app reaches one of targetStates,
// logging every state transition along the way.
// ctx controls the deadline; callers must derive it from d.th.ctx.
// Calls t.Fatalf on timeout or error.
func (d *EdgeDevice) waitUntilAppState(
	ctx context.Context, appUUID uuid.UUID, targetStates ...eveinfo.ZSwState) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()

	var lastState = eveinfo.ZSwState_INVALID

	d.th.log.Infof("Waiting for app %q on device %q to reach state(s) %v",
		appUUID, d.devName, targetStates)
	err := d.th.adamClient.IterateDeviceInfoMsgs(ctx, devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiApp {
				return false
			}
			ainfo := msg.GetAinfo()
			return ainfo != nil && ainfo.GetAppID() == appUUIDStr
		},
		infoMsgIterFn(func(msg *eveinfo.ZInfoMsg) (bool, error) {
			ainfo := msg.GetAinfo()
			state := ainfo.GetState()
			if state != lastState {
				lastState = state
				d.th.log.Infof("App %q (%s) on device %q state changed to %s",
					appUUID, ainfo.GetAppName(), d.devName, state)
			}
			if generics.ContainsItem(targetStates, state) {
				return true, nil
			}
			return false, nil
		}),
		true,
	)

	if err != nil {
		d.th.t.Fatalf("Waiting for app %q on device %q to reach state(s) %v: %v",
			appUUID, d.devName, targetStates, err)
	}
}

// WaitUntilAppIsRunning waits until the specified application reaches
// the running state or fails.
//
// timeoutExcludingDownload is the maximum time to wait excluding any
// period spent actively downloading (i.e. in DOWNLOAD_STARTED state with
// advancing progress). If a download stalls for downloadStalledTimeout the
// function fails immediately regardless of this timeout.
func (d *EdgeDevice) WaitUntilAppIsRunning(
	appUUID uuid.UUID, timeoutExcludingDownload time.Duration) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	d.appsBeingWaited.Store(appUUIDStr, struct{}{})
	defer d.appsBeingWaited.Delete(appUUIDStr)
	d.th.log.Infof("Waiting for app %q on device %q to reach RUNNING state...",
		appUUID, d.devName)

	var (
		lastState          = eveinfo.ZSwState_INVALID
		lastDownloadPct    uint32
		nonDownloadStart   = time.Now()
		nonDownloadElapsed time.Duration
		inDownload         bool
		appName            string
		volumeRefs         []string
		lastAppErrs        string // concatenated error descriptions for change detection
		// Keyed by volume UUID; accumulates the latest ZInfoVolume for each volume.
		volumes = make(map[string]*eveinfo.ZInfoVolume)
	)

	// ctx is canceled either by the timer below (timeout) or by d.th.ctx (test end).
	ctx, cancel := context.WithCancel(d.th.ctx)
	defer cancel()

	// The timer drives timeouts when no info messages arrive:
	//   - non-download phase: fires after the remaining non-download budget
	//   - download phase: fires after downloadStalledTimeout with no progress
	// iterCb resets it on each relevant transition or progress update.
	timer := time.NewTimer(timeoutExcludingDownload)
	defer timer.Stop()

	// Cancel the context when the timer fires so IterateDeviceInfoMsgs unblocks.
	go func() {
		select {
		case <-timer.C:
			cancel()
		case <-ctx.Done():
		}
	}()

	// Accept ZiApp messages for this app and all ZiVolume messages.
	// Volume messages are further filtered in the iterator once the app's
	// VolumeRefs are known.
	filter := func(msg *eveinfo.ZInfoMsg) bool {
		switch msg.GetZtype() {
		case eveinfo.ZInfoTypes_ZiApp:
			ainfo := msg.GetAinfo()
			return ainfo != nil && ainfo.GetAppID() == appUUIDStr
		case eveinfo.ZInfoTypes_ZiVolume:
			return true
		}
		return false
	}

	iterCb := func(msg *eveinfo.ZInfoMsg) (bool, error) {
		// Handle volume updates: store the latest state for each volume
		// and re-evaluate download progress if the app is currently downloading.
		if msg.GetZtype() == eveinfo.ZInfoTypes_ZiVolume {
			vinfo := msg.GetVinfo()
			if vinfo == nil {
				return false, nil
			}
			volumes[vinfo.GetUuid()] = vinfo
			// If the app is in DOWNLOAD_STARTED state, a volume update may
			// change the reported progress -- check and log.
			if inDownload {
				pct := appDownloadProgress(volumeRefs, volumes)
				if pct != lastDownloadPct {
					lastDownloadPct = pct
					timer.Reset(downloadStalledTimeout)
					d.th.log.Infof("App %q (%s) on device %q state changed to %s (%d%%)",
						appUUID, appName, d.devName, lastState, pct)
				}
			}
			return false, nil
		}

		ainfo := msg.GetAinfo()
		state := ainfo.GetState()
		appName = ainfo.GetAppName()

		// Update volume refs from the latest app info.
		volumeRefs = ainfo.GetVolumeRefs()

		// Maintain non-download elapsed time and update the timer when
		// transitioning between download and non-download phases.
		nowInDownload := state == eveinfo.ZSwState_DOWNLOAD_STARTED
		if inDownload && !nowInDownload {
			// Leaving download: resume non-download clock and set timer to
			// the remaining non-download budget.
			nonDownloadStart = time.Now()
			remaining := timeoutExcludingDownload - nonDownloadElapsed
			if remaining <= 0 {
				return true, fmt.Errorf(
					"timed out after %s (excluding download) waiting for app %q (%s) "+
						"on device %q to reach RUNNING state (last state: %s)",
					timeoutExcludingDownload, appUUID, appName, d.devName, state)
			}
			timer.Reset(remaining)
		} else if !inDownload && nowInDownload {
			// Entering download: freeze non-download clock and arm stall timer.
			nonDownloadElapsed += time.Since(nonDownloadStart)
			timer.Reset(downloadStalledTimeout)
		}
		inDownload = nowInDownload

		// Log every state change and every download-progress change.
		if state != lastState {
			lastState = state
			if state == eveinfo.ZSwState_DOWNLOAD_STARTED {
				pct := appDownloadProgress(volumeRefs, volumes)
				lastDownloadPct = pct
				d.th.log.Infof("App %q (%s) on device %q state changed to %s (%d%%)",
					appUUID, appName, d.devName, state, pct)
			} else {
				d.th.log.Infof("App %q (%s) on device %q state changed to %s",
					appUUID, appName, d.devName, state)
			}
		} else if state == eveinfo.ZSwState_DOWNLOAD_STARTED {
			pct := appDownloadProgress(volumeRefs, volumes)
			if pct != lastDownloadPct {
				lastDownloadPct = pct
				timer.Reset(downloadStalledTimeout)
				d.th.log.Infof("App %q (%s) on device %q state changed to %s (%d%%)",
					appUUID, appName, d.devName, state, pct)
			}
		}

		// Log changes in app errors.
		var errDescs []string
		for _, e := range ainfo.GetAppErr() {
			if desc := e.GetDescription(); desc != "" {
				errDescs = append(errDescs, desc)
			}
		}
		currentAppErrs := strings.Join(errDescs, "; ")
		if currentAppErrs != lastAppErrs {
			lastAppErrs = currentAppErrs
			if currentAppErrs != "" {
				d.th.log.Warnf("App %q (%s) on device %q errors: %s",
					appUUID, appName, d.devName, currentAppErrs)
			} else {
				d.th.log.Infof("App %q (%s) on device %q errors cleared",
					appUUID, appName, d.devName)
			}
		}

		// Fail immediately on unrecoverable error.
		if state == eveinfo.ZSwState_ERROR {
			if currentAppErrs != "" {
				return true, fmt.Errorf(
					"app %q (%s) on device %q entered ERROR state: %s",
					appUUID, appName, d.devName, currentAppErrs)
			}
			return true, fmt.Errorf(
				"app %q (%s) on device %q entered ERROR state",
				appUUID, appName, d.devName)
		}

		// Success.
		if state == eveinfo.ZSwState_RUNNING {
			d.th.log.Infof("App %q (%s) on device %q is RUNNING",
				appUUID, appName, d.devName)
			return true, nil
		}

		return false, nil
	}

	err := d.th.adamClient.IterateDeviceInfoMsgs(ctx, devUUID, filter,
		infoMsgIterFn(iterCb), true)

	if err != nil {
		// If the test framework context was canceled, propagate the error.
		if d.th.ctx.Err() != nil {
			d.th.t.Fatalf("%v", err)
		}

		// If our context was not canceled, the error came from iterCb
		// (e.g. ZSwState_ERROR or explicit failure).
		if ctx.Err() == nil {
			d.th.t.Fatalf("%v", err)
		}

		// Otherwise our timer fired — determine which timeout occurred.
		if inDownload {
			d.th.t.Fatalf(
				"app %q (%s) on device %q download stalled at %d%% for more than %s",
				appUUID, appName, d.devName, lastDownloadPct, downloadStalledTimeout)
		}

		nonDownloadTotal := nonDownloadElapsed + time.Since(nonDownloadStart)
		d.th.t.Fatalf(
			"timed out after %s (excluding download) waiting for app %q (%s) "+
				"on device %q to reach RUNNING state (last state: %s)",
			nonDownloadTotal, appUUID, appName, d.devName, lastState)
	}
}

// RebootApplication requests a reboot of the specified application instance.
func (d *EdgeDevice) RebootApplication(appUUID uuid.UUID, waitUntilRebooted bool,
	timeout time.Duration) {
	config := d.getConfig(true)
	appUUIDStr := appUUID.String()

	// Locate the application in the config and increment the restart counter.
	found := false
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			restart := app.GetRestart()
			if restart == nil {
				app.Restart = &eveconfig.InstanceOpsCmd{Counter: 1}
			} else {
				app.Restart = &eveconfig.InstanceOpsCmd{Counter: restart.GetCounter() + 1}
			}
			found = true
			break
		}
	}
	if !found {
		d.th.t.Fatalf("App %q not found in device %q config", appUUID, d.devName)
	}
	d.ApplyConfig(config, false, false)
	if waitUntilRebooted {
		ctx, cancel := context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
		d.waitUntilAppState(ctx, appUUID,
			eveinfo.ZSwState_RESTARTING, eveinfo.ZSwState_HALTING)
		d.waitUntilAppState(ctx, appUUID, eveinfo.ZSwState_RUNNING)
	}
}

// PurgeApplication purges the specified application instance and its state.
func (d *EdgeDevice) PurgeApplication(appUUID uuid.UUID, waitUntilPurged bool,
	timeout time.Duration) {
	config := d.getConfig(true)
	appUUIDStr := appUUID.String()

	// Locate the application in the config and increment the purge counter.
	found := false
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			purge := app.GetPurge()
			if purge == nil {
				app.Purge = &eveconfig.InstanceOpsCmd{Counter: 1}
			} else {
				app.Purge = &eveconfig.InstanceOpsCmd{Counter: purge.GetCounter() + 1}
			}
			found = true
			break
		}
	}
	if !found {
		d.th.t.Fatalf("App %q not found in device %q config", appUUID, d.devName)
	}
	d.ApplyConfig(config, false, false)
	if waitUntilPurged {
		ctx, cancel := context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
		d.waitUntilAppState(ctx, appUUID,
			eveinfo.ZSwState_PURGING, eveinfo.ZSwState_HALTING)
		d.waitUntilAppState(ctx, appUUID, eveinfo.ZSwState_RUNNING)
	}
}

// ActivateApplication activates the specified application instance.
func (d *EdgeDevice) ActivateApplication(appUUID uuid.UUID, waitUntilActivated bool,
	timeout time.Duration) {
	config := d.getConfig(true)
	appUUIDStr := appUUID.String()

	// Locate the application in the config and mark it as activated.
	found := false
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			app.Activate = true
			found = true
			break
		}
	}
	if !found {
		d.th.t.Fatalf("App %q not found in device %q config", appUUID, d.devName)
	}

	d.ApplyConfig(config, false, false)
	if waitUntilActivated {
		d.WaitUntilAppIsRunning(appUUID, timeout)
	}
}

// DeactivateApplication deactivates the specified application instance.
func (d *EdgeDevice) DeactivateApplication(appUUID uuid.UUID, waitUntilDeactivated bool,
	timeout time.Duration) {
	config := d.getConfig(true)
	appUUIDStr := appUUID.String()

	// Locate the application in the config and mark it as deactivated.
	found := false
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			app.Activate = false
			found = true
			break
		}
	}
	if !found {
		d.th.t.Fatalf("App %q not found in device %q config", appUUID, d.devName)
	}

	d.ApplyConfig(config, false, false)
	if waitUntilDeactivated {
		ctx, cancel := context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
		d.waitUntilAppState(ctx, appUUID, eveinfo.ZSwState_HALTED)
	}
}

// RunShellScript executes the provided shell script on the device over SSH
// and returns its standard output and standard error as strings.
//
// If timeout is non-zero, execution is bounded by the given duration and
// will be canceled if the timeout expires. If timeout is zero, no explicit
// deadline is applied.
//
// If stdoutWatchdogTimeout is non-zero, the script will be terminated if
// it produces no output on stdout for longer than the specified duration.
// This acts as a "watchdog" to detect stalled scripts.
func (d *EdgeDevice) RunShellScript(script string, timeout time.Duration,
	stdoutWatchdogTimeout time.Duration) (stdout, stderr string, err error) {
	ctx := d.th.ctx
	if timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
	}
	var stdoutBuf, stderrBuf bytes.Buffer
	err = d.th.runScriptOnEVEOverSSH(
		ctx, d.devName, script, &stdoutBuf, &stderrBuf, stdoutWatchdogTimeout)
	if err != nil {
		err = fmt.Errorf(
			"failed to execute script over SSH for EVE device %s: %w (stderr: %s)",
			d.devName, err, stderrBuf.String())
	}
	return stdoutBuf.String(), stderrBuf.String(), err
}

// RunShellScriptInsideApp executes a shell script inside an application
// instance over SSH and returns its standard output and standard error.
//
// The method discovers SSH endpoints for the application by inspecting:
//  1. Port-forwarding ACL rules (port 22 mapped through a local network
//     instance) -- the device IP on the uplink adapter plus the external port.
//  2. Switch network instance interfaces -- the app IP at port 22 (directly
//     bridged, reachable on the SDN network).
//  3. RoutesTowardsEve entries in the SDN network model -- if any SDN network's
//     router has a route towards the EVE device that covers a VIF's IP, that
//     IP:22 is tried. This makes air-gap NI apps reachable once the app acting
//     as their gateway has IP forwarding enabled.
//
// auth specifies how to authenticate with the application's SSH server
// (username/password or client certificate). timeout and stdoutWatchdogTimeout
// behave the same as in RunShellScript.
func (d *EdgeDevice) RunShellScriptInsideApp(appUUID uuid.UUID, auth AuthMethod,
	script string, timeout time.Duration,
	stdoutWatchdogTimeout time.Duration) (stdout, stderr string, err error) {

	ctx := d.th.ctx
	if timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
	}

	appUUIDStr := appUUID.String()
	config := d.getConfig(false)

	// Find the app in the device config.
	var appConfig *eveconfig.AppInstanceConfig
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			appConfig = app
			break
		}
	}
	if appConfig == nil {
		d.th.t.Fatalf("app %q not found in device %q config", appUUID, d.devName)
	}

	var addrs []string

	// Collect SSH endpoints for the app:
	// 1. Port-forwarded endpoints: device-IP:mappedPort where ACLs
	//    map external port to app's port 22.
	// 2. Switch (bridged) endpoints: app-IP:22 for interfaces
	//    connected to switch network instances.
	appInfo := d.GetAppInfo(appUUID)
	for _, iface := range appConfig.GetInterfaces() {
		networkID := iface.GetNetworkId()

		// Find the network instance config for this interface.
		var niConfig *eveconfig.NetworkInstanceConfig
		for _, ni := range config.GetNetworkInstances() {
			if ni.GetUuidandversion().GetUuid() == networkID {
				niConfig = ni
				break
			}
		}
		if niConfig == nil {
			continue
		}

		// Check ACLs for port-map rules that forward to app port 22.
		for _, acl := range iface.GetAcls() {
			var devicePort, adapterLabel string
			var mapsToApp22 bool
			for _, action := range acl.GetActions() {
				if action.GetPortmap() && action.GetAppPort() == 22 {
					mapsToApp22 = true
					break
				}
			}
			if !mapsToApp22 {
				continue
			}
			// Find the external port from "lport" and optional adapter restriction.
			for _, match := range acl.GetMatches() {
				switch match.GetType() {
				case "lport":
					devicePort = match.GetValue()
				case "adapter":
					adapterLabel = match.GetValue()
				}
			}
			if devicePort == "" {
				continue
			}

			// Port-forwarding applies to adapters that match the NI port label
			// AND, if an "adapter" ACE match is defined, also carry that label.
			adapters := getAdaptersByLabel(config, niConfig.GetPort().GetName())
			if adapterLabel != "" {
				aclAdapters := getAdaptersByLabel(config, adapterLabel)
				var filtered []string
				for _, name := range adapters {
					if generics.ContainsItem(aclAdapters, name) {
						filtered = append(filtered, name)
					}
				}
				adapters = filtered
			}
			for _, name := range adapters {
				for _, ip := range d.GetDeviceIPAddress(name) {
					addrs = append(addrs, net.JoinHostPort(ip.String(), devicePort))
				}
			}
		}

		// For switch network instances, the app is directly reachable
		// on the IP assigned to this interface.
		if niConfig.GetInstType() == eveconfig.ZNetworkInstType_ZnetInstSwitch {
			for _, netInfo := range appInfo.GetNetwork() {
				if netInfo.GetDevName() != iface.GetName() {
					continue
				}
				for _, ipStr := range netInfo.GetIPAddrs() {
					if net.ParseIP(ipStr) != nil {
						addrs = append(addrs, net.JoinHostPort(ipStr, "22"))
					}
				}
			}
		}
	}

	// Check RoutesTowardsEve in the SDN network model: any VIF IP that falls
	// within a subnet listed in RoutesTowardsEve is reachable from the evetest
	// host via the SDN router (which forwards those subnets towards app-gw).
	d.th.netModelM.Lock()
	for _, network := range d.th.netModel.GetNetworks() {
		for _, route := range network.GetRouter().GetRoutesTowardsEve() {
			_, dstNet, err2 := net.ParseCIDR(route.GetDstNetwork())
			if err2 != nil {
				continue
			}
			for _, netInfo := range appInfo.GetNetwork() {
				for _, ipStr := range netInfo.GetIPAddrs() {
					ip := net.ParseIP(ipStr)
					if ip != nil && dstNet.Contains(ip) {
						addrs = append(addrs, net.JoinHostPort(ipStr, "22"))
					}
				}
			}
		}
	}
	d.th.netModelM.Unlock()

	if len(addrs) == 0 {
		return "", "", fmt.Errorf(
			"no SSH endpoints found for app %q on device %q", appUUID, d.devName)
	}

	addr, err := d.th.probeReachableAddr(ctx, addrs)
	if err != nil {
		return "", "", fmt.Errorf(
			"unable to reach app %q SSH on device %q: %w", appUUID, d.devName, err)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	err = d.th.runScriptOverSSH(ctx, addr, auth, script,
		&stdoutBuf, &stderrBuf, stdoutWatchdogTimeout)
	if err != nil {
		err = fmt.Errorf(
			"failed to execute script over SSH for app %s: %w (stderr: %s)",
			appUUID, err, stderrBuf.String())
	}
	return stdoutBuf.String(), stderrBuf.String(), err
}

// getAdapterNamesByLabel returns the logical labels of adapters whose Name
// equals the given label or whose SharedLabels contain it.
func getAdaptersByLabel(config *EdgeDeviceConfig, label string) []string {
	var names []string
	for _, sa := range config.GetSystemAdapterList() {
		if sa.GetName() == label ||
			generics.ContainsItem(sa.GetSharedLabels(), label) ||
			label == "all" ||
			(label == "uplink" && sa.Uplink) ||
			(label == "freeuplink" && sa.Uplink && sa.Cost == 0) {
			names = append(names, sa.GetName())
		}
	}
	return names
}

// FileExists checks whether a file exists on the device.
func (d *EdgeDevice) FileExists(fileName string) bool {
	stdout, _, err := d.RunShellScript(
		"test -f "+shellEscape(fileName)+" && echo EXISTS",
		quickSSHCommandTimeout, 0)
	if err != nil {
		d.th.t.Fatalf("FileExists: SSH command failed: %v", err)
	}
	return strings.Contains(stdout, "EXISTS")
}

// ReadFile reads the contents of a file from the device.
func (d *EdgeDevice) ReadFile(fileName string) []byte {
	ctx, cancel := context.WithTimeout(d.th.ctx, fileTransferTimeout)
	defer cancel()

	tmpFile, err := os.CreateTemp("", "eve-file-*")
	if err != nil {
		d.th.t.Fatalf("ReadFile: failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	err = d.th.scpFromEVE(ctx, d.devName, fileName, tmpPath, false)
	if err != nil {
		d.th.t.Fatalf("ReadFile: failed to copy %q from device %q: %v",
			fileName, d.devName, err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		d.th.t.Fatalf("ReadFile: failed to read temp file: %v", err)
	}
	return data
}

// WriteFile writes content to a file on the device.
func (d *EdgeDevice) WriteFile(fileName string, content []byte) {
	ctx, cancel := context.WithTimeout(d.th.ctx, fileTransferTimeout)
	defer cancel()

	tmpFile, err := os.CreateTemp("", "eve-file-*")
	if err != nil {
		d.th.t.Fatalf("WriteFile: failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		d.th.t.Fatalf("WriteFile: failed to write temp file: %v", err)
	}
	tmpFile.Close()

	err = d.th.scpToEVE(ctx, d.devName, tmpPath, fileName, false)
	if err != nil {
		d.th.t.Fatalf("WriteFile: failed to copy %q to device %q: %v",
			fileName, d.devName, err)
	}
}

// DeleteFile removes a file from the device.
func (d *EdgeDevice) DeleteFile(fileName string) {
	_, _, err := d.RunShellScript(
		"rm -f "+shellEscape(fileName), quickSSHCommandTimeout, 0)
	if err != nil {
		d.th.t.Fatalf("DeleteFile: SSH command failed: %v", err)
	}
}

// GetDeviceInfo returns the last recorded device information,
// or nil if no info message has been received yet.
func (d *EdgeDevice) GetDeviceInfo() *eveinfo.ZInfoDevice {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoDevice
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetDinfo()
		},
	)
	return result
}

// WatchDeviceInfo subscribes to device info updates and returns a buffered
// channel that receives each new ZInfoDevice as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchDeviceInfo() (updates <-chan *eveinfo.ZInfoDevice, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchDeviceInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoDevice, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetDinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// trackWatcherUnsub registers an unsubscribe callback so it can be automatically
// called during Close() if the test forgets to stop the watcher.
// Returns a wrapped stop function that unsubscribes and removes the tracking entry.
func (d *EdgeDevice) trackWatcherUnsub(unsub func()) func() {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	devState := d.th.devices[d.devName]
	if devState.watcherUnsubs == nil {
		devState.watcherUnsubs = make(map[*func()]func())
	}
	key := &unsub
	devState.watcherUnsubs[key] = unsub
	return func() {
		unsub()
		d.th.devicesM.Lock()
		defer d.th.devicesM.Unlock()
		delete(devState.watcherUnsubs, key)
	}
}

// GetAppInfo returns the last recorded runtime information for the specified
// application, or nil if no info message for that app has been received yet.
func (d *EdgeDevice) GetAppInfo(appUUID uuid.UUID) *eveinfo.ZInfoApp {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	var result *eveinfo.ZInfoApp
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiApp {
				return false
			}
			return msg.GetAinfo().GetAppID() == appUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetAinfo()
		},
	)
	return result
}

// WatchAppInfo subscribes to info updates for the specified application and
// returns a buffered channel that receives each new ZInfoApp as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchAppInfo(
	appUUID uuid.UUID) (updates <-chan *eveinfo.ZInfoApp, stop func()) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiApp &&
				msg.GetAinfo().GetAppID() == appUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchAppInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoApp, watchChannelBufSize)
	go func() {
		defer close(ch)
		var lastState eveinfo.ZSwState
		for msg := range rawCh {
			ainfo := msg.GetAinfo()
			// Skip logging if WaitUntilAppIsRunning is active for this app,
			// as it already logs state changes and errors.
			_, waiting := d.appsBeingWaited.Load(appUUIDStr)
			if !waiting {
				if ainfo.State != lastState {
					d.th.log.Infof("App %q (%s) on device %q state changed: %s -> %s",
						appUUID, ainfo.AppName, d.devName, lastState, ainfo.State)
				}
				for _, appErr := range ainfo.AppErr {
					d.th.log.Warnf("App %q (%s) on device %q error: %s",
						appUUID, ainfo.AppName, d.devName, appErr.GetDescription())
				}
			}
			lastState = ainfo.State
			ch <- ainfo
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetNetworkInstanceInfo returns the last recorded information about the
// specified network instance, or nil if no info message for it has been
// received yet.
func (d *EdgeDevice) GetNetworkInstanceInfo(niUUID uuid.UUID) *eveinfo.ZInfoNetworkInstance {
	devUUID := d.getDevUUID()
	niUUIDStr := niUUID.String()
	var result *eveinfo.ZInfoNetworkInstance
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiNetworkInstance {
				return false
			}
			return msg.GetNiinfo().GetNetworkID() == niUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetNiinfo()
		},
	)
	return result
}

// WatchNetworkInstanceInfo subscribes to info updates for the specified network
// instance and returns a buffered channel that receives each new
// ZInfoNetworkInstance as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchNetworkInstanceInfo(
	niUUID uuid.UUID) (updates <-chan *eveinfo.ZInfoNetworkInstance, stop func()) {
	devUUID := d.getDevUUID()
	niUUIDStr := niUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiNetworkInstance &&
				msg.GetNiinfo().GetNetworkID() == niUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchNetworkInstanceInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoNetworkInstance, watchChannelBufSize)
	go func() {
		defer close(ch)
		var lastState eveinfo.ZNetworkInstanceState
		for msg := range rawCh {
			niInfo := msg.GetNiinfo()
			if niInfo.State != lastState {
				d.th.log.Infof("Network instance %q (%s) on device %q state changed: %s -> %s",
					niUUID, niInfo.Displayname, d.devName,
					shortNIState(lastState), shortNIState(niInfo.State))
				lastState = niInfo.State
			}
			for _, niErr := range niInfo.NetworkErr {
				d.th.log.Warnf("Network instance %q (%s) on device %q error: %s",
					niUUID, niInfo.Displayname, d.devName, niErr)
			}
			ch <- niInfo
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

func shortNIState(s eveinfo.ZNetworkInstanceState) string {
	return strings.TrimPrefix(s.String(), "ZNETINST_STATE_")
}

// GetVolumeInfo returns the last recorded information about the specified
// storage volume, or nil if no info message for it has been received yet.
func (d *EdgeDevice) GetVolumeInfo(volumeUUID uuid.UUID) *eveinfo.ZInfoVolume {
	devUUID := d.getDevUUID()
	volUUIDStr := volumeUUID.String()
	var result *eveinfo.ZInfoVolume
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiVolume {
				return false
			}
			return msg.GetVinfo().GetUuid() == volUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetVinfo()
		},
	)
	return result
}

// WatchVolumeInfo subscribes to info updates for the specified storage volume
// and returns a buffered channel that receives each new ZInfoVolume as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchVolumeInfo(volumeUUID uuid.UUID) (
	updates <-chan *eveinfo.ZInfoVolume, stop func()) {

	devUUID := d.getDevUUID()
	volUUIDStr := volumeUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiVolume &&
				msg.GetVinfo().GetUuid() == volUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchVolumeInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoVolume, watchChannelBufSize)
	go func() {
		defer close(ch)
		var lastState eveinfo.ZSwState
		for msg := range rawCh {
			vinfo := msg.GetVinfo()
			if vinfo.State != lastState {
				d.th.log.Infof("Volume %q (%s) on device %q state changed: %s -> %s",
					volumeUUID, vinfo.DisplayName, d.devName, lastState, vinfo.State)
				lastState = vinfo.State
			}
			if volErr := vinfo.GetVolumeErr(); volErr != nil && volErr.GetDescription() != "" {
				d.th.log.Warnf("Volume %q (%s) on device %q error: %s",
					volumeUUID, vinfo.DisplayName, d.devName, volErr.GetDescription())
			}
			ch <- vinfo
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetContentTreeInfo returns the last recorded information about the specified
// content tree, or nil if no info message for it has been received yet.
func (d *EdgeDevice) GetContentTreeInfo(ctUUID uuid.UUID) *eveinfo.ZInfoContentTree {
	devUUID := d.getDevUUID()
	ctUUIDStr := ctUUID.String()
	var result *eveinfo.ZInfoContentTree
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiContentTree {
				return false
			}
			return msg.GetCinfo().GetUuid() == ctUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetCinfo()
		},
	)
	return result
}

// WatchContentTreeInfo subscribes to info updates for the specified content tree
// and returns a buffered channel that receives each new ZInfoContentTree as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchContentTreeInfo(
	ctUUID uuid.UUID) (updates <-chan *eveinfo.ZInfoContentTree, stop func()) {
	devUUID := d.getDevUUID()
	ctUUIDStr := ctUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiContentTree &&
				msg.GetCinfo().GetUuid() == ctUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchContentTreeInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoContentTree, watchChannelBufSize)
	go func() {
		defer close(ch)
		var lastState eveinfo.ZSwState
		for msg := range rawCh {
			cinfo := msg.GetCinfo()
			if cinfo.State != lastState {
				d.th.log.Infof("Content tree %q (%s) on device %q state changed: %s -> %s",
					ctUUID, cinfo.DisplayName, d.devName, lastState, cinfo.State)
				lastState = cinfo.State
			}
			if ctErr := cinfo.GetErr(); ctErr != nil && ctErr.GetDescription() != "" {
				d.th.log.Warnf("Content tree %q (%s) on device %q error: %s",
					ctUUID, cinfo.DisplayName, d.devName, ctErr.GetDescription())
			}
			ch <- cinfo
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetBlobInfo returns the last recorded information about stored blobs on the
// device, or nil if no blob info message has been received yet.
func (d *EdgeDevice) GetBlobInfo() *eveinfo.ZInfoBlobList {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoBlobList
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiBlobList
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetBinfo()
		},
	)
	return result
}

// WatchBlobInfo subscribes to blob info updates and returns a buffered channel
// that receives each new ZInfoBlobList as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchBlobInfo() (updates <-chan *eveinfo.ZInfoBlobList, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiBlobList
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchBlobInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoBlobList, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetBinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetAppMetadata returns the last recorded metadata associated with the
// specified application instance, or nil if none has been received yet.
func (d *EdgeDevice) GetAppMetadata(appUUID uuid.UUID) *eveinfo.ZInfoAppInstMetaData {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	var result *eveinfo.ZInfoAppInstMetaData
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiAppInstMetaData {
				return false
			}
			return msg.GetAmdinfo().GetUuid() == appUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetAmdinfo()
		},
	)
	return result
}

// WatchAppMetadata subscribes to metadata updates for the specified application
// instance and returns a buffered channel that receives each new
// ZInfoAppInstMetaData as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchAppMetadata(
	appUUID uuid.UUID) (updates <-chan *eveinfo.ZInfoAppInstMetaData, stop func()) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiAppInstMetaData &&
				msg.GetAmdinfo().GetUuid() == appUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchAppMetadata: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoAppInstMetaData, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetAmdinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetHardwareInfo returns the last recorded hardware inventory information,
// or nil if no hardware info message has been received yet.
func (d *EdgeDevice) GetHardwareInfo() *eveinfo.ZInfoHardware {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoHardware
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiHardware
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetHwinfo()
		},
	)
	return result
}

// WatchHardwareInfo subscribes to hardware info updates and returns a buffered
// channel that receives each new ZInfoHardware as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchHardwareInfo() (
	updates <-chan *eveinfo.ZInfoHardware, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiHardware
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchHardwareInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoHardware, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetHwinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetLocationInfo returns the last recorded device location information,
// or nil if no location info message has been received yet.
func (d *EdgeDevice) GetLocationInfo() *eveinfo.ZInfoLocation {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoLocation
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiLocation
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetLocinfo()
		},
	)
	return result
}

// WatchLocationInfo subscribes to location info updates and returns a buffered
// channel that receives each new ZInfoLocation as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchLocationInfo() (
	updates <-chan *eveinfo.ZInfoLocation, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiLocation
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchLocationInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoLocation, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetLocinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetNTPSources returns the last recorded NTP sources configured on the device,
// or nil if no NTP sources info message has been received yet.
func (d *EdgeDevice) GetNTPSources() *eveinfo.ZInfoNTPSources {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoNTPSources
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiNTPSources
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetNtpSources()
		},
	)
	return result
}

// WatchNTPSources subscribes to NTP sources updates and returns a buffered
// channel that receives each new ZInfoNTPSources as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchNTPSources() (
	updates <-chan *eveinfo.ZInfoNTPSources, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiNTPSources
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchNTPSources: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoNTPSources, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetNtpSources()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetClusterInfo returns the last recorded information about the Kubernetes
// cluster, or nil if no such info message has been received yet.
func (d *EdgeDevice) GetClusterInfo() *eveinfo.ZInfoKubeCluster {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoKubeCluster
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeCluster &&
				msg.GetClusterInfo() != nil
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetClusterInfo()
		},
	)
	return result
}

// WatchClusterInfo subscribes to Kubernetes cluster info updates and returns a
// buffered channel that receives each new ZInfoKubeCluster as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchClusterInfo() (
	updates <-chan *eveinfo.ZInfoKubeCluster, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeCluster &&
				msg.GetClusterInfo() != nil
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchClusterInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoKubeCluster, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetClusterInfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetClusterUpdateInfo returns the last recorded information regarding the Kubernetes
// cluster update, or nil if no such info message has been received yet.
func (d *EdgeDevice) GetClusterUpdateInfo() *eveinfo.ZInfoKubeClusterUpdateStatus {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoKubeClusterUpdateStatus
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeClusterUpdateStatus &&
				msg.GetClusterUpdateInfo() != nil
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetClusterUpdateInfo()
		},
	)
	return result
}

// WatchClusterUpdateInfo subscribes to Kubernetes cluster-update info messages
// and returns a buffered channel that receives each new ZInfoKubeClusterUpdateStatus
// as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchClusterUpdateInfo() (
	updates <-chan *eveinfo.ZInfoKubeClusterUpdateStatus, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeClusterUpdateStatus &&
				msg.GetClusterUpdateInfo() != nil
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchClusterUpdateInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoKubeClusterUpdateStatus, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetClusterUpdateInfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetDeviceMetrics returns the last recorded device-level metrics,
// or nil if no metrics message has been received yet.
func (d *EdgeDevice) GetDeviceMetrics() *evemetrics.DeviceMetric {
	devUUID := d.getDevUUID()
	var result *evemetrics.DeviceMetric
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			if msg.GetDm() != nil {
				result = msg.GetDm()
			}
		},
	)
	return result
}

// WatchDeviceMetrics subscribes to device-level metrics updates and returns a
// buffered channel that receives each new DeviceMetric as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchDeviceMetrics() (
	updates <-chan *evemetrics.DeviceMetric, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchDeviceMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.DeviceMetric, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			if dm := msg.GetDm(); dm != nil {
				ch <- dm
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetAppMetrics returns the last recorded metrics for the specified application,
// or nil if no metrics message for that app has been received yet.
func (d *EdgeDevice) GetAppMetrics(appUUID uuid.UUID) *evemetrics.AppMetric {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	var result *evemetrics.AppMetric
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			for _, am := range msg.GetAm() {
				if am.GetAppID() == appUUIDStr {
					result = am
				}
			}
		},
	)
	return result
}

// WatchAppMetrics subscribes to metrics updates for the specified application
// and returns a buffered channel that receives each new AppMetric as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchAppMetrics(
	appUUID uuid.UUID) (updates <-chan *evemetrics.AppMetric, stop func()) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchAppMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.AppMetric, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			for _, am := range msg.GetAm() {
				if am.GetAppID() == appUUIDStr {
					ch <- am
				}
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetNetworkInstanceMetrics returns the last recorded metrics for the specified
// network instance, or nil if no metrics message for it has been received yet.
func (d *EdgeDevice) GetNetworkInstanceMetrics(
	niUUID uuid.UUID) *evemetrics.ZMetricNetworkInstance {
	devUUID := d.getDevUUID()
	niUUIDStr := niUUID.String()
	var result *evemetrics.ZMetricNetworkInstance
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			for _, nm := range msg.GetNm() {
				if nm.GetNetworkID() == niUUIDStr {
					result = nm
				}
			}
		},
	)
	return result
}

// WatchNetworkInstanceMetrics subscribes to metrics updates for the specified
// network instance and returns a buffered channel that receives each new
// ZMetricNetworkInstance as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchNetworkInstanceMetrics(
	niUUID uuid.UUID) (updates <-chan *evemetrics.ZMetricNetworkInstance, stop func()) {
	devUUID := d.getDevUUID()
	niUUIDStr := niUUID.String()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchNetworkInstanceMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.ZMetricNetworkInstance, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			for _, nm := range msg.GetNm() {
				if nm.GetNetworkID() == niUUIDStr {
					ch <- nm
				}
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetVolumeMetrics returns the last recorded metrics for the specified storage
// volume, or nil if no metrics message for it has been received yet.
func (d *EdgeDevice) GetVolumeMetrics(volumeUUID uuid.UUID) *evemetrics.ZMetricVolume {
	devUUID := d.getDevUUID()
	volUUIDStr := volumeUUID.String()
	var result *evemetrics.ZMetricVolume
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			for _, vm := range msg.GetVm() {
				if vm.GetUuid() == volUUIDStr {
					result = vm
				}
			}
		},
	)
	return result
}

// WatchVolumeMetrics subscribes to metrics updates for the specified storage
// volume and returns a buffered channel that receives each new ZMetricVolume
// as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchVolumeMetrics(
	volumeUUID uuid.UUID) (updates <-chan *evemetrics.ZMetricVolume, stop func()) {
	devUUID := d.getDevUUID()
	volUUIDStr := volumeUUID.String()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchVolumeMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.ZMetricVolume, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			for _, vm := range msg.GetVm() {
				if vm.GetUuid() == volUUIDStr {
					ch <- vm
				}
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetClusterMetrics returns the last recorded metrics for the Kubernetes cluster,
// or nil if no cluster metrics message has been received yet.
func (d *EdgeDevice) GetClusterMetrics() *evemetrics.KubeClusterMetrics {
	devUUID := d.getDevUUID()
	var result *evemetrics.KubeClusterMetrics
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			if msg.GetCm() != nil {
				result = msg.GetCm()
			}
		},
	)
	return result
}

// WatchClusterMetrics subscribes to Kubernetes cluster metrics updates and
// returns a buffered channel that receives each new KubeClusterMetrics as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchClusterMetrics() (
	updates <-chan *evemetrics.KubeClusterMetrics, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchClusterMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.KubeClusterMetrics, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			if cm := msg.GetCm(); cm != nil {
				ch <- cm
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// ReadPublication retrieves a single message from a pub-sub topic published by
// the specified device and agent (microservice).
//
// Parameters:
//   - d: the EdgeDevice handle to read from
//   - fromAgent: the name of the agent/microservice publishing the topic
//   - key: identifies the specific message within the topic to fetch
//   - output: pointer to a value of type T to unmarshal the message into
//
// Returns an error if the topic or message does not exist, cannot be read, or
// fails to unmarshal into the provided output type.
func ReadPublication[T any](d *EdgeDevice, fromAgent string, persistent bool,
	key string, output *T) {
	fullName := fmt.Sprintf("%T", *new(T))
	typeName := fullName[strings.LastIndex(fullName, ".")+1:]
	var path string
	if persistent {
		path = fmt.Sprintf("/persistent/status/%s/%s/%s.json", fromAgent, typeName, key)
	} else {
		path = fmt.Sprintf("/run/%s/%s/%s.json", fromAgent, typeName, key)
	}
	data := d.ReadFile(path)
	if err := json.Unmarshal(data, output); err != nil {
		d.th.t.Fatalf("ReadPublication: failed to unmarshal %q from device %q: %v",
			path, d.devName, err)
	}
}

// ReadAllPublications retrieves all messages from a pub-sub topic published by
// the specified device and agent (microservice).
//
// Parameters:
//   - d: the EdgeDevice handle to read from
//   - fromAgent: the name of the agent/microservice publishing the topic
//
// Returns a slice of values of type T representing all messages from the topic,
// or an error if reading or unmarshaling fails.
func ReadAllPublications[T any](d *EdgeDevice, fromAgent string, persistent bool) []T {
	fullName := fmt.Sprintf("%T", *new(T))
	typeName := fullName[strings.LastIndex(fullName, ".")+1:]
	var dir string
	if persistent {
		dir = fmt.Sprintf("/persistent/status/%s/%s", fromAgent, typeName)
	} else {
		dir = fmt.Sprintf("/run/%s/%s", fromAgent, typeName)
	}
	// List all JSON files in the directory; suppress errors if the dir is absent.
	stdout, _, err := d.RunShellScript(
		"find "+shellEscape(dir)+" -maxdepth 1 -name '*.json' -type f 2>/dev/null || true",
		quickSSHCommandTimeout, 0)
	if err != nil {
		d.th.t.Fatalf("ReadAllPublications: failed to list %q on device %q: %v",
			dir, d.devName, err)
	}
	var results []T
	for _, file := range strings.Fields(stdout) {
		data := d.ReadFile(file)
		var item T
		if err := json.Unmarshal(data, &item); err != nil {
			d.th.t.Fatalf("ReadAllPublications: failed to unmarshal %q from device %q: %v",
				file, d.devName, err)
		}
		results = append(results, item)
	}
	return results
}

// getDevUUID returns the device UUID, calling t.Fatalf if not found/onboarded.
func (d *EdgeDevice) getDevUUID() uuid.UUID {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	devState, found := d.th.devices[d.devName]
	if !found {
		d.th.t.Fatalf("Unknown device %q", d.devName)
	}
	if devState.ID == NilUUID {
		d.th.t.Fatalf("Device %q is not onboarded", d.devName)
	}
	return devState.ID
}

// iterateInfoMsgs fetches all info messages from Adam matching the filter,
// calling onMatch for each. It uses a short timeout and calls t.Fatalf on error.
func (d *EdgeDevice) iterateInfoMsgs(devUUID uuid.UUID,
	filter func(*eveinfo.ZInfoMsg) bool, onMatch func(*eveinfo.ZInfoMsg)) {
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherInfoMsgsTimeout)
	defer cancel()
	err := d.th.adamClient.IterateDeviceInfoMsgs(ctx, devUUID, filter,
		infoMsgIterFn(func(msg *eveinfo.ZInfoMsg) (bool, error) {
			onMatch(msg)
			return false, nil
		}), false)
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve info messages for device %q: %v",
			d.devName, err)
	}
}

// iterateMetricMsgs fetches all metric messages from Adam, calling onMatch for each.
// It uses a short timeout and calls t.Fatalf on error.
func (d *EdgeDevice) iterateMetricMsgs(
	devUUID uuid.UUID, onMatch func(*evemetrics.ZMetricMsg)) {
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherMetricsMsgsTimeout)
	defer cancel()
	err := d.th.adamClient.IterateDeviceMetrics(ctx, devUUID,
		metricMsgIterFn(func(msg *evemetrics.ZMetricMsg) (bool, error) {
			onMatch(msg)
			return false, nil
		}), false)
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve metrics for device %q: %v",
			d.devName, err)
	}
}

// infoMsgIterFn adapts a function to the controller.InfoMsgIterator interface.
type infoMsgIterFn func(*eveinfo.ZInfoMsg) (bool, error)

func (f infoMsgIterFn) Iterate(msg *eveinfo.ZInfoMsg) (bool, error) { return f(msg) }

// metricMsgIterFn adapts a function to the controller.MetricMsgIterator interface.
type metricMsgIterFn func(*evemetrics.ZMetricMsg) (bool, error)

func (f metricMsgIterFn) Iterate(msg *evemetrics.ZMetricMsg) (bool, error) { return f(msg) }

// appDownloadProgress returns the average download progress (0–100) across
// the app's volumes. For each volume UUID listed in volumeRefs the progress
// is taken from the latest ZInfoVolume in volumes:
//   - INVALID or INITIAL state → 0%
//   - DOWNLOADED or above      → 100%
//   - any other state          → ProgressPercentage as reported
//
// Returns 0 if volumeRefs is empty or no volume info has been received yet.
func appDownloadProgress(
	volumeRefs []string, volumes map[string]*eveinfo.ZInfoVolume) uint32 {
	if len(volumeRefs) == 0 {
		return 0
	}
	var total uint32
	for _, ref := range volumeRefs {
		vol, ok := volumes[ref]
		if !ok {
			// No info received yet for this volume; treat as 0%.
			continue
		}
		state := vol.GetState()
		switch {
		case state == eveinfo.ZSwState_INVALID || state == eveinfo.ZSwState_INITIAL:
			// 0 -- nothing added
		case state >= eveinfo.ZSwState_DOWNLOADED:
			total += 100
		default:
			total += vol.GetProgressPercentage()
		}
	}
	return total / uint32(len(volumeRefs))
}

// logMsgCollector accumulates log entries into []LogMsg, applying LogMsgMatch filters.
type logMsgCollector struct {
	match LogMsgMatch
	msgs  []LogMsg
}

func (c *logMsgCollector) toMatcher() logger.LogEntryMatcher {
	m := c.match
	return func(entry *evelogs.LogEntry) bool {
		ts := entry.GetTimestamp().AsTime()
		if m.Severity != "" && entry.GetSeverity() != m.Severity {
			return false
		}
		if m.Source != "" && entry.GetSource() != m.Source {
			return false
		}
		if m.Filename != "" && entry.GetFilename() != m.Filename {
			return false
		}
		if m.MsgHasSubstring != "" &&
			!strings.Contains(entry.GetContent(), m.MsgHasSubstring) {
			return false
		}
		if m.MsgMatchesRegexp.String() != "" &&
			!m.MsgMatchesRegexp.MatchString(entry.GetContent()) {
			return false
		}
		if !m.NotBefore.IsZero() && ts.Before(m.NotBefore) {
			return false
		}
		if !m.NotAfter.IsZero() && ts.After(m.NotAfter) {
			return false
		}
		return true
	}
}

func (c *logMsgCollector) Iterate(entry *evelogs.LogEntry) (bool, error) {
	c.msgs = append(c.msgs, LogMsg{
		Severity:  entry.GetSeverity(),
		Source:    entry.GetSource(),
		Filename:  entry.GetFilename(),
		Message:   entry.GetContent(),
		Timestamp: entry.GetTimestamp().AsTime(),
	})
	return false, nil
}

// shellEscape returns a single-quoted shell-safe version of s.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
