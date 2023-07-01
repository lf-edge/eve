// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/conntester"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
)

const (
	errorTime      = 60 * time.Second
	warningTime    = 40 * time.Second
	watchdogPeriod = 25 * time.Second
)

// LastResortKey : key used for DPC used as a last-resort.
const LastResortKey = "lastresort"

var nilUUID = uuid.UUID{} // used as a constant

// DpcManager manages a list of received device port configurations.
// Note that device port configuration (DevicePortConfig struct; abbreviated
// to DPC) represents configuration for all (physical) network interfaces
// to be used for device management or to be shared by applications
// (i.e. excluding NIC pass-through).
// The goal is to select and apply DPC with a working external connectivity,
// so that EVE is able to access the controller, and among the working DPCs
// prefer the one with the highest assigned priority (typically the last received).
// The manager uses ConnectivityTester to probe the connectivity status
// of the currently applied DPC. Based on the probing result, it may keep DPC
// unchanged or it may fallback to a lower-priority but working configuration.
// Whenever there is a higher-priority DPC available, the manager will test
// it periodically and switch to it as soon as the probing succeeds.
// DPC is applied into the device state using DpcReconciler (see pillar/dpcreconciler).
// The reconciler is able to switch from one DPC to another.
// Lastly, NetworkMonitor is used to monitor network stack for interesting
// events, such as link state changes, and to collect state information.
// Manager publishes device network status (DeviceNetworkStatus struct; abbreviated
// to DNS), updated on every state change, including a switch to another DPC.
// DpcManager is a generic state machine, not tied to any particular network stack.
// Instead, the injected components NetworkMonitor, DpcReconciler and ConnTester
// make all the probing, monitoring and network configuration operations.
type DpcManager struct {
	Log       *base.LogObject
	Watchdog  Watchdog
	AgentName string

	// Keep nil values to let DpcManager to use default implementations.
	// It is useful to override for unit testing purposes.
	WwanWatcher WwanWatcher
	GeoService  GeolocationService

	// Minimum time that should pass after a DPC verification failure
	// until the DPC is eligible for another round of verification.
	// By default it is 5 minutes.
	// It is useful to override for unit testing purposes.
	// XXX Should we make this a global config parameter?
	DpcMinTimeSinceFailure time.Duration

	// NIM components that the manager interacts with
	NetworkMonitor netmonitor.NetworkMonitor
	DpcReconciler  dpcreconciler.DpcReconciler
	ConnTester     conntester.ConnectivityTester

	// Publications
	PubDummyDevicePortConfig pubsub.Publication // for logging
	PubDevicePortConfigList  pubsub.Publication
	PubDeviceNetworkStatus   pubsub.Publication
	PubWwanStatus            pubsub.Publication
	PubWwanMetrics           pubsub.Publication
	PubWwanLocationInfo      pubsub.Publication

	// Metrics
	ZedcloudMetrics *zedcloud.AgentMetrics

	// Current configuration
	dpcList          types.DevicePortConfigList
	adapters         types.AssignableAdapters
	globalCfg        types.ConfigItemValueMap
	hasGlobalCfg     bool
	radioSilence     types.RadioSilence
	enableLastResort bool
	devUUID          uuid.UUID
	// Boot-time configuration
	dpclPresentAtBoot bool

	// DPC verification
	dpcVerify dpcVerify

	// Current status
	reconcileStatus dpcreconciler.ReconcileStatus
	deviceNetStatus types.DeviceNetworkStatus
	wwanStatus      types.WwanStatus
	wwanMetrics     types.WwanMetrics

	// Channels
	inputCommands chan inputCommand
	networkEvents <-chan netmonitor.Event
	wwanEvents    <-chan WwanEvent

	// Timers
	dpcTestTimer          *time.Timer
	dpcTestBetterTimer    *time.Timer
	pendingDpcTimer       *time.Timer
	geoTimer              flextimer.FlexTickerHandle
	dpcTestDuration       time.Duration // Wait for DHCP address
	dpcTestInterval       time.Duration // Test interval in minutes.
	dpcTestBetterInterval time.Duration // Look for lower/better index
	geoRedoInterval       time.Duration
	geoRetryInterval      time.Duration
	lastPublishedLocInfo  types.WwanLocationInfo

	// Netdump
	netDumper       *netdump.NetDumper // nil if netdump is disabled
	netdumpInterval time.Duration
	lastNetdumpPub  time.Time // last call to publishNetdump
	startTime       time.Time
}

// Watchdog : methods used by DpcManager to interact with Watchdog.
type Watchdog interface {
	// RegisterFileWatchdog tells the watchdog about the touch file.
	RegisterFileWatchdog(agentName string)
	// StillRunning touches a file per agentName to signal the event loop is still running
	// Those files are observed by the watchdog
	StillRunning(agentName string, warnTime, errTime time.Duration)
	// CheckMaxTimeTopic verifies if the time for a call has exceeded a reasonable number.
	CheckMaxTimeTopic(agentName, topic string, start time.Time,
		warnTime, errTime time.Duration)
}

// WwanEvent is sent by WwanWatcher whenever there is new output coming
// from wwan microservice.
type WwanEvent uint8

const (
	// WwanEventUndefined : undefined event, will be ignored.
	WwanEventUndefined WwanEvent = iota
	// WwanEventNewStatus : new wwan status data are available,
	// reload with WwanWatcher.LoadStatus()
	WwanEventNewStatus
	// WwanEventNewMetrics : new wwan metrics are available,
	// reload with WwanWatcher.LoadMetrics()
	WwanEventNewMetrics
	// WwanEventNewLocationInfo : new location info published by wwan microservice,
	// reload with WwanWatcher.LoadLocationInfo()
	WwanEventNewLocationInfo
)

// WwanWatcher allows to watch for output coming from wwan microservice.
// wwan microservice is a shell script and uses files for input/output
// instead of pubsub.
type WwanWatcher interface {
	Watch(ctx context.Context) (<-chan WwanEvent, error)
	LoadStatus() (types.WwanStatus, error)
	LoadMetrics() (types.WwanMetrics, error)
	LoadLocationInfo() (types.WwanLocationInfo, error)
}

// GeolocationService allows to obtain geolocation information based
// on assigned IP address.
type GeolocationService interface {
	// GetGeolocationInfo tries to obtain geolocation information
	// corresponding to the given IP address.
	GetGeolocationInfo(ipAddr net.IP) (*ipinfo.IPInfo, error)
}

type command uint8

const (
	commandUndefined command = iota
	commandAddDPC
	commandDelDPC
	commandUpdateGCP
	commandUpdateAA
	commandUpdateRS
	commandUpdateDevUUID
)

type inputCommand struct {
	cmd     command
	dpc     types.DevicePortConfig   // for commandAddDPC and commandDelDPC
	gcp     types.ConfigItemValueMap // for commandUpdateGCP
	aa      types.AssignableAdapters // for commandUpdateAA
	rs      types.RadioSilence       // for commandUpdateRS
	devUUID uuid.UUID                // for commandUpdateDevUUID
}

type dpcVerify struct {
	inProgress     bool
	startedAt      time.Time
	cloudConnWorks bool
	crucialIfs     map[string]netmonitor.IfAttrs // key = ifName, change triggers restartVerify
}

// Init DpcManager
func (m *DpcManager) Init(ctx context.Context) error {
	m.dpcVerify.crucialIfs = make(map[string]netmonitor.IfAttrs)
	m.inputCommands = make(chan inputCommand, 10)
	if m.WwanWatcher == nil {
		m.WwanWatcher = &wwanWatcher{Log: m.Log}
	}
	if m.GeoService == nil {
		m.GeoService = &geoService{}
	}
	if m.DpcMinTimeSinceFailure == 0 {
		m.DpcMinTimeSinceFailure = 5 * time.Minute
	}
	m.dpcList.CurrentIndex = -1
	// We start assuming cloud connectivity works
	m.dpcVerify.cloudConnWorks = true

	// Keep timers inactive until we receive GCP.
	m.dpcTestTimer = &time.Timer{}
	m.dpcTestBetterTimer = &time.Timer{}
	m.pendingDpcTimer = &time.Timer{}
	m.geoTimer = flextimer.FlexTickerHandle{}

	// Ingest persisted list of DPCs. ingestDPCList will return false
	// to indicate the file is missing in /persist
	m.dpclPresentAtBoot = m.ingestDPCList()
	return nil
}

// Run DpcManager as a separate task with its own loop and a watchdog file.
func (m *DpcManager) Run(ctx context.Context) (err error) {
	m.startTime = time.Now()
	m.networkEvents = m.NetworkMonitor.WatchEvents(ctx, "dpc-reconciler")
	m.wwanEvents, err = m.WwanWatcher.Watch(ctx)
	if err != nil {
		return err
	}

	go m.run(ctx)
	return nil
}

func (m *DpcManager) run(ctx context.Context) {
	wdName := m.AgentName + "-DpcManager"
	stillRunning := time.NewTicker(watchdogPeriod)
	m.Watchdog.StillRunning(wdName, warningTime, errorTime)
	m.Watchdog.RegisterFileWatchdog(wdName)

	// Run initial reconciliation.
	m.reconcileStatus = m.DpcReconciler.Reconcile(ctx, m.reconcilerArgs())

	for {
		select {
		case inputCmd := <-m.inputCommands:
			switch inputCmd.cmd {
			case commandUndefined:
				m.Log.Warn("DpcManager: Received undefined command")
			case commandAddDPC:
				m.doAddDPC(ctx, inputCmd.dpc)
			case commandDelDPC:
				m.doDelDPC(ctx, inputCmd.dpc)
			case commandUpdateGCP:
				m.doUpdateGCP(ctx, inputCmd.gcp)
			case commandUpdateAA:
				m.doUpdateAA(ctx, inputCmd.aa)
			case commandUpdateRS:
				m.doUpdateRadioSilence(ctx, inputCmd.rs)
			case commandUpdateDevUUID:
				m.doUpdateDevUUID(ctx, inputCmd.devUUID)
			}
			m.resumeVerifyIfAsyncDone(ctx)

		case <-m.reconcileStatus.ResumeReconcile:
			m.reconcileStatus = m.DpcReconciler.Reconcile(ctx, m.reconcilerArgs())
			m.resumeVerifyIfAsyncDone(ctx)

		case _, ok := <-m.dpcTestTimer.C:
			start := time.Now()
			if !ok {
				m.Log.Noticef("DPC test timer stopped?")
			} else if m.dpcList.CurrentIndex == -1 {
				m.Log.Tracef("Starting looking for working Device connectivity to cloud")
				m.restartVerify(ctx, "looking for working DPC")
				m.Log.Noticef("Looking for working done at index %d. Took %v",
					m.dpcList.CurrentIndex, time.Since(start))
			} else {
				m.Log.Tracef("Starting test of Device connectivity to cloud")
				err := m.testConnectivityToCloud(ctx)
				if err == nil {
					m.Log.Tracef("Device connectivity to cloud worked. Took %v",
						time.Since(start))
				} else {
					m.Log.Noticef("Device connectivity to cloud failed (%v). Took %v",
						err, time.Since(start))
				}
			}
			m.Watchdog.CheckMaxTimeTopic(m.AgentName, "TestTimer", start,
				warningTime, errorTime)

		case _, ok := <-m.dpcTestBetterTimer.C:
			start := time.Now()
			if !ok {
				m.Log.Noticef("DPC testBetterTimer stopped?")
			} else if m.dpcList.CurrentIndex == 0 && !m.deviceNetStatus.HasErrors() {
				m.Log.Tracef("DPC testBetterTimer at zero ignored")
			} else {
				m.Log.Noticef("Network testBetterTimer at index %d",
					m.dpcList.CurrentIndex)
				m.restartVerify(ctx, "looking for better DPC")
				m.Log.Noticef("Network testBetterTimer done at index %d. Took %v",
					m.dpcList.CurrentIndex, time.Since(start))
			}
			m.Watchdog.CheckMaxTimeTopic(m.AgentName, "TestBetterTimer", start,
				warningTime, errorTime)

		case _, ok := <-m.pendingDpcTimer.C:
			start := time.Now()
			if !ok {
				m.Log.Noticef("Device port test timer stopped?")
			} else {
				m.Log.Trace("PendTimer at", start)
				m.runVerify(ctx, "PendTimer fired")
			}
			m.Watchdog.CheckMaxTimeTopic(m.AgentName, "PendTimer", start,
				warningTime, errorTime)

		case <-m.geoTimer.C:
			start := time.Now()
			m.Log.Trace("GeoTimer at", start)
			m.updateGeo()
			m.Watchdog.CheckMaxTimeTopic(m.AgentName, "geoTimer", start,
				warningTime, errorTime)

		case event := <-m.networkEvents:
			switch ev := event.(type) {
			case netmonitor.IfChange:
				ifName := ev.Attrs.IfName
				if !m.adapters.Initialized {
					continue
				}
				if !m.isInterfaceCrucial(ifName) {
					delete(m.dpcVerify.crucialIfs, ifName)
					continue
				}
				m.Log.Noticef("Crucial port %s changed", ifName)
				newAttrs := ev.Attrs
				m.dpcVerify.crucialIfs[ifName] = newAttrs
				prevAttrs, known := m.dpcVerify.crucialIfs[ifName]
				if !known ||
					prevAttrs.AdminUp != newAttrs.AdminUp ||
					prevAttrs.LowerUp != newAttrs.LowerUp ||
					prevAttrs.Enslaved != newAttrs.Enslaved ||
					prevAttrs.IfIndex != newAttrs.IfIndex {
					m.Log.Noticef("Restarting network connectivity verification "+
						"because port %s is crucial to network configuration", ifName)
					reasonForVerify := fmt.Sprintf("crucial interface %s changed", ifName)
					m.restartVerify(ctx, reasonForVerify)
					m.updateDNS()
				}
			case netmonitor.AddrChange:
				ifAttrs, err := m.NetworkMonitor.GetInterfaceAttrs(ev.IfIndex)
				if err != nil {
					m.Log.Warnf("Failed to get attributes for ifIndex %d: %v",
						ev.IfIndex, err)
					continue
				}
				if m.isInterfaceCrucial(ifAttrs.IfName) {
					if dpc := m.currentDPC(); dpc != nil {
						reasonForVerify := "IP address change for interface " + ifAttrs.IfName
						switch dpc.State {
						case types.DPCStateIPDNSWait,
							types.DPCStatePCIWait,
							types.DPCStateIntfWait:
							// Note that DPCStatePCIWait and DPCStateIntfWait can be returned
							// also in scenarios where some ports are in PCIBack while others
							// are waiting for IP addresses.
							// For the sake of those not in PCIBack it makes sense to retest DPC.
							m.runVerify(ctx, reasonForVerify)
						case types.DPCStateFail:
							m.restartVerify(ctx, reasonForVerify)
						}
					}
				}
				m.updateDNS()
			case netmonitor.DNSInfoChange:
				m.updateDNS()
			}

		case event, ok := <-m.wwanEvents:
			if !ok {
				m.Log.Warnf("Wwan watcher stopped")
				continue
			}
			switch event {
			case WwanEventUndefined:
				m.Log.Warnf("Undefined event received from WwanWatcher")
			case WwanEventNewStatus:
				m.reloadWwanStatus()
			case WwanEventNewMetrics:
				m.reloadWwanMetrics()
			case WwanEventNewLocationInfo:
				m.reloadWwanLocationInfo()
			}

		case <-ctx.Done():
			return

		case <-stillRunning.C:
		}

		m.Watchdog.StillRunning(wdName, warningTime, errorTime)
	}
}

func (m *DpcManager) reconcilerArgs() dpcreconciler.Args {
	args := dpcreconciler.Args{
		GCP: m.globalCfg,
		AA:  m.adapters,
		RS:  m.radioSilence,
	}
	if m.currentDPC() != nil {
		args.DPC = *m.currentDPC()
	}
	return args
}

// AddDPC : add a new DPC into the list of configurations to work with.
// It will be added into the list at a position determined by the TimePriority
// attribute. The higher the timestamp is, the higher the priority is.
func (m *DpcManager) AddDPC(dpc types.DevicePortConfig) {
	m.inputCommands <- inputCommand{
		cmd: commandAddDPC,
		dpc: dpc,
	}
}

// DelDPC : remove DPC from the list of configurations to work with.
func (m *DpcManager) DelDPC(dpc types.DevicePortConfig) {
	m.inputCommands <- inputCommand{
		cmd: commandDelDPC,
		dpc: dpc,
	}
}

// UpdateGCP : apply an updated set of global configuration properties.
// These properties decides for example how often to probe connectivity
// status, whether to allow SSH access, etc.
func (m *DpcManager) UpdateGCP(gcp types.ConfigItemValueMap) {
	m.inputCommands <- inputCommand{
		cmd: commandUpdateGCP,
		gcp: gcp,
	}
}

// UpdateAA : apply an updated set of assignable adapters. This list
// contains low-level information about all the physical adapters,
// such as their names in the kernel, PCI addresses, etc.
func (m *DpcManager) UpdateAA(aa types.AssignableAdapters) {
	m.inputCommands <- inputCommand{
		cmd: commandUpdateAA,
		aa:  aa,
	}
}

// UpdateRadioSilence : apply an update radio silence configuration.
// When radio silence is set to ON, all wireless ports should be configured
// with radio transmission disabled.
func (m *DpcManager) UpdateRadioSilence(rs types.RadioSilence) {
	m.inputCommands <- inputCommand{
		cmd: commandUpdateRS,
		rs:  rs,
	}
}

// UpdateDevUUID : apply an update of the UUID assigned to the device by the controller.
func (m *DpcManager) UpdateDevUUID(devUUID uuid.UUID) {
	m.inputCommands <- inputCommand{
		cmd:     commandUpdateDevUUID,
		devUUID: devUUID,
	}
}

// GetDNS returns device network state information.
func (m *DpcManager) GetDNS() types.DeviceNetworkStatus {
	return m.deviceNetStatus
}

func (m *DpcManager) doUpdateGCP(ctx context.Context, gcp types.ConfigItemValueMap) {
	firstGCP := !m.hasGlobalCfg
	m.globalCfg = gcp
	m.hasGlobalCfg = true
	testInterval := time.Second *
		time.Duration(m.globalCfg.GlobalValueInt(types.NetworkTestInterval))
	testBetterInterval := time.Second *
		time.Duration(m.globalCfg.GlobalValueInt(types.NetworkTestBetterInterval))
	testDuration := time.Second *
		time.Duration(m.globalCfg.GlobalValueInt(types.NetworkTestDuration))
	// We refresh the gelocation information when the underlay
	// IP address(es) change, plus periodically with this interval.
	geoRedoInterval := time.Second *
		time.Duration(m.globalCfg.GlobalValueInt(types.NetworkGeoRedoTime))
	// Interval for Geo retries after failure etc. Should be less than geoRedoInterval.
	geoRetryInterval := time.Second *
		time.Duration(m.globalCfg.GlobalValueInt(types.NetworkGeoRetryTime))

	fallbackAnyEth := m.globalCfg.GlobalValueTriState(types.NetworkFallbackAnyEth)
	m.enableLastResort = fallbackAnyEth == types.TS_ENABLED

	if m.dpcTestInterval != testInterval {
		if testInterval == 0 {
			m.Log.Warn("NOT running TestTimer")
			m.dpcTestTimer = &time.Timer{}
		} else {
			m.Log.Functionf("Starting TestTimer: %v", testInterval)
			m.dpcTestTimer = time.NewTimer(testInterval)
		}
		m.dpcTestInterval = testInterval
	}
	if m.dpcTestBetterInterval != testBetterInterval {
		if testBetterInterval == 0 {
			m.Log.Warn("NOT running TestBetterTimer")
			m.dpcTestBetterTimer = &time.Timer{}
		} else {
			m.Log.Functionf("Starting TestBetterTimer: %v", testBetterInterval)
			m.dpcTestBetterTimer = time.NewTimer(testBetterInterval)
		}
		m.dpcTestBetterInterval = testBetterInterval
	}
	if m.dpcTestDuration != testDuration {
		if testDuration == 0 {
			m.Log.Warn("NOT running PendingTimer")
		}
		m.dpcTestDuration = testDuration
	}
	if m.geoRetryInterval != geoRetryInterval {
		if geoRetryInterval == 0 {
			m.Log.Warn("NOT running GeoTimer")
			m.geoTimer = flextimer.FlexTickerHandle{}
		} else {
			m.Log.Functionf("Starting GeoTimer: %v", geoRetryInterval)
			geoMax := float64(geoRetryInterval)
			geoMin := geoMax * 0.3
			m.geoTimer = flextimer.NewRangeTicker(time.Duration(geoMin),
				time.Duration(geoMax))
		}
		m.geoRetryInterval = geoRetryInterval
	}
	m.geoRedoInterval = geoRedoInterval
	m.reinitNetdumper()

	m.reconcileStatus = m.DpcReconciler.Reconcile(ctx, m.reconcilerArgs())
	// If we have persisted DPCs then go ahead and pick a working one
	// with the highest priority, do not wait for dpcTestTimer to fire.
	if firstGCP && m.currentDPC() == nil && len(m.dpcList.PortConfigList) > 0 {
		m.restartVerify(ctx, "looking for working (persisted) DPC")
	}
}

func (m *DpcManager) doUpdateAA(ctx context.Context, adapters types.AssignableAdapters) {
	m.adapters = adapters
	// In case a verification is in progress and is waiting for return from pciback
	if dpc := m.currentDPC(); dpc != nil {
		if dpc.State == types.DPCStatePCIWait || dpc.State == types.DPCStateIntfWait {
			m.runVerify(ctx, "assignable adapters were updated")
		}
	}
	m.reconcileStatus = m.DpcReconciler.Reconcile(ctx, m.reconcilerArgs())
}

func (m *DpcManager) resumeVerifyIfAsyncDone(ctx context.Context) {
	if dpc := m.currentDPC(); dpc != nil {
		asyncInProgress := m.reconcileStatus.AsyncInProgress
		if dpc.State == types.DPCStateAsyncWait && !asyncInProgress {
			// Config is ready, continue verification.
			m.runVerify(ctx, "async ops no longer in progress")
		}
	}
}

func (m *DpcManager) doUpdateDevUUID(ctx context.Context, newUUID uuid.UUID) {
	m.devUUID = newUUID
	// Netdumper uses different publish period after onboarding.
	m.reinitNetdumper()
}

func (m *DpcManager) reinitNetdumper() {
	gcp := m.globalCfg
	netDumper := m.netDumper
	netdumpEnabled := gcp.GlobalValueBool(types.NetDumpEnable)
	if netdumpEnabled {
		if netDumper == nil {
			netDumper = &netdump.NetDumper{}
			// Determine when was the last time DPCManager published anything.
			var err error
			m.lastNetdumpPub, err = netDumper.LastPublishAt(
				m.netDumpOKTopic(), m.netDumpFailTopic())
			if err != nil {
				m.Log.Warn(err)
			}
		}
		isOnboarded := m.devUUID != nilUUID
		if isOnboarded {
			m.netdumpInterval = time.Second *
				time.Duration(gcp.GlobalValueInt(types.NetDumpTopicPostOnboardInterval))
		} else {
			m.netdumpInterval = time.Second *
				time.Duration(gcp.GlobalValueInt(types.NetDumpTopicPreOnboardInterval))
		}
		maxCount := gcp.GlobalValueInt(types.NetDumpTopicMaxCount)
		netDumper.MaxDumpsPerTopic = int(maxCount)
	} else {
		netDumper = nil
	}
	m.netDumper = netDumper
}
