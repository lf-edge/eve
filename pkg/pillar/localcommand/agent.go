// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

const (
	// Default TCP port used by LPS.
	defaultLpsPort = "8888"

	// Prefix for all goroutines fetching commands from LPS.
	// Used by the watchdog for monitoring.
	watchdogPrefix = "lps-"

	// Time thresholds for event loop handlers.
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	// logPrefix is prepended to every log message, making it easy to filter
	// or search logs related to local commands.
	logPrefix = "LocalCmdAgent"
)

var nilUUID uuid.UUID // used as a constant

// LocalCmdAgent handles processing of "local commands" received from LPS or LOC.
type LocalCmdAgent struct {
	ConstructorArgs
	RunArgs
	globalConfig *types.ConfigItemValueMap

	// Task control.
	tc taskControl

	// LPS configuration
	lpsConfig    types.LPSConfig
	lpsURL       *url.URL
	lpsAddresses lpsAddresses

	// LOC configuration is only used to check if LOC is configured.
	// The actual compound config fetch is done by zedagent and LocalCmdAgent
	// only receives the command-portion of the config via ProcessLocalCommandsFromLoc.
	locConfig types.LOCConfig

	// local_profile
	currentProfile string
	globalProfile  string
	localProfile   string
	profileMx      sync.RWMutex
	profileTicker  *taskTicker

	// radio
	radioSilence   types.RadioSilence
	radioSilenceMx sync.RWMutex
	radioTicker    *taskTicker

	// appinfo
	appCommands   types.LocalCommands
	appCommandsMx sync.RWMutex
	appInfoTicker *taskTicker

	// devinfo
	lastDevCmdTimestamp uint64
	devInfoTicker       *taskTicker

	// location
	lastPublishedLocation time.Time
	// We do not use ticker and a background task here, operation to publish location
	// is triggered from outside (when e.g. the location changes).
	throttledLocation bool
	// At most one publish triggered from outside at a time.
	locationMx sync.Mutex

	// network
	networkConfig   types.DevicePortConfig
	networkConfigMx sync.RWMutex
	networkTicker   *taskTicker
	lastNetworkErr  error

	// LPS app boot configuration (USB boot priority, etc.)
	// key = app UUID (uuid.UUID), value = types.AppBootConfig
	// Uses sync.Map for lock-free reads from multiple goroutines.
	// Only appBootInfoTask goroutine writes to this map.
	currentAppBootConfigs sync.Map

	// LPS app boot info posting and boot config receiving
	appBootInfoTicker *taskTicker
}

// ConstructorArgs are required input arguments for creating a LocalCmdAgent.
// These are available in the early initialization phase of zedagent.
type ConstructorArgs struct {
	Log         *base.LogObject
	Watchdog    Watchdog
	ConfigAgent ConfigAgent
}

// RunArgs are arguments passed to LocalCmdAgent.RunTasks, available later
// when pubsub topics are ready.
type RunArgs struct {
	CtrlClient            *controllerconn.Client
	OnboardingStatus      PubSubTopicReader
	AppInstanceStatus     PubSubTopicReader
	AppInstanceConfig     PubSubTopicReader
	AppNetworkStatus      PubSubTopicReader
	DeviceNetworkStatus   PubSubTopicReader
	NetworkInstanceConfig PubSubTopicReader
	WwanMetrics           PubSubTopicReader
	NodeAgentStatus       PubSubTopicReader
	ZedagentStatus        PubSubTopicReader
	DevicePortConfigList  PubSubTopicReader
}

// Watchdog : methods used by LocalCmdAgent to interact with Watchdog.
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

// ConfigAgent applies commands and partial configuration changes received
// locally from LPS or LOC.
// This is implemented by zedagent (see pkg/pillar/cmd/zedagent/localcommand.go).
type ConfigAgent interface {
	// ApplyProfile applies a given profile, which then decides the subset of applications
	// to activate.
	ApplyProfile(string)

	// ApplyRadioSilence applies radio silence configuration.
	ApplyRadioSilence(types.RadioSilence)

	// ApplyLocalDeviceCommand applies a locally received device command and reports
	// if any changes were actually triggered.
	ApplyLocalDeviceCommand(cmd types.DevCommand, timestamp uint64) (triggeredChanges bool)

	// ApplyLocalAppRestartCmd applies a locally requested restart command for an app.
	ApplyLocalAppRestartCmd(appUUID uuid.UUID, localCmd types.AppInstanceOpsCmd)

	// ApplyLocalAppPurgeCmd applies a locally requested purge command for an app.
	ApplyLocalAppPurgeCmd(appUUID uuid.UUID, localCmd types.AppInstanceOpsCmd,
		localVolumeGenCounters map[string]int64)

	// ApplyLocalNetworkConfig applies a network port configuration received from LPS,
	// overriding the active configuration for the set of locally changed ports.
	ApplyLocalNetworkConfig(types.DevicePortConfig)

	// ApplyAppBootConfig applies boot configuration for an app received from LPS.
	ApplyAppBootConfig(appUUID uuid.UUID)

	// ApplyDevicePropertyBootOrder applies boot order from device property to all apps
	// that don't have LPS or Controller overrides. Called when app.boot.order changes.
	// Returns true if any app was actually updated.
	ApplyDevicePropertyBootOrder() (changed bool)
}

// PubSubTopicReader : methods used by LocalCmdAgent to read messages from pubsub topics.
// LocalCmdAgent only reads from pubsub topics, it does not change anything.
// It is up to ConfigAgent to make and publish any changes.
type PubSubTopicReader interface {
	// GetAll returns all published messages.
	GetAll() map[string]interface{}
	// Get returns message identified by the given key.
	Get(key string) (interface{}, error)
}

// lpsAddresses stores discovered LPS addresses grouped by network interface.
// addrDiscoveryMx is used to serialize calls to discoverLpsAddresses().
// LocalCmdAgent tasks that read from this map do not need to take the lock,
// since they are paused while LPS address discovery is in progress.
type lpsAddresses struct {
	addrsByIface    map[string][]lpsAddress // key = interface name, value = addresses
	upToDate        bool
	addrDiscoveryMx sync.Mutex
}

// Returns true if there are no stored LPS addresses.
func (la *lpsAddresses) empty() bool {
	for _, addrs := range la.addrsByIface {
		if len(addrs) > 0 {
			return false
		}
	}
	return true
}

// taskTicker wraps a flextimer.FlexTickerHandle with synchronization
// and a throttle flag. It allows dynamically adjusting ticker intervals,
// forcing immediate ticks, and temporarily suppressing ticks when throttled.
type taskTicker struct {
	sync.RWMutex
	tickerHandle flextimer.FlexTickerHandle
	throttled    bool
}

// newTaskTicker creates a new taskTicker with a randomized firing interval.
// The actual interval is chosen randomly between 0.8×1.1×interval (0.88×interval)
// and 1.1×interval, which introduces jitter to avoid synchronized task execution
// across multiple Go routines.
func newTaskTicker(interval time.Duration) *taskTicker {
	maxTime := 1.1 * float64(interval)
	minTime := 0.8 * maxTime
	t := &taskTicker{
		tickerHandle: flextimer.NewRangeTicker(
			time.Duration(minTime), time.Duration(maxTime)),
	}
	return t
}

// update sets the throttle state and recalculates the ticker's randomized interval.
// When throttled is true, callers are expected to pass a longer interval (e.g. 1h
// instead of 1m), and the ticker will continue to fire within the new randomized
// [0.8×1.1×interval, 1.1×interval] range.
func (t *taskTicker) update(throttle bool, interval time.Duration) {
	t.Lock()
	defer t.Unlock()
	t.throttled = throttle
	maxTime := 1.1 * float64(interval)
	minTime := 0.8 * maxTime
	t.tickerHandle.UpdateRangeTicker(time.Duration(minTime), time.Duration(maxTime))
}

// tickerIsThrottled reports whether the ticker is currently throttled.
func (t *taskTicker) tickerIsThrottled() bool {
	t.RLock()
	defer t.RUnlock()
	return t.throttled
}

// tickNow forces the ticker to fire immediately, unless throttled.
func (t *taskTicker) tickNow() {
	if t.tickerIsThrottled() {
		return
	}
	t.tickerHandle.TickNow()
}

// tickerChan returns the ticker’s channel for receiving tick events.
func (t *taskTicker) tickerChan() <-chan time.Time {
	return t.tickerHandle.C
}

// taskControl provides thread-safe pause/resume functionality for concurrent tasks.
// It allows multiple callers to pause task execution and requires all of them
// to resume before tasks can continue running. Tasks can run in parallel when
// not paused.
type taskControl struct {
	beforeStart     func()
	pauseCounter    int // protected by pauseMx
	pauseMx         sync.Mutex
	pauseGeneration uint64 // protected by taskMx
	taskMx          sync.RWMutex
}

// pause increments the pause counter and blocks new tasks from starting.
// This blocks until the already running tasks complete and release the task lock.
// Multiple callers can pause concurrently — all must call the returned resume
// function before tasks can continue. Tasks that need to perform long-running
// operations without blocking pause can use runInterruptible, which temporarily
// releases the task lock and detects if a pause occurred during the operation.
func (lc *taskControl) pause() (resume func()) {
	lc.pauseMx.Lock()
	defer lc.pauseMx.Unlock()

	lc.pauseCounter++
	if lc.pauseCounter == 1 {
		// Pause begins here.
		lc.taskMx.Lock()
		lc.pauseGeneration++
	} // else already paused

	return func() {
		lc.pauseMx.Lock()
		defer lc.pauseMx.Unlock()

		lc.pauseCounter--
		if lc.pauseCounter == 0 {
			// Pause ends here.
			lc.taskMx.Unlock()
		}
	}
}

// startTask marks the beginning of a task.
//   - If a beforeStart callback is configured, it is executed before attempting to start.
//   - Returns true if task execution is currently paused, in which case the caller
//     should not proceed.
func (lc *taskControl) startTask() (paused bool) {
	if lc.beforeStart != nil {
		lc.beforeStart()
	}
	locked := lc.taskMx.TryRLock()
	return !locked // If we couldn't get read lock, we're paused
}

// endTask marks the completion of a task started with startTask.
func (lc *taskControl) endTask() {
	lc.taskMx.RUnlock()
}

// runInterruptible temporarily releases the task lock to allow Pause() to proceed,
// runs the provided callback, then re-acquires the lock. Returns true if a pause
// was triggered while the callback was running, indicating the caller should
// discard or retry the operation.
func (lc *taskControl) runInterruptible(callback func()) (wasPaused bool) {
	// Capture current pause generation
	startGen := lc.pauseGeneration

	// Temporarily release task lock so Pause() can proceed
	lc.taskMx.RUnlock()

	// Run the callback
	callback()

	// Re-acquire the task lock.
	lc.taskMx.RLock()

	// Check if a pause occurred during callback
	wasPaused = lc.pauseGeneration != startGen
	return
}

// lpsAddress contains a source IP and a destination URL (without path)
// to use to connect to LPS.
type lpsAddress struct {
	sourceIP net.IP
	destURL  *url.URL
	appUUID  uuid.UUID
}

// NewLocalCmdAgent creates and initializes a new instance of LocalCmdAgent.
func NewLocalCmdAgent(args ConstructorArgs) *LocalCmdAgent {
	lc := &LocalCmdAgent{ConstructorArgs: args}
	// Make sure that newly started task is using up-to-date LPS addresses.
	lc.tc.beforeStart = lc.ensureLpsAddresses
	lc.initializeProfile()
	lc.initializeRadioConfig()
	lc.initializeAppCommands()
	lc.initializeDevCommands()
	lc.initializeNetworkConfig()
	lc.initializeAppBootInfo()
	return lc
}

// RunTasks starts all the periodic tasks of the LocalCmdAgent.
func (lc *LocalCmdAgent) RunTasks(args RunArgs) {
	// Pubsub topics with app status and NI config are now available to discover
	// the LPS addresses.
	lc.lpsAddresses.addrDiscoveryMx.Lock()
	lc.RunArgs = args
	lc.discoverLpsAddresses()
	lc.lpsAddresses.addrDiscoveryMx.Unlock()
	// Start each task in a separate Go routine.
	go lc.runProfileTask()
	go lc.runRadioTask()
	go lc.runAppInfoTask()
	go lc.runDevInfoTask()
	go lc.runNetworkTask()
	go lc.runAppBootInfoTask()
}

// Pause temporarily suspends all tasks, blocking the processing of
// new commands or configuration from LPS until resumed.
// Must not be called from within ConfigAgent handler methods,
// as this would result in deadlock.
// Returns a resume function that must be called to continue execution.
func (lc *LocalCmdAgent) Pause() (resume func()) {
	return lc.tc.pause()
}

// ProcessLocalCommandsFromLoc handles commands received from LOC.
// Processes radio configuration, application commands, and device command
// if they are present in the received compound configuration.
func (lc *LocalCmdAgent) ProcessLocalCommandsFromLoc(
	compoundConfig *config.CompoundEdgeDevConfig) {
	resume := lc.tc.pause()
	defer resume()
	radioConfig := compoundConfig.GetRadioConfig()
	if radioConfig != nil {
		lc.processReceivedRadioConfig(radioConfig)
	}
	appCmdList := compoundConfig.GetAppCmdList()
	if appCmdList != nil {
		lc.processReceivedAppCommands(appCmdList)
	}
	devCmd := compoundConfig.GetDevCmd()
	if devCmd != nil {
		lc.processReceivedDevCommand(devCmd)
	}
}

// UpdateGlobalConfig updates the LocalCmdAgent with the latest global configuration.
// This handles:
// - Adjusting the local profile timer interval
// - Detecting changes to app.boot.order and updating affected apps
func (lc *LocalCmdAgent) UpdateGlobalConfig(config *types.ConfigItemValueMap) {
	oldBootOrder := ""
	if lc.globalConfig != nil {
		oldBootOrder = lc.globalConfig.GlobalValueString(types.AppBootOrder)
	}
	lc.globalConfig = config
	lc.updateProfileTicker()

	// Check if app.boot.order changed
	newBootOrder := ""
	if config != nil {
		newBootOrder = config.GlobalValueString(types.AppBootOrder)
	}
	if oldBootOrder != newBootOrder {
		lc.Log.Noticef("%s: app.boot.order changed from %q to %q",
			logPrefix, oldBootOrder, newBootOrder)
		// Apply the new device property boot order to all affected apps.
		// Returns true if any app was actually updated.
		if lc.ConfigAgent.ApplyDevicePropertyBootOrder() {
			// Trigger immediate POST of boot order info to LPS
			lc.TriggerAppBootInfoPOST()
		}
	}
}

// UpdateLocConfig updates the LocalCmdAgent with the latest LOC configuration.
// This primarily indicates whether LOC is enabled and if radio silence configuration
// may be expected from it. Task execution is paused briefly while updating.
func (lc *LocalCmdAgent) UpdateLocConfig(locConfig types.LOCConfig) {
	resume := lc.tc.pause()
	defer resume()
	lc.locConfig = locConfig
}

// UpdateLpsConfig updates the LPS configuration.
// If the LPS URL changes, the agent re-discovers all the LPS addresses.
// Task execution is suspended while the update is applied.
func (lc *LocalCmdAgent) UpdateLpsConfig(globalProfile, lpsAddr, lpsToken string) error {
	resume := lc.tc.pause()
	defer resume()

	// Re-discover LPS addresses if the LPS URL changed.
	lc.lpsConfig.LpsToken = lpsToken
	var lpsAddrChanged bool
	if lc.lpsConfig.LpsAddress != lpsAddr {
		lc.Log.Noticef("%s: UpdateLpsConfig: LPS address changed from %q to %q",
			logPrefix, lc.lpsConfig.LpsAddress, lpsAddr)
		var lpsURL *url.URL
		if lpsAddr != "" {
			var err error
			lpsURL, err = lc.makeLpsBaseURL(lpsAddr)
			if err != nil {
				lc.Log.Errorf("%s: UpdateLpsConfig: makeLpsBaseURL: %v", logPrefix, err)
				return err
			}
		}
		// Refresh discovered LPS addresses.
		lc.lpsAddresses.addrDiscoveryMx.Lock()
		lc.lpsConfig.LpsAddress = lpsAddr
		lc.lpsURL = lpsURL
		lc.discoverLpsAddresses()
		lc.lpsAddresses.addrDiscoveryMx.Unlock()
		lpsAddrChanged = true
	}

	// Apply possibly changed global profile.
	lc.updateActiveProfile(true, globalProfile)

	// If LPS address changed, disable throttling and trigger immediate LPS GET/POST
	// requests (from the possibly new LPS instance).
	if lpsAddrChanged {
		lc.triggerProfileGET()
		lc.updateRadioTicker(false)
		lc.TriggerRadioPOST()
		lc.updateAppInfoTicker(false)
		lc.TriggerAppInfoPOST()
		lc.updateDevInfoTicker(false)
		lc.TriggerDevInfoPOST()
		lc.updateNetworkTicker(false)
		lc.TriggerNetworkPOST()
		lc.updateAppBootInfoTicker(false)
		lc.TriggerAppBootInfoPOST()
		lc.throttledLocation = false
	}
	return nil
}

// RefreshLpsAddresses only invalidates the cached LPS addresses.
// The next call to discoverLpsAddresses() will re-populate them.
func (lc *LocalCmdAgent) RefreshLpsAddresses() {
	lc.lpsAddresses.addrDiscoveryMx.Lock()
	defer lc.lpsAddresses.addrDiscoveryMx.Unlock()
	lc.lpsAddresses.upToDate = false
}

// ensureLpsAddresses ensures that cached LPS addresses are up-to-date.
// If the cache is invalidated, it pauses running tasks, re-discovers
// LPS addresses, and then resumes task execution.
// If already up-to-date, it does nothing.
func (lc *LocalCmdAgent) ensureLpsAddresses() {
	lc.lpsAddresses.addrDiscoveryMx.Lock()
	defer lc.lpsAddresses.addrDiscoveryMx.Unlock()
	if !lc.lpsAddresses.upToDate {
		resume := lc.tc.pause()
		lc.discoverLpsAddresses()
		resume()
	}
}

// IsAppRunningLps checks if the given application runs Local Profile Server.
func (lc *LocalCmdAgent) IsAppRunningLps(appUUID uuid.UUID) bool {
	lc.lpsAddresses.addrDiscoveryMx.Lock()
	defer lc.lpsAddresses.addrDiscoveryMx.Unlock()
	addrMap := lc.lpsAddresses.addrsByIface
	for _, srvAddrs := range addrMap {
		for _, srvAddr := range srvAddrs {
			if srvAddr.appUUID == appUUID {
				return true
			}
		}
	}
	return false
}

// makeLpsBaseURL constructs LPS URL without path.
func (lc *LocalCmdAgent) makeLpsBaseURL(lpsAddr string) (*url.URL, error) {
	host, port, err := net.SplitHostPort(lpsAddr)
	if err != nil {
		// No port given, treat the whole input as host.
		host = lpsAddr
		port = defaultLpsPort
	}
	if port == "" {
		port = defaultLpsPort
	}
	lpsURL := "http://" + net.JoinHostPort(host, port)
	u, err := url.Parse(lpsURL)
	if err != nil {
		return nil, fmt.Errorf("url.Parse: %w", err)
	}
	return u, nil
}

// discoverLpsAddresses processes configuration of network instances to locate all LPS
// addresses matching the given LPS URL.
func (lc *LocalCmdAgent) discoverLpsAddresses() {
	lc.lpsAddresses.addrsByIface = make(map[string][]lpsAddress)
	lc.lpsAddresses.upToDate = true

	if lc.lpsURL == nil || lc.AppNetworkStatus == nil || lc.NetworkInstanceConfig == nil {
		// LPS not configured or the required pubsub topics are not yet provided.
		return
	}

	appNetworkStatuses := lc.AppNetworkStatus.GetAll()
	networkInstanceConfigs := lc.NetworkInstanceConfig.GetAll()
	lpsHostname := lc.lpsURL.Hostname()
	lpsIP := net.ParseIP(lpsHostname)

	for _, entry := range appNetworkStatuses {
		appNetworkStatus := entry.(types.AppNetworkStatus)
		for _, adapterStatus := range appNetworkStatus.AppNetAdapterList {
			if len(adapterStatus.BridgeIPAddr) == 0 {
				continue
			}
			if lpsIP != nil {
				// Check if the defined IP of LPS equals one of the IPs
				// allocated to the app.
				var matchesApp bool
				for _, ip := range adapterStatus.AssignedAddresses.IPv4Addrs {
					if ip.Address.Equal(lpsIP) {
						matchesApp = true
						break
					}
				}
				for _, ip := range adapterStatus.AssignedAddresses.IPv6Addrs {
					if ip.Address.Equal(lpsIP) {
						matchesApp = true
						break
					}
				}
				if matchesApp {
					lpsAddr := lpsAddress{
						destURL:  lc.lpsURL,
						sourceIP: adapterStatus.BridgeIPAddr,
						appUUID:  appNetworkStatus.UUIDandVersion.UUID,
					}
					lc.lpsAddresses.addrsByIface[adapterStatus.Bridge] = append(
						lc.lpsAddresses.addrsByIface[adapterStatus.Bridge], lpsAddr)
				}
				continue
			}
			// check if defined hostname of LPS is in DNS records
			for _, ni := range networkInstanceConfigs {
				networkInstanceConfig := ni.(types.NetworkInstanceConfig)
				for _, dnsNameToIPList := range networkInstanceConfig.DnsNameToIPList {
					if dnsNameToIPList.HostName != lpsHostname {
						continue
					}
					for _, ip := range dnsNameToIPList.IPs {
						destURL := lc.replaceHostInURL(lc.lpsURL, ip.String())
						lc.Log.Functionf(
							"%s: discoverLpsAddresses: will use %s for bridge %s",
							logPrefix, destURL, adapterStatus.Bridge)
						lpsAddr := lpsAddress{
							destURL:  destURL,
							sourceIP: adapterStatus.BridgeIPAddr,
							appUUID:  appNetworkStatus.UUIDandVersion.UUID,
						}
						lc.lpsAddresses.addrsByIface[adapterStatus.Bridge] = append(
							lc.lpsAddresses.addrsByIface[adapterStatus.Bridge], lpsAddr)
					}
				}
			}
		}
	}
	return
}

// replaceHostInURL replaces the hostname in a URL while preserving the port.
// Handles both IPv4 and IPv6 addresses correctly.
func (lc *LocalCmdAgent) replaceHostInURL(url *url.URL, newHost string) *url.URL {
	result := *url // copy
	_, port, err := net.SplitHostPort(result.Host)
	if err != nil {
		// No port in original URL
		result.Host = newHost
	} else {
		// Preserve original port with new host
		result.Host = net.JoinHostPort(newHost, port)
	}
	return &result
}
