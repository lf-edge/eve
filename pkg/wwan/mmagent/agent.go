// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/wwan/mmagent/mmdbus"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/tatsushid/go-fastping"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	agentName              = "wwan"
	errorTime              = 3 * time.Minute
	warningTime            = 40 * time.Second
	wdTouchPeriod          = 25 * time.Second
	mmStartTimeout         = time.Minute
	metricsPublishPeriod   = time.Minute
	retryPeriod            = 1 * time.Minute
	suspendReconcilePeriod = retryPeriod >> 1
	connProbePeriod        = 5 * time.Minute
	defRouteBaseMetric     = 65000
	icmpProbeMaxRTT        = time.Second
	icmpProbeMaxAttempts   = 3
	proxyProbeTimeout      = 5 * time.Second
	dnsProbeTimeout        = 5 * time.Second
	scanProvidersPeriod    = time.Hour
)

const (
	// WwanResolvConfDir : directory where wwan microservice stores resolv.conf
	// files separately for every interface (named <interface>.dhcp).
	// TODO: this is already defined in pillar/devicenetwork, but importing that package
	//       brings in tons of unnecessary dependencies. It would be better to move this
	//       constant to pillar/types or to some other small common package.
	//       Alternatively, CheckAndGetNetworkProxy (which has those many deps) could be
	//       moved out from devicenetwork to some other place.
	WwanResolvConfDir = "/run/wwan/resolv.conf"
)

var (
	_, ipv4Any, _    = net.ParseCIDR("0.0.0.0/0")
	_, ipv6Any, _    = net.ParseCIDR("::/0")
	emptyPhysAddrs   = types.WwanPhysAddrs{}
	defaultProbeAddr = net.ParseIP("8.8.8.8")
	emptyIPSettings  = types.WwanIPSettings{}
)

// Version is set from Makefile
var Version = "No version specified"

// MMAgent is an EVE microservice controlling ModemManager (https://modemmanager.org/).
type MMAgent struct {
	agentbase.AgentBase
	logger     *logrus.Logger
	log        *base.LogObject
	ps         *pubsub.PubSub
	versionPtr *bool

	// publications
	pubWwanStatus        pubsub.Publication
	pubWwanMetrics       pubsub.Publication
	pubWwanLocationInfo  pubsub.Publication
	pubCipherBlockStatus pubsub.Publication
	pubCipherMetrics     pubsub.Publication
	cipherMetrics        *cipher.AgentMetrics

	// subscriptions
	subGlobalConfig   pubsub.Subscription
	subWwanConfig     pubsub.Subscription
	subControllerCert pubsub.Subscription
	subEdgeNodeCert   pubsub.Subscription

	// client for communication with MM
	mmClient *mmdbus.Client

	// global config properties
	gcInitialized     bool
	globalConfig      types.ConfigItemValueMap
	dpcKey            string
	dpcTimestamp      time.Time
	rsConfigTimestamp time.Time
	radioSilence      bool
	locPublishPeriod  time.Duration
	locTrackingModem  string // selected modem for location tracking (DBus path)
	scanProviders     bool

	// config, state data and metrics collected for every cellular modem
	modemInfo     map[string]*ModemInfo // key: DBus path
	missingModems []types.WwanNetworkConfig

	// True when modem metrics have been updated and should be published
	metricsUpdated bool
}

// ModemInfo : collection of config, state data and metrics stored by the agent
// inside MMAgent.modemInfo for every modem detected by ModemManager.
// Note that modems which have config but are not physically present are recorded
// in MMAgent.missingModems.
type ModemInfo struct {
	// State data and metrics received from the ModemManager D-Bus client.
	mmdbus.Modem
	// Unmanaged modem has empty Config (LogicalLabel is empty string).
	config types.WwanNetworkConfig
	// Previous config - used only within the applyWwanConfig function.
	prevConfig types.WwanNetworkConfig
	// IP settings applied for the wwan* interface in the Linux network stack.
	appliedIPSettings types.WwanIPSettings
	// Decrypted username and password (from Config.AccessPoint.EncryptedCredentials).
	decryptedUsername string
	decryptedPassword string
	// Latest errors encountered while managing this modem.
	probeError       error
	connectError     error
	decryptError     error
	locTrackingError error
	// Modem changes/operations take time to apply.
	// After changing any modem settings, we suspend reconcileModem from touching the modem
	// for a short period of time (half the retryPeriod).
	suspendedReconcileUntil time.Time
}

// IsManaged : modem configured by EVE controller is denoted as "managed".
func (m *ModemInfo) IsManaged() bool {
	return m.config.LogicalLabel != ""
}

// AddAgentSpecificCLIFlags defines the version argument.
func (a *MMAgent) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	a.versionPtr = flagSet.Bool("v", false, "Version")
}

// Init performs initialization of the agent. Should be called before Run.
func (a *MMAgent) Init() (err error) {
	a.logger, a.log = agentlog.Init(agentName)
	a.ps = pubsub.New(
		&socketdriver.SocketDriver{Logger: a.logger, Log: a.log},
		a.logger, a.log)
	arguments := os.Args[1:]
	agentbase.Init(a, a.logger, a.log, agentName,
		agentbase.WithArguments(arguments), agentbase.WithPidFile(),
		agentbase.WithWatchdog(a.ps, warningTime, errorTime))
	if *a.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return nil
	}
	a.modemInfo = make(map[string]*ModemInfo)
	if err = a.ensureDir(WwanResolvConfDir); err != nil {
		return err
	}
	if err = a.initPublications(); err != nil {
		return err
	}
	if err = a.initSubscriptions(); err != nil {
		return err
	}
	a.cipherMetrics = cipher.NewAgentMetrics(agentName)
	a.mmClient, err = mmdbus.NewClient(a.log)
	if err != nil {
		return err
	}
	return nil
}

func (a *MMAgent) initPublications() (err error) {
	a.pubWwanStatus, err = a.ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.WwanStatus{},
		})
	if err != nil {
		return err
	}
	a.pubWwanMetrics, err = a.ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.WwanMetrics{},
		})
	if err != nil {
		return err
	}
	a.pubWwanLocationInfo, err = a.ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.WwanLocationInfo{},
		})
	if err != nil {
		return err
	}
	a.pubCipherBlockStatus, err = a.ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.CipherBlockStatus{},
		})
	if err != nil {
		return err
	}
	a.pubCipherMetrics, err = a.ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.CipherMetrics{},
	})
	if err != nil {
		return err
	}
	return nil
}

func (a *MMAgent) initSubscriptions() (err error) {
	a.subGlobalConfig, err = a.ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		CreateHandler: a.handleGlobalConfigCreate,
		ModifyHandler: a.handleGlobalConfigModify,
		DeleteHandler: a.handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}
	a.subWwanConfig, err = a.ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		TopicImpl:     types.WwanConfig{},
		Activate:      false,
		CreateHandler: a.handleWwanConfigCreate,
		ModifyHandler: a.handleWwanConfigModify,
		DeleteHandler: a.handleWwanConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}
	// Look for controller certs which will be used for decryption.
	a.subControllerCert, err = a.ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.ControllerCert{},
		Persistent:  true,
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		return err
	}
	// Look for edge node certs which will be used for decryption
	a.subEdgeNodeCert, err = a.ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeCert{},
		Persistent:  true,
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		return err
	}
	return nil
}

func (a *MMAgent) ensureDir(dirname string) error {
	err := os.MkdirAll(dirname, 0755)
	if err != nil {
		err = fmt.Errorf("failed to create directory %s: %w", dirname, err)
		a.log.Error(err)
		return err
	}
	return nil
}

// Run runs the agent.
// It is a blocking call and returns only when a critical run-time error is detected
// or the context is canceled.
func (a *MMAgent) Run(ctx context.Context) error {
	a.log.Noticef("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(wdTouchPeriod)
	a.ps.StillRunning(agentName, warningTime, errorTime)

	// Wait for ModemManager.
	deadline := time.Now().Add(mmStartTimeout)
	mmVersion, err := a.mmClient.GetMMVersion()
	for err != nil {
		if time.Now().After(deadline) {
			return fmt.Errorf("ModemManager is not available even %s after start: %v",
				mmStartTimeout, err)
		}
		time.Sleep(time.Second)
		a.ps.StillRunning(agentName, warningTime, errorTime)
		mmVersion, err = a.mmClient.GetMMVersion()
	}
	a.log.Noticef("ModemManager version: %s", mmVersion)

	// Wait for initial GlobalConfig.
	if err := a.subGlobalConfig.Activate(); err != nil {
		return err
	}
	for !a.gcInitialized {
		a.log.Noticef("Waiting for GCInitialized")
		select {
		case change := <-a.subGlobalConfig.MsgChan():
			a.subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		a.ps.StillRunning(agentName, warningTime, errorTime)
	}
	a.log.Noticef("Processed GlobalConfig")

	// Periodically reconnect modems where the last attempt to establish
	// connection failed.
	retryTicker := time.NewTicker(retryPeriod)

	// Periodically recheck modem connectivity by talking to a remote endpoint
	// using a minimum traffic possible.
	probeTicker := time.NewTicker(connProbePeriod)

	// If enabled, periodically scan visible providers.
	scanTicker := time.NewTicker(scanProvidersPeriod)

	// Publish metrics for zedagent
	maxInterval := float64(metricsPublishPeriod)
	minInterval := maxInterval * 0.3
	metricPollInterval := time.Duration(minInterval)
	publishMetricsTimer := flextimer.NewRangeTicker(
		time.Duration(minInterval), time.Duration(maxInterval))

	// Start monitoring state of all detected cellular modems.
	modems, modemNotifications := a.mmClient.RunModemMonitoring(metricPollInterval)
	for _, modem := range modems {
		a.log.Noticef("Modem detected at startup, path: %s, physical addresses: %+v",
			modem.Path, modem.Status.PhysAddrs)
		modemInfo := &ModemInfo{Modem: modem}
		a.modemInfo[modem.Path] = modemInfo
		// Unmanaged modems have radio function disabled.
		modemInfo.connectError = a.mmClient.DisableRadio(modem.Path)
	}
	a.publishWwanStatus()

	// Start receiving configuration.
	if err := a.subWwanConfig.Activate(); err != nil {
		return err
	}
	if err := a.subControllerCert.Activate(); err != nil {
		return err
	}
	if err := a.subEdgeNodeCert.Activate(); err != nil {
		return err
	}

	for {
		select {
		case change := <-a.subGlobalConfig.MsgChan():
			a.subGlobalConfig.ProcessChange(change)

		case change := <-a.subWwanConfig.MsgChan():
			a.subWwanConfig.ProcessChange(change)

		case change := <-a.subControllerCert.MsgChan():
			a.subControllerCert.ProcessChange(change)

		case change := <-a.subEdgeNodeCert.MsgChan():
			a.subEdgeNodeCert.ProcessChange(change)

		case notif := <-modemNotifications:
			a.processModemNotif(notif)

		case <-retryTicker.C:
			var statusChanged bool
			for _, modem := range a.modemInfo {
				statusChanged = a.reconcileModem(modem, false) || statusChanged
			}
			if statusChanged {
				a.publishWwanStatus()
			}

		case <-probeTicker.C:
			a.probeConnectivity()

		case <-scanTicker.C:
			if !a.scanProviders || a.radioSilence {
				break
			}
			for _, modem := range a.modemInfo {
				if !modem.IsManaged() {
					continue
				}
				a.scanVisibleProviders(modem)
			}
			a.publishWwanStatus()

		case <-publishMetricsTimer.C:
			a.publishMetrics()

		case <-stillRunning.C:
			if time.Since(a.mmClient.LastSeenMM()) >= wdTouchPeriod {
				if _, err := a.mmClient.GetMMVersion(); err != nil {
					a.log.Warnf("Failed to get MM version (process crashed?): %v", err)
				}
			}
		}

		// Here we implement watchdog detection for both this agent and the ModemManager.
		if time.Since(a.mmClient.LastSeenMM()) < wdTouchPeriod {
			a.ps.StillRunning(agentName, warningTime, errorTime)
		}
	}
}

func (a *MMAgent) ignoreNonGlobalKey(key string) bool {
	if key != "global" {
		a.log.Warnf("Ignoring pubsub message key=%s", key)
		return true
	}
	return false
}

func (a *MMAgent) handleGlobalConfigCreate(_ interface{}, key string, arg interface{}) {
	if a.ignoreNonGlobalKey(key) {
		return
	}
	a.applyGlobalConfig(arg.(types.ConfigItemValueMap))
}

func (a *MMAgent) handleGlobalConfigModify(_ interface{}, key string, arg, _ interface{}) {
	if a.ignoreNonGlobalKey(key) {
		return
	}
	a.applyGlobalConfig(arg.(types.ConfigItemValueMap))
}

func (a *MMAgent) handleGlobalConfigDelete(_ interface{}, key string, arg interface{}) {
	if a.ignoreNonGlobalKey(key) {
		return
	}
	a.applyGlobalConfig(*types.DefaultConfigItemValueMap())
}

func (a *MMAgent) handleWwanConfigCreate(_ interface{}, key string, arg interface{}) {
	if a.ignoreNonGlobalKey(key) {
		return
	}
	a.applyWwanConfig(arg.(types.WwanConfig))
}

func (a *MMAgent) handleWwanConfigModify(_ interface{}, key string, arg, _ interface{}) {
	if a.ignoreNonGlobalKey(key) {
		return
	}
	a.applyWwanConfig(arg.(types.WwanConfig))
}

func (a *MMAgent) handleWwanConfigDelete(_ interface{}, key string, _ interface{}) {
	if a.ignoreNonGlobalKey(key) {
		return
	}
	a.applyWwanConfig(types.WwanConfig{})
}

func (a *MMAgent) applyGlobalConfig(config types.ConfigItemValueMap) {
	a.globalConfig = config
	prevLogLevel := a.logger.GetLevel()
	agentlog.HandleGlobalConfig(a.log, a.subGlobalConfig, agentName,
		a.CLIParams().DebugOverride, a.logger)
	if a.logger.GetLevel() != prevLogLevel || !a.gcInitialized {
		err := a.mmClient.SetMMLogLevel(a.logger.GetLevel())
		if err == nil {
			a.log.Noticef("Changed ModemManager log level to %v", a.logger.GetLevel())
		} else {
			a.log.Warnf("Failed to set ModemManager log level to %v: %v",
				a.logger.GetLevel(), err)
		}
	}
	// Publish location info 2x more often (at most) than zedagent publishes
	// to applications and controller.
	locPublishCloudPeriod := time.Second *
		time.Duration(a.globalConfig.GlobalValueInt(types.LocationCloudInterval))
	locPublishAppPeriod := time.Second *
		time.Duration(a.globalConfig.GlobalValueInt(types.LocationAppInterval))
	publishInterval := locPublishAppPeriod
	if locPublishCloudPeriod < publishInterval {
		// This is quite unlikely config.
		publishInterval = locPublishCloudPeriod
	}
	publishInterval = publishInterval >> 1
	if a.locPublishPeriod != publishInterval {
		a.locPublishPeriod = publishInterval
		if a.locTrackingModem != "" && !a.radioSilence {
			modem := a.modemInfo[a.locTrackingModem]
			err := a.mmClient.StopLocationTracking(modem.Path)
			if err == nil {
				err = a.mmClient.StartLocationTracking(
					modem.Path, publishInterval)
			}
			if err == nil {
				a.log.Noticef(
					"Updated location tracking publish interval for modem %s (%s) to %s",
					modem.config.LogicalLabel, modem.Path, a.locPublishPeriod)
			} else {
				modem.locTrackingError = fmt.Errorf("failed to restart location tracking "+
					"to update publish interval for modem %s (%s): %v",
					modem.config.LogicalLabel, modem.Path, err)
				a.log.Error(modem.locTrackingError.Error())
			}
		}
	}
	scanProviders := a.globalConfig.GlobalValueBool(types.WwanQueryVisibleProviders)
	if a.scanProviders != scanProviders {
		a.scanProviders = scanProviders
		if a.scanProviders && !a.radioSilence {
			for _, modem := range a.modemInfo {
				if !modem.IsManaged() {
					continue
				}
				a.scanVisibleProviders(modem)
			}
			a.publishWwanStatus()
		}
	}
	a.gcInitialized = true
}

func (a *MMAgent) applyWwanConfig(config types.WwanConfig) {
	a.log.Noticef("Applying wwan config, DPC: %s/%v, RS config timestamp: %v",
		config.DPCKey, config.DPCTimestamp, config.RSConfigTimestamp)
	resumeMonitoring := a.mmClient.PauseModemMonitoring()
	for _, modem := range a.modemInfo {
		modem.prevConfig = modem.config
		modem.config = types.WwanNetworkConfig{}
	}
	a.dpcKey = config.DPCKey
	a.dpcTimestamp = config.DPCTimestamp
	a.rsConfigTimestamp = config.RSConfigTimestamp
	a.radioSilence = config.RadioSilence
	a.missingModems = nil
	// Associate config with ModemInfo.
	for _, modemConfig := range config.Networks {
		var foundModem bool
		for _, modem := range a.modemInfo {
			if a.configMatchesModem(modemConfig, modem) {
				modem.config = modemConfig
				foundModem = true
				break
			}
		}
		if !foundModem {
			a.missingModems = append(a.missingModems, modemConfig)
		}
	}
	// Determine which modem to use for location tracking if enabled.
	if a.locTrackingModem != "" &&
		!a.modemInfo[a.locTrackingModem].config.LocationTracking {
		// Modem used for location tracking should no longer be used for that purpose.
		a.locTrackingModem = ""
	}
	if a.locTrackingModem == "" {
		for _, modem := range a.modemInfo {
			if modem.config.LocationTracking {
				a.locTrackingModem = modem.Path
				break
			}
		}
	}
	// Apply the new config
	var rescanProviders []string
	for _, modem := range a.modemInfo {
		var forceReconnect bool
		// Logical label can appear of disappear but cannot change - it is fixed
		// in the device model.
		if modem.prevConfig.LogicalLabel != "" && modem.config.LogicalLabel == "" {
			a.log.Noticef("Modem at path %s is no longer managed "+
				"(previously had logical label %s)", modem.Path,
				modem.prevConfig.LogicalLabel)
		}
		if modem.prevConfig.LogicalLabel == "" && modem.config.LogicalLabel != "" {
			a.log.Noticef("Associated modem at path %s with logical label %s",
				modem.Path, modem.config.LogicalLabel)
			// Previously unmanaged modem now has configuration.
			rescanProviders = append(rescanProviders, modem.Path)
		}
		if !modem.config.AccessPoint.Equal(modem.prevConfig.AccessPoint) {
			modem.decryptedUsername, modem.decryptedPassword, modem.decryptError =
				a.decryptAPCredentials(&modem.config.AccessPoint)
			if modem.decryptError != nil {
				a.log.Errorf("Failed to decrypt username/password for modem %s (%s): %v",
					modem.config.LogicalLabel, modem.Path, modem.decryptError)
			}
			forceReconnect = true
		}
		a.reconcileModem(modem, forceReconnect)
	}
	// Resume monitoring of modems and record all state changes that happened during
	// the execution of this function (while monitoring was paused).
	modems := resumeMonitoring()
	existingModems := make(map[string]struct{})
	for _, modem := range modems {
		existingModems[modem.Path] = struct{}{}
		if _, haveInfo := a.modemInfo[modem.Path]; !haveInfo {
			// This is very unlikely scenario.
			a.log.Warnf(
				"New modem %s appeared during the execution of applyWwanConfig: %+v",
				modem.Path, modem.Status.PhysAddrs)
			modemInfo := &ModemInfo{Modem: modem}
			a.modemInfo[modem.Path] = modemInfo
			a.findConfigForNewModem(modemInfo)
			// Modem will be reconciled from retryTicker.
		} else {
			var providers []types.WwanProvider
			if a.scanProviders && a.modemInfo[modem.Path].IsManaged() {
				// Preserve output from the last scan of visible providers.
				providers = a.modemInfo[modem.Path].Status.VisibleProviders
			}
			modem.Status.VisibleProviders = providers
			a.modemInfo[modem.Path].Modem = modem
		}
	}
	for _, modem := range a.modemInfo {
		if _, exists := existingModems[modem.Path]; !exists {
			// This is very unlikely scenario.
			a.log.Warnf("Modem %s disappeared during the execution of applyWwanConfig",
				modem.Path)
			a.handleRemovedModem(modem)
		}
	}
	a.publishWwanStatus()
	if len(rescanProviders) > 0 && a.scanProviders && !a.radioSilence {
		a.log.Noticef("Re-scanning visible providers for modems: %v", rescanProviders)
		for _, modemPath := range rescanProviders {
			modem := a.modemInfo[modemPath]
			if modem == nil || !modem.IsManaged() {
				continue
			}
			a.scanVisibleProviders(modem)
		}
		a.publishWwanStatus()
	}
	a.metricsUpdated = true
}

func (a *MMAgent) processModemNotif(notif mmdbus.Notification) {
	switch notif.Event {
	case mmdbus.EventUndefined:
		a.log.Warnf("Undefined notification received from MM Client")

	case mmdbus.EventAddedModem:
		a.log.Noticef("New modem was added at path %s, physical addresses: %+v",
			notif.Modem.Path, notif.Modem.Status.PhysAddrs)
		_, haveInfo := a.modemInfo[notif.Modem.Path]
		if haveInfo {
			// Should be unreachable
			a.log.Warnf("Received notification about new modem %s which is already known",
				notif.Modem.Path)
			return
		}
		modem := &ModemInfo{Modem: notif.Modem}
		a.modemInfo[notif.Modem.Path] = modem
		a.findConfigForNewModem(modem)
		a.reconcileModem(modem, false)
		if a.scanProviders && modem.IsManaged() && !a.radioSilence {
			a.scanVisibleProviders(modem)
		}
		a.publishWwanStatus()

	case mmdbus.EventUpdatedModemStatus:
		modem, haveInfo := a.modemInfo[notif.Modem.Path]
		if !haveInfo {
			// Should be unreachable
			a.log.Warnf("Received status change for an unknown modem %s",
				notif.Modem.Path)
			return
		}
		var providers []types.WwanProvider
		if a.scanProviders && modem.IsManaged() {
			// Preserve output from the last scan of visible providers.
			providers = modem.Status.VisibleProviders
		}
		a.log.Functionf("Modem status update: %+v", notif.Modem)
		modem.Status = notif.Modem.Status
		modem.Status.VisibleProviders = providers
		// Immediately publish status change, do not delay it with reconciliation.
		a.publishWwanStatus()
		statusChanged := a.reconcileModem(modem, false)
		if statusChanged {
			a.publishWwanStatus()
		}

	case mmdbus.EventRemovedModem:
		a.log.Noticef("Modem at path %s was removed", notif.Modem.Path)
		modem, haveInfo := a.modemInfo[notif.Modem.Path]
		if !haveInfo {
			// Should be unreachable
			a.log.Warnf("Received notification about removal of an unknown modem %s",
				notif.Modem.Path)
			return
		}
		a.handleRemovedModem(modem)
		a.publishWwanStatus()

	case mmdbus.EventUpdatedModemMetrics:
		modem, haveInfo := a.modemInfo[notif.Modem.Path]
		if !haveInfo {
			// Should be unreachable
			a.log.Warnf("Received metrics for unknown modem %s", notif.Modem.Path)
			return
		}
		modem.Metrics = notif.Modem.Metrics
		a.metricsUpdated = true

	case mmdbus.EventUpdatedModemLocation:
		modem, haveInfo := a.modemInfo[notif.Modem.Path]
		if !haveInfo {
			// Should be unreachable
			a.log.Warnf("Received location info for unknown modem %s", notif.Modem.Path)
			return
		}
		location := notif.Modem.Location
		if location.Latitude == mmdbus.UnavailLocAttribute ||
			location.Longitude == mmdbus.UnavailLocAttribute {
			// Do not publish incomplete location information.
			return
		}
		modem.Location = location
		location.LogicalLabel = modem.config.LogicalLabel
		err := a.pubWwanLocationInfo.Publish("global", location)
		if err != nil {
			a.log.Errorf("Failed to publish location info: %v", err)
		}
	}
}

// Check if we already have config for this modem inside the missingModems slice.
func (a *MMAgent) findConfigForNewModem(modem *ModemInfo) {
	for i, config := range a.missingModems {
		if !a.configMatchesModem(config, modem) {
			continue
		}
		modem.config = config
		a.log.Noticef("Associated modem at path %s with logical label %s",
			modem.Path, modem.config.LogicalLabel)
		modem.decryptedUsername, modem.decryptedPassword, modem.decryptError =
			a.decryptAPCredentials(&config.AccessPoint)
		if modem.decryptError != nil {
			a.log.Errorf("Failed to decrypt username/password for modem %s (%s): %v",
				modem.config.LogicalLabel, modem.Path, modem.decryptError)
		}
		// Remove entry from missingModems.
		a.missingModems[i] = a.missingModems[len(a.missingModems)-1]
		a.missingModems = a.missingModems[:len(a.missingModems)-1]
		// Check if we should start location tracking on this modem.
		if a.locTrackingModem == "" && modem.config.LocationTracking {
			a.locTrackingModem = modem.Path
		}
		break
	}
}

func (a *MMAgent) handleRemovedModem(modem *ModemInfo) {
	delete(a.modemInfo, modem.Path)
	if modem.IsManaged() {
		a.missingModems = append(a.missingModems, modem.config)
	}
	if a.locTrackingModem == modem.Path {
		// This removed modem was used for location tracking.
		// Check if there is another modem with location tracking enabled.
		a.locTrackingModem = ""
		for _, modem2 := range a.modemInfo {
			if modem2.config.LocationTracking {
				a.locTrackingModem = modem2.Path
				a.reconcileModem(modem2, false)
				break
			}
		}
	}
}

// Reconcile the modem current state with the intended state (i.e. config).
// Possible actions that may be performed are:
//   - (dis)connect modem
//   - start/stop location tracking
//   - enable/disable radio
func (a *MMAgent) reconcileModem(
	modem *ModemInfo, forceReconnect bool) (statusChanged bool) {
	if !forceReconnect && modem.suspendedReconcileUntil.After(time.Now()) {
		if modem.IsManaged() {
			a.log.Noticef("Skipping reconcileModem for modem %s (%s) - suspended",
				modem.config.LogicalLabel, modem.Path)
		} else {
			a.log.Noticef("Skipping reconcileModem for unmanaged modem %+v (%s) - suspended",
				modem.Status.PhysAddrs, modem.Path)
		}
		return false
	}
	// Sync connection state.
	var connErr error
	var connErrChanged bool
	if !modem.IsManaged() || a.radioSilence {
		opReason := "modem is not managed"
		if a.radioSilence {
			opReason = "radio silence"
		}
		// Modem should be switched off.
		if modem.Status.Module.OpMode == types.WwanOpModeConnected {
			connErr = a.disconnectModem(modem)
			connErrChanged = true
			a.logReconcileOp(modem, "close connection", opReason, connErr)
		}
		if connErr == nil && modem.Status.Module.OpMode != types.WwanOpModeRadioOff {
			// Note that we disable radio function of all unmanaged modems.
			connErr = a.mmClient.DisableRadio(modem.Path)
			connErrChanged = true
			a.logReconcileOp(modem, "disable radio", opReason, connErr)
		}
	} else {
		// Modem should be connected.
		isConnected := modem.Status.Module.OpMode == types.WwanOpModeConnected
		if !isConnected || forceReconnect {
			opReason := "modem not connected"
			if forceReconnect {
				opReason = "forcing reconnection"
			}
			if modem.Status.Module.OpMode == types.WwanOpModeRadioOff {
				connErr = a.mmClient.EnableRadio(modem.Path)
				a.logReconcileOp(modem, "enable radio", opReason, connErr)
			}
			if connErr == nil {
				if isConnected {
					connErr = a.disconnectModem(modem)
					a.logReconcileOp(modem, "close (obsolete) connection",
						opReason, connErr)
				} else {
					// Make sure that the wwan interface is in the clean state
					// before connecting.
					connErr = a.removeIPSettings(modem)
					a.logReconcileOp(modem, "remove (obsolete) IP settings",
						opReason, connErr)
				}
			}
			if connErr == nil &&
				// Do not try to connect if we failed to decrypt credentials.
				modem.decryptError == nil {
				connErr = a.connectModem(modem)
				a.logReconcileOp(modem, "establish connection", opReason, connErr)
			}
			if connErr == nil {
				// Clear probe error after successfully reconnecting.
				modem.probeError = nil
			}
			connErrChanged = true
		} else {
			// Connection is already working. Clear previous error if there is any.
			connErrChanged = modem.connectError != nil
		}
	}
	if connErr == nil &&
		!modem.appliedIPSettings.Equal(modem.Status.IPSettings) {
		// IP settings between modem and Linux network stack are out-of-sync.
		// This could happen if modem re-connects behind the scenes or maybe if network
		// changes IP settings (never happens through this agent's own action).
		opReason := "IP settings are out-of-sync"
		connErr = a.removeIPSettings(modem)
		a.logReconcileOp(modem, "remove (obsolete) IP settings", opReason, connErr)
		if connErr == nil && !modem.Status.IPSettings.Equal(emptyIPSettings) {
			connErr = a.applyIPSettings(modem, modem.Status.IPSettings)
			a.logReconcileOp(modem, "apply IP settings", opReason, connErr)
		}
		connErrChanged = true
	}
	if connErrChanged {
		modem.connectError = connErr
		if connErr != nil {
			a.log.Warnf(connErr.Error())
		}
	}
	// Sync location tracking state.
	var locErr error
	var locErrChanged bool
	if modem.Status.LocationTracking {
		if a.locTrackingModem != modem.Path {
			// This modem should have location tracking disabled.
			locErr = a.mmClient.StopLocationTracking(modem.Path)
			locErrChanged = true
			a.logReconcileOp(modem, "stop location tracking", "", locErr)
		}
	} else {
		if a.locTrackingModem == modem.Path && !a.radioSilence {
			// This modem should have location tracking enabled.
			locErr = a.mmClient.StartLocationTracking(
				modem.Path, a.locPublishPeriod)
			locErrChanged = true
			a.logReconcileOp(modem, "start location tracking", "", locErr)
		}
	}
	if locErrChanged {
		modem.locTrackingError = locErr
		if locErr != nil {
			a.log.Warnf(locErr.Error())
		}
	}
	statusChanged = connErrChanged || locErrChanged
	if statusChanged {
		a.suspendReconcile(modem)
	}
	return statusChanged
}

// After modifying modem settings, give changes some time to apply before trying
// to reconcile again.
func (a *MMAgent) suspendReconcile(modem *ModemInfo) {
	modem.suspendedReconcileUntil = time.Now().Add(suspendReconcilePeriod)
	if modem.IsManaged() {
		a.log.Noticef("Suspended reconciliation for modem %s (%s) until %v",
			modem.config.LogicalLabel, modem.Path, modem.suspendedReconcileUntil)
	} else {
		a.log.Noticef("Suspended reconciliation for unmanaged modem %+v (%s) until %v",
			modem.Status.PhysAddrs, modem.Path, modem.suspendedReconcileUntil)
	}
}

func (a *MMAgent) logReconcileOp(modem *ModemInfo, operation, reason string, retval error) {
	var modemDescr string
	if modem.IsManaged() {
		modemDescr = fmt.Sprintf("modem %s (%s)", modem.config.LogicalLabel, modem.Path)
	} else {
		modemDescr = fmt.Sprintf("unmanaged modem %+v", modem.Status.PhysAddrs)
	}
	var reasonDescr string
	if reason != "" {
		reasonDescr = fmt.Sprintf(" (run due to: %s)", reason)
	}
	if retval == nil {
		a.log.Noticef("Succeeded to %s for %s%s", operation, modemDescr, reasonDescr)
	} else {
		a.log.Errorf("Failed to %s for %s%s: %v", operation, modemDescr,
			reasonDescr, retval)
	}
}

func (a *MMAgent) scanVisibleProviders(modem *ModemInfo) {
	var resumeRecAfter time.Duration
	suspRecUntil := modem.suspendedReconcileUntil
	if suspRecUntil.After(time.Now()) {
		// Pause the countdown of suspended reconciliation while we wait
		// for visible providers.
		// Otherwise, scan will eat up all the duration for suspension, and therefore
		// it will lose its meaning (to wait for the last reconciliation changes to take
		// effect and to receive the corresponding status update)
		resumeRecAfter = time.Until(suspRecUntil)
	}
	providers, err := a.mmClient.ScanVisibleProviders(modem.Path)
	if err == nil {
		modem.Status.VisibleProviders = providers
	} else {
		modem.Status.VisibleProviders = nil
		a.log.Errorf("Failed to scan visible providers for modem %s (%s): %v",
			modem.config.LogicalLabel, modem.Path, err)
	}
	if resumeRecAfter > 0 {
		modem.suspendedReconcileUntil = time.Now().Add(resumeRecAfter)
	}
}

// Check if connected modems are actually working and traffic is getting through.
func (a *MMAgent) probeConnectivity() {
	if a.radioSilence {
		return
	}
	var statusChanged bool
	for _, modem := range a.modemInfo {
		if !modem.IsManaged() {
			continue
		}
		prevError := modem.probeError
		if modem.Status.Module.OpMode != types.WwanOpModeConnected {
			modem.probeError = fmt.Errorf("modem is not connected")
			if prevError == nil || prevError.Error() != modem.probeError.Error() {
				statusChanged = true
			}
			continue
		}
		modem.probeError = a.probeModemConnectivity(modem)
		if modem.probeError != nil {
			a.log.Warnf("Connectivity probing failed for modem %s: %v",
				modem.config.LogicalLabel, modem.probeError)
			// Try to fix connectivity by recreating connection.
			err := a.disconnectModem(modem)
			if err == nil {
				err = a.connectModem(modem)
			}
			if err == nil {
				a.log.Noticef("Successfully fixed connectivity for modem %s",
					modem.config.LogicalLabel)
			} else {
				a.log.Errorf("Tried to fix connectivity for modem %s but failed: %v",
					modem.config.LogicalLabel, err)
			}
			if err == nil {
				// Retry after reconnecting.
				modem.probeError = a.probeModemConnectivity(modem)
			} else {
				err = fmt.Errorf(
					"attempt to fix connection triggered by probing failed: %w", err)
				a.log.Warnf(err.Error())
			}
			a.suspendReconcile(modem)
			modem.connectError = err
			statusChanged = true
		} else if prevError != nil {
			// Probe succeeded but previously there was an error published.
			statusChanged = true
		}
	}
	if statusChanged {
		a.publishWwanStatus()
	}
}

// probeModemConnectivity returns non-nil error when probe fails to reach remote
// endpoint(s) using the wwan interface.
func (a *MMAgent) probeModemConnectivity(modem *ModemInfo) error {
	probeConfig := modem.config.Probe
	if probeConfig.Disable {
		return nil
	}
	modemAddr := modem.Status.IPSettings.Address
	if modemAddr == nil || len(modemAddr.IP) == 0 {
		return fmt.Errorf("modem is without IP address")
	}
	startTime := time.Now()
	a.log.Noticef("Started connectivity probing for modem %s", modem.config.LogicalLabel)
	defer func() {
		a.log.Noticef("Finished connectivity probing for modem %s, took: %v",
			modem.config.LogicalLabel, time.Since(startTime))
	}()
	modemIP := modemAddr.IP
	if probeConfig.Address != "" {
		// User-configured ICMP probe address.
		remoteIP := net.ParseIP(probeConfig.Address)
		if remoteIP == nil {
			return fmt.Errorf("failed to parse probe IP address %s", probeConfig.Address)
		}
		return a.runICMPProbe(modemIP, remoteIP)
	}
	// Default probing behaviour (probe address not configured by user).
	// First try endpoints from inside the LTE network:
	//  - TCP handshake with an IP-addressed proxy
	//  - DNS request to a DNS server provided by the LTE network
	// As a last resort, try to ping Google DNS (can be blocked by firewall).
	var allErrors []string
	proxyDialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: modemIP},
		Timeout:   proxyProbeTimeout,
	}
	for _, proxy := range modem.config.Proxies {
		if proxyIP := net.ParseIP(proxy.Server); proxyIP == nil {
			// Skip proxies referenced by hostname.
			continue
		}
		address := net.JoinHostPort(proxy.Server, strconv.Itoa(int(proxy.Port)))
		conn, err := proxyDialer.Dial("tcp", address)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		allErrors = append(allErrors, err.Error())
	}
	// Try DNS query (for the root domain to get only small-sized response).
	dnsDialer := net.Dialer{
		LocalAddr: &net.UDPAddr{IP: modemIP},
		Timeout:   dnsProbeTimeout,
	}
	dnsClient := dns.Client{
		Dialer:  &dnsDialer,
		Timeout: dnsProbeTimeout,
	}
	for _, dnsSrv := range modem.Status.IPSettings.DNSServers {
		msg := dns.Msg{}
		msg.SetQuestion(".", dns.TypeA)
		dnsSrvAddr := net.JoinHostPort(dnsSrv.String(), "53")
		_, _, err := dnsClient.Exchange(&msg, dnsSrvAddr)
		if err == nil {
			return nil
		}
		allErrors = append(allErrors, err.Error())
	}
	// Try to ping Google DNS.
	// This is a last-resort probing option.
	// In a private LTE network ICMP requests headed towards public DNS servers
	// may be blocked by the firewall and thus produce probing false negatives.
	err := a.runICMPProbe(modemIP, defaultProbeAddr)
	if err == nil {
		return nil
	}
	allErrors = append(allErrors, err.Error())
	return errors.New(strings.Join(allErrors, "; "))
}

func (a *MMAgent) runICMPProbe(modemIP, remoteIP net.IP) error {
	var dstAddr, srcAddr net.IPAddr
	srcAddr.IP = modemIP
	dstAddr.IP = remoteIP
	pinger := fastping.NewPinger()
	pinger.Debug = true
	pinger.MaxRTT = icmpProbeMaxRTT
	pinger.AddIPAddr(&dstAddr)
	_, err := pinger.Source(srcAddr.String())
	if err != nil {
		return fmt.Errorf("failed to set source IP %s for ICMP probe: %w", srcAddr.IP, err)
	}
	errChan := make(chan error, 1)
	pinger.OnRecv = func(ip *net.IPAddr, d time.Duration) {
		if ip != nil && ip.IP.Equal(dstAddr.IP) {
			select {
			case errChan <- nil:
			default:
			}
		}
	}
	var attempt int
	pinger.OnIdle = func() {
		attempt++
		if attempt == icmpProbeMaxAttempts {
			select {
			case errChan <- fmt.Errorf("no ping response received from %s", dstAddr.IP):
			default:
			}
		}
	}
	pinger.RunLoop()
	select {
	case <-pinger.Done():
		err = pinger.Err()
	case err = <-errChan:
		break
	}
	pinger.Stop()
	return err
}

// Request activation of a packet data connection and configure Linux network stack
// with the received IP settings.
func (a *MMAgent) connectModem(modem *ModemInfo) error {
	ipSettings, err := a.mmClient.Connect(modem.Path, mmdbus.ConnectionArgs{
		CellularAccessPoint: modem.config.AccessPoint,
		DecryptedUsername:   modem.decryptedUsername,
		//pragma: allowlist nextline secret
		DecryptedPassword: modem.decryptedPassword,
	})
	if err != nil {
		return err
	}
	modem.Status.IPSettings = ipSettings
	return a.applyIPSettings(modem, ipSettings)
}

func (a *MMAgent) applyIPSettings(modem *ModemInfo, ipSettings types.WwanIPSettings) error {
	modem.appliedIPSettings = ipSettings
	wwanIfaceName := modem.Status.PhysAddrs.Interface
	if ipSettings.Address == nil {
		return fmt.Errorf(
			"missing IP address to set for wwan interface %s of the modem %s",
			wwanIfaceName, modem.config.LogicalLabel)
	}
	if ipSettings.Gateway == nil {
		return fmt.Errorf(
			"missing gateway IP address to set for wwan interface %s of the modem %s",
			wwanIfaceName, modem.config.LogicalLabel)
	}
	link, err := netlink.LinkByName(wwanIfaceName)
	if err != nil {
		return fmt.Errorf(
			"failed to get handle for wwan interface %s of the modem %s: %w",
			wwanIfaceName, modem.config.LogicalLabel, err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf(
			"failed to set wwan interface %s of the modem %s UP: %w",
			wwanIfaceName, modem.config.LogicalLabel, err)
	}
	addr := &netlink.Addr{IPNet: ipSettings.Address}
	err = netlink.AddrAdd(link, addr)
	if err != nil {
		return fmt.Errorf(
			"failed to add IP address %s to wwan interface %s of the modem %s: %w",
			addr, wwanIfaceName, modem.config.LogicalLabel, err)
	}
	anyDst := ipv4Any
	if ipSettings.Gateway.To4() == nil {
		anyDst = ipv6Any
	}
	defaultRoute := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       anyDst,
		Gw:        ipSettings.Gateway,
		// With multiple modems there will be multiple default routes and each should have
		// different metric otherwise there is a conflict.
		// Note that the actual metric value does not matter all that much. EVE does not use
		// the main routing table, instead it chooses uplink interface for a particular mgmt
		// request or network instance and routes the traffic using the interface-specific
		// table where this route is copied to.
		Priority: defRouteBaseMetric + link.Attrs().Index,
		Table:    unix.RT_TABLE_MAIN,
		Scope:    netlink.SCOPE_UNIVERSE,
		Protocol: unix.RTPROT_STATIC,
		Family:   netlink.FAMILY_V4,
	}
	err = netlink.RouteAdd(defaultRoute)
	if err != nil {
		return fmt.Errorf("failed to configure default route %v for wwan interface %s "+
			"of the modem %s: %v", defaultRoute, wwanIfaceName,
			modem.config.LogicalLabel, err)
	}
	if ipSettings.MTU != 0 {
		err = netlink.LinkSetMTU(link, int(ipSettings.MTU))
		if err != nil {
			return fmt.Errorf(
				"failed to set MTU %d for wwan interface %s of the modem %s: %w",
				ipSettings.MTU, wwanIfaceName, modem.config.LogicalLabel, err)
		}
	}
	var resolvConfData bytes.Buffer
	for _, dnsServer := range ipSettings.DNSServers {
		resolvConfData.WriteString("nameserver ")
		resolvConfData.WriteString(dnsServer.String())
		resolvConfData.WriteString("\n")
	}
	resolvConfFilename := a.getResolvConfFilename(modem)
	err = fileutils.WriteRename(resolvConfFilename, resolvConfData.Bytes())
	if err != nil {
		return fmt.Errorf("failed to write resolv conf file %s for modem %s: %v",
			resolvConfFilename, modem.config.LogicalLabel, err)
	}
	return nil
}

// Terminate the modem connection and remove related IP settings from the Linux
// network stack.
func (a *MMAgent) disconnectModem(modem *ModemInfo) error {
	err := a.mmClient.Disconnect(modem.Path)
	if err != nil {
		return err
	}
	modem.Status.IPSettings = emptyIPSettings
	return a.removeIPSettings(modem)
}

func (a *MMAgent) removeIPSettings(modem *ModemInfo) error {
	modem.appliedIPSettings = emptyIPSettings
	wwanIfaceName := modem.Status.PhysAddrs.Interface
	link, err := netlink.LinkByName(wwanIfaceName)
	if err != nil {
		return fmt.Errorf(
			"failed to get handle for wwan interface %s of the modem %s: %v",
			wwanIfaceName, modem.config.LogicalLabel, err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list addresses assigned to the wwan interface %s "+
			"of the modem %s: %v", wwanIfaceName, modem.config.LogicalLabel, err)
	}
	for _, addr := range addrs {
		err = netlink.AddrDel(link, &addr)
		if err != nil {
			return fmt.Errorf(
				"failed to remove address %s from the wwan interface %s of the modem %s: %v",
				addr, wwanIfaceName, modem.config.LogicalLabel, err)
		}
		// Note that the default route should be automatically removed by the Linux kernel.
	}
	err = netlink.LinkSetDown(link)
	if err != nil {
		return fmt.Errorf(
			"failed to set wwan interface %s of the modem %s DOWN: %w",
			wwanIfaceName, modem.config.LogicalLabel, err)
	}
	resolvConfFilename := a.getResolvConfFilename(modem)
	if _, err := os.Stat(resolvConfFilename); err == nil {
		err = os.Remove(resolvConfFilename)
		if err != nil {
			return fmt.Errorf("failed to remove resolv conf file %s for modem %s: %v",
				resolvConfFilename, modem.config.LogicalLabel, err)
		}
	}
	return nil
}

func (a *MMAgent) getResolvConfFilename(modem *ModemInfo) string {
	return path.Join(WwanResolvConfDir, modem.Status.PhysAddrs.Interface+".dhcp")
}

func (a *MMAgent) decryptAPCredentials(ap *types.CellularAccessPoint) (
	username, password string, err error) {
	if !ap.EncryptedCredentials.IsCipher {
		return "", "", nil
	}
	// Regardless of how decryption will go, metrics will be updated.
	a.metricsUpdated = true
	decryptAvailable := a.subControllerCert != nil && a.subEdgeNodeCert != nil
	if !decryptAvailable {
		a.cipherMetrics.RecordFailure(a.log, types.NotReady)
		return "", "", fmt.Errorf(
			"missing certificates for decryption of cellular network credentials")
	}
	status, decBlock, err := cipher.GetCipherCredentials(
		&cipher.DecryptCipherContext{
			Log:                  a.log,
			AgentName:            agentName,
			AgentMetrics:         a.cipherMetrics,
			PubSubControllerCert: a.subControllerCert,
			PubSubEdgeNodeCert:   a.subEdgeNodeCert,
		},
		ap.EncryptedCredentials)
	if a.pubCipherBlockStatus != nil {
		err2 := a.pubCipherBlockStatus.Publish(status.Key(), status)
		if err2 != nil {
			// This does not affect the decryption procedure itself, just log error.
			a.log.Errorf("Failed to publish CipherBlockStatus: %v", err2)
		}
	}
	if err != nil {
		a.cipherMetrics.RecordFailure(a.log, types.DecryptFailed)
		return "", "", fmt.Errorf(
			"failed to decrypt cellular network credentials: %w", err)
	}
	return decBlock.CellularNetUsername, decBlock.CellularNetPassword, nil
}

func (a *MMAgent) publishWwanStatus() {
	var wwanStatus types.WwanStatus
	wwanStatus.DPCKey = a.dpcKey
	wwanStatus.DPCTimestamp = a.dpcTimestamp
	wwanStatus.RSConfigTimestamp = a.rsConfigTimestamp
	for _, modem := range a.modemInfo {
		status := modem.Status
		status.LogicalLabel = modem.config.LogicalLabel
		// Publish the most serious error.
		switch {
		case modem.decryptError != nil:
			status.ConfigError = modem.decryptError.Error()
		case modem.connectError != nil:
			status.ConfigError = modem.connectError.Error()
		case modem.locTrackingError != nil:
			status.ConfigError = modem.locTrackingError.Error()
		}
		if modem.probeError != nil {
			status.ProbeError = modem.probeError.Error()
		}
		wwanStatus.Networks = append(wwanStatus.Networks, status)
	}
	for _, missingModem := range a.missingModems {
		wwanStatus.Networks = append(wwanStatus.Networks, types.WwanNetworkStatus{
			LogicalLabel: missingModem.LogicalLabel,
			PhysAddrs:    missingModem.PhysAddrs,
			ConfigError:  "modem not found",
		})
	}
	err := a.pubWwanStatus.Publish("global", wwanStatus)
	if err != nil {
		a.log.Errorf("Failed to publish wwan status: %v", err)
	}
}

func (a *MMAgent) publishMetrics() {
	if !a.metricsUpdated {
		return
	}
	start := time.Now()
	err := a.cipherMetrics.Publish(a.log, a.pubCipherMetrics, "global")
	if err != nil {
		a.log.Error(err)
	}
	a.publishWwanMetrics()
	a.ps.CheckMaxTimeTopic(agentName, "publishMetricsTimer", start,
		warningTime, errorTime)
	a.metricsUpdated = false
}

func (a *MMAgent) publishWwanMetrics() {
	var wwanMetrics types.WwanMetrics
	for _, modem := range a.modemInfo {
		metrics := modem.Metrics
		metrics.LogicalLabel = modem.config.LogicalLabel
		wwanMetrics.Networks = append(wwanMetrics.Networks, metrics)
	}
	err := a.pubWwanMetrics.Publish("global", wwanMetrics)
	if err != nil {
		a.log.Errorf("Failed to publish wwan metrics: %v", err)
	}
}

func (a *MMAgent) configMatchesModem(
	config types.WwanNetworkConfig, modem *ModemInfo) bool {
	if modem.Status.PhysAddrs == emptyPhysAddrs {
		// Missing physical addresses in the status - cannot match with any config.
		return false
	}
	if config.PhysAddrs.Interface != "" &&
		config.PhysAddrs.Interface != modem.Status.PhysAddrs.Interface {
		return false
	}
	if config.PhysAddrs.USB != "" &&
		config.PhysAddrs.USB != modem.Status.PhysAddrs.USB {
		return false
	}
	if config.PhysAddrs.PCI != "" &&
		config.PhysAddrs.PCI != modem.Status.PhysAddrs.PCI {
		return false
	}
	return true
}

func main() {
	flag.Parse()
	agent := new(MMAgent)
	if err := agent.Init(); err != nil {
		logrus.Fatal(err)
	}
	if err := agent.Run(context.Background()); err != nil {
		logrus.Fatal(err)
	}
}
