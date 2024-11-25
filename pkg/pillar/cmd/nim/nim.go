// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nim

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/conntester"
	"github.com/lf-edge/eve/pkg/pillar/dpcmanager"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "nim"
	// Time limits for event loop handlers; shorter for nim than other agents
	errorTime    = 60 * time.Second
	warningTime  = 40 * time.Second
	stillRunTime = 25 * time.Second
)

const (
	configDevicePortConfigDir = types.IdentityDirname + "/DevicePortConfig"
	runDevicePortConfigDir    = "/run/global/DevicePortConfig"
	maxReadSize               = 16384       // Punt on too large files
	dpcAvailableTimeLimit     = time.Minute // TODO: make configurable?
)

// Really a constant
var nilUUID uuid.UUID

// NIM - Network Interface Manager.
// Manage (physical) network interfaces of the device based on configuration from
// various sources (controller, override, last-resort, persisted config).
// Verifies new configuration changes before fully applying them.
// Maintains old configuration with a lower-priority, but always tries to move
// to the most recent aka highest priority configuration.
type nim struct {
	agentbase.AgentBase
	Log    *base.LogObject
	Logger *logrus.Logger
	PubSub *pubsub.PubSub

	useStdout bool

	// CLI args
	stdoutPtr *bool

	// NIM components
	connTester     *conntester.ZedcloudConnectivityTester
	dpcManager     *dpcmanager.DpcManager
	dpcReconciler  dpcreconciler.DpcReconciler
	networkMonitor netmonitor.NetworkMonitor

	// Subscriptions
	subGlobalConfig          pubsub.Subscription
	subControllerCert        pubsub.Subscription
	subEdgeNodeCert          pubsub.Subscription
	subDevicePortConfigA     pubsub.Subscription
	subDevicePortConfigO     pubsub.Subscription
	subDevicePortConfigS     pubsub.Subscription
	subDevicePortConfigM     pubsub.Subscription
	subZedAgentStatus        pubsub.Subscription
	subAssignableAdapters    pubsub.Subscription
	subOnboardStatus         pubsub.Subscription
	subWwanStatus            pubsub.Subscription
	subNetworkInstanceConfig pubsub.Subscription

	// Publications
	pubDummyDevicePortConfig pubsub.Publication // For logging
	pubDevicePortConfig      pubsub.Publication
	pubDevicePortConfigList  pubsub.Publication
	pubCipherBlockStatus     pubsub.Publication
	pubDeviceNetworkStatus   pubsub.Publication
	pubZedcloudMetrics       pubsub.Publication
	pubCipherMetrics         pubsub.Publication
	pubCachedResolvedIPs     pubsub.Publication
	pubWwanConfig            pubsub.Publication

	// Metrics
	zedcloudMetrics *zedcloud.AgentMetrics
	cipherMetrics   *cipher.AgentMetrics

	// Configuration
	globalConfig       types.ConfigItemValueMap
	gcInitialized      bool // Received initial GlobalConfig
	assignableAdapters types.AssignableAdapters
	enabledLastResort  bool
	forceLastResort    bool
	forceManualDPC     bool
	lastResort         *types.DevicePortConfig
	manualDPC          *types.DevicePortConfig
}

// AddAgentSpecificCLIFlags adds CLI options
func (n *nim) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	n.stdoutPtr = flagSet.Bool("s", false, "Use stdout")
}

// ProcessAgentSpecificCLIFlags process received CLI options
func (n *nim) ProcessAgentSpecificCLIFlags(_ *flag.FlagSet) {
	n.useStdout = *n.stdoutPtr
}

// Run - Main function - invoked from zedbox.go
func Run(ps *pubsub.PubSub, logger *logrus.Logger, log *base.LogObject, arguments []string, baseDir string) int {
	nim := &nim{
		Log:    log,
		PubSub: ps,
		Logger: logger,
	}
	agentbase.Init(nim, logger, log, agentName,
		agentbase.WithBaseDir(baseDir),
		agentbase.WithPidFile(),
		agentbase.WithArguments(arguments))

	if err := nim.init(); err != nil {
		log.Fatal(err)
	}
	if err := nim.run(context.Background()); err != nil {
		log.Fatal(err)
	}
	return 0
}

func (n *nim) init() (err error) {

	n.cipherMetrics = cipher.NewAgentMetrics(agentName)
	n.zedcloudMetrics = zedcloud.NewAgentMetrics()

	if err = n.initPublications(); err != nil {
		return err
	}
	if err = n.initSubscriptions(); err != nil {
		return err
	}

	// Initialize NIM components (for Linux network stack).
	linuxNetMonitor := &netmonitor.LinuxNetworkMonitor{
		Log: n.Log,
	}
	n.networkMonitor = linuxNetMonitor
	n.connTester = &conntester.ZedcloudConnectivityTester{
		Log:       n.Log,
		AgentName: agentName,
		Metrics:   n.zedcloudMetrics,
	}
	n.dpcReconciler = &dpcreconciler.LinuxDpcReconciler{
		Log:                  n.Log,
		ExportCurrentState:   true, // XXX make configurable
		ExportIntendedState:  true, // XXX make configurable
		AgentName:            agentName,
		NetworkMonitor:       linuxNetMonitor,
		SubControllerCert:    n.subControllerCert,
		SubEdgeNodeCert:      n.subEdgeNodeCert,
		PubCipherBlockStatus: n.pubCipherBlockStatus,
		PubWwanConfig:        n.pubWwanConfig,
		CipherMetrics:        n.cipherMetrics,
		HVTypeKube:           base.IsHVTypeKube(),
	}
	n.dpcManager = &dpcmanager.DpcManager{
		Log:                      n.Log,
		Watchdog:                 n.PubSub,
		AgentName:                agentName,
		NetworkMonitor:           n.networkMonitor,
		DpcReconciler:            n.dpcReconciler,
		ConnTester:               n.connTester,
		PubDummyDevicePortConfig: n.pubDummyDevicePortConfig,
		PubDevicePortConfigList:  n.pubDevicePortConfigList,
		PubDeviceNetworkStatus:   n.pubDeviceNetworkStatus,
		ZedcloudMetrics:          n.zedcloudMetrics,
	}
	return nil
}

func (n *nim) run(ctx context.Context) (err error) {
	n.Log.Noticef("Starting %s", agentName)

	// Start DPC Manager.
	if err = n.dpcManager.Init(ctx); err != nil {
		return err
	}
	if err = n.dpcManager.Run(ctx); err != nil {
		return err
	}

	// Wait for initial GlobalConfig.
	if err = n.subGlobalConfig.Activate(); err != nil {
		return err
	}
	for !n.gcInitialized {
		n.Log.Noticef("Waiting for GCInitialized")
		select {
		case change := <-n.subGlobalConfig.MsgChan():
			n.subGlobalConfig.ProcessChange(change)
		}
	}
	n.Log.Noticef("Processed GlobalConfig")

	// Check if we have a /config/DevicePortConfig/*.json which we need to
	// take into account by copying it to /run/global/DevicePortConfig/
	n.ingestDevicePortConfig()

	// Activate some subscriptions.
	// Not all yet though, first we wait for last-resort and AA to initialize.
	if err = n.subControllerCert.Activate(); err != nil {
		return err
	}
	if err = n.subEdgeNodeCert.Activate(); err != nil {
		return err
	}
	if err = n.subDevicePortConfigS.Activate(); err != nil {
		return err
	}
	if err = n.subOnboardStatus.Activate(); err != nil {
		return err
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunTime)
	n.PubSub.StillRunning(agentName, warningTime, errorTime)

	// Publish metrics for zedagent every 10 seconds
	interval := 10 * time.Second
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	// Watch for interface changes to update last resort DPC.
	done := make(chan struct{})
	defer close(done)
	netEvents := n.networkMonitor.WatchEvents(ctx, agentName)

	// Time limit to obtain some network config.
	// If it runs out and we still do not have any config, lastresort will be enabled
	// unconditionally.
	// This is mainly to handle the case when for whatever reason the device
	// has lost /persist/status/nim/DevicePortConfigList
	dpcAvailTimer := time.After(dpcAvailableTimeLimit)

	if !n.enabledLastResort {
		// Even if lastresort DPC is disabled by config, it can be forcefully used
		// until NIM obtains any proper network config (from controller or bootstrap config
		// or override/usb json).
		//  * Before onboarding, we can easily determine if there is going to be any network
		//    config available. If there is neither bootstrap device config nor any network
		//    config override inside the /config partition or inside an (already plugged in)
		//    USB stick, then device has no source of network configuration (currently)
		//    available. The only exception is if the user is planning to insert USB stick
		//    with usb.json *later*, but this cannot be predicted.
		//    In order to not prolong onboarding in situations where the use of lastresort
		//    is expected (ethernet + DHCP scenarios; often relied upon in lab/testing cases),
		//    we will forcefully enable lastresort immediately if the above conditions for
		//    missing network config source are satisfied. If the user later inserts a USB
		//    stick with usb.json or the device onboards using lastresort and obtains a proper
		//    config from the controller, the lastresort DPC will be unpublished (unless it is
		//    enabled explicitly by config - by default it is disabled).
		//  * After onboarding, it is expected that device always keeps and persists
		//    at least the latest and the last working DPC, so it should never run out of
		//    network configurations. But should device loose all of its /persist partition,
		//    e.g. due to replacing or wiping the single disk where /persist lives, NIM will
		//    notice that even after one minute of runtime (when dpcAvailTimer fires) there
		//    is still no network config available and it will forcefully enable lastresort.
		if !n.isDeviceOnboarded() &&
			len(n.listPublishedDPCs(runDevicePortConfigDir)) == 0 &&
			!fileutils.FileExists(n.Log, types.BootstrapConfFileName) {
			n.forceLastResort = true
			n.reevaluateLastResortDPC()
		}
	}

	waitForLastResort := n.enabledLastResort
	lastResortIsReady := func() error {
		if err = n.subDevicePortConfigM.Activate(); err != nil {
			return err
		}
		if err = n.subDevicePortConfigO.Activate(); err != nil {
			return err
		}
		if err = n.subDevicePortConfigA.Activate(); err != nil {
			return err
		}
		if err = n.subZedAgentStatus.Activate(); err != nil {
			return err
		}
		if err = n.subAssignableAdapters.Activate(); err != nil {
			return err
		}
		if err = n.subWwanStatus.Activate(); err != nil {
			return err
		}
		if err = n.subNetworkInstanceConfig.Activate(); err != nil {
			return err
		}
		go n.runResolverCacheForController()
		return nil
	}
	if !waitForLastResort {
		if err = lastResortIsReady(); err != nil {
			return err
		}
	} else {
		n.Log.Notice("Waiting for last-resort DPC...")
	}

	for {
		select {
		case change := <-n.subControllerCert.MsgChan():
			n.subControllerCert.ProcessChange(change)

		case change := <-n.subEdgeNodeCert.MsgChan():
			n.subEdgeNodeCert.ProcessChange(change)

		case change := <-n.subGlobalConfig.MsgChan():
			n.subGlobalConfig.ProcessChange(change)
			if waitForLastResort && !n.enabledLastResort {
				waitForLastResort = false
				n.Log.Notice("last-resort DPC is not enabled")
				if err = lastResortIsReady(); err != nil {
					return err
				}
			}

		case change := <-n.subDevicePortConfigM.MsgChan():
			n.subDevicePortConfigM.ProcessChange(change)
		case change := <-n.subDevicePortConfigA.MsgChan():
			n.subDevicePortConfigA.ProcessChange(change)

		case change := <-n.subDevicePortConfigO.MsgChan():
			n.subDevicePortConfigO.ProcessChange(change)

		case change := <-n.subDevicePortConfigS.MsgChan():
			n.subDevicePortConfigS.ProcessChange(change)
			if waitForLastResort && n.lastResort != nil {
				waitForLastResort = false
				n.Log.Notice("last-resort DPC is ready")
				if err = lastResortIsReady(); err != nil {
					return err
				}
			}

		case change := <-n.subZedAgentStatus.MsgChan():
			n.subZedAgentStatus.ProcessChange(change)

		case change := <-n.subAssignableAdapters.MsgChan():
			n.subAssignableAdapters.ProcessChange(change)

		case change := <-n.subOnboardStatus.MsgChan():
			n.subOnboardStatus.ProcessChange(change)

		case change := <-n.subWwanStatus.MsgChan():
			n.subWwanStatus.ProcessChange(change)

		case change := <-n.subNetworkInstanceConfig.MsgChan():
			n.subNetworkInstanceConfig.ProcessChange(change)
			n.handleNetworkInstanceUpdate()

		case event := <-netEvents:
			ifChange, isIfChange := event.(netmonitor.IfChange)
			if isIfChange {
				n.processInterfaceChange(ifChange)
			}

		case <-publishTimer.C:
			start := time.Now()
			err = n.cipherMetrics.Publish(n.Log, n.pubCipherMetrics, "global")
			if err != nil {
				n.Log.Error(err)
			}
			err = n.zedcloudMetrics.Publish(n.Log, n.pubZedcloudMetrics, "global")
			if err != nil {
				n.Log.Error(err)
			}
			n.PubSub.CheckMaxTimeTopic(agentName, "publishTimer", start,
				warningTime, errorTime)

		case <-dpcAvailTimer:
			obj, err := n.pubDevicePortConfigList.Get("global")
			if err != nil {
				n.Log.Errorf("Failed to get published DPCL: %v", err)
				continue
			}
			dpcl := obj.(types.DevicePortConfigList)
			if len(dpcl.PortConfigList) == 0 {
				n.Log.Noticef("DPC Manager has no network config to work with "+
					"even after %v, enabling lastresort unconditionally", dpcAvailableTimeLimit)
				n.forceLastResort = true
				n.reevaluateLastResortDPC()
			}

		case <-ctx.Done():
			return nil

		case <-stillRunning.C:
		}
		n.PubSub.StillRunning(agentName, warningTime, errorTime)
	}
}

func (n *nim) initPublications() (err error) {
	n.pubDeviceNetworkStatus, err = n.PubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DeviceNetworkStatus{},
		})
	if err != nil {
		return err
	}
	if err = n.pubDeviceNetworkStatus.ClearRestarted(); err != nil {
		return err
	}

	n.pubZedcloudMetrics, err = n.PubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.MetricsMap{},
		})
	if err != nil {
		return err
	}

	n.pubDevicePortConfig, err = n.PubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DevicePortConfig{},
		})
	if err != nil {
		return err
	}
	if err = n.pubDevicePortConfig.ClearRestarted(); err != nil {
		return err
	}

	// Publication to get logs
	n.pubDummyDevicePortConfig, err = n.PubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			AgentScope: "dummy",
			TopicType:  types.DevicePortConfig{},
		})
	if err != nil {
		return err
	}
	if err = n.pubDummyDevicePortConfig.ClearRestarted(); err != nil {
		return err
	}

	n.pubDevicePortConfigList, err = n.PubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: true,
			TopicType:  types.DevicePortConfigList{},
		})
	if err != nil {
		return err
	}
	if err = n.pubDevicePortConfigList.ClearRestarted(); err != nil {
		return err
	}

	n.pubCipherBlockStatus, err = n.PubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.CipherBlockStatus{},
		})
	if err != nil {
		return err
	}

	n.pubCipherMetrics, err = n.PubSub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.CipherMetrics{},
	})
	if err != nil {
		return err
	}

	n.pubCachedResolvedIPs, err = n.PubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.CachedResolvedIPs{},
		})
	if err != nil {
		return err
	}

	n.pubWwanConfig, err = n.PubSub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.WwanConfig{},
	})
	if err != nil {
		return err
	}
	return nil
}

func (n *nim) initSubscriptions() (err error) {
	// Look for global config such as log levels.
	n.subGlobalConfig, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		CreateHandler: n.handleGlobalConfigCreate,
		ModifyHandler: n.handleGlobalConfigModify,
		DeleteHandler: n.handleGlobalConfigDelete,
		SyncHandler:   n.handleGlobalConfigSynchronized,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	// Look for controller certs which will be used for decryption.
	n.subControllerCert, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.ControllerCert{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	// Look for edge node certs which will be used for decryption
	n.subEdgeNodeCert, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeCert{},
		Activate:    false,
		Persistent:  true,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		return err
	}

	// We get DevicePortConfig from three sources in this priority:
	// 0. A request from monitor TUI application (manual override)
	// 1. zedagent publishing DevicePortConfig
	// 2. override file in /run/global/DevicePortConfig/*.json
	// 3. "lastresort" derived from the set of network interfaces
	n.subDevicePortConfigM, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "monitor",
		MyAgentName: agentName,
		TopicImpl:   types.DevicePortConfig{},
		Persistent:  true,
		//TODO: check for activation
		//TODO: check persistent
		Activate:      false,
		CreateHandler: n.handleDPCCreate,
		ModifyHandler: n.handleDPCModify,
		DeleteHandler: n.handleDPCDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}
	n.subDevicePortConfigA, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.DevicePortConfig{},
		Activate:      false,
		CreateHandler: n.handleDPCCreate,
		ModifyHandler: n.handleDPCModify,
		DeleteHandler: n.handleDPCDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	n.subDevicePortConfigO, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		MyAgentName:   agentName,
		TopicImpl:     types.DevicePortConfig{},
		Activate:      false,
		CreateHandler: n.handleDPCFileCreate,
		ModifyHandler: n.handleDPCFileModify,
		DeleteHandler: n.handleDPCDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	n.subDevicePortConfigS, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     agentName,
		MyAgentName:   agentName,
		TopicImpl:     types.DevicePortConfig{},
		Activate:      false,
		CreateHandler: n.handleDPCCreate,
		ModifyHandler: n.handleDPCModify,
		DeleteHandler: n.handleDPCDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	// To read radio silence configuration.
	n.subZedAgentStatus, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		CreateHandler: n.handleZedAgentStatusCreate,
		ModifyHandler: n.handleZedAgentStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	// To determine which ports are in PCIBack.
	n.subAssignableAdapters, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.AssignableAdapters{},
		Activate:      false,
		CreateHandler: n.handleAssignableAdaptersCreate,
		ModifyHandler: n.handleAssignableAdaptersModify,
		DeleteHandler: n.handleAssignableAdaptersDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	// To determine if device is onboarded
	n.subOnboardStatus, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		MyAgentName:   agentName,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      false,
		CreateHandler: n.handleOnboardStatusCreate,
		ModifyHandler: n.handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		Persistent:    true,
	})
	if err != nil {
		return err
	}

	n.subWwanStatus, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "wwan",
		MyAgentName:   agentName,
		TopicImpl:     types.WwanStatus{},
		Activate:      false,
		CreateHandler: n.handleWwanStatusCreate,
		ModifyHandler: n.handleWwanStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	// Used to find out if at least one NI has flowlog enabled.
	n.subNetworkInstanceConfig, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.NetworkInstanceConfig{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		return err
	}
	return nil
}

func (n *nim) handleGlobalConfigCreate(_ interface{}, key string, _ interface{}) {
	n.handleGlobalConfigImpl(key)
}

func (n *nim) handleGlobalConfigModify(_ interface{}, key string, _, _ interface{}) {
	n.handleGlobalConfigImpl(key)
}

func (n *nim) handleGlobalConfigImpl(key string) {
	if key != "global" {
		n.Log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	gcp := agentlog.HandleGlobalConfig(n.Log, n.subGlobalConfig, agentName,
		n.CLIParams().DebugOverride, n.Logger)
	n.applyGlobalConfig(gcp)
}

func (n *nim) handleGlobalConfigDelete(_ interface{}, key string, _ interface{}) {
	if key != "global" {
		n.Log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	agentlog.HandleGlobalConfig(n.Log, n.subGlobalConfig, agentName,
		n.CLIParams().DebugOverride, n.Logger)
	n.applyGlobalConfig(types.DefaultConfigItemValueMap())
}

// In case there is no GlobalConfig.json this will move us forward.
func (n *nim) handleGlobalConfigSynchronized(_ interface{}, done bool) {
	n.Log.Functionf("handleGlobalConfigSynchronized(%v)", done)
	if done && !n.gcInitialized {
		n.applyGlobalConfig(types.DefaultConfigItemValueMap())
	}
}

func (n *nim) applyGlobalConfig(gcp *types.ConfigItemValueMap) {
	if gcp == nil {
		return
	}
	n.globalConfig = *gcp
	n.dpcManager.UpdateGCP(n.globalConfig)
	timeout := gcp.GlobalValueInt(types.NetworkTestTimeout)
	n.connTester.TestTimeout = time.Second * time.Duration(timeout)
	n.reevaluateLastResortDPC()
	n.gcInitialized = true
}

// handleDPCCreate handles four different sources in this priority order:
// 0. A request from monitor TUI application
// 1. zedagent with any key
// 2. "usb" key from build or USB stick file
// 3. "lastresort" derived from the set of network interfaces
// We determine the priority from TimePriority in the config.
func (n *nim) handleDPCCreate(_ interface{}, key string, configArg interface{}) {
	n.handleDPCImpl(key, configArg, false)
}

// handleDPCModify handles three different sources as above
func (n *nim) handleDPCModify(_ interface{}, key string, configArg, _ interface{}) {
	n.handleDPCImpl(key, configArg, false)
}

func (n *nim) handleDPCFileCreate(_ interface{}, key string, configArg interface{}) {
	n.handleDPCImpl(key, configArg, true)
}

func (n *nim) handleDPCFileModify(_ interface{}, key string, configArg, _ interface{}) {
	n.handleDPCImpl(key, configArg, true)
}

func (n *nim) handleDPCImpl(key string, configArg interface{}, fromFile bool) {
	dpc := configArg.(types.DevicePortConfig)
	dpc.DoSanitize(n.Log, types.DPCSanitizeArgs{
		SanitizeTimePriority: true,
		SanitizeKey:          true,
		KeyToUseIfEmpty:      key,
		SanitizeName:         true,
		SanitizeL3Port:       true,
		SanitizeSharedLabels: true,
	})
	if fromFile {
		// Use sha to determine if file has already been ingested
		filename := filepath.Join(types.TmpDirname, "DevicePortConfig",
			key) + ".json"
		shaFilename := filepath.Join(types.IngestedDirname, "DevicePortConfig",
			key) + ".sha"
		changed, dpcSha, err := fileutils.CompareSha(filename,
			shaFilename)
		if err != nil {
			n.Log.Errorf("CompareSha failed: %s", err)
		} else if changed {
			dpc.ShaFile = shaFilename
			dpc.ShaValue = dpcSha
		} else {
			n.Log.Noticef("No change to %s", filename)
			return
		}
	}
	// Lastresort DPC is allowed to be forcefully used only until NIM receives
	// any (proper) network configuration.
	if dpc.Key != dpcmanager.LastResortKey {
		n.forceLastResort = false
		n.reevaluateLastResortDPC()
	}
	// if device can connect to controller it may get a new DPC in global config. This global DPC
	// will have higher priority but can be invalid and the device will loose connectifity again
	// at least temporraraly while DPC is being tested. To avoid this we reset the timestamp on
	// the Manual DPC to the current time
	// TODO: do it. or check for ManualDPCKey in DPCManager
	// TODO 2: we should not try lastresort DPC if the user set the DPC to manual
	n.dpcManager.AddDPC(dpc)
}

func (n *nim) handleDPCDelete(_ interface{}, key string, configArg interface{}) {
	dpc := configArg.(types.DevicePortConfig)
	dpc.DoSanitize(n.Log, types.DPCSanitizeArgs{
		SanitizeTimePriority: false,
		SanitizeKey:          true,
		KeyToUseIfEmpty:      key,
		SanitizeName:         true,
		SanitizeL3Port:       true,
		SanitizeSharedLabels: true,
	})
	n.dpcManager.DelDPC(dpc)
}

func (n *nim) handleAssignableAdaptersCreate(_ interface{}, key string, configArg interface{}) {
	n.handleAssignableAdaptersImpl(key, configArg)
}

func (n *nim) handleAssignableAdaptersModify(_ interface{}, key string, configArg, _ interface{}) {
	n.handleAssignableAdaptersImpl(key, configArg)
}

func (n *nim) handleAssignableAdaptersImpl(key string, configArg interface{}) {
	if key != "global" {
		n.Log.Functionf("handleAssignableAdaptersImpl: ignoring %s\n", key)
		return
	}
	assignableAdapters := configArg.(types.AssignableAdapters)
	n.assignableAdapters = assignableAdapters
	n.dpcManager.UpdateAA(n.assignableAdapters)
	if n.enabledLastResort {
		n.publishLastResortDPC("assignable adapters changed")
	}
}

func (n *nim) handleAssignableAdaptersDelete(_ interface{}, key string, _ interface{}) {
	// This usually happens only at restart - as any changes to assignable
	// adapters results in domain restart and takes affect only after
	// the restart.
	// UsbAccess can change dynamically - but it is not network device,
	// so can be ignored. Assuming there are no USB based network interfaces.
	n.Log.Functionf("handleAssignableAdaptersDelete done for %s\n", key)
}

func (n *nim) handleZedAgentStatusCreate(_ interface{}, key string, statusArg interface{}) {
	n.handleZedAgentStatusImpl(key, statusArg)
}

func (n *nim) handleZedAgentStatusModify(_ interface{}, key string, statusArg, _ interface{}) {
	n.handleZedAgentStatusImpl(key, statusArg)
}

func (n *nim) handleZedAgentStatusImpl(_ string, statusArg interface{}) {
	zedagentStatus := statusArg.(types.ZedAgentStatus)
	n.dpcManager.UpdateRadioSilence(zedagentStatus.RadioSilence)
}

func (n *nim) handleOnboardStatusCreate(_ interface{}, key string, statusArg interface{}) {
	n.handleOnboardStatusImpl(key, statusArg)
}

func (n *nim) handleOnboardStatusModify(_ interface{}, key string, statusArg, _ interface{}) {
	n.handleOnboardStatusImpl(key, statusArg)
}

func (n *nim) handleOnboardStatusImpl(_ string, statusArg interface{}) {
	status := statusArg.(types.OnboardingStatus)
	n.dpcManager.UpdateDevUUID(status.DeviceUUID)
}

func (n *nim) handleWwanStatusCreate(_ interface{}, key string, statusArg interface{}) {
	n.handleWwanStatusImpl(key, statusArg)
}

func (n *nim) handleWwanStatusModify(_ interface{}, key string, statusArg, _ interface{}) {
	n.handleWwanStatusImpl(key, statusArg)
}

func (n *nim) handleWwanStatusImpl(_ string, statusArg interface{}) {
	status := statusArg.(types.WwanStatus)
	n.dpcManager.ProcessWwanStatus(status)
}

func (n *nim) handleNetworkInstanceUpdate() {
	var flowlogEnabled bool
	for _, item := range n.subNetworkInstanceConfig.GetAll() {
		niConfig := item.(types.NetworkInstanceConfig)
		if niConfig.EnableFlowlog {
			flowlogEnabled = true
			break
		}
	}
	n.dpcManager.UpdateFlowlogState(flowlogEnabled)
}

func (n *nim) isDeviceOnboarded() bool {
	obj, err := n.subOnboardStatus.Get("global")
	if err != nil {
		return false
	}
	status, ok := obj.(types.OnboardingStatus)
	if !ok {
		return false
	}
	return status.DeviceUUID != nilUUID
}

func (n *nim) listPublishedDPCs(directory string) (dpcFilePaths []string) {
	locations, err := os.ReadDir(directory)
	if err != nil {
		// Directory might not exist
		return
	}
	for _, location := range locations {
		if location.IsDir() {
			continue
		}
		// Files from /config can have any name while files from an
		// override USB stick must be named usb.json.
		dpcFile := location.Name()
		if !strings.HasSuffix(dpcFile, ".json") {
			n.Log.Noticef("Ignoring %s file (not DPC)", dpcFile)
			continue
		}
		dpcFilePaths = append(dpcFilePaths, dpcFile)
	}
	return dpcFilePaths
}

// ingestPortConfig reads all json files in configDevicePortConfigDir, ensures
// they have a TimePriority, and adds a ShaFile and Shavalue to them and then writes to
// runDevicePortConfigDir.
// If a file has already been ingested (based on finding the sha of the file content
// being in /persist/ingested/DevicePortConfig/<key>.sha), it is ignored.
// Otherwise the ShaFile and Shavalue is used to write the sha for the new file to avoid
// re-application of the same config.
func (n *nim) ingestDevicePortConfig() {
	dpcFiles := n.listPublishedDPCs(configDevicePortConfigDir)
	// Skip these legacy DPC json files if there is bootstrap config.
	if fileutils.FileExists(n.Log, types.BootstrapConfFileName) && len(dpcFiles) > 0 {
		n.Log.Noticef("Not ingesting DPC jsons (%v) from config partition: "+
			"bootstrap config is present", strings.Join(dpcFiles, ", "))
		return
	}
	for _, dpcFile := range dpcFiles {
		n.ingestDevicePortConfigFile(configDevicePortConfigDir,
			runDevicePortConfigDir, dpcFile)
	}
}

func (n *nim) ingestDevicePortConfigFile(oldDirname string, newDirname string, name string) {
	filename := path.Join(oldDirname, name)
	n.Log.Noticef("ingestDevicePortConfigFile(%s)", filename)
	b, err := fileutils.ReadWithMaxSize(n.Log, filename, maxReadSize)
	if err != nil {
		n.Log.Errorf("Failed to read file %s: %v", filename, err)
		return
	}
	if len(b) == 0 {
		n.Log.Errorf("Ignore empty file %s", filename)
		return
	}

	var dpc types.DevicePortConfig
	err = json.Unmarshal(b, &dpc)
	if err != nil {
		n.Log.Errorf("Could not parse json data in file %s: %s",
			filename, err)
		return
	}
	key := strings.TrimSuffix(name, ".json")
	dpc.DoSanitize(n.Log, types.DPCSanitizeArgs{
		SanitizeTimePriority: true,
		SanitizeKey:          true,
		KeyToUseIfEmpty:      key,
		SanitizeName:         true,
		SanitizeL3Port:       true,
		SanitizeSharedLabels: true,
	})

	// Use sha to determine if file has already been ingested
	basename := filepath.Base(filename)
	shaFilename := filepath.Join(types.IngestedDirname, "DevicePortConfig",
		strings.TrimSuffix(basename, ".json")) + ".sha"
	changed, dpcSha, err := fileutils.CompareSha(filename,
		shaFilename)
	if err != nil {
		n.Log.Errorf("CompareSha failed: %s", err)
	} else if changed {
		dpc.ShaFile = shaFilename
		dpc.ShaValue = dpcSha
	} else {
		n.Log.Noticef("No change to %s", filename)
		return
	}

	// Save New config to file.
	var data []byte
	data, err = json.Marshal(dpc)
	if err != nil {
		n.Log.Fatalf("Failed to json marshall new DevicePortConfig err %s",
			err)
	}
	filename = path.Join(newDirname, name)
	err = fileutils.WriteRename(filename, data)
	if err != nil {
		n.Log.Errorf("Failed to write new DevicePortConfig to %s: %s",
			filename, err)
	}
}

// reevaluateLastResortDPC re-evaluates the current state of Last resort DPC.
// If the config or the overall situation around DPC availability changed since
// the last call, an already enabled lastresort could be disabled and vice versa.
// The function applies a potential change in the intended state of lastresort
// by (un)publishing lastresort DPC (notification will be delivered to NIM itself
// and further propagated to DPCManager).
// Note that the function also updates n.enabledLastResort, signaling the current
// (intended) state of Last resort DPC.
func (n *nim) reevaluateLastResortDPC() {
	fallbackAnyEth := n.globalConfig.GlobalValueTriState(types.NetworkFallbackAnyEth)
	enabledByConfig := fallbackAnyEth == types.TS_ENABLED
	enableLastResort := enabledByConfig || n.forceLastResort
	if n.enabledLastResort != enableLastResort {
		if enableLastResort {
			reason := "lastresort enabled by global config"
			if !enabledByConfig {
				reason = "lastresort forcefully enabled"
			}
			n.publishLastResortDPC(reason)
		} else {
			n.removeLastResortDPC()
		}
	}
	n.enabledLastResort = enableLastResort
}

func (n *nim) publishLastResortDPC(reason string) {
	n.Log.Functionf("publishLastResortDPC")
	dpc, err := n.makeLastResortDPC()
	if err != nil {
		n.Log.Error(err)
		return
	}
	if n.lastResort != nil && n.lastResort.MostlyEqual(&dpc) {
		return
	}
	n.Log.Noticef("Publishing last-resort DPC, reason: %v", reason)
	if err := n.pubDevicePortConfig.Publish(dpcmanager.LastResortKey, dpc); err != nil {
		n.Log.Errorf("Failed to publish last-resort DPC: %v", err)
		return
	}
	n.lastResort = &dpc
}

func (n *nim) removeLastResortDPC() {
	n.Log.Noticef("removeLastResortDPC")
	if err := n.pubDevicePortConfig.Unpublish(dpcmanager.LastResortKey); err != nil {
		n.Log.Errorf("Failed to un-publish last-resort DPC: %v", err)
		return
	}
	n.lastResort = nil
}

func (n *nim) makeLastResortDPC() (types.DevicePortConfig, error) {
	config := types.DevicePortConfig{}
	config.Key = dpcmanager.LastResortKey
	config.Version = types.DPCIsMgmt
	// Set to higher than all zero but lower than the hardware model derived one above
	config.TimePriority = time.Unix(0, 0)
	ifNames, err := n.networkMonitor.ListInterfaces()
	if err != nil {
		err = fmt.Errorf("makeLastResortDPC: Failed to list interfaces: %v", err)
		return config, err
	}
	for _, ifName := range ifNames {
		ifIndex, _, err := n.networkMonitor.GetInterfaceIndex(ifName)
		if err != nil {
			n.Log.Errorf("makeLastResortDPC: failed to get interface index: %v", err)
			continue
		}
		ifAttrs, err := n.networkMonitor.GetInterfaceAttrs(ifIndex)
		if err != nil {
			n.Log.Errorf("makeLastResortDPC: failed to get interface attrs: %v", err)
			continue
		}
		if !n.includeLastResortPort(ifAttrs) {
			continue
		}
		port := types.NetworkPortConfig{
			IfName:       ifName,
			Phylabel:     ifName,
			Logicallabel: ifName,
			IsMgmt:       true,
			IsL3Port:     true,
			DhcpConfig: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
			},
		}
		dns := n.dpcManager.GetDNS()
		portStatus := dns.LookupPortByIfName(ifName)
		if portStatus != nil {
			port.WirelessCfg = portStatus.WirelessCfg
		}
		config.Ports = append(config.Ports, port)
	}
	return config, nil
}

func (n *nim) includeLastResortPort(ifAttrs netmonitor.IfAttrs) bool {
	ifName := ifAttrs.IfName
	exclude := strings.HasPrefix(ifName, "vif") ||
		strings.HasPrefix(ifName, "nbu") ||
		strings.HasPrefix(ifName, "nbo") ||
		strings.HasPrefix(ifName, "wlan") ||
		strings.HasPrefix(ifName, "wwan") ||
		strings.HasPrefix(ifName, "keth")
	if exclude {
		return false
	}
	if n.isInterfaceAssigned(ifName) {
		return false
	}
	if ifAttrs.IsLoopback || !ifAttrs.WithBroadcast || ifAttrs.Enslaved {
		return false
	}

	switch ifAttrs.IfType {
	case "device":
		return true
	case "bridge":
		// Was this originally an ethernet interface turned into a bridge?
		_, exists, _ := n.networkMonitor.GetInterfaceIndex("k" + ifName)
		return exists
	case "can", "vcan":
		return false
	}

	return false
}

func (n *nim) isInterfaceAssigned(ifName string) bool {
	ib := n.assignableAdapters.LookupIoBundleIfName(ifName)
	if ib == nil {
		return false
	}
	n.Log.Tracef("isAssigned(%s): pciback %t, used %s",
		ifName, ib.IsPCIBack, ib.UsedByUUID.String())
	if ib.UsedByUUID != nilUUID {
		return true
	}
	return false
}

func (n *nim) processInterfaceChange(ifChange netmonitor.IfChange) {
	if !n.enabledLastResort || n.lastResort == nil {
		return
	}
	includePort := n.includeLastResortPort(ifChange.Attrs)
	port := n.lastResort.LookupPortByIfName(ifChange.Attrs.IfName)
	if port == nil && includePort {
		n.publishLastResortDPC(fmt.Sprintf("interface %s should be included",
			ifChange.Attrs.IfName))
	}
}
