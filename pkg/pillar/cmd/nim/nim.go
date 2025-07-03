// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nim

import (
	"context"
	"encoding/json"
	"flag"
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
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/dpcmanager"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
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
	maxReadSize               = 16384 // Punt on too large files
)

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
	connTester     *conntester.ControllerConnectivityTester
	dpcManager     *dpcmanager.DpcManager
	dpcReconciler  dpcreconciler.DpcReconciler
	networkMonitor netmonitor.NetworkMonitor

	// Subscriptions
	subGlobalConfig          pubsub.Subscription
	subControllerCert        pubsub.Subscription
	subEdgeNodeCert          pubsub.Subscription
	subDevicePortConfigA     pubsub.Subscription
	subDevicePortConfigO     pubsub.Subscription
	subDevicePortConfigM     pubsub.Subscription
	subZedAgentStatus        pubsub.Subscription
	subAssignableAdapters    pubsub.Subscription
	subOnboardStatus         pubsub.Subscription
	subWwanStatus            pubsub.Subscription
	subNetworkInstanceConfig pubsub.Subscription
	subEdgeNodeClusterStatus pubsub.Subscription
	subKubeUserServices      pubsub.Subscription

	// Publications
	pubDummyDevicePortConfig pubsub.Publication // For logging
	pubDevicePortConfig      pubsub.Publication
	pubDevicePortConfigList  pubsub.Publication
	pubCipherBlockStatus     pubsub.Publication
	pubDeviceNetworkStatus   pubsub.Publication
	pubAgentMetrics          pubsub.Publication
	pubCipherMetrics         pubsub.Publication
	pubCachedResolvedIPs     pubsub.Publication
	pubWwanConfig            pubsub.Publication

	// Metrics
	agentMetrics  *controllerconn.AgentMetrics
	cipherMetrics *cipher.AgentMetrics

	// Configuration
	globalConfig       types.ConfigItemValueMap
	gcInitialized      bool // Received initial GlobalConfig
	assignableAdapters types.AssignableAdapters
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
	n.agentMetrics = controllerconn.NewAgentMetrics()

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
	n.connTester = &conntester.ControllerConnectivityTester{
		Log:            n.Log,
		AgentName:      agentName,
		Metrics:        n.agentMetrics,
		NetworkMonitor: n.networkMonitor,
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
		AgentMetrics:             n.agentMetrics,
	}
	return nil
}

func (n *nim) run(ctx context.Context) (err error) {
	n.Log.Noticef("Starting %s", agentName)

	// Check if we have a /config/DevicePortConfig/*.json which we need to
	// take into account by copying it to /run/global/DevicePortConfig/
	n.ingestDevicePortConfig()

	// Start DPC Manager.
	if err = n.dpcManager.Init(ctx); err != nil {
		return err
	}
	installerDPCs := n.listPublishedDPCs(runDevicePortConfigDir)
	haveBootstrapConf := fileutils.FileExists(n.Log, types.BootstrapConfFileName)
	expectBootstrapDPCs := len(installerDPCs) > 0 || haveBootstrapConf
	if err = n.dpcManager.Run(ctx, expectBootstrapDPCs); err != nil {
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

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunTime)
	n.PubSub.StillRunning(agentName, warningTime, errorTime)

	// Publish metrics for zedagent every 10 seconds
	interval := 10 * time.Second
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	// Periodically resolve the controller hostname to keep its DNS entry cached,
	// reducing the need for DNS lookups on every controller API request.
	go n.runResolverCacheForController()

	// Activate all subscriptions now.
	inactiveSubs := []pubsub.Subscription{
		n.subControllerCert,
		n.subEdgeNodeCert,
		n.subOnboardStatus,
		n.subEdgeNodeClusterStatus,
		n.subDevicePortConfigM,
		n.subDevicePortConfigO,
		n.subDevicePortConfigA,
		n.subZedAgentStatus,
		n.subAssignableAdapters,
		n.subWwanStatus,
		n.subNetworkInstanceConfig,
		n.subKubeUserServices,
	}
	for _, sub := range inactiveSubs {
		if err = sub.Activate(); err != nil {
			return err
		}
	}

	for {
		select {
		case change := <-n.subControllerCert.MsgChan():
			n.subControllerCert.ProcessChange(change)

		case change := <-n.subEdgeNodeClusterStatus.MsgChan():
			n.subEdgeNodeClusterStatus.ProcessChange(change)

		case change := <-n.subEdgeNodeCert.MsgChan():
			n.subEdgeNodeCert.ProcessChange(change)

		case change := <-n.subGlobalConfig.MsgChan():
			n.subGlobalConfig.ProcessChange(change)

		case change := <-n.subDevicePortConfigM.MsgChan():
			n.subDevicePortConfigM.ProcessChange(change)

		case change := <-n.subDevicePortConfigA.MsgChan():
			n.subDevicePortConfigA.ProcessChange(change)

		case change := <-n.subDevicePortConfigO.MsgChan():
			n.subDevicePortConfigO.ProcessChange(change)

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

		case change := <-n.subKubeUserServices.MsgChan():
			n.subKubeUserServices.ProcessChange(change)

		case <-publishTimer.C:
			start := time.Now()
			err = n.cipherMetrics.Publish(n.Log, n.pubCipherMetrics, "global")
			if err != nil {
				n.Log.Error(err)
			}
			err = n.agentMetrics.Publish(n.Log, n.pubAgentMetrics, "global")
			if err != nil {
				n.Log.Error(err)
			}
			n.PubSub.CheckMaxTimeTopic(agentName, "publishTimer", start,
				warningTime, errorTime)

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

	n.pubAgentMetrics, err = n.PubSub.NewPublication(
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
	// 1. A request from monitor TUI application (manual override)
	// 2. zedagent publishing DevicePortConfig (received from controller or LOC)
	// 3. override file in /run/global/DevicePortConfig/*.json
	n.subDevicePortConfigM, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "monitor",
		MyAgentName:   agentName,
		TopicImpl:     types.DevicePortConfig{},
		Persistent:    false,
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

	// Subscribe to EdgeNodeClusterStatus to get the cluster interface and the cluster
	// IP address which DPC Reconciler should assign statically.
	n.subEdgeNodeClusterStatus, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedkube",
		MyAgentName:   agentName,
		TopicImpl:     types.EdgeNodeClusterStatus{},
		Activate:      false,
		CreateHandler: n.handleEdgeNodeClusterStatusCreate,
		ModifyHandler: n.handleEdgeNodeClusterStatusModify,
		DeleteHandler: n.handleEdgeNodeClusterStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	// Subscribe to KubeUserServices to get the Kubernetes services and ingresses
	// for firewall configuration.
	n.subKubeUserServices, err = n.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedkube",
		MyAgentName:   agentName,
		TopicImpl:     types.KubeUserServices{},
		Activate:      false,
		CreateHandler: n.handleKubeUserServicesCreate,
		ModifyHandler: n.handleKubeUserServicesModify,
		DeleteHandler: n.handleKubeUserServicesDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
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
	n.gcInitialized = true
}

// handleDPCCreate handles three different sources in this priority order:
// 1. A request from monitor TUI application
// 2. DPC from zedagent (received from the controller or LOC)
// 3. "override"/"usb" key from build or USB stick file
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
	// if device can connect to controller it may get a new DPC in global config. This global DPC
	// will have higher priority but can be invalid and the device will loose connectivity again
	// at least temporarily while DPC is being tested. To avoid this we reset the timestamp on
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
	n.dpcManager.UpdateLOCUrl(zedagentStatus.LOCUrl)
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

func (n *nim) handleEdgeNodeClusterStatusCreate(_ interface{}, _ string,
	statusArg interface{}) {
	status := statusArg.(types.EdgeNodeClusterStatus)
	n.dpcManager.UpdateClusterStatus(status)
}

func (n *nim) handleEdgeNodeClusterStatusModify(_ interface{}, _ string,
	statusArg, _ interface{}) {
	status := statusArg.(types.EdgeNodeClusterStatus)
	n.dpcManager.UpdateClusterStatus(status)
}

func (n *nim) handleEdgeNodeClusterStatusDelete(_ interface{}, _ string, _ interface{}) {
	// Apply empty cluster status, which effectively removes the cluster IP.
	n.dpcManager.UpdateClusterStatus(types.EdgeNodeClusterStatus{})
}

func (n *nim) handleKubeUserServicesCreate(_ interface{}, _ string,
	statusArg interface{}) {
	services := statusArg.(types.KubeUserServices)
	n.dpcManager.UpdateKubeUserServices(services)
}

func (n *nim) handleKubeUserServicesModify(_ interface{}, _ string,
	statusArg, _ interface{}) {
	services := statusArg.(types.KubeUserServices)
	n.dpcManager.UpdateKubeUserServices(services)
}

func (n *nim) handleKubeUserServicesDelete(_ interface{}, _ string, _ interface{}) {
	// Apply empty services, which effectively removes all services and ingresses.
	n.dpcManager.UpdateKubeUserServices(types.KubeUserServices{})
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
