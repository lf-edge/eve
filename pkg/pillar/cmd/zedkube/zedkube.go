// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
)

const (
	agentName = "zedkube"
	// Time limits for event loop handlers
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	stillRunningInterval = 25 * time.Second
	logcollectInterval   = 30
	// run VNC file
	vmiVNCFileName = "/run/zedkube/vmiVNC.run"
)

var (
	logger *logrus.Logger
	log    *base.LogObject
)

// GetKubePodsError is used to check and handle get kube pods error
type GetKubePodsError struct {
	getKubePodsErrorTime    time.Time
	processedErrorCondition bool
}

type zedkube struct {
	agentbase.AgentBase
	globalConfig             *types.ConfigItemValueMap
	subAppInstanceConfig     pubsub.Subscription
	subGlobalConfig          pubsub.Subscription
	subDeviceNetworkStatus   pubsub.Subscription
	subEdgeNodeClusterConfig pubsub.Subscription
	subEdgeNodeInfo          pubsub.Subscription
	subZedAgentStatus        pubsub.Subscription

	subControllerCert    pubsub.Subscription
	subEdgeNodeCert      pubsub.Subscription
	cipherMetrics        *cipher.AgentMetrics
	pubCipherBlockStatus pubsub.Publication
	pubCipherMetrics     pubsub.Publication

	pubEdgeNodeClusterStatus pubsub.Publication
	pubENClusterAppStatus    pubsub.Publication
	pubKubeClusterInfo       pubsub.Publication
	pubLeaderElectInfo       pubsub.Publication

	subNodeDrainRequestZA  pubsub.Subscription
	subNodeDrainRequestBoM pubsub.Subscription
	pubNodeDrainStatus     pubsub.Publication

	networkInstanceStatusMap sync.Map
	ioAdapterMap             sync.Map
	deviceNetworkStatus      types.DeviceNetworkStatus
	clusterConfig            types.EdgeNodeClusterConfig
	config                   *rest.Config
	appLogStarted            bool
	appContainerLogger       *logrus.Logger
	clusterIPIsReady         bool
	nodeuuid                 string
	nodeName                 string
	isKubeStatsLeader        atomic.Bool
	inKubeLeaderElection     atomic.Bool
	electionFuncRunning      atomic.Bool
	leaderIdentity           string
	electionStartCh          chan struct{}
	electionStopCh           chan struct{}
	statusServer             *http.Server
	statusServerWG           sync.WaitGroup
	getKubePodsError         GetKubePodsError
	drainOverrideTimer       *time.Timer

	// Config Properties for Drain
	drainTimeoutHours                  uint32
	drainSkipK8sAPINotReachableTimeout uint32

	// Block 'uncordon' after running it once at bootup
	onBootUncordonCheckComplete bool
}

// Run - an zedkube run
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	zedkubeCtx := zedkube{
		globalConfig: types.DefaultConfigItemValueMap(),
	}
	agentbase.Init(&zedkubeCtx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningInterval)

	zedkubeCtx.appContainerLogger = agentlog.CustomLogInit(logrus.InfoLevel)

	// Get AppInstanceConfig from zedagent
	subAppInstanceConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceConfig{},
		Activate:      false,
		Ctx:           &zedkubeCtx,
		CreateHandler: handleAppInstanceConfigCreate,
		ModifyHandler: handleAppInstanceConfigModify,
		DeleteHandler: handleAppInstanceConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subAppInstanceConfig = subAppInstanceConfig
	subAppInstanceConfig.Activate()

	// Look for controller certs which will be used for decryption.
	subControllerCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.ControllerCert{},
		Persistent:  true,
		Activate:    true,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subControllerCert = subControllerCert

	// Look for edge node certs which will be used for decryption
	subEdgeNodeCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeCert{},
		Persistent:  true,
		Activate:    true,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subEdgeNodeCert = subEdgeNodeCert

	pubCipherBlockStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.CipherBlockStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.pubCipherBlockStatus = pubCipherBlockStatus
	pubCipherBlockStatus.ClearRestarted()

	pubEdgeNodeClusterStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.EdgeNodeClusterStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.pubEdgeNodeClusterStatus = pubEdgeNodeClusterStatus

	pubENClusterAppStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.ENClusterAppStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.pubENClusterAppStatus = pubENClusterAppStatus

	pubKubeClusterInfo, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.KubeClusterInfo{},
		})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.pubKubeClusterInfo = pubKubeClusterInfo

	pubLeaderElectInfo, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.KubeLeaderElectInfo{},
		})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.pubLeaderElectInfo = pubLeaderElectInfo

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &zedkubeCtx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Watch DNS to learn if the Cluster Interface and Cluster Prefix is ready to use
	subDeviceNetworkStatus, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "nim",
			MyAgentName:   agentName,
			TopicImpl:     types.DeviceNetworkStatus{},
			Activate:      false,
			Ctx:           &zedkubeCtx,
			CreateHandler: handleDNSCreate,
			ModifyHandler: handleDNSModify,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	zedkubeCtx.cipherMetrics = cipher.NewAgentMetrics(agentName)
	pubCipherMetrics, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.CipherMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.pubCipherMetrics = pubCipherMetrics

	// Look for edge node info
	subEdgeNodeInfo, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeInfo{},
		Persistent:  true,
		Activate:    false,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subEdgeNodeInfo = subEdgeNodeInfo
	subEdgeNodeInfo.Activate()

	// start the leader election
	zedkubeCtx.electionStartCh = make(chan struct{}, 1)
	zedkubeCtx.electionStopCh = make(chan struct{}, 1)
	go zedkubeCtx.handleLeaderElection()

	// Wait for the certs, and nodeInfo which are needed to decrypt the token inside the
	// cluster config and other operations
	var controllerCertInitialized, edgenodeCertInitialized, edgenodeInfoInitialized bool
	for !controllerCertInitialized || !edgenodeCertInitialized || !edgenodeInfoInitialized {
		log.Noticef("zedkube run: waiting for controller cert (initialized=%t), "+
			"edgenode cert (initialized=%t), edgenode info (initialized=%t)", controllerCertInitialized,
			edgenodeCertInitialized, edgenodeInfoInitialized)
		select {
		case change := <-subControllerCert.MsgChan():
			subControllerCert.ProcessChange(change)
			controllerCertInitialized = true

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)
			edgenodeCertInitialized = true

		case change := <-subEdgeNodeInfo.MsgChan():
			subEdgeNodeInfo.ProcessChange(change)
			edgenodeInfoInitialized = zedkubeCtx.checkAndSaveEdgeNodeInfo()

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Noticef("zedkube run: controller and edge node certs are ready")

	//
	// NodeDrainRequest subscriber and NodeDrainStatus publisher
	//
	// Sub the request
	zedkubeCtx.subNodeDrainRequestZA, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleNodeDrainRequestCreate,
		ModifyHandler: handleNodeDrainRequestModify,
		DeleteHandler: handleNodeDrainRequestDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     kubeapi.NodeDrainRequest{},
		Ctx:           &zedkubeCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	kubeapi.CleanupDrainStatusOverride(log)
	zedkubeCtx.subNodeDrainRequestZA.Activate()

	// Sub the request
	zedkubeCtx.subNodeDrainRequestBoM, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleNodeDrainRequestCreate,
		ModifyHandler: handleNodeDrainRequestModify,
		DeleteHandler: handleNodeDrainRequestDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "baseosmgr",
		MyAgentName:   agentName,
		TopicImpl:     kubeapi.NodeDrainRequest{},
		Ctx:           &zedkubeCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subNodeDrainRequestBoM.Activate()

	//Pub the status
	zedkubeCtx.pubNodeDrainStatus, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: kubeapi.NodeDrainStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}

	zedkubeCtx.drainOverrideTimer = time.NewTimer(5 * time.Minute)
	zedkubeCtx.drainOverrideTimer.Stop()
	// Until we hear otherwise that we are in a cluster
	publishNodeDrainStatus(&zedkubeCtx, kubeapi.NOTSUPPORTED)
	// EdgeNodeClusterConfig create needs to publish NodeDrainStatus, so wait to activate it.

	// EdgeNodeClusterConfig subscription
	subEdgeNodeClusterConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.EdgeNodeClusterConfig{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &zedkubeCtx,
		CreateHandler: handleEdgeNodeClusterConfigCreate,
		ModifyHandler: handleEdgeNodeClusterConfigModify,
		DeleteHandler: handleEdgeNodeClusterConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subEdgeNodeClusterConfig = subEdgeNodeClusterConfig
	subEdgeNodeClusterConfig.Activate()

	if len(subEdgeNodeClusterConfig.GetAll()) != 0 {
		// Handle persistent existing cluster config
		publishNodeDrainStatus(&zedkubeCtx, kubeapi.NOTREQUESTED)
	}

	zedkubeCtx.config, err = kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("zedkube: GetKubeConfig %v", err)
	} else {
		log.Noticef("zedkube: running")
	}

	// subscribe to zedagent status events, for controller connection status
	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           &zedkubeCtx,
		CreateHandler: handleZedAgentStatusCreate,
		ModifyHandler: handleZedAgentStatusModify,
		DeleteHandler: handleZedAgentStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	err = kubeapi.WaitForKubernetes(agentName, ps, stillRunning,
		// Make sure we keep ClusterIPIsReady up to date while we wait
		// for Kubernetes to come up.
		pubsub.WatchAndProcessSubChanges(subEdgeNodeClusterConfig),
		pubsub.WatchAndProcessSubChanges(subDeviceNetworkStatus))
	if err != nil {
		log.Errorf("zedkube: WaitForKubenetes %v", err)
	}

	appLogTimer := time.NewTimer(logcollectInterval * time.Second)

	log.Notice("zedkube online")

	for {
		select {
		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAppInstanceConfig.MsgChan():
			subAppInstanceConfig.ProcessChange(change)

		case <-appLogTimer.C:
			zedkubeCtx.collectAppLogs()
			zedkubeCtx.checkAppsStatus()
			zedkubeCtx.collectKubeStats()
			appLogTimer = time.NewTimer(logcollectInterval * time.Second)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subEdgeNodeClusterConfig.MsgChan():
			subEdgeNodeClusterConfig.ProcessChange(change)

		case change := <-subControllerCert.MsgChan():
			subControllerCert.ProcessChange(change)

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)

		case change := <-subEdgeNodeInfo.MsgChan():
			subEdgeNodeInfo.ProcessChange(change)

		case change := <-subZedAgentStatus.MsgChan():
			subZedAgentStatus.ProcessChange(change)

		case change := <-zedkubeCtx.subNodeDrainRequestZA.MsgChan():
			zedkubeCtx.subNodeDrainRequestZA.ProcessChange(change)

		case change := <-zedkubeCtx.subNodeDrainRequestBoM.MsgChan():
			zedkubeCtx.subNodeDrainRequestBoM.ProcessChange(change)

		case <-zedkubeCtx.drainOverrideTimer.C:
			zedkubeCtx.drainOverrideTimer.Reset(5 * time.Minute)
			override := kubeapi.GetDrainStatusOverride(log)
			if override != nil {
				publishNodeDrainPs(&zedkubeCtx, override)
			}

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleAppInstanceConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	z := ctxArg.(*zedkube)
	config := configArg.(types.AppInstanceConfig)

	log.Functionf("handleAppInstanceConfigCreate(%v) spec for %s",
		config.UUIDandVersion, config.DisplayName)

	err := z.checkIoAdapterEthernet(&config)
	log.Functionf("handleAppInstancConfigModify: genAISpec %v", err)
}

func handleAppInstanceConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	z := ctxArg.(*zedkube)
	config := configArg.(types.AppInstanceConfig)
	oldconfig := oldConfigArg.(types.AppInstanceConfig)

	log.Functionf("handleAppInstancConfigModify(%v) spec for %s",
		config.UUIDandVersion, config.DisplayName)

	err := z.checkIoAdapterEthernet(&config)

	if oldconfig.RemoteConsole != config.RemoteConsole {
		log.Functionf("handleAppInstancConfigModify: new remote console %v", config.RemoteConsole)
		go z.runAppVNC(&config)
	}
	log.Functionf("handleAppInstancConfigModify: genAISpec %v", err)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleAppInstanceConfigDelete(%s)", key)
	z := ctxArg.(*zedkube)
	config := configArg.(types.AppInstanceConfig)

	z.checkDelIoAdapterEthernet(&config)
	log.Functionf("handleAppInstanceConfigDelete(%s) done", key)

	// remove the cluster app status publication
	pub := z.pubENClusterAppStatus
	stItmes := pub.GetAll()
	for _, st := range stItmes {
		aiStatus := st.(types.ENClusterAppStatus)
		if aiStatus.AppUUID == config.UUIDandVersion.UUID {
			z.pubENClusterAppStatus.Unpublish(config.UUIDandVersion.UUID.String())
			break
		}
	}
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	z := ctxArg.(*zedkube)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, z.subGlobalConfig, agentName,
		z.CLIParams().DebugOverride, z.Logger())
	if gcp != nil {
		currentConfigItemValueMap := z.globalConfig
		newConfigItemValueMap := gcp

		// Handle Drain Timeout Change
		newDrainTimeout := newConfigItemValueMap.GlobalValueInt(types.KubevirtDrainTimeout)
		existingDrainTimeout := currentConfigItemValueMap.GlobalValueInt(types.KubevirtDrainTimeout)
		if newDrainTimeout != 0 && newDrainTimeout != existingDrainTimeout {
			log.Functionf("handleGlobalConfigImpl: Updating drainTimeoutHours from %d to %d",
				existingDrainTimeout, newDrainTimeout)
			z.drainTimeoutHours = newDrainTimeout
		}

		//
		// Handle cases of kubernetes node unavailability
		//
		newDrainK8sApiNotReachableTimeout := newConfigItemValueMap.GlobalValueInt(types.KubevirtDrainSkipK8sAPINotReachableTimeout)
		existingDrainK8sApiNotReachableTimeout := currentConfigItemValueMap.GlobalValueInt(types.KubevirtDrainSkipK8sAPINotReachableTimeout)
		if newDrainK8sApiNotReachableTimeout != 0 && newDrainK8sApiNotReachableTimeout != existingDrainK8sApiNotReachableTimeout {
			log.Functionf("handleGlobalConfigImpl: Updating drainSkipK8sApiTimeout from %d to %d",
				existingDrainK8sApiNotReachableTimeout, newDrainK8sApiNotReachableTimeout)
			z.drainSkipK8sAPINotReachableTimeout = newDrainK8sApiNotReachableTimeout
		}
	}
	log.Functionf("handleGlobalConfigImpl(%s): done", key)
}

func handleEdgeNodeClusterConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Functionf("handleEdgeNodeClusterConfigCreate: %s", key)
	handleEdgeNodeClusterConfigImpl(ctxArg, key, configArg, nil)
}

func handleEdgeNodeClusterConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	log.Functionf("handleEdgeNodeClusterConfigModify: %s", key)
	handleEdgeNodeClusterConfigImpl(ctxArg, key, configArg, oldConfigArg)
}

func handleEdgeNodeClusterConfigImpl(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	var config, oldconfig types.EdgeNodeClusterConfig
	var oldConfigPtr *types.EdgeNodeClusterConfig
	config = configArg.(types.EdgeNodeClusterConfig)
	if oldConfigArg != nil {
		oldconfig = oldConfigArg.(types.EdgeNodeClusterConfig)
		oldConfigPtr = &oldconfig
	}

	z := ctxArg.(*zedkube)
	log.Functionf("handleEdgeNodeClusterConfigImpl for %s, config %+v, oldconfig %+v",
		key, config, oldconfig)

	z.applyClusterConfig(&config, oldConfigPtr)

	publishNodeDrainStatus(z, kubeapi.NOTREQUESTED)
}

func handleEdgeNodeClusterConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	z := ctxArg.(*zedkube)
	log.Functionf("handleEdgeNodeClusterConfigDelete for %s", key)
	config := statusArg.(types.EdgeNodeClusterConfig)
	z.applyClusterConfig(nil, &config)
	z.pubEdgeNodeClusterStatus.Unpublish("global")
	publishNodeDrainStatus(z, kubeapi.NOTSUPPORTED)
}

// handle zedagent status events, for cloud connectivity
func handleZedAgentStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	z := ctxArg.(*zedkube)
	status := statusArg.(types.ZedAgentStatus)
	z.handleControllerStatusChange(&status)
	log.Functionf("handleZedAgentStatusImpl: for Leader status %v, done", status)
}

func handleZedAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	// do nothing
	log.Functionf("handleZedAgentStatusDelete(%s) done", key)
}

// checkAndSaveEdgeNodeInfo checks if the device name is set in the EdgeNodeInfo
// it returns true if we got the valid EdgeNodeInfo update
func (ctx *zedkube) checkAndSaveEdgeNodeInfo() bool {
	items := ctx.subEdgeNodeInfo.GetAll()
	if len(items) > 0 {
		for _, item := range items {
			enInfo := item.(types.EdgeNodeInfo)
			if enInfo.DeviceName != "" {
				log.Noticef("checkAndSaveEdgeNodeInfo: found devicename %s", enInfo.DeviceName)
				ctx.nodeName = strings.ReplaceAll(strings.ToLower(enInfo.DeviceName), "_", "-")
				ctx.nodeuuid = enInfo.DeviceID.String()
				if ctx.nodeName != "" && ctx.nodeuuid != "" {
					//Re-enable local node
					if !ctx.onBootUncordonCheckComplete {
						go nodeOnBootHealthStatusWatcher(ctx)
					}
					return true
				}
			}
		}
	}
	return false
}

// It may be a while until the node is ready to be uncordoned
// so we'll keep trying until it is
func nodeOnBootHealthStatusWatcher(z *zedkube) {
	// Assume we're cordoned until we know otherwise
	cordoned := true

	// Loop until it is uncordoned once to allow for later
	// cordon operations to be successful
	for cordoned {
		time.Sleep(15 * time.Second)

		// Get the local kubernetes node health status
		node, err := getLocalNode(z.nodeuuid)
		if node == nil || err != nil {
			continue
		}

		// Is the node is ready?
		var ready bool = false
		for _, condition := range node.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				ready = true
			}
		}
		if !ready {
			continue
		}

		cordoned, err = isNodeCordoned(z.nodeuuid)
		if err != nil {
			log.Errorf("zedkube can't read local node cordon state, err:%v", err)
			continue
		}

		if !cordoned {
			// Block this from running again this boot.
			z.onBootUncordonCheckComplete = true
		}

		if err = cordonNode(z.nodeuuid, false); err != nil {
			log.Errorf("zedkube Unable to uncordon local node: %v", err)
		}
	}
}
