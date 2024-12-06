// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"net/http"
	"strings"
	"sync"
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
	isKubeStatsLeader        bool
	inKubeLeaderElection     bool
	electionStartCh          chan struct{}
	electionStopCh           chan struct{}
	statusServer             *http.Server
	statusServerWG           sync.WaitGroup
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

	// start the leader election
	zedkubeCtx.electionStartCh = make(chan struct{})
	zedkubeCtx.electionStopCh = make(chan struct{})
	go zedkubeCtx.handleLeaderElection()

	// Wait for the certs, which are needed to decrypt the token inside the cluster config.
	var controllerCertInitialized, edgenodeCertInitialized bool
	for !controllerCertInitialized || !edgenodeCertInitialized {
		log.Noticef("zedkube run: waiting for controller cert (initialized=%t), "+
			"edgenode cert (initialized=%t)", controllerCertInitialized,
			edgenodeCertInitialized)
		select {
		case change := <-subControllerCert.MsgChan():
			subControllerCert.ProcessChange(change)
			controllerCertInitialized = true

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)
			edgenodeCertInitialized = true

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Noticef("zedkube run: controller and edge node certs are ready")

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

	zedkubeCtx.config, err = kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("zedkube: GetKubeConfig %v", err)
	} else {
		log.Noticef("zedkube: running")
	}

	// Look for edge node info
	subEdgeNodeInfo, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.EdgeNodeInfo{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &zedkubeCtx,
		CreateHandler: handleEdgeNodeInfoCreate,
		ModifyHandler: handleEdgeNodeInfoModify,
		DeleteHandler: handleEdgeNodeInfoDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subEdgeNodeInfo = subEdgeNodeInfo
	subEdgeNodeInfo.Activate()

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
	_ = agentlog.HandleGlobalConfig(log, z.subGlobalConfig, agentName,
		z.CLIParams().DebugOverride, z.Logger())
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
}

func handleEdgeNodeClusterConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	z := ctxArg.(*zedkube)
	log.Functionf("handleEdgeNodeClusterConfigDelete for %s", key)
	config := statusArg.(types.EdgeNodeClusterConfig)
	z.applyClusterConfig(nil, &config)
	z.pubEdgeNodeClusterStatus.Unpublish("global")
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

func handleEdgeNodeInfoCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleEdgeNodeInfoImpl(ctxArg, key, statusArg)
}

func handleEdgeNodeInfoModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleEdgeNodeInfoImpl(ctxArg, key, statusArg)
}

func handleEdgeNodeInfoImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	z := ctxArg.(*zedkube)
	nodeInfo := statusArg.(types.EdgeNodeInfo)
	if err := z.getnodeNameAndUUID(); err != nil {
		log.Errorf("handleEdgeNodeInfoImpl: getnodeNameAndUUID failed: %v", err)
		return
	}

	z.nodeName = strings.ToLower(nodeInfo.DeviceName)
	z.nodeuuid = nodeInfo.DeviceID.String()
}

func handleEdgeNodeInfoDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	// do nothing?
	log.Functionf("handleEdgeNodeInfoDelete(%s) done", key)
}
