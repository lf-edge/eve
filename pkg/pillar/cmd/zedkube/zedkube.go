// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
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

type zedkubeContext struct {
	agentbase.AgentBase
	globalConfig             *types.ConfigItemValueMap
	subAppInstanceConfig     pubsub.Subscription
	subGlobalConfig          pubsub.Subscription
	networkInstanceStatusMap sync.Map
	ioAdapterMap             sync.Map
	config                   *rest.Config
	appLogStarted            bool
	appContainerLogger       *logrus.Logger
}

// Run - an zedkube run
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	zedkubeCtx := zedkubeContext{
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

	err = kubeapi.WaitForKubernetes(agentName, ps, stillRunning)
	if err != nil {
		log.Errorf("zedkube: WaitForKubenetes %v", err)
	}
	zedkubeCtx.config, err = kubeapi.GetKubeConfig()
	if err != nil {
		log.Errorf("zedkube: GetKubeConfi %v", err)
	} else {
		log.Noticef("zedkube: running")
	}

	appLogTimer := time.NewTimer(logcollectInterval * time.Second)

	for {
		select {
		case change := <-subAppInstanceConfig.MsgChan():
			subAppInstanceConfig.ProcessChange(change)

		case <-appLogTimer.C:
			collectAppLogs(&zedkubeCtx)
			appLogTimer = time.NewTimer(logcollectInterval * time.Second)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleAppInstanceConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.AppInstanceConfig)

	log.Functionf("handleAppInstanceConfigCreate(%v) spec for %s",
		config.UUIDandVersion, config.DisplayName)

	err := checkIoAdapterEthernet(ctx, &config)
	log.Functionf("handleAppInstancConfigModify: genAISpec %v", err)
}

func handleAppInstanceConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.AppInstanceConfig)
	oldconfig := oldConfigArg.(types.AppInstanceConfig)

	log.Functionf("handleAppInstancConfigModify(%v) spec for %s",
		config.UUIDandVersion, config.DisplayName)

	err := checkIoAdapterEthernet(ctx, &config)

	if oldconfig.RemoteConsole != config.RemoteConsole {
		log.Functionf("handleAppInstancConfigModify: new remote console %v", config.RemoteConsole)
		go runAppVNC(ctx, &config)
	}
	log.Functionf("handleAppInstancConfigModify: genAISpec %v", err)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleAppInstanceConfigDelete(%s)", key)
	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.AppInstanceConfig)

	checkDelIoAdapterEthernet(ctx, &config)
	log.Functionf("handleAppInstanceConfigDelete(%s) done", key)
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

	ctx := ctxArg.(*zedkubeContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	_ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, ctx.Logger())
	log.Functionf("handleGlobalConfigImpl(%s): done", key)
}
