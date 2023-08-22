package zedkube

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/client-go/rest"
)

const (
	agentName = "zedkube"
	// Time limits for event loop handlers
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	stillRunningInterval = 25 * time.Second
	logcollectInterval   = 30
)

var (
	logger *logrus.Logger
	log    *base.LogObject
)

type zedkubeContext struct {
	agentbase.AgentBase
	globalConfig             *types.ConfigItemValueMap
	subNetworkInstanceStatus pubsub.Subscription
	subAppInstanceConfig     pubsub.Subscription
	subContentTreeStatus     pubsub.Subscription
	subGlobalConfig          pubsub.Subscription
	pubNetworkInstanceStatus pubsub.Publication
	pubAppNetworkConfig      pubsub.Publication
	pubDomainMetric          pubsub.Publication
	networkInstanceStatusMap sync.Map
	ioAdapterMap             sync.Map
	config                   *rest.Config
	appNetConfig             map[string]*types.AppNetworkConfig
	resendNITimer            *time.Timer
	appMetricsTimer          *time.Timer
	appLogStarted            bool
	appContainerLogger       *logrus.Logger
}

// Run - an zedkube run
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
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

	subNetworkInstanceStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		MyAgentName:   agentName,
		Ctx:           &zedkubeCtx,
		TopicImpl:     types.NetworkInstanceStatus{},
		CreateHandler: handleNetworkInstanceCreate,
		ModifyHandler: handleNetworkInstanceModify,
		DeleteHandler: handleNetworkInstanceDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		Activate:      false,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subNetworkInstanceStatus = subNetworkInstanceStatus
	subNetworkInstanceStatus.Activate()

	pubNetworkInstanceStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkInstanceStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.pubNetworkInstanceStatus = pubNetworkInstanceStatus

	pubAppNetworkConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppNetworkConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.pubAppNetworkConfig = pubAppNetworkConfig
	pubAppNetworkConfig.ClearRestarted()

	pubDomainMetric, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DomainMetric{},
		})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.pubDomainMetric = pubDomainMetric

	subContentTreeStatus, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "volumemgr",
			MyAgentName:   agentName,
			TopicImpl:     types.ContentTreeStatus{},
			Activate:      false,
			Ctx:           &zedkubeCtx,
			CreateHandler: handleContentTreeStatusCreate,
			ModifyHandler: handleContentTreeStatusModify,
			DeleteHandler: handleContentTreeStatusDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	zedkubeCtx.subContentTreeStatus = subContentTreeStatus
	subContentTreeStatus.Activate()

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

	//zedkubeCtx.configWait = make(map[string]bool)
	zedkubeCtx.appNetConfig = make(map[string]*types.AppNetworkConfig)

	config, err := kubeapi.WaitKubernetes(agentName, ps, stillRunning)
	if err != nil {
		// XXX may need to change this to loop
		log.Fatal(err)
	}
	zedkubeCtx.config = config
	log.Noticef("zedkube run: kubernetes running")

	zedkubeCtx.resendNITimer = time.NewTimer(5 * time.Second)
	zedkubeCtx.resendNITimer.Stop()

	zedkubeCtx.appMetricsTimer = time.NewTimer(10 * time.Second)

	appLogTimer := time.NewTimer(logcollectInterval * time.Second)

	go appNetStatusNotify(&zedkubeCtx)

	for {
		select {
		case change := <-subNetworkInstanceStatus.MsgChan():
			subNetworkInstanceStatus.ProcessChange(change)
			//checkWaitedNIStatus(&zedkubeCtx)

		case change := <-subAppInstanceConfig.MsgChan():
			subAppInstanceConfig.ProcessChange(change)

		case <-zedkubeCtx.resendNITimer.C:
			resendNIToCluster(&zedkubeCtx)

		case <-zedkubeCtx.appMetricsTimer.C:
			publishAppMetrics(&zedkubeCtx)
			zedkubeCtx.appMetricsTimer = time.NewTimer(10 * time.Second)

		case <-appLogTimer.C:
			collectAppLogs(&zedkubeCtx)
			appLogTimer = time.NewTimer(logcollectInterval * time.Second)

		case change := <-zedkubeCtx.subContentTreeStatus.MsgChan():
			zedkubeCtx.subContentTreeStatus.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func lookupNIStatusForNAD(ctx *zedkubeContext, netUUID string) string {
	var status *types.NetworkInstanceStatus
	ctx.networkInstanceStatusMap.Range(func(key, value interface{}) bool {
		st := value.(*types.NetworkInstanceStatus)
		if st.UUID.String() == netUUID {
			status = st
			return false
		}
		return true
	})

	if status != nil {
		return strings.ToLower(status.DisplayName)
	}
	return ""
}

func lookupNIStatusFromName(ctx *zedkubeContext, niName string) *types.NetworkInstanceStatus {
	var status *types.NetworkInstanceStatus
	ctx.networkInstanceStatusMap.Range(func(key, value interface{}) bool {
		st := value.(*types.NetworkInstanceStatus)
		if niName == strings.ToLower(st.DisplayName) {
			status = st
			return false
		}
		return true
	})

	return status
}

func handleNetworkInstanceCreate(
	ctxArg interface{},
	key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedkubeContext)
	status := configArg.(types.NetworkInstanceStatus)

	log.Noticef("handleNetworkInstanceCreate: (UUID: %s, name:%s)\n",
		key, status.DisplayName) // XXX Functionf

	err := genNISpecCreate(ctx, &status)
	log.Noticef("handleNetworkInstanceCreate: spec create %v", err)
	checkNISendStatus(ctx, &status, err)
}

func handleNetworkInstanceModify(
	ctxArg interface{},
	key string,
	statusArg interface{},
	oldStatusArg interface{}) {

	ctx := ctxArg.(*zedkubeContext)
	status := statusArg.(types.NetworkInstanceStatus)
	log.Noticef("handleNetworkInstanceModify: (UUID: %s, name:%s)\n",
		key, status.DisplayName)
	err := genNISpecCreate(ctx, &status)
	log.Noticef("handleNetworkInstanceModify: spec modify %v", err)
	checkNISendStatus(ctx, &status, err)
}

func resendNIToCluster(ctx *zedkubeContext) {
	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, item := range items {
		status := item.(types.NetworkInstanceStatus)
		if status.Activated {
			continue
		}
		err := genNISpecCreate(ctx, &status)
		log.Noticef("resendNIToCluster: spec %v", err)
		checkNISendStatus(ctx, &status, err)
	}
}

func checkNISendStatus(ctx *zedkubeContext, status *types.NetworkInstanceStatus, err error) {
	if err != nil {
		status.Activated = false
		ctx.resendNITimer = time.NewTimer(10 * time.Second)
	} else {
		status.Activated = true
	}
	publishNetworkInstanceStatus(ctx, status)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Noticef("handleNetworkInstanceDelete(%s)\n", key) // XXX Functionf
	ctx := ctxArg.(*zedkubeContext)
	status := configArg.(types.NetworkInstanceStatus)
	nadName := strings.ToLower(status.DisplayName)
	genNISpecDelete(ctx, nadName)
}

func kubeGetNIStatus(ctx *zedkubeContext, niUUID uuid.UUID) (*types.NetworkInstanceStatus, error) {

	sub := ctx.subNetworkInstanceStatus
	niItems := sub.GetAll()
	for _, item := range niItems {
		status := item.(types.NetworkInstanceStatus)
		if uuid.Equal(status.UUID, niUUID) {
			return &status, nil
		}
	}

	return nil, fmt.Errorf("kubeGetNIStatus: NI %v, spec status not found", niUUID)
}

func handleAppInstanceConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.AppInstanceConfig)

	log.Noticef("handleAppInstanceConfigCreate(%v) spec for %s, contentid %s",
		config.UUIDandVersion, config.DisplayName, config.ContentID)

	err := genAISpecCreate(ctx, &config)
	log.Noticef("handleAppInstancConfigModify: genAISpec %v", err)
}

func handleAppInstanceConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.AppInstanceConfig)

	log.Noticef("handleAppInstancConfigCreate(%v) spec for %s, contentid %s",
		config.UUIDandVersion, config.DisplayName, config.ContentID)

	err := genAISpecCreate(ctx, &config)
	log.Noticef("handleAppInstancConfigModify: genAISpec %v", err)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleAppInstanceConfigDelete(%s)", key)
	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.AppInstanceConfig)

	aiSpecDelete(ctx, &config)
	log.Functionf("handleAppInstanceConfigDelete(%s) done", key)
}

func publishNetworkInstanceStatus(ctx *zedkubeContext,
	status *types.NetworkInstanceStatus) {

	ctx.networkInstanceStatusMap.Store(status.UUID, status)
	pub := ctx.pubNetworkInstanceStatus
	pub.Publish(status.Key(), *status)
}

func handleContentTreeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleContentTreeStatusImpl(ctxArg, key, statusArg)
}

func handleContentTreeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleContentTreeStatusImpl(ctxArg, key, statusArg)
}

func handleContentTreeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	// XXX comment out
	//handleContentTreeStatusImpl(ctxArg, key, statusArg)
}

func handleContentTreeStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.ContentTreeStatus)
	ctx := ctxArg.(*zedkubeContext)
	log.Functionf("handleContentTreeStatusImpl: key:%s, name:%s",
		key, status.DisplayName)

	if status.OciImageName != "" {
		sub := ctx.subAppInstanceConfig
		items := sub.GetAll()
		for _, item := range items {
			aiconfig := item.(types.AppInstanceConfig)
			if aiconfig.ContentID == status.ContentID.String() {
				log.Noticef("handleContentTreeStatusImpl: found aiconfig")
				genAISpecCreate(ctx, &aiconfig)
			}
		}
	}
	log.Noticef("handleContentTreeStatusImpl done for %s", key)
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
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, ctx.Logger())
	if gcp != nil {
		ctx.globalConfig = gcp
	}
	log.Functionf("handleGlobalConfigImpl(%s): done", key)
}

func bringupInterface(intfName string) {
	link, err := netlink.LinkByName(intfName)
	if err != nil {
		log.Errorf("bringupInterface: %v", err)
		return
	}

	// Set the IFF_UP flag to bring up the interface
	if err := netlink.LinkSetUp(link); err != nil {
		log.Errorf("bringupInterface: %v", err)
		return
	}
}
