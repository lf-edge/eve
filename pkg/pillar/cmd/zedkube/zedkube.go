package zedkube

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	agentName = "zedkube"
	// Time limits for event loop handlers
	errorTime           = 3 * time.Minute
	warningTime         = 40 * time.Second
	stillRunningInerval = 25 * time.Second
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
	pubNetworkInstanceStatus pubsub.Publication
	pubAppNetworkConfig      pubsub.Publication
	pubDomainMetric          pubsub.Publication
	networkInstanceStatusMap sync.Map
	config                   *rest.Config
	appNetConfig             map[string]*types.AppNetworkConfig
	resendNITimer            *time.Timer
	appMetricsTimer          *time.Timer
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
	stillRunning := time.NewTicker(stillRunningInerval)

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

	//zedkubeCtx.configWait = make(map[string]bool)
	zedkubeCtx.appNetConfig = make(map[string]*types.AppNetworkConfig)

	checkTimer := time.NewTimer(5 * time.Second)
	configFileExist := false

	// wait until k3s server is started
	for !configFileExist {
		select {
		case <-checkTimer.C:
			if _, err := os.Stat(kubeConfigFile); err == nil {
				err = getKubeConfig(&zedkubeCtx)
				if err == nil {
					configFileExist = true
					break
				}
			}
			checkTimer = time.NewTimer(5 * time.Second)
		}
	}

	client, err := kubernetes.NewForConfig(zedkubeCtx.config)
	if err != nil {
		log.Errorf("Run: Failed to create clientset: %v", err)
	} else { // wait for ready
		readyCh := make(chan bool)

		go waitForNodeReady(client, readyCh)
		select {
		case isReady := <-readyCh:
			log.Noticef("Run: doprint, node %v", isReady)
		}
	}

	zedkubeCtx.resendNITimer = time.NewTimer(5 * time.Second)
	zedkubeCtx.resendNITimer.Stop()

	zedkubeCtx.appMetricsTimer = time.NewTimer(10 * time.Second)

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
	// XXX ctx := ctxArg.(*zedkubeContext)
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

	log.Noticef("handleAppInstanceConfigCreate(%v) spec for %s, url %s",
		config.UUIDandVersion, config.DisplayName, config.ImageURL)
	err := genAISpecCreate(ctx, &config)
	log.Noticef("handleAppInstancConfigModify: genAISpec %v", err)
}

func handleAppInstanceConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.AppInstanceConfig)

	log.Noticef("handleAppInstancConfigCreate(%v) spec for %s, url %s",
		config.UUIDandVersion, config.DisplayName, config.ImageURL)
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
