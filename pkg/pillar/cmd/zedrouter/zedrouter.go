// Copyright (c) 2017-2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Zedrouter creates and manages network instances - a set of virtual switches
// providing connectivity and various network services for applications.
// The configuration for these network instances comes from the controller as part
// of EdgeDevConfig. However, this is first retrieved and parsed by zedagent
// and in pieces published to corresponding microservices using pubsub channels.
// For application-specific configuration there is an extra hop through zedmanager,
// which uses pubsub to orchestrate the flow of configuration (and state) data
// between microservices directly involved in application management: volumemgr,
// domainmgr and last but not least zedrouter.
// Zedrouter subscribes specifically for NetworkInstanceConfig (from zedagent)
// and AppNetworkConfig (from zedmanager). Based on the configuration,
// it creates network instances and in cooperation with domainmgr connects
// applications to them.
// Zedrouter also collects state data and metrics, such as interface counters,
// dynamic IP assignments, flow statistics, etc. The state data are periodically
// or on-change published to zedagent to be further delivered to the controller.
// Zedrouter, NIM and wwan are 3 microservices that collectively manage all network
// services for edge node and deployed applications.

package zedrouter

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cmd/msrv"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler"
	"github.com/lf-edge/eve/pkg/pillar/nistate"
	"github.com/lf-edge/eve/pkg/pillar/objtonum"
	"github.com/lf-edge/eve/pkg/pillar/portprober"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	"github.com/sirupsen/logrus"
)

const (
	agentName  = "zedrouter"
	runDirname = "/run/zedrouter"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
	// Publish 4X more often than zedagent publishes to controller
	// to reduce effect of quantization errors
	publishTickerDivider = 4
	// After 30 min of a flow not being touched, the publication will be removed.
	flowStaleSec int64 = 1800
)

// zedrouter creates and manages network instances - a set of virtual switches
// providing connectivity and various network services for applications.
type zedrouter struct {
	agentbase.AgentBase
	pubSub *pubsub.PubSub
	logger *logrus.Logger
	log    *base.LogObject
	runCtx context.Context

	// CLI options
	enableArpSnooping  bool // enable/disable switch NI arp snooping
	localLegacyMACAddr bool // switch to legacy MAC address generation

	controllerHostname string
	controllerPort     uint16
	agentStartTime     time.Time
	receivedConfigTime time.Time
	triggerNumGC       bool // For appNum and bridgeNum

	deviceNetworkStatus *types.DeviceNetworkStatus
	subGlobalConfig     pubsub.Subscription
	gcInitialized       bool
	initReconcileDone   bool

	// Replaceable components
	// (different implementations for different network stacks)
	niStateCollector nistate.Collector
	networkMonitor   netmonitor.NetworkMonitor
	niReconciler     nireconciler.NIReconciler
	reachProberICMP  portprober.ReachabilityProber
	reachProberTCP   portprober.ReachabilityProber
	portProber       *portprober.PortProber

	// Number allocators
	appNumAllocator     *objtonum.Allocator
	bridgeNumAllocator  *objtonum.Allocator
	appIntfNumPublisher *objtonum.ObjNumPublisher
	appIntfNumAllocator map[string]*objtonum.Allocator // key: network instance UUID as string
	appMACGeneratorMap  objtonum.Map

	// To collect port info
	subDeviceNetworkStatus pubsub.Subscription
	subWwanMetrics         pubsub.Subscription

	// Configuration for Network Instances
	subNetworkInstanceConfig pubsub.Subscription

	// Metrics for all network interfaces
	pubNetworkMetrics pubsub.Publication

	// Status and metrics collected for Network Instances
	pubNetworkInstanceStatus  pubsub.Publication
	pubNetworkInstanceMetrics pubsub.Publication

	// Configuration for application interfaces
	subAppNetworkConfig   pubsub.Subscription
	subAppNetworkConfigAg pubsub.Subscription // From zedagent

	// Status of application interfaces
	pubAppNetworkStatus pubsub.Publication

	// State data, metrics and logs collected from application (from domUs)
	pubAppContainerStats        pubsub.Publication
	appContainerStatsCollecting bool
	appContainerStatsMutex      sync.Mutex // to protect appContainerStatsCollecting
	appContainerStatsInterval   uint32
	appContainerLogger          *logrus.Logger

	// Agent metrics
	agentMetrics    *controllerconn.AgentMetrics
	pubAgentMetrics pubsub.Publication

	// Flow recording
	pubAppFlowMonitor pubsub.Publication
	flowPublishMap    map[string]time.Time

	// Ticker for periodic publishing of metrics
	metricInterval uint32 // In seconds
	publishTicker  *flextimer.FlexTickerHandle

	// Retry NI or app network config that zedrouter failed to apply
	retryTimer *time.Timer

	metadataServer msrv.Msrv

	// Kubernetes networking
	withKubeNetworking bool
	cniRequests        chan *rpcRequest

	// publist nested App Status
	pubNestedAppDomainStatus pubsub.Publication
}

// AddAgentSpecificCLIFlags adds CLI options
func (z *zedrouter) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
}

func Run(ps *pubsub.PubSub, logger *logrus.Logger, log *base.LogObject, args []string, baseDir string) int {
	zedrouter := zedrouter{
		pubSub: ps,
		logger: logger,
		log:    log,
		metadataServer: msrv.Msrv{
			PubSub: ps,
			Logger: logger,
			Log:    log,
		},
	}

	agentbase.Init(&zedrouter, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithArguments(args))

	// We initialize and create metadata server inside zedrouter because it is
	// the easiest way to do it. Current implementation of LinuxNIReconciler
	// expects *http.Handler to metadata server endpoints to be passed on
	// initialization phase, then this reference is used when creating metadata
	// server for Local Network Instances (Local NI).
	// If we are to run it as a separate service, we can create separate instances
	// for every Local NI which will increase redundancy in pubsub messages and we will
	// have to combine all the information published from different instances.
	// Alternatively, we can create separate Metadata server and wrap it in a network
	// namespace for metadata service so that we won't run into any collisions,
	// but we will have to bridge LocalNIs to network namespace of metadata server
	agentbase.Init(&zedrouter.metadataServer, logger, log, "msrv")

	if err := zedrouter.metadataServer.Init(types.PersistCachePatchEnvelopesUsage, false); err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := zedrouter.metadataServer.Run(context.Background()); err != nil {
			log.Fatal(err)
		}
	}()

	if err := zedrouter.init(); err != nil {
		log.Fatal(err)
	}
	if err := zedrouter.run(context.Background()); err != nil {
		log.Fatal(err)
	}
	return 0
}

func (z *zedrouter) init() (err error) {
	z.agentStartTime = time.Now()
	z.appContainerLogger = agentlog.CustomLogInit(logrus.InfoLevel)
	z.flowPublishMap = make(map[string]time.Time)
	z.deviceNetworkStatus = &types.DeviceNetworkStatus{}

	z.agentMetrics = controllerconn.NewAgentMetrics()

	z.withKubeNetworking = base.IsHVTypeKube()
	z.cniRequests = make(chan *rpcRequest)

	gcp := *types.DefaultConfigItemValueMap()
	z.appContainerStatsInterval = gcp.GlobalValueInt(types.AppContainerStatsInterval)
	var content []byte
	for len(content) == 0 {
		content, err = os.ReadFile(types.ServerFileName)
		if err != nil {
			z.log.Errorf("Failed to read %s: %v; "+
				"waiting for it",
				types.ServerFileName, err)
			time.Sleep(10 * time.Second)
			z.pubSub.StillRunning(agentName, warningTime, errorTime)
		} else if len(content) == 0 {
			z.log.Errorf("Empty %s file - waiting for it",
				types.ServerFileName)
			time.Sleep(10 * time.Second)
			z.pubSub.StillRunning(agentName, warningTime, errorTime)
		}
	}
	z.controllerHostname = string(content)
	z.controllerHostname = strings.TrimSpace(z.controllerHostname)
	z.controllerPort = 443
	if host, port, err := net.SplitHostPort(z.controllerHostname); err == nil {
		z.controllerHostname = host
		if portNum, err := strconv.Atoi(port); err == nil && portNum <= 65535 {
			z.controllerPort = uint16(portNum)
		}
	}

	if err = z.ensureDir(runDirname); err != nil {
		return err
	}
	// Must be done before calling nistate.NewLinuxCollector.
	if err = z.ensureDir(types.DnsmasqLeaseDir); err != nil {
		return err
	}

	if err = z.initPublications(); err != nil {
		return err
	}
	if err = z.initSubscriptions(); err != nil {
		return err
	}

	// Initialize Zedrouter components (for Linux network stack).
	z.networkMonitor = &netmonitor.LinuxNetworkMonitor{Log: z.log}
	z.niStateCollector = nistate.NewLinuxCollector(z.log)
	z.reachProberICMP = &portprober.LinuxReachabilityProberICMP{}
	z.reachProberTCP = &portprober.LinuxReachabilityProberTCP{}
	z.niReconciler = nireconciler.NewLinuxNIReconciler(z.log, z.logger, z.networkMonitor,
		z.metadataServer.MakeMetadataHandler(), true, true,
		z.withKubeNetworking)

	z.initNumberAllocators()
	return nil
}

func (z *zedrouter) run(ctx context.Context) (err error) {
	z.runCtx = ctx
	z.log.Noticef("Starting %s", agentName)

	if base.IsHVTypeKube() {
		if err = z.runRPCServer(); err != nil {
			return err
		}
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	z.pubSub.StillRunning(agentName, warningTime, errorTime)

	// Wait for initial GlobalConfig.
	if err = z.subGlobalConfig.Activate(); err != nil {
		return err
	}
	for !z.gcInitialized {
		z.log.Noticef("Waiting for GCInitialized")
		select {
		case change := <-z.subGlobalConfig.MsgChan():
			z.subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		z.pubSub.StillRunning(agentName, warningTime, errorTime)
	}
	z.log.Noticef("Processed GlobalConfig")

	// Wait until we have been onboarded aka know our own UUID
	// (even though zedrouter does not use the UUID).
	err = wait.WaitForOnboarded(z.pubSub, z.log, agentName, warningTime, errorTime)
	if err != nil {
		return err
	}
	z.log.Noticef("Received device UUID")

	// Timer used to retry failed configuration
	z.retryTimer = time.NewTimer(1 * time.Second)
	z.retryTimer.Stop()

	// Publish network metrics (interface counters, etc.)
	interval := time.Duration(z.metricInterval) * time.Second
	max := float64(interval) / publishTickerDivider
	min := max * 0.3
	publishTicker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	z.publishTicker = &publishTicker

	// Start watchers
	reconcilerUpdates := z.niReconciler.WatchReconcilerUpdates()
	flowUpdates := z.niStateCollector.WatchFlows()
	ipAssignUpdates := z.niStateCollector.WatchIPAssignments()
	z.portProber = portprober.NewPortProber(
		z.log, portprober.DefaultConfig(), z.reachProberICMP, z.reachProberTCP)
	probeUpdates := z.portProber.WatchProbeUpdates()

	// Activate all subscriptions.
	inactiveSubs := []pubsub.Subscription{
		z.subDeviceNetworkStatus,
		z.subWwanMetrics,
		z.subNetworkInstanceConfig,
		z.subAppNetworkConfig,
		z.subAppNetworkConfigAg,
	}
	for _, sub := range inactiveSubs {
		if err = sub.Activate(); err != nil {
			return err
		}
	}

	z.log.Noticef("Entering main event loop")
	for {
		select {

		case change := <-z.subGlobalConfig.MsgChan():
			z.subGlobalConfig.ProcessChange(change)

		case change := <-z.subAppNetworkConfig.MsgChan():
			// If we have NetworkInstanceConfig process it first
			z.checkAndProcessNetworkInstanceConfig()
			z.subAppNetworkConfig.ProcessChange(change)

		case change := <-z.subAppNetworkConfigAg.MsgChan():
			z.subAppNetworkConfigAg.ProcessChange(change)

		case change := <-z.subDeviceNetworkStatus.MsgChan():
			z.subDeviceNetworkStatus.ProcessChange(change)

		case change := <-z.subWwanMetrics.MsgChan():
			z.subWwanMetrics.ProcessChange(change)

		case change := <-z.subNetworkInstanceConfig.MsgChan():
			z.subNetworkInstanceConfig.ProcessChange(change)

		case <-z.publishTicker.C:
			start := time.Now()
			z.log.Traceln("publishTicker at", time.Now())
			nms, err := z.niStateCollector.GetNetworkMetrics()
			if err == nil {
				err = z.pubNetworkMetrics.Publish("global", nms)
				if err != nil {
					z.log.Errorf("Failed to publish network metrics: %v", err)
				}
				z.publishNetworkInstanceMetricsAll(&nms)
			} else {
				z.log.Error(err)
			}

			err = z.agentMetrics.Publish(
				z.log, z.pubAgentMetrics, "global")
			if err != nil {
				z.log.Errorln(err)
			}

			z.pubSub.CheckMaxTimeTopic(agentName, "publishMetrics", start,
				warningTime, errorTime)
			// Check and remove stale flowlog publications.
			z.checkFlowUnpublish()

		case recUpdate := <-reconcilerUpdates:
			switch recUpdate.UpdateType {
			case nireconciler.AsyncOpDone:
				z.niReconciler.ResumeReconcile(ctx)
			case nireconciler.CurrentStateChanged:
				z.niReconciler.ResumeReconcile(ctx)
			case nireconciler.NIReconcileStatusChanged:
				key := recUpdate.NIStatus.NI.String()
				niStatus := z.lookupNetworkInstanceStatus(key)
				niConfig := z.lookupNetworkInstanceConfig(key)
				changed := z.processNIReconcileStatus(*recUpdate.NIStatus, niStatus)
				if changed {
					z.publishNetworkInstanceStatus(niStatus)
				}
				if niConfig == nil && recUpdate.NIStatus.Deleted &&
					niStatus != nil && !niStatus.ReconcileErr.HasError() &&
					niStatus.ChangeInProgress == types.ChangeInProgressTypeNone {
					z.unpublishNetworkInstanceStatus(niStatus)
				}
			case nireconciler.AppConnReconcileStatusChanged:
				key := recUpdate.AppConnStatus.App.String()
				appNetStatus := z.lookupAppNetworkStatus(key)
				appNetConfig := z.lookupAppNetworkConfig(key)
				changed := z.processAppConnReconcileStatus(*recUpdate.AppConnStatus,
					appNetStatus)
				if changed {
					z.publishAppNetworkStatus(appNetStatus)
				}
				if appNetConfig == nil && recUpdate.AppConnStatus.Deleted &&
					appNetStatus != nil && !appNetStatus.HasError() &&
					!appNetStatus.Pending() && appNetStatus.ConfigInSync {
					z.unpublishAppNetworkStatus(appNetStatus)
				}
			}

		case flowUpdate := <-flowUpdates:
			z.flowPublish(flowUpdate)

		case ipAssignUpdates := <-ipAssignUpdates:
			for _, ipAssignUpdate := range ipAssignUpdates {
				vif := ipAssignUpdate.Prev.VIF
				newAddrs := ipAssignUpdate.New
				mac := vif.GuestIfMAC.String()
				niKey := vif.NI.String()
				netStatus := z.lookupNetworkInstanceStatus(niKey)
				if netStatus == nil {
					z.log.Errorf("Failed to get status for network instance %s "+
						"(needed to update IPs assigned to VIF %s)",
						niKey, vif.NetAdapterName)
					continue
				}
				netStatus.IPAssignments[mac] = newAddrs.AssignedAddrs
				z.publishNetworkInstanceStatus(netStatus)
				appKey := vif.App.String()
				appStatus := z.lookupAppNetworkStatus(appKey)
				if appStatus == nil {
					z.log.Errorf("Failed to get network status for app %s "+
						"(needed to update IPs assigned to VIF %s)",
						appKey, vif.NetAdapterName)
					continue
				}

				for i := range appStatus.AppNetAdapterList {
					adapterStatus := &appStatus.AppNetAdapterList[i]
					if adapterStatus.Name != vif.NetAdapterName {
						continue
					}
					z.recordAssignedIPsToAdapterStatus(adapterStatus, &newAddrs)
					break
				}
				z.publishAppNetworkStatus(appStatus)
			}

		case updates := <-probeUpdates:
			start := time.Now()
			z.log.Tracef("ProbeUpdate at %v", time.Now())
			for _, probeUpdate := range updates {
				niKey := probeUpdate.NetworkInstance.String()
				status := z.lookupNetworkInstanceStatus(niKey)
				if status == nil {
					z.log.Errorf("Failed to get status for network instance %s", niKey)
					continue
				}
				config := z.lookupNetworkInstanceConfig(niKey)
				if config == nil {
					z.log.Errorf("Failed to get config for network instance %s", niKey)
					continue
				}
				z.updateNIRoutePort(probeUpdate.MPRoute, probeUpdate.SelectedPortLL,
					status, *config)
			}
			z.pubSub.CheckMaxTimeTopic(agentName, "probeUpdates", start,
				warningTime, errorTime)

		case req := <-z.cniRequests:
			start := time.Now()
			z.handleRPC(req)
			z.pubSub.CheckMaxTimeTopic(agentName, "handleRPC", start,
				warningTime, errorTime)

		case <-z.retryTimer.C:
			start := time.Now()
			z.log.Tracef("retryTimer: at %v", time.Now())
			z.retryFailedAppNetworks()
			z.pubSub.CheckMaxTimeTopic(agentName, "scanAppNetworkStatus", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		z.pubSub.StillRunning(agentName, warningTime, errorTime)
		// Are we likely to have seen all of the initial config?
		if z.triggerNumGC &&
			time.Since(z.receivedConfigTime) > 5*time.Minute {
			start := time.Now()
			z.gcNumAllocators()
			z.triggerNumGC = false
			z.pubSub.CheckMaxTimeTopic(agentName, "allocatorGC", start,
				warningTime, errorTime)
		}
	}
}

func (z *zedrouter) initPublications() (err error) {
	z.pubNetworkInstanceStatus, err = z.pubSub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkInstanceStatus{},
	})
	if err != nil {
		return err
	}

	z.pubAppNetworkStatus, err = z.pubSub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppNetworkStatus{},
	})
	if err != nil {
		return err
	}
	if err = z.pubAppNetworkStatus.ClearRestarted(); err != nil {
		return err
	}

	z.pubNetworkInstanceMetrics, err = z.pubSub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkInstanceMetrics{},
	})
	if err != nil {
		return err
	}

	z.pubAppFlowMonitor, err = z.pubSub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.IPFlow{},
	})
	if err != nil {
		return err
	}

	z.pubAppContainerStats, err = z.pubSub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppContainerMetrics{},
	})
	if err != nil {
		return err
	}

	z.pubNetworkMetrics, err = z.pubSub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkMetrics{},
	})
	if err != nil {
		log.Fatal(err)
	}

	z.pubAgentMetrics, err = z.pubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.MetricsMap{},
		})
	if err != nil {
		return err
	}

	z.pubNestedAppDomainStatus, err = z.pubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.NestedAppDomainStatus{},
		})
	if err != nil {
		return err
	}

	return nil
}

func (z *zedrouter) initSubscriptions() (err error) {
	z.subGlobalConfig, err = z.pubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		CreateHandler: z.handleGlobalConfigCreate,
		ModifyHandler: z.handleGlobalConfigModify,
		DeleteHandler: z.handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	z.subDeviceNetworkStatus, err = z.pubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		CreateHandler: z.handleDNSCreate,
		ModifyHandler: z.handleDNSModify,
		DeleteHandler: z.handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	z.subWwanMetrics, err = z.pubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "wwan",
		MyAgentName:   agentName,
		TopicImpl:     types.WwanMetrics{},
		CreateHandler: z.handleWwanMetricsCreate,
		ModifyHandler: z.handleWwanMetricsModify,
		Activate:      false,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	z.subNetworkInstanceConfig, err = z.pubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.NetworkInstanceConfig{},
		Activate:      false,
		CreateHandler: z.handleNetworkInstanceCreate,
		ModifyHandler: z.handleNetworkInstanceModify,
		DeleteHandler: z.handleNetworkInstanceDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	// Subscribe to AppNetworkConfig from zedmanager
	z.subAppNetworkConfig, err = z.pubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "zedmanager",
		MyAgentName:    agentName,
		TopicImpl:      types.AppNetworkConfig{},
		Activate:       false,
		CreateHandler:  z.handleAppNetworkCreate,
		ModifyHandler:  z.handleAppNetworkModify,
		DeleteHandler:  z.handleAppNetworkDelete,
		RestartHandler: z.handleRestart,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		return err
	}

	// Subscribe to AppNetworkConfig from zedagent
	z.subAppNetworkConfigAg, err = z.pubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.AppNetworkConfig{},
		Activate:      false,
		CreateHandler: z.handleAppNetworkCreate,
		ModifyHandler: z.handleAppNetworkModify,
		DeleteHandler: z.handleAppNetworkDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	return nil
}

// This functions updates but does not publish NetworkInstanceStatus.
// niStatus can be nil.
func (z *zedrouter) processNIReconcileStatus(recStatus nireconciler.NIReconcileStatus,
	niStatus *types.NetworkInstanceStatus) (changed bool) {
	key := recStatus.NI.String()
	if niStatus == nil {
		if !recStatus.Deleted {
			z.log.Errorf("Received NIReconcileStatus for unknown NI %s", key)
		}
		return false
	}
	if niStatus.BridgeIfindex != recStatus.BrIfIndex {
		niStatus.BridgeIfindex = recStatus.BrIfIndex
		changed = true
	}
	if niStatus.BridgeName != recStatus.BrIfName {
		niStatus.BridgeName = recStatus.BrIfName
		changed = true
	}
	if niStatus.MirrorIfName != recStatus.MirrorIfName {
		niStatus.MirrorIfName = recStatus.MirrorIfName
		changed = true
	}
	if !recStatus.InProgress {
		if niStatus.ChangeInProgress != types.ChangeInProgressTypeNone {
			niStatus.ChangeInProgress = types.ChangeInProgressTypeNone
			changed = true
		}
	}
	if len(recStatus.FailedItems) > 0 {
		var failedItems []string
		for itemRef, itemErr := range recStatus.FailedItems {
			failedItems = append(failedItems, fmt.Sprintf("%v (%v)", itemRef, itemErr))
		}
		err := fmt.Errorf("failed items: %s", strings.Join(failedItems, ";"))
		if niStatus.ReconcileErr.Error != err.Error() {
			niStatus.ReconcileErr.SetErrorNow(err.Error())
			changed = true
		}
	} else {
		if niStatus.ReconcileErr.HasError() {
			niStatus.ReconcileErr.ClearError()
			changed = true
		}
	}
	if !generics.EqualSetsFn(niStatus.CurrentRoutes, recStatus.Routes,
		func(r1, r2 types.IPRouteInfo) bool {
			return r1.Equal(r2)
		}) {
		niStatus.CurrentRoutes = recStatus.Routes
		changed = true
	}

	return changed
}

// Updates but does not publish AppNetworkStatus.
// appNetStatus can be nil.
func (z *zedrouter) processAppConnReconcileStatus(
	recStatus nireconciler.AppConnReconcileStatus,
	appNetStatus *types.AppNetworkStatus) (changed bool) {
	key := recStatus.App.String()
	if appNetStatus == nil {
		if !recStatus.Deleted {
			z.log.Errorf("Received AppConnReconcileStatus for unknown AppNetwork %s", key)
		}
		return false
	}
	var inProgress bool
	var failedItems []string
	for _, vif := range recStatus.VIFs {
		inProgress = inProgress || vif.InProgress
		for itemRef, itemErr := range vif.FailedItems {
			failedItems = append(failedItems, fmt.Sprintf("%v (%v)", itemRef, itemErr))
		}
		for i := range appNetStatus.AppNetAdapterList {
			adapterStatus := &appNetStatus.AppNetAdapterList[i]
			if adapterStatus.Name != vif.NetAdapterName {
				continue
			}
			if adapterStatus.Vif != vif.HostIfName {
				adapterStatus.Vif = vif.HostIfName
				changed = true
			}
		}
	}
	if appNetStatus.ConfigInSync != !inProgress {
		changed = true
		appNetStatus.ConfigInSync = !inProgress
	}
	if len(failedItems) > 0 {
		err := fmt.Errorf("failed items: %s", strings.Join(failedItems, ";"))
		if appNetStatus.Error != err.Error() {
			appNetStatus.SetErrorNow(err.Error())
			changed = true
		}
	} else {
		if appNetStatus.HasError() {
			appNetStatus.ClearError()
			changed = true
		}
	}
	return changed
}

func (z *zedrouter) ensureDir(path string) error {
	if _, err := os.Stat(path); err != nil {
		z.log.Functionf("Create directory %s", path)
		if err := os.Mkdir(path, 0755); err != nil {
			return err
		}
	} else {
		// dnsmasq needs to read as nobody
		if err := os.Chmod(path, 0755); err != nil {
			return err
		}
	}
	return nil
}

// If we have an NetworkInstanceConfig process it first
func (z *zedrouter) checkAndProcessNetworkInstanceConfig() {
	select {
	case change := <-z.subNetworkInstanceConfig.MsgChan():
		z.log.Functionf("Processing NetworkInstanceConfig before AppNetworkConfig")
		z.subNetworkInstanceConfig.ProcessChange(change)
	default:
		z.log.Functionf("NO NetworkInstanceConfig before AppNetworkConfig")
	}
}

// maybeScheduleRetry : if any AppNetwork is in failed state, schedule a retry
// of the failed operation.
func (z *zedrouter) maybeScheduleRetry() {
	pub := z.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		config := z.lookupAppNetworkConfig(status.Key())
		if config == nil || !config.Activate || !status.HasError() {
			continue
		}
		z.log.Functionf("maybeScheduleRetry: retryTimer set to 60 seconds")
		z.retryTimer = time.NewTimer(60 * time.Second)
	}
}

func (z *zedrouter) lookupNetworkInstanceConfig(key string) *types.NetworkInstanceConfig {
	sub := z.subNetworkInstanceConfig
	c, _ := sub.Get(key)
	if c == nil {
		return nil
	}
	config := c.(types.NetworkInstanceConfig)
	return &config
}

func (z *zedrouter) lookupNetworkInstanceStatus(key string) *types.NetworkInstanceStatus {
	pub := z.pubNetworkInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := st.(types.NetworkInstanceStatus)
	return &status
}

func (z *zedrouter) lookupNetworkInstanceMetrics(key string) *types.NetworkInstanceMetrics {
	pub := z.pubNetworkInstanceMetrics
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := st.(types.NetworkInstanceMetrics)
	return &status
}

func (z *zedrouter) lookupAppNetworkConfig(key string) *types.AppNetworkConfig {
	sub := z.subAppNetworkConfig
	c, _ := sub.Get(key)
	if c == nil {
		sub = z.subAppNetworkConfigAg
		c, _ = sub.Get(key)
		if c == nil {
			z.log.Tracef("lookupAppNetworkConfig(%s) not found", key)
			return nil
		}
	}
	config := c.(types.AppNetworkConfig)
	return &config
}

func (z *zedrouter) lookupAppNetworkStatus(key string) *types.AppNetworkStatus {
	pub := z.pubAppNetworkStatus
	st, _ := pub.Get(key)
	if st == nil {
		return nil
	}
	status := st.(types.AppNetworkStatus)
	return &status
}

func (z *zedrouter) publishNetworkInstanceStatus(status *types.NetworkInstanceStatus) {
	// Publish all errors as one instance of ErrorAndTime.
	status.ErrorAndTime = status.CombineErrors()
	pub := z.pubNetworkInstanceStatus
	err := pub.Publish(status.Key(), *status)
	if err != nil {
		z.log.Errorf("publishNetworkInstanceStatus failed: %v", err)
	}
}

func (z *zedrouter) unpublishNetworkInstanceStatus(status *types.NetworkInstanceStatus) {
	pub := z.pubNetworkInstanceStatus
	st, _ := pub.Get(status.Key())
	if st == nil {
		return
	}
	err := pub.Unpublish(status.Key())
	if err != nil {
		z.log.Errorf("unpublishNetworkInstanceStatus failed: %v", err)
	}
}

func (z *zedrouter) publishAppNetworkStatus(status *types.AppNetworkStatus) {
	key := status.Key()
	pub := z.pubAppNetworkStatus
	err := pub.Publish(key, *status)
	if err != nil {
		z.log.Errorf("publishAppNetworkStatus failed: %v", err)
	}
}

func (z *zedrouter) unpublishAppNetworkStatus(status *types.AppNetworkStatus) {
	key := status.Key()
	pub := z.pubAppNetworkStatus
	st, _ := pub.Get(key)
	if st == nil {
		return
	}
	err := pub.Unpublish(key)
	if err != nil {
		z.log.Errorf("unpublishAppNetworkStatus failed: %v", err)
	}
}

func (z *zedrouter) flowPublish(flow types.IPFlow) {
	flowKey := flow.Key()
	z.flowPublishMap[flowKey] = time.Now()
	err := z.pubAppFlowMonitor.Publish(flowKey, flow)
	if err != nil {
		z.log.Errorf("flowPublish failed: %v", err)
	}
}

func (z *zedrouter) checkFlowUnpublish() {
	for k, m := range z.flowPublishMap {
		passed := int64(time.Since(m) / time.Second)
		if passed > flowStaleSec { // no update after 30 minutes, unpublish this flow
			z.log.Functionf("checkFlowUnpublish: key %s, sec passed %d, remove",
				k, passed)
			err := z.pubAppFlowMonitor.Unpublish(k)
			if err != nil {
				z.log.Errorf("checkFlowUnpublish failed: %v", err)
			}
			delete(z.flowPublishMap, k)
		}
	}
}

// this is periodic metrics handler
// nms must be the unmodified output from getNetworkMetrics()
func (z *zedrouter) publishNetworkInstanceMetricsAll(nms *types.NetworkMetrics) {
	pub := z.pubNetworkInstanceStatus
	niList := pub.GetAll()
	if niList == nil {
		return
	}
	for _, ni := range niList {
		status := ni.(types.NetworkInstanceStatus)
		config := z.lookupNetworkInstanceConfig(status.Key())
		if config == nil || (!status.Activated || status.IPConflictErr.HasError()) {
			// NI was deleted or is inactive/dysfunctional - skip metrics publishing.
			continue
		}
		netMetrics := z.createNetworkInstanceMetrics(&status, nms)
		err := z.pubNetworkInstanceMetrics.Publish(netMetrics.Key(), *netMetrics)
		if err != nil {
			z.log.Errorf("publishNetworkInstanceMetricsAll failed: %v", err)
		}
	}
}

func (z *zedrouter) createNetworkInstanceMetrics(status *types.NetworkInstanceStatus,
	nms *types.NetworkMetrics) *types.NetworkInstanceMetrics {
	niMetrics := types.NetworkInstanceMetrics{
		UUIDandVersion: status.UUIDandVersion,
		DisplayName:    status.DisplayName,
		Type:           status.Type,
		BridgeName:     status.BridgeName,
	}
	netMetrics := types.NetworkMetrics{}
	if bridgeMetrics, found := nms.LookupNetworkMetrics(status.BridgeName); found {
		netMetrics.MetricList = append(netMetrics.MetricList, bridgeMetrics)
	}
	for _, vif := range status.Vifs {
		if vifMetrics, found := nms.LookupNetworkMetrics(vif.Name); found {
			netMetrics.MetricList = append(netMetrics.MetricList, vifMetrics)
		}
	}
	niMetrics.NetworkMetrics = netMetrics
	probeMetrics, err := z.portProber.GetProbeMetrics(status.UUID)
	if err == nil {
		niMetrics.ProbeMetrics = probeMetrics
	} else {
		z.log.Error(err)
	}
	niMetrics.VlanMetrics.NumTrunkPorts = status.NumTrunkPorts
	niMetrics.VlanMetrics.VlanCounts = status.VlanMap
	return &niMetrics
}

func (z *zedrouter) deleteNetworkInstanceMetrics(key string) {
	pub := z.pubNetworkInstanceMetrics
	if metrics := z.lookupNetworkInstanceMetrics(key); metrics != nil {
		err := pub.Unpublish(metrics.Key())
		if err != nil {
			z.log.Errorf("deleteNetworkInstanceMetrics failed: %v", err)
		}
	}
}
