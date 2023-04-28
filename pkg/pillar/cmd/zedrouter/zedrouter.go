// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of a collection of AppNetworkConfig structs
// from zedmanager and zedagent. Publish the status as AppNetworkStatus.
// Produce the updated configlets (for radvd, dnsmasq, ip*tables,
// ipset, ip link/addr/route configuration) based on that and apply those
// configlets.

package zedrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/nistate"
	"github.com/lf-edge/eve/pkg/pillar/objtonum"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/uplinkprober"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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

// Set from Makefile
var Version = "No version specified"

type zedrouterContext struct {
	agentbase.AgentBase
	// Legacy data plane enable/disable flag
	legacyDataPlane bool

	agentStartTime        time.Time
	receivedConfigTime    time.Time
	triggerNumGC          bool // For appNum and bridgeNum
	subAppNetworkConfig   pubsub.Subscription
	subAppNetworkConfigAg pubsub.Subscription // From zedagent for dom0
	subAppInstanceConfig  pubsub.Subscription // From zedagent to cleanup appInstMetadata
	pubAppNetworkStatus   pubsub.Publication
	networkMonitor        netmonitor.NetworkMonitor

	assignableAdapters     *types.AssignableAdapters
	subAssignableAdapters  pubsub.Subscription
	subDeviceNetworkStatus pubsub.Subscription
	deviceNetworkStatus    *types.DeviceNetworkStatus
	ready                  bool
	subGlobalConfig        pubsub.Subscription
	GCInitialized          bool
	subLocationInfo        pubsub.Subscription
	subWwanStatus          pubsub.Subscription
	subWwanMetrics         pubsub.Subscription
	subDomainStatus        pubsub.Subscription

	// number allocators
	appNumAllocator     *objtonum.Allocator
	bridgeNumAllocator  *objtonum.Allocator
	appIntfNumPublisher *objtonum.ObjNumPublisher
	appIntfNumAllocator map[string]*objtonum.Allocator // key: network instance UUID as string

	// NetworkInstance
	subNetworkInstanceConfig  pubsub.Subscription
	pubNetworkInstanceStatus  pubsub.Publication
	pubNetworkInstanceMetrics pubsub.Publication
	pubAppFlowMonitor         pubsub.Publication
	pubAppContainerMetrics    pubsub.Publication
	networkInstanceStatusMap  sync.Map
	NLaclMap                  map[uuid.UUID]map[string]types.ULNetworkACLs // app uuid plus bridge ul name
	dnsServers                map[string][]net.IP                          // Key is ifname
	uplinkProber              *uplinkprober.UplinkProber
	niStateCollector          nistate.Collector
	appNetCreateTimer         *time.Timer
	appCollectStatsRunning    bool
	appStatsMutex             sync.Mutex // to protect the changing appNetworkStatus & appCollectStatsRunning
	appStatsInterval          uint32
	aclog                     *logrus.Logger // App Container logger
	disableDHCPAllOnesNetMask bool
	flowPublishMap            map[string]time.Time
	metricInterval            uint32 // In seconds
	iptablesInitialized       bool   // iptablesInitialized from nim

	zedcloudMetrics *zedcloud.AgentMetrics
	cipherMetrics   *cipher.AgentMetrics

	// Edge node info
	subEdgeNodeInfo pubsub.Subscription
	// cipher context
	pubCipherBlockStatus pubsub.Publication
	decryptCipherContext cipher.DecryptCipherContext
	pubAppInstMetaData   pubsub.Publication
	publishTicker        *flextimer.FlexTickerHandle
	// cli options
	versionPtr *bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctx *zedrouterContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctx.versionPtr = flagSet.Bool("v", false, "Version")
}

var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	// Pick up (mostly static) AssignableAdapters before we process
	// any Routes; Pbr needs to know which network adapters are assignable

	aa := types.AssignableAdapters{}
	zedrouterCtx := zedrouterContext{
		legacyDataPlane:    false,
		assignableAdapters: &aa,
		agentStartTime:     time.Now(),
		dnsServers:         make(map[string][]net.IP),
		aclog:              agentlog.CustomLogInit(logrus.InfoLevel),
		NLaclMap:           make(map[uuid.UUID]map[string]types.ULNetworkACLs),
		flowPublishMap:     make(map[string]time.Time),
		zedcloudMetrics:    zedcloud.NewAgentMetrics(),
		cipherMetrics:      cipher.NewAgentMetrics(agentName),
		networkMonitor:     &netmonitor.LinuxNetworkMonitor{Log: log},
	}
	agentbase.Init(&zedrouterCtx, logger, log, agentName,
		agentbase.WithArguments(arguments))

	if *zedrouterCtx.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	handleInit()

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &zedrouterCtx,
		CreateHandler: handleDNSCreate,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	subAssignableAdapters, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.AssignableAdapters{},
		Activate:      false,
		Ctx:           &zedrouterCtx,
		CreateHandler: handleAACreate,
		ModifyHandler: handleAAModify,
		DeleteHandler: handleAADelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subAssignableAdapters = subAssignableAdapters
	subAssignableAdapters.Activate()

	gcp := *types.DefaultConfigItemValueMap()
	zedrouterCtx.appStatsInterval = gcp.GlobalValueInt(types.AppContainerStatsInterval)

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &zedrouterCtx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Look for edge node info
	subEdgeNodeInfo, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeInfo{},
		Persistent:  true,
		Activate:    false,
		Ctx:         &zedrouterCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subEdgeNodeInfo = subEdgeNodeInfo
	subEdgeNodeInfo.Activate()

	zedrouterCtx.deviceNetworkStatus = &types.DeviceNetworkStatus{}

	// Create publish before subscribing and activating subscriptions
	// Also need to do this before we wait for IP addresses since
	// zedagent waits for these to be published/exist, and zedagent
	// runs the fallback timers after that wait.
	pubNetworkInstanceStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkInstanceStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubNetworkInstanceStatus = pubNetworkInstanceStatus

	pubAppInstMetaData, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		Persistent: true,
		TopicType:  types.AppInstMetaData{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubAppInstMetaData = pubAppInstMetaData

	pubAppNetworkStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppNetworkStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubAppNetworkStatus = pubAppNetworkStatus
	pubAppNetworkStatus.ClearRestarted()

	pubNetworkInstanceMetrics, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkInstanceMetrics{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubNetworkInstanceMetrics = pubNetworkInstanceMetrics

	pubAppFlowMonitor, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.IPFlow{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubAppFlowMonitor = pubAppFlowMonitor

	pubAppContainerMetrics, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppContainerMetrics{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubAppContainerMetrics = pubAppContainerMetrics

	pubNetworkMetrics, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.NetworkMetrics{},
	})
	if err != nil {
		log.Fatal(err)
	}

	pubCipherBlockStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.CipherBlockStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubCipherBlockStatus = pubCipherBlockStatus

	cipherMetricsPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.CipherMetrics{},
	})
	if err != nil {
		log.Fatal(err)
	}

	zedrouterCtx.decryptCipherContext.Log = log
	zedrouterCtx.decryptCipherContext.AgentName = agentName
	zedrouterCtx.decryptCipherContext.AgentMetrics = zedrouterCtx.cipherMetrics

	// Look for controller certs which will be used for decryption
	subControllerCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.ControllerCert{},
		Activate:    false,
		Ctx:         &zedrouterCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.decryptCipherContext.SubControllerCert = subControllerCert
	subControllerCert.Activate()

	// Look for edge node certs which will be used for decryption
	subEdgeNodeCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeCert{},
		Activate:    false,
		Persistent:  true,
		Ctx:         &zedrouterCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.decryptCipherContext.SubEdgeNodeCert = subEdgeNodeCert
	subEdgeNodeCert.Activate()

	// Pick up debug aka log level before we start real work
	for !zedrouterCtx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	// Wait until we have been onboarded aka know our own UUID but we don't used the UUID
	err = utils.WaitForOnboarded(ps, log, agentName, warningTime, errorTime)
	if err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed onboarded")

	initNumberAllocators(&zedrouterCtx, ps)

	// Before we process any NetworkInstances we want to know the
	// assignable adapters.
	for !zedrouterCtx.assignableAdapters.Initialized {
		log.Functionf("Waiting for AssignableAdapters\n")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		// Run stillRunning since we waiting for zedagent to deliver
		// PhysicalIO to domainmgr and it in turn deliver AA initialized to us.
		// Former depends on cloud connectivity.
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("Have %d assignable adapters\n", len(aa.IoBundleList))

	subNetworkInstanceConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.NetworkInstanceConfig{},
		Activate:      false,
		Ctx:           &zedrouterCtx,
		CreateHandler: handleNetworkInstanceCreate,
		ModifyHandler: handleNetworkInstanceModify,
		DeleteHandler: handleNetworkInstanceDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subNetworkInstanceConfig = subNetworkInstanceConfig
	subNetworkInstanceConfig.Activate()
	log.Functionf("Subscribed to NetworkInstanceConfig")

	// Subscribe to AppNetworkConfig from zedmanager and from zedagent
	subAppNetworkConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "zedmanager",
		MyAgentName:    agentName,
		TopicImpl:      types.AppNetworkConfig{},
		Activate:       false,
		Ctx:            &zedrouterCtx,
		CreateHandler:  handleAppNetworkCreate,
		ModifyHandler:  handleAppNetworkModify,
		DeleteHandler:  handleAppNetworkConfigDelete,
		RestartHandler: handleRestart,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subAppNetworkConfig = subAppNetworkConfig
	subAppNetworkConfig.Activate()

	// Subscribe to AppNetworkConfig from zedagent
	subAppNetworkConfigAg, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.AppNetworkConfig{},
		Activate:      false,
		Ctx:           &zedrouterCtx,
		CreateHandler: handleAppNetworkCreate,
		ModifyHandler: handleAppNetworkModify,
		DeleteHandler: handleAppNetworkConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subAppNetworkConfigAg = subAppNetworkConfigAg
	subAppNetworkConfigAg.Activate()

	// Subscribe to AppInstConfig from zedagent
	subAppInstanceConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceConfig{},
		Activate:      false,
		Ctx:           &zedrouterCtx,
		DeleteHandler: handleAppInstConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subAppInstanceConfig = subAppInstanceConfig
	subAppInstanceConfig.Activate()

	// Look for geographic location reports
	subLocationInfo, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "nim",
		MyAgentName: agentName,
		TopicImpl:   types.WwanLocationInfo{},
		Activate:    false,
		Ctx:         &zedrouterCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subLocationInfo = subLocationInfo
	subLocationInfo.Activate()

	// Look for cellular status
	subWwanStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "nim",
		MyAgentName: agentName,
		TopicImpl:   types.WwanStatus{},
		Activate:    false,
		Ctx:         &zedrouterCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subWwanStatus = subWwanStatus
	subWwanStatus.Activate()

	// Look for cellular metrics
	subWwanMetrics, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "nim",
		MyAgentName: agentName,
		TopicImpl:   types.WwanMetrics{},
		Activate:    false,
		Ctx:         &zedrouterCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subWwanMetrics = subWwanMetrics
	subWwanMetrics.Activate()

	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.DomainStatus{},
		Activate:    false,
		Ctx:         &zedrouterCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	cloudProbeMetricPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.MetricsMap{},
		})
	if err != nil {
		log.Fatal(err)
	}

	interval := time.Duration(zedrouterCtx.metricInterval) * time.Second
	max := float64(interval) / publishTickerDivider
	min := max * 0.3
	publishTicker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	zedrouterCtx.publishTicker = &publishTicker

	niStateCollector := nistate.NewLinuxCollector(log)
	zedrouterCtx.niStateCollector = niStateCollector
	flowUpdates := niStateCollector.WatchFlows()
	ipAssignUpdates := niStateCollector.WatchIPAssignments()

	reachProber := uplinkprober.NewControllerReachProber(
		log, agentName, zedrouterCtx.zedcloudMetrics)
	uplinkProber := uplinkprober.NewUplinkProber(
		log, uplinkprober.DefaultConfig(), reachProber)
	zedrouterCtx.uplinkProber = uplinkProber
	probeUpdates := uplinkProber.WatchProbeUpdates()
	if zedrouterCtx.deviceNetworkStatus != nil {
		uplinkProber.ApplyDNSUpdate(*zedrouterCtx.deviceNetworkStatus)
	}

	zedrouterCtx.appNetCreateTimer = time.NewTimer(1 * time.Second)
	zedrouterCtx.appNetCreateTimer.Stop()

	// Start watching for link and route changes.
	netEvents := zedrouterCtx.networkMonitor.WatchEvents(context.TODO(), "zedrouter")

	// Create the dummy interface used to re-direct DROP/REJECT packets.
	createFlowMonDummyInterface(&zedrouterCtx)

	zedrouterCtx.ready = true
	log.Functionf("zedrouterCtx.ready\n")

	for {
		select {
		case change := <-subControllerCert.MsgChan():
			subControllerCert.ProcessChange(change)

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)

		case change := <-subAppNetworkConfig.MsgChan():
			// If we have NetworkInstanceConfig process it first
			checkAndProcessNetworkInstanceConfig(&zedrouterCtx)
			subAppNetworkConfig.ProcessChange(change)

		case change := <-subAppNetworkConfigAg.MsgChan():
			subAppNetworkConfigAg.ProcessChange(change)

		case change := <-subAppInstanceConfig.MsgChan():
			subAppInstanceConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subLocationInfo.MsgChan():
			subLocationInfo.ProcessChange(change)

		case change := <-subWwanStatus.MsgChan():
			subWwanStatus.ProcessChange(change)

		case change := <-subDomainStatus.MsgChan():
			subDomainStatus.ProcessChange(change)

		case change := <-subWwanMetrics.MsgChan():
			subWwanMetrics.ProcessChange(change)

		case change := <-subEdgeNodeInfo.MsgChan():
			subEdgeNodeInfo.ProcessChange(change)

		case event := <-netEvents:
			start := time.Now()
			switch ev := event.(type) {
			case netmonitor.IfChange:
				ifName := ev.Attrs.IfName
				if ev.Deleted {
					// XXX For now keeping this as it was (in removed PbrLinkChange),
					// but it will be refactored and go away.
					// Currently, zedrouter will also try to update port-specific
					// routing tables which, however, are under NIM management
					// (resulting in "trying to delete already removed route" errors and other
					// potential issues).
					rt := baseTableIndex + ev.Attrs.IfIndex
					devicenetwork.FlushRoutesTable(log, rt, 0)
					devicenetwork.FlushRules(log, ev.Attrs.IfIndex)
				}
				if !types.IsMgmtPort(*zedrouterCtx.deviceNetworkStatus, ifName) {
					// Even if ethN isn't individually assignable,
					// it could be used for a bridge.
					maybeUpdateBridgeIPAddr(&zedrouterCtx, ifName)
				}
			case netmonitor.RouteChange:
				PbrRouteChange(&zedrouterCtx, zedrouterCtx.deviceNetworkStatus, ev)
			}
			ps.CheckMaxTimeTopic(agentName, "netEvents", start,
				warningTime, errorTime)

		case <-zedrouterCtx.publishTicker.C:
			start := time.Now()
			log.Traceln("publishTicker at", time.Now())
			nms, err := niStateCollector.GetNetworkMetrics()
			if err == nil {
				err = pubNetworkMetrics.Publish("global", nms)
				if err != nil {
					log.Errorf("Failed to publish network metrics: %v", err)
				}
				publishNetworkInstanceMetricsAll(&zedrouterCtx, &nms)
			} else {
				log.Error(err)
			}

			err = zedrouterCtx.cipherMetrics.Publish(
				log, cipherMetricsPub, "global")
			if err != nil {
				log.Errorln(err)
			}
			err = zedrouterCtx.zedcloudMetrics.Publish(
				log, cloudProbeMetricPub, "global")
			if err != nil {
				log.Errorln(err)
			}

			ps.CheckMaxTimeTopic(agentName, "publishMetrics", start,
				warningTime, errorTime)
			// Check and remove stale flowlog publications.
			checkFlowUnpublish(&zedrouterCtx)

		case flowUpdate := <-flowUpdates:
			flowPublish(&zedrouterCtx, flowUpdate)

		case ipAssignUpdates := <-ipAssignUpdates:
			for _, ipAssignUpdate := range ipAssignUpdates {
				vif := ipAssignUpdate.Prev.VIF
				newAddrs := ipAssignUpdate.New
				mac := vif.GuestIfMAC.String()
				niKey := vif.NI.String()
				netStatus := lookupNetworkInstanceStatus(&zedrouterCtx, niKey)
				if netStatus == nil {
					log.Errorf("Failed to get status for network instance %s "+
						"(needed to update IPs assigned to VIF %s)",
						niKey, vif.NetAdapterName)
					continue
				}
				netStatus.IPAssignments[mac] = types.AssignedAddrs{
					IPv4Addr:  newAddrs.IPv4Addr,
					IPv6Addrs: newAddrs.IPv6Addrs,
				}
				publishNetworkInstanceStatus(&zedrouterCtx, netStatus)
				switchNI := netStatus.Type == types.NetworkInstanceTypeSwitch
				appKey := vif.App.String()
				appStatus := lookupAppNetworkStatus(&zedrouterCtx, appKey)
				if appStatus == nil {
					log.Errorf("Failed to get network status for app %s "+
						"(needed to update IPs assigned to VIF %s)",
						appKey, vif.NetAdapterName)
					continue
				}
				var ipv4Addr string
				if newAddrs.IPv4Addr != nil {
					ipv4Addr = newAddrs.IPv4Addr.String()
				}
				var ipv6Addrs []string
				for _, ipv6Addr := range newAddrs.IPv6Addrs {
					ipv6Addrs = append(ipv6Addrs, ipv6Addr.String())
				}
				for i := range appStatus.UnderlayNetworkList {
					ulStatus := &appStatus.UnderlayNetworkList[i]
					if ulStatus.Name != vif.NetAdapterName {
						continue
					}
					if switchNI {
						if ipv4Addr != "" {
							ulStatus.AllocatedIPv4Addr = ipv4Addr
						}
						ulStatus.IPAddrMisMatch = false
					} else {
						if ulStatus.AllocatedIPv4Addr == "" {
							ulStatus.AllocatedIPv4Addr = ipv4Addr
							ulStatus.IPAddrMisMatch = false
						} else if ulStatus.AllocatedIPv4Addr != ipv4Addr {
							ulStatus.IPAddrMisMatch = true
						}
					}
					ulStatus.AllocatedIPv6List = ipv6Addrs
					ulStatus.IPv4Assigned = ipv4Addr != ""
					break
				}
				publishAppNetworkStatus(&zedrouterCtx, appStatus)
			}

		case updates := <-probeUpdates:
			start := time.Now()
			log.Tracef("ProbeUpdates at %v", time.Now())
			for _, probeUpdate := range updates {
				niKey := probeUpdate.NetworkInstance.String()
				item, err := zedrouterCtx.pubNetworkInstanceStatus.Get(niKey)
				if err != nil {
					log.Errorf("Failed to get status for network instance %s", niKey)
					continue
				}
				status := item.(types.NetworkInstanceStatus)
				ports := zedrouterCtx.deviceNetworkStatus.GetPortsByLogicallabel(
					probeUpdate.SelectedUplinkLL)
				if len(ports) != 1 {
					log.Errorf("Label of selected uplink does not match single interface (%v)",
						ports)
					continue
				}
				status.SelectedUplinkIntf = ports[0].IfName
				publishNetworkInstanceStatus(&zedrouterCtx, &status)
				if status.ProgUplinkIntf == status.SelectedUplinkIntf {
					log.Noticef("Uplink (%s) has not actually changed"+
						" for network instance %s",
						status.SelectedUplinkIntf, status.DisplayName)
					continue
				}
				err = doNetworkInstanceFallback(&zedrouterCtx, &status)
				if err != nil {
					log.Errorf("Failed to perform network instance (%s) fallback: %v",
						status.DisplayName, err)
					continue
				}
			}
			ps.CheckMaxTimeTopic(agentName, "probeUpdates", start,
				warningTime, errorTime)

		case <-zedrouterCtx.appNetCreateTimer.C:
			start := time.Now()
			log.Tracef("appNetCreateTimer: at %v", time.Now())
			scanAppNetworkStatusInErrorAndUpdate(&zedrouterCtx)
			ps.CheckMaxTimeTopic(agentName, "scanAppNetworkStatus", start,
				warningTime, errorTime)

		case change := <-subNetworkInstanceConfig.MsgChan():
			log.Functionf("NetworkInstanceConfig change at %+v", time.Now())
			subNetworkInstanceConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
		// Are we likely to have seen all of the initial config?
		if zedrouterCtx.triggerNumGC &&
			time.Since(zedrouterCtx.receivedConfigTime) > 5*time.Minute {
			start := time.Now()
			gcNumAllocators(&zedrouterCtx)
			zedrouterCtx.triggerNumGC = false
			ps.CheckMaxTimeTopic(agentName, "allocatorGC", start,
				warningTime, errorTime)
		}
	}
}

// If we have an NetworkInstanceConfig process it first
func checkAndProcessNetworkInstanceConfig(ctx *zedrouterContext) {
	select {
	case change := <-ctx.subNetworkInstanceConfig.MsgChan():
		log.Functionf("Processing NetworkInstanceConfig before AppNetworkConfig")
		ctx.subNetworkInstanceConfig.ProcessChange(change)
	default:
		log.Functionf("NO NetworkInstanceConfig before AppNetworkConfig")
	}
}

func maybeHandleDNS(ctx *zedrouterContext) {
	if !ctx.ready {
		return
	}

	// XXX do a NatInactivate/NatActivate if management ports changed?
}

func handleRestart(ctxArg interface{}, restartCounter int) {

	log.Tracef("handleRestart(%d)", restartCounter)
	ctx := ctxArg.(*zedrouterContext)
	if restartCounter != 0 {
		// Since all work is done inline we can immediately say that
		// we have restarted.
		ctx.pubAppNetworkStatus.SignalRestarted()
	}
}

func handleInit() {
	if _, err := os.Stat(runDirname); err != nil {
		log.Functionf("Create %s\n", runDirname)
		if err := os.Mkdir(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	} else {
		// dnsmasq needs to read as nobody
		if err := os.Chmod(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	dnsmasqInitDirs()
	// Need to make sure we don't have any stale leases
	dnsmasqClearLeases()

	// ipsets which are independent of config
	createDefaultIpset()
}

func publishAppNetworkStatus(ctx *zedrouterContext,
	status *types.AppNetworkStatus) {

	key := status.Key()
	log.Functionf("publishAppNetworkStatus(%s-%s)\n", status.DisplayName, key)
	pub := ctx.pubAppNetworkStatus
	pub.Publish(key, *status)
}

func unpublishAppNetworkStatus(ctx *zedrouterContext,
	status *types.AppNetworkStatus) {

	key := status.Key()
	log.Tracef("unpublishAppNetworkStatus(%s)\n", key)
	pub := ctx.pubAppNetworkStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishAppNetworkStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func handleAppNetworkConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleAppNetworkConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	config := configArg.(types.AppNetworkConfig)
	status := lookupAppNetworkStatus(ctx, key)
	if status == nil {
		log.Functionf("handleAppNetworkConfigDelete: unknown %s\n", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Functionf("handleAppNetworkConfigDelete(%s) done\n", key)
	// on resource release, check whether any one else
	// needs it
	checkAppNetworkErrorAndStartTimer(ctx)
	updateStateCollectingForApp(ctx, &config, nil)
}

// Callers must be careful to publish any changes to AppNetworkStatus
func lookupAppNetworkStatus(ctx *zedrouterContext, key string) *types.AppNetworkStatus {

	pub := ctx.pubAppNetworkStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Tracef("lookupAppNetworkStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.AppNetworkStatus)
	return &status
}

func lookupAppNetworkStatusByAppIP(ctx *zedrouterContext, ip net.IP) *types.AppNetworkStatus {

	ipStr := ip.String()
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		for _, ulStatus := range status.UnderlayNetworkList {
			if ipStr == ulStatus.AllocatedIPv4Addr {
				return &status
			}
		}
	}
	return nil
}

func lookupAppNetworkConfig(ctx *zedrouterContext, key string) *types.AppNetworkConfig {

	sub := ctx.subAppNetworkConfig
	c, _ := sub.Get(key)
	if c == nil {
		sub = ctx.subAppNetworkConfigAg
		c, _ = sub.Get(key)
		if c == nil {
			log.Tracef("lookupAppNetworkConfig(%s) not found\n", key)
			return nil
		}
	}
	config := c.(types.AppNetworkConfig)
	return &config
}

func lookupDiskStatusList(ctx *zedrouterContext, key string) []types.DiskStatus {
	st, err := ctx.subDomainStatus.Get(key)
	if err != nil || st == nil {
		log.Warnf("could not find domain %s", key)
		return nil
	}

	domainStatus := st.(types.DomainStatus)
	return domainStatus.DiskStatusList
}

func handleAppNetworkCreate(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	config := configArg.(types.AppNetworkConfig)
	log.Functionf("handleAppNetworkCreate(%s-%s)\n", config.DisplayName, key)

	// If this is the first time, update the timer for GC
	if ctx.receivedConfigTime.IsZero() {
		log.Functionf("triggerNumGC")
		ctx.receivedConfigTime = time.Now()
		ctx.triggerNumGC = true
	}

	log.Functionf("handleAppAppNetworkCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// Start by marking with PendingAdd
	status := types.AppNetworkStatus{
		UUIDandVersion: config.UUIDandVersion,
		PendingAdd:     true,
		DisplayName:    config.DisplayName,
	}

	// Pick a local number to identify the application instance
	// Used for IP addresses as well bridge and file names.
	appNumKey := types.UuidToNumKey{UUID: config.UUIDandVersion.UUID}
	appNum, err := ctx.appNumAllocator.GetOrAllocate(appNumKey)
	if err != nil {
		status.PendingAdd = false
		addError(ctx, &status, "handleAppNetworkCreate", err)
		return
	}
	status.AppNum = appNum
	publishAppNetworkStatus(ctx, &status)

	// allocate application numbers on underlay network
	err = allocateAppIntfNums(ctx, config.UUIDandVersion.UUID, config.UnderlayNetworkList)
	if err != nil {
		status.PendingAdd = false
		addError(ctx, &status, "handleAppNetworkCreate", err)
		return
	}

	if config.Activate {
		doActivate(ctx, config, &status) // We check any error below
	}
	status.PendingAdd = false
	publishAppNetworkStatus(ctx, &status)
	log.Functionf("handleAppNetworkCreate done for %s\n", config.DisplayName)
	if status.HasError() && config.Activate && !status.Activated {
		releaseAppNetworkResources(ctx, key, &status)
	}
	log.Functionf("handleAppNetworkCreate(%s) done\n", key)
	// on resource release, check whether any one else
	// needs it
	checkAppNetworkErrorAndStartTimer(ctx)
	updateStateCollectingForApp(ctx, nil, &config)
}

func publishAppInstMetadata(ctx *zedrouterContext,
	appInstMetadata *types.AppInstMetaData) {
	if appInstMetadata == nil {
		log.Errorf("publishAppInstMetadata: nil appInst metadata")
		return
	}
	key := appInstMetadata.Key()
	log.Functionf("publishAppInstMetadata(%s)", key)

	pub := ctx.pubAppInstMetaData
	pub.Publish(appInstMetadata.Key(), *appInstMetadata)
}

func unpublishAppInstMetadata(ctx *zedrouterContext,
	appInstMetadata *types.AppInstMetaData) {
	if appInstMetadata == nil {
		log.Errorf("unpublishAppInstMetadata: nil appInst metadata")
		return
	}
	key := appInstMetadata.Key()
	log.Tracef("unpublishAppInstMetadata(%s)\n", key)

	pub := ctx.pubAppInstMetaData
	if exists, _ := pub.Get(key); exists == nil {
		log.Errorf("unpublishAppInstMetadata(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func lookupAppInstMetadata(ctx *zedrouterContext, key string) *types.AppInstMetaData {

	pub := ctx.pubAppInstMetaData
	st, _ := pub.Get(key)
	if st == nil {
		log.Tracef("lookupAppInstMetadata(%s) not found\n", key)
		return nil
	}
	appInstMetadata := st.(types.AppInstMetaData)
	return &appInstMetadata
}

func flowPublish(ctx *zedrouterContext, flow types.IPFlow) {
	flowKey := flow.Key()
	ctx.flowPublishMap[flowKey] = time.Now()
	ctx.pubAppFlowMonitor.Publish(flowKey, flow)
}

func checkFlowUnpublish(ctx *zedrouterContext) {
	for k, m := range ctx.flowPublishMap {
		passed := int64(time.Since(m) / time.Second)
		if passed > flowStaleSec { // no update after 30 minutes, unpublish this flow
			log.Functionf("checkFlowUnpublish: key %s, sec passed %d, remove", k, passed)
			ctx.pubAppFlowMonitor.Unpublish(k)
			delete(ctx.flowPublishMap, k)
		}
	}
}

func handleAppInstConfigDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Functionf("handleAppInstConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	appInstMetadata := lookupAppInstMetadata(ctx, key)
	if appInstMetadata == nil {
		log.Functionf("handleAppInstConfigDelete: unknown %s\n", key)
		return
	}

	// Clean up appInst Metadata
	unpublishAppInstMetadata(ctx, appInstMetadata)
	log.Functionf("handleAppNetworkConfigDelete(%s) done\n", key)
}

func doActivate(ctx *zedrouterContext, config types.AppNetworkConfig,
	status *types.AppNetworkStatus) error {

	log.Functionf("doActivate %s-%s", config.DisplayName, config.UUIDandVersion)

	// Check that Network exists for all underlays.
	// We look for AwaitNetworkInstance when a NetworkInstance is added
	allNetworksExist := appNetworkCheckAllNetworksExist(ctx, config, status)
	if !allNetworksExist {
		// Not reported as error since should be transient, but has unique state
		status.AwaitNetworkInstance = true
		log.Functionf("doActivate(%v) for %s: missing networks\n",
			config.UUIDandVersion, config.DisplayName)
		publishAppNetworkStatus(ctx, status)
		return nil
	}

	// during doActive, copy the collect stats IP to status and
	// check to see if need to launch the process
	appCheckStatsCollect(ctx, &config, status)

	appNetworkDoCopyNetworksToStatus(ctx, config, status)
	if err := validateAppNetworkConfig(ctx, config, status); err != nil {
		log.Errorf("doActivate(%v) AppNetwork Config check failed for %s: %v",
			config.UUIDandVersion, config.DisplayName, err)
		// addError has already been done
		publishAppNetworkStatus(ctx, status)
		return err
	}

	// Note that with IPv4/IPv6 interfaces the domU can do
	// dns lookups on either IPv4 and IPv6 on any interface, hence we
	// configure the ipsets for all the domU's interfaces/bridges.
	ipsets := compileAppInstanceIpsets(ctx, config.UnderlayNetworkList)

	err := appNetworkDoActivateAllUnderlayNetworks(ctx, config, status, ipsets)
	if err != nil {
		log.Error(err.Error())
		publishAppNetworkStatus(ctx, status)
		return err
	}
	if status.AwaitNetworkInstance {
		log.Functionf("doActivate %s-%s clearing error %s",
			config.DisplayName, config.UUIDandVersion, status.Error)
		status.AwaitNetworkInstance = false
		// XXX better to use ErrorWithSource and check for NetworkInstanceStatus?
		status.ClearError()
	}
	status.Activated = true
	publishAppNetworkStatus(ctx, status)
	log.Functionf("doActivate done for %s\n", config.DisplayName)
	return nil
}

func appNetworkDoActivateAllUnderlayNetworks(
	ctx *zedrouterContext,
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus,
	ipsets []string) error {
	for i, ulConfig := range config.UnderlayNetworkList {
		ulNum := i + 1
		log.Tracef("ulNum %d network %s ACLs %v\n",
			ulNum, ulConfig.Network.String(), ulConfig.ACLs)
		err := appNetworkDoActivateUnderlayNetwork(
			ctx, config, status, ipsets, &ulConfig, ulNum)
		if err != nil {
			return err
		}
	}
	return nil
}

func compareIPVersion(a, b net.IP) bool {
	return (a.To4() == nil) == (b.To4() == nil)
}

func checkIPRange(start, middle, end net.IP) {
	if start == nil {
		log.Warnf("no range check without start address")
		return
	}

	if middle == nil && end == nil {
		return
	}
	if middle == nil && end != nil {
		if !compareIPVersion(start, end) {
			log.Warnf("IPv6 and IPv4 mixed: %s, %s", start.String(), end.String())
			return
		}

		if bytes.Compare(start, end) > 0 {
			log.Warnf("start %s > end %s", start.String(), end.String())
			return
		}
	}
	if middle != nil && end != nil {
		if !compareIPVersion(start, middle) || !compareIPVersion(middle, end) {
			log.Warnf("IPv6 and IPv4 mixed: %s, %s, %s", start.String(), middle.String(), end.String())
			return
		}

		if bytes.Compare(start, middle) > 0 {
			log.Warnf("start %s > middle %s", start.String(), middle.String())
			return
		}
		if bytes.Compare(start, end) > 0 {
			log.Warnf("start %s > end %s", start.String(), end.String())
			return
		}
		if bytes.Compare(middle, end) > 0 {
			log.Warnf("middle %s > end %s", middle.String(), end.String())
			return
		}
	}
}

func appNetworkDoActivateUnderlayNetwork(
	ctx *zedrouterContext,
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus,
	ipsets []string,
	ulConfig *types.UnderlayNetworkConfig,
	ulNum int) error {

	netInstConfig := lookupNetworkInstanceConfig(ctx,
		ulConfig.Network.String())
	if netInstConfig == nil {
		log.Fatalf("Cannot find UL NetworkInstance %s for App %s",
			ulConfig.Name, config.DisplayName)
	}
	netInstStatus := lookupNetworkInstanceStatus(ctx,
		ulConfig.Network.String())
	if netInstStatus == nil {
		err := fmt.Errorf("no network instance status for %s",
			ulConfig.Network.String())
		log.Error(err.Error())
		// Set up to retry later
		status.AwaitNetworkInstance = true
		addError(ctx, status, "doActivate underlay", err)
		return err
	}
	if netInstStatus.HasError() {
		err := errors.New(netInstStatus.Error)
		log.Error(err.Error())
		// Set up to retry later
		status.AwaitNetworkInstance = true
		addError(ctx, status, "error from network instance", err)
		return err
	}
	// Fetch the network that this underlay is attached to
	bridgeName := netInstStatus.BridgeName
	vifName := "nbu" + strconv.Itoa(ulNum) + "x" +
		strconv.Itoa(status.AppNum)
	uLink, err := findBridge(bridgeName)
	if err != nil {
		log.Error(err.Error())
		// Set up to retry later
		status.AwaitNetworkInstance = true
		addError(ctx, status, "findBridge", err)
		return err
	}
	bridgeMac := uLink.HardwareAddr
	log.Functionf("bridgeName %s MAC %s\n",
		bridgeName, bridgeMac.String())

	var appMac string // Handed to domU
	if ulConfig.AppMacAddr != nil {
		appMac = ulConfig.AppMacAddr.String()
	} else {
		appMac = generateAppMac(status.UUIDandVersion.UUID,
			ulNum, status.AppNum, netInstStatus)
	}
	log.Functionf("appMac %s\n", appMac)

	// Record what we have so far
	ulStatus := &status.UnderlayNetworkList[ulNum-1]
	log.Functionf("doActivate ulNum %d: %v\n", ulNum, ulStatus)
	ulStatus.Name = ulConfig.Name
	ulStatus.Bridge = bridgeName
	ulStatus.BridgeMac = bridgeMac
	ulStatus.Vif = vifName
	ulStatus.Mac = appMac
	ulStatus.HostName = config.Key()

	if netInstStatus.Type == types.NetworkInstanceTypeSwitch {
		if ulConfig.AccessVlanID <= 1 {
			// No valid vlan configuration on this app adapter.
			// There are valid vlans configured on adapters of other apps
			// connected to this particular network instance.
			// Make this adapter trunk port
			ulStatus.Vlan.IsTrunk = true
			ulStatus.Vlan.Start = 2
			ulStatus.Vlan.End = 4093
			netInstStatus.NumTrunkPorts++
		} else {
			ulStatus.Vlan.IsTrunk = false
			ulStatus.Vlan.Start = ulConfig.AccessVlanID
			ulStatus.Vlan.End = ulConfig.AccessVlanID
			netInstStatus.VlanMap[ulConfig.AccessVlanID]++
		}
		if len(netInstStatus.IfNameList) > 0 {
			ulStatus.Vlan.SwitchUplink = netInstStatus.IfNameList[0]
		}
	}

	appID := status.UUIDandVersion.UUID
	appIPAddr, err := getUlAddrs(ctx, netInstStatus, ulStatus, appID)
	if err != nil {
		err := fmt.Errorf("App IP address allocation failed: %v", err)
		log.Error(err.Error())
		addError(ctx, status, "getUlAddrs", err)
		return err
	}
	bridgeIPAddr := netInstStatus.BridgeIPAddr
	log.Functionf("bridgeIPAddr %s appIPAddr %s\n", bridgeIPAddr, appIPAddr)
	ulStatus.BridgeIPAddr = bridgeIPAddr
	// appIPAddr is "" for switch NI. DHCP snoop will set AllocatedIPv4Addr later
	ulStatus.AllocatedIPv4Addr = appIPAddr
	hostsDirpath := runDirname + "/hosts." + bridgeName
	if appIPAddr != "" {
		addToHostsConfiglet(hostsDirpath, config.DisplayName,
			[]string{appIPAddr})
	}

	// Default ipset
	deleteDefaultIpsetConfiglet(vifName, false)
	createDefaultIpsetConfiglet(vifName, netInstStatus.DnsNameToIPList,
		appIPAddr)

	aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: bridgeName,
		VifName: vifName, BridgeIP: bridgeIPAddr, AppIP: appIPAddr,
		UpLinks: netInstStatus.IfNameList, NIType: netInstStatus.Type,
		AppNum: int32(status.AppNum)}

	// Set up ACLs
	ruleList, dependList, err := createACLConfiglet(ctx, aclArgs, ulConfig.ACLs)
	ulStatus.ACLDependList = dependList
	if err != nil {
		addError(ctx, status, "createACL", err)
		return err
	}
	setNetworkACLRules(ctx, appID, ulStatus.Name, ruleList)

	if appIPAddr != "" {
		checkIPRange(netInstStatus.DhcpRange.Start, net.ParseIP(appIPAddr), netInstStatus.DhcpRange.End)
		// XXX clobber any IPv6 EID entry since same name
		// but that's probably OK since we're doing IPv4 EIDs
		addhostDnsmasq(bridgeName, appMac, appIPAddr,
			config.UUIDandVersion.UUID.String())
	}

	// Look for added or deleted ipsets
	newIpsets, staleIpsets, restartDnsmasq := diffIpsets(ipsets,
		netInstStatus.BridgeIPSets)

	if restartDnsmasq && !isEmptyIP(ulStatus.BridgeIPAddr) {
		stopDnsmasq(bridgeName, true, false)
		dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
			netInstStatus.SelectedUplinkIntf)
		ntpServers := types.GetNTPServers(*ctx.deviceNetworkStatus,
			netInstStatus.SelectedUplinkIntf)
		createDnsmasqConfiglet(ctx, bridgeName,
			ulStatus.BridgeIPAddr, netInstStatus, hostsDirpath,
			newIpsets, netInstStatus.SelectedUplinkIntf,
			dnsServers, ntpServers)
		startDnsmasq(bridgeName)
	}
	netInstStatus.AddVif(log, vifName, appMac,
		config.UUIDandVersion.UUID)
	netInstStatus.BridgeIPSets = newIpsets
	log.Functionf("set BridgeIPSets to %v for %s", newIpsets,
		netInstStatus.Key())

	// Check App Container Stats ACL need to be reinstalled
	appStatsMayNeedReinstallACL(ctx, config)

	publishNetworkInstanceStatus(ctx, netInstStatus)

	maybeRemoveStaleIpsets(staleIpsets)
	return nil
}

// generateAppMac picks a fixed address for Local and Cloud and uses a fixed
// hash for Switch which still produces a stable MAC address
// for a given app instance
func generateAppMac(appUUID uuid.UUID, ulNum int, appNum int, netInstStatus *types.NetworkInstanceStatus) string {
	var appMac string

	switch netInstStatus.Type {
	case types.NetworkInstanceTypeSwitch:
		h := sha256.New()
		h.Write(appUUID[:])
		h.Write(netInstStatus.UUIDandVersion.UUID[:])
		nums := make([]byte, 2)
		nums[0] = byte(ulNum)
		nums[1] = byte(appNum)
		h.Write(nums)
		hash := h.Sum(nil)
		appMac = fmt.Sprintf("02:16:3e:%02x:%02x:%02x",
			hash[0], hash[1], hash[2])

	case types.NetworkInstanceTypeLocal:
		// Room to handle multiple underlays in 5th byte
		appMac = fmt.Sprintf("00:16:3e:00:%02x:%02x",
			ulNum, appNum)
	}
	return appMac
}

func appNetworkDoCopyNetworksToStatus(
	ctx *zedrouterContext,
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	ulcount := len(config.UnderlayNetworkList)
	status.UnderlayNetworkList = make([]types.UnderlayNetworkStatus,
		ulcount)
	for i := range config.UnderlayNetworkList {
		status.UnderlayNetworkList[i].UnderlayNetworkConfig =
			config.UnderlayNetworkList[i]
	}
}

func appNetworkCheckAllNetworksExist(
	ctx *zedrouterContext,
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus) bool {

	// Check networks for Underlay
	// XXX - Should we also check for Network(instance)Status
	// objects here itself?
	for _, ulConfig := range config.UnderlayNetworkList {
		netInstConfig := lookupNetworkInstanceConfig(ctx,
			ulConfig.Network.String())
		if netInstConfig != nil {
			continue
		}
		errStr := fmt.Sprintf("Missing underlay network %s for %s/%s",
			ulConfig.Network.String(),
			config.UUIDandVersion, config.DisplayName)
		log.Errorf(errStr)
		log.Functionf("doActivate failed: %s\n", errStr)

		// App network configuration that has underlays pointing to non-existent
		// network instances is invalid. Such, configuration should never come to
		// device from cloud.
		// But, on the device sometimes, zedrouter sees the app network configuration
		// before seeing the required network instance configuration. This is transient
		// and zedrouter re-creates the app network when the corresponding network instance
		// configuration finally arrives.
		// In such cases it is less confusing to put the app network in network wait state
		// rather than in error state.
		// We use the AwaitNetworkInstance in AppNetworkStatus that is already present.
		return false
	}
	return true
}

// Called when a NetworkInstance is added or when an error is cleared
// Walk all AppNetworkStatus looking for AwaitNetworkInstance, then
// check if network UUID is there.
// Also check if error on network instance and propagate to app network
func checkAndRecreateAppNetwork(ctx *zedrouterContext, niStatus types.NetworkInstanceStatus) {

	log.Functionf("checkAndRecreateAppNetwork(%s)", niStatus.Key())
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		config := lookupAppNetworkConfig(ctx, status.Key())
		if config == nil {
			log.Warnf("checkAndRecreateAppNetwork(%s) no config for %s\n",
				niStatus.Key(), status.DisplayName)
			continue
		}
		if !config.IsNetworkUsed(niStatus.UUID) {
			continue
		}

		// Any new error?
		if niStatus.HasError() {
			err := errors.New(niStatus.Error)
			if niStatus.Error != status.Error {
				log.Error(niStatus.Error)
				// Set up to retry later
				status.AwaitNetworkInstance = true
				addError(ctx, &status, "error from network instance", err)
				publishAppNetworkStatus(ctx, &status)
			}
			return
		}
		// Any error to clear?
		// XXX better to use ErrorWithSource and check for NetworkInstanceStatus?
		if !status.AwaitNetworkInstance && !status.HasError() {
			continue
		}

		log.Functionf("checkAndRecreateAppNetwork(%s) try remove error %s for %s",
			niStatus.Key(), status.Error, status.DisplayName)
		doActivate(ctx, *config, &status) // If error we will try again
		log.Functionf("checkAndRecreateAppNetwork(%s) done for %s\n",
			niStatus.Key(), config.DisplayName)
	}
}

// Returns the link
func findBridge(bridgeName string) (*netlink.Bridge, error) {

	var bridgeLink *netlink.Bridge
	link, err := netlink.LinkByName(bridgeName)
	if link == nil {
		errStr := fmt.Sprintf("findBridge(%s) failed %s",
			bridgeName, err)
		// XXX how to handle this failure? bridge disappeared?
		return nil, errors.New(errStr)
	}
	switch link.(type) {
	case *netlink.Bridge:
		bridgeLink = link.(*netlink.Bridge)
	default:
		errStr := fmt.Sprintf("findBridge(%s) not a bridge %T",
			bridgeName, link)
		// XXX why wouldn't it be a bridge?
		return nil, errors.New(errStr)
	}
	return bridgeLink, nil
}

// XXX Need additional logic for IPv6 underlays.
func getUlAddrs(ctx *zedrouterContext,
	netInstStatus *types.NetworkInstanceStatus,
	ulStatus *types.UnderlayNetworkStatus, appID uuid.UUID) (string, error) {
	var err error
	var mac net.HardwareAddr
	networkID := netInstStatus.UUID

	if netInstStatus.Subnet.IP == nil ||
		netInstStatus.DhcpRange.Start == nil {
		log.Functionf("getUlAddrs(%s): app(%s), no subnet\n",
			networkID.String(), appID.String())
		return "", nil
	}
	if ulStatus.Mac == "" {
		log.Functionf("getUlAddrs(%s): app(%s) fail: no mac",
			networkID.String(), appID.String())
		return "", nil
	}
	log.Functionf("getUlAddrs(%s): app(%s)",
		networkID.String(), appID.String())

	// XXX or change type of VifInfo.Mac to avoid parsing?
	mac, err = net.ParseMAC(ulStatus.Mac)
	if err != nil {
		errStr := fmt.Sprintf("parse Mac fail: %v\n", err)
		log.Errorf("getUlAddrs(%s): app(%s) fail: %s\n",
			networkID.String(), appID.String(), err)
		return "", errors.New(errStr)
	}

	ipAddr := ""
	// for static IP Address
	if ulStatus.AppIPAddr != nil {
		ipAddr = ulStatus.AppIPAddr.String()
		// the IP Address, should not be in dhcpRange
		if netInstStatus.DhcpRange.Contains(ulStatus.AppIPAddr) {
			errStr := fmt.Sprintf("static IP(%s) is in DhcpRange(%s, %s)",
				ipAddr, netInstStatus.DhcpRange.Start.String(),
				netInstStatus.DhcpRange.End.String())
			log.Errorf("getUlAddrs(%s): app(%s) fail: %s",
				networkID.String(), appID.String(), errStr)
			return "", errors.New(errStr)
		}
		// IP Address must be inside the subnet range
		if !netInstStatus.Subnet.Contains(ulStatus.AppIPAddr) {
			errStr := fmt.Sprintf("static IP(%s) is outside subnet range",
				ipAddr)
			log.Errorf("getUlAddrs(%s): app(%s) fail: %s",
				networkID.String(), appID.String(), errStr)
			return "", errors.New(errStr)
		}
	} else {
		// Get the app number for the underlay network entry.
		appNum, err := getAppIntfNum(ctx, networkID, appID, ulStatus.IfIdx)
		if err != nil {
			errStr := fmt.Sprintf("App Number get failed: %v", err)
			log.Errorf("getUlAddrs(%s): app(%s) fail: %s",
				networkID.String(), appID.String(), errStr)
			return "", errors.New(errStr)
		}
		ipAddr, err = lookupOrAllocateIPv4(netInstStatus, appID, appNum, mac)
		if err != nil {
			errStr := fmt.Sprintf("IP Addr get fail: %v", err)
			log.Errorf("getUlAddrs(%s): app(%s) fail: %s",
				networkID.String(), appID.String(), errStr)
			return "", errors.New(errStr)
		}
	}
	addr := net.ParseIP(ipAddr)
	ulStatus.BridgeIPAddr = netInstStatus.BridgeIPAddr
	recordIPAssignment(ctx, netInstStatus, addr, ulStatus.Mac)
	log.Functionf("getUlAddrs(%s): App %s done, ipAddr: %s",
		networkID.String(), appID.String(), ipAddr)
	return ipAddr, nil
}

// Caller should clear the appropriate status.Pending* if the the caller will
// return after adding the error.
func addError(ctx *zedrouterContext,
	status *types.AppNetworkStatus, tag string, err error) {

	log.Errorf("%s: %s\n", tag, err.Error())
	// XXX The use of appendError() could be more normalized
	status.Error = appendError(status.Error, tag, err.Error())
	status.ErrorTime = time.Now()
	publishAppNetworkStatus(ctx, status)
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

// Note that handleAppNetworkModify will not touch the EID; just ACLs,
// network instance, and static IP/MAC changes.
// In particular, the number of underlay networks can not be changed.
func handleAppNetworkModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	config := configArg.(types.AppNetworkConfig)
	oldConfig := oldConfigArg.(types.AppNetworkConfig)
	status := lookupAppNetworkStatus(ctx, key)
	log.Functionf("handleAppNetworkModify(%v) for %s",
		config.UUIDandVersion, config.DisplayName)
	// reset error status and mark pending modify as true
	status.ClearError()
	status.PendingModify = true
	publishAppNetworkStatus(ctx, status)

	if err := doAppNetworkSanityCheckForModify(ctx, config, oldConfig, status); err != nil {
		status.PendingModify = false
		publishAppNetworkStatus(ctx, status)
		log.Errorf("handleAppNetworkModify: Config check failed for %s: %v",
			config.DisplayName, err)
		return
	}

	// No check for version numbers since the ACLs etc might change
	// even for the same version.
	log.Tracef("handleAppNetworkModify appNum %d\n", status.AppNum)

	// Check for unsupported changes
	status.UUIDandVersion = config.UUIDandVersion
	publishAppNetworkStatus(ctx, status)

	// Note that with IPv4/IPv6 interfaces the domU can do
	// dns lookups on either IPv4 and IPv6 on any interface, hence should
	// configure the ipsets for all the domU's interfaces/bridges.
	ipsets := compileAppInstanceIpsets(ctx, config.UnderlayNetworkList)

	// We need to make sure we update any network instance references which
	// have changed, but we need to do that when the status is not Activated,
	// hence the order depends on the state.
	if !config.Activate && status.Activated {
		doInactivateAppNetwork(ctx, status)
		checkAppNetworkModifyUNetAppNum(ctx, config, status)
		appNetworkDoCopyNetworksToStatus(ctx, config, status)
	} else if config.Activate && !status.Activated {
		checkAppNetworkModifyUNetAppNum(ctx, config, status)
		appNetworkDoCopyNetworksToStatus(ctx, config, status)
		doActivate(ctx, config, status) // We check any error below
	} else if !status.Activated {
		checkAppNetworkModifyUNetAppNum(ctx, config, status)
		// Just copy in config
		appNetworkDoCopyNetworksToStatus(ctx, config, status)
	} else {
		// during modify, copy the collect stats IP to status and
		// check to see if need to launch the process
		appCheckStatsCollect(ctx, &config, status)

		// Check which underlays have changes while active
		// that require bringing them down and up
		for i := range config.UnderlayNetworkList {
			ulNum := i + 1
			log.Tracef("handleModify ulNum %d\n", ulNum)
			ulConfig := &config.UnderlayNetworkList[i]
			oldulConfig := &oldConfig.UnderlayNetworkList[i]
			ulStatus := &status.UnderlayNetworkList[i]
			if ulConfig.Network == ulStatus.Network &&
				ulConfig.AppIPAddr.Equal(ulStatus.AppIPAddr) &&
				ulConfig.AppMacAddr.String() == ulStatus.AppMacAddr.String() {
				// Save new config then process any ACL changes
				ulStatus.UnderlayNetworkConfig = *ulConfig
				doAppNetworkModifyUNetAcls(ctx, status, ulConfig,
					oldulConfig, ulStatus, ipsets, false)
				continue
			}
			appNetworkDoInactivateUnderlayNetwork(ctx, status,
				ulStatus, ipsets)
			err := ctx.niStateCollector.InactivateVIFStateCollecting(ulConfig.Network,
				config.UUIDandVersion.UUID, ulConfig.Name)
			if err != nil {
				log.Errorf(
					"handleAppNetworkModify: InactivateVIFStateCollecting failed for %s: %v",
					config.DisplayName, err)
			}

			if ulConfig.Network != ulStatus.Network {
				log.Functionf("checkAppNetworkModifyUNetAppNum(%v) for %s: change from %s to %s",
					config.UUIDandVersion, config.DisplayName,
					ulStatus.Network, ulConfig.Network)
				// update the reference to the network instance
				err := doAppNetworkModifyUNetAppNum(ctx,
					status.UUIDandVersion.UUID,
					ulConfig, ulStatus)
				if err != nil {
					log.Errorf("handleAppNetworkModify: AppNum failed for %s: %v",
						config.DisplayName, err)
					addError(ctx, status, "handleModify", err)
				}
			}
			// Save new config
			ulStatus.UnderlayNetworkConfig = *ulConfig

			err = appNetworkDoActivateUnderlayNetwork(
				ctx, config, status, ipsets, ulConfig, ulNum)
			if err != nil {
				// addError already done
				log.Errorf("handleAppNetworkModify: Underlay Network activation failed for %s: %v",
					config.DisplayName, err)
			}
			err = ctx.niStateCollector.ActivateVIFStateCollecting(ulConfig.Network,
				config.UUIDandVersion.UUID, ulConfig.Name)
			if err != nil {
				log.Errorf(
					"handleAppNetworkModify: ActivateVIFStateCollecting failed for %s: %v",
					config.DisplayName, err)
			}

		}
	}

	status.PendingModify = false
	publishAppNetworkStatus(ctx, status)
	log.Functionf("handleAppNetworkModify done for %s\n", config.DisplayName)

	if status != nil && status.HasError() &&
		config.Activate && !status.Activated {
		releaseAppNetworkResources(ctx, key, status)
	}
	log.Functionf("handleAppNetworkModify(%s) done\n", key)
	// on resource release, check whether any one else
	// needs it
	checkAppNetworkErrorAndStartTimer(ctx)
	updateStateCollectingForApp(ctx, &oldConfig, &config)
}

func doAppNetworkSanityCheckForModify(ctx *zedrouterContext,
	config types.AppNetworkConfig, oldConfig types.AppNetworkConfig,
	status *types.AppNetworkStatus) error {

	// XXX what about changing the number of interfaces as
	// part of an inactive/active transition?
	// XXX We could should we allow the addition of interfaces
	// if the domU would find out through some hotplug event.
	// But deletion is hard.
	// For now don't allow any adds or deletes.
	if len(config.UnderlayNetworkList) != len(oldConfig.UnderlayNetworkList) {
		err := fmt.Errorf("Unsupported: Changed number of underlays for %s",
			config.UUIDandVersion)
		log.Error(err.Error())
		addError(ctx, status, "handleModify", err)
		return err
	}
	// Wait for all network instances to arrive if they have not already.
	if status.AwaitNetworkInstance {
		err := fmt.Errorf("Still waiting for all network instances to arrive for %s",
			config.UUIDandVersion)
		log.Error(err.Error())
		// We intentionally do not addError here but we return the error indication
		return err
	}
	for i := range config.UnderlayNetworkList {
		ulConfig := &config.UnderlayNetworkList[i]
		netconfig := lookupNetworkInstanceConfig(ctx,
			ulConfig.Network.String())
		if netconfig == nil {
			err := fmt.Errorf("no network Instance config for %s",
				ulConfig.Network.String())
			addError(ctx, status, "lookupNetworkInstanceConfig", err)
			return err
		}
		netstatus := lookupNetworkInstanceStatus(ctx,
			ulConfig.Network.String())
		if netstatus == nil {
			// We had a netconfig but no status!
			err := fmt.Errorf("no network Instance status for %s",
				ulConfig.Network.String())
			addError(ctx, status, "handleModify underlay sanity check "+
				" - no network instance", err)
			return err
		}
	}

	if err := validateAppNetworkConfig(ctx, config, status); err != nil {
		publishAppNetworkStatus(ctx, status)
		log.Errorf("handleModify: AppNetworkConfig check failed for %s: %v",
			config.DisplayName, err)
		// addError has already been done
		return err
	}
	return nil
}

func doAppNetworkModifyUNetAcls(
	ctx *zedrouterContext,
	status *types.AppNetworkStatus,
	ulConfig *types.UnderlayNetworkConfig,
	oldulConfig *types.UnderlayNetworkConfig,
	ulStatus *types.UnderlayNetworkStatus,
	ipsets []string, force bool) {

	bridgeName := ulStatus.Bridge
	appIPAddr := ulStatus.AllocatedIPv4Addr

	netstatus := lookupNetworkInstanceStatus(ctx, ulConfig.Network.String())

	aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: bridgeName,
		VifName: ulStatus.Vif, BridgeIP: ulStatus.BridgeIPAddr, AppIP: appIPAddr,
		UpLinks: netstatus.IfNameList, NIType: netstatus.Type,
		AppNum: int32(status.AppNum)}

	// We ignore any errors in netstatus

	appID := status.UUIDandVersion.UUID
	rules := getNetworkACLRules(ctx, appID, ulStatus.Name)
	ruleList, dependList, err := updateACLConfiglet(ctx, aclArgs,
		oldulConfig.ACLs, ulConfig.ACLs, rules.ACLRules,
		ulStatus.ACLDependList, force)
	if err != nil {
		addError(ctx, status, "updateACL", err)
	}
	ulStatus.ACLDependList = dependList
	setNetworkACLRules(ctx, appID, ulStatus.Name, ruleList)

	newIpsets, staleIpsets, restartDnsmasq := diffIpsets(ipsets,
		netstatus.BridgeIPSets)

	if restartDnsmasq && !isEmptyIP(ulStatus.BridgeIPAddr) {
		hostsDirpath := runDirname + "/hosts." + bridgeName
		stopDnsmasq(bridgeName, true, false)
		dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
			netstatus.SelectedUplinkIntf)
		ntpServers := types.GetNTPServers(*ctx.deviceNetworkStatus,
			netstatus.SelectedUplinkIntf)
		createDnsmasqConfiglet(ctx, bridgeName,
			ulStatus.BridgeIPAddr, netstatus, hostsDirpath,
			newIpsets, netstatus.SelectedUplinkIntf,
			dnsServers, ntpServers)
		startDnsmasq(bridgeName)
	}
	netstatus.BridgeIPSets = newIpsets
	log.Functionf("set BridgeIPSets to %v for %s", newIpsets, netstatus.Key())
	publishNetworkInstanceStatus(ctx, netstatus)

	maybeRemoveStaleIpsets(staleIpsets)
}

// Check if any references to network instances changed and update the appnums
// if so.
// Requires that the AppNetworkStatus is not Activated
// Adds errors to status if there is a failure.
func checkAppNetworkModifyUNetAppNum(ctx *zedrouterContext,
	config types.AppNetworkConfig, status *types.AppNetworkStatus) {

	if status.Activated {
		log.Fatalf("Called for Activated status %s", status.DisplayName)
	}

	// Check if any underlays have changes to the Networks
	for i := range config.UnderlayNetworkList {
		ulConfig := &config.UnderlayNetworkList[i]
		ulStatus := &status.UnderlayNetworkList[i]
		if ulConfig.Network == ulStatus.Network {
			continue
		}
		log.Functionf("checkAppNetworkModifyUNetAppNum(%v) for %s: change from %s to %s",
			config.UUIDandVersion, config.DisplayName,
			ulStatus.Network, ulConfig.Network)
		// update the reference to the network instance
		err := doAppNetworkModifyUNetAppNum(ctx,
			status.UUIDandVersion.UUID, ulConfig, ulStatus)
		if err != nil {
			log.Errorf("handleAppNetworkModify: AppNum failed for %s: %v",
				config.DisplayName, err)
			addError(ctx, status, "handleModify", err)
		}
	}
}

// handle a change to the network UUID for one underlayNetworkConfig.
// Assumes the caller has checked that such a change is present.
// Release the appNum and acquire appNum on the new network instance.
func doAppNetworkModifyUNetAppNum(
	ctx *zedrouterContext,
	appID uuid.UUID,
	ulConfig *types.UnderlayNetworkConfig,
	ulStatus *types.UnderlayNetworkStatus) error {

	networkID := ulConfig.Network
	oldNetworkID := ulStatus.Network
	ifIdx := ulConfig.IfIdx
	oldIfIdx := ulStatus.IfIdx

	// Try to release the app number on the old network.
	err := freeAppIntfNum(ctx, oldNetworkID, appID, oldIfIdx)
	if err != nil {
		log.Error(err)
		// Continue anyway...
	}

	// Allocate an app number on the new network.
	withStaticIP := ulConfig.AppIPAddr != nil
	err = allocateAppIntfNum(ctx, networkID, appID, ifIdx, withStaticIP)
	if err != nil {
		log.Error(err)
		return err
	}
	// Did the freeAppIntfNum release any last reference?
	netstatus := lookupNetworkInstanceStatus(ctx, ulStatus.Network.String())
	if netstatus != nil {
		if maybeNetworkInstanceDelete(ctx, netstatus) {
			log.Functionf("post freeAppIntfNum(%v) for %s deleted %s",
				oldNetworkID, appID, netstatus.Key())
		}
	}
	return nil
}

func maybeRemoveStaleIpsets(staleIpsetHosts []string) {
	// Remove stale ipsets previously created for ACLs with the "host" match.
	// In case if there are any references to these ipsets from other
	// domUs, then the kernel would not remove them.
	// The ipset destroy command would just fail.
	for _, host := range staleIpsetHosts {
		ipsetBasename := hostIpsetBasename(host)
		err := ipsetDestroy(fmt.Sprintf("ipv4.%s", ipsetBasename))
		if err != nil {
			log.Errorln("ipset destroy ipv4", ipsetBasename, err)
		}
		err = ipsetDestroy(fmt.Sprintf("ipv6.%s", ipsetBasename))
		if err != nil {
			log.Errorln("ipset destroy ipv6", ipsetBasename, err)
		}
	}
}

func handleDelete(ctx *zedrouterContext, key string,
	status *types.AppNetworkStatus) {

	log.Functionf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	status.PendingDelete = true
	publishAppNetworkStatus(ctx, status)

	if status.Activated {
		doInactivateAppNetwork(ctx, status)
	}
	status.PendingDelete = false
	publishAppNetworkStatus(ctx, status)

	// Write out what we modified to AppNetworkStatus aka delete
	unpublishAppNetworkStatus(ctx, status)

	appNumKey := types.UuidToNumKey{UUID: status.UUIDandVersion.UUID}
	err := ctx.appNumAllocator.Free(appNumKey, false)
	if err != nil {
		log.Errorf("failed to free number allocated to app %s: %v",
			status.UUIDandVersion.UUID, err)
	}
	freeAppIntfNums(ctx, status)
	// Did this free up any last references against any Network Instance Status?
	for ulNum := 0; ulNum < len(status.UnderlayNetworkList); ulNum++ {
		ulStatus := &status.UnderlayNetworkList[ulNum]
		netstatus := lookupNetworkInstanceStatus(ctx, ulStatus.Network.String())
		if netstatus != nil {
			if maybeNetworkInstanceDelete(ctx, netstatus) {
				log.Functionf("post freeAppIntfNums(%v) for %s deleted %s",
					status.UUIDandVersion, status.DisplayName,
					netstatus.Key())
			}
		}
	}

	log.Functionf("handleDelete done for %s\n", status.DisplayName)
}

func doInactivateAppNetwork(ctx *zedrouterContext,
	status *types.AppNetworkStatus) {

	log.Functionf("doInactivate(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	// remove app container stats collection items
	appCheckStatsCollect(ctx, nil, status)

	// Note that with IPv4/IPv6 interfaces the domU can do
	// dns lookups on either IPv4 and IPv6 on any interface, hence should
	// configure the ipsets for all the domU's interfaces/bridges.
	// We skip our own contributions since we're going away
	ipsets := compileOldAppInstanceIpsets(ctx, status.UnderlayNetworkList, status.Key())

	// Delete everything in underlay
	appNetworkDoInactivateAllUnderlayNetworks(ctx, status, ipsets)

	status.Activated = false
	publishAppNetworkStatus(ctx, status)
	log.Functionf("doInactivate done for %s\n", status.DisplayName)
}

func appNetworkDoInactivateAllUnderlayNetworks(
	ctx *zedrouterContext,
	status *types.AppNetworkStatus,
	ipsets []string) {

	appID := status.UUIDandVersion.UUID
	for ulNum := 0; ulNum < len(status.UnderlayNetworkList); ulNum++ {
		ulStatus := &status.UnderlayNetworkList[ulNum]
		log.Functionf("doInactivate ulNum %d: %v\n", ulNum, ulStatus)
		appNetworkDoInactivateUnderlayNetwork(
			ctx, status, ulStatus, ipsets)
	}
	delete(ctx.NLaclMap, appID)
}

func appNetworkDoInactivateUnderlayNetwork(
	ctx *zedrouterContext,
	status *types.AppNetworkStatus,
	ulStatus *types.UnderlayNetworkStatus,
	ipsets []string) {

	bridgeName := ulStatus.Bridge

	netstatus := lookupNetworkInstanceStatus(ctx,
		ulStatus.Network.String())
	if netstatus == nil {
		errStr := fmt.Sprintf("no network status for %s",
			ulStatus.Network.String())
		err := errors.New(errStr)
		addError(ctx, status, "doInactivate underlay", err)
		return
	}
	// We ignore any errors in netstatus

	if ulStatus.Mac != "" {
		// XXX or change type of VifInfo.Mac?
		mac, err := net.ParseMAC(ulStatus.Mac)
		if err != nil {
			log.Fatal("ParseMAC failed: ",
				ulStatus.Mac, err)
		}
		err = releaseIPv4FromNetworkInstance(ctx, netstatus, mac)
		if err != nil {
			// XXX publish error?
			addError(ctx, status, "releaseIPv4", err)
		}
	}

	appIPAddr := ulStatus.AllocatedIPv4Addr
	if appIPAddr != "" {
		removehostDnsmasq(bridgeName, ulStatus.Mac,
			appIPAddr)
	}

	appID := status.UUIDandVersion.UUID
	aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: bridgeName,
		VifName: ulStatus.Vif, BridgeIP: ulStatus.BridgeIPAddr, AppIP: appIPAddr,
		UpLinks: netstatus.IfNameList}

	// XXX Could ulStatus.Vif not be set? Means we didn't add
	if ulStatus.Vif != "" {
		rules := getNetworkACLRules(ctx, appID, ulStatus.Name)
		ruleList, err := deleteACLConfiglet(aclArgs, rules.ACLRules)
		if err != nil {
			addError(ctx, status, "deleteACL", err)
		}
		setNetworkACLRules(ctx, appID, ulStatus.Name, ruleList)
	} else {
		log.Warnf("doInactivate(%s): no vifName for bridge %s for %s\n",
			status.UUIDandVersion, bridgeName,
			status.DisplayName)
	}

	// Delete underlay hosts file for this app
	hostsDirpath := runDirname + "/hosts." + bridgeName
	removeFromHostsConfiglet(hostsDirpath,
		status.DisplayName)
	// Look for added or deleted ipsets
	newIpsets, staleIpsets, restartDnsmasq := diffIpsets(ipsets,
		netstatus.BridgeIPSets)

	if restartDnsmasq && !isEmptyIP(ulStatus.BridgeIPAddr) {
		stopDnsmasq(bridgeName, true, false)
		dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
			netstatus.SelectedUplinkIntf)
		ntpServers := types.GetNTPServers(*ctx.deviceNetworkStatus,
			netstatus.SelectedUplinkIntf)
		createDnsmasqConfiglet(ctx, bridgeName,
			ulStatus.BridgeIPAddr, netstatus, hostsDirpath,
			newIpsets, netstatus.SelectedUplinkIntf,
			dnsServers, ntpServers)
		startDnsmasq(bridgeName)
	}
	if netstatus.Type == types.NetworkInstanceTypeSwitch {
		if ulStatus.AccessVlanID <= 1 {
			netstatus.NumTrunkPorts--
		} else {
			netstatus.VlanMap[ulStatus.AccessVlanID]++
			if _, ok := netstatus.VlanMap[ulStatus.AccessVlanID]; ok {
				netstatus.VlanMap[ulStatus.AccessVlanID]--
				if netstatus.VlanMap[ulStatus.AccessVlanID] == 0 {
					delete(netstatus.VlanMap, ulStatus.AccessVlanID)
				}
			}
		}
	}
	netstatus.BridgeIPSets = newIpsets
	log.Functionf("set BridgeIPSets to %v for %s", newIpsets, netstatus.Key())
	maybeRemoveStaleIpsets(staleIpsets)

	netstatus.RemoveVif(log, ulStatus.Vif)
	publishNetworkInstanceStatus(ctx, netstatus)
	if maybeNetworkInstanceDelete(ctx, netstatus) {
		log.Noticef("deleted network instance %s", netstatus.Key())
	} else {
		// publish the changes to network instance status
		publishNetworkInstanceStatus(ctx, netstatus)
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

	ctx := ctxArg.(*zedrouterContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s\n", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s\n", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.GCInitialized = true
		ctx.appStatsInterval = gcp.GlobalValueInt(types.AppContainerStatsInterval)
		ctx.disableDHCPAllOnesNetMask = gcp.GlobalValueBool(types.DisableDHCPAllOnesNetMask)
		metricInterval := gcp.GlobalValueInt(types.MetricInterval)
		if metricInterval != 0 && ctx.metricInterval != metricInterval {
			if ctx.publishTicker != nil {
				interval := time.Duration(metricInterval) * time.Second
				max := float64(interval) / publishTickerDivider
				min := max * 0.3
				ctx.publishTicker.UpdateRangeTicker(time.Duration(min), time.Duration(max))
			}

			ctx.metricInterval = metricInterval
		}
	}
	log.Functionf("handleGlobalConfigImpl done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s\n", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	gcp := *types.DefaultConfigItemValueMap()
	ctx.appStatsInterval = gcp.GlobalValueInt(types.AppContainerStatsInterval)
	log.Functionf("handleGlobalConfigDelete done for %s\n", key)
}

func handleAACreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAAImpl(ctxArg, key, statusArg)
}

func handleAAModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAAImpl(ctxArg, key, statusArg)
}

func handleAAImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	status := statusArg.(types.AssignableAdapters)
	if key != "global" {
		log.Functionf("handleAAImpl: ignoring %s\n", key)
		return
	}
	log.Functionf("handleAAImpl() %+v\n", status)
	*ctx.assignableAdapters = status

	// Look for ports which disappeared
	maybeRetryNetworkInstances(ctx)
	propagateNetworkInstToAppNetwork(ctx)
	log.Functionf("handleAAImpl() done\n")
}

func handleAADelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	if key != "global" {
		log.Functionf("handleAADelete: ignoring %s\n", key)
		return
	}
	log.Functionf("handleAADelete()\n")
	ctx.assignableAdapters.Initialized = false
	log.Functionf("handleAADelete() done\n")
}

func handleDNSCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*zedrouterContext)
	if key != "global" {
		log.Functionf("handleDNSImpl: ignoring %s\n", key)
		return
	}
	log.Functionf("handleDNSImpl for %s\n", key)

	// if we received DeviceNetworkStatus it indicates that default iptables chains allocated
	if !ctx.iptablesInitialized {
		// Setup initial iptables rules
		dropEscapedFlows()
		ctx.iptablesInitialized = true
	}

	// Ignore test status and timestamps
	if ctx.deviceNetworkStatus.MostlyEqual(status) {
		log.Functionf("handleDNSImpl no change\n")
		return
	}
	log.Functionf("handleDNSImpl: changed %v",
		cmp.Diff(ctx.deviceNetworkStatus, status))

	if isDNSServerChanged(ctx, &status) {
		doDnsmasqRestart(ctx)
	}

	changedDepend := changedACLDepend(ctx, *ctx.deviceNetworkStatus,
		status)
	*ctx.deviceNetworkStatus = status
	maybeHandleDNS(ctx)
	if changedDepend != nil {
		updateACLIPAddr(ctx, changedDepend)
	}

	if ctx.uplinkProber != nil {
		ctx.uplinkProber.ApplyDNSUpdate(status)
	}

	// Look for ports which disappeared
	maybeRetryNetworkInstances(ctx)
	propagateNetworkInstToAppNetwork(ctx)
	handleMetaDataServerChange(ctx, &status)
	log.Functionf("handleDNSImpl done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*zedrouterContext)

	if key != "global" {
		log.Functionf("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	maybeHandleDNS(ctx)
	log.Functionf("handleDNSDelete done for %s\n", key)
}

// changedACLDepend determines the interfaces/ports and assigned IP addresses
// which are changed from old to new.
// The old IP address is placed in ACLDepend
func changedACLDepend(ctx *zedrouterContext, oldDNS types.DeviceNetworkStatus,
	newDNS types.DeviceNetworkStatus) []types.ACLDepend {

	var dependList []types.ACLDepend
	// Any change of ports in DeviceNetworkStatus that can affect application
	// network instances will be responded to by the network probing subsystem
	// by changing current uplink of the affected network instance.
	// Any change to current uplink of a network instance triggers a complete
	// re-programming of ACLs.
	for i, op := range oldDNS.Ports {
		if len(newDNS.Ports) <= i {
			log.Tracef("changedACLDepend: %s disappeared",
				op.IfName)
			// Port disappeared - treat as change
			depend := types.ACLDepend{Ifname: op.IfName}
			dependList = append(dependList, depend)
			continue
		}
		np := newDNS.Ports[i]
		for j, oai := range op.AddrInfoList {
			if len(np.AddrInfoList) <= j {
				log.Tracef("changedACLDepend: %s %s disappeared",
					op.IfName, oai.Addr.String())
				// Address disappeared - treat as change
				depend := types.ACLDepend{Ifname: op.IfName,
					IPAddr: oai.Addr}
				dependList = append(dependList, depend)
				continue
			}
			nai := np.AddrInfoList[j]
			if !oai.Addr.Equal(nai.Addr) {
				log.Tracef("changedACLDepend: %s %s changed to %s",
					op.IfName, oai.Addr.String(), nai.Addr.String())
				depend := types.ACLDepend{Ifname: op.IfName,

					IPAddr: oai.Addr}
				dependList = append(dependList, depend)
			}
		}
		// Does the new DNS port have new addresses?
		if len(np.AddrInfoList) > len(op.AddrInfoList) {
			depend := types.ACLDepend{Ifname: np.IfName}
			dependList = append(dependList, depend)
		}
	}
	return dependList
}

// updateACLIPAddr checks which AppNetworkStatus have ACLDependList
// which is a subset of the changedDepend
// An empty IP address in ACLDependList means match is just on the ifname
func updateACLIPAddr(ctx *zedrouterContext, changedDepend []types.ACLDepend) {
	log.Functionf("updateACLIPAddr changedDepend: %+v", changedDepend)
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		config := lookupAppNetworkConfig(ctx, status.Key())
		if config == nil || !config.Activate {
			log.Tracef("updateACLIPAddr skipping %s: no config",
				status.Key())
			continue
		}
		for i := range config.UnderlayNetworkList {
			ulConfig := &config.UnderlayNetworkList[i]
			if len(status.UnderlayNetworkList) <= i {
				log.Noticef("updateACLIPAddr skipping ul %d %s: no status",
					i, config.Key())
				continue
			}
			ulStatus := &status.UnderlayNetworkList[i]
			if ulStatus.ACLDependList == nil {
				log.Tracef("updateACLIPAddr skipping ul %d %s: ACLDependList",
					i, status.Key())
				continue
			}
			match := false
			for _, d := range ulStatus.ACLDependList {
				// if d.Ifname in changedDepend
				for _, c := range changedDepend {
					if d.Ifname != c.Ifname {
						continue
					}
					if len(d.IPAddr) == 0 || len(c.IPAddr) == 0 ||
						d.IPAddr.Equal(c.IPAddr) {
						log.Noticef("updateACLIPAddr match on %s == %s for %s",
							c.IPAddr, d.IPAddr, status.Key())
						match = true
						break
					}
				}
				if match {
					break
				}
			}
			if !match {
				continue
			}
			ipsets := compileAppInstanceIpsets(ctx,
				config.UnderlayNetworkList)
			doAppNetworkModifyUNetAcls(ctx, &status,
				ulConfig, ulConfig, ulStatus, ipsets, true)
			publishAppNetworkStatus(ctx, &status)
		}
	}
}

func validateAppNetworkConfig(ctx *zedrouterContext, appNetConfig types.AppNetworkConfig,
	appNetStatus *types.AppNetworkStatus) error {
	log.Functionf("AppNetwork(%s), check for duplicate port map acls", appNetConfig.DisplayName)
	// For App Networks, check for common port map rules
	ulCfgList0 := appNetConfig.UnderlayNetworkList
	if len(ulCfgList0) == 0 {
		return nil
	}
	if containsHangingACLPortMapRule(ctx, ulCfgList0) {
		err := fmt.Errorf("network with no uplink, has portmap")
		log.Error(err.Error())
		addError(ctx, appNetStatus, "underlayACL", err)
		return err
	}
	sub := ctx.subAppNetworkConfig
	items := sub.GetAll()
	for _, c := range items {
		appNetConfig1 := c.(types.AppNetworkConfig)
		ulCfgList1 := appNetConfig1.UnderlayNetworkList
		if len(ulCfgList1) == 0 {
			continue
		}
		// XXX can an delete+add of app instance with same
		// portmap result in a failure?
		if appNetConfig.DisplayName == appNetConfig1.DisplayName {
			continue
		}
		appNetStatus1 := lookupAppNetworkStatus(ctx, appNetConfig1.Key())
		if appNetStatus1 == nil {
			continue
		}
		if appNetStatus1.HasError() && !appNetStatus1.Activated {
			continue
		}
		if checkUnderlayNetworkForPortMapOverlap(ctx, appNetStatus, ulCfgList0, ulCfgList1) {
			err := fmt.Errorf("app %s and %s have duplicate portmaps",
				appNetStatus.DisplayName, appNetStatus1.DisplayName)
			log.Error(err.Error())
			addError(ctx, appNetStatus, "underlayACL", err)
			return err
		}
	}
	return nil
}

// whether there is a portmap rule, on with a network instance with no
// uplink interface
func containsHangingACLPortMapRule(ctx *zedrouterContext,
	ulCfgList []types.UnderlayNetworkConfig) bool {
	for _, ulCfg := range ulCfgList {
		network := ulCfg.Network.String()
		netInstStatus := lookupNetworkInstanceStatus(ctx, network)
		if netInstStatus == nil || netInstStatus.Logicallabel != "" ||
			len(netInstStatus.IfNameList) != 0 {
			continue
		}
		if containsPortMapACE(ulCfg.ACLs) {
			return true
		}
	}
	return false
}

func checkUnderlayNetworkForPortMapOverlap(ctx *zedrouterContext,
	appNetStatus *types.AppNetworkStatus, ulCfgList []types.UnderlayNetworkConfig,
	ulCfgList1 []types.UnderlayNetworkConfig) bool {
	for _, ulCfg := range ulCfgList {
		network := ulCfg.Network.String()
		// validate whether there are duplicate portmap rules
		// within itself
		if matchACLForPortMap(ulCfg.ACLs) {
			log.Errorf("app Network(%s) has duplicate portmaps\n", network)
			errStr := fmt.Sprintf("duplicate portmap rules")
			err := errors.New(errStr)
			addError(ctx, appNetStatus, "underlayACL", err)
			return false
		}
		for _, ulCfg1 := range ulCfgList1 {
			network1 := ulCfg1.Network.String()
			if network == network1 || checkUplinkPortOverlap(ctx, network, network1) {
				if matchACLsForPortMap(ulCfg.ACLs, ulCfg1.ACLs) {
					log.Functionf("ACL PortMap overlaps for %s, %s\n", network, network1)
					log.Errorf("app Network(%s) have overlapping portmap rule in %s\n",
						network, network1)
					errStr := fmt.Sprintf("duplicate portmap in %s", network1)
					err := errors.New(errStr)
					addError(ctx, appNetStatus, "underlayACL", err)
					return true
				}
			}
		}
	}
	return false
}

// network instances sharing common uplink
func checkUplinkPortOverlap(ctx *zedrouterContext, network string, network1 string) bool {
	netInstStatus := lookupNetworkInstanceStatus(ctx, network)
	netInstStatus1 := lookupNetworkInstanceStatus(ctx, network1)
	if netInstStatus == nil || netInstStatus1 == nil {
		log.Tracef("non-existent network-instance status\n")
		return false
	}
	// check the interface list for overlap
	for _, ifName := range netInstStatus.IfNameList {
		for _, ifName1 := range netInstStatus1.IfNameList {
			if ifName == ifName1 {
				log.Tracef("uplink(%s) overlaps for (%s, %s)\n", ifName, network, network1)
				return true
			}
		}
	}
	log.Tracef("no uplink overlaps for (%s, %s)\n", network, network1)
	return false
}

// scan through existing AppNetworkStatus list and set a timer
// to retry later
func checkAppNetworkErrorAndStartTimer(ctx *zedrouterContext) {
	log.Functionf("checkAppNetworkErrorAndStartTimer()\n")
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		config := lookupAppNetworkConfig(ctx, status.Key())
		if config == nil || !config.Activate || !status.HasError() {
			continue
		}
		// We wouldn't have even copied underlay
		// networks into status. This is as good as starting
		// from scratch all over. App num that would have been
		// allocated will be used this time also, since the app UUID
		// does not change.
		// When hit error while creating, set a timer for 60 sec and come back to retry
		log.Functionf("checkAppNetworkErrorAndStartTimer: set timer\n")
		ctx.appNetCreateTimer = time.NewTimer(60 * time.Second)
	}
}

// scan through existing AppNetworkStatus list to bring
// up any AppNetwork struck in error state, while
// contending for resource
func scanAppNetworkStatusInErrorAndUpdate(ctx *zedrouterContext) {
	log.Functionf("scanAppNetworkStatusInErrorAndUpdate()\n")
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		config := lookupAppNetworkConfig(ctx, status.Key())
		if config == nil || !config.Activate || !status.HasError() {
			continue
		}
		// called from the timer, run the AppNetworkCreate to retry
		log.Functionf("scanAppNetworkStatusInErrorAndUpdate: retry the AppNetworkCreate\n")
		handleAppNetworkCreate(ctx, status.Key(), *config)
	}
}

// in case of any failures, its better to release the set
// of ip rules, created by this app network
func releaseAppNetworkResources(ctx *zedrouterContext, key string,
	status *types.AppNetworkStatus) {
	log.Functionf("relaseAppNetworkResources(%s)\n", key)
	appID := status.UUIDandVersion.UUID
	for _, ulStatus := range status.UnderlayNetworkList {
		aclArgs := types.AppNetworkACLArgs{BridgeName: ulStatus.Bridge,
			VifName: ulStatus.Vif}
		rules := getNetworkACLRules(ctx, appID, ulStatus.Name)
		ruleList, err := deleteACLConfiglet(aclArgs, rules.ACLRules)
		if err != nil {
			addError(ctx, status, "deleteACL", err)
		}
		setNetworkACLRules(ctx, appID, ulStatus.Name, ruleList)
	}
	publishAppNetworkStatus(ctx, status)
}

func isDNSServerChanged(ctx *zedrouterContext, newStatus *types.DeviceNetworkStatus) bool {
	var dnsDiffer bool
	for _, port := range newStatus.Ports {
		if _, ok := ctx.dnsServers[port.IfName]; !ok {
			// if dnsServer does not have valid server IPs, assign now
			// and if we lose uplink connection, it will not overwrite the previous server IPs
			if len(port.DNSServers) > 0 { // just assigned
				ctx.dnsServers[port.IfName] = port.DNSServers
			}
		} else {
			// only check if we have valid new DNS server sets on the uplink
			// valid DNS server IP changes will trigger the restart of dnsmasq.
			if len(port.DNSServers) != 0 {
				// new one has different entries, and not the Internet disconnect case
				if len(ctx.dnsServers[port.IfName]) != len(port.DNSServers) {
					ctx.dnsServers[port.IfName] = port.DNSServers
					dnsDiffer = true
					continue
				}
				for idx, server := range port.DNSServers { // compare each one and update if changed
					if server.Equal(ctx.dnsServers[port.IfName][idx]) == false {
						log.Functionf("isDnsServerChanged: intf %s exist %v, new %v\n",
							port.IfName, ctx.dnsServers[port.IfName], port.DNSServers)
						ctx.dnsServers[port.IfName] = port.DNSServers
						dnsDiffer = true
						break
					}
				}

			}
		}
	}
	return dnsDiffer
}

func doDnsmasqRestart(ctx *zedrouterContext) {
	pub := ctx.pubNetworkInstanceStatus
	stList := pub.GetAll()
	for _, st := range stList {
		status := st.(types.NetworkInstanceStatus)
		if status.Type != types.NetworkInstanceTypeLocal {
			continue
		}
		if status.Activated {
			log.Functionf("restart dnsmasq on bridgename %s\n", status.BridgeName)
			restartDnsmasq(ctx, &status)
		}
	}
}

// XXX: Dead code. May be useful when we do wireguard/tailscale
func deleteAppInstanceOverlayRoute(
	ctx *zedrouterContext,
	status *types.AppNetworkStatus) {
	bridgeName := "" // XXX Fill bridge name
	oLink, err := findBridge(bridgeName)
	if err != nil {
		addError(ctx, status, "findBridge", err)
		log.Functionf("deleteAppInstanceOverlayRoute done for %s\n",
			status.DisplayName)
		return
	}
	var subnetSuffix string

	EID := net.IP{} // XXX Fill with valid ip address
	isIPv6 := (EID.To4() == nil)
	if isIPv6 {
		subnetSuffix = "/128"
	} else {
		subnetSuffix = "/32"
	}
	_, ipnet, err := net.ParseCIDR(EID.String() + subnetSuffix)
	if err != nil {
		errStr := fmt.Sprintf("ParseCIDR %s failed: %v",
			EID.String()+subnetSuffix, err)
		addError(ctx, status, "deleteAppInstanceOverlayRoute",
			errors.New(errStr))
		log.Functionf("deleteAppInstanceOverlayRoute done for %s\n",
			status.DisplayName)
		return
	}
	rt := netlink.Route{Dst: ipnet, LinkIndex: oLink.Index}
	if err := netlink.RouteDel(&rt); err != nil {
		errStr := fmt.Sprintf("RouteDelete %s failed: %s",
			EID, err)
		addError(ctx, status, "deleteAppInstanceOverlayRoute",
			errors.New(errStr))
		log.Functionf("deleteAppInstanceOverlayRoute done for %s\n",
			status.DisplayName)
	}
}

// XXX: Deac code. May be useful when we do wireguard/tailscale
func addAppInstanceOverlayRoute(
	ctx *zedrouterContext,
	status *types.AppNetworkStatus) {
	bridgeName := "" // XXX Fill bridge name
	oLink, err := findBridge(bridgeName)
	if err != nil {
		addError(ctx, status, "findBridge", err)
		log.Functionf("addAppInstaneOverlayRoute done for %s\n",
			status.DisplayName)
		return
	}
	var subnetSuffix string

	EID := net.IP{} // XXX Fill with valid ip address
	isIPv6 := (EID.To4() == nil)
	if isIPv6 {
		subnetSuffix = "/128"
	} else {
		subnetSuffix = "/32"
	}
	_, ipnet, err := net.ParseCIDR(EID.String() + subnetSuffix)
	if err != nil {
		errStr := fmt.Sprintf("ParseCIDR %s failed: %v",
			EID.String()+subnetSuffix, err)
		addError(ctx, status, "addAppInstaneOverlayRoute",
			errors.New(errStr))
		log.Functionf("addAppInstaneOverlayRoute done for %s\n",
			status.DisplayName)
		return
	}
	rt := netlink.Route{Dst: ipnet, LinkIndex: oLink.Index}
	if err := netlink.RouteAdd(&rt); err != nil {
		errStr := fmt.Sprintf("RouteAdd %s failed: %s",
			EID, err)
		addError(ctx, status, "addAppInstaneOverlayRoute",
			errors.New(errStr))
		log.Functionf("addAppInstaneOverlayRoute done for %s\n",
			status.DisplayName)
	}
}

// getSSHPublicKeys : returns trusted SSH public keys
func getSSHPublicKeys(ctx *zedrouterContext, dc *types.AppNetworkConfig) []string {
	// TBD: add ssh keys into cypher block
	return nil
}

// getCloudInitUserData : returns decrypted cloud-init user data
func getCloudInitUserData(ctx *zedrouterContext,
	dc *types.AppNetworkConfig) (string, error) {
	if dc.CipherBlockStatus.IsCipher {
		status, decBlock, err := cipher.GetCipherCredentials(&ctx.decryptCipherContext,
			dc.CipherBlockStatus)
		ctx.pubCipherBlockStatus.Publish(status.Key(), status)
		if err != nil {
			log.Errorf("%s, appnetwork config cipherblock decryption unsuccessful, falling back to cleartext: %v",
				dc.Key(), err)
			if dc.CloudInitUserData == nil {
				ctx.cipherMetrics.RecordFailure(log, types.MissingFallback)
				return decBlock.ProtectedUserData, fmt.Errorf("appnetwork config cipherblock decryption"+
					"unsuccessful (%s); "+
					"no fallback data", err)
			}
			decBlock.ProtectedUserData = *dc.CloudInitUserData
			// We assume IsCipher is only set when there was some
			// data. Hence this is a fallback if there is
			// some cleartext.
			if decBlock.ProtectedUserData != "" {
				ctx.cipherMetrics.RecordFailure(log, types.CleartextFallback)
			} else {
				ctx.cipherMetrics.RecordFailure(log, types.MissingFallback)
			}
			return decBlock.ProtectedUserData, nil
		}
		log.Functionf("%s, appnetwork config cipherblock decryption successful", dc.Key())
		return decBlock.ProtectedUserData, nil
	}
	log.Functionf("%s, appnetwork config cipherblock not present", dc.Key())
	decBlock := types.EncryptionBlock{}
	if dc.CloudInitUserData == nil {
		ctx.cipherMetrics.RecordFailure(log, types.NoCipher)
		return decBlock.ProtectedUserData, nil
	}
	decBlock.ProtectedUserData = *dc.CloudInitUserData
	if decBlock.ProtectedUserData != "" {
		ctx.cipherMetrics.RecordFailure(log, types.NoCipher)
	} else {
		ctx.cipherMetrics.RecordFailure(log, types.NoData)
	}
	return decBlock.ProtectedUserData, nil
}
