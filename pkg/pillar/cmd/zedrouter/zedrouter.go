// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of a collection of AppNetworkConfig structs
// from zedmanager and zedagent. Publish the status as AppNetworkStatus.
// Produce the updated configlets (for radvd, dnsmasq, ip*tables,
// ipset, ip link/addr/route configuration) based on that and apply those
// configlets.

package zedrouter

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/eriknordmark/netlink"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName  = "zedrouter"
	runDirname = "/var/run/zedrouter"
	// DropMarkValue :
	DropMarkValue = 0xFFFFFF
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Set from Makefile
var Version = "No version specified"

type zedrouterContext struct {
	// Legacy data plane enable/disable flag
	legacyDataPlane bool

	agentStartTime        time.Time
	receivedConfigTime    time.Time
	triggerNumGC          bool // For appNum and bridgeNum
	subAppNetworkConfig   pubsub.Subscription
	subAppNetworkConfigAg pubsub.Subscription // From zedagent for dom0

	pubAppNetworkStatus pubsub.Publication

	assignableAdapters     *types.AssignableAdapters
	subAssignableAdapters  pubsub.Subscription
	subDeviceNetworkStatus pubsub.Subscription
	deviceNetworkStatus    *types.DeviceNetworkStatus
	ready                  bool
	subGlobalConfig        pubsub.Subscription
	GCInitialized          bool
	pubUuidToNum           pubsub.Publication
	dhcpLeases             []dnsmasqLease

	// NetworkInstance
	subNetworkInstanceConfig  pubsub.Subscription
	pubNetworkInstanceStatus  pubsub.Publication
	pubNetworkInstanceMetrics pubsub.Publication
	pubAppFlowMonitor         pubsub.Publication
	pubAppVifIPTrig           pubsub.Publication
	pubAppContainerMetrics    pubsub.Publication
	networkInstanceStatusMap  map[uuid.UUID]*types.NetworkInstanceStatus
	dnsServers                map[string][]net.IP // Key is ifname
	checkNIUplinks            chan bool
	hostProbeTimer            *time.Timer
	hostFastProbe             bool
	appNetCreateTimer         *time.Timer
	appCollectStatsRunning    bool
	appStatsMutex             sync.Mutex // to protect the changing appNetworkStatus & appCollectStatsRunning
	appStatsInterval          uint32
}

var debug = false
var debugOverride bool // From command line arg
var log *base.LogObject

func Run(ps *pubsub.PubSub) int {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return 0
	}
	// XXX Make logrus record a noticable global source
	agentlog.Init("xyzzy-" + agentName)

	log = agentlog.Init(agentName)

	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s\n", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	if _, err := os.Stat(runDirname); err != nil {
		log.Infof("Create %s\n", runDirname)
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

	pubUuidToNum, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		Persistent: true,
		TopicType:  types.UuidToNum{},
	})
	if err != nil {
		log.Fatal(err)
	}
	pubUuidToNum.ClearRestarted()

	// Create the dummy interface used to re-direct DROP/REJECT packets.
	createFlowMonDummyInterface(DropMarkValue)

	// Pick up (mostly static) AssignableAdapters before we process
	// any Routes; Pbr needs to know which network adapters are assignable

	aa := types.AssignableAdapters{}
	zedrouterCtx := zedrouterContext{
		legacyDataPlane:    false,
		assignableAdapters: &aa,
		agentStartTime:     time.Now(),
		dnsServers:         make(map[string][]net.IP),
	}
	zedrouterCtx.networkInstanceStatusMap =
		make(map[uuid.UUID]*types.NetworkInstanceStatus)

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &zedrouterCtx,
		CreateHandler: handleDNSModify,
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
		TopicImpl:     types.AssignableAdapters{},
		Activate:      false,
		Ctx:           &zedrouterCtx,
		CreateHandler: handleAAModify,
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
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           &zedrouterCtx,
		CreateHandler: handleGlobalConfigModify,
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

	zedrouterCtx.deviceNetworkStatus = &types.DeviceNetworkStatus{}
	zedrouterCtx.pubUuidToNum = pubUuidToNum

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

	pubAppVifIPTrig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VifIPTrig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubAppVifIPTrig = pubAppVifIPTrig

	pubAppContainerMetrics, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppContainerMetrics{},
	})
	if err != nil {
		log.Fatal(err)
	}
	zedrouterCtx.pubAppContainerMetrics = pubAppContainerMetrics

	nms := getNetworkMetrics(&zedrouterCtx) // Need type of data
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: nms,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Pick up debug aka log level before we start real work
	for !zedrouterCtx.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

	appNumAllocatorInit(&zedrouterCtx)
	bridgeNumAllocatorInit(&zedrouterCtx)
	handleInit(runDirname)

	// Before we process any NetworkInstances we want to know the
	// assignable adapters.
	for !zedrouterCtx.assignableAdapters.Initialized {
		log.Infof("Waiting for AssignableAdapters\n")
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
	log.Infof("Have %d assignable adapters\n", len(aa.IoBundleList))

	subNetworkInstanceConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		TopicImpl:     types.NetworkInstanceConfig{},
		Activate:      false,
		Ctx:           &zedrouterCtx,
		CreateHandler: handleNetworkInstanceModify,
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
	log.Infof("Subscribed to NetworkInstanceConfig")

	// Subscribe to AppNetworkConfig from zedmanager and from zedagent
	subAppNetworkConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "zedmanager",
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

	// Subscribe to AppNetworkConfig from zedmanager
	subAppNetworkConfigAg, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
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

	PbrInit(&zedrouterCtx)
	routeChanges := devicenetwork.RouteChangeInit(log)
	addrChanges := devicenetwork.AddrChangeInit(log)
	linkChanges := devicenetwork.LinkChangeInit(log)

	// Publish network metrics for zedagent every 10 seconds
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	flowStatIntv := time.Duration(120 * time.Second) // 120 sec, flow timeout if less than150 sec
	fmax := float64(flowStatIntv)
	fmin := fmax * 0.9
	flowStatTimer := flextimer.NewRangeTicker(time.Duration(fmin),
		time.Duration(fmax))

	setProbeTimer(&zedrouterCtx, nhProbeInterval)
	zedrouterCtx.checkNIUplinks = make(chan bool, 1) // allow one signal without blocking

	zedrouterCtx.appNetCreateTimer = time.NewTimer(1 * time.Second)
	zedrouterCtx.appNetCreateTimer.Stop()

	zedrouterCtx.ready = true
	log.Infof("zedrouterCtx.ready\n")

	// First wait for restarted from zedmanager to
	// reduce the number of LISP-RESTARTs
	for !subAppNetworkConfig.Restarted() {
		log.Infof("Waiting for zedrouter to report restarted")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)

		case change := <-subAppNetworkConfig.MsgChan():
			// If we have an NetworkInstanceConfig process it first
			checkAndProcessNetworkInstanceConfig(&zedrouterCtx)
			subAppNetworkConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subNetworkInstanceConfig.MsgChan():
			log.Infof("AppNetworkConfig - waiting to Restart - "+
				"InstanceConfig change at %+v", time.Now())
			subNetworkInstanceConfig.ProcessChange(change)
		}
		// Are we likely to have seen all of the initial config?
		if zedrouterCtx.triggerNumGC &&
			time.Since(zedrouterCtx.receivedConfigTime) > 5*time.Minute {

			start := time.Now()
			bridgeNumAllocatorGC(&zedrouterCtx)
			appNumAllocatorGC(&zedrouterCtx)
			zedrouterCtx.triggerNumGC = false
			ps.CheckMaxTimeTopic(agentName, "allocatorGC", start,
				warningTime, errorTime)
		}
	}
	log.Infof("Zedrouter has restarted. Entering main Select loop")

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)

		case change := <-subAppNetworkConfig.MsgChan():
			// If we have an NetworkInstanceConfig process it first
			checkAndProcessNetworkInstanceConfig(&zedrouterCtx)
			subAppNetworkConfig.ProcessChange(change)

		case change := <-subAppNetworkConfigAg.MsgChan():
			subAppNetworkConfigAg.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change, ok := <-addrChanges:
			start := time.Now()
			if !ok {
				log.Errorf("addrChanges closed\n")
				addrChanges = devicenetwork.AddrChangeInit(log)
				break
			}
			ifname := PbrAddrChange(zedrouterCtx.deviceNetworkStatus,
				change)
			if ifname != "" &&
				!types.IsMgmtPort(*zedrouterCtx.deviceNetworkStatus,
					ifname) {
				log.Debugf("addrChange(%s) not mgmt port\n", ifname)
				// Even if ethN isn't individually assignable, it
				// could be used for a bridge.
				maybeUpdateBridgeIPAddr(
					&zedrouterCtx, ifname)
			}
			ps.CheckMaxTimeTopic(agentName, "addrChanges", start,
				warningTime, errorTime)

		case change, ok := <-linkChanges:
			start := time.Now()
			if !ok {
				log.Errorf("linkChanges closed\n")
				linkChanges = devicenetwork.LinkChangeInit(log)
				break
			}
			ifname := PbrLinkChange(zedrouterCtx.deviceNetworkStatus,
				change)
			if ifname != "" &&
				!types.IsMgmtPort(*zedrouterCtx.deviceNetworkStatus,
					ifname) {
				log.Debugf("linkChange(%s) not mgmt port\n", ifname)
				// Even if ethN isn't individually assignable, it
				// could be used for a bridge.
				maybeUpdateBridgeIPAddr(
					&zedrouterCtx, ifname)
			}
			ps.CheckMaxTimeTopic(agentName, "linkChanges", start,
				warningTime, errorTime)

		case change, ok := <-routeChanges:
			start := time.Now()
			if !ok {
				log.Errorf("routeChanges closed\n")
				routeChanges = devicenetwork.RouteChangeInit(log)
				break
			}
			PbrRouteChange(&zedrouterCtx,
				zedrouterCtx.deviceNetworkStatus, change)
			ps.CheckMaxTimeTopic(agentName, "routeChanges", start,
				warningTime, errorTime)

		case <-publishTimer.C:
			start := time.Now()
			log.Debugln("publishTimer at", time.Now())
			err := pub.Publish("global",
				getNetworkMetrics(&zedrouterCtx))
			if err != nil {
				log.Errorf("getNetworkMetrics failed %s\n", err)
			}
			publishNetworkInstanceMetricsAll(&zedrouterCtx)
			ps.CheckMaxTimeTopic(agentName, "publishNetworkInstanceMetrics", start,
				warningTime, errorTime)

			start = time.Now()
			// Check for changes to DHCP leases
			// XXX can we trigger it as part of boot? Or watch file?
			// XXX add file watch...
			checkAndPublishDhcpLeases(&zedrouterCtx)
			ps.CheckMaxTimeTopic(agentName, "PublishDhcpLeases", start,
				warningTime, errorTime)

		case <-flowStatTimer.C:
			start := time.Now()
			log.Debugf("FlowStatTimer at %v", time.Now())
			// XXX why start a new go routine for each change?
			log.Infof("Creating %s at %s", "FlowStatsCollect",
				agentlog.GetMyStack())
			go FlowStatsCollect(&zedrouterCtx)
			ps.CheckMaxTimeTopic(agentName, "FlowStatsCollect", start,
				warningTime, errorTime)

		case <-zedrouterCtx.hostProbeTimer.C:
			start := time.Now()
			log.Debugf("HostProbeTimer at %v", time.Now())
			// launch the go function gateway/remote hosts probing check
			log.Infof("Creating %s at %s", "launchHostProbe",
				agentlog.GetMyStack())
			go launchHostProbe(&zedrouterCtx)
			ps.CheckMaxTimeTopic(agentName, "lauchHostProbe", start,
				warningTime, errorTime)

		case <-zedrouterCtx.appNetCreateTimer.C:
			start := time.Now()
			log.Debugf("appNetCreateTimer: at %v", time.Now())
			scanAppNetworkStatusInErrorAndUpdate(&zedrouterCtx)
			ps.CheckMaxTimeTopic(agentName, "scanAppNetworkStatus", start,
				warningTime, errorTime)

		case <-zedrouterCtx.checkNIUplinks:
			start := time.Now()
			log.Infof("checkNIUplinks channel signal\n")
			checkAndReprogramNetworkInstances(&zedrouterCtx)
			ps.CheckMaxTimeTopic(agentName, "checkAndReprogram", start,
				warningTime, errorTime)

		case change := <-subNetworkInstanceConfig.MsgChan():
			log.Infof("NetworkInstanceConfig change at %+v", time.Now())
			subNetworkInstanceConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
		// Are we likely to have seen all of the initial config?
		if zedrouterCtx.triggerNumGC &&
			time.Since(zedrouterCtx.receivedConfigTime) > 5*time.Minute {
			start := time.Now()
			bridgeNumAllocatorGC(&zedrouterCtx)
			appNumAllocatorGC(&zedrouterCtx)
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
		log.Infof("Processing NetworkInstanceConfig before AppNetworkConfig")
		ctx.subNetworkInstanceConfig.ProcessChange(change)
	default:
		log.Infof("NO NetworkInstanceConfig before AppNetworkConfig")
	}
}

func maybeHandleDNS(ctx *zedrouterContext) {
	if !ctx.ready {
		return
	}

	// XXX do a NatInactivate/NatActivate if management ports changed?
}

func handleRestart(ctxArg interface{}, done bool) {

	log.Debugf("handleRestart(%v)\n", done)
	ctx := ctxArg.(*zedrouterContext)
	if done {
		// Since all work is done inline we can immediately say that
		// we have restarted.
		ctx.pubAppNetworkStatus.SignalRestarted()
	}
}

func handleInit(runDirname string) {
	// XXX should this be in dnsmasq code?
	// Need to make sure we don't have any stale leases
	leasesFile := "/var/lib/misc/dnsmasq.leases"
	if _, err := os.Stat(leasesFile); err == nil {
		if err := os.Remove(leasesFile); err != nil {
			log.Fatal(err)
		}
	}

	// Setup initial iptables rules
	iptables.IptablesInit(log)

	// ipsets which are independent of config
	createDefaultIpset()
}

func publishAppNetworkStatus(ctx *zedrouterContext,
	status *types.AppNetworkStatus) {

	key := status.Key()
	log.Infof("publishAppNetworkStatus(%s-%s)\n", status.DisplayName, key)
	pub := ctx.pubAppNetworkStatus
	pub.Publish(key, *status)
}

func unpublishAppNetworkStatus(ctx *zedrouterContext,
	status *types.AppNetworkStatus) {

	key := status.Key()
	log.Debugf("unpublishAppNetworkStatus(%s)\n", key)
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

	log.Infof("handleAppNetworkConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedrouterContext)
	status := lookupAppNetworkStatus(ctx, key)
	if status == nil {
		log.Infof("handleAppNetworkConfigDelete: unknown %s\n", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Infof("handleAppNetworkConfigDelete(%s) done\n", key)
	// on resource release, check whether any one else
	// needs it
	checkAppNetworkErrorAndStartTimer(ctx)
}

// Callers must be careful to publish any changes to AppNetworkStatus
func lookupAppNetworkStatus(ctx *zedrouterContext, key string) *types.AppNetworkStatus {

	pub := ctx.pubAppNetworkStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Debugf("lookupAppNetworkStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.AppNetworkStatus)
	return &status
}

func lookupAppNetworkConfig(ctx *zedrouterContext, key string) *types.AppNetworkConfig {

	sub := ctx.subAppNetworkConfig
	c, _ := sub.Get(key)
	if c == nil {
		sub = ctx.subAppNetworkConfigAg
		c, _ = sub.Get(key)
		if c == nil {
			log.Debugf("lookupAppNetworkConfig(%s) not found\n", key)
			return nil
		}
	}
	config := c.(types.AppNetworkConfig)
	return &config
}

// Track the device information so we can annotate the application EIDs
// Note that when we start with zedrouter config files in place the
// device one might be processed after application ones, in which case these
// empty. This results in less additional info recorded in the map servers.
// XXX note that this only works well when the IsZedmanager AppNetworkConfig
// arrives first so that these fields are filled in before other
// AppNetworkConfig entries are processed.
var deviceEID net.IP
var deviceIID uint32
var additionalInfoDevice *types.AdditionalInfoDevice

func handleAppNetworkCreate(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	config := configArg.(types.AppNetworkConfig)
	log.Infof("handleAppNetworkCreate(%s-%s)\n", config.DisplayName, key)

	// If this is the first time, update the timer for GC
	if ctx.receivedConfigTime.IsZero() {
		log.Infof("triggerNumGC")
		ctx.receivedConfigTime = time.Now()
		ctx.triggerNumGC = true
	}

	log.Infof("handleAppAppNetworkCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// Pick a local number to identify the application instance
	// Used for IP addresses as well bridge and file names.
	appNum := appNumAllocate(ctx, config.UUIDandVersion.UUID, false)

	// Start by marking with PendingAdd
	status := types.AppNetworkStatus{
		UUIDandVersion: config.UUIDandVersion,
		AppNum:         appNum,
		PendingAdd:     true,
		DisplayName:    config.DisplayName,
	}
	publishAppNetworkStatus(ctx, &status)

	if config.Activate {
		doActivate(ctx, config, &status)
	}
	status.PendingAdd = false
	publishAppNetworkStatus(ctx, &status)
	log.Infof("handleAppNetworkCreate done for %s\n", config.DisplayName)
	if status.HasError() && config.Activate && !status.Activated {
		releaseAppNetworkResources(ctx, key, &status)
	}
	log.Infof("handleAppNetworkCreate(%s) done\n", key)
	// on resource release, check whether any one else
	// needs it
	checkAppNetworkErrorAndStartTimer(ctx)
}

func doActivate(ctx *zedrouterContext, config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	log.Infof("%s-%s\n",
		config.DisplayName, config.UUIDandVersion)

	// Check that Network exists for all underlays.
	// We look for MissingNetwork when a NetworkInstance is added
	allNetworksExist := appNetworkCheckAllNetworksExist(ctx, config, status)
	if !allNetworksExist {
		// XXX error or not?
		status.MissingNetwork = true
		log.Infof("doActivate(%v) for %s: missing networks\n",
			config.UUIDandVersion, config.DisplayName)
		publishAppNetworkStatus(ctx, status)
		return
	}
	appNetworkDoCopyNetworksToStatus(ctx, config, status)
	if !validateAppNetworkConfig(ctx, config, status) {
		log.Errorf("doActivate(%v) AppNetwork Config check failed for %s\n",
			config.UUIDandVersion, config.DisplayName)
		publishAppNetworkStatus(ctx, status)
		return
	}

	// Note that with IPv4/IPv6 interfaces the domU can do
	// dns lookups on either IPv4 and IPv6 on any interface, hence we
	// configure the ipsets for all the domU's interfaces/bridges.
	ipsets := compileAppInstanceIpsets(ctx, config.UnderlayNetworkList)

	appNetworkDoActivateAllUnderlayNetworks(ctx, config, status, ipsets)

	status.Activated = true
	publishAppNetworkStatus(ctx, status)
	log.Infof("doActivate done for %s\n", config.DisplayName)
}

func appNetworkDoActivateAllUnderlayNetworks(
	ctx *zedrouterContext,
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus,
	ipsets []string) {
	for i, ulConfig := range config.UnderlayNetworkList {
		ulNum := i + 1
		log.Debugf("ulNum %d network %s ACLs %v\n",
			ulNum, ulConfig.Network.String(), ulConfig.ACLs)
		appNetworkDoActivateUnderlayNetwork(
			ctx, config, status, ipsets, &ulConfig, ulNum)

	}
}

// Get Switch's IPv4 address for the port in NetworkInstance
func getSwitchIPv4Addr(ctx *zedrouterContext,
	status *types.NetworkInstanceStatus) (string, error) {
	// Find any service which is associated with the appLink UUID
	log.Infof("getSwitchIPv4Addr(%s-%s)\n",
		status.DisplayName, status.UUID.String())
	if status.Type != types.NetworkInstanceTypeSwitch {
		errStr := fmt.Sprintf("NI not a switch. Type: %d", status.Type)
		return "", errors.New(errStr)
	}
	if status.Logicallabel == "" {
		log.Infof("SwitchType, but no LogicalLabel\n")
		return "", nil
	}

	ifname := types.LogicallabelToIfName(ctx.deviceNetworkStatus, status.Logicallabel)
	ifindex, err := devicenetwork.IfnameToIndex(log, ifname)
	if err != nil {
		errStr := fmt.Sprintf("getSwitchIPv4Addr(%s): IfnameToIndex(%s) failed %s",
			status.DisplayName, ifname, err)
		return "", errors.New(errStr)
	}
	addrs, err := devicenetwork.IfindexToAddrs(log, ifindex)
	if err != nil {
		errStr := fmt.Sprintf("getSwitchIPv4Addr(%s): IfindexToAddrs(%s, index %d) failed %s",
			status.DisplayName, ifname, ifindex, err)
		return "", errors.New(errStr)
	}
	for _, addr := range addrs {
		log.Infof("getSwitchIPv4Addr(%s): found addr %s\n",
			status.DisplayName, addr.String())
		// XXX Add IPv6 underlay; ignore link-locals.
		if addr.To4() != nil {
			return addr.String(), nil
		}
	}
	log.Infof("getSwitchIPv4Addr(%s): no IPv4 address on %s yet\n",
		status.DisplayName, status.Logicallabel)
	return "", nil
}

func appNetworkDoActivateUnderlayNetwork(
	ctx *zedrouterContext,
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus,
	ipsets []string,
	ulConfig *types.UnderlayNetworkConfig,
	ulNum int) {

	netInstConfig := lookupNetworkInstanceConfig(ctx,
		ulConfig.Network.String())
	if netInstConfig == nil {
		log.Fatalf("Cannot find UL NetworkInstance %s for App %s",
			ulConfig.Name, config.DisplayName)
	}
	netInstStatus := lookupNetworkInstanceStatus(ctx,
		ulConfig.Network.String())
	if netInstStatus == nil {
		errStr := fmt.Sprintf("no status for %s",
			ulConfig.Network.String())
		err := errors.New(errStr)
		addError(ctx, status, "doActivate underlay", err)
		return
	}
	if netInstStatus.HasError() {
		log.Errorf("doActivate sees network error %s\n",
			netInstStatus.Error)
		addError(ctx, status, "error from network instance",
			errors.New(netInstStatus.Error))
		return
	}
	networkInstanceInfo := &netInstStatus.NetworkInstanceInfo

	// Fetch the network that this underlay is attached to
	bridgeName := networkInstanceInfo.BridgeName
	vifName := "nbu" + strconv.Itoa(ulNum) + "x" +
		strconv.Itoa(status.AppNum)
	uLink, err := findBridge(bridgeName)
	if err != nil {
		addError(ctx, status, "findBridge", err)
		log.Infof("doActivate done for %s\n",
			config.DisplayName)
		return
	}
	bridgeMac := uLink.HardwareAddr
	log.Infof("bridgeName %s MAC %s\n",
		bridgeName, bridgeMac.String())

	var appMac string // Handed to domU
	if ulConfig.AppMacAddr != nil {
		appMac = ulConfig.AppMacAddr.String()
	} else {
		// Room to handle multiple underlays in 5th byte
		appMac = fmt.Sprintf("00:16:3e:00:%02x:%02x",
			ulNum, status.AppNum)
	}
	log.Infof("appMac %s\n", appMac)

	// Record what we have so far
	ulStatus := &status.UnderlayNetworkList[ulNum-1]
	log.Infof("doActivate ulNum %d: %v\n", ulNum, ulStatus)
	ulStatus.Name = ulConfig.Name
	ulStatus.Bridge = bridgeName
	ulStatus.BridgeMac = bridgeMac
	ulStatus.Vif = vifName
	ulStatus.Mac = appMac
	ulStatus.HostName = config.Key()

	bridgeIPAddr, appIPAddr, err := getUlAddrs(ctx, ulNum-1,
		status.AppNum, ulStatus, netInstStatus)
	if err != nil {
		addError(ctx, status, "getUlAddrs", err)
		log.Errorf("appNetworkDoActivateUnderlayNetwork: Bridge/App IP address allocation "+
			"failed for app %s", status.DisplayName)
		return
	}

	// Check if we have a bridge service with an address
	bridgeIP, err := getSwitchIPv4Addr(ctx, netInstStatus)
	if err != nil {
		log.Infof("doActivate: %s\n", err)
	} else if bridgeIP != "" {
		log.Infof("bridgeIp: %s\n", bridgeIP)
		bridgeIPAddr = bridgeIP
	}
	log.Infof("bridgeIPAddr %s appIPAddr %s\n", bridgeIPAddr, appIPAddr)
	ulStatus.BridgeIPAddr = bridgeIPAddr
	// XXX appIPAddr is "" if bridge service
	ulStatus.AllocatedIPAddr = appIPAddr
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
	ruleList, err := createACLConfiglet(aclArgs, ulStatus.ACLs)
	if err != nil {
		addError(ctx, status, "createACL", err)
	}
	ulStatus.ACLRules = ruleList

	if appIPAddr != "" {
		// XXX clobber any IPv6 EID entry since same name
		// but that's probably OK since we're doing IPv4 EIDs
		addhostDnsmasq(bridgeName, appMac, appIPAddr,
			config.UUIDandVersion.UUID.String())
	}

	// Look for added or deleted ipsets
	newIpsets, staleIpsets, restartDnsmasq := diffIpsets(ipsets,
		networkInstanceInfo.BridgeIPSets)

	if restartDnsmasq && ulStatus.BridgeIPAddr != "" {
		stopDnsmasq(bridgeName, true, false)
		dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
			netInstStatus.CurrentUplinkIntf)
		createDnsmasqConfiglet(bridgeName,
			ulStatus.BridgeIPAddr, netInstConfig, hostsDirpath,
			newIpsets, false, netInstStatus.CurrentUplinkIntf,
			dnsServers)
		startDnsmasq(bridgeName)
	}
	networkInstanceInfo.AddVif(log, vifName, appMac,
		config.UUIDandVersion.UUID)
	networkInstanceInfo.BridgeIPSets = newIpsets
	log.Infof("set BridgeIPSets to %v for %s", newIpsets,
		networkInstanceInfo.BridgeName)

	// Check App Container Stats ACL need to be reinstalled
	appStatsMayNeedReinstallACL(ctx, config)

	publishNetworkInstanceStatus(ctx, netInstStatus)

	maybeRemoveStaleIpsets(staleIpsets)
}

func appNetworkDoCopyNetworksToStatus(
	ctx *zedrouterContext,
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	// during doActive, copy the collect stats IP to status and
	// check to see if need to launch the process
	appCheckStatsCollect(ctx, &config, status)

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
		log.Infof("doActivate failed: %s\n", errStr)
		addError(ctx, status, "doActivate underlay",
			errors.New(errStr))
		return false
	}
	return true
}

// Called when a NetworkInstance is added
// Walk all AppNetworkStatus looking for MissingNetwork, then
// check if network UUID is there.
func checkAndRecreateAppNetwork(
	ctx *zedrouterContext, network uuid.UUID) {

	log.Infof("checkAndRecreateAppNetwork(%s)\n", network.String())
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		if !status.MissingNetwork {
			continue
		}
		log.Infof("checkAndRecreateAppNetwork(%s) missing for %s\n",
			network.String(), status.DisplayName)

		config := lookupAppNetworkConfig(ctx, status.Key())
		if config == nil {
			log.Warnf("checkAndRecreateAppNetwork(%s) no config for %s\n",
				network.String(), status.DisplayName)
			continue
		}
		if !config.IsNetworkUsed(network) {
			continue
		}
		log.Infof("checkAndRecreateAppNetwork(%s) recreating for %s\n",
			network.String(), status.DisplayName)
		if status.HasError() {
			log.Infof("checkAndRecreateAppNetwork(%s) remove error %s for %s\n",
				network.String(), status.Error,
				status.DisplayName)
			status.ClearError()
		}
		doActivate(ctx, *config, &status)
		log.Infof("checkAndRecreateAppNetwork done for %s\n",
			config.DisplayName)
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
	ifnum int, appNum int,
	status *types.UnderlayNetworkStatus,
	netInstStatus *types.NetworkInstanceStatus) (string, string, error) {

	log.Infof("getUlAddrs(%d/%d)\n", ifnum, appNum)

	bridgeIPAddr := ""
	appIPAddr := ""

	// Allocate bridgeIPAddr based on BridgeMac
	log.Infof("getUlAddrs(%d/%d for %s) bridgeMac %s\n",
		ifnum, appNum, netInstStatus.UUID.String(),
		status.BridgeMac.String())
	var err error
	var addr string
	addr, err = lookupOrAllocateIPv4(ctx, netInstStatus,
		status.BridgeMac)
	if err != nil {
		log.Errorf("getUlAddrs: Bridge IP address allocation failed %s\n", err)
		return bridgeIPAddr, appIPAddr, err
	} else {
		bridgeIPAddr = addr
	}

	if status.AppIPAddr != nil {
		// Static IP assignment case.
		// Note that appIPAddr can be in a different subnet.
		// Assumption is that the config specifies a gateway/router
		// in the same subnet as the static address.
		appIPAddr = status.AppIPAddr.String()
		recordIPAssignment(ctx, netInstStatus, status.AppIPAddr,
			status.Mac)
	} else if status.Mac != "" {
		// XXX or change type of VifInfo.Mac to avoid parsing?
		var mac net.HardwareAddr
		mac, err = net.ParseMAC(status.Mac)
		if err != nil {
			log.Fatal("ParseMAC failed: ", status.Mac, err)
		}
		log.Infof("getUlAddrs(%d/%d for %s) app Mac %s\n",
			ifnum, appNum, netInstStatus.UUID.String(), mac.String())
		addr, err = lookupOrAllocateIPv4(ctx, netInstStatus, mac)
		if err != nil {
			log.Errorf("getUlAddrs: App IP address allocation failed: %s\n", err)
			return bridgeIPAddr, appIPAddr, err
		} else {
			appIPAddr = addr
		}
	}
	log.Infof("getUlAddrs(%d/%d) done %s/%s\n",
		ifnum, appNum, bridgeIPAddr, appIPAddr)
	return bridgeIPAddr, appIPAddr, err
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

// Note that handleModify will not touch the EID; just ACLs
// XXX should we check that nothing else has changed?
// XXX If so flag other changes as errors; would need lastError in status.
func handleAppNetworkModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	config := configArg.(types.AppNetworkConfig)
	status := lookupAppNetworkStatus(ctx, key)
	log.Infof("handleAppNetworkModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	// reset error status and mark pending modify as true
	status.ClearError()
	status.PendingModify = true
	publishAppNetworkStatus(ctx, status)

	if !doAppNetworkSanityCheckForModify(ctx, config, status) {
		status.PendingModify = false
		publishAppNetworkStatus(ctx, status)
		log.Errorf("handleAppNetworkModify: Config check failed for %s\n", config.DisplayName)
		return
	}

	// No check for version numbers since the ACLs etc might change
	// even for the same version.
	log.Debugf("handleAppNetworkModify appNum %d\n", status.AppNum)

	// Check for unsupported changes
	status.UUIDandVersion = config.UUIDandVersion
	publishAppNetworkStatus(ctx, status)

	if !config.Activate && status.Activated {
		doInactivateAppNetwork(ctx, status)
	}

	// Note that with IPv4/IPv6 interfaces the domU can do
	// dns lookups on either IPv4 and IPv6 on any interface, hence should
	// configure the ipsets for all the domU's interfaces/bridges.
	ipsets := compileAppInstanceIpsets(ctx, config.UnderlayNetworkList)

	// If we are not activated, then the doActivate below will set up
	// the ACLs
	if status.Activated {
		// during modify, copy the collect stats IP to status and
		// check to see if need to launch the process
		appCheckStatsCollect(ctx, &config, status)

		// Look for ACL changes in underlay
		doAppNetworkModifyAllUnderlayNetworks(ctx, config, status, ipsets)

		// Write out what we modified to AppNetworkStatus
		// Note that lengths are the same as before
		for i := range config.UnderlayNetworkList {
			status.UnderlayNetworkList[i].UnderlayNetworkConfig =
				config.UnderlayNetworkList[i]
		}
	}

	if config.Activate && !status.Activated {
		// XXX the doAppNetworkModify calls above did
		// an updateACL and doActivate will do a createACL resulting
		// in duplicate (but harmless) rules.
		doActivate(ctx, config, status)
	}

	status.PendingModify = false
	publishAppNetworkStatus(ctx, status)
	log.Infof("handleAppNetworkModify done for %s\n", config.DisplayName)

	if status != nil && status.HasError() &&
		config.Activate && !status.Activated {
		releaseAppNetworkResources(ctx, key, status)
	}
	log.Infof("handleAppNetworkModify(%s) done\n", key)
	// on resource release, check whether any one else
	// needs it
	checkAppNetworkErrorAndStartTimer(ctx)
}

func doAppNetworkSanityCheckForModify(ctx *zedrouterContext,
	config types.AppNetworkConfig, status *types.AppNetworkStatus) bool {
	// XXX what about changing the number of interfaces as
	// part of an inactive/active transition?
	// XXX We could should we allow the addition of interfaces
	// if the domU would find out through some hotplug event.
	// But deletion is hard.
	// For now don't allow any adds or deletes.
	if len(config.UnderlayNetworkList) != len(status.UnderlayNetworkList) {
		errStr := fmt.Sprintf("Unsupported: Changed number of underlays for %s",
			config.UUIDandVersion)
		addError(ctx, status, "handleModify", errors.New(errStr))
		log.Infof("handleModify done for %s\n", config.DisplayName)
		return false
	}
	for i := range config.UnderlayNetworkList {
		ulConfig := &config.UnderlayNetworkList[i]
		netconfig := lookupNetworkInstanceConfig(ctx,
			ulConfig.Network.String())
		if netconfig == nil {
			errStr := fmt.Sprintf("no network Instance config for %s",
				ulConfig.Network.String())
			err := errors.New(errStr)
			addError(ctx, status, "lookupNetworkInstanceConfig", err)
			return false
		}
		netstatus := lookupNetworkInstanceStatus(ctx,
			ulConfig.Network.String())
		if netstatus == nil {
			// We had a netconfig but no status!
			errStr := fmt.Sprintf("no network Instance status for %s",
				ulConfig.Network.String())
			err := errors.New(errStr)
			addError(ctx, status, "handleModify underlay sanity check "+
				" - no network instance", err)
			return false
		}
	}

	if !validateAppNetworkConfig(ctx, config, status) {
		publishAppNetworkStatus(ctx, status)
		log.Errorf("handleModify: AppNetworkConfig check failed for %s\n", config.DisplayName)
		return false
	}
	return true
}

func doAppNetworkModifyAllUnderlayNetworks(
	ctx *zedrouterContext,
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus,
	ipsets []string) {

	for i := range config.UnderlayNetworkList {
		log.Debugf("handleModify ulNum %d\n", i)
		ulConfig := &config.UnderlayNetworkList[i]
		ulStatus := &status.UnderlayNetworkList[i]
		doAppNetworkModifyUnderlayNetwork(
			ctx, status, ulConfig, ulStatus, ipsets, false)
	}
}

func doAppNetworkModifyUnderlayNetwork(
	ctx *zedrouterContext,
	status *types.AppNetworkStatus,
	ulConfig *types.UnderlayNetworkConfig,
	ulStatus *types.UnderlayNetworkStatus,
	ipsets []string, force bool) {

	bridgeName := ulStatus.Bridge
	appIPAddr := ulStatus.AllocatedIPAddr

	netconfig := lookupNetworkInstanceConfig(ctx, ulConfig.Network.String())
	netstatus := lookupNetworkInstanceStatus(ctx, ulConfig.Network.String())

	aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: bridgeName,
		VifName: ulStatus.Vif, BridgeIP: ulStatus.BridgeIPAddr, AppIP: appIPAddr,
		UpLinks: netstatus.IfNameList, NIType: netstatus.Type,
		AppNum: int32(status.AppNum)}

	// We ignore any errors in netstatus

	// XXX could there be a change to AllocatedIPAddress?
	// If so updateNetworkACLConfiglet needs to know old and new
	// XXX Could ulStatus.Vif not be set? Means we didn't add
	ruleList, err := updateACLConfiglet(aclArgs,
		ulStatus.ACLs, ulConfig.ACLs, ulStatus.ACLRules, force)
	if err != nil {
		addError(ctx, status, "updateACL", err)
	}
	ulStatus.ACLRules = ruleList

	newIpsets, staleIpsets, restartDnsmasq := diffIpsets(ipsets,
		netstatus.BridgeIPSets)

	if restartDnsmasq && ulStatus.BridgeIPAddr != "" {
		hostsDirpath := runDirname + "/hosts." + bridgeName
		stopDnsmasq(bridgeName, true, false)
		dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
			netstatus.CurrentUplinkIntf)
		createDnsmasqConfiglet(bridgeName,
			ulStatus.BridgeIPAddr, netconfig, hostsDirpath,
			newIpsets, false, netstatus.CurrentUplinkIntf, dnsServers)
		startDnsmasq(bridgeName)
	}
	netstatus.BridgeIPSets = newIpsets
	log.Infof("set BridgeIPSets to %v for %s", newIpsets, netstatus.Key())
	publishNetworkInstanceStatus(ctx, netstatus)

	maybeRemoveStaleIpsets(staleIpsets)
}

func maybeRemoveStaleIpsets(staleIpsets []string) {
	// Remove stale ipsets
	// In case if there are any references to these ipsets from other
	// domUs, then the kernel would not remove them.
	// The ipset destroy command would just fail.
	for _, ipset := range staleIpsets {
		err := ipsetDestroy(fmt.Sprintf("ipv4.%s", ipset))
		if err != nil {
			log.Errorln("ipset destroy ipv4", ipset, err)
		}
		err = ipsetDestroy(fmt.Sprintf("ipv6.%s", ipset))
		if err != nil {
			log.Errorln("ipset destroy ipv6", ipset, err)
		}
	}
}

func handleDelete(ctx *zedrouterContext, key string,
	status *types.AppNetworkStatus) {

	log.Infof("handleDelete(%v) for %s\n",
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

	appNumFree(ctx, status.UUIDandVersion.UUID)
	log.Infof("handleDelete done for %s\n", status.DisplayName)
}

func doInactivateAppNetwork(ctx *zedrouterContext,
	status *types.AppNetworkStatus) {

	log.Infof("doInactivate(%v) for %s\n",
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
	log.Infof("doInactivate done for %s\n", status.DisplayName)
}

func appNetworkDoInactivateAllUnderlayNetworks(
	ctx *zedrouterContext,
	status *types.AppNetworkStatus,
	ipsets []string) {

	for ulNum := 0; ulNum < len(status.UnderlayNetworkList); ulNum++ {
		ulStatus := &status.UnderlayNetworkList[ulNum]
		log.Infof("doInactivate ulNum %d: %v\n", ulNum, ulStatus)
		appNetworkDoInactivateUnderlayNetwork(
			ctx, status, ulStatus, ipsets)
	}
}

func appNetworkDoInactivateUnderlayNetwork(
	ctx *zedrouterContext,
	status *types.AppNetworkStatus,
	ulStatus *types.UnderlayNetworkStatus,
	ipsets []string) {

	bridgeName := ulStatus.Bridge

	netconfig := lookupNetworkInstanceConfig(ctx,
		ulStatus.Network.String())
	if netconfig == nil {
		errStr := fmt.Sprintf("no network config for %s",
			ulStatus.Network.String())
		err := errors.New(errStr)
		addError(ctx, status, "lookupNetworkInstanceConfig", err)
		return
	}
	netstatus := lookupNetworkInstanceStatus(ctx,
		ulStatus.Network.String())
	if netstatus == nil {
		// We had a netconfig but no status!
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

	appIPAddr := ulStatus.AllocatedIPAddr
	if appIPAddr != "" {
		removehostDnsmasq(bridgeName, ulStatus.Mac,
			appIPAddr)
	}

	aclArgs := types.AppNetworkACLArgs{IsMgmt: false, BridgeName: bridgeName,
		VifName: ulStatus.Vif, BridgeIP: ulStatus.BridgeIPAddr, AppIP: appIPAddr,
		UpLinks: netstatus.IfNameList}

	// XXX Could ulStatus.Vif not be set? Means we didn't add
	if ulStatus.Vif != "" {
		ruleList, err := deleteACLConfiglet(aclArgs, ulStatus.ACLRules)
		if err != nil {
			addError(ctx, status, "deleteACL", err)
		}
		ulStatus.ACLRules = ruleList
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

	if restartDnsmasq && ulStatus.BridgeIPAddr != "" {
		stopDnsmasq(bridgeName, true, false)
		dnsServers := types.GetDNSServers(*ctx.deviceNetworkStatus,
			netstatus.CurrentUplinkIntf)
		createDnsmasqConfiglet(bridgeName,
			ulStatus.BridgeIPAddr, netconfig, hostsDirpath,
			newIpsets, false, netstatus.CurrentUplinkIntf, dnsServers)
		startDnsmasq(bridgeName)
	}
	netstatus.RemoveVif(log, ulStatus.Vif)
	netstatus.BridgeIPSets = newIpsets
	log.Infof("set BridgeIPSets to %v for %s", newIpsets, netstatus.Key())
	maybeRemoveStaleIpsets(staleIpsets)

	// publish the changes to network instance status
	publishNetworkInstanceStatus(ctx, netstatus)
}

func pkillUserArgs(userName string, match string, printOnError bool) {
	cmd := "pkill"
	args := []string{
		// XXX note that alpine does not support -u
		// XXX		"-u",
		// XXX		userName,
		"-f",
		match,
	}
	var err error
	var out []byte
	for i := 0; i < 3; i++ {
		log.Infof("Calling command %s %v\n", cmd, args)
		out, err = exec.Command(cmd, args...).CombinedOutput()
		if err == nil {
			break
		}
		if printOnError {
			log.Warnf("Retrying failed command %v %v: %s output %s",
				cmd, args, err, out)
		}
		time.Sleep(time.Second)
	}
	if err != nil && printOnError {
		log.Errorf("Command %v %v failed: %s output %s\n",
			cmd, args, err, out)
	}
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		ctx.GCInitialized = true
		ctx.appStatsInterval = gcp.GlobalValueInt(types.AppContainerStatsInterval)
	}
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
	gcp := *types.DefaultConfigItemValueMap()
	ctx.appStatsInterval = gcp.GlobalValueInt(types.AppContainerStatsInterval)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

func handleAAModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	status := statusArg.(types.AssignableAdapters)
	if key != "global" {
		log.Infof("handleAAModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleAAModify() %+v\n", status)
	*ctx.assignableAdapters = status
	log.Infof("handleAAModify() done\n")
}

func handleAADelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedrouterContext)
	if key != "global" {
		log.Infof("handleAADelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleAADelete()\n")
	ctx.assignableAdapters.Initialized = false
	log.Infof("handleAADelete() done\n")
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*zedrouterContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	// Ignore test status and timestamps
	if ctx.deviceNetworkStatus.Equal(status) {
		log.Infof("handleDNSModify no change\n")
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(ctx.deviceNetworkStatus, status))

	if isDNSServerChanged(ctx, &status) {
		doDnsmasqRestart(ctx)
	}

	*ctx.deviceNetworkStatus = status
	maybeHandleDNS(ctx)

	deviceUpdateNIprobing(ctx, &status)

	log.Infof("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*zedrouterContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	maybeHandleDNS(ctx)
	log.Infof("handleDNSDelete done for %s\n", key)
}

func validateAppNetworkConfig(ctx *zedrouterContext, appNetConfig types.AppNetworkConfig,
	appNetStatus *types.AppNetworkStatus) bool {
	log.Infof("AppNetwork(%s), check for duplicate port map acls", appNetConfig.DisplayName)
	// For App Networks, check for common port map rules
	ulCfgList0 := appNetConfig.UnderlayNetworkList
	if len(ulCfgList0) == 0 {
		return true
	}
	if containsHangingACLPortMapRule(ctx, ulCfgList0) {
		log.Errorf("app (%s) on network with no uplink and has portmap rule\n",
			appNetConfig.DisplayName)
		errStr := fmt.Sprintf("network with no uplink, has portmap")
		err := errors.New(errStr)
		addError(ctx, appNetStatus, "underlayACL", err)
		return false
	}
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		appNetStatus1 := st.(types.AppNetworkStatus)
		ulCfgList1 := appNetStatus1.UnderlayNetworkList
		// XXX can an delete+add of app instance with same
		// portmap result in a failure?
		if appNetStatus.DisplayName == appNetStatus1.DisplayName ||
			(appNetStatus1.HasError() && !appNetStatus1.Activated) || len(ulCfgList1) == 0 {
			continue
		}
		if checkUnderlayNetworkForPortMapOverlap(ctx, appNetStatus, ulCfgList0, ulCfgList1) {
			log.Errorf("app %s and %s have duplicate portmaps",
				appNetStatus.DisplayName, appNetStatus1.DisplayName)
			return false
		}
	}
	return true
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
	ulCfgList1 []types.UnderlayNetworkStatus) bool {
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
					log.Infof("ACL PortMap overlaps for %s, %s\n", network, network1)
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
		log.Debugf("non-existent network-instance status\n")
		return false
	}
	// check the interface list for overlap
	for _, ifName := range netInstStatus.IfNameList {
		for _, ifName1 := range netInstStatus1.IfNameList {
			if ifName == ifName1 {
				log.Debugf("uplink(%s) overlaps for (%s, %s)\n", ifName, network, network1)
				return true
			}
		}
	}
	log.Debugf("no uplink overlaps for (%s, %s)\n", network, network1)
	return false
}

// scan through existing AppNetworkStatus list and set a timer
// to retry later
func checkAppNetworkErrorAndStartTimer(ctx *zedrouterContext) {
	log.Infof("checkAppNetworkErrorAndStartTimer()\n")
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
		log.Infof("checkAppNetworkErrorAndStartTimer: set timer\n")
		ctx.appNetCreateTimer = time.NewTimer(60 * time.Second)
	}
}

// scan through existing AppNetworkStatus list to bring
// up any AppNetwork struck in error state, while
// contending for resource
func scanAppNetworkStatusInErrorAndUpdate(ctx *zedrouterContext) {
	log.Infof("scanAppNetworkStatusInErrorAndUpdate()\n")
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		config := lookupAppNetworkConfig(ctx, status.Key())
		if config == nil || !config.Activate || !status.HasError() {
			continue
		}
		// called from the timer, run the AppNetworkCreate to retry
		log.Infof("scanAppNetworkStatusInErrorAndUpdate: retry the AppNetworkCreate\n")
		handleAppNetworkCreate(ctx, status.Key(), *config)
	}
}

// in case of any failures, its better to release the set
// of ip rules, created by this app network
func releaseAppNetworkResources(ctx *zedrouterContext, key string,
	status *types.AppNetworkStatus) {
	log.Infof("relaseAppNetworkResources(%s)\n", key)
	for idx, ulStatus := range status.UnderlayNetworkList {
		aclArgs := types.AppNetworkACLArgs{BridgeName: ulStatus.Bridge,
			VifName: ulStatus.Vif}
		ruleList, err := deleteACLConfiglet(aclArgs, ulStatus.ACLRules)
		if err != nil {
			addError(ctx, status, "deleteACL", err)
		}
		status.UnderlayNetworkList[idx].ACLRules = ruleList
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
						log.Infof("isDnsServerChanged: intf %s exist %v, new %v\n",
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
			log.Infof("restart dnsmasq on bridgename %s\n", status.BridgeName)
			restartDnsmasq(ctx, &status)
		}
	}
}

// XXX: Dead code. May be useful when we do wireguard/tailscale
func deleteAppInstaneOverlayRoute(
	ctx *zedrouterContext,
	status *types.AppNetworkStatus) {
	bridgeName := "" // XXX Fill bridge name
	oLink, err := findBridge(bridgeName)
	if err != nil {
		addError(ctx, status, "findBridge", err)
		log.Infof("deleteAppInstaneOverlayRoute done for %s\n",
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
		addError(ctx, status, "deleteAppInstaneOverlayRoute",
			errors.New(errStr))
		log.Infof("deleteAppInstaneOverlayRoute done for %s\n",
			status.DisplayName)
		return
	}
	rt := netlink.Route{Dst: ipnet, LinkIndex: oLink.Index}
	if err := netlink.RouteDel(&rt); err != nil {
		errStr := fmt.Sprintf("RouteDelete %s failed: %s",
			EID, err)
		addError(ctx, status, "deleteAppInstaneOverlayRoute",
			errors.New(errStr))
		log.Infof("deleteAppInstaneOverlayRoute done for %s\n",
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
		log.Infof("addAppInstaneOverlayRoute done for %s\n",
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
		log.Infof("addAppInstaneOverlayRoute done for %s\n",
			status.DisplayName)
		return
	}
	rt := netlink.Route{Dst: ipnet, LinkIndex: oLink.Index}
	if err := netlink.RouteAdd(&rt); err != nil {
		errStr := fmt.Sprintf("RouteAdd %s failed: %s",
			EID, err)
		addError(ctx, status, "addAppInstaneOverlayRoute",
			errors.New(errStr))
		log.Infof("addAppInstaneOverlayRoute done for %s\n",
			status.DisplayName)
	}
}
