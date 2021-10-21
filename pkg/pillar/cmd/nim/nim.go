// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage the network interfaces based on configuration from
// different sources. Attempts to test configuration changes before applying
// them.
// Maintains old configuration as lower-priority but always tries to move to the
// most recent aka highest priority configuration.

package nim

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"sort"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/ssh"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "nim"
	// Time limits for event loop handlers; shorter for nim than other agents
	errorTime   = 60 * time.Second
	warningTime = 40 * time.Second
)

type nimContext struct {
	deviceNetworkContext devicenetwork.DeviceNetworkContext
	subGlobalConfig      pubsub.Subscription
	GCInitialized        bool // Received initial GlobalConfig
	globalConfig         *types.ConfigItemValueMap
	sshAccess            bool
	sshAuthorizedKeys    string
	allowAppVnc          bool

	subNetworkInstanceStatus pubsub.Subscription

	networkFallbackAnyEth types.TriState
	fallbackPortMap       map[string]bool
	filteredFallback      map[string]bool

	// CLI args
	debug         bool
	debugOverride bool // From command line arg
	useStdout     bool
	version       bool
}

// Set from Makefile
var Version = "No version specified"
var logger *logrus.Logger
var log *base.LogObject

func (ctx *nimContext) processArgs() {
	versionPtr := flag.Bool("v", false, "Print Version of the agent.")
	debugPtr := flag.Bool("d", false, "Set Debug level")
	stdoutPtr := flag.Bool("s", false, "Use stdout")
	flag.Parse()

	ctx.debug = *debugPtr
	ctx.debugOverride = ctx.debug
	ctx.useStdout = *stdoutPtr
	if ctx.debugOverride {
		logrus.SetLevel(logrus.TraceLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	ctx.version = *versionPtr
}

// Run - Main function - invoked from zedbox.go
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	nimCtx := nimContext{
		deviceNetworkContext: devicenetwork.DeviceNetworkContext{
			ZedcloudMetrics: zedcloud.NewAgentMetrics(),
			CipherMetrics:   cipher.NewAgentMetrics(agentName),
		},
		fallbackPortMap:  make(map[string]bool),
		filteredFallback: make(map[string]bool),
	}
	nimCtx.deviceNetworkContext.AgentName = agentName
	nimCtx.deviceNetworkContext.AssignableAdapters = &types.AssignableAdapters{}
	nimCtx.sshAccess = true // Kernel default - no iptables filters
	nimCtx.globalConfig = types.DefaultConfigItemValueMap()

	nimCtx.processArgs()
	if nimCtx.version {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return 0
	}
	nimCtx.deviceNetworkContext.Log = log

	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}
	log.Noticef("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Publish metrics for zedagent every 10 seconds
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &nimCtx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		SyncHandler:   handleGlobalConfigSynchronized,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Wait for initial GlobalConfig
	for !nimCtx.GCInitialized {
		log.Noticef("Waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		}
	}
	log.Noticef("processed GlobalConfig")

	pubDeviceNetworkStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DeviceNetworkStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubDeviceNetworkStatus.ClearRestarted()

	cloudPingMetricPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.MetricsMap{},
		})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.deviceNetworkContext.PubPingMetricMap = cloudPingMetricPub

	pubDevicePortConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DevicePortConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubDevicePortConfig.ClearRestarted()

	// Publication to get lohs
	pubDummyDevicePortConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			AgentScope: "dummy",
			TopicType:  types.DevicePortConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubDummyDevicePortConfig.ClearRestarted()

	pubDevicePortConfigList, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: true,
			TopicType:  types.DevicePortConfigList{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubDevicePortConfigList.ClearRestarted()

	pubCipherBlockStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.CipherBlockStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}

	cipherMetricsPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.CipherMetrics{},
	})
	if err != nil {
		log.Fatal(err)
	}

	pubWwanMetrics, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.WwanMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}

	// Look for controller certs which will be used for decryption
	subControllerCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.ControllerCert{},
		Activate:    false,
		Ctx:         &nimCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.deviceNetworkContext.DecryptCipherContext.Log = log
	nimCtx.deviceNetworkContext.DecryptCipherContext.AgentName = agentName
	nimCtx.deviceNetworkContext.DecryptCipherContext.AgentMetrics = nimCtx.deviceNetworkContext.CipherMetrics
	nimCtx.deviceNetworkContext.DecryptCipherContext.SubControllerCert = subControllerCert
	subControllerCert.Activate()

	// Look for edge node certs which will be used for decryption
	subEdgeNodeCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeCert{},
		Activate:    false,
		Persistent:  true,
		Ctx:         &nimCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.deviceNetworkContext.DecryptCipherContext.SubEdgeNodeCert = subEdgeNodeCert
	subEdgeNodeCert.Activate()

	// Look for cipher context which will be used for decryption
	subCipherContext, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.CipherContext{},
		Activate:    false,
		Ctx:         &nimCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.deviceNetworkContext.DecryptCipherContext.SubCipherContext = subCipherContext
	subCipherContext.Activate()

	nimCtx.deviceNetworkContext.DevicePortConfig = &types.DevicePortConfig{}
	nimCtx.deviceNetworkContext.DeviceNetworkStatus = &types.DeviceNetworkStatus{}
	nimCtx.deviceNetworkContext.PubDevicePortConfig = pubDevicePortConfig
	nimCtx.deviceNetworkContext.PubDummyDevicePortConfig = pubDummyDevicePortConfig
	nimCtx.deviceNetworkContext.PubDevicePortConfigList = pubDevicePortConfigList
	nimCtx.deviceNetworkContext.PubCipherBlockStatus = pubCipherBlockStatus
	nimCtx.deviceNetworkContext.PubDeviceNetworkStatus = pubDeviceNetworkStatus
	nimCtx.deviceNetworkContext.PubWwanMetrics = pubWwanMetrics
	dnc := &nimCtx.deviceNetworkContext
	devicenetwork.IngestPortConfigList(dnc)

	// Check if we have a /config/DevicePortConfig/*.json which we need to
	// take into account by copying it to /run/global/DevicePortConfig/
	// We tag it with a OriginFile so that the file in /config/DevicePortConfig/
	// will be deleted once we have published its content in
	// the DevicePortConfigList.
	// This avoids repeated application of this startup file.
	ingestDevicePortConfig(&nimCtx)

	// We get DevicePortConfig from three sources in this priority:
	// 1. zedagent publishing DevicePortConfig
	// 2. override file in /run/global/DevicePortConfig/*.json
	// 3. "lastresort" derived from the set of network interfaces
	subDevicePortConfigA, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.DevicePortConfig{},
		Activate:      false,
		Ctx:           &nimCtx.deviceNetworkContext,
		CreateHandler: devicenetwork.HandleDPCCreate,
		ModifyHandler: devicenetwork.HandleDPCModify,
		DeleteHandler: devicenetwork.HandleDPCDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.deviceNetworkContext.SubDevicePortConfigA = subDevicePortConfigA
	subDevicePortConfigA.Activate()

	subDevicePortConfigO, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		MyAgentName:   agentName,
		TopicImpl:     types.DevicePortConfig{},
		Activate:      false,
		Ctx:           &nimCtx.deviceNetworkContext,
		CreateHandler: devicenetwork.HandleDPCCreate,
		ModifyHandler: devicenetwork.HandleDPCModify,
		DeleteHandler: devicenetwork.HandleDPCDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.deviceNetworkContext.SubDevicePortConfigO = subDevicePortConfigO
	subDevicePortConfigO.Activate()

	subDevicePortConfigS, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     agentName,
		MyAgentName:   agentName,
		TopicImpl:     types.DevicePortConfig{},
		Activate:      false,
		Ctx:           &nimCtx.deviceNetworkContext,
		CreateHandler: devicenetwork.HandleDPCCreate,
		ModifyHandler: devicenetwork.HandleDPCModify,
		DeleteHandler: devicenetwork.HandleDPCDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.deviceNetworkContext.SubDevicePortConfigS = subDevicePortConfigS
	subDevicePortConfigS.Activate()

	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           &nimCtx.deviceNetworkContext,
		CreateHandler: devicenetwork.HandleZedAgentStatusCreate,
		ModifyHandler: devicenetwork.HandleZedAgentStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.deviceNetworkContext.SubZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	subAssignableAdapters, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.AssignableAdapters{},
		Activate:      false,
		Ctx:           &nimCtx.deviceNetworkContext,
		CreateHandler: devicenetwork.HandleAssignableAdaptersCreate,
		ModifyHandler: devicenetwork.HandleAssignableAdaptersModify,
		DeleteHandler: devicenetwork.HandleAssignableAdaptersDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.deviceNetworkContext.SubAssignableAdapters = subAssignableAdapters
	subAssignableAdapters.Activate()

	subNetworkInstanceStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedrouter",
		MyAgentName:   agentName,
		TopicImpl:     types.NetworkInstanceStatus{},
		Activate:      false,
		Ctx:           &nimCtx,
		CreateHandler: handleNetworkInstanceCreate,
		ModifyHandler: handleNetworkInstanceModify,
		DeleteHandler: handleNetworkInstanceDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	nimCtx.subNetworkInstanceStatus = subNetworkInstanceStatus
	subNetworkInstanceStatus.Activate()

	devicenetwork.DoDNSUpdate(&nimCtx.deviceNetworkContext)

	// Apply any changes from the port config to date.
	publishDeviceNetworkStatus(&nimCtx)

	// We refresh the gelocation information when the underlay
	// IP address(es) change, plus periodically based on this timer
	geoRedoTime := time.Duration(nimCtx.globalConfig.GlobalValueInt(types.NetworkGeoRedoTime)) * time.Second

	// Timer for retries after failure etc. Should be less than geoRedoTime
	geoInterval := time.Duration(nimCtx.globalConfig.GlobalValueInt(types.NetworkGeoRetryTime)) * time.Second
	geoMax := float64(geoInterval)
	geoMin := geoMax * 0.3
	geoTimer := flextimer.NewRangeTicker(time.Duration(geoMin),
		time.Duration(geoMax))

	// Time we wait for DHCP to get an address before giving up
	dnc.DPCTestDuration = nimCtx.globalConfig.GlobalValueInt(types.NetworkTestDuration)

	// Timer for checking/verifying pending device network status
	// We stop this timer before using in the select loop below, because
	// we do not want the DPC list verification to start yet. We need a place
	// holder in the select loop.
	// Let the select loop have this stopped timer for now and
	// create a new timer when it's deemed required (change in DPC config).
	pendTimer := time.NewTimer(time.Duration(dnc.DPCTestDuration) * time.Second)
	pendTimer.Stop()
	dnc.Pending.PendTimer = pendTimer

	// Periodic timer that tests device cloud connectivity
	dnc.NetworkTestInterval = nimCtx.globalConfig.GlobalValueInt(types.NetworkTestInterval)
	dnc.NetworkTestTimer = time.NewTimer(time.Duration(dnc.NetworkTestInterval) * time.Second)
	// We start assuming cloud connectivity works
	dnc.CloudConnectivityWorks = true

	dnc.NetworkTestBetterInterval = nimCtx.globalConfig.GlobalValueInt(types.NetworkTestBetterInterval)
	if dnc.NetworkTestBetterInterval == 0 {
		log.Warnln("NOT running TestBetterTimer")
		// Dummy which is stopped needed for select loop
		networkTestBetterTimer := time.NewTimer(time.Hour)
		networkTestBetterTimer.Stop()
		dnc.NetworkTestBetterTimer = networkTestBetterTimer
	} else {
		networkTestBetterInterval := time.Duration(dnc.NetworkTestBetterInterval) * time.Second
		networkTestBetterTimer := time.NewTimer(networkTestBetterInterval)
		dnc.NetworkTestBetterTimer = networkTestBetterTimer
	}

	// Look for address and link changes
	routeChanges := devicenetwork.RouteChangeInit(log)
	addrChanges := devicenetwork.AddrChangeInit(log)
	linkChanges := devicenetwork.LinkChangeInit(log)

	// Build an initial lastresort by picking up initial links
	// XXX hack to pre-populate
	for idx := 0; idx < 16; idx++ {
		devicenetwork.IfindexToName(log, idx)
	}
	handleLinkChange(&nimCtx)
	updateFilteredFallback(&nimCtx)

	// Kick off intial configuration, which could be remembered from last boot
	// Prunes any useless entries
	devicenetwork.IngestPortConfigList(dnc)

	for nimCtx.networkFallbackAnyEth == types.TS_ENABLED &&
		len(dnc.DevicePortConfigList.PortConfigList) == 0 {

		log.Noticef("Waiting for initial DevicePortConfigList from lastresort")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDevicePortConfigS.MsgChan():
			subDevicePortConfigS.ProcessChange(change)
			log.Noticef("Got subDevicePortConfigS: len %d",
				len(dnc.DevicePortConfigList.PortConfigList))

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)

		case change, ok := <-linkChanges:
			start := time.Now()
			if !ok {
				log.Errorf("linkChanges closed")
				linkChanges = devicenetwork.LinkChangeInit(log)
				// XXX Need to discard all cached information?
			} else {
				ch, ifindex := devicenetwork.LinkChange(log, change)
				if ch {
					handleLinkChange(&nimCtx)
					handleInterfaceChange(&nimCtx, ifindex,
						"LinkChange", true)
				}
			}
			ps.CheckMaxTimeTopic(agentName, "linkChanges", start,
				warningTime, errorTime)

		case <-stillRunning.C:
			// Need StillRunning when ports yet Ethernets
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}

	devicenetwork.RestartVerify(dnc, "Initial config")

	// Watch for status and metrics published by wwan service.
	wwanWatcher, err := devicenetwork.InitWwanWatcher(log)
	if err != nil {
		log.Fatal(err)
	}
	defer wwanWatcher.Close()
	// Load initial wwan status if there is any.
	devicenetwork.ReloadWwanStatus(dnc)

	// To avoid a race between domainmgr starting and moving this to pciback
	// and zedagent publishing its DevicePortConfig using those assigned-away
	// adapter(s), we first wait for domainmgr to initialize AA, then enable
	// subDevicePortConfigA.
	// This wait can take a very long time since we first need to get
	// some usable IP addresses, or have waitforaddr time out, before we
	// even start the other agents. Punch StillRunning
	for !nimCtx.deviceNetworkContext.AssignableAdapters.Initialized {
		log.Noticef("Waiting for AA to initialize")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)

		case change := <-subDevicePortConfigO.MsgChan():
			subDevicePortConfigO.ProcessChange(change)

		case change := <-subDevicePortConfigS.MsgChan():
			subDevicePortConfigS.ProcessChange(change)

		case change := <-subZedAgentStatus.MsgChan():
			subZedAgentStatus.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)
			updateFilteredFallback(&nimCtx)

		case change := <-subNetworkInstanceStatus.MsgChan():
			subNetworkInstanceStatus.ProcessChange(change)

		case change, ok := <-addrChanges:
			start := time.Now()
			if !ok {
				log.Errorf("addrChanges closed")
				// XXX Need to discard all cached information?
				addrChanges = devicenetwork.AddrChangeInit(log)
			} else {
				ch, ifindex := devicenetwork.AddrChange(nimCtx.deviceNetworkContext, change)
				if ch {
					handleInterfaceChange(&nimCtx, ifindex,
						"AddrChange", true)
				}
			}
			ps.CheckMaxTimeTopic(agentName, "addrChanges", start,
				warningTime, errorTime)

		case change, ok := <-linkChanges:
			start := time.Now()
			if !ok {
				log.Errorf("linkChanges closed")
				linkChanges = devicenetwork.LinkChangeInit(log)
				// XXX Need to discard all cached information?
			} else {
				ch, ifindex := devicenetwork.LinkChange(log, change)
				if ch {
					handleLinkChange(&nimCtx)
					handleInterfaceChange(&nimCtx, ifindex,
						"LinkChange", true)
				}
			}
			ps.CheckMaxTimeTopic(agentName, "linkChanges", start,
				warningTime, errorTime)

		case change, ok := <-routeChanges:
			start := time.Now()
			if !ok {
				log.Errorf("routeChanges closed")
				routeChanges = devicenetwork.RouteChangeInit(log)
			} else {
				ch, ifindex := devicenetwork.RouteChange(nimCtx.deviceNetworkContext, change)
				if ch {
					handleInterfaceChange(&nimCtx, ifindex,
						"RouteChange", false)
				}
			}
			ps.CheckMaxTimeTopic(agentName, "linkChanges", start,
				warningTime, errorTime)

		case event, ok := <-wwanWatcher.Events:
			if !ok {
				log.Warnf("wwan watcher stopped")
				continue
			}
			devicenetwork.ProcessWwanWatchEvent(dnc, event)

		case <-geoTimer.C:
			start := time.Now()
			log.Traceln("geoTimer at", time.Now())
			change := devicenetwork.UpdateDeviceNetworkGeo(log,
				geoRedoTime, nimCtx.deviceNetworkContext.DeviceNetworkStatus)
			if change {
				publishDeviceNetworkStatus(&nimCtx)
			}
			ps.CheckMaxTimeTopic(agentName, "geoTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.Pending.PendTimer.C:
			start := time.Now()
			if !ok {
				log.Noticef("Device port test timer stopped?")
			} else {
				log.Traceln("PendTimer at", time.Now())
				devicenetwork.VerifyDevicePortConfig(dnc)
			}
			ps.CheckMaxTimeTopic(agentName, "PendTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.NetworkTestTimer.C:
			start := time.Now()
			if !ok {
				log.Noticef("Network test timer stopped?")
			} else if nimCtx.deviceNetworkContext.DevicePortConfigList.CurrentIndex == -1 {
				log.Tracef("Starting looking for working Device connectivity to cloud")
				devicenetwork.RestartVerify(dnc,
					"Looking for working")
				log.Noticef("Looking for working  done at index %d. Took %v",
					dnc.NextDPCIndex, time.Since(start))
			} else {
				log.Tracef("Starting test of Device connectivity to cloud")
				ok := tryDeviceConnectivityToCloud(dnc)
				if ok {
					log.Tracef("Device connectivity to cloud worked. Took %v",
						time.Since(start))
					// Look for DNS etc update
					devicenetwork.CheckDNSUpdate(
						&nimCtx.deviceNetworkContext)
				} else {
					log.Noticef("Device connectivity to cloud failed. Took %v",
						time.Since(start))
				}
			}
			ps.CheckMaxTimeTopic(agentName, "TestTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.NetworkTestBetterTimer.C:
			start := time.Now()
			if !ok {
				log.Noticef("Network testBetterTimer stopped?")
			} else if dnc.NextDPCIndex == 0 && !dnc.DeviceNetworkStatus.HasErrors() {
				log.Tracef("Network testBetterTimer at zero ignored")
			} else {
				log.Noticef("Network testBetterTimer at index %d",
					dnc.NextDPCIndex)
				devicenetwork.RestartVerify(dnc,
					"NetworkTestBetterTimer")
				log.Noticef("Network testBetterTimer done at index %d. Took %v",
					dnc.NextDPCIndex, time.Since(start))
			}
			ps.CheckMaxTimeTopic(agentName, "TestTimer", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Noticef("AA initialized")
	devicenetwork.MoveDownLocalIPRule(log, devicenetwork.PbrLocalDestPrio)

	for {
		select {
		case change := <-subControllerCert.MsgChan():
			subControllerCert.ProcessChange(change)

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)

		case change := <-subCipherContext.MsgChan():
			subCipherContext.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDevicePortConfigA.MsgChan():
			subDevicePortConfigA.ProcessChange(change)

		case change := <-subDevicePortConfigO.MsgChan():
			subDevicePortConfigO.ProcessChange(change)

		case change := <-subDevicePortConfigS.MsgChan():
			subDevicePortConfigS.ProcessChange(change)

		case change := <-subZedAgentStatus.MsgChan():
			subZedAgentStatus.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)
			updateFilteredFallback(&nimCtx)

		case change := <-subNetworkInstanceStatus.MsgChan():
			subNetworkInstanceStatus.ProcessChange(change)

		case change, ok := <-addrChanges:
			start := time.Now()
			if !ok {
				log.Errorf("addrChanges closed")
				addrChanges = devicenetwork.AddrChangeInit(log)
				// XXX Need to discard all cached information?
			} else {
				ch, ifindex := devicenetwork.AddrChange(nimCtx.deviceNetworkContext, change)
				if ch {
					handleInterfaceChange(&nimCtx, ifindex,
						"AddrChange", true)
				}
			}
			ps.CheckMaxTimeTopic(agentName, "addrChanges", start,
				warningTime, errorTime)

		case change, ok := <-linkChanges:
			start := time.Now()
			if !ok {
				log.Errorf("linkChanges closed")
				linkChanges = devicenetwork.LinkChangeInit(log)
				// XXX Need to discard all cached information?
			} else {
				ch, ifindex := devicenetwork.LinkChange(log, change)
				if ch {
					handleLinkChange(&nimCtx)
					handleInterfaceChange(&nimCtx, ifindex,
						"LinkChange", true)
					if isIfNameCrucial(&nimCtx.deviceNetworkContext, change.Attrs().Name) {
						log.Noticef("Start network connectivity verfication because ifname %s "+
							"is crucial to network configuration", change.Attrs().Name)
						devicenetwork.RestartVerify(&nimCtx.deviceNetworkContext, "HandleLinkChange")
					}
				}
			}
			ps.CheckMaxTimeTopic(agentName, "linkChanges", start,
				warningTime, errorTime)

		case change, ok := <-routeChanges:
			start := time.Now()
			if !ok {
				log.Errorf("routeChanges closed")
				routeChanges = devicenetwork.RouteChangeInit(log)
			} else {
				ch, ifindex := devicenetwork.RouteChange(nimCtx.deviceNetworkContext, change)
				if ch {
					handleInterfaceChange(&nimCtx, ifindex,
						"RouteChange", false)
				}
			}
			ps.CheckMaxTimeTopic(agentName, "routeChanges", start,
				warningTime, errorTime)

		case event, ok := <-wwanWatcher.Events:
			if !ok {
				log.Noticef("wwan watcher stopped")
				continue
			}
			devicenetwork.ProcessWwanWatchEvent(dnc, event)

		case <-geoTimer.C:
			start := time.Now()
			log.Traceln("geoTimer at", time.Now())
			change := devicenetwork.UpdateDeviceNetworkGeo(log,
				geoRedoTime, nimCtx.deviceNetworkContext.DeviceNetworkStatus)
			if change {
				publishDeviceNetworkStatus(&nimCtx)
			}
			ps.CheckMaxTimeTopic(agentName, "geoTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.Pending.PendTimer.C:
			start := time.Now()
			if !ok {
				log.Noticef("Device port test timer stopped?")
			} else {
				log.Traceln("PendTimer at", time.Now())
				devicenetwork.VerifyDevicePortConfig(dnc)
			}
			ps.CheckMaxTimeTopic(agentName, "PendTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.NetworkTestTimer.C:
			start := time.Now()
			if !ok {
				log.Noticef("Network test timer stopped?")
			} else {
				log.Tracef("Starting test of Device connectivity to cloud")
				ok := tryDeviceConnectivityToCloud(dnc)
				if ok {
					log.Tracef("Device connectivity to cloud worked. Took %v",
						time.Since(start))
				} else {
					log.Noticef("Device connectivity to cloud failed. Took %v",
						time.Since(start))
				}
			}
			ps.CheckMaxTimeTopic(agentName, "TestTimer", start,
				warningTime, errorTime)

		case _, ok := <-dnc.NetworkTestBetterTimer.C:
			start := time.Now()
			if !ok {
				log.Noticef("Network testBetterTimer stopped?")
			} else if dnc.NextDPCIndex == 0 && !dnc.DeviceNetworkStatus.HasErrors() {
				log.Tracef("Network testBetterTimer at zero ignored")
			} else {
				log.Noticef("Network testBetterTimer at index %d",
					dnc.NextDPCIndex)
				devicenetwork.RestartVerify(dnc,
					"NetworkTestBetterTimer")
				log.Noticef("Network testBetterTimer done at index %d. Took %v",
					dnc.NextDPCIndex, time.Since(start))
			}
			ps.CheckMaxTimeTopic(agentName, "TestBetterTimer", start,
				warningTime, errorTime)

		case <-publishTimer.C:
			start := time.Now()
			err = dnc.CipherMetrics.Publish(log, cipherMetricsPub, "global")
			if err != nil {
				log.Errorln(err)
			}
			ps.CheckMaxTimeTopic(agentName, "publishTimer", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

// network port is crucial if it's either part of current running DPC or
// is part of DPC at index 0 in DevicePortConfigList
func isIfNameCrucial(ctx *devicenetwork.DeviceNetworkContext, ifname string) bool {
	portConfigList := ctx.DevicePortConfigList.PortConfigList
	currentIndex := ctx.DevicePortConfigList.CurrentIndex

	if ifname == "" || currentIndex < 0 || currentIndex >= len(portConfigList) {
		return false
	}

	if !ctx.Pending.Inprogress {
		// Is part of DPC at CurrentIndex in DPCL?
		portStatus := portConfigList[currentIndex].GetPortByIfName(ifname)
		if portStatus != nil {
			log.Noticef("Crucial port %s that is part of DPC at index %d of DPCL changed",
				ifname, currentIndex)
			return true
		}

		// Is part of DPC at index 0 in DPCL?
		portStatus = portConfigList[0].GetPortByIfName(ifname)
		if portStatus != nil {
			log.Noticef("Crucial port %s that is part of DPC at index 0 of DPCL changed", ifname)
			return true
		}
	}
	return false
}

func handleLinkChange(ctx *nimContext) {
	// Create superset; update to have the latest upFlag
	// Note that upFlag gets cleared when the device is assigned away to pciback
	ifmap := devicenetwork.IfindexGetLastResortMap()
	changed := false
	for ifname, upFlag := range ifmap {
		v, ok := ctx.fallbackPortMap[ifname]
		if ok && v == upFlag {
			continue
		}
		changed = true
		if !ok {
			log.Functionf("fallbackPortMap added %s %t", ifname, upFlag)
		} else {
			log.Functionf("fallbackPortMap updated %s to %t", ifname, upFlag)
		}
		ctx.fallbackPortMap[ifname] = upFlag
	}
	if changed {
		log.Functionf("new fallbackPortmap: %+v", ctx.fallbackPortMap)
		updateFilteredFallback(ctx)
	}
}

// handleInterfaceChange deals with the fact that linkchange, addrchange, and
// routechange do not reliably indicate when a link/address comes and goes, so
// we explicitly check whether there are changes to the kernel list of IP
// address.
// Only applies to device ports.
func handleInterfaceChange(ctx *nimContext, ifindex int, logstr string, force bool) {
	// We do not see address change notifications when
	// link drops so call directly
	ifname, _, _ := devicenetwork.IfindexToName(log, ifindex)
	log.Functionf("%s(%s) ifindex %d force %t", logstr, ifname, ifindex, force)
	if ifname != "" && !types.IsPort(*ctx.deviceNetworkContext.DeviceNetworkStatus, ifname) {
		log.Tracef("%s(%s): not port", logstr, ifname)
		return
	}
	if force {
		// The caller has already purged addresses from IfindexToAddrs
		addrs, _, _, err := devicenetwork.GetIPAddrs(log, ifindex)
		if err != nil {
			addrs = nil
		}
		log.Functionf("%s(%s) force changed to %v",
			logstr, ifname, addrs)
		// Do not have a baseline to delete from
		devicenetwork.FlushRules(log, ifindex)
		for _, a := range addrs {
			devicenetwork.AddSourceRule(log, ifindex, devicenetwork.HostSubnet(a), false, devicenetwork.PbrLocalOrigPrio)
		}
		devicenetwork.HandleAddressChange(&ctx.deviceNetworkContext)
		// XXX should we trigger restarting testing?
		return
	}

	// Compare old vs. current
	oldAddrs, _ := devicenetwork.IfindexToAddrs(log, ifindex)
	addrs, _, _, err := devicenetwork.GetIPAddrs(log, ifindex)
	if err != nil {
		log.Warnf("%s(%s %d) no addrs: %s",
			logstr, ifname, ifindex, err)
		addrs = nil
	}
	if len(oldAddrs) == 0 && len(addrs) == 0 {
		// Equal but one might be nil
	} else if reflect.DeepEqual(oldAddrs, addrs) {
		// Equal
	} else {
		log.Functionf("%s(%s) changed from %v to %v",
			logstr, ifname, oldAddrs, addrs)
		for _, a := range oldAddrs {
			devicenetwork.DelSourceRule(log, ifindex, devicenetwork.HostSubnet(a), false, devicenetwork.PbrLocalOrigPrio)
		}
		for _, a := range addrs {
			devicenetwork.AddSourceRule(log, ifindex, devicenetwork.HostSubnet(a), false, devicenetwork.PbrLocalOrigPrio)
		}

		devicenetwork.HandleAddressChange(&ctx.deviceNetworkContext)
		// XXX should we trigger restarting testing?
	}
}

func updateFilteredFallback(ctx *nimContext) {
	ctx.filteredFallback = filterIfMap(ctx, ctx.fallbackPortMap)
	log.Functionf("new filteredFallback: %+v", ctx.filteredFallback)
	if ctx.networkFallbackAnyEth == types.TS_ENABLED {
		updateFallbackAnyEth(ctx)
	}
}

// Hard-coded at 1 for now; at least one interface needs to work
const successCount uint = 1

// Verify that at least one of the management interfaces work.
// Start with a different one (based on Iteration) to make sure that we try
// all over time.
func tryDeviceConnectivityToCloud(ctx *devicenetwork.DeviceNetworkContext) bool {
	// Start with a different port to cycle through them all over time
	ctx.Iteration++
	rtf, intfStatusMap, err := devicenetwork.VerifyDeviceNetworkStatus(
		log, ctx, *ctx.DeviceNetworkStatus, successCount, ctx.TestSendTimeout)
	ctx.DevicePortConfig.UpdatePortStatusFromIntfStatusMap(intfStatusMap)
	// Use TestResults to update the DevicePortConfigList and publish
	// Note that the TestResults will at least have an updated timestamp
	// for one of the ports.
	if ctx.NextDPCIndex < len(ctx.DevicePortConfigList.PortConfigList) {
		dpc := &ctx.DevicePortConfigList.PortConfigList[ctx.NextDPCIndex]
		dpc.UpdatePortStatusFromIntfStatusMap(intfStatusMap)
		if err == nil {
			dpc.State = types.DPC_SUCCESS
			dpc.TestResults.RecordSuccess()
		}
		ctx.PubDummyDevicePortConfig.Publish(dpc.PubKey(), *dpc)
		log.Functionf("publishing DevicePortConfigList update: %+v",
			*ctx.DevicePortConfigList)
		ctx.PubDevicePortConfigList.Publish("global",
			*ctx.DevicePortConfigList)
	}

	// Use TestResults to update the DeviceNetworkStatus and publish
	ctx.DeviceNetworkStatus.UpdatePortStatusFromIntfStatusMap(intfStatusMap)
	if err == nil {
		ctx.DeviceNetworkStatus.State = types.DPC_SUCCESS
	}
	log.Functionf("PublishDeviceNetworkStatus updated: %+v\n",
		*ctx.DeviceNetworkStatus)
	ctx.DeviceNetworkStatus.CurrentIndex = ctx.DevicePortConfigList.CurrentIndex
	ctx.PubDeviceNetworkStatus.Publish("global", *ctx.DeviceNetworkStatus)

	if err == nil {
		log.Functionf("tryDeviceConnectivityToCloud: Device cloud connectivity test passed.")
		ctx.CloudConnectivityWorks = true
		// Restart network test timer for next slot.
		ctx.NetworkTestTimer = time.NewTimer(time.Duration(ctx.NetworkTestInterval) * time.Second)
		return true
	}
	if !ctx.CloudConnectivityWorks && !rtf {
		// If previous cloud connectivity test also failed, it means
		// that the current DPC configuration stopped working.
		// In this case we start the process where device tries to
		// figure out a DevicePortConfig that works.
		// We avoid doing this for remoteTemporaryFailures
		if ctx.Pending.Inprogress {
			log.Functionf("tryDeviceConnectivityToCloud: Device port configuration list " +
				"verification in progress")
			// Connectivity to cloud is already being figured out.
			// We wait till the next cloud connectivity test slot.
		} else {
			log.Functionf("tryDeviceConnectivityToCloud: Triggering Device port "+
				"verification to resume cloud connectivity after %s",
				err)
			// Start DPC verification to find a working configuration
			devicenetwork.RestartVerify(ctx, "tryDeviceConnectivityToCloud")
		}
	} else {
		// Restart network test timer for next slot.
		ctx.NetworkTestTimer = time.NewTimer(time.Duration(ctx.NetworkTestInterval) * time.Second)
		if rtf {
			// The fact that cloud replied with a status code shows that the cloud is UP, but not functioning
			// fully at this time. So, we mark the cloud connectivity as UP for now.
			log.Warnf("tryDeviceConnectivityToCloud: remoteTemporaryFailure: %s", err)
			ctx.CloudConnectivityWorks = true

			return true
		} else {
			log.Functionf("tryDeviceConnectivityToCloud: Device cloud connectivity test restart timer due to %s", err)
			ctx.CloudConnectivityWorks = false
		}
	}
	return false
}

func publishDeviceNetworkStatus(ctx *nimContext) {
	log.Functionf("PublishDeviceNetworkStatus: %+v",
		ctx.deviceNetworkContext.DeviceNetworkStatus)
	devicenetwork.UpdateResolvConf(log,
		*ctx.deviceNetworkContext.DeviceNetworkStatus)
	devicenetwork.UpdatePBR(log,
		*ctx.deviceNetworkContext.DeviceNetworkStatus)
	ctx.deviceNetworkContext.DeviceNetworkStatus.Testing = false
	ctx.deviceNetworkContext.DeviceNetworkStatus.CurrentIndex = ctx.deviceNetworkContext.DevicePortConfigList.CurrentIndex
	ctx.deviceNetworkContext.PubDeviceNetworkStatus.Publish("global", *ctx.deviceNetworkContext.DeviceNetworkStatus)
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

	ctx := ctxArg.(*nimContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	var gcp *types.ConfigItemValueMap
	ctx.debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.debugOverride, logger)
	first := !ctx.GCInitialized
	if gcp != nil {
		gcpSSHAccess := gcp.GlobalValueString(types.SSHAuthorizedKeys) != ""
		gcpSSHAuthorizedKeys := gcp.GlobalValueString(types.SSHAuthorizedKeys)
		gcpAllowAppVnc := gcp.GlobalValueBool(types.AllowAppVnc)
		gcpNetworkFallbackAnyEth := gcp.GlobalValueTriState(types.NetworkFallbackAnyEth)
		if gcpSSHAccess != ctx.sshAccess || first {
			ctx.sshAccess = gcpSSHAccess
			iptables.UpdateSshAccess(log, ctx.sshAccess, first)
		}
		if gcpSSHAuthorizedKeys != ctx.sshAuthorizedKeys || first {
			ctx.sshAuthorizedKeys = gcpSSHAuthorizedKeys
			ssh.UpdateSshAuthorizedKeys(log, ctx.sshAuthorizedKeys)
		}
		if gcpAllowAppVnc != ctx.allowAppVnc {
			ctx.allowAppVnc = gcpAllowAppVnc
			iptables.UpdateVncAccess(log, ctx.allowAppVnc)
		}
		if gcpNetworkFallbackAnyEth != ctx.networkFallbackAnyEth || first {
			ctx.networkFallbackAnyEth = gcpNetworkFallbackAnyEth
			updateFallbackAnyEth(ctx)
		}
		// Check for change to NetworkTestBetterInterval
		gcpNetworkTestBetterInterval := gcp.GlobalValueInt(types.NetworkTestBetterInterval)
		if ctx.deviceNetworkContext.NetworkTestBetterInterval != gcpNetworkTestBetterInterval {
			if gcpNetworkTestBetterInterval == 0 {
				log.Warnln("NOT running TestBetterTimer")
				networkTestBetterTimer := time.NewTimer(time.Hour)
				networkTestBetterTimer.Stop()
				ctx.deviceNetworkContext.NetworkTestBetterTimer = networkTestBetterTimer
			} else {
				log.Functionf("Starting TestBetterTimer: %d",
					gcpNetworkTestBetterInterval)
				networkTestBetterInterval := time.Duration(gcpNetworkTestBetterInterval) * time.Second
				networkTestBetterTimer := time.NewTimer(networkTestBetterInterval)
				ctx.deviceNetworkContext.NetworkTestBetterTimer = networkTestBetterTimer
			}
			ctx.deviceNetworkContext.NetworkTestBetterInterval = gcpNetworkTestBetterInterval
		}
		ctx.globalConfig = gcp
		dnc := &ctx.deviceNetworkContext
		dnc.NetworkTestInterval = ctx.globalConfig.GlobalValueInt(types.NetworkTestInterval)
		dnc.DPCTestDuration = ctx.globalConfig.GlobalValueInt(types.NetworkTestDuration)
		dnc.TestSendTimeout = ctx.globalConfig.GlobalValueInt(types.NetworkTestTimeout)
	}
	ctx.GCInitialized = true
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*nimContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	ctx.debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.debugOverride, logger)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

// In case there is no GlobalConfig.json this will move us forward
func handleGlobalConfigSynchronized(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*nimContext)

	log.Functionf("handleGlobalConfigSynchronized(%v)", done)
	if done {
		first := !ctx.GCInitialized
		if first {
			iptables.UpdateSshAccess(log, ctx.sshAccess, first)
		}
		ctx.GCInitialized = true
	}
}

func handleNetworkInstanceCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleNetworkInstanceImpl(ctxArg, key, statusArg)
}

func handleNetworkInstanceModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleNetworkInstanceImpl(ctxArg, key, statusArg)
}

func handleNetworkInstanceImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleNetworkInstanceStatusImpl(%s)", key)
	ctx := ctxArg.(*nimContext)
	updateFilteredFallback(ctx)
	log.Functionf("handleNetworkInstanceImpl(%s) done", key)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleNetworkInstanceDelete(%s)", key)
	ctx := ctxArg.(*nimContext)
	updateFilteredFallback(ctx)
	log.Functionf("handleNetworkInstanceDelete(%s) done", key)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func updateFallbackAnyEth(ctx *nimContext) {
	log.Tracef("updateFallbackAnyEth: enable %v ifs %v",
		ctx.networkFallbackAnyEth, ctx.filteredFallback)
	if ctx.networkFallbackAnyEth == types.TS_ENABLED {
		ports := mapToKeys(ctx.filteredFallback)
		// sort ports to reduce churn; otherwise with two they swap
		// almost every time
		sort.Strings(ports)
		log.Tracef("updateFallbackAnyEth: ports %+v", ports)
		devicenetwork.UpdateLastResortPortConfig(&ctx.deviceNetworkContext,
			ports)
	} else if ctx.networkFallbackAnyEth == types.TS_DISABLED {
		devicenetwork.RemoveLastResortPortConfig(&ctx.deviceNetworkContext)
	}
}

// Return an array with the keys in the map
func mapToKeys(m map[string]bool) []string {

	keys := make([]string, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	return keys
}

// Determine which interfaces are not used exclusively by device assignment.
//
// Exclude those in AssignableAdapters with usedByUUID!=0
func filterIfMap(ctx *nimContext, fallbackPortMap map[string]bool) map[string]bool {
	log.Tracef("filterIfMap: len %d", len(fallbackPortMap))

	filteredFallback := make(map[string]bool, len(fallbackPortMap))
	for ifname, upFlag := range fallbackPortMap {
		if isAssigned(ctx, ifname) {
			continue
		}
		filteredFallback[ifname] = upFlag
	}
	return filteredFallback
}

// Really a constant
var nilUUID uuid.UUID

// Check in AssignableAdapters with usedByUUID!=0
func isAssigned(ctx *nimContext, ifname string) bool {

	log.Tracef("isAssigned(%s) have %d bundles",
		ifname, len(ctx.deviceNetworkContext.AssignableAdapters.IoBundleList))
	ib := ctx.deviceNetworkContext.AssignableAdapters.LookupIoBundleIfName(ifname)
	if ib == nil {
		return false
	}
	log.Tracef("isAssigned(%s): pciback %t used %s",
		ifname, ib.IsPCIBack, ib.UsedByUUID.String())

	if ib.UsedByUUID != nilUUID {
		return true
	}
	return false
}

const (
	configDevicePortConfigDir = types.IdentityDirname + "/DevicePortConfig"
	runDevicePortConfigDir    = "/run/global/DevicePortConfig"
	maxReadSize               = 16384 // Punt on too large files
)

// ingestPortConfig reads all json files in configDevicePortConfigDir, ensures
// they have a TimePriority, and adds a OriginFile to them and then writes to
// runDevicePortConfigDir.
// Later the OriginFile field will result in removing the original file from
// /config/DevicePortConfig/ to avoid re-application.
func ingestDevicePortConfig(ctx *nimContext) {
	locations, err := ioutil.ReadDir(configDevicePortConfigDir)
	if err != nil {
		// Directory might not exist
		return
	}
	for _, location := range locations {
		if !location.IsDir() {
			ingestDevicePortConfigFile(ctx, configDevicePortConfigDir,
				runDevicePortConfigDir, location.Name())
		}
	}
}

func ingestDevicePortConfigFile(ctx *nimContext, oldDirname string, newDirname string, name string) {
	filename := path.Join(oldDirname, name)
	log.Noticef("ingestDevicePortConfigFile(%s)", filename)
	b, err := fileutils.ReadWithMaxSize(log, filename, maxReadSize)
	if err != nil {
		log.Errorf("Failed to read file %s: %v", filename, err)
		return
	}
	if len(b) == 0 {
		log.Errorf("Ignore empty file %s", filename)
		return
	}

	var dpc types.DevicePortConfig
	err = json.Unmarshal(b, &dpc)
	if err != nil {
		log.Errorf("Could not parse json data in file %s: %s",
			filename, err)
		return
	}
	dpc.DoSanitize(log, true, false, "", true)
	dpc.OriginFile = filename

	// Save New config to file.
	var data []byte
	data, err = json.Marshal(dpc)
	if err != nil {
		log.Fatalf("Failed to json marshall new DevicePortConfig err %s",
			err)
	}
	filename = path.Join(newDirname, name)
	err = fileutils.WriteRename(filename, data)
	if err != nil {
		log.Errorf("Failed to write new DevicePortConfig to %s: %s",
			filename, err)
	}
}
