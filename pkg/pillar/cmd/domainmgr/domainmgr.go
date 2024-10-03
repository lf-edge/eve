// Copyright (c) 2017-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package domainmgr

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/cgroups"
	"github.com/google/go-cmp/cmp"
	envp "github.com/hashicorp/go-envparse"
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/canbus"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/sema"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/cloudconfig"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	zfsutil "github.com/lf-edge/eve/pkg/pillar/utils/zfs"
	"github.com/opencontainers/runtime-spec/specs-go"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v2"
)

const (
	agentName  = "domainmgr"
	runDirname = "/run/" + agentName
	xenDirname = runDirname + "/xen"       // We store xen cfg files here
	ciDirname  = runDirname + "/cloudinit" // For cloud-init images

	// Time limits for event loop handlers
	errorTime     = 3 * time.Minute
	warningTime   = 40 * time.Second
	casClientType = "containerd"
)

// Really a constant
var nilUUID = uuid.UUID{}

func isPort(ctx *domainContext, ifname string) bool {
	ctx.dnsLock.Lock()
	defer ctx.dnsLock.Unlock()
	return types.IsPort(ctx.deviceNetworkStatus, ifname)
}

// Information for handleCreate/Modify/Delete
type domainContext struct {
	agentbase.AgentBase
	ps *pubsub.PubSub
	// The isPort function is called by different goroutines
	// hence we serialize the calls on a mutex.
	decryptCipherContext   cipher.DecryptCipherContext
	deviceNetworkStatus    types.DeviceNetworkStatus
	dnsLock                sync.Mutex
	assignableAdapters     *types.AssignableAdapters
	DNSinitialized         bool // Received DeviceNetworkStatus
	subDeviceNetworkStatus pubsub.Subscription
	subPhysicalIOAdapter   pubsub.Subscription
	subDomainConfig        pubsub.Subscription
	pubDomainStatus        pubsub.Publication
	subGlobalConfig        pubsub.Subscription
	subZFSPoolStatus       pubsub.Subscription
	pubAssignableAdapters  pubsub.Publication
	pubDomainMetric        pubsub.Publication
	pubHostMemory          pubsub.Publication
	pubProcessMetric       pubsub.Publication
	pubCipherBlockStatus   pubsub.Publication
	pubCapabilities        pubsub.Publication
	cipherMetrics          *cipher.AgentMetrics
	createSema             *sema.Semaphore
	GCComplete             bool

	usbAccess               bool
	setInitialUsbAccess     bool
	vgaAccess               bool
	setInitialVgaAccess     bool
	consoleAccess           bool
	setInitialConsoleAccess bool

	GCInitialized       bool
	domainBootRetryTime uint32 // In seconds
	metricInterval      uint32 // In seconds
	pids                map[int32]bool
	// Common CAS client which can be used by multiple routines.
	// There is no shared data so its safe to be used by multiple goroutines
	casClient cas.CAS

	// From global config setting
	processCloudInitMultiPart bool
	publishTicker             flextimer.FlexTickerHandle
	// cli options
	hypervisorPtr *string
	// CPUs management
	cpuAllocator        *cpuallocator.CPUAllocator
	cpuPinningSupported bool
	// Is it kubevirt eve
	hvTypeKube bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctx *domainContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	allHypervisors, enabledHypervisors := hypervisor.GetAvailableHypervisors()
	ctx.hypervisorPtr = flagSet.String("h", enabledHypervisors[0], fmt.Sprintf("Current hypervisor %+q", allHypervisors))
}

func (ctx *domainContext) publishAssignableAdapters() {
	log.Functionf("Publishing %v", *ctx.assignableAdapters)
	ctx.pubAssignableAdapters.Publish("global", *ctx.assignableAdapters)
}

var hyper hypervisor.Hypervisor // Current hypervisor
var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int { //nolint:gocyclo
	logger = loggerArg
	log = logArg

	// These settings can be overridden by GlobalConfig
	// Note that if this device has never connected to the controller
	// usbAccess is set to true. Once it connects it will get the default
	// from the controller which is likely to be false. That is persisted
	// hence will be overridden in handleGlobalConfig below.
	// This helps onboarding new hardware by making keyboard etc available
	domainCtx := domainContext{
		ps:                  ps,
		usbAccess:           true,
		vgaAccess:           true,
		domainBootRetryTime: 600,
		pids:                make(map[int32]bool),
		cipherMetrics:       cipher.NewAgentMetrics(agentName),
		metricInterval:      10,
		hvTypeKube:          base.IsHVTypeKube(),
	}
	agentbase.Init(&domainCtx, logger, log, agentName,
		agentbase.WithBaseDir(baseDir),
		agentbase.WithPidFile(),
		agentbase.WithArguments(arguments))

	var err error
	handlersInit()

	hyper, err = hypervisor.GetHypervisor(*domainCtx.hypervisorPtr)
	if err != nil {
		log.Fatal(err)
	}

	log.Functionf("Starting %s with %s hypervisor backend", agentName, hyper.Name())

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	if _, err := os.Stat(runDirname); err != nil {
		log.Tracef("Create %s", runDirname)
		if err := os.MkdirAll(runDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if err := os.RemoveAll(xenDirname); err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(ciDirname); err == nil {
		if err := os.RemoveAll(ciDirname); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(xenDirname); err != nil {
		if err := os.MkdirAll(xenDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(ciDirname); err != nil {
		if err := os.MkdirAll(ciDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// Publish metrics for zedagent every 10 seconds and
	// adjust publishTicker interval if global MetricInterval changed later
	interval := time.Duration(domainCtx.metricInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	domainCtx.publishTicker = flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	aa := types.AssignableAdapters{}
	domainCtx.assignableAdapters = &aa

	// Allow only one concurrent domain create
	domainCtx.createSema = sema.New(log, 1)
	domainCtx.createSema.P(1)

	pubDomainStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DomainStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubDomainStatus = pubDomainStatus
	pubDomainStatus.ClearRestarted()

	pubAssignableAdapters, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.AssignableAdapters{},
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubAssignableAdapters = pubAssignableAdapters

	pubDomainMetric, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DomainMetric{},
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubDomainMetric = pubDomainMetric

	pubProcessMetric, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.ProcessMetric{},
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubProcessMetric = pubProcessMetric

	pubHostMemory, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.HostMemory{},
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubHostMemory = pubHostMemory
	pubHostMemory.ClearRestarted()

	pubCipherBlockStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.CipherBlockStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubCipherBlockStatus = pubCipherBlockStatus
	pubCipherBlockStatus.ClearRestarted()

	cipherMetricsPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.CipherMetrics{},
	})
	if err != nil {
		log.Fatal(err)
	}

	capabilitiesInfoPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.Capabilities{},
	})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubCapabilities = capabilitiesInfoPub

	// Look for controller certs which will be used for decryption
	subControllerCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.ControllerCert{},
		Activate:    false,
		Ctx:         &domainCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.decryptCipherContext.Log = log
	domainCtx.decryptCipherContext.AgentName = agentName
	domainCtx.decryptCipherContext.AgentMetrics = domainCtx.cipherMetrics
	domainCtx.decryptCipherContext.PubSubControllerCert = subControllerCert
	subControllerCert.Activate()

	// Look for edge node certs which will be used for decryption
	subEdgeNodeCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeCert{},
		Activate:    false,
		Persistent:  true,
		Ctx:         &domainCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.decryptCipherContext.PubSubEdgeNodeCert = subEdgeNodeCert
	subEdgeNodeCert.Activate()

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "zedagent",
			MyAgentName:   agentName,
			TopicImpl:     types.ConfigItemValueMap{},
			Persistent:    true,
			Activate:      false,
			Ctx:           &domainCtx,
			CreateHandler: handleGlobalConfigCreate,
			ModifyHandler: handleGlobalConfigModify,
			DeleteHandler: handleGlobalConfigDelete,
			SyncHandler:   handleGlobalConfigSync,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Watch DNS to learn which ports are used for management.
	subDeviceNetworkStatus, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "nim",
			MyAgentName:   agentName,
			TopicImpl:     types.DeviceNetworkStatus{},
			Activate:      false,
			Ctx:           &domainCtx,
			CreateHandler: handleDNSCreate,
			ModifyHandler: handleDNSModify,
			DeleteHandler: handleDNSDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Subscribe to PhysicalIOAdapterList from zedagent.
	// Do not activate until we have DNS.
	subPhysicalIOAdapter, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "zedagent",
			MyAgentName:   agentName,
			TopicImpl:     types.PhysicalIOAdapterList{},
			Activate:      false,
			Ctx:           &domainCtx,
			CreateHandler: handlePhysicalIOAdapterListCreate,
			ModifyHandler: handlePhysicalIOAdapterListModify,
			DeleteHandler: handlePhysicalIOAdapterListDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.subPhysicalIOAdapter = subPhysicalIOAdapter
	subZFSPoolStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zfsmanager",
		MyAgentName: agentName,
		TopicImpl:   types.ZFSPoolStatus{},
		Activate:    true,
		Ctx:         &domainCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.subZFSPoolStatus = subZFSPoolStatus
	subZFSPoolStatus.Activate()

	// Parse any existing ConfigIntemValueMap but continue if there
	// is none
	for !domainCtx.GCComplete {
		log.Noticef("waiting for GCComplete")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-domainCtx.publishTicker.C:
			publishProcessesHandler(&domainCtx)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Noticef("processed GCComplete")

	if !domainCtx.setInitialUsbAccess {
		log.Functionf("GCComplete but not setInitialUsbAccess => first boot")
		// Enable USB keyboard and storage
		domainCtx.usbAccess = true
		updateUsbAccess(&domainCtx)
		domainCtx.setInitialUsbAccess = true
	}

	if !domainCtx.setInitialVgaAccess {
		log.Functionf("GCComplete but not setInitialVgaAccess => first boot")
		// Enable VGA
		domainCtx.vgaAccess = true
		updateVgaAccess(&domainCtx)
		domainCtx.setInitialVgaAccess = true
	}

	if !domainCtx.setInitialConsoleAccess {
		log.Functionf("GCComplete but not setInitialConsoleAccess => first boot")
		// Enable Console
		domainCtx.consoleAccess = true
		updateConsoleAccess(&domainCtx)
		domainCtx.setInitialConsoleAccess = true
	}

	// Pick up debug aka log level before we start real work
	for !domainCtx.GCInitialized {
		log.Noticef("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-domainCtx.publishTicker.C:
			publishProcessesHandler(&domainCtx)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Noticef("processed GlobalConfig")

	capabilitiesSent := false
	capabilitiesTicker := time.NewTicker(5 * time.Second)
	if err := getAndPublishCapabilities(&domainCtx, hyper); err != nil {
		log.Warnf("getAndPublishCapabilities: %v", err)
	} else {
		capabilitiesSent = true
		capabilitiesTicker.Stop()
	}

	log.Functionf("Creating %s at %s", "metricsTimerTask", agentlog.GetMyStack())
	go metricsTimerTask(&domainCtx, hyper)

	// Before starting to process DomainConfig, domainmgr should (in this order):
	//   1. wait for NIM to publish DNS to learn which ports are used for management
	//   2. wait for PhysicalIOAdapters (from zedagent) to be processed
	//   3. wait for capabilities information from hypervisor
	// Note: 3 may come in any order
	for !domainCtx.assignableAdapters.Initialized ||
		len(domainCtx.deviceNetworkStatus.Ports) == 0 ||
		!capabilitiesSent {
		log.Noticef("Waiting for AssignableAdapters, DPC with management ports " +
			"and hypervisor capabilities")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			wasDNSInitialized := domainCtx.DNSinitialized
			subDeviceNetworkStatus.ProcessChange(change)
			if domainCtx.DNSinitialized && !wasDNSInitialized {
				subPhysicalIOAdapter.Activate()
			}

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)

		case change := <-subPhysicalIOAdapter.MsgChan():
			subPhysicalIOAdapter.ProcessChange(change)

		case change := <-subZFSPoolStatus.MsgChan():
			subZFSPoolStatus.ProcessChange(change)

		case <-domainCtx.publishTicker.C:
			publishProcessesHandler(&domainCtx)

		case <-capabilitiesTicker.C:
			if err := getAndPublishCapabilities(&domainCtx, hyper); err != nil {
				log.Warnf("getAndPublishCapabilities: %v", err)
			} else {
				capabilitiesSent = true
				capabilitiesTicker.Stop()
			}

		// Run stillRunning since we waiting for zedagent to deliver
		// PhysicalIO which depends on cloud connectivity
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Noticef("Have %d assignable adapters", len(aa.IoBundleList))

	// at that stage we should have Capabilities published
	caps, err := lookupCapabilities(&domainCtx)
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.cpuPinningSupported = caps.CPUPinning

	// Need to wait for things to get started
	var resources types.HostMemory
	for i := 0; true; i++ {
		delay := 10
		resources, err = hyper.GetHostCPUMem()
		if err == nil {
			break
		}
		if i == 10 {
			log.Fatalf("Failed %d times due to %s", i, err)
		}
		log.Warnf("Retrying in %d seconds due to %s", delay, err)
		time.Sleep(time.Duration(delay) * time.Second)
		ps.StillRunning(agentName, warningTime, errorTime)
	}

	cpusReserved, err := getReservedCPUsNum()
	if err != nil {
		log.Warnf("Failed to get reserved CPU number, use 1 by default: %s", err)
	}

	if domainCtx.cpuAllocator, err = cpuallocator.Init(int(resources.Ncpus), cpusReserved); err != nil {
		log.Fatal(err)
	}

	// Wait until we have been onboarded aka know our own UUID however we do not use the UUID
	if err := wait.WaitForOnboarded(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Noticef("device is onboarded")

	if err := wait.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}

	log.Functionf("processed vault status")

	if err := containerd.StartUserContainerdInstance(); err != nil {
		log.Fatalf("StartUserContainerdInstance: failed %v", err)
	}

	if err := containerd.WaitForUserContainerd(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("user containerd ready")

	// wait for kubernetes to be ready in kubevirt mode, if gets error, move on
	if domainCtx.hvTypeKube {
		log.Noticef("Domainmgr run: wait for kubernetes")
		err = kubeapi.WaitForKubernetes(agentName, ps, stillRunning)
		if err != nil {
			log.Errorf("Domainmgr: wait for kubernetes error %v", err)
		} else {
			// If device rebooted abruptly, kubernetes did not get time to stop the VMs.
			// They will be in failed state, so clean them up if they exists.
			count, err := kubeapi.CleanupStaleVMI()
			log.Noticef("domainmgr cleanup vmi count %d, %v", count, err)
		}
	}

	if domainCtx.casClient, err = cas.NewCAS(casClientType); err != nil {
		err = fmt.Errorf("Run: exception while initializing CAS client: %s", err.Error())
		log.Fatal(err)
	}

	//casClient which is commonly used across volumemgr will be closed when volumemgr exits.
	defer domainCtx.casClient.CloseClient()

	// Subscribe to DomainConfig from zedmanager
	subDomainConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:      "zedmanager",
			MyAgentName:    agentName,
			TopicImpl:      types.DomainConfig{},
			Activate:       false,
			Ctx:            &domainCtx,
			CreateHandler:  handleDomainCreate,
			ModifyHandler:  handleDomainModify,
			DeleteHandler:  handleDomainDelete,
			RestartHandler: handleRestart,
			WarningTime:    warningTime,
			ErrorTime:      errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.subDomainConfig = subDomainConfig
	subDomainConfig.Activate()

	for {
		select {
		case change := <-subControllerCert.MsgChan():
			subControllerCert.ProcessChange(change)

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDomainConfig.MsgChan():
			subDomainConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subZFSPoolStatus.MsgChan():
			subZFSPoolStatus.ProcessChange(change)

		case change := <-subPhysicalIOAdapter.MsgChan():
			subPhysicalIOAdapter.ProcessChange(change)

		case <-domainCtx.publishTicker.C:
			start := time.Now()
			err = domainCtx.cipherMetrics.Publish(log, cipherMetricsPub, "global")
			if err != nil {
				log.Errorln(err)
			}
			ps.CheckMaxTimeTopic(agentName, "publishTimer", start,
				warningTime, errorTime)
			publishProcessesHandler(&domainCtx)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func getReservedCPUsNum() (int, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return 1, err
	}
	bootArgs := strings.Fields(string(data))
	for _, arg := range bootArgs {
		if strings.HasPrefix(arg, "eve_max_vcpus") {
			argSplitted := strings.Split(arg, "=")
			if len(argSplitted) < 2 {
				return 1, errors.New("kernel arg 'eve_max_vcpus' is malformed")
			}
			cpusReserved, err := strconv.Atoi(argSplitted[1])
			if err != nil {
				return 1, errors.New("value of kernel arg 'eve_max_vcpus' is malformed")
			}
			return cpusReserved, nil
		}
	}
	return 1, errors.New("kernel arg 'eve_max_vcpus' not found")
}

func publishProcessesHandler(domainCtx *domainContext) {
	start := time.Now()
	metrics, pids := gatherProcessMetricList(domainCtx)
	for _, m := range metrics {
		publishProcessMetric(domainCtx, &m)
	}
	unpublishRemovedPids(domainCtx, domainCtx.pids, pids)
	domainCtx.pids = pids
	domainCtx.ps.CheckMaxTimeTopic(agentName, "publishProcesses", start,
		warningTime, errorTime)
}

func handleRestart(ctxArg interface{}, restartCounter int) {
	log.Functionf("handleRestart(%d)", restartCounter)
	ctx := ctxArg.(*domainContext)
	if restartCounter != 0 {
		log.Functionf("handleRestart: avoid cleanup")
		ctx.pubDomainStatus.SignalRestarted()
		return
	}
}

func publishDomainStatus(ctx *domainContext, status *types.DomainStatus) {

	key := status.Key()
	log.Tracef("publishDomainStatus(%s)", key)
	pub := ctx.pubDomainStatus
	pub.Publish(key, *status)
}

func unpublishDomainStatus(ctx *domainContext, status *types.DomainStatus) {

	key := status.Key()
	log.Tracef("unpublishDomainStatus(%s)", key)
	pub := ctx.pubDomainStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishDomainStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func publishCipherBlockStatus(ctx *domainContext,
	status types.CipherBlockStatus) {
	key := status.Key()
	if ctx == nil || len(status.Key()) == 0 {
		return
	}
	log.Tracef("publishCipherBlockStatus(%s)", key)
	pub := ctx.pubCipherBlockStatus
	pub.Publish(key, status)
}

func unpublishCipherBlockStatus(ctx *domainContext, key string) {
	if ctx == nil || len(key) == 0 {
		return
	}
	log.Tracef("unpublishCipherBlockStatus(%s)", key)
	pub := ctx.pubCipherBlockStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishCipherBlockStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func xenCfgFilename(appNum int) string {
	return xenDirname + "/xen" + strconv.Itoa(appNum) + ".cfg"
}

// Notify simple struct to pass notification messages
type Notify struct{}

type channels struct {
	configChannel chan<- Notify
	cpuChannel    chan<- Notify
}

// We have one goroutine per provisioned domU object.
// Channel is used to send notifications about config (add and updates)
// Channel is closed when the object is deleted
// The go-routine owns writing status for the object
// The key in the map is the objects Key() - UUID in this case
type handlers map[string]channels

var handlerMap handlers

func handlersInit() {
	handlerMap = make(handlers)
}

func triggerCPUNotification() {
	for _, handler := range handlerMap {
		select {
		case handler.cpuChannel <- Notify{}:
		default:
			log.Warnf("Already sent a CPU Notify...")
		}
	}
}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func handleDomainModify(ctxArg interface{}, key string, configArg interface{},
	oldConfigArg interface{}) {

	log.Functionf("handleDomainModify(%s)", key)
	config := configArg.(types.DomainConfig)
	h, ok := handlerMap[config.Key()]
	if !ok {
		log.Fatalf("handleDomainModify called on config that does not exist")
	}
	select {
	case h.configChannel <- Notify{}:
		log.Functionf("handleDomainModify(%s) sent notify", key)
	default:
		// handler is slow
		log.Warnf("handleDomainModify(%s) NOT sent notify. Slow handler?", key)
	}
}

func handleDomainCreate(ctxArg interface{}, key string, configArg interface{}) {

	log.Functionf("handleDomainCreate(%s)", key)
	ctx := ctxArg.(*domainContext)
	config := configArg.(types.DomainConfig)
	h, ok := handlerMap[config.Key()]
	if ok {
		log.Fatalf("handleDomainCreate called on config that already exists")
	}
	hConfig := make(chan Notify, 1)
	hCPU := make(chan Notify, 1)
	h1 := channels{configChannel: hConfig, cpuChannel: hCPU}
	handlerMap[config.Key()] = h1
	log.Functionf("Creating %s at %s", "runHandler", agentlog.GetMyStack())
	go runHandler(ctx, key, hConfig, hCPU)
	h = h1
	select {
	case h.configChannel <- Notify{}:
		log.Functionf("handleDomainCreate(%s) sent notify", key)
	default:
		// Shouldn't happen since we just created channel
		log.Fatalf("handleDomainCreate(%s) NOT sent notify", key)
	}
}

func handleDomainDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleDomainDelete(%s)", key)
	// delete the specific cipher block status
	ctx := ctxArg.(*domainContext)
	config := configArg.(types.DomainConfig)
	// only when contains cloud-init user data (plain or cipher)
	if config.IsCipher || config.CloudInitUserData != nil {
		unpublishCipherBlockStatus(ctx, config.Key())
	}
	// Do we have a channel/goroutine?
	h, ok := handlerMap[key]
	if ok {
		log.Functionf("Closing channels")
		close(h.cpuChannel)
		close(h.configChannel)
		delete(handlerMap, key)
	} else {
		log.Tracef("handleDomainDelete: unknown %s", key)
		return
	}
	log.Functionf("handleDomainDelete(%s) done", key)
}

// Server for each domU
// Runs timer every 30 seconds to update status
func runHandler(ctx *domainContext, key string, configChannel <-chan Notify, cpuChannel <-chan Notify) {

	log.Functionf("runHandler starting")

	interval := 30 * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	closed := false
	for !closed {
		select {
		case _, ok := <-configChannel:
			if ok {
				sub := ctx.subDomainConfig
				c, err := sub.Get(key)
				if err != nil {
					log.Errorf("runHandler no config for %s", key)
					continue
				}
				config := c.(types.DomainConfig)
				status := lookupDomainStatus(ctx, key)
				if status == nil {
					handleCreate(ctx, key, &config)
				} else {
					handleModify(ctx, key, &config, status)
				}
			} else {
				// Closed
				status := lookupDomainStatus(ctx, key)
				if status != nil {
					handleDelete(ctx, key, status)
				}
				closed = true
			}
		case _, ok := <-cpuChannel:
			if ok {
				if !ctx.cpuPinningSupported {
					continue
				}
				sub := ctx.subDomainConfig
				c, err := sub.Get(key)
				if err != nil {
					log.Errorf("runHandler no config for %s", key)
					continue
				}
				config := c.(types.DomainConfig)
				status := lookupDomainStatus(ctx, key)
				if status == nil {
					log.Errorf("No Status for %s", config.DisplayName)
					continue
				}
				if !config.VmConfig.CPUsPinned {
					if err = updateNonPinnedCPUs(ctx, &config, status); err != nil {
						log.Warnf("failed to redistribute CPUs in %s", config.DisplayName)
					}
				}
			}
		case <-ticker.C:
			log.Tracef("runHandler(%s) timer", key)
			status := lookupDomainStatus(ctx, key)
			if status != nil {
				verifyStatus(ctx, status)
				maybeRetry(ctx, status)
			}
		}
	}
	log.Functionf("runHandler(%s) DONE", key)
}

// Check if it is still running
func verifyStatus(ctx *domainContext, status *types.DomainStatus) {
	// Check config.Active to avoid spurious errors when shutting down
	configActivate := false
	config := lookupDomainConfig(ctx, status.Key())
	if config != nil && config.Activate {
		configActivate = true
	}

	domainID, domainStatus, err := hyper.Task(status).Info(status.DomainName)
	if err != nil || domainStatus == types.HALTED {
		if status.Activated && configActivate {
			if err == nil {
				err = fmt.Errorf("unexpected state %s", domainStatus.String())
			}
			errStr := fmt.Sprintf("verifyStatus(%s) failed %s",
				status.Key(), err)
			log.Warnln(errStr)
			status.Activated = false
			status.State = types.HALTED

			// check if task is in the BROKEN state and kill it (later on we may do some
			// level of recovery or at least gather some intel on why and how it crashed)
			// NOTE: we don't do anything for repairing tasks in the UNKNOWN state, for those
			// the only remedy is an explicit user action (delete, restart, etc.)
			if domainStatus == types.BROKEN {
				err := fmt.Errorf("one of the %s tasks has crashed (%v)", status.Key(), err)
				log.Errorf(err.Error())
				status.SetErrorNow("one of the application's tasks has crashed - please restart application instance")
				status.State = types.BROKEN
			} else {
				//schedule for retry boot
				status.BootFailed = true
				errDescription := types.ErrorDescription{
					Error:               err.Error(),
					ErrorSeverity:       types.ErrorSeverityWarning,
					ErrorRetryCondition: fmt.Sprintf("will retry in %s", time.Duration(ctx.domainBootRetryTime)*time.Second),
				}
				status.SetErrorDescription(errDescription)
			}

			//cleanup app instance tasks
			if err := hyper.Task(status).Delete(status.DomainName); err != nil {
				log.Errorf("failed to delete domain: %s (%v)", status.DomainName, err)
			}
			if err := hyper.Task(status).Cleanup(status.DomainName); err != nil {
				log.Errorf("failed to cleanup domain: %s (%v)", status.DomainName, err)
			}
		}
		status.DomainId = 0
		publishDomainStatus(ctx, status)
	} else {
		if !status.Activated && domainStatus == types.RUNNING {
			log.Warnf("verifyDomain(%s) domain came back alive; id  %d",
				status.Key(), domainID)
			if status.HasError() {
				log.Noticef("verifyDomain(%s) clearing existing error: %s",
					status.Key(), status.Error)
				status.ClearError()
			}
			status.DomainId = domainID
			status.BootTime = time.Now()
			log.Noticef("Update domainId %d bootTime %s for %s",
				status.DomainId, status.BootTime.Format(time.RFC3339Nano),
				status.Key())
			status.Activated = true
			status.State = types.RUNNING
			publishDomainStatus(ctx, status)
		} else if domainID != status.DomainId {
			// XXX shutdown + create?
			log.Warnf("verifyDomain(%s) domainID changed from %d to %d",
				status.Key(), status.DomainId, domainID)
			status.DomainId = domainID
			status.BootTime = time.Now()
			log.Noticef("Update domainId %d bootTime %s for %s",
				status.DomainId, status.BootTime.Format(time.RFC3339Nano),
				status.Key())
			publishDomainStatus(ctx, status)
		}
	}
}

func maybeRetry(ctx *domainContext, status *types.DomainStatus) {
	maybeRetryConfig(ctx, status)
	maybeRetryBoot(ctx, status)
	maybeRetryAdapters(ctx, status)
}

// Retry in case of previous configuration errors
func maybeRetryConfig(ctx *domainContext, status *types.DomainStatus) {
	if !status.ConfigFailed {
		return
	}
	config := lookupDomainConfig(ctx, status.Key())
	if config == nil {
		// Odd to have status but no config
		log.Errorf("maybeRetryConfig(%s) no DomainConfig",
			status.Key())
		return
	}
	status.ConfigFailed = false
	status.PendingModify = true
	publishDomainStatus(ctx, status)
	// Update disks based on any change to volumes
	if err := configToStatus(ctx, *config, status); err != nil {
		log.Errorf("Failed to update DomainStatus from %v: %s",
			config, err)
		// will retry again later
		status.ConfigFailed = true
		status.PendingModify = false
		status.SetErrorDescription(types.ErrorDescription{Error: err.Error()})
		publishDomainStatus(ctx, status)
		return
	}
	if status.HasError() {
		log.Noticef("maybeRetryConfig(%s) clearing existing error: %s",
			status.Key(), status.Error)
		status.ClearError()
	}
	if config.Activate && !status.Activated && status.State != types.BROKEN {
		updateStatusFromConfig(status, *config)
		doActivate(ctx, *config, status)
	} else if !config.Activate {
		updateStatusFromConfig(status, *config)
	}
	status.PendingModify = false
	publishDomainStatus(ctx, status)
}

// Retry a boot after a failure.
func maybeRetryBoot(ctx *domainContext, status *types.DomainStatus) {

	if !status.BootFailed {
		return
	}
	if status.Activated && status.BootFailed {
		log.Functionf("maybeRetryBoot(%s) clearing bootFailed since Activated",
			status.Key())
		status.BootFailed = false
		publishDomainStatus(ctx, status)
		return
	}
	config := lookupDomainConfig(ctx, status.Key())
	if config == nil {
		// Odd to have status but no config
		log.Errorf("maybeRetryBoot(%s) no DomainConfig",
			status.Key())
		return
	}
	if !config.Activate {
		log.Errorf("maybeRetryBoot(%s) Config not Activate - nothing to do",
			status.Key())
		status.BootFailed = false
		publishDomainStatus(ctx, status)
		return
	}

	t := time.Now()
	elapsed := t.Sub(status.ErrorTime)
	timeLimit := time.Duration(ctx.domainBootRetryTime) * time.Second
	if elapsed < timeLimit {
		log.Functionf("maybeRetryBoot(%s) %d remaining",
			status.Key(),
			(timeLimit-elapsed)/time.Second)
		return
	}
	log.Noticef("maybeRetryBoot(%s) after %s at %v",
		status.Key(), status.Error, status.ErrorTime)

	if status.HasError() {
		log.Noticef("maybeRetryBoot(%s) clearing existing error: %s",
			status.Key(), status.Error)
		status.ClearError()
	}

	filename := xenCfgFilename(config.AppNum)
	file, err := os.Create(filename)
	if err != nil {
		//it is retry, so omit error
		log.Error("os.Create for ", filename, err)
	}
	defer file.Close()

	if err := hyper.Task(status).VirtualTPMSetup(status.DomainName, agentName, ctx.ps, warningTime, errorTime); err != nil {
		log.Errorf("Failed to setup virtual TPM for %s: %s", status.DomainName, err)
		status.VirtualTPM = false
	} else {
		status.VirtualTPM = true
	}

	if err := hyper.Task(status).Setup(*status, *config, ctx.assignableAdapters, nil, file); err != nil {
		//it is retry, so omit error
		log.Errorf("Failed to create DomainStatus from %+v: %s",
			config, err)

		if err := hyper.Task(status).VirtualTPMTerminate(status.DomainName); err != nil {
			log.Errorf("Failed to terminate virtual TPM for %s: %s", status.DomainName, err)
		}
	}

	status.TriedCount++

	ctx.createSema.V(1)
	domainID, err := DomainCreate(ctx, *status)
	ctx.createSema.P(1)
	if err != nil {
		log.Errorf("maybeRetryBoot DomainCreate for %s: %s",
			status.DomainName, err)
		status.BootFailed = true
		status.SetErrorNow(err.Error())
		publishDomainStatus(ctx, status)
		return
	}
	status.BootFailed = false
	doActivateTail(ctx, status, domainID)
	publishDomainStatus(ctx, status)
	log.Functionf("maybeRetryBoot(%s) DONE for %s",
		status.Key(), status.DisplayName)
}

// Retry assigning adapters after a failure.
func maybeRetryAdapters(ctx *domainContext, status *types.DomainStatus) {

	if !status.AdaptersFailed {
		return
	}
	if status.Activated && status.AdaptersFailed {
		log.Functionf("maybeRetryAdapters(%s) clearing adaptersFailed since Activated",
			status.Key())
		status.AdaptersFailed = false
		publishDomainStatus(ctx, status)
		return
	}
	config := lookupDomainConfig(ctx, status.Key())
	if config == nil {
		// Odd to have status but no config
		log.Errorf("maybeRetryAdapters(%s) no DomainConfig",
			status.Key())
		return
	}
	if !config.Activate {
		log.Errorf("maybeRetryAdapters(%s) Config not Activate - nothing to do",
			status.Key())
		status.AdaptersFailed = false
		publishDomainStatus(ctx, status)
		return
	}
	log.Noticef("maybeRetryAdapters(%s) after %s at %v",
		status.Key(), status.Error, status.ErrorTime)

	// Write any Location so that it can later be deleted based on status
	publishDomainStatus(ctx, status)
	doActivate(ctx, *config, status)
	// work done
	publishDomainStatus(ctx, status)
	log.Functionf("maybeRetryAdapters(%s) DONE for %s",
		status.Key(), status.DisplayName)
}

// Callers must be careful to publish any changes to DomainStatus
func lookupDomainStatus(ctx *domainContext, key string) *types.DomainStatus {

	pub := ctx.pubDomainStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Functionf("lookupDomainStatus(%s) not found", key)
		return nil
	}
	status := st.(types.DomainStatus)
	return &status
}

// lookupDomainStatusByUUID ignores the version part of the key
func lookupDomainStatusByUUID(ctx *domainContext, uuid uuid.UUID) *types.DomainStatus {

	pub := ctx.pubDomainStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.DomainStatus)
		if status.UUIDandVersion.UUID == uuid {
			return &status
		}
	}
	return nil
}

func lookupDomainConfig(ctx *domainContext, key string) *types.DomainConfig {

	sub := ctx.subDomainConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Functionf("lookupDomainConfig(%s) not found", key)
		return nil
	}
	config := c.(types.DomainConfig)
	return &config
}

func setCgroupCpuset(config *types.DomainConfig, status *types.DomainStatus) error {
	cgroupName := filepath.Join(containerd.GetServicesNamespace(), config.GetTaskName())
	cgroupPath := cgroups.StaticPath(cgroupName)
	controller, err := cgroups.Load(cgroups.V1, cgroupPath)
	if err != nil {
		// It's still not an error, since the path may still not exist
		log.Warnf("Failed to find cgroups directory for %s", config.DisplayName)
		return nil
	}
	err = controller.Update(&specs.LinuxResources{CPU: &specs.LinuxCPU{Cpus: status.VmConfig.CPUs}})
	if err != nil {
		log.Warnf("Failed to update CPU set for %s", config.DisplayName)
		return err
	}
	log.Functionf("Adjust the cgroups cpuset of %s to %s", config.DisplayName, status.VmConfig.CPUs)
	return nil
}

// constructNonPinnedCpumaskString returns a cpumask that contains at least CPUs reserved for the system
// services. Hence, it can never be empty.
func constructNonPinnedCpumaskString(ctx *domainContext) string {
	result := ""
	for _, cpu := range ctx.cpuAllocator.GetAllFree() {
		addToMask(cpu, &result)
	}
	return result
}

func addToMask(cpu int, s *string) {
	if s == nil {
		return
	}
	if *s == "" {
		*s = fmt.Sprintf("%d", cpu)
	} else {
		*s = fmt.Sprintf("%s,%d", *s, cpu)
	}
}

func updateNonPinnedCPUs(ctx *domainContext, config *types.DomainConfig, status *types.DomainStatus) error {
	status.VmConfig.CPUs = constructNonPinnedCpumaskString(ctx)
	err := setCgroupCpuset(config, status)
	if err != nil {
		return errors.New("failed to redistribute CPUs between VMs, can affect the inter-VM isolation")
	}
	return nil
}

// assignCPUs assigns CPUs to the VM based on the configuration
// By the assignment, we mean that the CPUs are assigned in the CPUAllocator context to the given VM
// and the cpumask is updated in the *status*
func assignCPUs(ctx *domainContext, config *types.DomainConfig, status *types.DomainStatus) error {
	if config.VmConfig.CPUsPinned { // Pin the CPU
		cpusToAssign, err := ctx.cpuAllocator.Allocate(config.UUIDandVersion.UUID, config.VCpus)
		if err != nil {
			return errors.New("failed to allocate necessary amount of CPUs")
		}
		for _, cpu := range cpusToAssign {
			addToMask(cpu, &status.VmConfig.CPUs)
		}
	} else { // VM has no pinned CPUs, assign all the CPUs from the shared set
		status.VmConfig.CPUs = constructNonPinnedCpumaskString(ctx)
	}
	return nil
}

// releaseCPUs releases the CPUs that were previously assigned to the VM.
// The cpumask in the *status* is updated accordingly, and the CPUs are released in the CPUAllocator context.
func releaseCPUs(ctx *domainContext, config *types.DomainConfig, status *types.DomainStatus) {
	if ctx.cpuPinningSupported && config.VmConfig.CPUsPinned && status.VmConfig.CPUs != "" {
		if err := ctx.cpuAllocator.Free(config.UUIDandVersion.UUID); err != nil {
			log.Errorf("Failed to free CPUs for %s: %s", config.DisplayName, err)
		}
	}
	status.VmConfig.CPUs = ""
}

func handleCreate(ctx *domainContext, key string, config *types.DomainConfig) {

	log.Functionf("handleCreate(%v) for %s",
		config.UUIDandVersion, config.DisplayName)
	log.Tracef("DomainConfig %+v", config)

	// Start by marking with PendingAdd
	status := types.DomainStatus{
		UUIDandVersion: config.UUIDandVersion,
		PendingAdd:     true,
		DisplayName:    config.DisplayName,
		DomainName:     config.GetTaskName(),
		AppNum:         config.AppNum,
		DisableLogs:    config.DisableLogs,
		State:          types.INSTALLED,
		VmConfig:       config.VmConfig,
		Service:        config.Service,
	}

	status.VmConfig.CPUs = ""

	// Note that the -emu interface doesn't exist until after boot of the domU, but we
	// initialize the VifList here with the VifUsed.
	status.VifList = fillVifUsed(config.VifList)

	publishDomainStatus(ctx, &status)
	log.Functionf("handleCreate(%v) set domainName %s for %s",
		config.UUIDandVersion, status.DomainName,
		config.DisplayName)

	if err := configToStatus(ctx, *config, &status); err != nil {
		log.Errorf("Failed to create DomainStatus from %+v: %s",
			config, err)
		status.PendingAdd = false
		// will retry in maybeRetryConfig
		status.ConfigFailed = true
		status.SetErrorNow(err.Error())
		publishDomainStatus(ctx, &status)
		return
	}

	// Write any Location so that it can later be deleted based on status
	publishDomainStatus(ctx, &status)

	if config.Activate {
		doActivate(ctx, *config, &status)
	}
	// work done
	status.PendingAdd = false
	publishDomainStatus(ctx, &status)
	log.Functionf("handleCreate(%v) DONE for %s",
		config.UUIDandVersion, config.DisplayName)
}

// returns a map of PciLong to *types.IoBundle
func usbControllersWithoutPCIReserve(ioBundles []types.IoBundle) map[string][]*types.IoBundle {
	ret := make(map[string][]*types.IoBundle, 0)

	usbControllerGroups := make(map[string][]*types.IoBundle) // assigngrp -> iobundle

	for i, ioBundle := range ioBundles {
		if ioBundle.Type != types.IoUSBController {
			continue
		}

		if usbControllerGroups[ioBundle.AssignmentGroup] == nil {
			usbControllerGroups[ioBundle.AssignmentGroup] = make([]*types.IoBundle, 0)
		}

		usbControllerGroups[ioBundle.AssignmentGroup] = append(usbControllerGroups[ioBundle.AssignmentGroup], &ioBundles[i])
	}

	for _, ioBundle := range ioBundles {
		if ioBundle.UsbAddr == "" && ioBundle.UsbProduct == "" && ioBundle.Type != types.IoUSBDevice {
			continue
		}

		if ioBundle.ParentAssignmentGroup == "" {
			ret = make(map[string][]*types.IoBundle, 0)

			for i, usbControllers := range usbControllerGroups {
				for j, usbController := range usbControllers {
					if ret[usbController.PciLong] == nil {
						ret[usbController.PciLong] = make([]*types.IoBundle, 0)
					}

					ret[usbController.PciLong] = append(ret[usbController.PciLong], usbControllerGroups[i][j])
				}
			}

			return ret
		}

		if usbControllerGroups[ioBundle.ParentAssignmentGroup] != nil {
			for i, usbController := range usbControllerGroups[ioBundle.ParentAssignmentGroup] {
				if ret[usbController.PciLong] == nil {
					ret[usbController.PciLong] = make([]*types.IoBundle, 0)
				}

				ret[usbController.PciLong] = append(ret[usbController.PciLong], usbControllerGroups[ioBundle.ParentAssignmentGroup][i])
			}
		}
	}

	return ret
}

// doAssignAdaptersToDomain assigns IO adapters to the newly created domain.
// Note that the adapters are already reserved for the domain using reserveAdapters (UsedByUUID is set).
func doAssignIoAdaptersToDomain(ctx *domainContext, config types.DomainConfig,
	status *types.DomainStatus) error {

	publishAssignableAdapters := false
	var assignmentsPci []string
	var assignmentsUsb []string
	for _, adapter := range config.IoAdapterList {
		log.Functionf("doAssignIoAdaptersToDomain processing adapter %d %s",
			adapter.Type, adapter.Name)

		aa := ctx.assignableAdapters
		list := aa.LookupIoBundleAny(adapter.Name)
		// We reserved it in reserveAdapters so nobody could have stolen it
		if len(list) == 0 {
			log.Fatalf("doAssignIoAdaptersToDomain IoBundle disappeared %d %s for %s",
				adapter.Type, adapter.Name, status.DomainName)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			log.Functionf("doAssignIoAdaptersToDomain processing adapter %d %s phylabel %s",
				adapter.Type, adapter.Name, ib.Phylabel)
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				log.Fatalf("doAssignIoAdaptersToDomain IoBundle stolen by %s: %d %s for %s",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					status.DomainName)
			}
			if ib.IsPort {
				log.Fatalf("doAssignIoAdaptersToDomain IoBundle stolen by zedrouter: %d %s for %s",
					adapter.Type, adapter.Name,
					status.DomainName)
			}
			// Also checked in reserveAdapters. Check here in case there was a late error.
			if !ib.Error.Empty() {
				return fmt.Errorf(ib.Error.String())
			}
			if ib.UsbAddr != "" {
				log.Functionf("Assigning %s (%s) to %s",
					ib.Phylabel, ib.UsbAddr, status.DomainName)
				assignmentsUsb = addNoDuplicate(assignmentsUsb, ib.UsbAddr)
			} else if ib.PciLong != "" && !ib.IsPCIBack {
				if !(ctx.hvTypeKube && config.VirtualizationMode == types.NOHYPER) || ib.Type != types.IoNetEth {
					log.Functionf("Assigning %s (%s) to %s",
						ib.Phylabel, ib.PciLong, status.DomainName)
					assignmentsPci = addNoDuplicate(assignmentsPci, ib.PciLong)
					ib.IsPCIBack = true
				} else {
					// For native container with ethernet IO passthrough, we use the NAD for the Multus
					// for the container to directly access the ethernet port through network mechanism
					log.Noticef("doAssignIoAdaptersToDomain: skip IO assign %v", ib)
				}
			}
		}
		publishAssignableAdapters = len(assignmentsUsb) > 0 || len(assignmentsPci) > 0
	}

	for i, long := range assignmentsPci {
		err := hyper.PCIReserve(long)
		if err != nil {
			// Undo what we assigned
			for j, long := range assignmentsPci {
				if j >= i {
					break
				}
				hyper.PCIRelease(long)
			}
			if publishAssignableAdapters {
				ctx.publishAssignableAdapters()
			}
			return err
		}
	}
	checkIoBundleAll(ctx)
	if publishAssignableAdapters {
		ctx.publishAssignableAdapters()
	}
	return nil
}

func getVersionFromMetaFile(path string) (uint64, error) {
	var curCIVersion uint64

	// read cloud init version from the meta-data file
	metafile, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("Failed to open meta-data file: %s", err)
	}
	scanner := bufio.NewScanner(metafile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "instance-id:") {
			parts := strings.Split(line, "/")
			if len(parts) >= 2 {
				curCIVersion, err = strconv.ParseUint(parts[1], 10, 32)
				if err != nil {
					return 0, fmt.Errorf("Failed to parse cloud init version: %s", err.Error())
				}
				return curCIVersion, nil
			}
		}
	}

	// Check for scanner errors.
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("Reading the file failed: %s", err.Error())
	}

	return 0, errors.New("Version not found in meta-data file")
}

func doActivate(ctx *domainContext, config types.DomainConfig,
	status *types.DomainStatus) {

	log.Functionf("doActivate(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	if ctx.cpuPinningSupported {
		if err := assignCPUs(ctx, &config, status); err != nil {
			log.Warnf("failed to assign CPUs for %s", config.DisplayName)
			errDescription := types.ErrorDescription{Error: err.Error()}
			status.SetErrorDescription(errDescription)
			publishDomainStatus(ctx, status)
			return
		}
		log.Functionf("CPUs for %s assigned: %s", config.DisplayName, status.VmConfig.CPUs)
	}

	if errDescription := reserveAdapters(ctx, config); errDescription != nil {
		log.Errorf("Failed to reserve adapters for %s: %s",
			config.Key(), errDescription.Error)
		status.PendingAdd = false
		status.SetErrorDescription(*errDescription)
		status.AdaptersFailed = true
		releaseCPUs(ctx, &config, status)
		publishDomainStatus(ctx, status)
		releaseAdapters(ctx, config.IoAdapterList, config.UUIDandVersion.UUID,
			nil)
		status.IoAdapterList = nil
		return
	}
	status.AdaptersFailed = false
	if status.HasError() {
		log.Noticef("maybeRetryAdapters(%s) clearing existing error: %s",
			status.Key(), status.Error)
		status.ClearError()
	}

	// We now have reserved all of the IoAdapters
	status.IoAdapterList = config.IoAdapterList

	// Assign any I/O devices
	if err := doAssignIoAdaptersToDomain(ctx, config, status); err != nil {
		log.Errorf("Failed to assign adapters for %s: %s",
			config.Key(), err)
		status.PendingAdd = false
		status.SetErrorNow(err.Error())
		status.AdaptersFailed = true
		releaseCPUs(ctx, &config, status)
		publishDomainStatus(ctx, status)
		releaseAdapters(ctx, config.IoAdapterList, config.UUIDandVersion.UUID,
			nil)
		status.IoAdapterList = nil
		return
	}
	// Finish preparing for container runtime.
	for _, ds := range status.DiskStatusList {
		switch ds.Format {
		case zconfig.Format_FmtUnknown:
			// do nothing
		case zconfig.Format_CONTAINER:
			if ctx.hvTypeKube {
				// do nothing. In Kubevirt eve we convert the container content to PVC in volumemanager.
				continue
			}
			snapshotID := containerd.GetSnapshotID(ds.FileLocation)
			rootPath := cas.GetRoofFsPath(ds.FileLocation)
			if err := ctx.casClient.MountSnapshot(snapshotID, rootPath); err != nil {
				err := fmt.Errorf("doActivate: Failed mount snapshot: %s for %s. Error %s",
					snapshotID, config.UUIDandVersion.UUID, err)
				log.Error(err.Error())
				status.SetErrorNow(err.Error())
				releaseCPUs(ctx, &config, status)
				return
			}

			metadataPath := filepath.Join(rootPath, "meta-data")

			// get current cloud init version
			curCIVersion, err := getVersionFromMetaFile(metadataPath)
			if err != nil {
				curCIVersion = 0 // make sure the cloud init config gets executed
			}

			// get new cloud init version
			newCIVersion, err := strconv.ParseUint(getCloudInitVersion(config), 10, 32)
			if err != nil {
				log.Error("Failed to parse cloud init version: ", err)
				newCIVersion = curCIVersion + 1 // make sure the cloud init config gets executed
			}

			if curCIVersion < newCIVersion {
				log.Notice("New cloud init config detected - applying")

				// write meta-data file
				versionString := fmt.Sprintf("instance-id: %s/%s\n", config.UUIDandVersion.UUID.String(), getCloudInitVersion(config))
				err = fileutils.WriteRename(metadataPath, []byte(versionString))
				if err != nil {
					err := fmt.Errorf("doActivate: Failed to write cloud-init metadata file. Error %s", err)
					log.Error(err.Error())
					status.SetErrorNow(err.Error())
					releaseCPUs(ctx, &config, status)
					return
				}

				// apply cloud init config
				for _, writableFile := range status.WritableFiles {
					err := cloudconfig.WriteFile(log, writableFile, rootPath)
					if err != nil {
						err := fmt.Errorf("doActivate: Failed to apply cloud-init config. Error %s", err)
						log.Error(err.Error())
						status.SetErrorNow(err.Error())
						releaseCPUs(ctx, &config, status)
						return
					}
				}
			}
		default:
			// assume everything else to be disk formats
			format, err := utils.GetVolumeFormat(log, ds.FileLocation)
			if err == nil && format != ds.Format {
				err = fmt.Errorf("Disk format mismatch, format in config %v and output of qemu-img/zfs get %v\n"+
					"Note: Format mismatch may be because of disk corruption also.",
					ds.Format, format)
			}
			if err != nil {
				log.Errorf("Failed to check disk format: %v", err.Error())
				status.SetErrorNow(err.Error())
				releaseCPUs(ctx, &config, status)
				return
			}
		}
	}

	filename := xenCfgFilename(config.AppNum)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal("os.Create for ", filename, err)
	}
	defer file.Close()

	if err := hyper.Task(status).VirtualTPMSetup(status.DomainName, agentName, ctx.ps, warningTime, errorTime); err != nil {
		log.Errorf("Failed to setup virtual TPM for %s: %s", status.DomainName, err)
		status.VirtualTPM = false
	} else {
		status.VirtualTPM = true
	}

	globalConfig := agentlog.GetGlobalConfig(log, ctx.subGlobalConfig)
	if err := hyper.Task(status).Setup(*status, config, ctx.assignableAdapters, globalConfig, file); err != nil {
		log.Errorf("Failed to create DomainStatus from %+v: %s",
			config, err)
		status.SetErrorNow(err.Error())
		releaseCPUs(ctx, &config, status)

		if err := hyper.Task(status).VirtualTPMTerminate(status.DomainName); err != nil {
			log.Errorf("Failed to terminate virtual TPM for %s: %s", status.DomainName, err)
		}

		return
	}

	status.TriedCount = 0
	var domainID int
	// Invoke domain create; try 3 times with a timeout
	for {
		status.TriedCount++
		var err error
		ctx.createSema.V(1)
		domainID, err = DomainCreate(ctx, *status)
		ctx.createSema.P(1)
		if err == nil {
			break
		}
		if status.TriedCount >= 3 {
			log.Errorf("DomainCreate for %s: %s", status.DomainName, err)
			status.BootFailed = true
			status.SetErrorNow(err.Error())
			releaseCPUs(ctx, &config, status)
			publishDomainStatus(ctx, status)
			return
		}
		log.Warnf("Retry domain create for %s: failed %s",
			status.DomainName, err)
		publishDomainStatus(ctx, status)
		time.Sleep(5 * time.Second)
	}
	if ctx.cpuPinningSupported {
		if err := setCgroupCpuset(&config, status); err != nil {
			log.Errorf("Failed to set CPUs for %s: %s", config.DisplayName, err)
			errDescription := types.ErrorDescription{Error: err.Error()}
			status.SetErrorDescription(errDescription)
			publishDomainStatus(ctx, status)
		}
		if config.CPUsPinned {
			triggerCPUNotification()
		}
	}

	status.BootFailed = false
	doActivateTail(ctx, status, domainID)
}

func doActivateTail(ctx *domainContext, status *types.DomainStatus,
	domainID int) {

	log.Functionf("created domainID %d for %s", domainID, status.DomainName)
	status.DomainId = domainID
	status.BootTime = time.Now()
	log.Functionf("Set domainId %d bootTime %s for %s",
		status.DomainId, status.BootTime.Format(time.RFC3339Nano),
		status.Key())
	status.State = types.BOOTING
	publishDomainStatus(ctx, status)

	err := hyper.Task(status).Start(status.DomainName)
	if err != nil {
		log.Errorf("domain start for %s: %s", status.DomainName, err)
		status.SetErrorNow(err.Error())

		// Delete
		if err := hyper.Task(status).Delete(status.DomainName); err != nil {
			log.Errorf("failed to delete domain: %s (%v)", status.DomainName, err)
		}
		// Cleanup
		if err := hyper.Task(status).Cleanup(status.DomainName); err != nil {
			log.Errorf("failed to cleanup domain: %s (%v)", status.DomainName, err)
		}

		// Set BootFailed to cause retry
		status.BootFailed = true
		status.State = types.BROKEN
		return
	}
	// The -emu interfaces were most likely created as result of the boot so we
	// update VifUsed here.
	status.VifList = checkIfEmu(status.VifList)

	status.State = types.RUNNING
	domainID, state, err := hyper.Task(status).Info(status.DomainName)

	if err != nil {
		// Immediate failure treat as above
		status.BootFailed = true
		status.State = state
		status.Activated = false
		status.SetErrorNow(err.Error())
		log.Errorf("doActivateTail(%v) failed for %s: %s",
			status.UUIDandVersion, status.DisplayName, err)
		// Delete
		if err := hyper.Task(status).Delete(status.DomainName); err != nil {
			log.Errorf("failed to delete domain: %s (%v)", status.DomainName, err)
		}
		// Cleanup
		if err := hyper.Task(status).Cleanup(status.DomainName); err != nil {
			log.Errorf("failed to cleanup domain: %s (%v)", status.DomainName, err)
		}
		return
	}
	if err == nil && domainID != status.DomainId {
		status.DomainId = domainID
		status.BootTime = time.Now()
		log.Noticef("Update domainId %d bootTime %s for %s",
			status.DomainId, status.BootTime.Format(time.RFC3339Nano),
			status.Key())
	}
	status.Activated = true
	log.Functionf("doActivateTail(%v) done for %s",
		status.UUIDandVersion, status.DisplayName)
}

// shutdown and wait for the domain to go away; if that fails destroy and wait
func doInactivate(ctx *domainContext, status *types.DomainStatus, impatient bool) {

	log.Functionf("doInactivate(%v) for %s domainId %d",
		status.UUIDandVersion, status.DisplayName, status.DomainId)
	domainID, _, err := hyper.Task(status).Info(status.DomainName)
	if err == nil && domainID != status.DomainId {
		status.DomainId = domainID
		status.BootTime = time.Now()
		log.Noticef("Update domainId %d bootTime %s for %s",
			status.DomainId, status.BootTime.Format(time.RFC3339Nano),
			status.Key())
	} else if err != nil {
		log.Errorf("doInactivate(%v) for %s Info error: %s",
			status.UUIDandVersion, status.DisplayName, err)
	}
	maxDelay := time.Second * 600 // 10 minutes
	if impatient {
		maxDelay /= 10
	}

	firstDelay := maxDelay
	doShutdown := false // shutdown for particular VirtualizationModes

	switch status.VirtualizationMode {
	case types.HVM, types.FML:
		doShutdown = true

		// Do a short shutdown wait, just in case there are
		// PV tools in guest, then a shutdown -F
		firstDelay = time.Second * 60
	case types.PV:
		doShutdown = true
	}

	if status.DomainId != 0 {
		status.State = types.HALTING
		publishDomainStatus(ctx, status)

		if doShutdown {
			// If the Shutdown fails we don't wait; assume failure
			// was due to no PV tools
			if err := DomainShutdown(*status, false); err != nil {
				log.Errorf("DomainShutdown %s failed: %s",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Functionf("doInactivate(%v) for %s: waiting for domain to shutdown",
					status.UUIDandVersion, status.DisplayName)
				gone := waitForDomainGone(*status, firstDelay)
				if gone {
					status.DomainId = 0
				}
			}
		}
	}
	if status.DomainId != 0 && doShutdown {
		// This often fails with "X is an invalid domain identifier (rc=-6)"
		// due to the DomainShutdown above, in which case
		// the domain is already on the way down.
		// In case of errors we proceed directly to deleting the task,
		// and after that we waitForDomainGone
		if err := DomainShutdown(*status, true); err != nil {
			log.Warnf("DomainShutdown -F %s failed: %s",
				status.DomainName, err)
		} else {
			log.Functionf("doInactivate(%v) for %s Shutdown(force) succeeded",
				status.UUIDandVersion, status.DisplayName)
			// Wait for the domain to go away
			log.Functionf("doInactivate(%v) for %s: waiting for domain to poweroff",
				status.UUIDandVersion, status.DisplayName)
			gone := waitForDomainGone(*status, maxDelay)
			if gone {
				status.DomainId = 0
			}
		}
	}

	if status.DomainId != 0 {
		if err := hyper.Task(status).Delete(status.DomainName); err != nil {
			log.Errorf("Failed to delete domain %s (%v)", status.DomainName, err)
		} else {
			log.Functionf("doInactivate(%v) for %s: Delete succeeded",
				status.UUIDandVersion, status.DisplayName)
		}
		// Even if Delete failed we wait
		log.Functionf("doInactivate(%v) for %s: waiting for domain to be destroyed",
			status.UUIDandVersion, status.DisplayName)
		gone := waitForDomainGone(*status, maxDelay)
		if gone {
			status.DomainId = 0
		}
	}
	doCleanup(ctx, status)
}

func doCleanup(ctx *domainContext, status *types.DomainStatus) {
	if err := hyper.Task(status).Cleanup(status.DomainName); err != nil {
		log.Errorf("failed to cleanup domain: %s (%v)", status.DomainName, err)
	}

	// If everything failed we leave it marked as Activated
	if status.DomainId != 0 {
		errStr := fmt.Sprintf("doInactivate(%s) failed to halt/destroy %d",
			status.Key(), status.DomainId)
		log.Error(errStr)
		// Don't clobber an existing error
		if !status.HasError() {
			status.SetErrorNow(errStr)
		}
	} else {
		status.Activated = false
		status.State = types.HALTED
	}
	// first try to unmount containers without force flag
	if !unmountContainers(ctx, status.DiskStatusList, false) {
		log.Warnln("unmountContainers not done, wait and retry with force flag")
		time.Sleep(10 * time.Second)
		// the second try to unmount containers with force flag
		if !unmountContainers(ctx, status.DiskStatusList, true) {
			log.Errorln("unmountContainers failed after retry with force flag")
		}
	}

	if ctx.cpuPinningSupported {
		if status.VmConfig.CPUsPinned {
			if err := ctx.cpuAllocator.Free(status.UUIDandVersion.UUID); err != nil {
				log.Warnf("Failed to free for %s: %s", status.DisplayName, err)
			}
			triggerCPUNotification()
		}
		status.VmConfig.CPUs = ""
	}
	releaseAdapters(ctx, status.IoAdapterList, status.UUIDandVersion.UUID,
		status)
	status.IoAdapterList = nil
	publishDomainStatus(ctx, status)

	log.Functionf("doCleanup(%v) done for %s",
		status.UUIDandVersion, status.DisplayName)
}

// unmountContainers process provided diskStatusList and unmount all disks with Format_CONTAINER
func unmountContainers(ctx *domainContext, diskStatusList []types.DiskStatus, force bool) bool {
	done := true
	for _, ds := range diskStatusList {
		switch ds.Format {
		case zconfig.Format_CONTAINER:
			if err := ctx.casClient.UnmountContainerRootDir(ds.FileLocation, force); err != nil {
				log.Errorf("unmountContainers: %s", err)
				done = false
			}
		}
	}
	return done
}

// releaseAdapters is called when the domain is done with the device and we
// clear UsedByUUID
// In addition, if KeepInHost is set, we move it back to the host.
// If status is set, any errors are recorded in status
func releaseAdapters(ctx *domainContext, ioAdapterList []types.IoAdapter,
	myUUID uuid.UUID, status *types.DomainStatus) {

	log.Functionf("releaseAdapters(%s)", myUUID)
	ignoreErrors := (status == nil)
	var assignments []string
	for _, adapter := range ioAdapterList {
		log.Tracef("releaseAdapters processing adapter %d %s",
			adapter.Type, adapter.Name)
		aa := ctx.assignableAdapters
		list := aa.LookupIoBundleAny(adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if len(list) == 0 {
			if ignoreErrors {
				continue
			}
			log.Fatalf("releaseAdapters IoBundle disappeared %d %s for %s",
				adapter.Type, adapter.Name, myUUID)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			if ctx.hvTypeKube && status != nil && status.VirtualizationMode == types.NOHYPER && ib.Type == types.IoNetEth {
				continue
			}
			if ib.UsedByUUID != myUUID {
				log.Warnf("releaseAdapters IoBundle not ours by %s: %d %s for %s",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					myUUID)
				continue
			}
			if ib.PciLong != "" && ib.KeepInHost && ib.IsPCIBack {
				log.Functionf("releaseAdapters removing %s (%s) from %s",
					ib.Phylabel, ib.PciLong, myUUID)
				assignments = addNoDuplicate(assignments, ib.PciLong)
				ib.IsPCIBack = false
			}
			ib.UsedByUUID = nilUUID
		}
		checkIoBundleAll(ctx)
	}
	for _, long := range assignments {
		err := hyper.PCIRelease(long)
		if err != nil && !ignoreErrors {
			status.SetErrorNow(err.Error())
		}
	}
	ctx.publishAssignableAdapters()
}

// Produce DomainStatus based on the config
func configToStatus(ctx *domainContext, config types.DomainConfig,
	status *types.DomainStatus) error {

	log.Functionf("configToStatus(%v) for %s",
		config.UUIDandVersion, config.DisplayName)
	status.DiskStatusList = make([]types.DiskStatus,
		len(config.DiskConfigList))
	need9P := false
	for i, dc := range config.DiskConfigList {
		ds := &status.DiskStatusList[i]
		ds.VolumeKey = dc.VolumeKey
		ds.ReadOnly = dc.ReadOnly
		ds.FileLocation = dc.FileLocation
		ds.Format = dc.Format
		ds.MountDir = dc.MountDir
		ds.DisplayName = dc.DisplayName
		ds.WWN = dc.WWN
		ds.CustomMeta = dc.CustomMeta
		// Generate Devtype for hypervisor package
		// XXX can hypervisor look at something different?
		if dc.Target == zconfig.Target_AppCustom {
			ds.Devtype = "AppCustom"
		} else if dc.Format == zconfig.Format_CONTAINER {
			if i == 0 {
				ds.MountDir = "/"
				status.OCIConfigDir = ds.FileLocation
			}
			ds.Devtype = ""
			need9P = true
		} else {
			ds.Devtype = "hdd"
			if dc.Format == zconfig.Format_ISO {
				// set required devtype and adjust format to raw as required by hypervisor
				ds.Format = zconfig.Format_RAW
				ds.Devtype = "cdrom"
			}
			if config.VirtualizationMode == types.LEGACY {
				ds.Devtype = "legacy"
			}
		}
		// map from i=1 to xvdb, 2 to xvdc etc
		ds.Vdev = fmt.Sprintf("xvd%c", int('a')+i)
	}

	//clean environment variables
	status.EnvVariables = nil

	// Fetch cloud-init userdata
	if config.IsCipher || config.CloudInitUserData != nil {
		ciStr, err := fetchCloudInit(ctx, config)
		if err != nil {
			return fmt.Errorf("failed to fetch cloud-init userdata: %s",
				err)
		}

		// Set FML custom resolution if it is set in cloud-init config,
		// xxx : this is hack and this should be removed, this should be
		// part of the vm config, but desprate times call for desprate measures.
		if cloudconfig.IsCloudConfig(ciStr) {
			setFmlCustomResolution(ciStr, status)
		}

		if status.OCIConfigDir != "" { // If AppInstance is a container, we need to parse cloud-init config and apply the supported parts
			if cloudconfig.IsCloudConfig(ciStr) { // treat like the cloud-init config
				cc, err := cloudconfig.ParseCloudConfig(ciStr)
				if err != nil {
					return fmt.Errorf("failed to unmarshal cloud-init userdata: %s",
						err)
				}
				status.WritableFiles = cc.WriteFiles

				envList, err := parseEnvVariablesFromCloudInit(cc.RunCmd)
				if err != nil {
					return fmt.Errorf("failed to parse environment variable from cloud-init userdata: %s",
						err)
				}
				status.EnvVariables = envList
			} else { // treat like the key value map for envs (old syntax)
				envPairs := strings.Split(ciStr, "\n")
				envList, err := parseEnvVariablesFromCloudInit(envPairs)
				if err != nil {
					return fmt.Errorf("failed to parse environment variable from cloud-init env map: %s",
						err)
				}
				status.EnvVariables = envList
			}
		} else { // If AppInstance is a VM, we need to create a cloud-init ISO
			switch config.MetaDataType {
			case types.MetaDataDrive, types.MetaDataDriveMultipart:
				ds, err := createCloudInitISO(ctx, config, ciStr)
				if err != nil {
					return err
				}
				status.DiskStatusList = append(status.DiskStatusList, *ds)
			}
		}
	}

	if need9P {
		status.DiskStatusList = append(status.DiskStatusList, types.DiskStatus{
			FileLocation: "/mnt",
			Devtype:      "9P",
			ReadOnly:     false,
		})
	}
	return nil
}

func setFmlCustomResolution(config string, status *types.DomainStatus) {
	var cloudinit map[string]interface{}
	err := yaml.Unmarshal([]byte(config), &cloudinit)
	if err != nil {
		log.Errorf("error parsing cloud-config YAML: %v", err)
		return
	}

	if val, ok := cloudinit[string(types.FmlCustomResolution)]; ok {
		if fmlCustomResolution, valid := val.(string); valid {
			status.FmlCustomResolution = fmlCustomResolution
			log.Noticef("FML resolution is set to: %s", status.FmlCustomResolution)
		}
	}
}

// Check for errors and reserve any assigned adapters.
// Please note that reservation is done only by setting UsedByUUID to the application UUID.
// The actual call to PCIReserve() is done later by doAssignIoAdaptersToDomain().
func reserveAdapters(ctx *domainContext, config types.DomainConfig) *types.ErrorDescription {
	description := types.ErrorDescription{}

	log.Functionf("reserveAdapters(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	defer ctx.publishAssignableAdapters()

	hasIOVirtualization := true
	capabilities, err := lookupCapabilities(ctx)
	if err != nil {
		log.Errorf("cannot check capabilities: %v", err)
	} else {
		hasIOVirtualization = capabilities.IOVirtualization
	}

	for _, adapter := range config.IoAdapterList {
		log.Functionf("reserveAdapters processing adapter %d %s",
			adapter.Type, adapter.Name)
		// Lookup to make sure adapter exists on this device
		list := ctx.assignableAdapters.LookupIoBundleAny(adapter.Name)
		if len(list) == 0 {
			description.Error = fmt.Sprintf("unknown adapter %d %s",
				adapter.Type, adapter.Name)
			return &description
		}

		for _, ibp := range list {
			if ibp == nil {
				continue
			}
			log.Functionf("reserveAdapters processing adapter %d %s phylabel %s",
				adapter.Type, adapter.Name, ibp.Phylabel)
			if ctx.hvTypeKube && config.VirtualizationMode == types.NOHYPER && ibp.Type == types.IoNetEth {
				log.Noticef("reserveAdapters: ethernet io, skip reserve")
				continue
			}
			if ibp.AssignmentGroup == "" {
				description.Error = fmt.Sprintf("adapter %d %s phylabel %s is not assignable",
					adapter.Type, adapter.Name, ibp.Phylabel)
				return &description
			}
			if ibp.UsedByUUID != config.UUIDandVersion.UUID &&
				ibp.UsedByUUID != nilUUID {
				// Check if current user of ibp is halting
				extraStr := ""
				other := lookupDomainStatusByUUID(ctx, ibp.UsedByUUID)
				if other == nil {
					log.Warnf("UsedByUUID %s but no status",
						ibp.UsedByUUID)
					extraStr = "(which is missing)"
				} else {
					description.ErrorSeverity = types.ErrorSeverityWarning
					if other.State == types.HALTING {
						extraStr = "(which is halting)"
						description.ErrorSeverity = types.ErrorSeverityNotice
					}
					description.ErrorEntities = []*types.ErrorEntity{{EntityID: other.UUIDandVersion.UUID.String(), EntityType: types.ErrorEntityAppInstance}}
					description.ErrorRetryCondition = "Will wait for adapter to release from app"
				}
				description.Error = fmt.Sprintf("adapter %d %s used by %s %s",
					adapter.Type, adapter.Name,
					ibp.UsedByUUID, extraStr)
				return &description
			}
			if ibp.IsPort {
				description.Error = fmt.Sprintf("adapter %d %s phylabel %s is (part of) a zedrouter port",
					adapter.Type, adapter.Name, ibp.Phylabel)
				return &description
			}
			if !ibp.Error.Empty() {
				description.Error = fmt.Sprintf("adapter %d %s phylabel %s has error: %s",
					adapter.Type, adapter.Name, ibp.Phylabel, ibp.Error.String())
				return &description
			}
		}
		for _, ibp := range list {
			if ibp == nil {
				continue
			}
			if ibp.PciLong != "" && !hasIOVirtualization {
				description.Error = fmt.Sprintf("no I/O virtualization support: adapter %d %s phylabel %s cannot be assigned",
					adapter.Type, adapter.Name, ibp.Phylabel)
				return &description
			}
			log.Tracef("reserveAdapters setting uuid %s for adapter %d %s phylabel %s",
				config.Key(), adapter.Type, adapter.Name, ibp.Phylabel)
			ibp.UsedByUUID = config.UUIDandVersion.UUID
		}
	}
	return nil
}

func addNoDuplicate(list []string, add string) []string {

	for _, s := range list {
		if s == add {
			return list
		}
	}
	return append(list, add)
}

// Need to compare what might have changed. If any content change
// then we need to reboot. Thus version can change but can't handle disk or
// vif changes.
// XXX should we reboot if there are such changes? Or reject with error?
func handleModify(ctx *domainContext, key string,
	config *types.DomainConfig, status *types.DomainStatus) {

	log.Functionf("handleModify(%v) activate %t for %s state %s",
		config.UUIDandVersion, config.Activate, config.DisplayName,
		status.State.String())

	status.PendingModify = true
	publishDomainStatus(ctx, status)

	changed := false
	// if a VM has an error status, it should be restarted in the maybeRetryBoot function, not here
	if config.Activate && !status.Activated && status.State != types.BROKEN && !status.HasError() {
		log.Functionf("handleModify(%v) activating for %s",
			config.UUIDandVersion, config.DisplayName)

		if status.DomainName != config.GetTaskName() {
			status.DomainName = config.GetTaskName()
			status.AppNum = config.AppNum
			log.Functionf("handleModify(%v) set domainName %s for %s",
				config.UUIDandVersion, status.DomainName,
				config.DisplayName)
		}
		status.VifList = fillVifUsed(config.VifList)
		publishDomainStatus(ctx, status)

		// Update disks based on any change to volumes
		if err := configToStatus(ctx, *config, status); err != nil {
			log.Errorf("Failed to update DomainStatus from %v: %s",
				config, err)
			// will retry in maybeRetryConfig
			status.ConfigFailed = true
			status.PendingModify = false
			status.SetErrorNow(err.Error())
			publishDomainStatus(ctx, status)
			return
		}
		updateStatusFromConfig(status, *config)
		doActivate(ctx, *config, status)
		changed = true
	} else if !config.Activate {
		log.Functionf("handleModify(%v) NOT activating for %s",
			config.UUIDandVersion, config.DisplayName)
		if status.HasError() {
			log.Noticef("handleModify(%s) clearing existing error: %s",
				status.Key(), status.Error)
			status.ClearError()
			publishDomainStatus(ctx, status)
			doInactivate(ctx, status, false)
			updateStatusFromConfig(status, *config)
			changed = true
		} else if status.Activated {
			doInactivate(ctx, status, false)
			updateStatusFromConfig(status, *config)
			changed = true
		}
		// Update disks based on any change to volumes
		if err := configToStatus(ctx, *config, status); err != nil {
			log.Errorf("Failed to update DomainStatus from %v: %s",
				config, err)
			// will retry in maybeRetryConfig
			status.ConfigFailed = true
			status.PendingModify = false
			status.SetErrorNow(err.Error())
			publishDomainStatus(ctx, status)
			return
		}
		updateStatusFromConfig(status, *config)
		changed = true
	}
	if changed {
		// XXX could we also have changes in the IoBundle?
		// Need to update the UsedByUUID if so since we reserved
		// the IoBundle in handleCreate before activating.
		// XXX currently those reservations are only changed
		// in handleDelete
		status.PendingModify = false
		publishDomainStatus(ctx, status)
		log.Functionf("handleModify(%v) DONE for %s",
			config.UUIDandVersion, config.DisplayName)
		return
	}

	// XXX check if we have status.HasError() and delete and retry
	// even if same version. XXX won't the above Activate/Activated checks
	// result in redoing things? Could have failures during copy i.e.
	// before activation.

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Functionf("Same version %s for %s",
			config.UUIDandVersion.Version, key)
		status.PendingModify = false
		publishDomainStatus(ctx, status)
		return
	}

	publishDomainStatus(ctx, status)
	// XXX Any work?
	// XXX create tmp xen cfg and diff against existing xen cfg
	// If different then stop and start. XXX domain shutdown takes a while
	// need to watch status using a go routine?

	status.PendingModify = false
	status.UUIDandVersion = config.UUIDandVersion
	publishDomainStatus(ctx, status)
	log.Functionf("handleModify(%v) DONE for %s",
		config.UUIDandVersion, config.DisplayName)
}

func updateStatusFromConfig(status *types.DomainStatus, config types.DomainConfig) {
	status.VirtualizationMode = config.VirtualizationModeOrDefault()
	status.EnableVnc = config.EnableVnc
	status.EnableVncShimVM = config.EnableVncShimVM
	status.VncDisplay = config.VncDisplay
	status.VncPasswd = config.VncPasswd
	status.DisableLogs = config.DisableLogs
}

// fillVifUsed iterates over vifs from received config and fill VifUsed
func fillVifUsed(vifList []types.VifConfig) []types.VifInfo {
	var retList []types.VifInfo
	for _, net := range vifList {
		retList = append(retList, types.VifInfo{VifConfig: net})
	}
	return checkIfEmu(retList)
}

// If we have a -emu named interface we assume it is being used
func checkIfEmu(vifList []types.VifInfo) []types.VifInfo {
	var retList []types.VifInfo

	for _, net := range vifList {
		net.VifUsed = net.Vif
		emuIfname := net.Vif + "-emu"
		_, err := netlink.LinkByName(emuIfname)
		if err == nil && net.VifUsed != emuIfname {
			log.Functionf("Found EMU %s and update %s", emuIfname, net.VifUsed)
			net.VifUsed = emuIfname
		}
		retList = append(retList, net)
	}
	return retList
}

// Used to wait both after shutdown and destroy
func waitForDomainGone(status types.DomainStatus, maxDelay time.Duration) bool {
	delay := time.Second
	var waited time.Duration
	for {
		log.Functionf("waitForDomainGone(%v) for %s: waiting for %v",
			status.UUIDandVersion, status.DisplayName, delay)
		if delay != 0 {
			time.Sleep(delay)
			waited += delay
		}
		_, state, err := hyper.Task(&status).Info(status.DomainName)
		if err != nil {
			log.Errorf("waitForDomainGone(%v) for %s error %s state %s",
				status.UUIDandVersion, status.DisplayName,
				err, state.String())
			// If we get here it is typically because Info reported
			// the task as broken.
			return true
		}
		if state == types.HALTED || state == types.UNKNOWN {
			log.Functionf("waitForDomainGone(%v) for %s: done state %s",
				status.UUIDandVersion, status.DisplayName,
				state.String())
			return true
		}
		log.Functionf("waitForDomainGone(%v) for %s state still %s waited %v",
			status.UUIDandVersion, status.DisplayName,
			state.String(), waited)
		if waited > maxDelay {
			// Give up
			log.Warnf("waitForDomainGone(%v) for %s: giving up after %v state %s",
				status.UUIDandVersion, status.DisplayName,
				waited, state.String())
			return false
		}
		delay = 2 * delay
		if delay > time.Minute {
			delay = time.Minute
		}
	}
}

func handleDelete(ctx *domainContext, key string, status *types.DomainStatus) {

	log.Functionf("handleDelete(%v) for %s",
		status.UUIDandVersion, status.DisplayName)

	status.PendingDelete = true
	publishDomainStatus(ctx, status)

	if status.Activated {
		doInactivate(ctx, status, true)
	} else if status.HasError() {
		doCleanup(ctx, status)
	}

	// Check if the USB controller became available for dom0
	updateUsbAccess(ctx)
	updateVgaAccess(ctx)

	// Delete xen cfg file for good measure
	filename := xenCfgFilename(status.AppNum)
	if err := os.Remove(filename); err != nil {
		log.Errorln(err)
	}
	deleteCloudInitISO(ctx, *status)

	status.PendingDelete = false
	publishDomainStatus(ctx, status)
	// Write out what we modified to DomainStatus aka delete
	unpublishDomainStatus(ctx, status)
	// No point in publishing metrics any more
	ctx.pubDomainMetric.Unpublish(status.Key())

	err := hyper.Task(status).Delete(status.DomainName)
	if err != nil {
		log.Errorln(err)
	}

	if err := hyper.Task(status).VirtualTPMTeardown(status.DomainName); err != nil {
		log.Errorln(err)
	}

	log.Functionf("handleDelete(%v) DONE for %s",
		status.UUIDandVersion, status.DisplayName)
}

// DomainCreate is a wrapper for domain creation
// returns domainID and error
func DomainCreate(ctx *domainContext, status types.DomainStatus) (int, error) {

	var (
		domainID int
		err      error
	)

	filename := xenCfgFilename(status.AppNum)
	log.Functionf("DomainCreate %s ... xenCfgFilename - %s", status.DomainName, filename)

	// Now create a domain
	log.Functionf("Creating domain with the config - %s", filename)
	config := lookupDomainConfig(ctx, status.Key())
	if config == nil {
		// Odd to have status but no config
		log.Errorf("DomainCreate(%s) no DomainConfig", status.Key())
		return 0, fmt.Errorf("DomainCreate(%s) no DomainConfig", status.Key())
	}
	domainID, err = hyper.Task(&status).Create(status.DomainName, filename, config)

	return domainID, err
}

// DomainShutdown is a wrapper for domain shutdown
func DomainShutdown(status types.DomainStatus, force bool) error {

	var err error
	log.Functionf("DomainShutdown force-%v %s %d", force, status.DomainName, status.DomainId)

	// Stop the domain
	log.Functionf("Stopping domain - %s", status.DomainName)
	err = hyper.Task(&status).Stop(status.DomainName, force)

	return err
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
	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Functionf("handleDNSImpl: ignoring %s", key)
		return
	}
	if status.DPCKey == "" {
		// Do not activate PhysicalIOAdapterList subscription until NIM receives
		// a DPC and publishes corresponding DNS.
		// NIM can publish DNS even before it receives first DPC. In such case
		// DPCKey is empty.
		// The goal is to avoid assigning network ports to PCIBack if they are going to be
		// used for management purposes. This way we avoid doing unintended port assignment
		// to PCIBack that would be shortly followed by a release, therefore mitigating
		// the risk of race conditions between domainmgr and NIM.
		log.Warnf("handleDNSImpl: DNS with empty DPCKey")
		return
	}
	// Ignore test status and timestamps
	// Compare Testing to save its updated value which is used by us
	if ctx.deviceNetworkStatus.MostlyEqual(status) &&
		ctx.deviceNetworkStatus.Testing == status.Testing {
		log.Functionf("handleDNSImpl unchanged")
		ctx.DNSinitialized = true
		return
	}
	log.Functionf("handleDNSImpl: changed %v",
		cmp.Diff(ctx.deviceNetworkStatus, status))
	// Even if Testing is set we look at it for pciback transitions to
	// bring things out of pciback (but not to add to pciback)
	ctx.deviceNetworkStatus = status
	updatePortAndPciBackIoBundleAll(ctx)
	ctx.DNSinitialized = true
	log.Functionf("handleDNSImpl done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Functionf("handleDNSDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleDNSDelete for %s", key)
	ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	ctx.DNSinitialized = false
	updatePortAndPciBackIoBundleAll(ctx)
	log.Functionf("handleDNSDelete done for %s", key)
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

	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		if gcp.GlobalValueInt(types.DomainBootRetryTime) != 0 {
			ctx.domainBootRetryTime = gcp.GlobalValueInt(types.DomainBootRetryTime)
		}
		// XXX remove the initialized case?
		if gcp.GlobalValueBool(types.UsbAccess) != ctx.usbAccess ||
			!ctx.setInitialUsbAccess {

			ctx.usbAccess = gcp.GlobalValueBool(types.UsbAccess)
			updateUsbAccess(ctx)
			ctx.setInitialUsbAccess = true
		}
		if gcp.GlobalValueBool(types.VgaAccess) != ctx.vgaAccess ||
			!ctx.setInitialVgaAccess {

			ctx.vgaAccess = gcp.GlobalValueBool(types.VgaAccess)
			updateVgaAccess(ctx)
			ctx.setInitialVgaAccess = true
		}
		if gcp.GlobalValueBool(types.ConsoleAccess) != ctx.consoleAccess ||
			!ctx.setInitialConsoleAccess {

			ctx.consoleAccess = gcp.GlobalValueBool(types.ConsoleAccess)
			updateConsoleAccess(ctx)
			ctx.setInitialConsoleAccess = true
		}
		metricInterval := gcp.GlobalValueInt(types.MetricInterval)
		if metricInterval != 0 && ctx.metricInterval != metricInterval {
			// adjust publishTicker interval if metricInterval changed
			interval := time.Duration(metricInterval) * time.Second
			max := float64(interval) / publishTickerDivider
			min := max * 0.3
			ctx.publishTicker.UpdateRangeTicker(time.Duration(min), time.Duration(max))

			ctx.metricInterval = metricInterval
		}
		ctx.processCloudInitMultiPart = gcp.GlobalValueBool(types.ProcessCloudInitMultiPart)
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s. "+
		"DomainBootRetryTime: %d, usbAccess: %t, metricInterval: %d",
		key, ctx.domainBootRetryTime, ctx.usbAccess,
		ctx.metricInterval)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

// This gets called once the GlobalConfig subscription/directory has been
// completely processed. Thus will signal that we might have an empty
// ConfigValueMap on initial boot, if GCComplete is set but GCInitialized is
// not set.
func handleGlobalConfigSync(ctxArg interface{}, done bool) {

	ctx := ctxArg.(*domainContext)
	log.Functionf("handleGlobalConfigSync %t", done)
	if done {
		ctx.GCComplete = true
	}
}

// getCloudInitUserData : returns decrypted cloud-init user data
func getCloudInitUserData(ctx *domainContext,
	dc types.DomainConfig) (types.EncryptionBlock, error) {

	if dc.CipherBlockStatus.IsCipher {
		status, decBlock, err := cipher.GetCipherCredentials(&ctx.decryptCipherContext,
			dc.CipherBlockStatus)
		ctx.pubCipherBlockStatus.Publish(status.Key(), status)
		if err != nil {
			log.Errorf("%s, domain config cipherblock decryption unsuccessful, falling back to cleartext: %v",
				dc.Key(), err)
			if dc.CloudInitUserData == nil {
				ctx.cipherMetrics.RecordFailure(log, types.MissingFallback)
				return decBlock, fmt.Errorf("domain config cipherblock decryption unsuccessful (%s); "+
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
			return decBlock, nil
		}
		log.Functionf("%s, domain config cipherblock decryption successful", dc.Key())
		return decBlock, nil
	}
	log.Functionf("%s, domain config cipherblock not present", dc.Key())
	decBlock := types.EncryptionBlock{}
	if dc.CloudInitUserData == nil {
		ctx.cipherMetrics.RecordFailure(log, types.NoCipher)
		return decBlock, nil
	}
	decBlock.ProtectedUserData = *dc.CloudInitUserData
	if decBlock.ProtectedUserData != "" {
		ctx.cipherMetrics.RecordFailure(log, types.NoCipher)
	} else {
		ctx.cipherMetrics.RecordFailure(log, types.NoData)
	}
	return decBlock, nil
}

// fetch the cloud init content
func fetchCloudInit(ctx *domainContext,
	config types.DomainConfig) (string, error) {
	decBlock, err := getCloudInitUserData(ctx, config)
	if err != nil {
		errStr := fmt.Sprintf("%s, cloud-init data get failed %s",
			config.DisplayName, err)
		return "", errors.New(errStr)
	}

	ud, err := base64.StdEncoding.DecodeString(decBlock.ProtectedUserData)
	if err != nil {
		errStr := fmt.Sprintf("%s, base64 decode failed %s",
			config.DisplayName, err)
		return "", errors.New(errStr)
	}
	return string(ud), err
}

// Parse the list of environment variables from the cloud init
// We are expecting the environment variables to be pass in particular format in cloud-int
// Example:
// Key1=Val1
// Key2=Val2 ...
func parseEnvVariablesFromCloudInit(envPairs []string) (map[string]string, error) {
	var envStr string
	for _, v := range envPairs {
		pair := strings.SplitN(v, "=", 2)
		if len(pair) != 2 {
			// We will check syntax errors later
			envStr += v + "\n"
			continue
		}
		// Trim off (i.e., remove leading and trailing) spaces and
		// double quotes, so we allow declarations like "VAR=VALUE"
		key := strings.Trim(pair[0], " \"")
		value := strings.Trim(pair[1], " \"")
		envStr += key + "=\"" + value + "\"\n"
	}

	// Use go-envparse to parse all environment variables and check for
	// syntax errors. Fail if any invalid declaration is found
	envList, err := envp.Parse(bytes.NewReader([]byte(envStr)))
	if err != nil {
		return nil, fmt.Errorf("Error processing environment variables: %s", err)
	}
	return envList, nil
}

func cloudInitISOFileLocation(ctx *domainContext, uuid uuid.UUID) string {
	return fmt.Sprintf("%s/%s.cidata",
		ciDirname, uuid.String())
}

func getCloudInitVersion(config types.DomainConfig) string {
	//
	// `CloudInitVersion` is a proper field for cloud-init config tracking,
	// but this field was introduced long after the cloud-init feature
	// implemented and in order to keep backwards compatibility with old
	// configuration we return `UUIDandVersion.Version` as it was before
	// if `CloudInitVersion` is zeroed (thus does not exist).
	//
	// Why we need a separate version field? According to the spec
	// `UUIDandVersion.Version` is increased for each change of the application
	// config so even an application restart from the controller side leads
	// to the version increase, which in its turn leads to the config-init tool
	// restart on the guest side and this behavior is catastrophic.
	//
	if config.CloudInitVersion > 0 {
		return fmt.Sprintf("%d", config.CloudInitVersion)
	}

	return config.UUIDandVersion.Version
}

// Create a isofs with user-data and meta-data and add it to DiskStatus
// We do this in domainmgr and keep it in /run (and not volumemgr and /persist)
// since it 1) potentially contains confidential info like passwords,
// 2) only needed if we run as a VM, and 3) the data might be changed
// by the controller when reactivating hence
// more short-lived than other volumes/virtual disks.
func createCloudInitISO(ctx *domainContext,
	config types.DomainConfig, ciStr string) (*types.DiskStatus, error) {

	fileName := cloudInitISOFileLocation(ctx, config.UUIDandVersion.UUID)

	dir, err := os.MkdirTemp("", "cloud-init")
	if err != nil {
		log.Fatalf("createCloudInitISO failed %s", err)
	}
	defer os.RemoveAll(dir)

	didMultipart := false
	// If we need to help the guest VM we look for MIME multi-part
	// and use it to lay out the file/directory structure for the ISO
	// image. Even if set, If the content is not multi-part we treat it
	// as normal and fill in a user-data file below.
	if config.MetaDataType == types.MetaDataDriveMultipart ||
		ctx.processCloudInitMultiPart {
		didMultipart, err = handleMimeMultipart(dir, ciStr, true)
		if err != nil {
			return nil, err
		}
	}
	if !didMultipart {
		metafile, err := os.Create(dir + "/meta-data")
		if err != nil {
			log.Fatalf("createCloudInitISO failed %s", err)
		}
		metafile.WriteString(fmt.Sprintf("instance-id: %s/%s\n",
			config.UUIDandVersion.UUID.String(),
			getCloudInitVersion(config)))
		metafile.WriteString(fmt.Sprintf("local-hostname: %s\n",
			config.UUIDandVersion.UUID.String()))
		metafile.Close()

		// Handle normal user-data
		userFileName := "/user-data"
		if strings.Contains(ciStr, "#junos-config") {
			userFileName = "/juniper.conf"
		}
		userfile, err := os.Create(dir + userFileName)
		if err != nil {
			log.Fatalf("createCloudInitISO failed %s", err)
		}
		userfile.WriteString(ciStr)
		userfile.Close()
	}

	if err := mkisofs(fileName, dir); err != nil {
		errStr := fmt.Sprintf("createCloudInitISO failed %s", err)
		return nil, errors.New(errStr)
	}

	ds := new(types.DiskStatus)
	ds.FileLocation = fileName
	ds.Format = zconfig.Format_RAW
	// XXX FIXME the issue with declaring cloud init ISO xvdz is that:
	//   1. we may have more than 26 drives (unlikely)
	//   2. xvdz is only available via PV route
	// Both of these don't seem to be a problem for modern Linux kernels
	// and we can leave it be while we're looking for a more generic solution
	ds.Vdev = "xvdz"
	ds.ReadOnly = true
	// Generate Devtype for hypervisor package
	// XXX can hypervisor look at something different?
	ds.Devtype = "cdrom"
	return ds, nil
}

// deleteCloudInitISO will check if a file exists and if so delete it
func deleteCloudInitISO(ctx *domainContext, status types.DomainStatus) {
	fileName := cloudInitISOFileLocation(ctx, status.UUIDandVersion.UUID)
	if _, err := os.Stat(fileName); err != nil {
		return
	}
	if err := os.RemoveAll(fileName); err != nil {
		log.Error(err)
	}
}

// mkisofs -output %s -volid cidata -joliet -rock %s, fileName, dir
func mkisofs(output string, dir string) error {
	log.Functionf("mkisofs(%s, %s)", output, dir)

	cmd := "mkisofs"
	args := []string{
		"-output",
		output,
		"-volid",
		"cidata",
		"-joliet",
		"-rock",
		dir,
	}
	log.Functionf("Calling command %s %v\n", cmd, args)
	stdoutStderr, err := base.Exec(log, cmd, args...).WithUnlimitedTimeout(15 * time.Minute).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("mkisofs failed: %s",
			string(stdoutStderr))
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Functionf("mkisofs done")
	return nil
}

func handlePhysicalIOAdapterListCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handlePhysicalIOAdapterListImpl(ctxArg, key, configArg)
}

func handlePhysicalIOAdapterListModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handlePhysicalIOAdapterListImpl(ctxArg, key, configArg)
}

func handlePhysicalIOAdapterListImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*domainContext)
	phyIOAdapterList := configArg.(types.PhysicalIOAdapterList)
	aa := ctx.assignableAdapters

	defer func() {
		ctx.publishAssignableAdapters()
		log.Functionf("handlePhysicalIOAdapterListImpl() done len %d",
			len(aa.IoBundleList))
	}()

	log.Functionf("handlePhysicalIOAdapterListImpl: current len %d, update %+v",
		len(aa.IoBundleList), phyIOAdapterList)

	// Is this the initial setup?
	if !aa.Initialized {
		// Setup list first because functions lookup in IoBundleList
		for _, phyAdapter := range phyIOAdapterList.AdapterList {
			ib := types.IoBundleFromPhyAdapter(log, phyAdapter)
			// Fill in PCIlong, macaddr, unique
			_, err := checkAndFillIoBundle(ib)
			if err != nil {
				ib.Error.Append(err)
			} else {
				ib.Error.Clear()
			}
			// We assume AddOrUpdateIoBundle will preserve any
			// existing IsPort/IsPCIBack/UsedByUUID
			aa.AddOrUpdateIoBundle(log, *ib)

			// Adding PF before VF to have correct boot order
			if ib.Type == types.IoNetEthPF && ib.Vfs.Count > 0 {
				exists, ifName := types.PciLongToIfname(log, ib.PciLong)
				if !exists {
					log.Fatal("Failed to resolve ifname for PCI address ", ib.PciLong)
				}

				err = sriov.CreateVF(ifName, ib.Vfs.Count)
				if err != nil {
					log.Fatal("Failed to create VF for iface with PCI address", ib.PciLong)
				}

				vfs, err := sriov.GetVfByTimeout(150*time.Second, ifName, ib.Vfs.Count)
				if err != nil {
					log.Fatal("Failed to get VF for iface ", ifName, " ", err)
				}

				for _, vf := range vfs.Data {
					vfIb, err := createVfIoBundle(*ib, vf)
					if err != nil {
						log.Fatal("createVfIoBundle failed ", err)
					}
					aa.AddOrUpdateIoBundle(log, vfIb)
				}
			} else if ib.Type == types.IoVCAN {
				// Initialize (create and enable) Virtual CAN device
				err := setupVCAN(ib)
				if err != nil {
					err = fmt.Errorf("setupVCAN: %w", err)
					log.Error(err)
					ib.Error.Append(err)
				}
			} else if ib.Type == types.IoCAN {
				// Initialize physical CAN device
				err := setupCAN(ib)
				if err != nil {
					err = fmt.Errorf("setupCAN: %w", err)
					log.Error(err)
					ib.Error.Append(err)
				}
			}
		}
		log.Functionf("handlePhysicalIOAdapterListImpl: initialized to get len %d",
			len(aa.IoBundleList))

		aa.CheckBadUSBBundles()
		// check for mismatched PCI-ids and assignment groups and mark as errors
		aa.CheckBadAssignmentGroups(log, hyper.PCISameController)
		for i := range aa.IoBundleList {
			ib := &aa.IoBundleList[i]
			log.Functionf("handlePhysicalIOAdapterListImpl: new Adapter: %+v",
				ib)
			updatePortAndPciBackIoBundle(ctx, ib)
		}
		aa.Initialized = true
		return
	}

	// Check if any adapters got deleted
	// Loop first then delete to avoid deleting while we iterate
	var deleteList []string
	for indx := range aa.IoBundleList {
		phylabel := aa.IoBundleList[indx].Phylabel
		phyAdapter := phyIOAdapterList.LookupAdapter(phylabel)
		if phyAdapter == nil {
			deleteList = append(deleteList, phylabel)
		}
	}
	for _, phylabel := range deleteList {
		handleIBDelete(ctx, phylabel)
	}

	// Any add or modify?
	for _, phyAdapter := range phyIOAdapterList.AdapterList {
		ib := types.IoBundleFromPhyAdapter(log, phyAdapter)
		// Fill in PCIlong, macaddr, unique
		_, err := checkAndFillIoBundle(ib)
		if err != nil {
			ib.Error.Append(err)
		} else {
			ib.Error.Clear()
		}
		currentIbPtr := aa.LookupIoBundlePhylabel(phyAdapter.Phylabel)
		if currentIbPtr == nil || currentIbPtr.HasAdapterChanged(log, phyAdapter) {

			log.Functionf("handlePhysicalIOAdapterListImpl: Adapter %s "+
				"add/modify: %+v", phyAdapter.Phylabel, ib)
			aa.AddOrUpdateIoBundle(log, *ib)

			aa.CheckBadUSBBundles()
			// check for mismatched PCI-ids and assignment groups and mark as errors
			aa.CheckBadAssignmentGroups(log, hyper.PCISameController)
			// Lookup since it could have changed
			ib = aa.LookupIoBundlePhylabel(ib.Phylabel)
			updatePortAndPciBackIoBundle(ctx, ib)
		} else {
			log.Functionf("handlePhysicalIOAdapterListImpl: Adapter %s "+
				"- No Change", phyAdapter.Phylabel)
		}
	}
}

func createVfIoBundle(pfIb types.IoBundle, vf sriov.EthVF) (types.IoBundle, error) {
	vfUserConfig := pfIb.Vfs.GetInfo(vf.Index)
	if vfUserConfig == nil {
		return types.IoBundle{}, fmt.Errorf("Can't find any with index %d", vf.Index)
	}
	vfIb := pfIb
	vfIb.Type = types.IoNetEthVF
	vfIb.Ifname = sriov.GetVfIfaceName(vf.Index, pfIb.Ifname)
	vfIb.Phylabel = sriov.GetVfIfaceName(vf.Index, pfIb.Phylabel)
	vfIb.Logicallabel = sriov.GetVfIfaceName(vf.Index, pfIb.Logicallabel)
	// Don't inherit the parent's AssignmentGroup since VFs will be part of another IOMMU group.
	vfIb.AssignmentGroup = sriov.GetVfIfaceName(vf.Index, pfIb.AssignmentGroup)
	vfIb.PciLong = vf.PciLong
	vfIb.VfParams = types.VfInfo{Index: vf.Index, VlanID: vf.VlanID, PFIface: pfIb.Ifname}
	if vfUserConfig.Mac != "" {
		vfIb.MacAddr = vfUserConfig.Mac
		if err := sriov.SetupVfHardwareAddr(vfIb.Ifname, vfIb.MacAddr, vf.Index); err != nil {
			return types.IoBundle{}, fmt.Errorf("setupVfHardwareAddr failed %s", err)
		}
	}
	if vfUserConfig.VlanID != 0 {
		if err := sriov.SetupVfVlan(vfIb.Ifname, vf.Index, vf.VlanID); err != nil {
			return types.IoBundle{}, fmt.Errorf("setupVfVlan failed %s", err)
		}
	}
	return vfIb, nil
}

func handlePhysicalIOAdapterListDelete(ctxArg interface{},
	key string, value interface{}) {

	phyAdapterList := value.(types.PhysicalIOAdapterList)
	ctx := ctxArg.(*domainContext)
	log.Functionf("handlePhysicalIOAdapterListDelete: ALL PhysicalIoAdapters " +
		"deleted")

	for indx := range phyAdapterList.AdapterList {
		phylabel := phyAdapterList.AdapterList[indx].Phylabel
		log.Functionf("handlePhysicalIOAdapterListDelete: Deleting Adapter %s",
			phylabel)
		handleIBDelete(ctx, phylabel)
	}
	ctx.publishAssignableAdapters()
	log.Functionf("handlePhysicalIOAdapterListDelete done")
}

// updatePortAndPciBackIoBundleAll is used when DeviceNetworkStatus might have changed
// the set of Ports hence we might need to move something in and out of pciback
// Sets ib.Error as appropriately and publishes the results
// XXX do we need to clear ib.Error?
func updatePortAndPciBackIoBundleAll(ctx *domainContext) {
	var anyChanged bool
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		changed := updatePortAndPciBackIoBundle(ctx, ib)
		anyChanged = anyChanged || changed
	}
	if anyChanged {
		ctx.publishAssignableAdapters()
	}

	keepInHostUsbControllers := usbControllersWithoutPCIReserve(ctx.assignableAdapters.IoBundleList)
	for i := range keepInHostUsbControllers {
		for j := range keepInHostUsbControllers[i] {
			keepInHostUsbControllers[i][j].KeepInHost = true
		}
	}
}

// updatePortAndPciBackIoBundle determines whether IsPort should be set for
// the members in this bundle, and based on that whether it needs to be moved
// in or out of pciback
// Sets Error/ErrorTime if there is an error
func updatePortAndPciBackIoBundle(ctx *domainContext, ib *types.IoBundle) (changed bool) {

	log.Functionf("updatePortAndPciBackIoBundle(%d %s %s)",
		ib.Type, ib.Phylabel, ib.AssignmentGroup)
	aa := ctx.assignableAdapters
	var list []*types.IoBundle

	if ib.AssignmentGroup != "" {
		list = aa.LookupIoBundleGroup(ib.AssignmentGroup)
	} else {
		list = append(list, ib)
	}

	keepInHostUsbControllers := usbControllersWithoutPCIReserve(ctx.assignableAdapters.IoBundleList)

	// Is any member a network port?
	// We look across all members in the assignment group (expanded below
	// for safety when the model is incorrect) and if any member is a port
	// providing network connectivity (therefore needed to be kept in the host),
	// we set it for all the members.
	isPort := false
	// Keep device in the host?
	// Note that without isPort enabled assignments still take precedence.
	keepInHost := false
	// expand list to include other PCI functions on the same PCI controller
	// since they need to be treated as part of the same bundle even if the
	// EVE controller doesn't know it
	list = aa.ExpandControllers(log, list, hyper.PCISameController)
	for _, ib := range list {
		if types.IsPort(ctx.deviceNetworkStatus, ib.Ifname) {
			isPort = true
			keepInHost = true
		}
		if ib.Type == types.IoNetWLAN || ib.Type == types.IoNetWWAN {
			// Do not put unused wireless devices (unassigned and not associated with any network) into pciback,
			// instead let EVE to properly un-configure them (e.g. turn off radio transmission).
			// But note that IO assignments take precedence and if any member of the same group
			// is assigned to an application, EVE will not be able to manage the state of the wireless device.
			keepInHost = true
		}
		if ctx.usbAccess && (ib.Type == types.IoUSB || ib.Type == types.IoUSBController) {
			keepInHost = true
		}
		if ctx.vgaAccess && ib.Type == types.IoHDMI {
			// only return VGA devices that were marked as boot devices.
			// console output won't be visible on others anyway
			// it allows us to debug issues with GPUs assigned to applications
			if keep, err := types.PCIIsBootVga(log, ib.PciLong); err == nil {
				keepInHost = keep
			} else {
				log.Errorf("Couldn't get boot_vga statues for VGA device %s", ib.PciLong)
				log.Error(err)
			}
		}
		if ib.Type == types.IoNVME && zfsutil.NVMEIsUsed(log, ctx.subZFSPoolStatus.GetAll(), ib.PciLong) {
			keepInHost = true
		}
		if ib.Type == types.IoNetEthPF {
			keepInHost = true
		}
		if ib.Type == types.IoCAN || ib.Type == types.IoVCAN {
			keepInHost = true
		}
		_, found := keepInHostUsbControllers[ib.PciLong]
		if found {
			keepInHost = true
		}
	}

	log.Functionf("updatePortAndPciBackIoBundle(%d %s %s) isPort %t keepInHost %t members %d",
		ib.Type, ib.Phylabel, ib.AssignmentGroup, isPort, keepInHost, len(list))
	anyChanged := false
	for _, ib := range list {
		if ib.UsbAddr != "" || ib.UsbProduct != "" {
			// this is usb device forwarding, so usbmanager cares for not passing through network devices
			continue
		}
		changed, err := updatePortAndPciBackIoMember(ctx, ib, isPort, keepInHost)
		anyChanged = anyChanged || changed
		if err != nil {
			ib.Error.Append(err)
			log.Error(err)
		} else {
			ib.Error.Clear()
		}
	}
	return anyChanged
}

// updatePortAndPciBackIoMember moves device in or out of pciback and updates IsPort and KeepInHost.
// Side note: IsPort=true implies KeepInHost=true.
// XXX move all members and once and fall back on failure?
func updatePortAndPciBackIoMember(ctx *domainContext, ib *types.IoBundle, isPort, keepInHost bool) (changed bool, err error) {

	log.Functionf("updatePortAndPciBackIoMember(%d %s %s) isPort %t keepInHost %t",
		ib.Type, ib.Phylabel, ib.AssignmentGroup, isPort, keepInHost)
	if ib.KeepInHost != keepInHost {
		ib.KeepInHost = keepInHost
		changed = true
	}
	if ib.IsPort != isPort {
		ib.IsPort = isPort
		changed = true
		log.Warnf("updatePortAndPciBackIoMember(%d, %s, %s): EVE port",
			ib.Type, ib.Phylabel, ib.AssignmentGroup)
		if ib.UsedByUUID != nilUUID {
			err = fmt.Errorf("adapter %s (group %s, type %d) is used by %s; can not be used as EVE port",
				ib.Phylabel, ib.AssignmentGroup, ib.Type,
				ib.UsedByUUID.String())
			return changed, err
		}
	}
	if changed && ib.KeepInHost && ib.UsedByUUID == nilUUID && ib.IsPCIBack {
		log.Functionf("updatePortAndPciBackIoMember(%d, %s, %s) take back from pciback",
			ib.Type, ib.Phylabel, ib.AssignmentGroup)
		if ib.PciLong != "" {
			log.Functionf("updatePortAndPciBackIoMember: Removing %s (%s) from pciback",
				ib.Phylabel, ib.PciLong)
			err = hyper.PCIRelease(ib.PciLong)
			if err != nil {
				err = fmt.Errorf("adapter %s (group %s, type %d) PCI ID %s; not released by hypervisor: %v",
					ib.Phylabel, ib.AssignmentGroup, ib.Type,
					ib.PciLong, err)
				return changed, err
			}
			if ib.IsPort {
				// Seems like like no risk for race; when we return
				// from above the driver has been attached and
				// any ifname has been registered.
				found, ifname := types.PciLongToIfname(log, ib.PciLong)
				if !found {
					err = fmt.Errorf("adapter %s (group %s type %d) PCI ID %s not found after released by hypervisor",
						ib.Phylabel, ib.AssignmentGroup, ib.Type,
						ib.PciLong)
					return changed, err
				}
				if ifname != ib.Ifname {
					log.Warnf("Found: %d %s %s at %s",
						ib.Type, ib.Phylabel, ib.Ifname,
						ifname)
					types.IfRename(log, ifname, ib.Ifname)
				}
			}
		}
		ib.IsPCIBack = false
		// Verify that it has been returned from pciback
		_, err = types.IoBundleToPci(log, ib)
		if err != nil || ib.UsbAddr != "" {
			err = fmt.Errorf("adapter %s (group %s type %d) PCI ID %s not found: %v",
				ib.Phylabel, ib.AssignmentGroup, ib.Type,
				ib.PciLong, err)
			return changed, err
		}
	}

	if !ib.KeepInHost && !ib.IsPCIBack {
		if !ib.Error.Empty() {
			log.Warningf("Not assigning %s (%s) to pciback due to error: %s at %s",
				ib.Phylabel, ib.PciLong, ib.Error.String(), ib.Error.ErrorTime())
		} else if ctx.deviceNetworkStatus.Testing && ib.Type.IsNet() {
			log.Noticef("Not assigning %s (%s) to pciback due to Testing",
				ib.Phylabel, ib.PciLong)
		} else if ib.PciLong != "" && ib.UsbAddr == "" {
			log.Noticef("Assigning %s (%s) to pciback",
				ib.Phylabel, ib.PciLong)
			err := hyper.PCIReserve(ib.PciLong)
			if err != nil {
				return changed, err
			}
			ib.IsPCIBack = true
			changed = true
		}
	}
	return changed, nil
}

// checkAndFillIoBundle checks if PCI devices exists, and extracts information like PciLong
// (if not set) MacAddr, and Unique
// Returns changed bool and error for non-existent devices
func checkAndFillIoBundle(ib *types.IoBundle) (bool, error) {

	log.Functionf("checkAndFillIoBundle(%d %s %s)", ib.Type, ib.Phylabel, ib.AssignmentGroup)
	changed := false
	if ib.Type.IsNet() && ib.MacAddr == "" {
		ib.MacAddr = getMacAddr(ib.Ifname)
		changed = true
		log.Functionf("checkAndFillIoBundle(%d %s %s) found macaddr %s",
			ib.Type, ib.Ifname, ib.AssignmentGroup, ib.MacAddr)
	}

	// For a new PCI device we check if it exists in hardware/kernel
	long, err := types.IoBundleToPci(log, ib)
	if err != nil {
		log.Error(err)
		return changed, err
	}
	if long == "" {
		return changed, nil
	}
	// This is a PCI device
	ib.PciLong = long
	changed = true
	log.Functionf("checkAndFillIoBundle(%d %s %s) found long %s",
		ib.Type, ib.Phylabel, ib.AssignmentGroup, long)

	// Save somewhat Unique string for debug
	found, unique := types.PciLongToUnique(log, long)
	if !found {
		errStr := fmt.Sprintf("checkAndFillIoBundleIoBundle(%d %s %s) %s unique not found",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, long)
		log.Warn(errStr)
	} else {
		ib.Unique = unique
		changed = true
		log.Functionf("checkAndFillIoBundle(%d %s %s) %s found unique %s",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, long, unique)
	}
	return changed, nil
}

func getMacAddr(ifname string) string {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		log.Errorf("Can't find ifname %s", ifname)
		return ""
	}
	if link.Attrs().HardwareAddr == nil {
		return ""
	}
	return link.Attrs().HardwareAddr.String()
}

// Check if anything moved around and log warning
func checkIoBundleAll(ctx *domainContext) {
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		err := checkIoBundle(ctx, ib)
		if err != nil {
			log.Warnf("checkIoBundleAll failed for %d: %s", i, err)
		}
	}
}

// Check if the name to pci-id or Mac Address has changed. Indication of confusion.
// We track a mostly unique string to see if the underlying firmware node has
// changed in addition to the name to pci-id lookup.
func checkIoBundle(ctx *domainContext, ib *types.IoBundle) error {

	if ib.Type.IsNet() && ib.MacAddr != "" {
		macAddr := getMacAddr(ib.Phylabel)
		// Will be empty string if adapter is assigned away
		if macAddr != "" && macAddr != ib.MacAddr {
			errStr := fmt.Sprintf("IoBundle(%d %s %s) changed MacAddr from %s to %s",
				ib.Type, ib.Phylabel, ib.AssignmentGroup,
				ib.MacAddr, macAddr)
			return errors.New(errStr)
		}
	}
	long, err := types.IoBundleToPci(log, ib)
	if err != nil {
		// Disappeared or different PCI ID?
		return err
	}
	if long == "" {
		// Not PCI
		return nil
	}
	found, unique := types.PciLongToUnique(log, long)
	if !found {
		errStr := fmt.Sprintf("IoBundle(%d %s %s) %s unique %s not found",
			ib.Type, ib.Phylabel, ib.AssignmentGroup,
			long, ib.Unique)
		log.Warn(errStr)
	} else if unique != ib.Unique && ib.Unique != "" {
		errStr := fmt.Sprintf("IoBundle(%d %s %s) changed unique from %s to %s",
			ib.Type, ib.Phylabel, ib.AssignmentGroup,
			ib.Unique, unique)
		return errors.New(errStr)
	}
	return nil
}

// Move the USB controllers to/from pciback based on usbAccess
// Also enable/disable usbhid and related mouse/keyboard based on that
// XXX should we have a separate knob for HID and for usb-storage?
func updateUsbAccess(ctx *domainContext) {

	log.Functionf("updateUsbAccess(%t)", ctx.usbAccess)
	if !ctx.usbAccess {
		removeUSBfromKernel()
	} else {
		addUSBtoKernel()
	}
	updatePortAndPciBackIoBundleAll(ctx)
	checkIoBundleAll(ctx)
}

func updateVgaAccess(ctx *domainContext) {

	log.Functionf("updateVgaAccess(%t)", ctx.usbAccess)
	// TODO: we might need some extra work here for some VGA devices
	// that do not enable output upon HDMI cable attachment
	updatePortAndPciBackIoBundleAll(ctx)
	checkIoBundleAll(ctx)
}

func updateConsoleAccess(ctx *domainContext) {
	log.Functionf("updateConsoleAccess(%t)", ctx.consoleAccess)
	// FIXME: explore the way to stop getty/login
	if ctx.consoleAccess {
		startGetty(log)
	}
}

// Track which ones of these are loaded
// loaded starts off as TS_NONE at boot since we don't know the state
// in the kernel.
type loadedDriver struct {
	driverName string
	loaded     types.TriState
}

var usbDrivers = []loadedDriver{
	{"usbhid", types.TS_NONE},
	{"usbkbd", types.TS_NONE},
	{"usbmouse", types.TS_NONE},
	{"usb_storage", types.TS_NONE},
}

// Enable the above drivers; record which ones loaded
func addUSBtoKernel() {

	log.Functionf("addUSBtoKernel()")
	for i := range usbDrivers {
		drv := &usbDrivers[i]
		if drv.loaded == types.TS_ENABLED {
			log.Errorf("drober %s already loaded",
				drv.driverName)
			continue
		}
		if err := doModprobe(drv.driverName, true); err != nil {
			log.Errorf("modprobe failed to add %s: %s",
				drv.driverName, err)
			drv.loaded = types.TS_DISABLED
		} else {
			drv.loaded = types.TS_ENABLED
		}
	}
}

// Disable usbhid etc
func removeUSBfromKernel() bool {

	log.Functionf("removeUSBfromKernel()")
	ret := true
	for i := range usbDrivers {
		drv := &usbDrivers[i]
		if drv.loaded == types.TS_DISABLED {
			log.Functionf("driver %s not loaded; no unload",
				drv.driverName)
			continue
		}
		if err := doModprobe(drv.driverName, false); err != nil {
			log.Errorf("modprobe failed to remove %s: %s",
				drv.driverName, err)
			ret = false
		} else {
			drv.loaded = types.TS_DISABLED
		}
	}
	return ret
}

// Initialize (create and enable) Virtual CAN device
func setupVCAN(ib *types.IoBundle) error {
	vcan, err := canbus.AddVCANLink(ib.Ifname)
	if err != nil {
		return err
	}
	err = canbus.LinkSetUp(vcan)
	if err != nil {
		return err
	}
	return nil
}

// Initialize physical CAN device
func setupCAN(ib *types.IoBundle) error {
	canIf, err := canbus.GetCANLink(ib.Ifname)
	if err != nil {
		return err
	}
	err = canbus.SetupCAN(canIf, ib.Cbattr)
	if err != nil {
		return err
	}
	err = canbus.LinkSetUp(canIf)
	if err != nil {
		return err
	}
	return nil
}

func doModprobe(driver string, add bool) error {
	cmd := "modprobe"
	args := []string{}
	if !add {
		args = append(args, "-r")
	}
	args = append(args, driver)
	log.Functionf("Calling command %s %v\n", cmd, args)
	stdoutStderr, err := base.Exec(log, cmd, args...).CombinedOutput()
	if err != nil {
		log.Error(err)
		log.Errorf("modprobe output: %s", stdoutStderr)
		return err
	}
	return nil
}

func handleIBDelete(ctx *domainContext, phylabel string) {

	log.Noticef("handleIBDelete(%s) len %d", phylabel,
		len(ctx.assignableAdapters.IoBundleList))
	aa := ctx.assignableAdapters

	ib := aa.LookupIoBundlePhylabel(phylabel)
	if ib == nil {
		log.Functionf("handleIBDelete: Adapter ( %s ) not found", phylabel)
		return
	}

	if ib.IsPCIBack {
		log.Functionf("handleIBDelete: Assigning %s (%s) back",
			ib.Phylabel, ib.PciLong)
		if ib.PciLong != "" {
			err := hyper.PCIRelease(ib.PciLong)
			if err != nil {
				log.Errorf("handleIBDelete(%d %s %s) PCIRelease %s failed %v",
					ib.Type, ib.Phylabel, ib.AssignmentGroup, ib.PciLong, err)
			}
			ib.IsPCIBack = false
		}
	}
	// Create a new list with everything but "ib" included
	replace := types.AssignableAdapters{Initialized: true,
		IoBundleList: make([]types.IoBundle, 0, len(aa.IoBundleList)-1)}
	for _, e := range aa.IoBundleList {
		if e.Type == ib.Type && e.Phylabel == ib.Phylabel {
			continue
		}
		replace.IoBundleList = append(replace.IoBundleList, e)
	}
	*ctx.assignableAdapters = replace
	log.Noticef("handleIBDelete(%s) done len %d", phylabel,
		len(ctx.assignableAdapters.IoBundleList))
	checkIoBundleAll(ctx)
}

func getAndPublishCapabilities(ctx *domainContext, hyper hypervisor.Hypervisor) error {
	capabilities, err := hyper.GetCapabilities()
	if err != nil {
		return fmt.Errorf("cannot get capabilities: %v", err)
	}
	return ctx.pubCapabilities.Publish("global", *capabilities)
}

func lookupCapabilities(ctx *domainContext) (*types.Capabilities, error) {
	c, err := ctx.pubCapabilities.Get("global")
	if err != nil {
		return nil, fmt.Errorf("cannot lookup capabilities: %w", err)
	}
	capabilities, ok := c.(types.Capabilities)
	if !ok {
		log.Fatalf("Unexpected type from pubCapabilities: %T", c)
	}
	return &capabilities, nil
}
