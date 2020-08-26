// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package domainmgr

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eriknordmark/netlink"
	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/sema"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName  = "domainmgr"
	runDirname = "/var/run/" + agentName
	xenDirname = runDirname + "/xen"       // We store xen cfg files here
	ciDirname  = runDirname + "/cloudinit" // For cloud-init images
	// Time limits for event loop handlers
	errorTime           = 3 * time.Minute
	warningTime         = 40 * time.Second
	containerRootfsPath = "rootfs/"
	casClientType       = "containerd"
)

// Really a constant
var nilUUID = uuid.UUID{}

// Set from Makefile
var Version = "No version specified"

func isPort(ctx *domainContext, ifname string) bool {
	ctx.dnsLock.Lock()
	defer ctx.dnsLock.Unlock()
	return types.IsPort(ctx.deviceNetworkStatus, ifname)
}

// Information for handleCreate/Modify/Delete
type domainContext struct {
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
	subOnboardStatus       pubsub.Subscription
	pubAssignableAdapters  pubsub.Publication
	pubDomainMetric        pubsub.Publication
	pubHostMemory          pubsub.Publication
	pubCipherBlockStatus   pubsub.Publication
	usbAccess              bool
	createSema             *sema.Semaphore
	onboarded              bool
	GCComplete             bool
	setInitialUsbAccess    bool
	GCInitialized          bool
	domainBootRetryTime    uint32 // In seconds
	metricInterval         uint32 // In seconds

	// Common CAS client which can be used by multiple routines.
	// There is no shared data so its safe to be used by multiple goroutines
	casClient cas.CAS
}

func (ctx *domainContext) publishAssignableAdapters() {
	log.Infof("Publishing %v", *ctx.assignableAdapters)
	ctx.pubAssignableAdapters.Publish("global", *ctx.assignableAdapters)
}

var debug = false
var debugOverride bool          // From command line arg
var hyper hypervisor.Hypervisor // Current hypervisor
var log *base.LogObject

func Run(ps *pubsub.PubSub) int {
	var err error
	handlersInit()
	allHypervisors, enabledHypervisors := hypervisor.GetAvailableHypervisors()
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	hypervisorPtr := flag.String("h", enabledHypervisors[0], fmt.Sprintf("Current hypervisor %+q", allHypervisors))
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

	hyper, err = hypervisor.GetHypervisor(*hypervisorPtr)
	if err != nil {
		log.Fatal(err)
	}

	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s with %s hypervisor backend", agentName, hyper.Name())

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Publish metrics for zedagent every 10 seconds
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	if _, err := os.Stat(runDirname); err != nil {
		log.Debugf("Create %s", runDirname)
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

	// These settings can be overridden by GlobalConfig
	// Note that if this device has never connected to the controller
	// usbAccess is set to true. Once it connects it will get the default
	// from the controller which is likely to be false. That is persisted
	// hence will be overridden in handleGlobalConfig below.
	// This helps onboarding new hardware by making keyboard etc available
	domainCtx := domainContext{
		ps:                  ps,
		usbAccess:           true,
		domainBootRetryTime: 600,
	}
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
		TopicType: types.CipherMetricsMap{},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for controller certs which will be used for decryption
	subControllerCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
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
	domainCtx.decryptCipherContext.SubControllerCert = subControllerCert
	subControllerCert.Activate()

	// Look for edge node certs which will be used for decryption
	subEdgeNodeCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		TopicImpl:   types.EdgeNodeCert{},
		Activate:    false,
		Ctx:         &domainCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.decryptCipherContext.SubEdgeNodeCert = subEdgeNodeCert
	subEdgeNodeCert.Activate()

	// Look for cipher context which will be used for decryption
	subCipherContext, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		TopicImpl:   types.CipherContext{},
		Activate:    false,
		Ctx:         &domainCtx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.decryptCipherContext.SubCipherContext = subCipherContext
	subCipherContext.Activate()

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "",
			TopicImpl:     types.ConfigItemValueMap{},
			Activate:      false,
			Ctx:           &domainCtx,
			CreateHandler: handleGlobalConfigModify,
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

	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		CreateHandler: handleOnboardStatusModify,
		ModifyHandler: handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      true,
		Persistent:    true,
		Ctx:           &domainCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.subOnboardStatus = subOnboardStatus

	subDeviceNetworkStatus, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "nim",
			TopicImpl:     types.DeviceNetworkStatus{},
			Activate:      false,
			Ctx:           &domainCtx,
			CreateHandler: handleDNSModify,
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

	if domainCtx.casClient, err = cas.NewCAS(casClientType); err != nil {
		err = fmt.Errorf("Run: exception while initializing CAS client: %s", err.Error())
		log.Fatal(err)
	}

	//casClient which is commonly used across volumemgr will be closed when volumemgr exits.
	defer domainCtx.casClient.CloseClient()

	// Parse any existing ConfigIntemValueMap but continue if there
	// is none
	for !domainCtx.GCComplete {
		log.Infof("waiting for GCComplete")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GCComplete")

	if !domainCtx.setInitialUsbAccess {
		log.Infof("GCComplete but not setInitialUsbAccess => first boot")
		// Enable USB keyboard and storage
		domainCtx.usbAccess = true
		updateUsbAccess(&domainCtx)
		domainCtx.setInitialUsbAccess = true
	}

	// Pick up debug aka log level before we start real work
	for !domainCtx.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

	// Wait until we have been onboarded aka know our own UUID
	for !domainCtx.onboarded {
		log.Infof("Waiting for onboarded")
		select {
		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case <-stillRunning.C:

		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed onboarded")

	log.Infof("Creating %s at %s", "metricsTimerTask", agentlog.GetMyStack())
	go metricsTimerTask(&domainCtx, hyper)

	// Wait for DeviceNetworkStatus to be init so we know the management
	// ports and then wait for assignableAdapters.
	for !domainCtx.DNSinitialized {

		log.Infof("Waiting for DeviceNetworkStatus init")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}

	// Subscribe to PhysicalIOAdapterList from zedagent
	subPhysicalIOAdapter, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "zedagent",
			TopicImpl:     types.PhysicalIOAdapterList{},
			Activate:      false,
			Ctx:           &domainCtx,
			CreateHandler: handlePhysicalIOAdapterListCreateModify,
			ModifyHandler: handlePhysicalIOAdapterListCreateModify,
			DeleteHandler: handlePhysicalIOAdapterListDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.subPhysicalIOAdapter = subPhysicalIOAdapter
	subPhysicalIOAdapter.Activate()

	// Wait for PhysicalIOAdapters to be initialized.
	for !domainCtx.assignableAdapters.Initialized {
		log.Infof("Waiting for AssignableAdapters")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subPhysicalIOAdapter.MsgChan():
			subPhysicalIOAdapter.ProcessChange(change)

		// Run stillRunning since we waiting for zedagent to deliver
		// PhysicalIO which depends on cloud connectivity
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("Have %d assignable adapters", len(aa.IoBundleList))

	// Subscribe to DomainConfig from zedmanager
	subDomainConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:      "zedmanager",
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

		case change := <-subCipherContext.MsgChan():
			subCipherContext.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDomainConfig.MsgChan():
			subDomainConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subPhysicalIOAdapter.MsgChan():
			subPhysicalIOAdapter.ProcessChange(change)

		case <-publishTimer.C:
			start := time.Now()
			err = cipherMetricsPub.Publish("global", cipher.GetCipherMetrics())
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

func handleRestart(ctxArg interface{}, done bool) {
	log.Infof("handleRestart(%v)", done)
	ctx := ctxArg.(*domainContext)
	if done {
		log.Infof("handleRestart: avoid cleanup")
		ctx.pubDomainStatus.SignalRestarted()
		return
	}
}

func publishDomainStatus(ctx *domainContext, status *types.DomainStatus) {

	key := status.Key()
	log.Debugf("publishDomainStatus(%s)", key)
	pub := ctx.pubDomainStatus
	pub.Publish(key, *status)
}

func unpublishDomainStatus(ctx *domainContext, status *types.DomainStatus) {

	key := status.Key()
	log.Debugf("unpublishDomainStatus(%s)", key)
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
	log.Debugf("publishCipherBlockStatus(%s)", key)
	pub := ctx.pubCipherBlockStatus
	pub.Publish(key, status)
}

func unpublishCipherBlockStatus(ctx *domainContext, key string) {
	if ctx == nil || len(key) == 0 {
		return
	}
	log.Debugf("unpublishCipherBlockStatus(%s)", key)
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

// We have one goroutine per provisioned domU object.
// Channel is used to send notifications about config (add and updates)
// Channel is closed when the object is deleted
// The go-routine owns writing status for the object
// The key in the map is the objects Key() - UUID in this case
type handlers map[string]chan<- Notify

var handlerMap handlers

func handlersInit() {
	handlerMap = make(handlers)
}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func handleDomainModify(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("handleDomainModify(%s)", key)
	config := configArg.(types.DomainConfig)
	h, ok := handlerMap[config.Key()]
	if !ok {
		log.Fatalf("handleDomainModify called on config that does not exist")
	}
	select {
	case h <- Notify{}:
		log.Infof("handleDomainModify(%s) sent notify", key)
	default:
		// handler is slow
		log.Warnf("handleDomainModify(%s) NOT sent notify. Slow handler?", key)
	}
}

func handleDomainCreate(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("handleDomainCreate(%s)", key)
	ctx := ctxArg.(*domainContext)
	config := configArg.(types.DomainConfig)
	h, ok := handlerMap[config.Key()]
	if ok {
		log.Fatalf("handleDomainCreate called on config that already exists")
	}
	h1 := make(chan Notify, 1)
	handlerMap[config.Key()] = h1
	log.Infof("Creating %s at %s", "runHandler", agentlog.GetMyStack())
	go runHandler(ctx, key, h1)
	h = h1
	select {
	case h <- Notify{}:
		log.Infof("handleDomainCreate(%s) sent notify", key)
	default:
		// Shouldn't happen since we just created channel
		log.Fatalf("handleDomainCreate(%s) NOT sent notify", key)
	}
}

func handleDomainDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleDomainDelete(%s)", key)
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
		log.Infof("Closing channel")
		close(h)
		delete(handlerMap, key)
	} else {
		log.Debugf("handleDomainDelete: unknown %s", key)
		return
	}
	log.Infof("handleDomainDelete(%s) done", key)
}

// Server for each domU
// Runs timer every 30 seconds to update status
func runHandler(ctx *domainContext, key string, c <-chan Notify) {

	log.Infof("runHandler starting")

	interval := 30 * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	closed := false
	for !closed {
		select {
		case _, ok := <-c:
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
		case <-ticker.C:
			log.Debugf("runHandler(%s) timer", key)
			status := lookupDomainStatus(ctx, key)
			if status != nil {
				verifyStatus(ctx, status)
				maybeRetry(ctx, status)
			}
		}
	}
	log.Infof("runHandler(%s) DONE", key)
}

// Check if it is still running
func verifyStatus(ctx *domainContext, status *types.DomainStatus) {
	// Check config.Active to avoid spurious errors when shutting down
	configActivate := false
	config := lookupDomainConfig(ctx, status.Key())
	if config != nil && config.Activate {
		configActivate = true
	}

	domainID, domainStatus, err := hyper.Task(status).Info(status.DomainName, status.DomainId)
	if err != nil || domainStatus == types.HALTED {
		if status.Activated && configActivate {
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
				if err := hyper.Task(status).Delete(status.DomainName, status.DomainId); err != nil {
					log.Errorf("failed to delete domain: %s (%v)", status.DomainName, err)
				}
			}
		}
		status.DomainId = 0
		publishDomainStatus(ctx, status)
	} else {
		if !status.Activated && domainStatus == types.RUNNING {
			log.Warnf("verifyDomain(%s) domain came back alive; id  %d",
				status.Key(), domainID)
			status.ClearError()
			status.DomainId = domainID
			status.BootTime = time.Now()
			log.Infof("Update domainId %d bootTime %s for %s",
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
			log.Infof("Update domainId %d bootTime %s for %s",
				status.DomainId, status.BootTime.Format(time.RFC3339Nano),
				status.Key())
			publishDomainStatus(ctx, status)
		}
	}
}

func maybeRetry(ctx *domainContext, status *types.DomainStatus) {

	maybeRetryBoot(ctx, status)
	maybeRetryAdapters(ctx, status)
}

// Retry a boot after a failure.
func maybeRetryBoot(ctx *domainContext, status *types.DomainStatus) {

	if !status.BootFailed {
		return
	}
	if status.Activated && status.BootFailed {
		log.Infof("maybeRetryBoot(%s) clearing bootFailed since Activated",
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
		log.Infof("maybeRetryBoot(%s) %d remaining",
			status.Key(),
			(timeLimit-elapsed)/time.Second)
		return
	}
	log.Infof("maybeRetryBoot(%s) after %s at %v",
		status.Key(), status.Error, status.ErrorTime)

	status.ClearError()
	status.TriedCount += 1

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
	log.Infof("maybeRetryBoot(%s) DONE for %s",
		status.Key(), status.DisplayName)
}

// Retry assigning adapters after a failure.
func maybeRetryAdapters(ctx *domainContext, status *types.DomainStatus) {

	if !status.AdaptersFailed {
		return
	}
	if status.Activated && status.AdaptersFailed {
		log.Infof("maybeRetryAdapters(%s) clearing adaptersFailed since Activated",
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
	log.Infof("maybeRetryAdapters(%s) after %s at %v",
		status.Key(), status.Error, status.ErrorTime)

	if err := configAdapters(ctx, *config); err != nil {
		log.Errorf("Failed to reserve adapters for %s: %s",
			config.Key(), err)
		status.PendingAdd = false
		status.SetErrorNow(err.Error())
		status.AdaptersFailed = true
		publishDomainStatus(ctx, status)
		cleanupAdapters(ctx, config.IoAdapterList,
			config.UUIDandVersion.UUID)
		return
	}
	status.AdaptersFailed = false
	status.ClearError()

	// We now have reserved all of the IoAdapters
	status.IoAdapterList = config.IoAdapterList

	// Write any Location so that it can later be deleted based on status
	publishDomainStatus(ctx, status)
	if config.Activate {
		doActivate(ctx, *config, status)
	}
	// work done
	publishDomainStatus(ctx, status)
	log.Infof("maybeRetryAdapters(%s) DONE for %s",
		status.Key(), status.DisplayName)
}

// Callers must be careful to publish any changes to DomainStatus
func lookupDomainStatus(ctx *domainContext, key string) *types.DomainStatus {

	pub := ctx.pubDomainStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupDomainStatus(%s) not found", key)
		return nil
	}
	status := st.(types.DomainStatus)
	return &status
}

func lookupDomainConfig(ctx *domainContext, key string) *types.DomainConfig {

	sub := ctx.subDomainConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupDomainConfig(%s) not found", key)
		return nil
	}
	config := c.(types.DomainConfig)
	return &config
}

func handleCreate(ctx *domainContext, key string, config *types.DomainConfig) {

	log.Infof("handleCreate(%v) for %s",
		config.UUIDandVersion, config.DisplayName)
	log.Debugf("DomainConfig %+v", config)
	// Name of Xen domain must be unique; uniqify AppNum
	name := config.DisplayName + "." + strconv.Itoa(config.AppNum)

	// Start by marking with PendingAdd
	status := types.DomainStatus{
		UUIDandVersion:     config.UUIDandVersion,
		PendingAdd:         true,
		DisplayName:        config.DisplayName,
		DomainName:         name,
		AppNum:             config.AppNum,
		VifList:            config.VifList,
		VirtualizationMode: config.VirtualizationModeOrDefault(),
		EnableVnc:          config.EnableVnc,
		VncDisplay:         config.VncDisplay,
		VncPasswd:          config.VncPasswd,
		State:              types.INSTALLED,
		IsContainer:        config.IsContainer,
	}
	// Note that the -emu interface doesn't exist until after boot of the domU, but we
	// initialize the VifList here with the VifUsed.
	status.VifList = checkIfEmu(status.VifList)

	status.DiskStatusList = make([]types.DiskStatus,
		len(config.DiskConfigList))
	publishDomainStatus(ctx, &status)
	log.Infof("handleCreate(%v) set domainName %s for %s",
		config.UUIDandVersion, status.DomainName,
		config.DisplayName)

	if err := configToStatus(ctx, *config, &status); err != nil {
		log.Errorf("Failed to create DomainStatus from %v: %s",
			config, err)
		status.PendingAdd = false
		status.SetErrorNow(err.Error())
		publishDomainStatus(ctx, &status)
		return
	}

	if err := configAdapters(ctx, *config); err != nil {
		log.Errorf("Failed to reserve adapters for %v: %s",
			config, err)
		status.PendingAdd = false
		status.SetErrorNow(err.Error())
		status.AdaptersFailed = true
		publishDomainStatus(ctx, &status)
		cleanupAdapters(ctx, config.IoAdapterList,
			config.UUIDandVersion.UUID)
		return
	}

	status.AdaptersFailed = false
	// We now have reserved all of the IoAdapters
	status.IoAdapterList = config.IoAdapterList

	// Write any Location so that it can later be deleted based on status
	publishDomainStatus(ctx, &status)

	if config.Activate {
		doActivate(ctx, *config, &status)
	}
	// work done
	status.PendingAdd = false
	publishDomainStatus(ctx, &status)
	log.Infof("handleCreate(%v) DONE for %s",
		config.UUIDandVersion, config.DisplayName)
}

// XXX clear the UUID assignment; leave in pciback
func cleanupAdapters(ctx *domainContext, ioAdapterList []types.IoAdapter,
	myUuid uuid.UUID) {

	publishAssignableAdapters := false
	// Look for any adapters used by us and clear UsedByUUID
	for _, adapter := range ioAdapterList {
		log.Debugf("cleanupAdapters processing adapter %d %s",
			adapter.Type, adapter.Name)
		list := ctx.assignableAdapters.LookupIoBundleAny(adapter.Name)
		if len(list) == 0 {
			continue
		}
		for _, ib := range list {
			if ib.UsedByUUID != myUuid {
				continue
			}
			log.Infof("cleanupAdapters clearing uuid for adapter %d %s member %s",
				adapter.Type, adapter.Name, ib.Phylabel)
			ib.UsedByUUID = nilUUID
			publishAssignableAdapters = true
		}
	}
	if publishAssignableAdapters {
		ctx.publishAssignableAdapters()
	}
}

// XXX only for USB when usbAccess is set; really assign to pciback then separately
// assign to domain
func doAssignIoAdaptersToDomain(ctx *domainContext, config types.DomainConfig,
	status *types.DomainStatus) {

	publishAssignableAdapters := false
	var assignments []string
	for _, adapter := range config.IoAdapterList {
		log.Debugf("doAssignIoAdaptersToDomain processing adapter %d %s",
			adapter.Type, adapter.Name)

		aa := ctx.assignableAdapters
		list := aa.LookupIoBundleAny(adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if len(list) == 0 {
			log.Fatalf("doAssignIoAdaptersToDomain IoBundle disappeared %d %s for %s",
				adapter.Type, adapter.Name, status.DomainName)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				log.Fatalf("doAssignIoAdaptersToDomain IoBundle stolen by %s: %d %s for %s",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					status.DomainName)
			}
			if isPort(ctx, ib.Ifname) {
				log.Fatalf("doAssignIoAdaptersToDomain IoBundle stolen by zedrouter: %d %s for %s",
					adapter.Type, adapter.Name,
					status.DomainName)
			}
			if !isInUsbGroup(*aa, *ib) {
				continue
			}
			if ib.PciLong == "" {
				log.Warnf("doAssignIoAdaptersToDomain missing PciLong: %d %s for %s",
					adapter.Type, adapter.Name, status.DomainName)
			} else if ctx.usbAccess && !ib.IsPCIBack {
				log.Infof("Assigning %s (%s) to %s",
					ib.Phylabel, ib.PciLong, status.DomainName)
				assignments = addNoDuplicate(assignments, ib.PciLong)
				ib.IsPCIBack = true
				publishAssignableAdapters = true
			}
		}
	}
	for i, long := range assignments {
		err := hyper.PCIReserve(long)
		if err != nil {
			// Undo what we assigned
			for j, long := range assignments {
				if j >= i {
					break
				}
				hyper.PCIRelease(long)
			}
			status.SetErrorNow(err.Error())
			return
		}
	}
	checkIoBundleAll(ctx)
	if publishAssignableAdapters {
		ctx.publishAssignableAdapters()
	}
}

func doActivate(ctx *domainContext, config types.DomainConfig,
	status *types.DomainStatus) {

	log.Infof("doActivate(%v) for %s",
		config.UUIDandVersion, config.DisplayName)
	if status.AdaptersFailed || status.PendingModify {
		if err := configAdapters(ctx, config); err != nil {
			log.Errorf("Failed to reserve adapters for %v: %s",
				config, err)
			status.PendingAdd = false
			status.SetErrorNow(err.Error())
			status.AdaptersFailed = true
			publishDomainStatus(ctx, status)
			cleanupAdapters(ctx, config.IoAdapterList,
				config.UUIDandVersion.UUID)
			return
		}

		status.AdaptersFailed = false
		// We now have reserved all of the IoAdapters
		status.IoAdapterList = config.IoAdapterList
	}

	if status.IsContainer && (config.IsCipher || config.CloudInitUserData != nil) {
		envList, err := fetchEnvVariablesFromCloudInit(ctx, config)
		if err != nil {
			fetchError := fmt.Errorf("failed to fetch environment variable from userdata. %s", err.Error())
			log.Error(fetchError)
			status.SetErrorNow(fetchError.Error())
			return
		}
		status.EnvVariables = envList
	}

	// Assign any I/O devices
	doAssignIoAdaptersToDomain(ctx, config, status)

	// Finish preparing for container runtime.
	for _, ds := range status.DiskStatusList {
		if ds.Format != zconfig.Format_CONTAINER {
			continue
		}

		snapshotID := containerd.GetSnapshotID(ds.FileLocation)
		if err := ctx.casClient.MountSnapshot(snapshotID, getRoofFsPath(ds.FileLocation)); err != nil {
			err := fmt.Errorf("doActivate: Failed mount snapshot: %s for %s. Error %s",
				snapshotID, config.UUIDandVersion.UUID, err)
			log.Error(err.Error())
			status.SetErrorNow(err.Error())
			return
		}

		// XXX apparently this is under the appInstID and not under
		// the ImageID aka VolumeID
		if err := containerd.PrepareMount(config.UUIDandVersion.UUID,
			ds.FileLocation, status.EnvVariables,
			len(status.DiskStatusList)); err != nil {

			log.Errorf("Failed to create ctr bundle. Error %s", err)
			status.SetErrorNow(err.Error())
			return
		}
	}

	filename := xenCfgFilename(config.AppNum)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal("os.Create for ", filename, err)
	}
	defer file.Close()

	if err := hyper.Task(status).Setup(*status, config, ctx.assignableAdapters, file); err != nil {
		log.Errorf("Failed to create DomainStatus from %v: %s",
			config, err)
		status.SetErrorNow(err.Error())
		return
	}

	status.TriedCount = 0
	var domainID int
	// Invoke domain create; try 3 times with a timeout
	for {
		status.TriedCount += 1
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
			publishDomainStatus(ctx, status)
			return
		}
		log.Warnf("Retry domain create for %s: failed %s",
			status.DomainName, err)
		publishDomainStatus(ctx, status)
		time.Sleep(5 * time.Second)
	}
	status.BootFailed = false
	doActivateTail(ctx, status, domainID)
}

func doActivateTail(ctx *domainContext, status *types.DomainStatus,
	domainID int) {

	log.Infof("created domainID %d for %s", domainID, status.DomainName)
	status.DomainId = domainID
	status.BootTime = time.Now()
	log.Infof("Set domainId %d bootTime %s for %s",
		status.DomainId, status.BootTime.Format(time.RFC3339Nano),
		status.Key())
	status.State = types.BOOTING
	publishDomainStatus(ctx, status)

	err := hyper.Task(status).Start(status.DomainName, domainID)
	if err != nil {
		// XXX shouldn't we destroy it?
		log.Errorf("domain start for %s: %s", status.DomainName, err)
		status.SetErrorNow(err.Error())
		// XXX set BootFailed to cause retry
		status.BootFailed = true
		status.State = types.BROKEN
		return
	}
	// The -emu interfaces were most likely created as result of the boot so we
	// update VifUsed here.
	status.VifList = checkIfEmu(status.VifList)

	status.State = types.RUNNING
	domainID, state, err := hyper.Task(status).Info(status.DomainName, status.DomainId)

	// XXX key missing piece to avoid setting Activated below
	if err != nil {
		status.BootFailed = true
		status.State = state
		status.Activated = false
		status.SetErrorNow(err.Error())
		log.Infof("doActivateTail(%v) failed for %s: %s",
			status.UUIDandVersion, status.DisplayName, err)
		return
	}
	if err == nil && domainID != status.DomainId {
		status.DomainId = domainID
		status.BootTime = time.Now()
		log.Infof("Update domainId %d bootTime %s for %s",
			status.DomainId, status.BootTime.Format(time.RFC3339Nano),
			status.Key())
	}
	status.Activated = true
	log.Infof("doActivateTail(%v) done for %s",
		status.UUIDandVersion, status.DisplayName)
}

// shutdown and wait for the domain to go away; if that fails destroy and wait
func doInactivate(ctx *domainContext, status *types.DomainStatus, impatient bool) {

	log.Infof("doInactivate(%v) for %s",
		status.UUIDandVersion, status.DisplayName)
	domainID, _, err := hyper.Task(status).Info(status.DomainName, status.DomainId)
	if err == nil && domainID != status.DomainId {
		status.DomainId = domainID
		status.BootTime = time.Now()
		log.Infof("Update domainId %d bootTime %s for %s",
			status.DomainId, status.BootTime.Format(time.RFC3339Nano),
			status.Key())
	}
	// If this is a delete of the App Instance we wait for a shorter time
	// since all of the read-write disk images will be deleted.
	// A container only has a read-only image hence it can also be
	// torn down with less waiting.
	if status.IsContainer {
		impatient = true
	}
	maxDelay := time.Second * 600 // 10 minutes
	if impatient {
		maxDelay /= 10
	}
	if status.DomainId != 0 {
		status.State = types.HALTING
		publishDomainStatus(ctx, status)

		switch status.VirtualizationMode {
		case types.HVM, types.FML:
			// Do a short shutdown wait, then a shutdown -F
			// just in case there are PV tools in guest
			shortDelay := time.Second * 60
			if impatient {
				shortDelay /= 10
			}
			if err := DomainShutdown(*status, false); err != nil {
				log.Errorf("DomainShutdown %s failed: %s",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Infof("doInactivate(%v) for %s: waiting for domain to shutdown",
					status.UUIDandVersion, status.DisplayName)
			}
			gone := waitForDomainGone(*status, shortDelay)
			if gone {
				status.DomainId = 0
				break
			}
			if err := DomainShutdown(*status, true); err != nil {
				log.Errorf("DomainShutdown -F %s failed: %s",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Infof("doInactivate(%v) for %s: waiting for domain to poweroff",
					status.UUIDandVersion, status.DisplayName)
			}
			gone = waitForDomainGone(*status, maxDelay)
			if gone {
				status.DomainId = 0
				break
			}

		case types.PV:
			if err := DomainShutdown(*status, false); err != nil {
				log.Errorf("DomainShutdown %s failed: %s",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Infof("doInactivate(%v) for %s: waiting for domain to shutdown",
					status.UUIDandVersion, status.DisplayName)
			}
			gone := waitForDomainGone(*status, maxDelay)
			if gone {
				status.DomainId = 0
				break
			}
			if err := DomainShutdown(*status, true); err != nil {
				log.Errorf("DomainShutdown -F %s failed: %s",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Infof("doInactivate(%v) for %s: waiting for domain to poweroff",
					status.UUIDandVersion, status.DisplayName)
			}
			gone = waitForDomainGone(*status, maxDelay)
			if gone {
				status.DomainId = 0
				break
			}
		}
	}

	// Incase of ctr based container, DomainShutdown moves the
	// container to exit state and the domain is destroyed
	// Issue Domain Destroy irrespective in container case
	if status.IsContainer || status.DomainId != 0 {
		if err := hyper.Task(status).Delete(status.DomainName, status.DomainId); err != nil {
			log.Errorf("Failed to delete domain %s (%v)", status.DomainName, err)
		}
		// Even if destroy failed we wait again
		log.Infof("doInactivate(%v) for %s: waiting for domain to be destroyed",
			status.UUIDandVersion, status.DisplayName)

		gone := waitForDomainGone(*status, maxDelay)
		if gone {
			status.DomainId = 0
		}
	}
	// If everything failed we leave it marked as Activated
	if status.DomainId != 0 {
		errStr := fmt.Sprintf("doInactivate(%s) failed to halt/destroy %d",
			status.Key(), status.DomainId)
		log.Error(errStr)
		status.SetErrorNow(errStr)
	} else {
		status.Activated = false
		status.State = types.HALTED
	}
	publishDomainStatus(ctx, status)

	pciUnassign(ctx, status, false)

	log.Infof("doInactivate(%v) done for %s",
		status.UUIDandVersion, status.DisplayName)
}

// XXX currently only unassigns USB if usbAccess is set
func pciUnassign(ctx *domainContext, status *types.DomainStatus,
	ignoreErrors bool) {

	log.Infof("pciUnassign(%v, %v) for %s",
		status.UUIDandVersion, ignoreErrors, status.DisplayName)

	// Unassign any pci devices but keep UsedByUUID set and keep in status
	var assignments []string
	for _, adapter := range status.IoAdapterList {
		log.Debugf("doInactivate processing adapter %d %s",
			adapter.Type, adapter.Name)
		aa := ctx.assignableAdapters
		list := aa.LookupIoBundleAny(adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if len(list) == 0 {
			log.Fatalf("doInactivate IoBundle disappeared %d %s for %s",
				adapter.Type, adapter.Name, status.DomainName)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			if ib.UsedByUUID != status.UUIDandVersion.UUID {
				log.Infof("doInactivate IoBundle not ours by %s: %d %s for %s",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					status.DomainName)
				continue
			}
			// XXX also unassign others and assign during Activate?
			if !isInUsbGroup(*aa, *ib) {
				continue
			}
			if ib.PciLong == "" {
				log.Warnf("doInactivate lookup missing: %d %s for %s",
					adapter.Type, adapter.Name, status.DomainName)
			} else if ctx.usbAccess && ib.IsPCIBack {
				log.Infof("Removing %s (%s) from %s",
					ib.Phylabel, ib.PciLong, status.DomainName)
				assignments = addNoDuplicate(assignments, ib.PciLong)

				ib.IsPCIBack = false
			}
			ib.UsedByUUID = nilUUID // XXX see comment above. Clear if usbAccess only?
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

	log.Infof("configToStatus(%v) for %s",
		config.UUIDandVersion, config.DisplayName)
	numOfContainerDisks := 0
	for i, dc := range config.DiskConfigList {
		if dc.Format == zconfig.Format_CONTAINER {
			numOfContainerDisks++
		}
		ds := &status.DiskStatusList[i]
		ds.ReadOnly = dc.ReadOnly
		ds.FileLocation = dc.FileLocation
		ds.Format = dc.Format
		ds.MountDir = dc.MountDir
		ds.DisplayName = dc.DisplayName
		// Generate Devtype for hypervisor package
		// XXX can hypervisor look at something different?
		if dc.Format == zconfig.Format_CONTAINER {
			ds.Devtype = "container"
		} else {
			ds.Devtype = "hdd"
		}
		var xv string
		if status.IsContainer {
			// map from i=1 to xvdb, 2 to xvdc etc
			// For container instances xvda will be used for container disk
			// So for other disks we are starting from xvdb
			// Currently, we are not supporting multiple container disks inside a pod
			xv = "xvd" + string(int('b')+i)
		} else {
			// map from i=1 to xvda, 2 to xvdb etc
			xv = "xvd" + string(int('a')+i)
		}
		ds.Vdev = xv
	}
	if numOfContainerDisks > 1 {
		err := `Bundle contains more than one container disk, running multiple containers
				inside a pod is not supported now.`
		log.Errorf(err)
		return fmt.Errorf(err)
	}
	// XXX could defer to Activate
	if config.IsCipher || config.CloudInitUserData != nil {
		if !status.IsContainer {
			ds, err := createCloudInitISO(ctx, config)
			if err != nil {
				return err
			}
			if ds != nil {
				status.DiskStatusList = append(status.DiskStatusList,
					*ds)
			}
		}
	}
	return nil
}

// Check and reserve any assigned adapters
// XXX rename to reserveAdapters?
func configAdapters(ctx *domainContext, config types.DomainConfig) error {

	log.Infof("configAdapters(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	defer ctx.publishAssignableAdapters()

	for _, adapter := range config.IoAdapterList {
		log.Debugf("configAdapters processing adapter %d %s",
			adapter.Type, adapter.Name)
		// Lookup to make sure adapter exists on this device
		list := ctx.assignableAdapters.LookupIoBundleAny(adapter.Name)
		if len(list) == 0 {
			return fmt.Errorf("unknown adapter %d %s",
				adapter.Type, adapter.Name)
		}

		for _, ibp := range list {
			if ibp == nil {
				continue
			}
			if ibp.UsedByUUID != nilUUID {
				return fmt.Errorf("adapter %d %s used by %s",
					adapter.Type, adapter.Name, ibp.UsedByUUID)
			}
			if isPort(ctx, ibp.Ifname) {
				return fmt.Errorf("adapter %d %s member %s is (part of) a zedrouter port",
					adapter.Type, adapter.Name, ibp.Phylabel)
			}
		}
		for _, ibp := range list {
			if ibp == nil {
				continue
			}
			log.Debugf("configAdapters setting uuid %s for adapter %d %s member %s",
				config.Key(), adapter.Type, adapter.Name, ibp.Phylabel)
			ibp.UsedByUUID = config.UUIDandVersion.UUID
		}
	}
	return nil
}

// checkDiskFormat will check the disk corruption and format mismatch
// by comparing the output from 'qemu-img info' and the format passed
// in object in config
func checkDiskFormat(diskStatus types.DiskStatus) error {
	imgInfo, err := diskmetrics.GetImgInfo(diskStatus.FileLocation)
	if err != nil {
		return err
	}
	if imgInfo.Format != strings.ToLower(diskStatus.Format.String()) {
		return fmt.Errorf("Disk format mismatch, format in config %v and output of qemu-img %v\n"+
			"Note: Format mismatch may be because of disk corruption also.",
			diskStatus.Format, imgInfo.Format)
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

	log.Infof("handleModify(%v) activate %t for %s",
		config.UUIDandVersion, config.Activate, config.DisplayName)

	status.PendingModify = true
	publishDomainStatus(ctx, status)

	changed := false
	if config.Activate && !status.Activated {
		log.Infof("handleModify(%v) activating for %s",
			config.UUIDandVersion, config.DisplayName)
		// AppNum could have changed if we did not already Activate
		name := config.DisplayName + "." + strconv.Itoa(config.AppNum)
		if status.DomainName != name {
			status.DomainName = name
			status.AppNum = config.AppNum
			log.Infof("handleModify(%v) set domainName %s for %s",
				config.UUIDandVersion, status.DomainName,
				config.DisplayName)
		}
		status.VifList = checkIfEmu(config.VifList)
		publishDomainStatus(ctx, status)

		// This has the effect of trying a boot again for any
		// handleModify after an error.
		if status.HasError() {
			log.Infof("handleModify(%v) ignoring existing error for %s",
				config.UUIDandVersion, config.DisplayName)
			status.ClearError()
			publishDomainStatus(ctx, status)
			doInactivate(ctx, status, false)
		}
		// Update disks based on any change to volumes
		if err := configToStatus(ctx, *config, status); err != nil {
			log.Errorf("Failed to update DomainStatus from %v: %s",
				config, err)
			status.PendingModify = false
			status.SetErrorNow(err.Error())
			publishDomainStatus(ctx, status)
			return
		}
		updateStatusFromConfig(status, *config)
		doActivate(ctx, *config, status)
		changed = true
	} else if !config.Activate {
		log.Infof("handleModify(%v) NOT activating for %s",
			config.UUIDandVersion, config.DisplayName)
		if status.HasError() {
			log.Infof("handleModify(%v) clearing existing error for %s",
				config.UUIDandVersion, config.DisplayName)
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
		log.Infof("handleModify(%v) DONE for %s",
			config.UUIDandVersion, config.DisplayName)
		return
	}

	// XXX check if we have status.HasError() and delete and retry
	// even if same version. XXX won't the above Activate/Activated checks
	// result in redoing things? Could have failures during copy i.e.
	// before activation.

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Infof("Same version %s for %s",
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
	log.Infof("handleModify(%v) DONE for %s",
		config.UUIDandVersion, config.DisplayName)
}

func updateStatusFromConfig(status *types.DomainStatus, config types.DomainConfig) {
	status.VirtualizationMode = config.VirtualizationModeOrDefault()
	status.EnableVnc = config.EnableVnc
	status.VncDisplay = config.VncDisplay
	status.VncPasswd = config.VncPasswd
}

// If we have a -emu named interface we assume it is being used
func checkIfEmu(vifList []types.VifInfo) []types.VifInfo {
	var retList []types.VifInfo

	for _, net := range vifList {
		net.VifUsed = net.Vif
		emuIfname := net.Vif + "-emu"
		_, err := netlink.LinkByName(emuIfname)
		if err == nil && net.VifUsed != emuIfname {
			log.Infof("Found EMU %s and update %s", emuIfname, net.VifUsed)
			net.VifUsed = emuIfname
		}
		retList = append(retList, net)
	}
	return retList
}

// Used to wait both after shutdown and destroy
func waitForDomainGone(status types.DomainStatus, maxDelay time.Duration) bool {
	gone := false
	delay := time.Second
	var waited time.Duration
	for {
		log.Infof("waitForDomainGone(%v) for %s: waiting for %v",
			status.UUIDandVersion, status.DisplayName, delay)
		if delay != 0 {
			time.Sleep(delay)
			waited += delay
		}
		_, state, err := hyper.Task(&status).Info(status.DomainName, status.DomainId)
		if err != nil || state == types.HALTED {
			log.Infof("waitForDomainGone(%v) for %s: domain is gone",
				status.UUIDandVersion, status.DisplayName)
			gone = true
			break
		} else {
			if waited > maxDelay {
				// Give up
				log.Warnf("waitForDomainGone(%v) for %s: giving up",
					status.UUIDandVersion, status.DisplayName)
				break
			}
			delay = 2 * delay
			if delay > time.Minute {
				delay = time.Minute
			}
		}
	}
	return gone
}

func handleDelete(ctx *domainContext, key string, status *types.DomainStatus) {

	log.Infof("handleDelete(%v) for %s",
		status.UUIDandVersion, status.DisplayName)

	status.PendingDelete = true
	publishDomainStatus(ctx, status)

	if status.Activated {
		doInactivate(ctx, status, true)
	} else {
		pciUnassign(ctx, status, true)
	}

	// Look for any adapters used by us and clear UsedByUUID
	// XXX zedagent might assume that the setting to nil arrives before
	// the delete of the DomainStatus. Check
	cleanupAdapters(ctx, status.IoAdapterList, status.UUIDandVersion.UUID)

	publishDomainStatus(ctx, status)

	// Check if the USB controller became available for dom0
	updateUsbAccess(ctx)

	// Delete xen cfg file for good measure
	filename := xenCfgFilename(status.AppNum)
	if err := os.Remove(filename); err != nil {
		log.Errorln(err)
	}

	status.PendingDelete = false
	publishDomainStatus(ctx, status)
	// Write out what we modified to DomainStatus aka delete
	unpublishDomainStatus(ctx, status)
	log.Infof("handleDelete(%v) DONE for %s",
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
	log.Infof("DomainCreate %s ... xenCfgFilename - %s", status.DomainName, filename)
	for _, ds := range status.DiskStatusList {
		if ds.Format != zconfig.Format_CONTAINER {
			err := checkDiskFormat(ds)
			if err != nil {
				log.Errorf("%v", err)
				return domainID, err
			}
		}
	}

	// Now create a domain
	log.Infof("Creating domain with the config - %s", filename)
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
	log.Infof("DomainShutdown force-%v %s %d", force, status.DomainName, status.DomainId)

	// Stop the domain
	log.Infof("Stopping domain - %s", status.DomainName)
	err = hyper.Task(&status).Stop(status.DomainName, status.DomainId, force)

	return err
}

// Handles both create and modify events
func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s", key)
		return
	}
	// Ignore test status and timestamps
	// Compare Testing to save its updated value which is used by us
	if ctx.deviceNetworkStatus.Equal(status) &&
		ctx.deviceNetworkStatus.Testing == status.Testing {
		log.Infof("handleDNSModify unchanged")
		ctx.DNSinitialized = true
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(ctx.deviceNetworkStatus, status))
	// Even if Testing is set we look at it for pciback transitions to
	// bring things out of pciback (but not to add to pciback)
	ctx.deviceNetworkStatus = status
	checkAndSetIoBundleAll(ctx)
	ctx.DNSinitialized = true
	log.Infof("handleDNSModify done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s", key)
		return
	}
	log.Infof("handleDNSDelete for %s", key)
	ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	ctx.DNSinitialized = false
	checkAndSetIoBundleAll(ctx)
	log.Infof("handleDNSDelete done for %s", key)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
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
		if gcp.GlobalValueInt(types.MetricInterval) != 0 {
			ctx.metricInterval = gcp.GlobalValueInt(types.MetricInterval)
		}
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s. "+
		"DomainBootRetryTime: %d, usbAccess: %t, metricInterval: %d",
		key, ctx.domainBootRetryTime, ctx.usbAccess,
		ctx.metricInterval)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s", key)
}

// This gets called once the GlobalConfig subscription/directory has been
// completely processed. Thus will signal that we might have an empty
// ConfigValueMap on initial boot, if GCComplete is set but GCInitialized is
// not set.
func handleGlobalConfigSync(ctxArg interface{}, done bool) {

	ctx := ctxArg.(*domainContext)
	log.Infof("handleGlobalConfigSync %t", done)
	if done {
		ctx.GCComplete = true
	}
}

// getCloudInitUserData : returns decrypted cloud-init user data
func getCloudInitUserData(ctx *domainContext,
	dc types.DomainConfig) (types.EncryptionBlock, error) {
	if dc.CipherBlockStatus.IsCipher {
		status, decBlock, err := cipher.GetCipherCredentials(&ctx.decryptCipherContext,
			agentName, dc.CipherBlockStatus)
		ctx.pubCipherBlockStatus.Publish(status.Key(), status)
		if err != nil {
			log.Errorf("%s, domain config cipherblock decryption unsuccessful, falling back to cleartext: %v",
				dc.Key(), err)
			decBlock.ProtectedUserData = *dc.CloudInitUserData
			// We assume IsCipher is only set when there was some
			// data. Hence this is a fallback if there is
			// some cleartext.
			if decBlock.ProtectedUserData != "" {
				cipher.RecordFailure(agentName,
					types.CleartextFallback)
			} else {
				cipher.RecordFailure(agentName,
					types.MissingFallback)
			}
			return decBlock, nil
		}
		log.Infof("%s, domain config cipherblock decryption successful", dc.Key())
		return decBlock, nil
	}
	log.Infof("%s, domain config cipherblock not present", dc.Key())
	decBlock := types.EncryptionBlock{}
	decBlock.ProtectedUserData = *dc.CloudInitUserData
	if decBlock.ProtectedUserData != "" {
		cipher.RecordFailure(agentName, types.NoCipher)
	} else {
		cipher.RecordFailure(agentName, types.NoData)
	}
	return decBlock, nil
}

// Fetch the list of environment variables from the cloud init
// We are expecting the environment variables to be pass in particular format in cloud-int
// Example:
// Key1:Val1
// Key2:Val2 ...
func fetchEnvVariablesFromCloudInit(ctx *domainContext,
	config types.DomainConfig) (map[string]string, error) {
	decBlock, err := getCloudInitUserData(ctx, config)
	if err != nil {
		errStr := fmt.Sprintf("%s, cloud-init data get failed %s",
			config.DisplayName, err)
		return nil, errors.New(errStr)
	}

	ud, err := base64.StdEncoding.DecodeString(decBlock.ProtectedUserData)
	if err != nil {
		errStr := fmt.Sprintf("fetchEnvVariablesFromCloudInit failed %s", err)
		return nil, errors.New(errStr)
	}
	envList := make(map[string]string, 0)
	list := strings.Split(string(ud), "\n")
	for _, v := range list {
		pair := strings.SplitN(v, "=", 2)
		if len(pair) != 2 {
			errStr := fmt.Sprintf("Variable \"%s\" not defined properly\nKey value pair should be delimited by \"=\"", pair[0])
			return nil, errors.New(errStr)
		}
		envList[pair[0]] = pair[1]
	}

	return envList, nil
}

// Create a isofs with user-data and meta-data and add it to DiskStatus
// XXX this should move to volumemgr
func createCloudInitISO(ctx *domainContext,
	config types.DomainConfig) (*types.DiskStatus, error) {

	fileName := fmt.Sprintf("%s/%s.cidata",
		ciDirname, config.UUIDandVersion.UUID.String())

	dir, err := ioutil.TempDir("", "cloud-init")
	if err != nil {
		log.Fatalf("createCloudInitISO failed %s", err)
	}
	defer os.RemoveAll(dir)

	metafile, err := os.Create(dir + "/meta-data")
	if err != nil {
		log.Fatalf("createCloudInitISO failed %s", err)
	}
	metafile.WriteString(fmt.Sprintf("instance-id: %s/%s\n",
		config.UUIDandVersion.UUID.String(),
		config.UUIDandVersion.Version))
	metafile.WriteString(fmt.Sprintf("local-hostname: %s\n",
		config.UUIDandVersion.UUID.String()))
	metafile.Close()

	userfile, err := os.Create(dir + "/user-data")
	if err != nil {
		log.Fatalf("createCloudInitISO failed %s", err)
	}

	decBlock, err := getCloudInitUserData(ctx, config)
	if err != nil {
		return nil, err
	}
	ud, err := base64.StdEncoding.DecodeString(decBlock.ProtectedUserData)
	if err != nil {
		errStr := fmt.Sprintf("createCloudInitISO failed %s", err)
		return nil, errors.New(errStr)
	}
	userfile.WriteString(string(ud))
	userfile.Close()

	if err := mkisofs(fileName, dir); err != nil {
		errStr := fmt.Sprintf("createCloudInitISO failed %s", err)
		return nil, errors.New(errStr)
	}

	ds := new(types.DiskStatus)
	ds.FileLocation = fileName
	ds.Format = zconfig.Format_RAW
	switch runtime.GOARCH {
	case "arm64":
		ds.Vdev = "xvdz"
		ds.ReadOnly = true
	case "amd64":
		ds.Vdev = "hdc:cdrom"
		ds.ReadOnly = false
	}
	// Generate Devtype for hypervisor package
	// XXX can hypervisor look at something different?
	ds.Devtype = "cdrom"
	return ds, nil
}

// mkisofs -output %s -volid cidata -joliet -rock %s, fileName, dir
func mkisofs(output string, dir string) error {
	log.Infof("mkisofs(%s, %s)", output, dir)

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
	log.Infof("Calling command %s %v\n", cmd, args)
	stdoutStderr, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("mkisofs failed: %s",
			string(stdoutStderr))
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Infof("mkisofs done")
	return nil
}

func handlePhysicalIOAdapterListCreateModify(ctxArg interface{},
	key string, configArg interface{}) {

	ctx := ctxArg.(*domainContext)
	phyIOAdapterList := configArg.(types.PhysicalIOAdapterList)
	aa := ctx.assignableAdapters
	log.Infof("handlePhysicalIOAdapterListCreateModify: current len %d, update %+v",
		len(aa.IoBundleList), phyIOAdapterList)

	if !aa.Initialized {
		// Setup list first because functions lookup in IoBundleList
		for _, phyAdapter := range phyIOAdapterList.AdapterList {
			ib := *types.IoBundleFromPhyAdapter(log, phyAdapter)
			// We assume AddOrUpdateIoBundle will preserve any
			// existing IsPort/IsPCIBack/UsedByUUID
			aa.AddOrUpdateIoBundle(log, ib)
		}
		// Now initialize each entry
		for _, ib := range aa.IoBundleList {
			log.Infof("handlePhysicalIOAdapterListCreateModify: new Adapter: %+v",
				ib)
			handleIBCreate(ctx, ib)
		}
		log.Infof("handlePhysicalIOAdapterListCreateModify: initialized to get len %d",
			len(aa.IoBundleList))
		aa.Initialized = true
		ctx.publishAssignableAdapters()
		log.Infof("handlePhysicalIOAdapterListCreateModify() done len %d",
			len(aa.IoBundleList))
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
		ib := *types.IoBundleFromPhyAdapter(log, phyAdapter)
		currentIbPtr := aa.LookupIoBundlePhylabel(phyAdapter.Phylabel)
		if currentIbPtr == nil {
			log.Infof("handlePhysicalIOAdapterListCreateModify: Adapter %s "+
				"added. %+v", phyAdapter.Phylabel, ib)
			handleIBCreate(ctx, ib)
		} else if currentIbPtr.HasAdapterChanged(log, phyAdapter) {
			log.Infof("handlePhysicalIOAdapterListCreateModify: Adapter %s "+
				"changed. Current: %+v, New: %+v", phyAdapter.Phylabel,
				*currentIbPtr, ib)
			handleIBModify(ctx, ib)
		} else {
			log.Infof("handlePhysicalIOAdapterListCreateModify: Adapter %s "+
				"- No Change", phyAdapter.Phylabel)
		}
	}
	ctx.publishAssignableAdapters()
	log.Infof("handlePhysicalIOAdapterListCreateModify() done len %d",
		len(aa.IoBundleList))
}

func handlePhysicalIOAdapterListDelete(ctxArg interface{},
	key string, value interface{}) {

	phyAdapterList := value.(types.PhysicalIOAdapterList)
	ctx := ctxArg.(*domainContext)
	log.Infof("handlePhysicalIOAdapterListDelete: ALL PhysicalIoAdapters " +
		"deleted")

	for indx := range phyAdapterList.AdapterList {
		phylabel := phyAdapterList.AdapterList[indx].Phylabel
		log.Infof("handlePhysicalIOAdapterListDelete: Deleting Adapter %s",
			phylabel)
		handleIBDelete(ctx, phylabel)
	}
	ctx.publishAssignableAdapters()
	log.Infof("handlePhysicalIOAdapterListDelete done")
}

// Process new IoBundles. Check if PCI device exists, and check that not
// used in a DevicePortConfig/DeviceNetworkStatus
// Assign to pciback
func handleIBCreate(ctx *domainContext, ib types.IoBundle) {

	log.Infof("handleIBCreate(%d %s %s)", ib.Type, ib.Phylabel, ib.AssignmentGroup)
	aa := ctx.assignableAdapters
	if err := checkAndSetIoBundle(ctx, &ib, false); err != nil {
		log.Warnf("Not reporting non-existent PCI device %d %s: %v",
			ib.Type, ib.Phylabel, err)
		return
	}
	// We assume AddOrUpdateIoBundle will preserve any existing Unique/MacAddr
	aa.AddOrUpdateIoBundle(log, ib)
}

func checkAndSetIoBundleAll(ctx *domainContext) {
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		err := checkAndSetIoBundle(ctx, ib, true)
		if err != nil {
			log.Errorf("checkAndSetIoBundleAll failed for %d: %s",
				i, err)
		}
	}
}

func checkAndSetIoBundle(ctx *domainContext, ib *types.IoBundle,
	publish bool) error {

	log.Infof("checkAndSetIoBundle(%d %s %s) publish %t",
		ib.Type, ib.Phylabel, ib.AssignmentGroup, publish)
	aa := ctx.assignableAdapters
	var list []*types.IoBundle

	if ib.AssignmentGroup != "" {
		list = aa.LookupIoBundleGroup(ib.AssignmentGroup)
	} else {
		list = append(list, ib)
	}
	// Is any member a port? If so treat all as port
	isPort := false
	for _, ib := range list {
		if types.IsPort(ctx.deviceNetworkStatus, ib.Ifname) {
			isPort = true
		}
	}
	log.Infof("checkAndSetIoBundle(%d %s %s) isPort %t members %d",
		ib.Type, ib.Phylabel, ib.AssignmentGroup, isPort, len(list))
	for _, ib := range list {
		err := checkAndSetIoMember(ctx, ib, isPort, publish)
		if err != nil {
			log.Error(err)
			return err
		}
	}
	return nil
}

func checkAndSetIoMember(ctx *domainContext, ib *types.IoBundle, isPort bool, publish bool) error {

	log.Infof("checkAndSetIoMember(%d %s %s) isPort %t publish %t",
		ib.Type, ib.Phylabel, ib.AssignmentGroup, isPort, publish)
	aa := ctx.assignableAdapters
	// Check if part of DevicePortConfig
	ib.IsPort = false
	changed := false
	if isPort {
		log.Warnf("checkAndSetIoMember(%d %s %s) part of zedrouter port",
			ib.Type, ib.Phylabel, ib.AssignmentGroup)
		ib.IsPort = true
		changed = true
		if ib.UsedByUUID != nilUUID {
			log.Errorf("checkAndSetIoMember(%d %s %s) used by %s",
				ib.Type, ib.Phylabel, ib.AssignmentGroup,
				ib.UsedByUUID.String())

		} else if ib.IsPCIBack {
			log.Infof("checkAndSetIoMember(%d %s %s) take back from pciback",
				ib.Type, ib.Phylabel, ib.AssignmentGroup)
			if ib.PciLong != "" {
				log.Infof("Removing %s (%s) from pciback",
					ib.Phylabel, ib.PciLong)
				err := hyper.PCIRelease(ib.PciLong)
				if err != nil {
					log.Errorf("checkAndSetIoMember(%d %s %s) PCIRelease %s failed %v",
						ib.Type, ib.Phylabel, ib.AssignmentGroup, ib.PciLong, err)
				}
				// Seems like like no risk for race; when we return
				// from above the driver has been attached and
				// any ifname has been registered.
				found, ifname := types.PciLongToIfname(log, ib.PciLong)
				if !found {
					log.Errorf("Not found: %d %s %s",
						ib.Type, ib.Phylabel, ib.Ifname)
				} else if ifname != ib.Ifname {
					log.Warnf("Found: %d %s %s at %s",
						ib.Type, ib.Phylabel, ib.Ifname,
						ifname)
					types.IfRename(log, ifname, ib.Ifname)
				}
			}
			ib.IsPCIBack = false
			changed = true
			// Verify that it has been returned from pciback
			_, err := types.IoBundleToPci(log, ib)
			if err != nil {
				log.Warnf("checkAndSetIoMember(%d %s %s) gone?: %s",
					ib.Type, ib.Phylabel, ib.AssignmentGroup, err)
			}
		}
	}
	if ib.Type.IsNet() && ib.MacAddr == "" {
		ib.MacAddr = getMacAddr(ib.Ifname)
		changed = true
		log.Infof("checkAndSetIoMember(%d %s %s) long %s macaddr %s",
			ib.Type, ib.Ifname, ib.AssignmentGroup, ib.PciLong, ib.MacAddr)
	}

	if publish && changed {
		ctx.publishAssignableAdapters()
		changed = false
	}

	// For a new PCI device we check if it exists in hardware/kernel
	long, err := types.IoBundleToPci(log, ib)
	if err != nil {
		log.Error(err)
		return err
	}
	if long != "" {
		ib.PciLong = long
		changed = true
		log.Infof("checkAndSetIoMember(%d %s %s) found %s",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, long)

		// Save somewhat Unique string for debug
		found, unique := types.PciLongToUnique(log, long)
		if !found {
			errStr := fmt.Sprintf("IoBundle(%d %s %s) %s unique not found",
				ib.Type, ib.Phylabel, ib.AssignmentGroup, long)
			log.Errorln(errStr)
		} else {
			ib.Unique = unique
			changed = true
			log.Infof("checkAndSetIoMember(%d %s %s) %s unique %s",
				ib.Type, ib.Phylabel, ib.AssignmentGroup, long, unique)
		}
	} else {
		log.Infof("checkAndSetIoMember(%d %s %s) not found PCI",
			ib.Type, ib.Phylabel, ib.AssignmentGroup)
	}

	if !ib.IsPort && !ib.IsPCIBack {
		if ctx.deviceNetworkStatus.Testing && ib.Type.IsNet() {
			log.Infof("Not assigning %s (%s) to pciback due to Testing",
				ib.Phylabel, ib.PciLong)
		} else if ctx.usbAccess && isInUsbGroup(*aa, *ib) {
			log.Infof("Not assigning %s (%s) to pciback due to usbAccess",
				ib.Phylabel, ib.PciLong)
		} else if ib.PciLong != "" {
			log.Infof("Assigning %s (%s) to pciback",
				ib.Phylabel, ib.PciLong)
			err := hyper.PCIReserve(ib.PciLong)
			if err != nil {
				return err
			}
			ib.IsPCIBack = true
			changed = true
		}
	}
	if publish && changed {
		ctx.publishAssignableAdapters()
		changed = false
	}

	return nil
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

// Check if anything moved around
func checkIoBundleAll(ctx *domainContext) {
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		err := checkIoBundle(ctx, ib)
		if err != nil {
			log.Warnf("checkIoBundleAll failed for %d: %s", i, err)
		}
	}
}

// Check if the name to pci-id have changed
// We track a mostly unique string to see if the underlying firmware node has
// changed in addition to the name to pci-id lookup.
func checkIoBundle(ctx *domainContext, ib *types.IoBundle) error {

	long, err := types.IoBundleToPci(log, ib)
	if err != nil {
		return err
	}
	if long == "" {
		// Doesn't exist
		return nil
	}
	found, unique := types.PciLongToUnique(log, long)
	if !found {
		errStr := fmt.Sprintf("IoBundle(%d %s %s) %s unique %s not foun",
			ib.Type, ib.Phylabel, ib.AssignmentGroup,
			long, ib.Unique)
		return errors.New(errStr)
	}
	if unique != ib.Unique && ib.Unique != "" {
		errStr := fmt.Sprintf("IoBundle(%d %s %s) changed unique from %s to %s",
			ib.Type, ib.Phylabel, ib.AssignmentGroup,
			ib.Unique, unique)
		return errors.New(errStr)
	}
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
	return nil
}

// Move the USB controllers to/from pciback based on usbAccess
// Also enable/disable usbhid and related mouse/keyboard based on that
// XXX should we have a separate knob for HID and for usb-storage?
func updateUsbAccess(ctx *domainContext) {

	log.Infof("updateUsbAccess(%t)", ctx.usbAccess)
	if !ctx.usbAccess {
		if removeUSBfromKernel() {
			maybeAssignableAddUSB(ctx)
		}
	} else {
		if maybeAssignableRemUSB(ctx) {
			addUSBtoKernel()
		}
	}
	checkIoBundleAll(ctx)
}

// Try to add all of USB group to pciback
// Returns success/failure
func maybeAssignableAddUSB(ctx *domainContext) bool {

	log.Infof("maybeAssignableAddUSB()")
	var assignments []string
	ret := true
	aa := ctx.assignableAdapters
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		if !isInUsbGroup(*aa, *ib) {
			continue
		}
		if ib.PciLong == "" {
			continue
		}
		if !ib.IsPort && !ib.IsPCIBack {
			log.Infof("maybeAssignableAddUSB: Assigning %s (%s) to pciback",
				ib.Phylabel, ib.PciLong)
			assignments = addNoDuplicate(assignments, ib.PciLong)
			ib.IsPCIBack = true
		}
	}
	for _, long := range assignments {
		err := hyper.PCIReserve(long)
		if err != nil {
			log.Errorf("maybeAssignableAddUSB: add failed: %s", err)
			ret = false
		}
	}
	if len(assignments) != 0 {
		ctx.publishAssignableAdapters()
	}
	return ret
}

// Remove everything in USB group from pciback
// Returns success/failure based on current usage
func maybeAssignableRemUSB(ctx *domainContext) bool {

	log.Infof("maybeAssignableAddUSB()")
	var assignments []string
	ret := true
	aa := ctx.assignableAdapters
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		if !isInUsbGroup(*aa, *ib) {
			continue
		}
		if ib.PciLong == "" {
			continue
		}
		if ib.IsPCIBack {
			if ib.UsedByUUID == nilUUID {
				log.Infof("Removing %s (%s) from pciback",
					ib.Phylabel, ib.PciLong)
				assignments = addNoDuplicate(assignments, ib.PciLong)
				ib.IsPCIBack = false
			} else {
				log.Warnf("No removing %s (%s) from pciback: used by %s",
					ib.Phylabel, ib.PciLong, ib.UsedByUUID)
				ret = false
			}
		}
	}
	for _, long := range assignments {
		err := hyper.PCIRelease(long)
		if err != nil {
			log.Errorf("maybeAssignableRemUSB remove failed: %s", err)
			ret = false
		}
	}
	if len(assignments) != 0 {
		ctx.publishAssignableAdapters()
	}
	return ret
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

	log.Infof("addUSBtoKernel()")
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

	log.Infof("removeUSBfromKernel()")
	ret := true
	for i := range usbDrivers {
		drv := &usbDrivers[i]
		if drv.loaded == types.TS_DISABLED {
			log.Infof("driver %s not loaded; no unload",
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

func doModprobe(driver string, add bool) error {
	cmd := "modprobe"
	args := []string{}
	if !add {
		args = append(args, "-r")
	}
	args = append(args, driver)
	log.Infof("Calling command %s %v\n", cmd, args)
	stdoutStderr, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Error(err)
		log.Errorf("modprobe output: %s", stdoutStderr)
		return err
	}
	return nil
}

func handleIBDelete(ctx *domainContext, phylabel string) {

	log.Infof("handleIBDelete(%s)", phylabel)
	aa := ctx.assignableAdapters

	ib := aa.LookupIoBundlePhylabel(phylabel)
	if ib == nil {
		log.Infof("handleIBDelete: Adapter ( %s ) not found", phylabel)
		return
	}

	if ib.IsPCIBack {
		log.Infof("handleIBDelete: Assigning %s (%s) back",
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
		IoBundleList: make([]types.IoBundle, len(aa.IoBundleList)-1)}
	for _, e := range aa.IoBundleList {
		if e.Type == ib.Type && e.Phylabel == ib.Phylabel {
			continue
		}
		replace.IoBundleList = append(replace.IoBundleList, e)
	}
	*ctx.assignableAdapters = replace
	checkIoBundleAll(ctx)
}

func handleIBModify(ctx *domainContext, newIb types.IoBundle) {
	aa := ctx.assignableAdapters
	currentIbPtr := aa.LookupIoBundlePhylabel(newIb.Phylabel)
	if currentIbPtr == nil {
		log.Errorf("Failed to find IoBundle (%d %s).  aa: %+v",
			newIb.Type, newIb.Phylabel, aa)
		return
	}

	log.Infof("handleIBModify(%d %s %s) from %v to %v",
		currentIbPtr.Type, currentIbPtr.Phylabel, currentIbPtr.AssignmentGroup,
		*currentIbPtr, newIb)

	if err := checkAndSetIoBundle(ctx, &newIb, false); err != nil {
		log.Warnf("Not reporting non-existent PCI device %d %s: %v",
			newIb.Type, newIb.Phylabel, err)
		return
	}

	// XXX can we have changes which require us to
	// do PCIRelease for the old Adapter?
	*currentIbPtr = newIb
	checkIoBundleAll(ctx)
}

// usUnUsbGroup checks if either this member is of type USB, or if it is
// in a group when some member is of type USB
func isInUsbGroup(aa types.AssignableAdapters, ib types.IoBundle) bool {
	if ib.Type == types.IoUSB {
		return true
	}
	if ib.AssignmentGroup == "" {
		return false
	}
	list := aa.LookupIoBundleGroup(ib.AssignmentGroup)
	for _, m := range list {
		if m.Type == types.IoUSB {
			log.Infof("isInUsbGroup for %s found USB for %s",
				ib.Phylabel, m.Phylabel)
			return true
		}
	}
	return false
}

func getRoofFsPath(rootPath string) string {
	return path.Join(rootPath, containerRootfsPath)
}
