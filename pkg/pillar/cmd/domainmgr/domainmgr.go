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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eriknordmark/netlink"
	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/sema"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	agentName    = "domainmgr"
	runDirname   = "/var/run/" + agentName
	xenDirname   = runDirname + "/xen"       // We store xen cfg files here
	ciDirname    = runDirname + "/cloudinit" // For cloud-init images
	rwImgDirname = types.PersistDir + "/img" // We store images here
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
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
	// The isPort function is called by different goroutines
	// hence we serialize the calls on a mutex.
	deviceNetworkStatus    types.DeviceNetworkStatus
	dnsLock                sync.Mutex
	assignableAdapters     *types.AssignableAdapters
	DNSinitialized         bool // Received DeviceNetworkStatus
	subDeviceNetworkStatus pubsub.Subscription
	subPhysicalIOAdapter   pubsub.Subscription
	subDomainConfig        pubsub.Subscription
	pubDomainStatus        pubsub.Publication
	subGlobalConfig        pubsub.Subscription
	pubAssignableAdapters  pubsub.Publication
	pubDomainMetric        pubsub.Publication
	pubHostMemory          pubsub.Publication
	pubCipherBlockStatus   pubsub.Publication
	usbAccess              bool
	createSema             sema.Semaphore
	GCInitialized          bool
	domainBootRetryTime    uint32 // In seconds
	metricInterval         uint32 // In seconds
}

func (ctx *domainContext) publishAssignableAdapters() {
	log.Infof("Publishing %v", *ctx.assignableAdapters)
	ctx.pubAssignableAdapters.Publish("global", *ctx.assignableAdapters)
}

var debug = false
var debugOverride bool          // From command line arg
var hyper hypervisor.Hypervisor // Current hypervisor

func Run(ps *pubsub.PubSub) {
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
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	agentlog.Init(agentName)

	hyper, err = hypervisor.GetHypervisor(*hypervisorPtr)
	if err != nil {
		log.Fatal(err)
	}

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s with %s hypervisor backend\n", agentName, hyper.Name())

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	if _, err := os.Stat(runDirname); err != nil {
		log.Debugf("Create %s\n", runDirname)
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
	if _, err := os.Stat(rwImgDirname); err != nil {
		if err := os.MkdirAll(rwImgDirname, 0700); err != nil {
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
	if _, err := os.Stat(types.AppImgDirname); err != nil {
		if err := os.MkdirAll(types.AppImgDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(types.VerifiedAppImgDirname); err != nil {
		if err := os.MkdirAll(types.VerifiedAppImgDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// These settings can be overridden by GlobalConfig
	domainCtx := domainContext{
		usbAccess:           true,
		domainBootRetryTime: 600,
	}
	aa := types.AssignableAdapters{}
	domainCtx.assignableAdapters = &aa

	// Allow only one concurrent domain create
	domainCtx.createSema = sema.Create(1)
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
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

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

	// Pick up debug aka log level before we start real work
	for !domainCtx.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

	go metricsTimerTask(&domainCtx, hyper)

	// Wait for DeviceNetworkStatus to be init so we know the management
	// ports and then wait for assignableAdapters.
	for !domainCtx.DNSinitialized {

		log.Infof("Waiting for DeviceNetworkStatus init\n")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
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
		agentlog.StillRunning(agentName, warningTime, errorTime)
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
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDomainConfig.MsgChan():
			subDomainConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subPhysicalIOAdapter.MsgChan():
			subPhysicalIOAdapter.ProcessChange(change)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleRestart(ctxArg interface{}, done bool) {
	log.Infof("handleRestart(%v)\n", done)
	ctx := ctxArg.(*domainContext)
	if done {
		log.Infof("handleRestart: avoid cleanup\n")
		ctx.pubDomainStatus.SignalRestarted()
		return
	}
}

func publishDomainStatus(ctx *domainContext, status *types.DomainStatus) {

	key := status.Key()
	log.Debugf("publishDomainStatus(%s)\n", key)
	pub := ctx.pubDomainStatus
	pub.Publish(key, *status)
}

func unpublishDomainStatus(ctx *domainContext, status *types.DomainStatus) {

	key := status.Key()
	log.Debugf("unpublishDomainStatus(%s)\n", key)
	pub := ctx.pubDomainStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishDomainStatus(%s) not found\n", key)
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
	log.Debugf("publishCipherBlockStatus(%s)\n", key)
	pub := ctx.pubCipherBlockStatus
	pub.Publish(key, status)
}

func unpublishCipherBlockStatus(ctx *domainContext, key string) {
	if ctx == nil || len(key) == 0 {
		return
	}
	log.Debugf("unpublishCipherBlockStatus(%s)\n", key)
	pub := ctx.pubCipherBlockStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishCipherBlockStatus(%s) not found\n", key)
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

	log.Infof("handleDomainModify(%s)\n", key)
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

	log.Infof("handleDomainCreate(%s)\n", key)
	ctx := ctxArg.(*domainContext)
	config := configArg.(types.DomainConfig)
	h, ok := handlerMap[config.Key()]
	if ok {
		log.Fatalf("handleDomainCreate called on config that already exists")
	}
	h1 := make(chan Notify, 1)
	handlerMap[config.Key()] = h1
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

	log.Infof("handleDomainDelete(%s)\n", key)
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
		log.Infof("Closing channel\n")
		close(h)
		delete(handlerMap, key)
	} else {
		log.Debugf("handleDomainDelete: unknown %s\n", key)
		return
	}
	log.Infof("handleDomainDelete(%s) done\n", key)
}

// Server for each domU
// Runs timer every 30 seconds to update status
func runHandler(ctx *domainContext, key string, c <-chan Notify) {

	log.Infof("runHandler starting\n")

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
			log.Debugf("runHandler(%s) timer\n", key)
			status := lookupDomainStatus(ctx, key)
			if status != nil {
				verifyStatus(ctx, status)
				maybeRetry(ctx, status)
			}
		}
	}
	log.Infof("runHandler(%s) DONE\n", key)
}

// Check if it is still running
// XXX would xen state be useful?
func verifyStatus(ctx *domainContext, status *types.DomainStatus) {
	// Check config.Active to avoid spurious errors when shutting down
	configActivate := false
	config := lookupDomainConfig(ctx, status.Key())
	if config != nil && config.Activate {
		configActivate = true
	}

	domainID, err := hyper.LookupByName(status.DomainName, status.DomainId)
	if err != nil {
		if status.Activated && configActivate {
			errStr := fmt.Sprintf("verifyStatus(%s) failed %s",
				status.Key(), err)
			log.Warnln(errStr)
			status.Activated = false
			status.State = types.HALTED
			if status.IsContainer {
				status.SetErrorNow("container exited - please restart application instance")
			}
		}
		status.DomainId = 0
		publishDomainStatus(ctx, status)
	} else {
		if !status.Activated {
			log.Warnf("verifyDomain(%s) domain came back alive; id  %d\n",
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
			log.Warnf("verifyDomain(%s) domainID changed from %d to %d\n",
				status.Key(), status.DomainId, domainID)
			status.DomainId = domainID
			status.BootTime = time.Now()
			log.Infof("Update domainId %d bootTime %s for %s",
				status.DomainId, status.BootTime.Format(time.RFC3339Nano),
				status.Key())
			publishDomainStatus(ctx, status)
		}
		// check if qemu processes has crashed
		hasQemu := status.VirtualizationMode == types.HVM || status.VirtualizationMode == types.FML || status.IsContainer
		if configActivate && status.Activated && hasQemu && !hyper.IsDomainPotentiallyShuttingDown(status.DomainName) &&
			!hyper.IsDeviceModelAlive(status.DomainId) {
			errStr := fmt.Sprintf("verifyStatus(%s) qemu crashed",
				status.Key())
			log.Errorf(errStr)
			status.SetErrorNow("qemu crashed - please restart application instance")
			status.Activated = false
			status.State = types.HALTED
			publishDomainStatus(ctx, status)
			if err := hyper.Delete(status.DomainName, status.DomainId); err != nil {
				log.Errorf("failed to delete domain: %s (%v)\n", status.DomainName, err)
			}
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
		log.Infof("maybeRetryBoot(%s) %d remaining\n",
			status.Key(),
			(timeLimit-elapsed)/time.Second)
		return
	}
	log.Infof("maybeRetryBoot(%s) after %s at %v\n",
		status.Key(), status.Error, status.ErrorTime)

	status.ClearError()
	status.TriedCount += 1

	ctx.createSema.V(1)
	domainID, err := DomainCreate(*status)
	ctx.createSema.P(1)
	if err != nil {
		log.Errorf("maybeRetryBoot DomainCreate for %s: %s\n",
			status.DomainName, err)
		status.BootFailed = true
		status.SetErrorNow(err.Error())
		publishDomainStatus(ctx, status)
		return
	}
	status.BootFailed = false
	doActivateTail(ctx, status, domainID)
	publishDomainStatus(ctx, status)
	log.Infof("maybeRetryBoot(%s) DONE for %s\n",
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
	log.Infof("maybeRetryAdapters(%s) after %s at %v\n",
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
	log.Infof("maybeRetryAdapters(%s) DONE for %s\n",
		status.Key(), status.DisplayName)
}

// Callers must be careful to publish any changes to DomainStatus
func lookupDomainStatus(ctx *domainContext, key string) *types.DomainStatus {

	pub := ctx.pubDomainStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupDomainStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.DomainStatus)
	return &status
}

func lookupDomainConfig(ctx *domainContext, key string) *types.DomainConfig {

	sub := ctx.subDomainConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupDomainConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.DomainConfig)
	return &config
}

func handleCreate(ctx *domainContext, key string, config *types.DomainConfig) {

	log.Infof("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	log.Debugf("DomainConfig %+v\n", config)
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
	log.Infof("handleCreate(%v) set domainName %s for %s\n",
		config.UUIDandVersion, status.DomainName,
		config.DisplayName)

	if err := configToStatus(ctx, *config, &status); err != nil {
		log.Errorf("Failed to create DomainStatus from %v: %s\n",
			config, err)
		status.PendingAdd = false
		status.SetErrorNow(err.Error())
		publishDomainStatus(ctx, &status)
		return
	}

	if err := configAdapters(ctx, *config); err != nil {
		log.Errorf("Failed to reserve adapters for %v: %s\n",
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
	log.Infof("handleCreate(%v) DONE for %s\n",
		config.UUIDandVersion, config.DisplayName)
}

// XXX clear the UUID assignment; leave in pciback
func cleanupAdapters(ctx *domainContext, ioAdapterList []types.IoAdapter,
	myUuid uuid.UUID) {

	publishAssignableAdapters := false
	// Look for any adapters used by us and clear UsedByUUID
	for _, adapter := range ioAdapterList {
		log.Debugf("cleanupAdapters processing adapter %d %s\n",
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
		log.Debugf("doAssignIoAdaptersToDomain processing adapter %d %s\n",
			adapter.Type, adapter.Name)

		aa := ctx.assignableAdapters
		list := aa.LookupIoBundleAny(adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if len(list) == 0 {
			log.Fatalf("doAssignIoAdaptersToDomain IoBundle disappeared %d %s for %s\n",
				adapter.Type, adapter.Name, status.DomainName)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				log.Fatalf("doAssignIoAdaptersToDomain IoBundle stolen by %s: %d %s for %s\n",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					status.DomainName)
			}
			if !isInUsbGroup(*aa, *ib) {
				continue
			}
			if ib.PciLong == "" {
				log.Warnf("doAssignIoAdaptersToDomain missing PciLong: %d %s for %s\n",
					adapter.Type, adapter.Name, status.DomainName)
			} else if ctx.usbAccess && !ib.IsPCIBack {
				log.Infof("Assigning %s (%s) to %s\n",
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

	log.Infof("doActivate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	if status.AdaptersFailed || status.PendingModify {
		if err := configAdapters(ctx, config); err != nil {
			log.Errorf("Failed to reserve adapters for %v: %s\n",
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
		// XXX apparently this is under the appInstID and not under
		// the ImageID aka VolumeID
		if err := ctrPrepareMount(config.UUIDandVersion.UUID,
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

	if err := hyper.CreateDomConfig(status.DomainName, config, status.DiskStatusList, ctx.assignableAdapters, file); err != nil {
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
		domainID, err = DomainCreate(*status)
		ctx.createSema.P(1)
		if err == nil {
			break
		}
		if status.TriedCount >= 3 {
			log.Errorf("DomainCreate for %s: %s\n", status.DomainName, err)
			status.BootFailed = true
			status.SetErrorNow(err.Error())
			publishDomainStatus(ctx, status)
			return
		}
		log.Warnf("Retry domain create for %s: failed %s\n",
			status.DomainName, err)
		publishDomainStatus(ctx, status)
		time.Sleep(5 * time.Second)
	}
	status.BootFailed = false
	doActivateTail(ctx, status, domainID)
}

func doActivateTail(ctx *domainContext, status *types.DomainStatus,
	domainID int) {

	log.Infof("created domainID %d for %s\n", domainID, status.DomainName)
	status.DomainId = domainID
	status.BootTime = time.Now()
	log.Infof("Set domainId %d bootTime %s for %s",
		status.DomainId, status.BootTime.Format(time.RFC3339Nano),
		status.Key())
	status.State = types.BOOTING
	publishDomainStatus(ctx, status)

	// Disable offloads for all vifs
	err := hyper.Tune(status.DomainName, domainID,
		len(status.VifList))
	if err != nil {
		// XXX continuing even if we get a failure?
		log.Errorf("Tuning domain %s failed: %s\n",
			status.DomainName, err)
	}
	err = hyper.Start(status.DomainName, domainID)
	if err != nil {
		// XXX shouldn't we destroy it?
		log.Errorf("domain start for %s: %s\n", status.DomainName, err)
		status.SetErrorNow(err.Error())
		return
	}
	// The -emu interfaces were most likely created as result of the boot so we
	// update VifUsed here.
	status.VifList = checkIfEmu(status.VifList)

	status.State = types.RUNNING
	// XXX dumping status to log
	hyper.Info(status.DomainName, status.DomainId)

	domainID, err = hyper.LookupByName(status.DomainName, status.DomainId)
	if err == nil && domainID != status.DomainId {
		status.DomainId = domainID
		status.BootTime = time.Now()
		log.Infof("Update domainId %d bootTime %s for %s",
			status.DomainId, status.BootTime.Format(time.RFC3339Nano),
			status.Key())
	}
	status.Activated = true
	log.Infof("doActivateTail(%v) done for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

// shutdown and wait for the domain to go away; if that fails destroy and wait
func doInactivate(ctx *domainContext, status *types.DomainStatus, impatient bool) {

	log.Infof("doInactivate(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)
	domainID, err := hyper.LookupByName(status.DomainName, status.DomainId)
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
				log.Errorf("DomainShutdown %s failed: %s\n",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Infof("doInactivate(%v) for %s: waiting for domain to shutdown\n",
					status.UUIDandVersion, status.DisplayName)
			}
			gone := waitForDomainGone(*status, shortDelay)
			if gone {
				status.DomainId = 0
				break
			}
			if err := DomainShutdown(*status, true); err != nil {
				log.Errorf("DomainShutdown -F %s failed: %s\n",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Infof("doInactivate(%v) for %s: waiting for domain to poweroff\n",
					status.UUIDandVersion, status.DisplayName)
			}
			gone = waitForDomainGone(*status, maxDelay)
			if gone {
				status.DomainId = 0
				break
			}

		case types.PV:
			if err := DomainShutdown(*status, false); err != nil {
				log.Errorf("DomainShutdown %s failed: %s\n",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Infof("doInactivate(%v) for %s: waiting for domain to shutdown\n",
					status.UUIDandVersion, status.DisplayName)
			}
			gone := waitForDomainGone(*status, maxDelay)
			if gone {
				status.DomainId = 0
				break
			}
			if err := DomainShutdown(*status, true); err != nil {
				log.Errorf("DomainShutdown -F %s failed: %s\n",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Infof("doInactivate(%v) for %s: waiting for domain to poweroff\n",
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
		if err := hyper.Delete(status.DomainName, status.DomainId); err != nil {
			log.Errorf("Failed to delete domain %s (%v)\n", status.DomainName, err)
		}
		// Even if destroy failed we wait again
		log.Infof("doInactivate(%v) for %s: waiting for domain to be destroyed\n",
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

	log.Infof("doInactivate(%v) done for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

// XXX currently only unassigns USB if usbAccess is set
func pciUnassign(ctx *domainContext, status *types.DomainStatus,
	ignoreErrors bool) {

	log.Infof("pciUnassign(%v, %v) for %s\n",
		status.UUIDandVersion, ignoreErrors, status.DisplayName)

	// Unassign any pci devices but keep UsedByUUID set and keep in status
	var assignments []string
	for _, adapter := range status.IoAdapterList {
		log.Debugf("doInactivate processing adapter %d %s\n",
			adapter.Type, adapter.Name)
		aa := ctx.assignableAdapters
		list := aa.LookupIoBundleAny(adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if len(list) == 0 {
			log.Fatalf("doInactivate IoBundle disappeared %d %s for %s\n",
				adapter.Type, adapter.Name, status.DomainName)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			if ib.UsedByUUID != status.UUIDandVersion.UUID {
				log.Infof("doInactivate IoBundle not ours by %s: %d %s for %s\n",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					status.DomainName)
				continue
			}
			// XXX also unassign others and assign during Activate?
			if !isInUsbGroup(*aa, *ib) {
				continue
			}
			if ib.PciLong == "" {
				log.Warnf("doInactivate lookup missing: %d %s for %s\n",
					adapter.Type, adapter.Name, status.DomainName)
			} else if ctx.usbAccess && ib.IsPCIBack {
				log.Infof("Removing %s (%s) from %s\n",
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

	log.Infof("configToStatus(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	numOfContainerDisks := 0
	for i, dc := range config.DiskConfigList {
		if dc.Format == zconfig.Format_CONTAINER {
			numOfContainerDisks++
		}
		ds := &status.DiskStatusList[i]
		ds.ImageID = dc.ImageID
		ds.ImageSha256 = dc.ImageSha256
		ds.ReadOnly = dc.ReadOnly
		ds.Preserve = dc.Preserve
		ds.FileLocation = dc.FileLocation
		ds.Format = dc.Format
		ds.Maxsizebytes = dc.Maxsizebytes
		ds.Devtype = dc.Devtype
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

	log.Infof("configAdapters(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	defer ctx.publishAssignableAdapters()

	for _, adapter := range config.IoAdapterList {
		log.Debugf("configAdapters processing adapter %d %s\n",
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

func createMountPointExecEnvFiles(containerPath string, mountpoints map[string]struct{}, execpath []string, workdir string, env []string, noOfDisks int) error {
	mpFileName := containerPath + "/mountPoints"
	cmdFileName := containerPath + "/cmdline"
	envFileName := containerPath + "/environment"

	mpFile, err := os.Create(mpFileName)
	if err != nil {
		log.Errorf("createMountPointExecEnvFiles: os.Create for %v, failed: %v", mpFileName, err.Error())
	}
	defer mpFile.Close()

	cmdFile, err := os.Create(cmdFileName)
	if err != nil {
		log.Errorf("createMountPointExecEnvFiles: os.Create for %v, failed: %v", cmdFileName, err.Error())
	}
	defer cmdFile.Close()

	envFile, err := os.Create(envFileName)
	if err != nil {
		log.Errorf("createMountPointExecEnvFiles: os.Create for %v, failed: %v", envFileName, err.Error())
	}
	defer envFile.Close()

	//Ignoring container image in status.DiskStatusList
	noOfDisks = noOfDisks - 1

	//Validating if there are enough disks provided for the mount-points
	switch {
	case noOfDisks > len(mountpoints):
		//If no. of disks is (strictly) greater than no. of mount-points provided, we will ignore excessive disks.
		log.Warnf("createMountPointExecEnvFiles: Number of volumes provided: %v is more than number of mount-points: %v. "+
			"Excessive volumes will be ignored", noOfDisks, len(mountpoints))
	case noOfDisks < len(mountpoints):
		//If no. of mount-points is (strictly) greater than no. of disks provided, we need to throw an error as there
		// won't be enough disks to satisfy required mount-points.
		return fmt.Errorf("createMountPointExecEnvFiles: Number of volumes provided: %v is less than number of mount-points: %v. ",
			noOfDisks, len(mountpoints))
	}

	for path := range mountpoints {
		if !strings.HasPrefix(path, "/") {
			//Target path is expected to be absolute.
			err := fmt.Errorf("createMountPointExecEnvFiles: targetPath should be absolute")
			log.Errorf(err.Error())
			return err
		}
		log.Infof("createMountPointExecEnvFiles: Processing mount point %s\n", path)
		if _, err := mpFile.WriteString(fmt.Sprintf("%s\n", path)); err != nil {
			err := fmt.Errorf("createMountPointExecEnvFiles: writing to %s failed %v", mpFileName, err)
			log.Errorf(err.Error())
			return err
		}
	}

	// each item needs to be independently quoted for initrd
	execpathQuoted := make([]string, 0)
	for _, s := range execpath {
		execpathQuoted = append(execpathQuoted, fmt.Sprintf("\"%s\"", s))
	}
	if _, err := cmdFile.WriteString(strings.Join(execpathQuoted, " ")); err != nil {
		err := fmt.Errorf("createMountPointExecEnvFiles: writing to %s failed %v", cmdFileName, err)
		log.Errorf(err.Error())
		return err
	}

	envContent := ""
	if workdir != "" {
		envContent = fmt.Sprintf("export WORKDIR=\"%s\"\n", workdir)
	}
	for _, e := range env {
		envContent = envContent + fmt.Sprintf("export %s\n", e)
	}
	if _, err := envFile.WriteString(envContent); err != nil {
		err := fmt.Errorf("createMountPointExecEnvFiles: writing to %s failed %v", envFileName, err)
		log.Errorf(err.Error())
		return err
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

	log.Infof("handleModify(%v) activate %t for %s\n",
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
			log.Infof("handleModify(%v) set domainName %s for %s\n",
				config.UUIDandVersion, status.DomainName,
				config.DisplayName)
		}
		status.VifList = checkIfEmu(config.VifList)
		publishDomainStatus(ctx, status)

		// This has the effect of trying a boot again for any
		// handleModify after an error.
		if status.HasError() {
			log.Infof("handleModify(%v) ignoring existing error for %s\n",
				config.UUIDandVersion, config.DisplayName)
			status.ClearError()
			publishDomainStatus(ctx, status)
			doInactivate(ctx, status, false)
		}
		// Update disks based on any change to volumes
		if err := configToStatus(ctx, *config, status); err != nil {
			log.Errorf("Failed to update DomainStatus from %v: %s\n",
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
			log.Infof("handleModify(%v) clearing existing error for %s\n",
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
			log.Errorf("Failed to update DomainStatus from %v: %s\n",
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
		log.Infof("handleModify(%v) DONE for %s\n",
			config.UUIDandVersion, config.DisplayName)
		return
	}

	// XXX check if we have status.HasError() and delete and retry
	// even if same version. XXX won't the above Activate/Activated checks
	// result in redoing things? Could have failures during copy i.e.
	// before activation.

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Infof("Same version %s for %s\n",
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
	log.Infof("handleModify(%v) DONE for %s\n",
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
		log.Infof("waitForDomainGone(%v) for %s: waiting for %v\n",
			status.UUIDandVersion, status.DisplayName, delay)
		if delay != 0 {
			time.Sleep(delay)
			waited += delay
		}
		if err := hyper.Info(status.DomainName, status.DomainId); err != nil {
			log.Infof("waitForDomainGone(%v) for %s: domain is gone\n",
				status.UUIDandVersion, status.DisplayName)
			gone = true
			break
		} else {
			if waited > maxDelay {
				// Give up
				log.Warnf("waitForDomainGone(%v) for %s: giving up\n",
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

	log.Infof("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	// XXX dumping status to log
	hyper.Info(status.DomainName, status.DomainId)

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
	log.Infof("handleDelete(%v) DONE for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

// DomainCreate is a wrapper for domain creation
// returns domainID and error
func DomainCreate(status types.DomainStatus) (int, error) {

	var (
		domainID int
		err      error
	)

	filename := xenCfgFilename(status.AppNum)
	log.Infof("DomainCreate %s ... xenCfgFilename - %s\n", status.DomainName, filename)
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
	log.Infof("Creating domain with the config - %s\n", filename)
	domainID, err = hyper.Create(status.DomainName, filename, status.VirtualizationMode)

	return domainID, err
}

// DomainShutdown is a wrapper for domain shutdown
func DomainShutdown(status types.DomainStatus, force bool) error {

	var err error
	log.Infof("DomainShutdown force-%v %s %d\n", force, status.DomainName, status.DomainId)

	// Stop the domain
	log.Infof("Stopping domain - %s\n", status.DomainName)
	err = hyper.Stop(status.DomainName, status.DomainId, force)

	return err
}

// Handles both create and modify events
func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	if cmp.Equal(ctx.deviceNetworkStatus, status) {
		log.Infof("handleDNSModify unchanged\n")
		ctx.DNSinitialized = true
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	// Even if Testing is set we look at it for pciback transitions to
	// bring things out of pciback (but not to add to pciback)
	ctx.deviceNetworkStatus = status
	checkAndSetIoBundleAll(ctx)
	ctx.DNSinitialized = true
	log.Infof("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSDelete for %s\n", key)
	ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	ctx.DNSinitialized = false
	checkAndSetIoBundleAll(ctx)
	log.Infof("handleDNSDelete done for %s\n", key)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		if gcp.GlobalValueInt(types.DomainBootRetryTime) != 0 {
			ctx.domainBootRetryTime = gcp.GlobalValueInt(types.DomainBootRetryTime)
		}
		if gcp.GlobalValueBool(types.UsbAccess) != ctx.usbAccess {
			ctx.usbAccess = gcp.GlobalValueBool(types.UsbAccess)
			updateUsbAccess(ctx)
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
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

// getCloudInitUserData : returns decrypted cloud-init user data
func getCloudInitUserData(ctx *domainContext,
	dc types.DomainConfig) (zconfig.EncryptionBlock, error) {
	if dc.CipherBlockStatus.IsCipher {
		status, decBlock, err := utils.GetCipherCredentials(agentName,
			dc.CipherBlockStatus)
		ctx.pubCipherBlockStatus.Publish(status.Key(), status)
		if err != nil {
			log.Errorf("%s, domain config cipherblock decryption unsuccessful, falling back to cleartext: %v\n",
				dc.Key(), err)
			decBlock.ProtectedUserData = *dc.CloudInitUserData
			return decBlock, nil
		}
		log.Infof("%s, domain config cipherblock decryption successful\n", dc.Key())
		return decBlock, nil
	}
	log.Infof("%s, domain config cipherblock not present\n", dc.Key())
	decBlock := zconfig.EncryptionBlock{}
	decBlock.ProtectedUserData = *dc.CloudInitUserData
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
		errStr := fmt.Sprintf("%s, cloud-init data get failed %s\n",
			config.DisplayName, err)
		return nil, errors.New(errStr)
	}

	ud, err := base64.StdEncoding.DecodeString(decBlock.ProtectedUserData)
	if err != nil {
		errStr := fmt.Sprintf("fetchEnvVariablesFromCloudInit failed %s\n", err)
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
		log.Fatalf("createCloudInitISO failed %s\n", err)
	}
	defer os.RemoveAll(dir)

	metafile, err := os.Create(dir + "/meta-data")
	if err != nil {
		log.Fatalf("createCloudInitISO failed %s\n", err)
	}
	metafile.WriteString(fmt.Sprintf("instance-id: %s/%s\n",
		config.UUIDandVersion.UUID.String(),
		config.UUIDandVersion.Version))
	metafile.WriteString(fmt.Sprintf("local-hostname: %s\n",
		config.UUIDandVersion.UUID.String()))
	metafile.Close()

	userfile, err := os.Create(dir + "/user-data")
	if err != nil {
		log.Fatalf("createCloudInitISO failed %s\n", err)
	}

	decBlock, err := getCloudInitUserData(ctx, config)
	if err != nil {
		return nil, err
	}
	ud, err := base64.StdEncoding.DecodeString(decBlock.ProtectedUserData)
	if err != nil {
		errStr := fmt.Sprintf("createCloudInitISO failed %s\n", err)
		return nil, errors.New(errStr)
	}
	userfile.WriteString(string(ud))
	userfile.Close()

	if err := mkisofs(fileName, dir); err != nil {
		errStr := fmt.Sprintf("createCloudInitISO failed %s\n", err)
		return nil, errors.New(errStr)
	}

	ds := new(types.DiskStatus)
	ds.FileLocation = fileName
	ds.Format = zconfig.Format_RAW
	ds.Vdev = "hdc:cdrom"
	ds.ReadOnly = false
	ds.Preserve = true // Prevent attempt to copy; XXX remove
	return ds, nil
}

// mkisofs -output %s -volid cidata -joliet -rock %s, fileName, dir
func mkisofs(output string, dir string) error {
	log.Infof("mkisofs(%s, %s)\n", output, dir)

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
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("mkisofs failed: %s\n",
			string(stdoutStderr))
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Infof("mkisofs done\n")
	return nil
}

func handlePhysicalIOAdapterListCreateModify(ctxArg interface{},
	key string, configArg interface{}) {

	ctx := ctxArg.(*domainContext)
	phyIOAdapterList := configArg.(types.PhysicalIOAdapterList)
	aa := ctx.assignableAdapters
	log.Infof("handlePhysicalIOAdapterListCreateModify: current len %d, update %+v\n",
		len(aa.IoBundleList), phyIOAdapterList)

	if !aa.Initialized {
		// Setup list first because functions lookup in IoBundleList
		for _, phyAdapter := range phyIOAdapterList.AdapterList {
			ib := *types.IoBundleFromPhyAdapter(phyAdapter)
			// We assume AddOrUpdateIoBundle will preserve any
			// existing IsPort/IsPCIBack/UsedByUUID
			aa.AddOrUpdateIoBundle(ib)
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
		ib := *types.IoBundleFromPhyAdapter(phyAdapter)
		currentIbPtr := aa.LookupIoBundlePhylabel(phyAdapter.Phylabel)
		if currentIbPtr == nil {
			log.Infof("handlePhysicalIOAdapterListCreateModify: Adapter %s "+
				"added. %+v\n", phyAdapter.Phylabel, ib)
			handleIBCreate(ctx, ib)
		} else if currentIbPtr.HasAdapterChanged(phyAdapter) {
			log.Infof("handlePhysicalIOAdapterListCreateModify: Adapter %s "+
				"changed. Current: %+v, New: %+v\n", phyAdapter.Phylabel,
				*currentIbPtr, ib)
			handleIBModify(ctx, ib)
		} else {
			log.Infof("handlePhysicalIOAdapterListCreateModify: Adapter %s "+
				"- No Change\n", phyAdapter.Phylabel)
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
		"deleted\n")

	for indx := range phyAdapterList.AdapterList {
		phylabel := phyAdapterList.AdapterList[indx].Phylabel
		log.Infof("handlePhysicalIOAdapterListDelete: Deleting Adapter %s\n",
			phylabel)
		handleIBDelete(ctx, phylabel)
	}
	ctx.publishAssignableAdapters()
	log.Infof("handlePhysicalIOAdapterListDelete done\n")
}

// Process new IoBundles. Check if PCI device exists, and check that not
// used in a DevicePortConfig/DeviceNetworkStatus
// Assign to pciback
func handleIBCreate(ctx *domainContext, ib types.IoBundle) {

	log.Infof("handleIBCreate(%d %s %s)", ib.Type, ib.Phylabel, ib.AssignmentGroup)
	aa := ctx.assignableAdapters
	if err := checkAndSetIoBundle(ctx, &ib, false); err != nil {
		log.Warnf("Not reporting non-existent PCI device %d %s: %v\n",
			ib.Type, ib.Phylabel, err)
		return
	}
	// We assume AddOrUpdateIoBundle will preserve any existing Unique/MacAddr
	aa.AddOrUpdateIoBundle(ib)
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
	log.Infof("checkAndSetIoBundle(%d %s %s) isPort %t members %v",
		ib.Type, ib.Phylabel, ib.AssignmentGroup, isPort, list)
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
		log.Warnf("checkAndSetIoMember(%d %s %s) part of zedrouter port\n",
			ib.Type, ib.Phylabel, ib.AssignmentGroup)
		ib.IsPort = true
		changed = true
		if ib.UsedByUUID != nilUUID {
			log.Errorf("checkAndSetIoMember(%d %s %s) used by %s",
				ib.Type, ib.Phylabel, ib.AssignmentGroup,
				ib.UsedByUUID.String())

		} else if ib.IsPCIBack {
			log.Infof("checkAndSetIoMember(%d %s %s) take back from pciback\n",
				ib.Type, ib.Phylabel, ib.AssignmentGroup)
			if ib.PciLong != "" {
				log.Infof("Removing %s (%s) from pciback\n",
					ib.Phylabel, ib.PciLong)
				err := hyper.PCIRelease(ib.PciLong)
				if err != nil {
					log.Errorf("checkAndSetIoMember(%d %s %s) PCIRelease %s failed %v\n",
						ib.Type, ib.Phylabel, ib.AssignmentGroup, ib.PciLong, err)
				}
				// Seems like like no risk for race; when we return
				// from above the driver has been attached and
				// any ifname has been registered.
				found, ifname := types.PciLongToIfname(ib.PciLong)
				if !found {
					log.Errorf("Not found: %d %s %s",
						ib.Type, ib.Phylabel, ib.Ifname)
				} else if ifname != ib.Ifname {
					log.Warnf("Found: %d %s %s at %s",
						ib.Type, ib.Phylabel, ib.Ifname,
						ifname)
					types.IfRename(ifname, ib.Ifname)
				}
			}
			ib.IsPCIBack = false
			changed = true
			// Verify that it has been returned from pciback
			_, err := types.IoBundleToPci(ib)
			if err != nil {
				log.Warnf("checkAndSetIoMember(%d %s %s) gone?: %s\n",
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
	long, err := types.IoBundleToPci(ib)
	if err != nil {
		log.Error(err)
		return err
	}
	if long != "" {
		ib.PciLong = long
		changed = true
		log.Infof("checkAndSetIoMember(%d %s %s) found %s\n",
			ib.Type, ib.Phylabel, ib.AssignmentGroup, long)

		// Save somewhat Unique string for debug
		found, unique := types.PciLongToUnique(long)
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
			log.Infof("Not assigning %s (%s) to pciback due to Testing\n",
				ib.Phylabel, ib.PciLong)
		} else if ctx.usbAccess && isInUsbGroup(*aa, *ib) {
			log.Infof("Not assigning %s (%s) to pciback due to usbAccess\n",
				ib.Phylabel, ib.PciLong)
		} else if ib.PciLong != "" {
			log.Infof("Assigning %s (%s) to pciback\n",
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
			log.Warnf("checkIoBundleAll failed for %d: %s\n", i, err)
		}
	}
}

// Check if the name to pci-id have changed
// We track a mostly unique string to see if the underlying firmware node has
// changed in addition to the name to pci-id lookup.
func checkIoBundle(ctx *domainContext, ib *types.IoBundle) error {

	long, err := types.IoBundleToPci(ib)
	if err != nil {
		return err
	}
	if long == "" {
		// Doesn't exist
		return nil
	}
	found, unique := types.PciLongToUnique(long)
	if !found {
		errStr := fmt.Sprintf("IoBundle(%d %s %s) %s unique %s not foun\n",
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

func updateUsbAccess(ctx *domainContext) {

	log.Infof("updateUsbAccess(%t)", ctx.usbAccess)
	if !ctx.usbAccess {
		maybeAssignableAdd(ctx)
	} else {
		maybeAssignableRem(ctx)
	}
	checkIoBundleAll(ctx)
}

func maybeAssignableAdd(ctx *domainContext) {

	var assignments []string
	aa := ctx.assignableAdapters
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		if !isInUsbGroup(*aa, *ib) {
			continue
		}
		if ib.PciLong == "" {
			continue
		}
		if !ib.IsPCIBack {
			log.Infof("maybeAssignableAdd: Assigning %s (%s) to pciback\n",
				ib.Phylabel, ib.PciLong)
			assignments = addNoDuplicate(assignments, ib.PciLong)
			ib.IsPCIBack = true
		}
	}
	for _, long := range assignments {
		err := hyper.PCIReserve(long)
		if err != nil {
			log.Errorf("maybeAssignableAdd: add failed: %s", err)
		}
	}
	if len(assignments) != 0 {
		ctx.publishAssignableAdapters()
	}
}

func maybeAssignableRem(ctx *domainContext) {

	var assignments []string
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
				log.Infof("Removing %s (%s) from pciback\n",
					ib.Phylabel, ib.PciLong)
				assignments = addNoDuplicate(assignments, ib.PciLong)
				ib.IsPCIBack = false
			} else {
				log.Warnf("No removing %s (%s) from pciback: used by %s",
					ib.Phylabel, ib.PciLong, ib.UsedByUUID)
			}
		}
	}
	for _, long := range assignments {
		err := hyper.PCIRelease(long)
		if err != nil {
			log.Errorf("maybeAssignableRem remove failed: %s\n", err)
		}
	}
	if len(assignments) != 0 {
		ctx.publishAssignableAdapters()
	}
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
		log.Infof("handleIBDelete: Assigning %s (%s) back\n",
			ib.Phylabel, ib.PciLong)
		if ib.PciLong != "" {
			err := hyper.PCIRelease(ib.PciLong)
			if err != nil {
				log.Errorf("handleIBDelete(%d %s %s) PCIRelease %s failed %v\n",
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
		log.Errorf("Failed to find IoBundle (%d %s).  aa: %+v\n",
			newIb.Type, newIb.Phylabel, aa)
		return
	}

	log.Infof("handleIBModify(%d %s %s) from %v to %v\n",
		currentIbPtr.Type, currentIbPtr.Phylabel, currentIbPtr.AssignmentGroup,
		*currentIbPtr, newIb)

	if err := checkAndSetIoBundle(ctx, &newIb, false); err != nil {
		log.Warnf("Not reporting non-existent PCI device %d %s: %v\n",
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
