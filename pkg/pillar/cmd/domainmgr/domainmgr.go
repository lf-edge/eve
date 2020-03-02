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
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eriknordmark/netlink"
	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	pubsublegacy "github.com/lf-edge/eve/pkg/pillar/pubsub/legacy"
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
	pubImageStatus         pubsub.Publication
	pubAssignableAdapters  pubsub.Publication
	pubDomainMetric        pubsub.Publication
	pubHostMemory          pubsub.Publication
	usbAccess              bool
	createSema             sema.Semaphore
	GCInitialized          bool
	vdiskGCTime            uint32 // In seconds
	domainBootRetryTime    uint32 // In seconds
	metricInterval         uint32 // In seconds
}

// appRwImageName - Returns name of the image ( including parent dir )
// Note that we still use the sha in the filename to not impact running images. Otherwise
// we could switch this to imageID
func appRwImageName(sha256, uuidStr string, format zconfig.Format) string {
	formatStr := strings.ToLower(format.String())
	return fmt.Sprintf("%s/%s-%s.%s", rwImgDirname, sha256, uuidStr, formatStr)
}

// parseAppRwImageName - Returns rwImgDirname, sha256, uuidStr
func parseAppRwImageName(image string) (string, string, string) {
	// ImageSha is provided by the controller - it can be uppercase
	// or lowercase.
	re := regexp.MustCompile(`(.+)/([0-9A-Fa-f]+)-(.+)\.(.+)`)
	if !re.MatchString(image) {
		log.Errorf("AppRwImageName %s doesn't match pattern", image)
		return "", "", ""
	}
	parsedStrings := re.FindStringSubmatch(image)
	return parsedStrings[1], parsedStrings[2], parsedStrings[3]
}

func (ctx *domainContext) publishAssignableAdapters() {
	log.Infof("Publishing %v", *ctx.assignableAdapters)
	ctx.pubAssignableAdapters.Publish("global", *ctx.assignableAdapters)
}

var debug = false
var debugOverride bool // From command line arg

func Run(ps *pubsub.PubSub) {
	handlersInit()
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	curpartPtr := flag.String("c", "", "Current partition")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	curpart := *curpartPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	logf, err := agentlog.Init(agentName, curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s\n", agentName)

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
		vdiskGCTime:         3600,
		domainBootRetryTime: 600,
	}
	aa := types.AssignableAdapters{}
	domainCtx.assignableAdapters = &aa

	// Allow only one concurrent xl create
	domainCtx.createSema = sema.Create(1)
	domainCtx.createSema.P(1)

	pubDomainStatus, err := pubsublegacy.Publish(agentName, types.DomainStatus{})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubDomainStatus = pubDomainStatus
	pubDomainStatus.ClearRestarted()

	pubImageStatus, err := pubsublegacy.Publish(agentName, types.ImageStatus{})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubImageStatus = pubImageStatus
	pubImageStatus.ClearRestarted()

	// Publish existing images with RefCount zero
	populateInitialImageStatus(&domainCtx, rwImgDirname)
	pubImageStatus.SignalRestarted()

	pubAssignableAdapters, err := pubsublegacy.Publish(agentName,
		types.AssignableAdapters{})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubAssignableAdapters = pubAssignableAdapters

	pubDomainMetric, err := pubsublegacy.Publish(agentName,
		types.DomainMetric{})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubDomainMetric = pubDomainMetric

	pubHostMemory, err := pubsublegacy.Publish(agentName,
		types.HostMemory{})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubHostMemory = pubHostMemory
	pubHostMemory.ClearRestarted()

	// Look for global config such as log levels
	subGlobalConfig, err := pubsublegacy.Subscribe("", types.GlobalConfig{},
		false, &domainCtx, &pubsub.SubscriptionOptions{
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

	subDeviceNetworkStatus, err := pubsublegacy.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &domainCtx, &pubsub.SubscriptionOptions{
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

	go metricsTimerTask(&domainCtx)

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
	subPhysicalIOAdapter, err := pubsublegacy.Subscribe("zedagent",
		types.PhysicalIOAdapterList{}, false, &domainCtx, &pubsub.SubscriptionOptions{
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
	subDomainConfig, err := pubsublegacy.Subscribe("zedmanager",
		types.DomainConfig{}, false, &domainCtx, &pubsub.SubscriptionOptions{
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

	// We will cleanup zero RefCount objects after a while
	// We run timer 10 times more often than the limit on LastUse
	// Update the LastUse again here since it may not get updated since the
	// device reboot if network is not available
	duration := time.Duration(domainCtx.vdiskGCTime / 10)
	gc := time.NewTicker(duration * time.Second)
	gcResetObjectsLastUse(&domainCtx, rwImgDirname)

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

		case <-gc.C:
			start := time.Now()
			gcObjects(&domainCtx, rwImgDirname)
			pubsub.CheckMaxTimeTopic(agentName, "gc", start,
				warningTime, errorTime)

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

func deleteFile(filelocation string) {
	if err := os.Remove(filelocation); err != nil {
		log.Errorf("Failed to delete file %s. Error: %s",
			filelocation, err.Error())
	}
}

// recursive scanning for verified objects,
// to recreate the status files
func populateInitialImageStatus(ctx *domainContext, dirName string) {

	log.Infof("populateInitialImageStatus(%s)\n", dirName)
	locations, err := ioutil.ReadDir(dirName)
	if err != nil {
		log.Fatal(err)
	}

	for _, location := range locations {
		filelocation := dirName + "/" + location.Name()
		if location.IsDir() {
			log.Debugf("populateInitialImageStatus: directory %s ignored\n", filelocation)
			continue
		}

		info, err := os.Stat(filelocation)
		if err != nil {
			log.Errorf("Error in getting file information. Err: %s. "+
				"Deleting file %s", err, filelocation)
			deleteFile(filelocation)
			continue
		}

		size := info.Size()
		_, sha256, appUUIDStr := parseAppRwImageName(filelocation)
		log.Debugf("populateInitialImageStatus: Processing AppUuid: %s, "+
			"%d Mbytes, fileLocation:%s",
			appUUIDStr, size/(1024*1024), filelocation)

		appUUID, err := uuid.FromString(appUUIDStr)
		if err != nil {
			log.Errorf("populateInitialImageStatus: Invalid UUIDStr(%s) in "+
				"filename (%s). err: %s. Deleting the File",
				appUUIDStr, filelocation, err)
			deleteFile(filelocation)
			continue
		}

		status := types.ImageStatus{
			AppInstUUID:  appUUID,
			ImageSha256:  sha256, // Included in case app has multiple vdisks
			Filename:     location.Name(),
			FileLocation: filelocation,
			Size:         uint64(size),
			RefCount:     0,
			LastUse:      time.Now(),
		}

		publishImageStatus(ctx, &status)
	}
}

func addImageStatus(ctx *domainContext, fileLocation string) {

	filename := filepath.Base(fileLocation)
	pub := ctx.pubImageStatus
	st, _ := pub.Get(filename)
	if st == nil {
		log.Infof("addImageStatus(%s) not found\n", filename)
		info, err := os.Stat(fileLocation)
		var size int64
		if err != nil {
			log.Errorf("Error in getting file information: %s", err)
			size = 0
		} else {
			size = info.Size()
		}
		_, sha256, appUUIDStr := parseAppRwImageName(fileLocation)
		appUUID, err := uuid.FromString(appUUIDStr)
		if err != nil {
			log.Errorf("Invalid UUIDStr(%s) in filename (%s):: %s",
				appUUIDStr, fileLocation, err)
			appUUID = nilUUID
		}
		status := types.ImageStatus{
			AppInstUUID:  appUUID,
			ImageSha256:  sha256, // Included in case app has multiple vdisks
			Filename:     filename,
			FileLocation: fileLocation,
			Size:         uint64(size),
			RefCount:     1,
			LastUse:      time.Now(),
		}
		publishImageStatus(ctx, &status)
	} else {
		status := st.(types.ImageStatus)
		log.Infof("addImageStatus(%s) found RefCount %d LastUse %v\n",
			filename, status.RefCount, status.LastUse)

		status.RefCount += 1
		status.LastUse = time.Now()
		log.Infof("addImageStatus(%s) set RefCount %d LastUse %v\n",
			filename, status.RefCount, status.LastUse)
		publishImageStatus(ctx, &status)
	}
}

// Remove from ImageStatus since fileLocation has been deleted
func delImageStatus(ctx *domainContext, fileLocation string) {

	filename := filepath.Base(fileLocation)
	pub := ctx.pubImageStatus
	st, _ := pub.Get(filename)
	if st == nil {
		log.Errorf("delImageStatus(%s) not found\n", filename)
		return
	}
	status := st.(types.ImageStatus)
	log.Infof("delImageStatus(%s) found RefCount %d LastUse %v\n",
		filename, status.RefCount, status.LastUse)
	unpublishImageStatus(ctx, &status)
}

// Periodic garbage collection looking at RefCount=0 files
func gcObjects(ctx *domainContext, dirName string) {

	log.Debugf("gcObjects()\n")

	pub := ctx.pubImageStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.ImageStatus)
		// Make sure we update LastUse if it is still referenced
		// by a DomainConfig
		filelocation := status.FileLocation
		if findActiveFileLocation(ctx, filelocation) {
			log.Debugln("gcObjects skipping Active file",
				filelocation)
			status.LastUse = time.Now()
			publishImageStatus(ctx, &status)
			continue
		}
		if status.RefCount != 0 {
			log.Debugf("gcObjects: skipping RefCount %d: %s\n",
				status.RefCount, status.Key())
			continue
		}
		timePassed := time.Since(status.LastUse)
		timeLimit := time.Duration(ctx.vdiskGCTime) * time.Second
		if timePassed < timeLimit {
			log.Debugf("gcObjects: skipping recently used %s remains %d seconds\n",
				status.Key(), (timePassed-timeLimit)/time.Second)
			continue
		}
		log.Infof("gcObjects: removing %s LastUse %v now %v: %s\n",
			filelocation, status.LastUse, time.Now(), status.Key())
		if err := os.Remove(filelocation); err != nil {
			log.Errorln(err)
		}
		unpublishImageStatus(ctx, &status)
	}
}

// Check if the filename is used as ActiveFileLocation
func findActiveFileLocation(ctx *domainContext, filename string) bool {
	log.Debugf("findActiveFileLocation(%v)\n", filename)
	pub := ctx.pubDomainStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.DomainStatus)
		for _, ds := range status.DiskStatusList {
			if filename == ds.ActiveFileLocation {
				return true
			}
		}
	}
	return false
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

func publishImageStatus(ctx *domainContext, status *types.ImageStatus) {

	key := status.Key()
	log.Debugf("publishImageStatus(%s)\n", key)
	pub := ctx.pubImageStatus
	pub.Publish(key, *status)
}

func unpublishImageStatus(ctx *domainContext, status *types.ImageStatus) {

	key := status.Key()
	log.Debugf("unpublishImageStatus(%s)\n", key)
	pub := ctx.pubImageStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishImageStatus(%s) not found\n", key)
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

// doStopDestroyDomain will destroy the domain of an instance if qemu is crashed
func doStopDestroyDomain(status *types.DomainStatus) {
	err := DomainDestroy(*status)
	if err != nil {
		log.Errorf("DomainDestroy %s failed: %s\n", status.DomainName, err)
	}
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

	domainID, err := xlDomid(status.DomainName, status.DomainId)
	if err != nil {
		if status.Activated && configActivate {
			errStr := fmt.Sprintf("verifyStatus(%s) failed %s",
				status.Key(), err)
			log.Warnln(errStr)
			status.Activated = false
			status.State = types.HALTED
			if status.IsContainer {
				status.LastErr = "container exited - please restart application instance"
				status.LastErrTime = time.Now()
			}
		}
		status.DomainId = 0
		publishDomainStatus(ctx, status)
	} else {
		if !status.Activated {
			log.Warnf("verifyDomain(%s) domain came back alive; id  %d\n",
				status.Key(), domainID)
			status.LastErr = ""
			status.LastErrTime = time.Time{}
			status.DomainId = domainID
			status.Activated = true
			status.State = types.RUNNING
			publishDomainStatus(ctx, status)
		} else if domainID != status.DomainId {
			// XXX shutdown + create?
			log.Warnf("verifyDomain(%s) domainID changed from %d to %d\n",
				status.Key(), status.DomainId, domainID)
			status.DomainId = domainID
			publishDomainStatus(ctx, status)
		}
		// check if qemu processes has crashed
		hasQemu := status.VirtualizationMode == types.HVM || status.VirtualizationMode == types.FML || status.IsContainer
		if configActivate && status.Activated && hasQemu && !isQemuRunning(status.DomainId) {
			errStr := fmt.Sprintf("verifyStatus(%s) qemu crashed",
				status.Key())
			log.Errorf(errStr)
			status.LastErr = "qemu crashed - please restart application instance"
			status.LastErrTime = time.Now()
			status.Activated = false
			status.State = types.HALTED
			publishDomainStatus(ctx, status)
			doStopDestroyDomain(status)
		}
	}
}

func isQemuRunning(domid int) bool {
	// create pgrep command to see if dataplane is running
	match := fmt.Sprintf("domid %d", domid)
	cmd := wrap.Command("pgrep", "-f", match)

	// pgrep returns 0 when there is atleast one matching program running
	// cmd.Output returns nil when pgrep returns 0, otherwise pids.
	out, err := cmd.Output()

	if err != nil {
		log.Infof("isQemuRunning: %s process is not running: %s",
			match, err)
		return false
	}
	log.Infof("isQemuRunning: Instances of %s is running: %s",
		match, out)
	return true
}

func maybeRetry(ctx *domainContext, status *types.DomainStatus) {

	maybeRetryBoot(ctx, status)
	maybeRetryAdapters(ctx, status)
}

func maybeRetryBoot(ctx *domainContext, status *types.DomainStatus) {

	if !status.BootFailed {
		return
	}

	t := time.Now()
	elapsed := t.Sub(status.LastErrTime)
	timeLimit := time.Duration(ctx.domainBootRetryTime) * time.Second
	if elapsed < timeLimit {
		log.Infof("maybeRetryBoot(%s) %d remaining\n",
			status.Key(),
			(timeLimit-elapsed)/time.Second)
		return
	}
	log.Infof("maybeRetryBoot(%s) after %s at %v\n",
		status.Key(), status.LastErr, status.LastErrTime)

	status.LastErr = ""
	status.LastErrTime = time.Time{}
	status.TriedCount += 1

	ctx.createSema.V(1)
	domainID, err := DomainCreate(*status)
	ctx.createSema.P(1)
	if err != nil {
		log.Errorf("maybeRetryBoot DomainCreate for %s: %s\n",
			status.DomainName, err)
		status.BootFailed = true
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		publishDomainStatus(ctx, status)
		return
	}
	status.BootFailed = false
	doActivateTail(ctx, status, domainID)
}

func maybeRetryAdapters(ctx *domainContext, status *types.DomainStatus) {

	if !status.AdaptersFailed {
		return
	}
	log.Infof("maybeRetryAdapters(%s) after %s at %v\n",
		status.Key(), status.LastErr, status.LastErrTime)

	config := lookupDomainConfig(ctx, status.Key())
	if config == nil {
		log.Errorf("maybeRetryAdapters(%s) no DomainConfig\n",
			status.Key())
		return
	}
	if err := configAdapters(ctx, *config); err != nil {
		log.Errorf("Failed to reserve adapters for %v: %s\n",
			config, err)
		status.PendingAdd = false
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.AdaptersFailed = true
		publishDomainStatus(ctx, status)
		cleanupAdapters(ctx, config.IoAdapterList,
			config.UUIDandVersion.UUID)
		return
	}
	status.AdaptersFailed = false
	status.LastErr = ""
	status.LastErrTime = time.Time{}

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
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		publishDomainStatus(ctx, &status)
		return
	}

	// Do we need to copy any rw files? !Preserve ones are copied upon
	// activation.
	for _, ds := range status.DiskStatusList {
		if ds.Format == zconfig.Format_CONTAINER {
			continue
		}
		if ds.ReadOnly || !ds.Preserve {
			continue
		}
		log.Infof("Potentially copy from %s to %s\n", ds.FileLocation, ds.ActiveFileLocation)
		if _, err := os.Stat(ds.ActiveFileLocation); err == nil {
			if ds.Preserve {
				log.Infof("Preserve and target exists - skip copy\n")
			} else {
				log.Infof("Not preserve and target exists - assume rebooted and preserve\n")
			}
		} else {
			log.Infof("Copy from %s to %s\n", ds.FileLocation, ds.ActiveFileLocation)
			if err := cp(ds.ActiveFileLocation, ds.FileLocation); err != nil {
				log.Errorf("Copy failed from %s to %s: %s\n",
					ds.FileLocation, ds.ActiveFileLocation, err)
				status.PendingAdd = false
				status.LastErr = fmt.Sprintf("%v", err)
				status.LastErrTime = time.Now()
				publishDomainStatus(ctx, &status)
				return
			}
			// Do we need to expand disk?
			err := maybeResizeDisk(ds.ActiveFileLocation,
				ds.Maxsizebytes)
			if err != nil {
				errStr := fmt.Sprintf("handleCreate(%s) failed %v",
					status.Key(), err)
				log.Errorln(errStr)
				status.LastErr = errStr
				status.LastErrTime = time.Now()
				status.PendingAdd = false
				publishDomainStatus(ctx, &status)
				return
			}
			log.Infof("Copy DONE from %s to %s\n",
				ds.FileLocation, ds.ActiveFileLocation)
		}
		addImageStatus(ctx, ds.ActiveFileLocation)
	}

	if err := configAdapters(ctx, *config); err != nil {
		log.Errorf("Failed to reserve adapters for %v: %s\n",
			config, err)
		status.PendingAdd = false
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
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
		list := ctx.assignableAdapters.LookupIoBundleGroup(adapter.Name)
		if len(list) == 0 {
			continue
		}
		for _, ib := range list {
			if ib.UsedByUUID != myUuid {
				continue
			}
			log.Infof("cleanupAdapters clearing uuid for adapter %d %s member %s",
				adapter.Type, adapter.Name, ib.Name)
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
		list := aa.LookupIoBundleGroup(adapter.Name)
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
					ib.Name, ib.PciLong, status.DomainName)
				assignments = addNoDuplicate(assignments, ib.PciLong)
				ib.IsPCIBack = true
				publishAssignableAdapters = true
			}
		}
	}
	for i, long := range assignments {
		err := pciAssignableAdd(long)
		if err != nil {
			// Undo what we assigned
			for j, long := range assignments {
				if j >= i {
					break
				}
				pciAssignableRemove(long)
			}
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
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
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
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

	// Assign any I/O devices
	doAssignIoAdaptersToDomain(ctx, config, status)

	// Do we need to copy any rw files? Preserve ones are copied upon
	// creation
	var containerImageSha256 string
	for _, ds := range status.DiskStatusList {
		if ds.Format == zconfig.Format_CONTAINER {
			containerImageSha256 = ds.ImageSha256
			continue
		}
		if ds.ReadOnly || ds.Preserve {
			continue
		}
		log.Infof("Potentially copy from %s to %s\n", ds.FileLocation, ds.ActiveFileLocation)
		if _, err := os.Stat(ds.ActiveFileLocation); err == nil && ds.Preserve {
			log.Infof("Preserve and target exists - skip copy\n")
		} else {
			log.Infof("Copy from %s to %s\n", ds.FileLocation, ds.ActiveFileLocation)
			if err := cp(ds.ActiveFileLocation, ds.FileLocation); err != nil {
				log.Errorf("Copy failed from %s to %s: %s\n",
					ds.FileLocation, ds.ActiveFileLocation, err)
				status.LastErr = fmt.Sprintf("%v", err)
				status.LastErrTime = time.Now()
				return
			}
			log.Infof("Copy DONE from %s to %s\n",
				ds.FileLocation, ds.ActiveFileLocation)
		}
		addImageStatus(ctx, ds.ActiveFileLocation)
	}

	filename := xenCfgFilename(config.AppNum)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal("os.Create for ", filename, err)
	}
	defer file.Close()

	if err := configToXencfg(config, *status, ctx.assignableAdapters,
		file); err != nil {
		log.Errorf("Failed to create DomainStatus from %v\n", config)
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		return
	}

	// FIXME: this will go away once we do a proper volumemanager
	// Handle creating of rootFS bundle for containers
	if status.IsContainer {
		podUUID, err := ctrPrepare(containerImageSha256, status)
		if err != nil {
			log.Errorf("Failed to create ctr bundle from %v\n", config)
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
			return
		}

		file.WriteString(fmt.Sprintf("p9=[ 'tag=share_dir,security_model=none,path=%s']\n", getContainerRootfs(podUUID)))

		status.PodUUID = podUUID
	}

	status.TriedCount = 0
	var domainID int
	// Invoke xl create; try 3 times with a timeout
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
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
			publishDomainStatus(ctx, status)
			return
		}
		log.Warnf("Retry xl create for %s: failed %s\n",
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
	status.Activated = true
	status.BootTime = time.Now()
	status.State = types.BOOTING
	publishDomainStatus(ctx, status)

	// Disable offloads for all vifs
	err := xlDisableVifOffload(status.DomainName, domainID,
		len(status.VifList))
	if err != nil {
		// XXX continuing even if we get a failure?
		log.Errorf("xlDisableVifOffload for %s: %s\n",
			status.DomainName, err)
	}
	err = xlUnpause(status.DomainName, domainID)
	if err != nil {
		// XXX shouldn't we destroy it?
		log.Errorf("xl unpause for %s: %s\n", status.DomainName, err)
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		return
	}
	// The -emu interfaces were most likely created as result of the boot so we
	// update VifUsed here.
	status.VifList = checkIfEmu(status.VifList)

	status.State = types.RUNNING
	// XXX dumping status to log
	xlStatus(status.DomainName, status.DomainId)

	domainID, err = xlDomid(status.DomainName, status.DomainId)
	if err == nil && domainID != status.DomainId {
		status.DomainId = domainID
	}
	log.Infof("doActivateTail(%v) done for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

// shutdown and wait for the domain to go away; if that fails destroy and wait
func doInactivate(ctx *domainContext, status *types.DomainStatus, impatient bool) {

	log.Infof("doInactivate(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)
	domainID, err := xlDomid(status.DomainName, status.DomainId)
	if err == nil && domainID != status.DomainId {
		status.DomainId = domainID
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
		err := DomainDestroy(*status)
		if err != nil {
			log.Errorf("DomainDestroy %s failed: %s\n",
				status.DomainName, err)
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
		log.Errorln(errStr)
		status.LastErr = errStr
		status.LastErrTime = time.Now()
	} else {
		status.Activated = false
		status.State = types.HALTED
	}
	publishDomainStatus(ctx, status)

	// Do we need to delete any rw files that should
	// not be preserved across reboots?
	for _, ds := range status.DiskStatusList {
		if ds.Format == zconfig.Format_CONTAINER {
			continue
		}
		if !ds.ReadOnly && !ds.Preserve {
			log.Infof("Delete copy at %s\n", ds.ActiveFileLocation)
			if err := os.Remove(ds.ActiveFileLocation); err != nil {
				log.Errorln(err)
				// XXX return? Cleanup status?
			}
			delImageStatus(ctx, ds.ActiveFileLocation)
		}
	}
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
		list := aa.LookupIoBundleGroup(adapter.Name)
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
					ib.Name, ib.PciLong, status.DomainName)
				assignments = addNoDuplicate(assignments, ib.PciLong)

				ib.IsPCIBack = false
			}
			ib.UsedByUUID = nilUUID // XXX see comment above. Clear if usbAccess only?
		}
		checkIoBundleAll(ctx)
	}
	for _, long := range assignments {
		err := pciAssignableRemove(long)
		if err != nil && !ignoreErrors {
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
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

		target := ""
		if ds.Format != zconfig.Format_CONTAINER && !dc.ReadOnly {
			// XXX:Why are we excluding container images? Are they supposed to be
			//  readonly
			// Pick new location for a per-guest copy
			// Use App UUID to make sure name is the same even
			// after adds and deletes of instances and device reboots
			target = appRwImageName(dc.ImageSha256,
				config.UUIDandVersion.UUID.String(), dc.Format)
		}
		if _, err := os.Stat(target); err == nil && target != "" {
			log.Infof("using existing rw image file location %s for ImageID(%s), ImageSha256(%s)",
				target, ds.ImageID.String(), dc.ImageSha256)

			ds.ActiveFileLocation = target
			ds.FileLocation = target
		} else {
			if target != "" {
				log.Infof("XXX Did not find target at %s for ContainerImageId(%s), ImageSha256(%s)",
					target, ds.ImageID.String(), dc.ImageSha256)
			}
			log.Infof("getting image file location IsContainer(%v), ContainerImageId(%s), ImageSha256(%s)",
				status.IsContainer, ds.ImageID.String(), dc.ImageSha256)
			location, err := utils.VerifiedImageFileLocation(ds.ImageSha256)
			if err != nil {
				log.Errorf("configToStatus: Failed to get Image File Location (target %s) err: %s",
					target, err)
				return err
			}
			ds.FileLocation = location
			if target != "" {
				ds.ActiveFileLocation = target
			} else {
				ds.ActiveFileLocation = location
			}
		}

	}
	if numOfContainerDisks > 1 {
		err := `Bundle contains more than one container disk, running multiple containers
				inside a pod is not supported now.`
		log.Errorf(err)
		return fmt.Errorf(err)
	}
	// XXX could defer to Activate
	if config.IsCipher || config.CloudInitUserData != nil {
		if status.IsContainer {
			envList, err := fetchEnvVariablesFromCloudInit(config)
			if err != nil {
				return err
			}
			status.EnvVariables = envList
		} else {
			ds, err := createCloudInitISO(config)
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
		list := ctx.assignableAdapters.LookupIoBundleGroup(adapter.Name)
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
			if isPort(ctx, ibp.Name) {
				return fmt.Errorf("adapter %d %s member %s is (part of) a zedrouter port",
					adapter.Type, adapter.Name, ibp.Name)
			}
		}
		for _, ibp := range list {
			if ibp == nil {
				continue
			}
			log.Debugf("configAdapters setting uuid %s for adapter %d %s member %s",
				config.Key(), adapter.Type, adapter.Name, ibp.Name)
			ibp.UsedByUUID = config.UUIDandVersion.UUID
		}
	}
	return nil
}

func createMountPointExecEnvFiles(rootFs string, mountpoints, execpath []string, workdir string, env []KeyValue, status *types.DomainStatus) error {
	mpFileName := rootFs + "/mountPoints"
	cmdFileName := rootFs + "/cmdline"
	envFileName := rootFs + "/environment"

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
	noOfDisks := len(status.DiskStatusList) - 1

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

	for i, mp := range mountpoints {
		if mp == "" {
			err := fmt.Errorf("createMountPointExecEnvFiles: targetPath cannot be empty")
			log.Errorf(err.Error())
			return err
		} else if !strings.HasPrefix(mp, "/") {
			//Target path is expected to be absolute.
			err := fmt.Errorf("createMountPointExecEnvFiles: targetPath should be absolute")
			log.Errorf(err.Error())
			return err
		}
		log.Infof("createMountPointExecEnvFiles: Processing mount point %d: %s\n", i, mp)
		if _, err := mpFile.WriteString(fmt.Sprintf("%s\n", mp)); err != nil {
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
		envContent = envContent + fmt.Sprintf("export %s=\"%s\"\n", e.Name, e.Value)
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
	imgInfo, err := diskmetrics.GetImgInfo(diskStatus.ActiveFileLocation)
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

// Produce the xen cfg file based on the config and status created above
// XXX or produce output to a string instead of file to make comparison
// easier?
func configToXencfg(config types.DomainConfig, status types.DomainStatus,
	aa *types.AssignableAdapters, file *os.File) error {

	xen_type := "pvh"
	rootDev := ""
	extra := ""
	bootLoader := ""
	kernel := ""
	ramdisk := config.Ramdisk
	vif_type := "vif"
	xen_global := ""
	uuidStr := fmt.Sprintf("appuuid=%s ", config.UUIDandVersion.UUID)

	switch status.VirtualizationMode {
	case types.PV:
		xen_type = "pvh"
		extra = "console=hvc0 " + uuidStr + config.ExtraArgs
		kernel = "/usr/lib/xen/boot/ovmf-pvh.bin"
	case types.HVM:
		xen_type = "hvm"
		if config.Kernel != "" {
			kernel = config.Kernel
		}
	case types.FML:
		xen_type = "hvm"
		vif_type = "ioemu"
		xen_global = "hdtype = \"ahci\"\nspoof_xen = 1\npci_permissive = 1\n"
	default:
		log.Errorf("Internal error: Unknown virtualizationMode %d",
			status.VirtualizationMode)
	}

	if status.IsContainer {
		kernel = "/hostfs/boot/kernel"
		ramdisk = "/usr/lib/xen/boot/runx-initrd"
		extra = extra + " root=9p dhcp=1"
	}

	file.WriteString("# This file is automatically generated by domainmgr\n")
	file.WriteString(fmt.Sprintf("name = \"%s\"\n", status.DomainName))
	file.WriteString(fmt.Sprintf("type = \"%s\"\n", xen_type))
	file.WriteString(fmt.Sprintf("uuid = \"%s\"\n",
		config.UUIDandVersion.UUID))
	file.WriteString(xen_global)

	if kernel != "" {
		file.WriteString(fmt.Sprintf("kernel = \"%s\"\n", kernel))
	}

	if ramdisk != "" {
		file.WriteString(fmt.Sprintf("ramdisk = \"%s\"\n", ramdisk))
	}

	if bootLoader != "" {
		file.WriteString(fmt.Sprintf("bootloader = \"%s\"\n",
			bootLoader))
	}
	if config.EnableVnc {
		file.WriteString(fmt.Sprintf("vnc = 1\n"))
		file.WriteString(fmt.Sprintf("vnclisten = \"0.0.0.0\"\n"))
		file.WriteString(fmt.Sprintf("usb=1\n"))
		file.WriteString(fmt.Sprintf("usbdevice=[\"tablet\"]\n"))

		if config.VncDisplay != 0 {
			file.WriteString(fmt.Sprintf("vncdisplay = %d\n",
				config.VncDisplay))
		}
		if config.VncPasswd != "" {
			file.WriteString(fmt.Sprintf("vncpasswd = \"%s\"\n",
				config.VncPasswd))
		}
	} else {
		file.WriteString(fmt.Sprintf("vnc = 0\n"))
	}

	// Go from kbytes to mbytes
	kbyte2mbyte := func(kbyte int) int {
		return (kbyte + 1023) / 1024
	}
	file.WriteString(fmt.Sprintf("memory = %d\n",
		kbyte2mbyte(config.Memory)))
	if config.MaxMem != 0 {
		file.WriteString(fmt.Sprintf("maxmem = %d\n",
			kbyte2mbyte(config.MaxMem)))
	}
	vCpus := config.VCpus
	if vCpus == 0 {
		vCpus = 1
	}
	file.WriteString(fmt.Sprintf("vcpus = %d\n", vCpus))
	maxCpus := config.MaxCpus
	if maxCpus == 0 {
		maxCpus = vCpus
	}
	file.WriteString(fmt.Sprintf("maxcpus = %d\n", maxCpus))
	if config.CPUs != "" {
		file.WriteString(fmt.Sprintf("cpus = \"%s\"\n", config.CPUs))
	}
	if config.DeviceTree != "" {
		file.WriteString(fmt.Sprintf("device_tree = \"%s\"\n",
			config.DeviceTree))
	}
	dtString := ""
	for _, dt := range config.DtDev {
		if dtString != "" {
			dtString += ","
		}
		dtString += fmt.Sprintf("\"%s\"", dt)
	}
	if dtString != "" {
		file.WriteString(fmt.Sprintf("dtdev = [%s]\n", dtString))
	}
	// Note that qcow2 images might have partitions hence xvda1 by default
	if rootDev != "" {
		file.WriteString(fmt.Sprintf("root = \"%s\"\n", rootDev))
	}
	if extra != "" {
		file.WriteString(fmt.Sprintf("extra = \"%s\"\n", extra))
	}
	// XXX Should one be able to disable the serial console? Would need
	// knob in manifest

	var serialAssignments []string
	serialAssignments = append(serialAssignments, "pty")

	// Always prefer CDROM vdisk over disk
	file.WriteString(fmt.Sprintf("boot = \"%s\"\n", "dc"))

	diskString := ""
	for i, ds := range status.DiskStatusList {
		if ds.Format == zconfig.Format_CONTAINER {
			continue
		}
		err := checkDiskFormat(ds)
		if err != nil {
			log.Errorf("%v", err)
			return err
		}
		access := "rw"
		if ds.ReadOnly {
			access = "ro"
		}
		oneDisk := fmt.Sprintf("'%s,%s,%s,%s'",
			ds.ActiveFileLocation, strings.ToLower(ds.Format.String()), ds.Vdev, access)
		log.Debugf("Processing disk %d: %s\n", i, oneDisk)
		if diskString == "" {
			diskString = oneDisk
		} else {
			diskString = diskString + ", " + oneDisk
		}
	}
	file.WriteString(fmt.Sprintf("disk = [%s]\n", diskString))

	vifString := ""
	for _, net := range config.VifList {
		oneVif := fmt.Sprintf("'bridge=%s,vifname=%s,mac=%s,type=%s'",
			net.Bridge, net.Vif, net.Mac, vif_type)
		if vifString == "" {
			vifString = oneVif
		} else {
			vifString = vifString + ", " + oneVif
		}
	}
	file.WriteString(fmt.Sprintf("vif = [%s]\n", vifString))

	imString := ""
	for _, im := range config.IOMem {
		if imString != "" {
			imString += ","
		}
		imString += fmt.Sprintf("\"%s\"", im)
	}
	if imString != "" {
		file.WriteString(fmt.Sprintf("iomem = [%s]\n", imString))
	}

	// Gather all PCI assignments into a single line
	// Also irqs, ioports, and serials
	// irqs and ioports are used if we are pv; serials if hvm
	var pciAssignments []typeAndPCI
	var irqAssignments []string
	var ioportsAssignments []string

	for _, irq := range config.IRQs {
		irqString := fmt.Sprintf("%d", irq)
		irqAssignments = addNoDuplicate(irqAssignments, irqString)
	}
	for _, adapter := range config.IoAdapterList {
		log.Debugf("configToXenCfg processing adapter %d %s\n",
			adapter.Type, adapter.Name)
		list := aa.LookupIoBundleGroup(adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if len(list) == 0 {
			log.Fatalf("configToXencfg IoBundle disappeared %d %s for %s\n",
				adapter.Type, adapter.Name, status.DomainName)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				log.Fatalf("configToXencfg IoBundle not ours %s: %d %s for %s\n",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					status.DomainName)
			}
			if ib.PciLong != "" {
				tap := typeAndPCI{pciLong: ib.PciLong, ioType: ib.Type}
				pciAssignments = addNoDuplicatePCI(pciAssignments, tap)
			}
			if ib.Irq != "" && status.VirtualizationMode == types.PV {
				log.Infof("Adding irq <%s>\n", ib.Irq)
				irqAssignments = addNoDuplicate(irqAssignments,
					ib.Irq)
			}
			if ib.Ioports != "" && status.VirtualizationMode == types.PV {
				log.Infof("Adding ioport <%s>\n", ib.Ioports)
				ioportsAssignments = addNoDuplicate(ioportsAssignments, ib.Ioports)
			}
			if ib.Serial != "" && (status.VirtualizationMode == types.HVM || status.VirtualizationMode == types.FML) {
				log.Infof("Adding serial <%s>\n", ib.Serial)
				serialAssignments = addNoDuplicate(serialAssignments, ib.Serial)
			}
		}
	}
	if len(pciAssignments) != 0 {
		log.Infof("PCI assignments %v\n", pciAssignments)
		cfg := fmt.Sprintf("pci = [ ")
		for i, pa := range pciAssignments {
			if i != 0 {
				cfg = cfg + ", "
			}
			short := types.PCILongToShort(pa.pciLong)
			// USB controller are subject to legacy USB support from
			// some BIOS. Use relaxed to get past that.
			if pa.ioType == types.IoUSB {
				cfg = cfg + fmt.Sprintf("'%s,rdm_policy=relaxed'",
					short)
			} else {
				cfg = cfg + fmt.Sprintf("'%s'", short)
			}
		}
		cfg = cfg + "]"
		log.Debugf("Adding pci config <%s>\n", cfg)
		file.WriteString(fmt.Sprintf("%s\n", cfg))
	}
	irqString := ""
	for _, irq := range irqAssignments {
		if irqString != "" {
			irqString += ","
		}
		irqString += irq
	}
	if irqString != "" {
		file.WriteString(fmt.Sprintf("irqs = [%s]\n", irqString))
	}
	ioportString := ""
	for _, ioports := range ioportsAssignments {
		if ioportString != "" {
			ioportString += ","
		}
		ioportString += ioports
	}
	if ioportString != "" {
		file.WriteString(fmt.Sprintf("ioports = [%s]\n", ioportString))
	}
	serialString := ""
	for _, serial := range serialAssignments {
		if serialString != "" {
			serialString += ","
		}
		serialString += "'" + serial + "'"
	}
	if serialString != "" {
		file.WriteString(fmt.Sprintf("serial = [%s]\n", serialString))
	}
	// XXX log file content: log.Infof("Created %s: %s
	return nil
}

type typeAndPCI struct {
	pciLong string
	ioType  types.IoType
}

func addNoDuplicatePCI(list []typeAndPCI, tap typeAndPCI) []typeAndPCI {

	for _, t := range list {
		if t.pciLong == tap.pciLong {
			return list
		}
	}
	return append(list, tap)
}

func addNoDuplicate(list []string, add string) []string {

	for _, s := range list {
		if s == add {
			return list
		}
	}
	return append(list, add)
}

func cp(dst, src string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	// no need to check errors on read only file, we already got everything
	// we need from the filesystem, so nothing can go wrong now.
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(d, s); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// Need to compare what might have changed. If any content change
// then we need to reboot. Thus version can change but can't handle disk or
// vif changes.
// XXX should we reboot if there are such changes? Or reject with error?
func handleModify(ctx *domainContext, key string,
	config *types.DomainConfig, status *types.DomainStatus) {

	log.Infof("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	status.PendingModify = true
	publishDomainStatus(ctx, status)

	changed := false
	if config.Activate && !status.Activated {
		// AppNum could have changed if we did not already Activate
		name := config.DisplayName + "." + strconv.Itoa(config.AppNum)
		status.DomainName = name
		status.AppNum = config.AppNum
		status.VifList = checkIfEmu(config.VifList)
		publishDomainStatus(ctx, status)
		log.Infof("handleModify(%v) set domainName %s for %s\n",
			config.UUIDandVersion, status.DomainName,
			config.DisplayName)

		// This has the effect of trying a boot again for any
		// handleModify after an error.
		if status.LastErr != "" {
			log.Infof("handleModify(%v) ignoring existing error for %s\n",
				config.UUIDandVersion, config.DisplayName)
			status.LastErr = ""
			status.LastErrTime = time.Time{}
			publishDomainStatus(ctx, status)
			doInactivate(ctx, status, false)
		}
		updateStatusFromConfig(status, *config)
		doActivate(ctx, *config, status)
		changed = true
	} else if !config.Activate {
		if status.LastErr != "" {
			log.Infof("handleModify(%v) clearing existing error for %s\n",
				config.UUIDandVersion, config.DisplayName)
			status.LastErr = ""
			status.LastErrTime = time.Time{}
			publishDomainStatus(ctx, status)
			doInactivate(ctx, status, false)
			updateStatusFromConfig(status, *config)
			changed = true
		} else if status.Activated {
			doInactivate(ctx, status, false)
			updateStatusFromConfig(status, *config)
			changed = true
		}
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

	// XXX check if we have status.LastErr != "" and delete and retry
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
	// If different then stop and start. XXX xl shutdown takes a while
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
		if err := xlStatus(status.DomainName, status.DomainId); err != nil {
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

func deleteStorageDisksForDomain(ctx *domainContext,
	statusPtr *types.DomainStatus) {
	if statusPtr.IsContainer {
		log.Debugf("Container. Not deleting any images")
	}
	for _, ds := range statusPtr.DiskStatusList {
		if !ds.ReadOnly && ds.Preserve {
			log.Infof("Delete copy at %s\n", ds.ActiveFileLocation)
			if err := os.Remove(ds.ActiveFileLocation); err != nil {
				log.Errorln(err)
				// XXX return? Cleanup status?
			}
			delImageStatus(ctx, ds.ActiveFileLocation)
		}
	}
}

func handleDelete(ctx *domainContext, key string, status *types.DomainStatus) {

	log.Infof("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	// XXX dumping status to log
	xlStatus(status.DomainName, status.DomainId)

	status.PendingDelete = true
	publishDomainStatus(ctx, status)

	if status.Activated {
		doInactivate(ctx, status, true)
	} else {
		if status.IsContainer {
			// Use ctr to remove already exited or inactivated container apps
			log.Infof("Using ctr to remove already exited container app ... PodUUID - %s\n", status.PodUUID)
			err := ctrRm(status.PodUUID)
			if err != nil {
				log.Errorf("ctrRm %s failed: %s\n",
					status.DomainName, err)
			}
		}
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

	// Do we need to delete any rw files that were not deleted during
	// inactivation i.e. those preserved across reboots?
	deleteStorageDisksForDomain(ctx, status)

	status.PendingDelete = false
	publishDomainStatus(ctx, status)
	// Write out what we modified to DomainStatus aka delete
	unpublishDomainStatus(ctx, status)
	log.Infof("handleDelete(%v) DONE for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

// DomainCreate is a wrapper for domain creation thru xlCreate or ctrPrepare + xlCreate
// returns domainID, PodUUID and error
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

	// Use xl tool
	log.Infof("Using xl tool ... xenCfgFilename - %s\n", filename)
	domainID, err = xlCreate(status.DomainName, filename)

	return domainID, err
}

// Create in paused state; Need to call xlUnpause later
func xlCreate(domainName string, xenCfgFilename string) (int, error) {
	log.Infof("xlCreate %s %s\n", domainName, xenCfgFilename)
	cmd := "xl"
	args := []string{
		"create",
		xenCfgFilename,
		"-p",
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl create failed ", err)
		log.Errorln("xl create output ", string(stdoutStderr))
		return 0, fmt.Errorf("xl create failed: %s\n",
			string(stdoutStderr))
	}
	log.Infof("xl create done\n")

	args = []string{
		"domid",
		domainName,
	}
	stdoutStderr, err = wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl domid failed ", err)
		log.Errorln("xl domid output ", string(stdoutStderr))
		return 0, fmt.Errorf("xl domid failed: %s\n",
			string(stdoutStderr))
	}
	res := strings.TrimSpace(string(stdoutStderr))
	domainID, err := strconv.Atoi(res)
	if err != nil {
		log.Errorf("Can't extract domainID from %s: %s\n", res, err)
		return 0, fmt.Errorf("Can't extract domainID from %s: %s\n", res, err)
	}
	return domainID, nil
}

func xlStatus(domainName string, domainID int) error {
	log.Infof("xlStatus %s %d\n", domainName, domainID)
	// XXX xl list -l domainName returns json. XXX but state not included!
	// Note that state is not very useful anyhow
	cmd := "xl"
	args := []string{
		"list",
		"-l",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl list failed ", err)
		log.Errorln("xl list output ", string(stdoutStderr))
		return fmt.Errorf("xl list failed: %s\n",
			string(stdoutStderr))
	}
	// XXX parse json to look at state? Not currently included
	// XXX note that there is a warning at the top of the combined
	// output. If we want to parse the json we need to get Output()
	log.Infof("xl list done. Result %s\n", string(stdoutStderr))
	return nil
}

// If we have a domain reboot issue the domainID
// can change.
func xlDomid(domainName string, domainID int) (int, error) {
	log.Debugf("xlDomid %s %d\n", domainName, domainID)
	cmd := "xl"
	args := []string{
		"domid",
		domainName,
	}
	// Avoid wrap since we are called periodically
	stdoutStderr, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Debugln("xl domid failed ", err)
		log.Debugln("xl domid output ", string(stdoutStderr))
		return domainID, fmt.Errorf("xl domid failed: %s\n",
			string(stdoutStderr))
	}
	res := strings.TrimSpace(string(stdoutStderr))
	domainID2, err := strconv.Atoi(res)
	if err != nil {
		log.Errorf("xl domid not integer %s: failed %s\n", res, err)
		return domainID, err
	}
	if domainID2 != domainID {
		log.Warningf("domainid changed from %d to %d for %s\n",
			domainID, domainID2, domainName)
	}
	return domainID2, err
}

// Perform xenstore write to disable all of these for all VIFs
// feature-sg, feature-gso-tcpv4, feature-gso-tcpv6, feature-ipv6-csum-offload
func xlDisableVifOffload(domainName string, domainID int, vifCount int) error {
	log.Infof("xlDisableVifOffload %s %d %d\n",
		domainName, domainID, vifCount)
	pref := "/local/domain"
	for i := 0; i < vifCount; i += 1 {
		varNames := []string{
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-sg",
				pref, domainID, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-gso-tcpv4",
				pref, domainID, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-gso-tcpv6",
				pref, domainID, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-ipv4-csum-offload",
				pref, domainID, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-ipv6-csum-offload",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-sg",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-gso-tcpv4",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-gso-tcpv6",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-ipv4-csum-offload",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-ipv6-csum-offload",
				pref, domainID, i),
		}
		for _, varName := range varNames {
			cmd := "xenstore"
			args := []string{
				"write",
				varName,
				"0",
			}
			stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
			if err != nil {
				log.Errorln("xenstore write failed ", err)
				log.Errorln("xenstore write output ", string(stdoutStderr))
				return fmt.Errorf("xenstore write failed: %s\n",
					string(stdoutStderr))
			}
			log.Debugf("xenstore write done. Result %s\n",
				string(stdoutStderr))
		}
	}

	log.Infof("xlDisableVifOffload done.\n")
	return nil
}

func xlUnpause(domainName string, domainID int) error {
	log.Infof("xlUnpause %s %d\n", domainName, domainID)
	cmd := "xl"
	args := []string{
		"unpause",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl unpause failed ", err)
		log.Errorln("xl unpause output ", string(stdoutStderr))
		return fmt.Errorf("xl unpause failed: %s\n",
			string(stdoutStderr))
	}
	log.Infof("xlUnpause done. Result %s\n", string(stdoutStderr))
	return nil
}

// DomainShutdown is a wrapper for domain shutdown thru xlShutdown
func DomainShutdown(status types.DomainStatus, force bool) error {

	var err error
	log.Infof("DomainShutdown force-%v %s %d\n", force, status.DomainName, status.DomainId)

	// Use xl tool
	log.Infof("Using xl tool ... DomainName - %s\n", status.DomainName)
	err = xlShutdown(status.DomainName, status.DomainId, force)

	return err
}

func xlShutdown(domainName string, domainID int, force bool) error {
	log.Infof("xlShutdown %s %d\n", domainName, domainID)
	cmd := "xl"
	var args []string
	if force {
		args = []string{
			"shutdown",
			"-F",
			domainName,
		}
	} else {
		args = []string{
			"shutdown",
			domainName,
		}
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl shutdown failed ", err)
		log.Errorln("xl shutdown output ", string(stdoutStderr))
		return fmt.Errorf("xl shutdown failed: %s\n",
			string(stdoutStderr))
	}
	log.Infof("xl shutdown done\n")
	return nil
}

// DomainDestroy is a wrapper for domain Destroy thru xlDestroy or ctrRm
func DomainDestroy(status types.DomainStatus) error {

	var err error
	log.Infof("DomainDestroy %s %d\n", status.DomainName, status.DomainId)

	if status.IsContainer {
		// Use ctr
		log.Infof("Using ctr tool ... PodUUID - %s\n", status.PodUUID)
		err = ctrRm(status.PodUUID)
	} else {
		// Use xl tool
		log.Infof("Using xl tool ... DomainName - %s\n", status.DomainName)
		err = xlDestroy(status.DomainName, status.DomainId)
	}

	return err
}

func xlDestroy(domainName string, domainID int) error {
	log.Infof("xlDestroy %s %d\n", domainName, domainID)
	cmd := "xl"
	args := []string{
		"destroy",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl destroy failed ", err)
		log.Errorln("xl destroy output ", string(stdoutStderr))
		return fmt.Errorf("xl destroy failed: %s\n",
			string(stdoutStderr))
	}
	log.Infof("xl destroy done\n")
	return nil
}

func pciAssignableAdd(long string) error {
	log.Infof("pciAssignableAdd %s\n", long)
	cmd := "xl"
	args := []string{
		"pci-assignable-add",
		long,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("xl pci-assignable-add failed: %s\n",
			string(stdoutStderr))
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Infof("xl pci-assignable-add done\n")
	return nil
}

func pciAssignableRemove(long string) error {
	log.Infof("pciAssignableRemove %s\n", long)
	cmd := "xl"
	args := []string{
		"pci-assignable-rem",
		"-r",
		long,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("xl pci-assignable-rem failed: %s\n",
			string(stdoutStderr))
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Infof("xl pci-assignable-rem done\n")
	return nil
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
	var gcp *types.GlobalConfig
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		if gcp.VdiskGCTime != 0 {
			ctx.vdiskGCTime = gcp.VdiskGCTime
		}
		if gcp.DomainBootRetryTime != 0 {
			ctx.domainBootRetryTime = gcp.DomainBootRetryTime
		}
		if gcp.UsbAccess != ctx.usbAccess {
			ctx.usbAccess = gcp.UsbAccess
			updateUsbAccess(ctx)
		}
		if gcp.MetricInterval != 0 {
			ctx.metricInterval = gcp.MetricInterval
		}
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s. VdiskGCTime: %d, "+
		"DomainBootRetryTime: %d, usbAccess: %t, metricInterval: %d, "+
		key, ctx.vdiskGCTime, ctx.domainBootRetryTime, ctx.usbAccess,
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

// Make sure the (virtual) size of the disk is at least maxsizebytes
func maybeResizeDisk(diskfile string, maxsizebytes uint64) error {
	if maxsizebytes == 0 {
		return nil
	}
	currentSize, err := diskmetrics.GetDiskVirtualSize(diskfile)
	if err != nil {
		return err
	}
	log.Infof("maybeResizeDisk(%s) current %d to %d",
		diskfile, currentSize, maxsizebytes)
	if maxsizebytes < currentSize {
		log.Warnf("maybeResizeDisk(%s) already above maxsize  %d vs. %d",
			diskfile, maxsizebytes, currentSize)
		return nil
	}
	err = diskmetrics.ResizeImg(diskfile, maxsizebytes)
	return err
}

// getCloudInitData : returns decrypted cloud-init data
func getCloudInitData(config types.DomainConfig) (*string, error) {
	if !config.IsCipher {
		return config.CloudInitUserData, nil
	}
	if !config.IsValidCipher {
		errStr := fmt.Sprintf("%s, Cipher Block is not ready", config.DisplayName)
		return nil, errors.New(errStr)
	}
	clearData, err := tpmmgr.DecryptCipherBlock(config.CipherBlock)
	if err != nil {
		log.Errorf("%s, cloud-init data decryption failed, %v\n",
			config.DisplayName, err)
		return nil, err
	}
	cloudInitData := base64.StdEncoding.EncodeToString(clearData)
	return &cloudInitData, nil
}

// Fetch the list of environment variables from the cloud init
// We are expecting the environment variables to be pass in particular format in cloud-int
// Example:
// Key1:Val1
// Key2:Val2 ...
func fetchEnvVariablesFromCloudInit(config types.DomainConfig) (map[string]string, error) {
	userData, err := getCloudInitData(config)
	if err != nil {
		errStr := fmt.Sprintf("%s, cloud-init data get failed %s\n",
			config.DisplayName, err)
		return nil, errors.New(errStr)
	}

	ud, err := base64.StdEncoding.DecodeString(*userData)
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
func createCloudInitISO(config types.DomainConfig) (*types.DiskStatus, error) {

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

	userData, err := getCloudInitData(config)
	if err != nil {
		return nil, err
	}
	ud, err := base64.StdEncoding.DecodeString(*userData)
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
	ds.ActiveFileLocation = fileName
	ds.Format = zconfig.Format_RAW
	ds.Vdev = "hdc:cdrom"
	ds.ReadOnly = false
	ds.Preserve = true // Prevent attempt to copy
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
		name := aa.IoBundleList[indx].Name
		phyAdapter := phyIOAdapterList.LookupAdapter(name)
		if phyAdapter == nil {
			deleteList = append(deleteList, name)
		}
	}
	for _, name := range deleteList {
		handleIBDelete(ctx, name)
	}

	// Any add or modify?
	for _, phyAdapter := range phyIOAdapterList.AdapterList {
		ib := *types.IoBundleFromPhyAdapter(phyAdapter)
		currentIbPtr := aa.LookupIoBundle(phyAdapter.Phylabel)
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
		name := phyAdapterList.AdapterList[indx].Phylabel
		log.Infof("handlePhysicalIOAdapterListDelete: Deleting Adapter %s\n",
			name)
		handleIBDelete(ctx, name)
	}
	ctx.publishAssignableAdapters()
	log.Infof("handlePhysicalIOAdapterListDelete done\n")
}

// Process new IoBundles. Check if PCI device exists, and check that not
// used in a DevicePortConfig/DeviceNetworkStatus
// Assign to pciback
func handleIBCreate(ctx *domainContext, ib types.IoBundle) {

	log.Infof("handleIBCreate(%d %s %s)", ib.Type, ib.Name, ib.AssignmentGroup)
	aa := ctx.assignableAdapters
	if err := checkAndSetIoBundle(ctx, &ib, false); err != nil {
		log.Warnf("Not reporting non-existent PCI device %d %s: %v\n",
			ib.Type, ib.Name, err)
		return
	}
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
		ib.Type, ib.Name, ib.AssignmentGroup, publish)
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
		if types.IsPort(ctx.deviceNetworkStatus, ib.Name) {
			isPort = true
		}
	}
	log.Infof("checkAndSetIoBundle(%d %s %s) isPort %t members %v",
		ib.Type, ib.Name, ib.AssignmentGroup, isPort, list)
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
		ib.Type, ib.Name, ib.AssignmentGroup, isPort, publish)
	aa := ctx.assignableAdapters
	// Check if part of DevicePortConfig
	ib.IsPort = false
	changed := false
	if isPort {
		log.Warnf("checkAndSetIoMember(%d %s %s) part of zedrouter port\n",
			ib.Type, ib.Name, ib.AssignmentGroup)
		ib.IsPort = true
		changed = true
		if ib.UsedByUUID != nilUUID {
			log.Errorf("checkAndSetIoMember(%d %s %s) used by %s",
				ib.Type, ib.Name, ib.AssignmentGroup,
				ib.UsedByUUID.String())

		} else if ib.IsPCIBack {
			log.Infof("checkAndSetIoMember(%d %s %s) take back from pciback\n",
				ib.Type, ib.Name, ib.AssignmentGroup)
			if ib.PciLong != "" {
				log.Infof("Removing %s (%s) from pciback\n",
					ib.Name, ib.PciLong)
				err := pciAssignableRemove(ib.PciLong)
				if err != nil {
					log.Errorf("checkAndSetIoMember(%d %s %s) pciAssignableRemove %s failed %v\n",
						ib.Type, ib.Name, ib.AssignmentGroup, ib.PciLong, err)
				}
				// Seems like like no risk for race; when we return
				// from above the driver has been attached and
				// any ifname has been registered.
				found, ifname := types.PciLongToIfname(ib.PciLong)
				if !found {
					log.Errorf("Not found: %d %s %s",
						ib.Type, ib.Name, ib.Ifname)
				} else if ifname != ib.Ifname {
					log.Warnf("Found: %d %s %s at %s",
						ib.Type, ib.Name, ib.Ifname,
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
					ib.Type, ib.Name, ib.AssignmentGroup, err)
			}
		}
	}
	if ib.Type.IsNet() && ib.MacAddr == "" {
		ib.MacAddr = getMacAddr(ib.Name)
		changed = true
		log.Infof("checkAndSetIoMember(%d %s %s) long %s macaddr %s",
			ib.Type, ib.Name, ib.AssignmentGroup, ib.PciLong, ib.MacAddr)
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
			ib.Type, ib.Name, ib.AssignmentGroup, long)

		// Save somewhat Unique string for debug
		found, unique := types.PciLongToUnique(long)
		if !found {
			errStr := fmt.Sprintf("IoBundle(%d %s %s) %s unique not found",
				ib.Type, ib.Name, ib.AssignmentGroup, long)
			log.Errorln(errStr)
		} else {
			ib.Unique = unique
			changed = true
			log.Infof("checkAndSetIoMember(%d %s %s) %s unique %s",
				ib.Type, ib.Name, ib.AssignmentGroup, long, unique)
		}
	} else {
		log.Infof("checkAndSetIoMember(%d %s %s) not found PCI",
			ib.Type, ib.Name, ib.AssignmentGroup)
	}

	if !ib.IsPort && !ib.IsPCIBack {
		if ctx.deviceNetworkStatus.Testing && ib.Type.IsNet() {
			log.Infof("Not assigning %s (%s) to pciback due to Testing\n",
				ib.Name, ib.PciLong)
		} else if ctx.usbAccess && isInUsbGroup(*aa, *ib) {
			log.Infof("Not assigning %s (%s) to pciback due to usbAccess\n",
				ib.Name, ib.PciLong)
		} else if ib.PciLong != "" {
			log.Infof("Assigning %s (%s) to pciback\n",
				ib.Name, ib.PciLong)
			err := pciAssignableAdd(ib.PciLong)
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
			ib.Type, ib.Name, ib.AssignmentGroup,
			long, ib.Unique)
		return errors.New(errStr)
	}
	if unique != ib.Unique && ib.Unique != "" {
		errStr := fmt.Sprintf("IoBundle(%d %s %s) changed unique from %s to %s",
			ib.Type, ib.Name, ib.AssignmentGroup,
			ib.Unique, unique)
		return errors.New(errStr)
	}
	if ib.Type.IsNet() && ib.MacAddr != "" {
		macAddr := getMacAddr(ib.Name)
		// Will be empty string if adapter is assigned away
		if macAddr != "" && macAddr != ib.MacAddr {
			errStr := fmt.Sprintf("IoBundle(%d %s %s) changed MacAddr from %s to %s",
				ib.Type, ib.Name, ib.AssignmentGroup,
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
				ib.Name, ib.PciLong)
			assignments = addNoDuplicate(assignments, ib.PciLong)
			ib.IsPCIBack = true
		}
	}
	for _, long := range assignments {
		err := pciAssignableAdd(long)
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
					ib.Name, ib.PciLong)
				assignments = addNoDuplicate(assignments, ib.PciLong)
				ib.IsPCIBack = false
			} else {
				log.Warnf("No removing %s (%s) from pciback: used by %s",
					ib.Name, ib.PciLong, ib.UsedByUUID)
			}
		}
	}
	for _, long := range assignments {
		err := pciAssignableRemove(long)
		if err != nil {
			log.Errorf("maybeAssignableRem remove failed: %s\n", err)
		}
	}
	if len(assignments) != 0 {
		ctx.publishAssignableAdapters()
	}
}

func handleIBDelete(ctx *domainContext, name string) {

	log.Infof("handleIBDelete(%s)", name)
	aa := ctx.assignableAdapters

	ib := aa.LookupIoBundle(name)
	if ib == nil {
		log.Infof("handleIBDelete: Adapter ( %s ) not found", name)
		return
	}

	if ib.IsPCIBack {
		log.Infof("handleIBDelete: Assigning %s (%s) back\n",
			ib.Name, ib.PciLong)
		if ib.PciLong != "" {
			err := pciAssignableRemove(ib.PciLong)
			if err != nil {
				log.Errorf("handleIBDelete(%d %s %s) pciAssignableRemove %s failed %v\n",
					ib.Type, ib.Name, ib.AssignmentGroup, ib.PciLong, err)
			}
			ib.IsPCIBack = false
		}
	}
	replace := types.AssignableAdapters{Initialized: true,
		IoBundleList: make([]types.IoBundle, len(aa.IoBundleList)-1)}
	for _, e := range aa.IoBundleList {
		if e.Type == ib.Type && e.Name == ib.Name {
			continue
		}
		replace.AddOrUpdateIoBundle(e)
	}
	*ctx.assignableAdapters = replace
	checkIoBundleAll(ctx)
}

func handleIBModify(ctx *domainContext, newIb types.IoBundle) {
	aa := ctx.assignableAdapters
	currentIbPtr := aa.LookupIoBundle(newIb.Name)
	if currentIbPtr == nil {
		log.Errorf("Failed to find IoBundle (%d %s).  aa: %+v\n",
			newIb.Type, newIb.Name, aa)
		return
	}

	log.Infof("handleIBModify(%d %s %s) from %v to %v\n",
		currentIbPtr.Type, currentIbPtr.Name, currentIbPtr.AssignmentGroup,
		*currentIbPtr, newIb)

	if err := checkAndSetIoBundle(ctx, &newIb, false); err != nil {
		log.Warnf("Not reporting non-existent PCI device %d %s: %v\n",
			newIb.Type, newIb.Name, err)
		return
	}

	// XXX can we have changes which require us to
	// do pciAssignableRemove for the old Adapter?
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
				ib.Name, m.Name)
			return true
		}
	}
	return false
}

// gc timer just started, reset the LastUse timestamp
func gcResetObjectsLastUse(ctx *domainContext, dirName string) {

	log.Debugf("gcResetObjectsLastUse()\n")

	pub := ctx.pubImageStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.ImageStatus)
		if status.RefCount == 0 {
			log.Infof("gcResetObjectsLastUse: reset %v LastUse to now\n", status.Key())
			status.LastUse = time.Now()
			publishImageStatus(ctx, &status)
		}
	}
}
