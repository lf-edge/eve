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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eriknordmark/netlink"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/adapters"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/sema"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	appImgObj = "appImg.obj"
	agentName = "domainmgr"

	tmpDirname        = "/var/tmp/zededa"
	AADirname         = tmpDirname + "/AssignableAdapters"
	runDirname        = "/var/run/" + agentName
	persistDir        = "/persist"
	rwImgDirname      = persistDir + "/img"       // We store images here
	xenDirname        = runDirname + "/xen"       // We store xen cfg files here
	ciDirname         = runDirname + "/cloudinit" // For cloud-init images
	downloadDirname   = persistDir + "/downloads"
	imgCatalogDirname = downloadDirname + "/" + appImgObj
	// Read-only images named based on sha256 hash each in its own directory
	verifiedDirname = imgCatalogDirname + "/verified"
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
	subDeviceNetworkStatus *pubsub.Subscription
	subDomainConfig        *pubsub.Subscription
	pubDomainStatus        *pubsub.Publication
	subGlobalConfig        *pubsub.Subscription
	pubImageStatus         *pubsub.Publication
	pubAssignableAdapters  *pubsub.Publication
	usbAccess              bool
	createSema             sema.Semaphore
}

func (ctx *domainContext) publishAssignableAdapters() {
	ctx.pubAssignableAdapters.Publish("global", ctx.assignableAdapters)
}

var debug = false
var debugOverride bool                                     // From command line arg
var vdiskGCTime = time.Duration(3600) * time.Second        // Unless from GlobalConfig
var domainBootRetryTime = time.Duration(600) * time.Second // Unless from GlobalConfig

func Run() {
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
	agentlog.StillRunning(agentName)

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
	if _, err := os.Stat(imgCatalogDirname); err != nil {
		if err := os.MkdirAll(imgCatalogDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(verifiedDirname); err != nil {
		if err := os.MkdirAll(verifiedDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	domainCtx := domainContext{usbAccess: true}
	// Allow only one concurrent xl create
	domainCtx.createSema = sema.Create(1)
	domainCtx.createSema.P(1)

	pubDomainStatus, err := pubsub.Publish(agentName, types.DomainStatus{})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubDomainStatus = pubDomainStatus
	pubDomainStatus.ClearRestarted()

	pubImageStatus, err := pubsub.Publish(agentName, types.ImageStatus{})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubImageStatus = pubImageStatus
	pubImageStatus.ClearRestarted()

	// Publish existing images with RefCount zero
	populateInitialImageStatus(&domainCtx, rwImgDirname)

	pubAssignableAdapters, err := pubsub.Publish(agentName,
		types.AssignableAdapters{})
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubAssignableAdapters = pubAssignableAdapters
	pubAssignableAdapters.ClearRestarted()

	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &domainCtx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	domainCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &domainCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	domainCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	model := hardware.GetHardwareModel()
	// Logic to fall back to default.json model if cloud sends wrong
	// model string
	tries := 0
	for {
		AAFilename := fmt.Sprintf("%s/%s.json", AADirname, model)
		if _, err := os.Stat(AAFilename); err == nil {
			break
		}
		log.Warningln(err)
		log.Warningf("You need to create this file for this hardware: %s\n",
			AAFilename)
		time.Sleep(time.Second)
		tries += 1
		if tries == 10 { // 10 Seconds
			log.Infof("Falling back to using hardware model default\n")
			model = "default"
		}
	}

	aa := types.AssignableAdapters{}
	domainCtx.assignableAdapters = &aa

	// Wait for DeviceNetworkStatus to be init so we know the management
	// ports and then wait for assignableAdapters.
	for !domainCtx.DNSinitialized {

		log.Infof("Waiting for DeviceNetworkStatus init\n")
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
		}
	}

	// Pick up (mostly static) AssignableAdapters before we process
	// any DomainConfig
	var modifyFn adapters.ModifyHandler = handleAAModify
	var deleteFn adapters.DeleteHandler = handleAADelete
	subAa := adapters.Subscribe(&aa, model, &modifyFn, &deleteFn,
		&domainCtx)
	subAa.Activate()

	for !domainCtx.assignableAdapters.Initialized {

		log.Infof("Waiting for AssignableAdapters\n")
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAa.C:
			subAa.ProcessChange(change)
		}
	}
	log.Infof("Have %d assignable adapters\n", len(aa.IoBundleList))

	// Subscribe to DomainConfig from zedmanager
	subDomainConfig, err := pubsub.Subscribe("zedmanager",
		types.DomainConfig{}, false, &domainCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDomainConfig.ModifyHandler = handleDomainModify
	subDomainConfig.DeleteHandler = handleDomainDelete
	subDomainConfig.RestartHandler = handleRestart
	domainCtx.subDomainConfig = subDomainConfig
	subDomainConfig.Activate()

	// We will cleanup zero RefCount objects after a while
	// We run timer 10 times more often than the limit on LastUse
	gc := time.NewTicker(vdiskGCTime / 10)

	for {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDomainConfig.C:
			subDomainConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subAa.C:
			subAa.ProcessChange(change)

		case <-gc.C:
			gcObjects(&domainCtx, rwImgDirname)

		case <-stillRunning.C:
			agentlog.StillRunning(agentName)
		}
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
		size := int64(0)
		info, err := os.Stat(filelocation)
		if err != nil {
			log.Error(err)
		} else {
			size = info.Size()
		}
		log.Debugf("populateInitialImageStatus: Processing %d Mbytes %s \n",
			size/(1024*1024), filelocation)

		status := types.ImageStatus{
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
		status := types.ImageStatus{
			Filename:     filename,
			FileLocation: fileLocation,
			Size:         0, // XXX
			RefCount:     1,
			LastUse:      time.Now(),
		}
		publishImageStatus(ctx, &status)
	} else {
		status := cast.CastImageStatus(st)
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
	status := cast.CastImageStatus(st)
	log.Infof("delImageStatus(%s) found RefCount %d LastUse %v\n",
		filename, status.RefCount, status.LastUse)
	unpublishImageStatus(ctx, &status)
}

// Periodic garbage collection looking at RefCount=0 files
func gcObjects(ctx *domainContext, dirName string) {

	log.Debugf("gcObjects()\n")

	pub := ctx.pubImageStatus
	items := pub.GetAll()
	for key, st := range items {
		status := cast.CastImageStatus(st)
		if status.Key() != key {
			log.Errorf("gcObjects key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
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
				status.RefCount, key)
			continue
		}
		timePassed := time.Since(status.LastUse)
		if timePassed < vdiskGCTime {
			log.Debugf("gcObjects: skipping recently used %s remains %d seconds\n",
				key, (timePassed-vdiskGCTime)/time.Second)
			continue
		}
		log.Infof("gcObjects: removing %s LastUse %v now %v: %s\n",
			filelocation, status.LastUse, time.Now(), key)
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
	for key, st := range items {
		status := cast.CastDomainStatus(st)
		if status.Key() != key {
			log.Errorf("findActiveFileLocation key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
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
	pub.Publish(key, status)
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
	pub.Publish(key, status)
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

// We have one goroutine per provisioned domU object.
// Channel is used to send config (new and updates)
// Channel is closed when the object is deleted
// The go-routine owns writing status for the object
// The key in the map is the objects Key() - UUID in this case
type handlers map[string]chan<- interface{}

var handlerMap handlers

func handlersInit() {
	handlerMap = make(handlers)
}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func handleDomainModify(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("handleDomainModify(%s)\n", key)
	ctx := ctxArg.(*domainContext)
	config := cast.CastDomainConfig(configArg)
	if config.Key() != key {
		log.Errorf("handleDomainModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	// Do we have a channel/goroutine?
	h, ok := handlerMap[config.Key()]
	if !ok {
		h1 := make(chan interface{})
		handlerMap[config.Key()] = h1
		go runHandler(ctx, key, h1)
		h = h1
	}
	log.Debugf("Sending config to handler\n")
	h <- configArg
	log.Infof("handleDomainModify(%s) done\n", key)
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
func runHandler(ctx *domainContext, key string, c <-chan interface{}) {

	log.Infof("runHandler starting\n")

	interval := 30 * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	closed := false
	for !closed {
		select {
		case configArg, ok := <-c:
			if ok {
				config := cast.CastDomainConfig(configArg)
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
	domainId, err := xlDomid(status.DomainName, status.DomainId)
	if err != nil {
		if status.Activated {
			errStr := fmt.Sprintf("verifyStatus(%s) failed %s",
				status.Key(), err)
			log.Warnln(errStr)
			status.Activated = false
			status.State = types.HALTED
		}
		status.DomainId = 0
		publishDomainStatus(ctx, status)
	} else {
		if !status.Activated {
			log.Warnf("verifyDomain(%s) domain came back alive; id  %d\n",
				status.Key(), domainId)
			status.LastErr = ""
			status.LastErrTime = time.Time{}
			status.DomainId = domainId
			status.Activated = true
			status.State = types.RUNNING
			publishDomainStatus(ctx, status)
		} else if domainId != status.DomainId {
			// XXX shutdown + create?
			log.Warnf("verifyDomain(%s) domainId changed from %d to %d\n",
				status.Key(), status.DomainId, domainId)
			status.DomainId = domainId
			publishDomainStatus(ctx, status)
		}
	}
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
	if elapsed < domainBootRetryTime {
		log.Infof("maybeRetryBoot(%s) %v remaining\n",
			status.Key(),
			(domainBootRetryTime-elapsed)/time.Second)
		return
	}
	log.Infof("maybeRetryBoot(%s) after %s at %v\n",
		status.Key(), status.LastErr, status.LastErrTime)

	status.LastErr = ""
	status.LastErrTime = time.Time{}
	status.TriedCount += 1

	filename := xenCfgFilename(status.AppNum)
	ctx.createSema.V(1)
	domainId, err := xlCreate(status.DomainName, filename)
	ctx.createSema.P(1)
	if err != nil {
		log.Errorf("maybeRetryBoot xl create for %s: %s\n",
			status.DomainName, err)
		status.BootFailed = true
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		publishDomainStatus(ctx, status)
		return
	}
	status.BootFailed = false
	doActivateTail(ctx, status, domainId)
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
	status := cast.CastDomainStatus(st)
	if status.Key() != key {
		log.Errorf("lookupDomainStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func lookupDomainConfig(ctx *domainContext, key string) *types.DomainConfig {

	sub := ctx.subDomainConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupDomainConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastDomainConfig(c)
	if config.Key() != key {
		log.Errorf("lookupDomainConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func handleCreate(ctx *domainContext, key string, config *types.DomainConfig) {

	log.Infof("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

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
		VirtualizationMode: config.VirtualizationMode,
		EnableVnc:          config.EnableVnc,
		VncDisplay:         config.VncDisplay,
		VncPasswd:          config.VncPasswd,
		State:              types.INSTALLED,
	}
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
		if ds.ReadOnly || !ds.Preserve {
			continue
		}
		log.Infof("Copy from %s to %s\n", ds.FileLocation, ds.ActiveFileLocation)
		if _, err := os.Stat(ds.ActiveFileLocation); err == nil {
			if ds.Preserve {
				log.Infof("Preserve and target exists - skip copy\n")
			} else {
				log.Infof("Not preserve and target exists - assume rebooted and preserve\n")
			}
		} else {
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
		}
		addImageStatus(ctx, ds.ActiveFileLocation)
		log.Infof("Copy DONE from %s to %s\n",
			ds.FileLocation, ds.ActiveFileLocation)
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
		list := ctx.assignableAdapters.LookupIoBundleGroup(
			adapter.Type, adapter.Name)
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

		list := ctx.assignableAdapters.LookupIoBundleGroup(
			adapter.Type, adapter.Name)
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
			if ib.Type != types.IoUSB {
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
	for _, ds := range status.DiskStatusList {
		if ds.ReadOnly || ds.Preserve {
			continue
		}
		log.Infof("Copy from %s to %s\n", ds.FileLocation, ds.ActiveFileLocation)
		if _, err := os.Stat(ds.ActiveFileLocation); err == nil && ds.Preserve {
			log.Infof("Preserve and target exists - skip copy\n")
		} else if err := cp(ds.ActiveFileLocation, ds.FileLocation); err != nil {
			log.Errorf("Copy failed from %s to %s: %s\n",
				ds.FileLocation, ds.ActiveFileLocation, err)
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
			return
		}
		addImageStatus(ctx, ds.ActiveFileLocation)
		log.Infof("Copy DONE from %s to %s\n",
			ds.FileLocation, ds.ActiveFileLocation)
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

	status.TriedCount = 0
	var domainId int
	// Invoke xl create; try 3 times with a timeout
	for {
		status.TriedCount += 1
		var err error
		ctx.createSema.V(1)
		domainId, err = xlCreate(status.DomainName, filename)
		ctx.createSema.P(1)
		if err == nil {
			break
		}
		if status.TriedCount >= 3 {
			log.Errorf("xl create for %s: %s\n", status.DomainName, err)
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
	doActivateTail(ctx, status, domainId)
}

func doActivateTail(ctx *domainContext, status *types.DomainStatus,
	domainId int) {

	log.Infof("created domainId %d for %s\n", domainId, status.DomainName)
	status.DomainId = domainId
	status.Activated = true
	status.BootTime = time.Now()
	status.State = types.BOOTING
	publishDomainStatus(ctx, status)

	// Disable offloads for all vifs
	err := xlDisableVifOffload(status.DomainName, domainId,
		len(status.VifList))
	if err != nil {
		// XXX continuing even if we get a failure?
		log.Errorf("xlDisableVifOffload for %s: %s\n",
			status.DomainName, err)
	}
	err = xlUnpause(status.DomainName, domainId)
	if err != nil {
		// XXX shouldn't we destroy it?
		log.Errorf("xl unpause for %s: %s\n", status.DomainName, err)
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		return
	}

	status.State = types.RUNNING
	// XXX dumping status to log
	xlStatus(status.DomainName, status.DomainId)

	domainId, err = xlDomid(status.DomainName, status.DomainId)
	if err == nil && domainId != status.DomainId {
		status.DomainId = domainId
	}
	log.Infof("doActivateTail(%v) done for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

// shutdown and wait for the domain to go away; if that fails destroy and wait
func doInactivate(ctx *domainContext, status *types.DomainStatus) {

	log.Infof("doInactivate(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)
	domainId, err := xlDomid(status.DomainName, status.DomainId)
	if err == nil && domainId != status.DomainId {
		status.DomainId = domainId
	}
	maxDelay := time.Second * 60 // 1 minute
	if status.DomainId != 0 {
		status.State = types.HALTING
		publishDomainStatus(ctx, status)

		switch status.VirtualizationMode {
		case types.HVM:
			// Do a short shutdown wait, then a shutdown -F
			// just in case there are PV tools in guest
			shortDelay := time.Second * 10
			if err := xlShutdown(status.DomainName,
				status.DomainId, false); err != nil {
				log.Errorf("xl shutdown %s failed: %s\n",
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
			if err := xlShutdown(status.DomainName,
				status.DomainId, true); err != nil {
				log.Errorf("xl shutdown -F %s failed: %s\n",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Infof("doInactivate(%v) for %s: waiting for domain to shutdown\n",
					status.UUIDandVersion, status.DisplayName)
			}
			gone = waitForDomainGone(*status, maxDelay)
			if gone {
				status.DomainId = 0
				break
			}

		case types.PV:
			if err := xlShutdown(status.DomainName,
				status.DomainId, false); err != nil {
				log.Errorf("xl shutdown %s failed: %s\n",
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
		}
	}

	if status.DomainId != 0 {
		err := xlDestroy(status.DomainName, status.DomainId)
		if err != nil {
			log.Errorf("xl shutdown %s failed: %s\n",
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
		list := ctx.assignableAdapters.LookupIoBundleGroup(
			adapter.Type, adapter.Name)
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
			if ib.Type != types.IoUSB {
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
	for i, dc := range config.DiskConfigList {
		ds := &status.DiskStatusList[i]
		ds.ImageSha256 = dc.ImageSha256
		ds.ReadOnly = dc.ReadOnly
		ds.Preserve = dc.Preserve
		ds.Format = dc.Format
		ds.Maxsizebytes = dc.Maxsizebytes
		ds.Devtype = dc.Devtype
		// map from i=1 to xvda, 2 to xvdb etc
		xv := "xvd" + string(int('a')+i)
		ds.Vdev = xv
		locationDir := verifiedDirname + "/" + dc.ImageSha256
		log.Debugf("configToStatus(%v) processing disk img %s for %s\n",
			config.UUIDandVersion, locationDir, config.DisplayName)
		location, err := locationFromDir(locationDir)
		if err != nil {
			return err
		}
		ds.FileLocation = location
		target := location
		if !dc.ReadOnly {
			// Pick new location for a per-guest copy
			// Use App UUID to make sure name is the same even
			// after adds and deletes of instances and device reboots
			dstFilename := fmt.Sprintf("%s/%s-%s.%s",
				rwImgDirname, dc.ImageSha256,
				config.UUIDandVersion.UUID.String(),
				dc.Format)
			target = dstFilename
		}
		ds.ActiveFileLocation = target
	}
	// XXX could defer to Activate
	if config.CloudInitUserData != "" {
		ds, err := createCloudInitISO(config)
		if err != nil {
			return err
		}
		if ds != nil {
			status.DiskStatusList = append(status.DiskStatusList,
				*ds)
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
		list := ctx.assignableAdapters.LookupIoBundleGroup(
			adapter.Type, adapter.Name)
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

			log.Debugf("configAdapters setting uuid %s for adapter %d %s member %s",
				config.Key(), adapter.Type, adapter.Name, ibp.Name)
			ibp.UsedByUUID = config.UUIDandVersion.UUID
		}
	}
	return nil
}

// Produce the xen cfg file based on the config and status created above
// XXX or produce output to a string instead of file to make comparison
// easier?
func configToXencfg(config types.DomainConfig, status types.DomainStatus,
	aa *types.AssignableAdapters, file *os.File) error {

	xen_type := "pv"
	rootDev := ""
	extra := ""
	bootLoader := ""
	uuidStr := fmt.Sprintf("appuuid=%s ", config.UUIDandVersion.UUID)

	switch config.VirtualizationMode {
	case types.PV:
		xen_type = "pv"
		// Note that qcow2 images might have partitions hence xvda1 by default
		rootDev = config.RootDev
		if rootDev == "" {
			rootDev = "/dev/xvda1"
		}
		extra = "console=hvc0 " + uuidStr + config.ExtraArgs
		// XXX zedcloud should really set "pygrub"
		bootLoader = config.BootLoader
		if strings.HasSuffix(bootLoader, "pygrub") {
			log.Warnf("Changing from %s to pygrub for %s\n",
				bootLoader, config.Key())
			bootLoader = "pygrub"
		}
	case types.HVM:
		xen_type = "hvm"
	}

	file.WriteString("# This file is automatically generated by domainmgr\n")
	file.WriteString(fmt.Sprintf("name = \"%s\"\n", status.DomainName))
	file.WriteString(fmt.Sprintf("type = \"%s\"\n", xen_type))
	file.WriteString(fmt.Sprintf("uuid = \"%s\"\n",
		config.UUIDandVersion.UUID))

	if config.Kernel != "" {
		file.WriteString(fmt.Sprintf("kernel = \"%s\"\n",
			config.Kernel))
	}

	if config.Ramdisk != "" {
		file.WriteString(fmt.Sprintf("ramdisk = \"%s\"\n",
			config.Ramdisk))
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
		access := "rw"
		if ds.ReadOnly {
			access = "ro"
		}
		oneDisk := fmt.Sprintf("'%s,%s,%s,%s'",
			ds.ActiveFileLocation, ds.Format, ds.Vdev, access)
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
		oneVif := fmt.Sprintf("'bridge=%s,vifname=%s,mac=%s,type=vif'",
			net.Bridge, net.Vif, net.Mac)
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
		list := aa.LookupIoBundleGroup(adapter.Type, adapter.Name)
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
			if ib.Irq != "" && config.VirtualizationMode == types.PV {
				log.Infof("Adding irq <%s>\n", ib.Irq)
				irqAssignments = addNoDuplicate(irqAssignments,
					ib.Irq)
			}
			if ib.Ioports != "" && config.VirtualizationMode == types.PV {
				log.Infof("Adding ioport <%s>\n", ib.Ioports)
				ioportsAssignments = addNoDuplicate(ioportsAssignments, ib.Ioports)
			}
			if ib.Serial != "" && config.VirtualizationMode == types.HVM {
				log.Infof("Adding serial <%s>\n", ib.Serial)
				serialAssignments = addNoDuplicate(serialAssignments, ib.Serial)
			}
		}
	}
	if len(pciAssignments) != 0 {
		log.Debugf("PCI assignments %v\n", pciAssignments)
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
		status.VifList = config.VifList
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
			doInactivate(ctx, status)
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
			doInactivate(ctx, status)
			updateStatusFromConfig(status, *config)
			changed = true
		} else if status.Activated {
			doInactivate(ctx, status)
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
	status.VirtualizationMode = config.VirtualizationMode
	status.EnableVnc = config.EnableVnc
	status.VncDisplay = config.VncDisplay
	status.VncPasswd = config.VncPasswd
}

// Used to wait both after shutdown and destroy
func waitForDomainGone(status types.DomainStatus, maxDelay time.Duration) bool {
	gone := false
	var delay time.Duration
	for {
		log.Infof("waitForDomainGone(%v) for %s: waiting for %v\n",
			status.UUIDandVersion, status.DisplayName, delay)
		time.Sleep(delay)
		if err := xlStatus(status.DomainName, status.DomainId); err != nil {
			log.Infof("waitForDomainGone(%v) for %s: domain is gone\n",
				status.UUIDandVersion, status.DisplayName)
			gone = true
			break
		} else {
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				// Give up
				log.Infof("waitForDomainGone(%v) for %s: giving up\n",
					status.UUIDandVersion, status.DisplayName)
				break
			}
		}
	}
	return gone
}

func handleDelete(ctx *domainContext, key string, status *types.DomainStatus) {

	log.Infof("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	// XXX dumping status to log
	xlStatus(status.DomainName, status.DomainId)

	status.PendingDelete = true
	publishDomainStatus(ctx, status)

	if status.Activated {
		doInactivate(ctx, status)
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

	// Do we need to delete any rw files that were not deleted during
	// inactivation i.e. those preserved across reboots?
	for _, ds := range status.DiskStatusList {
		if !ds.ReadOnly && ds.Preserve {
			log.Infof("Delete copy at %s\n", ds.ActiveFileLocation)
			if err := os.Remove(ds.ActiveFileLocation); err != nil {
				log.Errorln(err)
				// XXX return? Cleanup status?
			}
			delImageStatus(ctx, ds.ActiveFileLocation)
		}
	}
	status.PendingDelete = false
	publishDomainStatus(ctx, status)
	// Write out what we modified to DomainStatus aka delete
	unpublishDomainStatus(ctx, status)
	log.Infof("handleDelete(%v) DONE for %s\n",
		status.UUIDandVersion, status.DisplayName)
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
		return 0, errors.New(fmt.Sprintf("xl create failed: %s\n",
			string(stdoutStderr)))
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
		return 0, errors.New(fmt.Sprintf("xl domid failed: %s\n",
			string(stdoutStderr)))
	}
	res := strings.TrimSpace(string(stdoutStderr))
	domainId, err := strconv.Atoi(res)
	if err != nil {
		log.Errorf("Can't extract domainId from %s: %s\n", res, err)
		return 0, errors.New(fmt.Sprintf("Can't extract domainId from %s: %s\n", res, err))
	}
	return domainId, nil
}

func xlStatus(domainName string, domainId int) error {
	log.Infof("xlStatus %s %d\n", domainName, domainId)
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
		return errors.New(fmt.Sprintf("xl list failed: %s\n",
			string(stdoutStderr)))
	}
	// XXX parse json to look at state? Not currently included
	// XXX note that there is a warning at the top of the combined
	// output. If we want to parse the json we need to get Output()
	log.Infof("xl list done. Result %s\n", string(stdoutStderr))
	return nil
}

// If we have a domain reboot issue the domainId
// can change.
func xlDomid(domainName string, domainId int) (int, error) {
	log.Debugf("xlDomid %s %d\n", domainName, domainId)
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
		return domainId, errors.New(fmt.Sprintf("xl domid failed: %s\n",
			string(stdoutStderr)))
	}
	res := strings.TrimSpace(string(stdoutStderr))
	domainId2, err := strconv.Atoi(res)
	if err != nil {
		log.Errorf("xl domid not integer %s: failed %s\n", res, err)
		return domainId, err
	}
	if domainId2 != domainId {
		log.Warningf("domainid changed from %d to %d for %s\n",
			domainId, domainId2, domainName)
	}
	return domainId2, err
}

// Perform xenstore write to disable all of these for all VIFs
// feature-sg, feature-gso-tcpv4, feature-gso-tcpv6, feature-ipv6-csum-offload
func xlDisableVifOffload(domainName string, domainId int, vifCount int) error {
	log.Infof("xlDisableVifOffload %s %d %d\n",
		domainName, domainId, vifCount)
	pref := "/local/domain"
	for i := 0; i < vifCount; i += 1 {
		varNames := []string{
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-sg",
				pref, domainId, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-gso-tcpv4",
				pref, domainId, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-gso-tcpv6",
				pref, domainId, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-ipv4-csum-offload",
				pref, domainId, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-ipv6-csum-offload",
				pref, domainId, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-sg",
				pref, domainId, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-gso-tcpv4",
				pref, domainId, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-gso-tcpv6",
				pref, domainId, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-ipv4-csum-offload",
				pref, domainId, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-ipv6-csum-offload",
				pref, domainId, i),
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
				return errors.New(fmt.Sprintf("xenstore write failed: %s\n",
					string(stdoutStderr)))
			}
			log.Debugf("xenstore write done. Result %s\n",
				string(stdoutStderr))
		}
	}

	log.Infof("xlDisableVifOffload done.\n")
	return nil
}

func xlUnpause(domainName string, domainId int) error {
	log.Infof("xlUnpause %s %d\n", domainName, domainId)
	cmd := "xl"
	args := []string{
		"unpause",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl unpause failed ", err)
		log.Errorln("xl unpause output ", string(stdoutStderr))
		return errors.New(fmt.Sprintf("xl unpause failed: %s\n",
			string(stdoutStderr)))
	}
	log.Infof("xlUnpause done. Result %s\n", string(stdoutStderr))
	return nil
}

func xlShutdown(domainName string, domainId int, force bool) error {
	log.Infof("xlShutdown %s %d\n", domainName, domainId)
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
		return errors.New(fmt.Sprintf("xl shutdown failed: %s\n",
			string(stdoutStderr)))
	}
	log.Infof("xl shutdown done\n")
	return nil
}

func xlDestroy(domainName string, domainId int) error {
	log.Infof("xlDestroy %s %d\n", domainName, domainId)
	cmd := "xl"
	args := []string{
		"destroy",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl destroy failed ", err)
		log.Errorln("xl destroy output ", string(stdoutStderr))
		return errors.New(fmt.Sprintf("xl destroy failed: %s\n",
			string(stdoutStderr)))
	}
	log.Infof("xl destroy done\n")
	return nil
}

func locationFromDir(locationDir string) (string, error) {
	if _, err := os.Stat(locationDir); err != nil {
		log.Errorf("Missing directory: %s, %s\n", locationDir, err)
		return "", err
	}
	// locationDir is a directory. Need to find single file inside
	// which the verifier ensures.
	locations, err := ioutil.ReadDir(locationDir)
	if err != nil {
		log.Errorln(err)
		return "", err
	}
	if len(locations) != 1 {
		log.Errorf("Multiple files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("Multiple files in %s\n",
			locationDir))
	}
	if len(locations) == 0 {
		log.Errorf("No files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("No files in %s\n",
			locationDir))
	}
	return locationDir + "/" + locations[0].Name(), nil
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

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	if cmp.Equal(ctx.deviceNetworkStatus, status) {
		log.Infof("handleDNSModify unchanged\n")
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
			vdiskGCTime = time.Duration(gcp.VdiskGCTime) * time.Second
		}
		if gcp.DomainBootRetryTime != 0 {
			domainBootRetryTime = time.Duration(gcp.DomainBootRetryTime) * time.Second
		}
		if gcp.UsbAccess != ctx.usbAccess {
			ctx.usbAccess = gcp.UsbAccess
			updateUsbAccess(ctx)
		}
	}
	log.Infof("handleGlobalConfigModify done for %s\n", key)
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
	currentSize, err := getDiskVirtualSize(diskfile)
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

func getDiskVirtualSize(diskfile string) (uint64, error) {
	imgInfo, err := diskmetrics.GetImgInfo(diskfile)
	if err != nil {
		return 0, err
	}
	return imgInfo.VirtualSize, nil
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
	ud, err := base64.StdEncoding.DecodeString(config.CloudInitUserData)
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
	ds.Format = "raw"
	ds.Vdev = "hdc"
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

func handleAAModify(ctxArg interface{}, config types.AssignableAdapters,
	status *types.AssignableAdapters) {

	ctx := ctxArg.(*domainContext)
	log.Infof("handleAAModify() %+v\n", status)
	// Any deletes?
	for _, statusIb := range (*status).IoBundleList {
		configIb := config.LookupIoBundle(statusIb.Type, statusIb.Name)
		if configIb == nil {
			handleIBDelete(ctx, statusIb, status)
		}
	}
	// Any add or modify?
	for _, configIb := range config.IoBundleList {
		statusIb := status.LookupIoBundle(configIb.Type, configIb.Name)
		if statusIb == nil {
			handleIBCreate(ctx, configIb, status)
		} else if statusIb.AssignmentGroup != configIb.AssignmentGroup ||
			statusIb.PciLong != configIb.PciLong ||
			statusIb.Ifname != configIb.Ifname ||
			statusIb.Irq != configIb.Irq ||
			statusIb.Ioports != configIb.Ioports ||
			statusIb.Serial != configIb.Serial {

			handleIBModify(ctx, *statusIb, configIb, status)
		}
	}
	status.Initialized = true
	ctx.publishAssignableAdapters()
	log.Infof("handleAAModify() done\n")
}

func handleAADelete(ctxArg interface{}, status *types.AssignableAdapters) {

	ctx := ctxArg.(*domainContext)
	log.Infof("handleAADelete()\n")
	for _, statusIb := range (*status).IoBundleList {
		handleIBDelete(ctx, statusIb, status)
	}
	ctx.publishAssignableAdapters()
	log.Infof("handleAADelete() done\n")
}

// Process new IoBundles. Check if PCI device exists, and check that not
// used in a DevicePortConfig/DeviceNetworkStatus
// Assign to pciback
func handleIBCreate(ctx *domainContext, ib types.IoBundle,
	status *types.AssignableAdapters) {

	log.Infof("handleIBCreate(%d %s %s)", ib.Type, ib.Name, ib.AssignmentGroup)
	if err := checkAndSetIoBundle(ctx, &ib); err != nil {
		log.Warnf("Not reporting non-existent PCI device %d %s: %v\n",
			ib.Type, ib.Name, err)
		return
	}
	status.IoBundleList = append(status.IoBundleList, ib)
}

func checkAndSetIoBundleAll(ctx *domainContext) {
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		err := checkAndSetIoBundle(ctx, ib)
		if err != nil {
			log.Errorf("checkAndSetIoBundleAll failed for %d\n", i)
		}
	}
}

func checkAndSetIoBundle(ctx *domainContext, ib *types.IoBundle) error {

	// Check if part of DevicePortConfig
	ib.IsPort = false
	publishAssignableAdapters := false
	if types.IsPort(ctx.deviceNetworkStatus, ib.Name) {
		log.Warnf("checkAndSetIoBundle(%d %s %s) part of zedrouter port\n",
			ib.Type, ib.Name, ib.AssignmentGroup)
		ib.IsPort = true
		if ib.IsPCIBack {
			log.Infof("checkAndSetIoBundle(%d %s %s) take back from pciback\n",
				ib.Type, ib.Name, ib.AssignmentGroup)
			if ib.PciLong != "" {
				log.Infof("Removing %s (%s) from pciback\n",
					ib.Name, ib.PciLong)
				err := pciAssignableRemove(ib.PciLong)
				if err != nil {
					log.Errorf("checkAndSetIoBundle(%d %s %s) pciAssignableRemove %s failed %v\n",
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
			publishAssignableAdapters = true
			// Verify that it has been returned from pciback
			_, err := types.IoBundleToPci(ib)
			if err != nil {
				log.Warnf("checkAndSetIoBundle(%d %s %s) gone?: %s\n",
					ib.Type, ib.Name, ib.AssignmentGroup, err)
			}
		}
	} else {
		// XXX potentially move to PCIBack if not already
		// and with USB check
		// XXX should not do that when Testing is set.
	}
	if publishAssignableAdapters {
		ctx.publishAssignableAdapters()
	}

	// For a new PCI device we check if it exists in hardware/kernel
	long, err := types.IoBundleToPci(ib)
	if err != nil {
		return err
	}
	if long != "" {
		ib.PciLong = long
		log.Infof("checkAndSetIoBundle(%d %s %s) found %s\n",
			ib.Type, ib.Name, ib.AssignmentGroup, long)

		// Save somewhat Unique string for debug
		found, unique := types.PciLongToUnique(long)
		if !found {
			errStr := fmt.Sprintf("IoBundle(%d %s %s) %s unique not found",
				ib.Type, ib.Name, ib.AssignmentGroup, long)
			log.Errorln(errStr)
		} else {
			ib.Unique = unique
			log.Infof("checkAndSetIoBundle(%d %s %s) %s unique %s",
				ib.Type, ib.Name, ib.AssignmentGroup, long, unique)
		}
		if ib.Type.IsNet() && ib.MacAddr == "" {
			ib.MacAddr = getMacAddr(ib.Name)
		}
		ctx.publishAssignableAdapters()
	}

	if !ib.IsPort && !ib.IsPCIBack {
		if ctx.deviceNetworkStatus.Testing && ib.Type.IsNet() {
			log.Infof("Not assigning %s (%s) to pciback due to Testing\n",
				ib.Name, ib.PciLong)
		} else if ctx.usbAccess && ib.Type == types.IoUSB {
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
			ctx.publishAssignableAdapters()
		}
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
	if unique != ib.Unique {
		errStr := fmt.Sprintf("IoBundle(%d %s %s) changed unique from %s to %sn",
			ib.Type, ib.Name, ib.AssignmentGroup,
			ib.Unique, unique)
		return errors.New(errStr)
	}
	if ib.Type.IsNet() && ib.MacAddr == "" {
		macAddr := getMacAddr(ib.Name)
		// Will be empty string if adapter is assigned away
		if macAddr != "" && macAddr != ib.MacAddr {
			errStr := fmt.Sprintf("IoBundle(%d %s %s) changed MacAddr from %s to %sn",
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
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		if ib.Type != types.IoUSB {
			continue
		}
		if !ib.IsPCIBack {
			log.Infof("Assigning %s (%s) to pciback\n",
				ib.Name, ib.PciLong)
			assignments = addNoDuplicate(assignments, ib.PciLong)
			ib.IsPCIBack = true
		}
	}
	for _, long := range assignments {
		err := pciAssignableAdd(long)
		if err != nil {
			log.Errorf("updateUsbAccess add failed: %s", err)
		}
	}
	if len(assignments) != 0 {
		ctx.publishAssignableAdapters()
	}
}

func maybeAssignableRem(ctx *domainContext) {

	var assignments []string
	for i := range ctx.assignableAdapters.IoBundleList {
		ib := &ctx.assignableAdapters.IoBundleList[i]
		if ib.Type != types.IoUSB {
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
			log.Errorf("updateUsbAccess remove failed: %s\n", err)
		}
	}
	if len(assignments) != 0 {
		ctx.publishAssignableAdapters()
	}
}

func handleIBDelete(ctx *domainContext, ib types.IoBundle,
	status *types.AssignableAdapters) {

	log.Infof("handleIBDelete(%d %s %s)", ib.Type, ib.Name, ib.AssignmentGroup)
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
		IoBundleList: make([]types.IoBundle, len(status.IoBundleList)-1)}
	for _, e := range status.IoBundleList {
		if e.Type == ib.Type && e.Name == ib.Name {
			continue
		}
		replace.IoBundleList = append(replace.IoBundleList, e)
	}
	*status = replace
	checkIoBundleAll(ctx)
}

func handleIBModify(ctx *domainContext, statusIb types.IoBundle, configIb types.IoBundle,
	status *types.AssignableAdapters) {

	log.Infof("handleIBModify(%d %s %s) from %v to %v\n",
		statusIb.Type, statusIb.Name, statusIb.AssignmentGroup,
		statusIb, configIb)

	for i := range status.IoBundleList {
		e := &(*status).IoBundleList[i]
		if e.Type != statusIb.Type || e.Name != statusIb.Name {
			continue
		}
		// XXX can we have changes which require us to
		// do pciAssignableRemove for the old status?
		if err := checkAndSetIoBundle(ctx, &configIb); err != nil {
			log.Warnf("Not reporting non-existent PCI device %d %s: %v\n",
				configIb.Type, configIb.Name, err)
			return
		}
		*e = configIb
	}
	checkIoBundleAll(ctx)
}
