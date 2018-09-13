// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package domainmgr

import (
	"errors"
	"flag"
	"fmt"
	"github.com/satori/go.uuid"
	"github.com/zededa/go-provision/adapters"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	appImgObj = "appImg.obj"
	agentName = "domainmgr"

	runDirname        = "/var/run/" + agentName
	persistDir        = "/persist"
	rwImgDirname      = persistDir + "/img" // We store images here
	xenDirname        = runDirname + "/xen" // We store xen cfg files here
	downloadDirname   = persistDir + "/downloads"
	imgCatalogDirname = downloadDirname + "/" + appImgObj
	// Read-only images named based on sha256 hash each in its own directory
	verifiedDirname = imgCatalogDirname + "/verified"
)

// Really a constant
var nilUUID = uuid.UUID{}

// Set from Makefile
var Version = "No version specified"

// The isUplink function is called by different goroutines
// hence we serialize the calls on a mutex.
var deviceNetworkStatus types.DeviceNetworkStatus
var dnsLock sync.Mutex

func isUplink(ifname string) bool {
	dnsLock.Lock()
	defer dnsLock.Unlock()
	return types.IsUplink(deviceNetworkStatus, ifname)
}

// Information for handleCreate/Modify/Delete
type domainContext struct {
	assignableAdapters     *types.AssignableAdapters
	subDeviceNetworkStatus *pubsub.Subscription
	subDomainConfig        *pubsub.Subscription
	pubDomainStatus        *pubsub.Publication
	subGlobalConfig        *pubsub.Subscription
}

var debug = false

func Run() {
	handlersInit()
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)

	if _, err := os.Stat(runDirname); err != nil {
		log.Printf("Create %s\n", runDirname)
		if err := os.MkdirAll(runDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if err := os.RemoveAll(xenDirname); err != nil {
		log.Fatal(err)
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

	// Pick up (mostly static) AssignableAdapters before we process
	// any DomainConfig
	model := hardware.GetHardwareModel()
	aa := types.AssignableAdapters{}
	subAa := adapters.SubscribeWithDebug(&aa, model, &debug)

	domainCtx := domainContext{assignableAdapters: &aa}

	pubDomainStatus, err := pubsub.PublishWithDebug(agentName,
		types.DomainStatus{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	domainCtx.pubDomainStatus = pubDomainStatus
	pubDomainStatus.ClearRestarted()

	// Look for global config like debug
	subGlobalConfig, err := pubsub.SubscribeWithDebug("",
		agentlog.GlobalConfig{}, false, &domainCtx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	domainCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	for !subAa.Found {
		log.Printf("Waiting for AssignableAdapters %v\n", subAa.Found)
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subAa.C:
			subAa.ProcessChange(change)
		}
	}
	log.Printf("Have %d assignable adapters\n", len(aa.IoBundleList))

	// Subscribe to DomainConfig from zedmanager
	subDomainConfig, err := pubsub.SubscribeWithDebug("zedmanager",
		types.DomainConfig{}, false, &domainCtx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subDomainConfig.ModifyHandler = handleDomainModify
	subDomainConfig.DeleteHandler = handleDomainDelete
	subDomainConfig.RestartHandler = handleRestart
	domainCtx.subDomainConfig = subDomainConfig
	subDomainConfig.Activate()

	subDeviceNetworkStatus, err := pubsub.SubscribeWithDebug("zedrouter",
		types.DeviceNetworkStatus{}, false, &domainCtx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	domainCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

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
		}
	}
}

// XXX need to run this sometime after boot to clean up
// Clean up any unused files in rwImgDirname
// XXX but need to preserve ones that might become in use. Switch to manual
// deletes from zedcloud i.e. explicit storage management?
func handleRestart(ctxArg interface{}, done bool) {
	log.Printf("handleRestart(%v)\n", done)
	ctx := ctxArg.(*domainContext)
	if done {
		log.Printf("handleRestart: avoid cleanup\n")
		ctx.pubDomainStatus.SignalRestarted()
		// XXX
		return

		files, err := ioutil.ReadDir(rwImgDirname)
		if err != nil {
			log.Fatal(err)
		}
		for _, file := range files {
			filename := rwImgDirname + "/" + file.Name()
			log.Println("handleRestart found existing",
				filename)
			if !findActiveFileLocation(ctx, filename) {
				log.Println("handleRestart removing",
					filename)
				if err := os.Remove(filename); err != nil {
					log.Println(err)
				}
			}
		}
	}
}

// Check if the filename is used as ActiveFileLocation
func findActiveFileLocation(ctx *domainContext, filename string) bool {
	log.Printf("findActiveFileLocation(%v)\n", filename)
	pub := ctx.pubDomainStatus
	items := pub.GetAll()
	for key, st := range items {
		status := cast.CastDomainStatus(st)
		if status.Key() != key {
			log.Printf("findActiveFileLocation key/UUID mismatch %s vs %s; ignored %+v\n",
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
	if debug {
		log.Printf("publishDomainStatus(%s)\n", key)
	}
	pub := ctx.pubDomainStatus
	pub.Publish(key, status)
}

func unpublishDomainStatus(ctx *domainContext, status *types.DomainStatus) {

	key := status.Key()
	if debug {
		log.Printf("unpublishDomainStatus(%s)\n", key)
	}
	pub := ctx.pubDomainStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("unpublishDomainStatus(%s) not found\n", key)
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

	log.Printf("handleDomainModify(%s)\n", key)
	ctx := ctxArg.(*domainContext)
	config := cast.CastDomainConfig(configArg)
	if config.Key() != key {
		log.Printf("handleDomainModify key/UUID mismatch %s vs %s; ignored %+v\n",
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
	log.Printf("Sending config to handler\n")
	h <- configArg
	log.Printf("handleDomainModify(%s) done\n", key)
}

func handleDomainDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Printf("handleDomainDelete(%s)\n", key)
	// Do we have a channel/goroutine?
	h, ok := handlerMap[key]
	if ok {
		log.Printf("Closing channel\n")
		close(h)
		delete(handlerMap, key)
	} else {
		log.Printf("handleDomainDelete: unknown %s\n", key)
		return
	}
	log.Printf("handleDomainDelete(%s) done\n", key)
}

// Server for each domU
// Runs timer every 30 seconds to update status
func runHandler(ctx *domainContext, key string, c <-chan interface{}) {

	log.Printf("runHandler starting\n")

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
			if debug {
				log.Printf("runHandler(%s) timer\n", key)
			}
			status := lookupDomainStatus(ctx, key)
			if status != nil {
				verifyStatus(ctx, status)
			}
		}
	}
	log.Printf("runHandler(%s) DONE\n", key)
}

// Check if it is still running
// XXX would xen state be useful?
func verifyStatus(ctx *domainContext, status *types.DomainStatus) {
	domainId, err := xlDomid(status.DomainName, status.DomainId)
	if err != nil {
		if status.Activated {
			errStr := fmt.Sprintf("verifyStatus(%s) failed %s",
				status.Key(), err)
			log.Println(errStr)
			status.LastErr = errStr
			status.LastErrTime = time.Now()
			status.Activated = false
			status.Failed = true // XXX useful?
		}
		status.DomainId = 0
		publishDomainStatus(ctx, status)
	} else {
		if domainId != status.DomainId {
			log.Printf("verifyDomain(%s) domainId changed from %d to %d\n",
				status.Key(), status.DomainId, domainId)
			status.DomainId = domainId
			publishDomainStatus(ctx, status)
		}
	}
}

// Callers must be careful to publish any changes to DomainStatus
func lookupDomainStatus(ctx *domainContext, key string) *types.DomainStatus {

	pub := ctx.pubDomainStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("lookupDomainStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastDomainStatus(st)
	if status.Key() != key {
		log.Printf("lookupDomainStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func lookupDomainConfig(ctx *domainContext, key string) *types.DomainConfig {

	sub := ctx.subDomainConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Printf("lookupDomainConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastDomainConfig(c)
	if config.Key() != key {
		log.Printf("lookupDomainConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func handleCreate(ctx *domainContext, key string, config *types.DomainConfig) {

	log.Printf("handleCreate(%v) for %s\n",
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
	}
	status.DiskStatusList = make([]types.DiskStatus,
		len(config.DiskConfigList))
	publishDomainStatus(ctx, &status)

	if err := configToStatus(*config, ctx.assignableAdapters,
		&status); err != nil {
		log.Printf("Failed to create DomainStatus from %v: %s\n",
			config, err)
		status.PendingAdd = false
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		publishDomainStatus(ctx, &status)
		cleanupAdapters(ctx, config.IoAdapterList,
			config.UUIDandVersion.UUID)
		return
	}
	// We now have reserved all of the IoAdapters
	status.IoAdapterList = config.IoAdapterList

	// Write any Location so that it can later be deleted based on status
	publishDomainStatus(ctx, &status)

	// Do we need to copy any rw files? !Preserve ones are copied upon
	// activation.
	for _, ds := range status.DiskStatusList {
		if ds.ReadOnly || !ds.Preserve {
			continue
		}
		log.Printf("Copy from %s to %s\n", ds.FileLocation, ds.ActiveFileLocation)
		if _, err := os.Stat(ds.ActiveFileLocation); err == nil {
			if ds.Preserve {
				log.Printf("Preserve and target exists - skip copy\n")
			} else {
				log.Printf("Not preserve and target exists - assume rebooted and preserve\n")
			}
		} else if err := cp(ds.ActiveFileLocation, ds.FileLocation); err != nil {
			log.Printf("Copy failed from %s to %s: %s\n",
				ds.FileLocation, ds.ActiveFileLocation, err)
			status.PendingAdd = false
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
			publishDomainStatus(ctx, &status)
			return
		}
		log.Printf("Copy DONE from %s to %s\n",
			ds.FileLocation, ds.ActiveFileLocation)
	}

	if config.Activate {
		doActivate(*config, &status, ctx.assignableAdapters)
	}
	// work done
	status.PendingAdd = false
	publishDomainStatus(ctx, &status)
	log.Printf("handleCreate(%v) DONE for %s\n",
		config.UUIDandVersion, config.DisplayName)
}

func cleanupAdapters(ctx *domainContext, ioAdapterList []types.IoAdapter,
	myUuid uuid.UUID) {
	// Look for any adapters used by us and clear UsedByUUID
	for _, adapter := range ioAdapterList {
		log.Printf("cleanupAdapters processing adapter %d %s\n",
			adapter.Type, adapter.Name)
		ib := types.LookupIoBundle(ctx.assignableAdapters,
			adapter.Type, adapter.Name)
		if ib == nil {
			continue
		}
		if ib.UsedByUUID != myUuid {
			continue
		}
		log.Printf("cleanupAdapters clearing uuid for adapter %d %s\n",
			adapter.Type, adapter.Name)
		ib.UsedByUUID = nilUUID
	}
}

func doActivate(config types.DomainConfig, status *types.DomainStatus,
	aa *types.AssignableAdapters) {
	log.Printf("doActivate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// Assign any I/O devices
	for _, adapter := range config.IoAdapterList {
		log.Printf("doActivate processing adapter %d %s\n",
			adapter.Type, adapter.Name)
		ib := types.LookupIoBundle(aa, adapter.Type, adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if ib == nil {
			log.Fatalf("doActivate IoBundle disappeared %d %s for %s\n",
				adapter.Type, adapter.Name, status.DomainName)
		}
		if ib.UsedByUUID != config.UUIDandVersion.UUID {
			log.Fatalf("doActivate IoBundle stolen by %s: %d %s for %s\n",
				ib.UsedByUUID, adapter.Type, adapter.Name,
				status.DomainName)
		}
		if ib.Lookup && ib.PciShort == "" {
			log.Fatal("doActivate lookup missing: %d %s for %s\n",
				adapter.Type, adapter.Name, status.DomainName)
		}
		if ib.PciShort != "" {
			log.Printf("Assigning %s %s to %s\n",
				ib.PciLong, ib.PciShort, status.DomainName)
			err := pciAssignableAdd(ib.PciLong)
			if err != nil {
				status.LastErr = fmt.Sprintf("%v", err)
				status.LastErrTime = time.Now()
				return
			}
		}
	}

	// Do we need to copy any rw files? Preserve ones are copied upon
	// creation
	for _, ds := range status.DiskStatusList {
		if ds.ReadOnly || ds.Preserve {
			continue
		}
		log.Printf("Copy from %s to %s\n", ds.FileLocation, ds.ActiveFileLocation)
		if _, err := os.Stat(ds.ActiveFileLocation); err == nil && ds.Preserve {
			log.Printf("Preserve and target exists - skip copy\n")
		} else if err := cp(ds.ActiveFileLocation, ds.FileLocation); err != nil {
			log.Printf("Copy failed from %s to %s: %s\n",
				ds.FileLocation, ds.ActiveFileLocation, err)
			status.LastErr = fmt.Sprintf("%v", err)
			status.LastErrTime = time.Now()
			return
		}
		log.Printf("Copy DONE from %s to %s\n",
			ds.FileLocation, ds.ActiveFileLocation)
	}

	filename := xenCfgFilename(config.AppNum)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal("os.Create for ", filename, err)
	}
	defer file.Close()

	if err := configToXencfg(config, *status, aa, file); err != nil {
		log.Printf("Failed to create DomainStatus from %v\n", config)
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		return
	}

	// Invoke xl create
	domainId, err := xlCreate(status.DomainName, filename)
	if err != nil {
		log.Printf("xl create for %s: %s\n", status.DomainName, err)
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		return
	}
	log.Printf("created domainId %d for %s\n", domainId, status.DomainName)
	status.DomainId = domainId
	status.Activated = true
	status.BootTime = time.Now()

	// Disable offloads for all vifs
	err = xlDisableVifOffload(status.DomainName, domainId,
		len(config.VifList))
	if err != nil {
		// XXX continuing even if we get a failure?
		log.Printf("xlDisableVifOffload for %s: %s\n",
			status.DomainName, err)
	}
	err = xlUnpause(status.DomainName, domainId)
	if err != nil {
		// XXX shouldn't we destroy it?
		log.Printf("xl unpause for %s: %s\n", status.DomainName, err)
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		return
	}

	// XXX dumping status to log
	xlStatus(status.DomainName, status.DomainId)

	domainId, err = xlDomid(status.DomainName, status.DomainId)
	if err == nil && domainId != status.DomainId {
		status.DomainId = domainId
	}
	log.Printf("doActivate(%v) done for %s\n",
		config.UUIDandVersion, config.DisplayName)
}

// shutdown and wait for the domain to go away; if that fails destroy and wait
func doInactivate(status *types.DomainStatus, aa *types.AssignableAdapters) {
	log.Printf("doInactivate(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)
	domainId, err := xlDomid(status.DomainName, status.DomainId)
	if err == nil && domainId != status.DomainId {
		status.DomainId = domainId
	}
	maxDelay := time.Second * 600 // 10 minutes
	if status.DomainId != 0 {
		switch status.VirtualizationMode {
		case types.HVM:
			// Do a short shutdown wait, then a shutdown -F
			// just in case there are PV tools in guest
			shortDelay := time.Second * 10
			if err := xlShutdown(status.DomainName,
				status.DomainId, false); err != nil {
				log.Printf("xl shutdown %s failed: %s\n",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Printf("doInactivate(%v) for %s: waiting for domain to shutdown\n",
					status.UUIDandVersion, status.DisplayName)
			}
			gone := waitForDomainGone(*status, shortDelay)
			if gone {
				status.DomainId = 0
				break
			}
			if err := xlShutdown(status.DomainName,
				status.DomainId, true); err != nil {
				log.Printf("xl shutdown -F %s failed: %s\n",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Printf("doInactivate(%v) for %s: waiting for domain to shutdown\n",
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
				log.Printf("xl shutdown %s failed: %s\n",
					status.DomainName, err)
			} else {
				// Wait for the domain to go away
				log.Printf("doInactivate(%v) for %s: waiting for domain to shutdown\n",
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
			log.Printf("xl shutdown %s failed: %s\n",
				status.DomainName, err)
		}
		// Even if destroy failed we wait again
		log.Printf("doInactivate(%v) for %s: waiting for domain to be destroyed\n",
			status.UUIDandVersion, status.DisplayName)

		gone := waitForDomainGone(*status, maxDelay)
		if gone {
			status.DomainId = 0
		}
	}
	// If everything failed we leave it marked as Activated
	if status.DomainId != 0 {
		log.Printf("doInactivate(%v) done for %s\n",
			status.UUIDandVersion, status.DisplayName)
	}
	status.Activated = false

	// Do we need to delete any rw files that should
	// not be preserved across reboots?
	for _, ds := range status.DiskStatusList {
		if !ds.ReadOnly && !ds.Preserve {
			log.Printf("Delete copy at %s\n", ds.ActiveFileLocation)
			if err := os.Remove(ds.ActiveFileLocation); err != nil {
				log.Println(err)
				// XXX return? Cleanup status?
			}
		}
	}
	pciUnassign(status, aa, false)

	log.Printf("doInactivate(%v) done for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

func pciUnassign(status *types.DomainStatus, aa *types.AssignableAdapters,
	ignoreErrors bool) {

	log.Printf("pciUnassign(%v, %v) for %s\n",
		status.UUIDandVersion, ignoreErrors, status.DisplayName)

	// Unassign any pci devices but keep UsedByUUID set and keep in status
	for _, adapter := range status.IoAdapterList {
		log.Printf("doInactivate processing adapter %d %s\n",
			adapter.Type, adapter.Name)
		ib := types.LookupIoBundle(aa, adapter.Type, adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if ib == nil {
			log.Fatalf("doInactivate IoBundle disappeared %d %s for %s\n",
				adapter.Type, adapter.Name, status.DomainName)
		}
		if ib.UsedByUUID != status.UUIDandVersion.UUID {
			log.Printf("doInactivate IoBundle not ours by %s: %d %s for %s\n",
				ib.UsedByUUID, adapter.Type, adapter.Name,
				status.DomainName)
			continue
		}
		if ib.Lookup && ib.PciShort == "" {
			log.Fatal("doInactivate lookup missing: %d %s for %s\n",
				adapter.Type, adapter.Name, status.DomainName)
		}
		if ib.PciShort != "" {
			log.Printf("Removing %s %s from %s\n",
				ib.PciLong, ib.PciShort, status.DomainName)
			err := pciAssignableRem(ib.PciLong)
			if err != nil && !ignoreErrors {
				status.LastErr = fmt.Sprintf("%v", err)
				status.LastErrTime = time.Now()
				return
			}
		}
	}
}

// Produce DomainStatus based on the config
func configToStatus(config types.DomainConfig, aa *types.AssignableAdapters,
	status *types.DomainStatus) error {
	log.Printf("configToStatus(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)
	for i, dc := range config.DiskConfigList {
		ds := &status.DiskStatusList[i]
		ds.ImageSha256 = dc.ImageSha256
		ds.ReadOnly = dc.ReadOnly
		ds.Preserve = dc.Preserve
		ds.Format = dc.Format
		ds.Devtype = dc.Devtype
		// map from i=1 to xvda, 2 to xvdb etc
		xv := "xvd" + string(int('a')+i)
		ds.Vdev = xv
		locationDir := verifiedDirname + "/" + dc.ImageSha256
		log.Printf("configToStatus(%v) processing disk img %s for %s\n",
			config.UUIDandVersion, locationDir, config.DisplayName)
		location, err := locationFromDir(locationDir)
		if err != nil {
			return err
		}
		ds.FileLocation = location
		target := location
		if !dc.ReadOnly {
			// Pick new location for a per-guest copy
			dstFilename := fmt.Sprintf("%s/%s-%d.%s",
				rwImgDirname, dc.ImageSha256, config.AppNum,
				dc.Format)
			target = dstFilename
		}
		ds.ActiveFileLocation = target
	}
	for _, adapter := range config.IoAdapterList {
		log.Printf("configToStatus processing adapter %d %s\n",
			adapter.Type, adapter.Name)
		// Lookup to make sure adapter exists on this device
		ib := types.LookupIoBundle(aa, adapter.Type, adapter.Name)
		if ib == nil {
			return errors.New(fmt.Sprintf("Unknown adapter %d %s\n",
				adapter.Type, adapter.Name))
		}
		if ib.UsedByUUID != nilUUID {
			return errors.New(fmt.Sprintf("Adapter %d %s used by %s\n",
				adapter.Type, adapter.Name, ib.UsedByUUID))
		}
		for _, m := range ib.Members {
			if isUplink(m) {
				return errors.New(fmt.Sprintf("Adapter %d %s member %s is (part of) an uplink\n",
					adapter.Type, adapter.Name, m))
			}
		}

		// Does it exist?
		// Then save the PCI ID before we assign it away
		long, short, err := types.IoBundleToPci(ib)
		if err != nil {
			log.Printf("IoBundleToPci failed: %v\n", err)
			return err
		}
		log.Printf("configToStatus setting uuid %s for adapter %d %s\n",
			config.Key(), adapter.Type, adapter.Name)
		ib.UsedByUUID = config.UUIDandVersion.UUID
		ib.PciLong = long
		ib.PciShort = short
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
		bootLoader = config.BootLoader
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
	irqString := ""
	for _, irq := range config.IRQs {
		if irqString != "" {
			irqString += ","
		}
		irqString += fmt.Sprintf("%d", irq)
	}
	if irqString != "" {
		file.WriteString(fmt.Sprintf("irqs = [%s]\n", irqString))
	}
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
	// Note that qcow2 images might have partitions hence xvda1 by default
	if rootDev != "" {
		file.WriteString(fmt.Sprintf("root = \"%s\"\n", rootDev))
	}
	if extra != "" {
		file.WriteString(fmt.Sprintf("extra = \"%s\"\n", extra))
	}
	file.WriteString(fmt.Sprintf("serial = \"%s\"\n", "pty"))
	// Always prefer CDROM vdisk over disk
	file.WriteString(fmt.Sprintf("boot = \"%s\"\n", "dc"))

	diskString := ""
	for i, dc := range config.DiskConfigList {
		ds := status.DiskStatusList[i]
		access := "rw"
		if dc.ReadOnly {
			access = "ro"
		}
		oneDisk := fmt.Sprintf("'%s,%s,%s,%s'",
			ds.ActiveFileLocation, dc.Format, ds.Vdev, access)
		log.Printf("Processing disk %d: %s\n", i, oneDisk)
		if diskString == "" {
			diskString = oneDisk
		} else {
			diskString = diskString + ", " + oneDisk
		}
	}
	file.WriteString(fmt.Sprintf("disk = [%s]\n", diskString))

	vifString := ""
	for _, net := range config.VifList {
		oneVif := fmt.Sprintf("'bridge=%s,vifname=%s,mac=%s'",
			net.Bridge, net.Vif, net.Mac)
		if vifString == "" {
			vifString = oneVif
		} else {
			vifString = vifString + ", " + oneVif
		}
	}
	file.WriteString(fmt.Sprintf("vif = [%s]\n", vifString))

	// Gather all PCI assignments into a single line
	var pciAssignments []string

	for _, adapter := range config.IoAdapterList {
		log.Printf("configToXenCfg processing adapter %d %s\n",
			adapter.Type, adapter.Name)
		ib := types.LookupIoBundle(aa, adapter.Type, adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if ib == nil {
			log.Fatalf("configToXencfg IoBundle disappeared %d %s for %s\n",
				adapter.Type, adapter.Name, status.DomainName)
		}
		if ib.UsedByUUID != config.UUIDandVersion.UUID {
			log.Fatalf("configToXencfg IoBundle not ours %s: %d %s for %s\n",
				ib.UsedByUUID, adapter.Type, adapter.Name,
				status.DomainName)
		}
		if ib.Lookup && ib.PciShort == "" {
			log.Fatal("configToXencfg lookup missing: %d %s\n",
				ib.Type, ib.Name)
		}
		if ib.PciShort != "" {
			pciAssignments = append(pciAssignments, ib.PciShort)
		} else {
			log.Printf("Adding io adapter config <%s>\n", ib.XenCfg)
			file.WriteString(fmt.Sprintf("%s\n", ib.XenCfg))
		}
	}
	if len(pciAssignments) != 0 {
		log.Printf("PCI assignments %v\n", pciAssignments)
		cfg := fmt.Sprintf("pci = [ ")
		for i, pa := range pciAssignments {
			if i != 0 {
				cfg = cfg + ", "
			}
			cfg = cfg + fmt.Sprintf("'%s'", pa)
		}
		cfg = cfg + "]"
		log.Printf("Adding pci config <%s>\n", cfg)
		file.WriteString(fmt.Sprintf("%s\n", cfg))
	}
	return nil
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
// XXX to save key when the goroutine is created.
// XXX separate goroutine to run cp? Add "copy complete" status?
func handleModify(ctx *domainContext, key string,
	config *types.DomainConfig, status *types.DomainStatus) {

	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	status.PendingModify = true
	publishDomainStatus(ctx, status)

	changed := false
	if config.Activate && !status.Activated {
		if status.LastErr != "" {
			log.Printf("handleModify(%v) existing error for %s\n",
				config.UUIDandVersion, config.DisplayName)
			status.PendingModify = false
			publishDomainStatus(ctx, status)
			return
		}
		status.VirtualizationMode = config.VirtualizationMode
		status.EnableVnc = config.EnableVnc
		doActivate(*config, status, ctx.assignableAdapters)
		changed = true
	} else if !config.Activate {
		if status.LastErr != "" {
			log.Printf("handleModify(%v) clearing existing error for %s\n",
				config.UUIDandVersion, config.DisplayName)
			status.LastErr = ""
			status.LastErrTime = time.Time{}
			publishDomainStatus(ctx, status)
			doInactivate(status, ctx.assignableAdapters)
			status.VirtualizationMode = config.VirtualizationMode
			status.EnableVnc = config.EnableVnc
			changed = true
		} else if status.Activated {
			doInactivate(status, ctx.assignableAdapters)
			status.VirtualizationMode = config.VirtualizationMode
			status.EnableVnc = config.EnableVnc
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
		log.Printf("handleModify(%v) DONE for %s\n",
			config.UUIDandVersion, config.DisplayName)
		return
	}

	// XXX check if we have status.LastErr != "" and delete and retry
	// even if same version. XXX won't the above Activate/Activated checks
	// result in redoing things? Could have failures during copy i.e.
	// before activation.

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Printf("Same version %s for %s\n",
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
	log.Printf("handleModify(%v) DONE for %s\n",
		config.UUIDandVersion, config.DisplayName)
}

// Used to wait both after shutdown and destroy
func waitForDomainGone(status types.DomainStatus, maxDelay time.Duration) bool {
	gone := false
	var delay time.Duration
	for {
		log.Printf("waitForDomainGone(%v) for %s: waiting for %v\n",
			status.UUIDandVersion, status.DisplayName, delay)
		time.Sleep(delay)
		if err := xlStatus(status.DomainName, status.DomainId); err != nil {
			log.Printf("waitForDomainGone(%v) for %s: domain is gone\n",
				status.UUIDandVersion, status.DisplayName)
			gone = true
			break
		} else {
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				// Give up
				log.Printf("waitForDomainGone(%v) for %s: giving up\n",
					status.UUIDandVersion, status.DisplayName)
				break
			}
		}
	}
	return gone
}

func handleDelete(ctx *domainContext, key string, status *types.DomainStatus) {

	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	// XXX dumping status to log
	xlStatus(status.DomainName, status.DomainId)

	status.PendingDelete = true
	publishDomainStatus(ctx, status)

	if status.Activated {
		doInactivate(status, ctx.assignableAdapters)
	} else {
		pciUnassign(status, ctx.assignableAdapters, true)
	}

	// Look for any adapters used by us and clear UsedByUUID
	// XXX zedagent might assume that the setting to nil arrives before
	// the delete of the DomainStatus. Check
	cleanupAdapters(ctx, status.IoAdapterList, status.UUIDandVersion.UUID)

	publishDomainStatus(ctx, status)

	// Delete xen cfg file for good measure
	filename := xenCfgFilename(status.AppNum)
	if err := os.Remove(filename); err != nil {
		log.Println(err)
	}

	// Do we need to delete any rw files that were not deleted during
	// inactivation i.e. those preserved across reboots?
	for _, ds := range status.DiskStatusList {
		if !ds.ReadOnly && ds.Preserve {
			log.Printf("Delete copy at %s\n", ds.ActiveFileLocation)
			if err := os.Remove(ds.ActiveFileLocation); err != nil {
				log.Println(err)
				// XXX return? Cleanup status?
			}
		}
	}
	status.PendingDelete = false
	publishDomainStatus(ctx, status)
	// Write out what we modified to DomainStatus aka delete
	unpublishDomainStatus(ctx, status)
	log.Printf("handleDelete(%v) DONE for %s\n",
		status.UUIDandVersion, status.DisplayName)
}

// Create in paused state; Need to call xlUnpause later
func xlCreate(domainName string, xenCfgFilename string) (int, error) {
	log.Printf("xlCreate %s %s\n", domainName, xenCfgFilename)
	cmd := "xl"
	args := []string{
		"create",
		xenCfgFilename,
		"-p",
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("xl create failed ", err)
		log.Println("xl create output ", string(stdoutStderr))
		return 0, errors.New(fmt.Sprintf("xl create failed: %s\n",
			string(stdoutStderr)))
	}
	log.Printf("xl create done\n")

	args = []string{
		"domid",
		domainName,
	}
	stdoutStderr, err = wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("xl domid failed ", err)
		log.Println("xl domid output ", string(stdoutStderr))
		return 0, errors.New(fmt.Sprintf("xl domid failed: %s\n",
			string(stdoutStderr)))
	}
	res := strings.TrimSpace(string(stdoutStderr))
	domainId, err := strconv.Atoi(res)
	if err != nil {
		log.Printf("Can't extract domainId from %s: %s\n", res, err)
		return 0, errors.New(fmt.Sprintf("Can't extract domainId from %s: %s\n", res, err))
	}
	return domainId, nil
}

func xlStatus(domainName string, domainId int) error {
	log.Printf("xlStatus %s %d\n", domainName, domainId)
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
		log.Println("xl list failed ", err)
		log.Println("xl list output ", string(stdoutStderr))
		return errors.New(fmt.Sprintf("xl list failed: %s\n",
			string(stdoutStderr)))
	}
	// XXX parse json to look at state? Not currently included
	log.Printf("xl list done. Result %s\n", string(stdoutStderr))
	return nil
}

// If we have a domain reboot issue the domainId
// can change.
func xlDomid(domainName string, domainId int) (int, error) {
	if debug {
		log.Printf("xlDomid %s %d\n", domainName, domainId)
	}
	cmd := "xl"
	args := []string{
		"domid",
		domainName,
	}
	// Avoid wrap since we are called periodically
	stdoutStderr, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		if debug {
			log.Println("xl domid failed ", err)
			log.Println("xl domid output ", string(stdoutStderr))
		}
		return domainId, errors.New(fmt.Sprintf("xl domid failed: %s\n",
			string(stdoutStderr)))
	}
	res := strings.TrimSpace(string(stdoutStderr))
	domainId2, err := strconv.Atoi(res)
	if err != nil {
		log.Printf("xl domid not integer %s: failed %s\n", res, err)
		return domainId, err
	}
	if domainId2 != domainId {
		log.Printf("Warning: domainid changed from %d to %d for %s\n",
			domainId, domainId2, domainName)
	}
	return domainId2, err
}

// Perform xenstore write to disable all of these for all VIFs
// feature-sg, feature-gso-tcpv4, feature-gso-tcpv6, feature-ipv6-csum-offload
func xlDisableVifOffload(domainName string, domainId int, vifCount int) error {
	log.Printf("xlDisableVifOffload %s %d %d\n",
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
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-ipv6-csum-offload",
				pref, domainId, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-sg",
				pref, domainId, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-gso-tcpv4",
				pref, domainId, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-gso-tcpv6",
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
				log.Println("xenstore write failed ", err)
				log.Println("xenstore write output ", string(stdoutStderr))
				return errors.New(fmt.Sprintf("xenstore write failed: %s\n",
					string(stdoutStderr)))
			}
			log.Printf("xenstore write done. Result %s\n",
				string(stdoutStderr))
		}
	}

	log.Printf("xlDisableVifOffload done.\n")
	return nil
}

func xlUnpause(domainName string, domainId int) error {
	log.Printf("xlUnpause %s %d\n", domainName, domainId)
	cmd := "xl"
	args := []string{
		"unpause",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("xl unpause failed ", err)
		log.Println("xl unpause output ", string(stdoutStderr))
		return errors.New(fmt.Sprintf("xl unpause failed: %s\n",
			string(stdoutStderr)))
	}
	log.Printf("xlUnpause done. Result %s\n", string(stdoutStderr))
	return nil
}

func xlShutdown(domainName string, domainId int, force bool) error {
	log.Printf("xlShutdown %s %d\n", domainName, domainId)
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
		log.Println("xl shutdown failed ", err)
		log.Println("xl shutdown output ", string(stdoutStderr))
		return errors.New(fmt.Sprintf("xl shutdown failed: %s\n",
			string(stdoutStderr)))
	}
	log.Printf("xl shutdown done\n")
	return nil
}

func xlDestroy(domainName string, domainId int) error {
	log.Printf("xlDestroy %s %d\n", domainName, domainId)
	cmd := "xl"
	args := []string{
		"destroy",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Println("xl destroy failed ", err)
		log.Println("xl destroy output ", string(stdoutStderr))
		return errors.New(fmt.Sprintf("xl destroy failed: %s\n",
			string(stdoutStderr)))
		return err
	}
	log.Printf("xl destroy done\n")
	return nil
}

func locationFromDir(locationDir string) (string, error) {
	if _, err := os.Stat(locationDir); err != nil {
		log.Printf("Missing directory: %s, %s\n", locationDir, err)
		return "", err
	}
	// locationDir is a directory. Need to find single file inside
	// which the verifier ensures.
	locations, err := ioutil.ReadDir(locationDir)
	if err != nil {
		log.Println(err)
		return "", err
	}
	if len(locations) != 1 {
		log.Printf("Multiple files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("Multiple files in %s\n",
			locationDir))
	}
	if len(locations) == 0 {
		log.Printf("No files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("No files in %s\n",
			locationDir))
	}
	return locationDir + "/" + locations[0].Name(), nil
}

func pciAssignableAdd(long string) error {
	log.Printf("pciAssignableAdd %s\n", long)
	cmd := "xl"
	args := []string{
		"pci-assignable-add",
		long,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("xl pci-assignable-add failed: %s\n",
			string(stdoutStderr))
		log.Println(errStr)
		return errors.New(errStr)
	}
	log.Printf("xl pci-assignable-add done\n")
	return nil
}

func pciAssignableRem(long string) error {
	log.Printf("pciAssignableRem %s\n", long)
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
		log.Println(errStr)
		return errors.New(errStr)
	}
	log.Printf("xl pci-assignable-rem done\n")
	return nil
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	if key != "global" {
		log.Printf("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Printf("handleDNSModify for %s\n", key)
	deviceNetworkStatus = status
	devicenetwork.ProxyToEnv(deviceNetworkStatus.ProxyConfig)
	log.Printf("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {
	log.Printf("handleDNSDelete for %s\n", key)

	if key != "global" {
		log.Printf("handleDNSDelete: ignoring %s\n", key)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	devicenetwork.ProxyToEnv(deviceNetworkStatus.ProxyConfig)
	log.Printf("handleDNSDelete done for %s\n", key)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*domainContext)
	if key != "global" {
		log.Printf("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Printf("handleGlobalConfigModify for %s\n", key)
	if val, ok := agentlog.GetDebug(ctx.subGlobalConfig, agentName); ok {
		debug = val
		log.Printf("handleGlobalConfigModify: debug %v\n", debug)
	}
	// XXX add loglevel etc
	log.Printf("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleGlobalConfigDelete for %s\n", key)

	if key != "global" {
		log.Printf("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	debug = false
	log.Printf("handleGlobalConfigDelete: debug %v\n", debug)
	// XXX add loglevel etc
	log.Printf("handleGlobalConfigDelete done for %s\n", key)
}
