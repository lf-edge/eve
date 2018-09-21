// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Process input in the form of collections of DownloaderConfig structs
// and publish the results as collections of DownloaderStatus structs.
// There are several inputs and outputs based on the objType.

package downloader

import (
	"errors"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/api/zconfig"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"github.com/zededa/go-provision/zedcloud"
	"github.com/zededa/shared/libs/zedUpload"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	appImgObj = "appImg.obj"
	baseOsObj = "baseOs.obj"
	certObj   = "cert.obj"
	agentName = "downloader"

	persistDir            = "/persist"
	objectDownloadDirname = persistDir + "/downloads"
)

// Go doesn't like this as a constant
var (
	downloaderObjTypes = []string{appImgObj, baseOsObj, certObj}
)

// Set from Makefile
var Version = "No version specified"

type downloaderContext struct {
	dCtx                    *zedUpload.DronaCtx
	subDeviceNetworkStatus  *pubsub.Subscription
	subAppImgConfig         *pubsub.Subscription
	pubAppImgStatus         *pubsub.Publication
	subBaseOsConfig         *pubsub.Subscription
	pubBaseOsStatus         *pubsub.Publication
	subCertObjConfig        *pubsub.Subscription
	pubCertObjStatus        *pubsub.Publication
	subGlobalDownloadConfig *pubsub.Subscription
	pubGlobalDownloadStatus *pubsub.Publication
	deviceNetworkStatus     types.DeviceNetworkStatus
	globalConfig            types.GlobalDownloadConfig
	globalStatus            types.GlobalDownloadStatus
	subGlobalConfig         *pubsub.Subscription
}

var debug = false
var debugOverride bool // From command line arg

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
	debugOverride = debug
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)

	cms := zedcloud.GetCloudMetrics() // Need type of data
	pub, err := pubsub.PublishWithDebug(agentName, cms, &debug)
	if err != nil {
		log.Fatal(err)
	}

	// Publish send metrics for zedagent every 10 seconds
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	// Any state needed by handler functions
	ctx := downloaderContext{}

	// Look for global config like debug
	subGlobalConfig, err := pubsub.SubscribeWithDebug("",
		agentlog.GlobalConfig{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := pubsub.SubscribeWithDebug("zedrouter",
		types.DeviceNetworkStatus{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	subGlobalDownloadConfig, err := pubsub.SubscribeWithDebug("",
		types.GlobalDownloadConfig{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalDownloadConfig.ModifyHandler = handleGlobalDownloadConfigModify
	ctx.subGlobalDownloadConfig = subGlobalDownloadConfig
	subGlobalDownloadConfig.Activate()

	pubGlobalDownloadStatus, err := pubsub.PublishWithDebug(agentName,
		types.GlobalDownloadStatus{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubGlobalDownloadStatus = pubGlobalDownloadStatus

	// Set up our publications before the subscriptions so ctx is set
	pubAppImgStatus, err := pubsub.PublishScopeWithDebug(agentName, appImgObj,
		types.DownloaderStatus{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppImgStatus = pubAppImgStatus
	pubAppImgStatus.ClearRestarted()

	pubBaseOsStatus, err := pubsub.PublishScopeWithDebug(agentName, baseOsObj,
		types.DownloaderStatus{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubBaseOsStatus = pubBaseOsStatus
	pubBaseOsStatus.ClearRestarted()

	pubCertObjStatus, err := pubsub.PublishScopeWithDebug(agentName, certObj,
		types.DownloaderStatus{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubCertObjStatus = pubCertObjStatus
	pubCertObjStatus.ClearRestarted()

	subAppImgConfig, err := pubsub.SubscribeScopeWithDebug("zedmanager",
		appImgObj, types.DownloaderConfig{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgConfig.ModifyHandler = handleAppImgModify
	subAppImgConfig.DeleteHandler = handleAppImgDelete
	ctx.subAppImgConfig = subAppImgConfig
	subAppImgConfig.Activate()

	subBaseOsConfig, err := pubsub.SubscribeScopeWithDebug("zedagent",
		baseOsObj, types.DownloaderConfig{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsConfig.ModifyHandler = handleBaseOsModify
	subBaseOsConfig.DeleteHandler = handleBaseOsDelete
	ctx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()

	subCertObjConfig, err := pubsub.SubscribeScopeWithDebug("zedagent",
		certObj, types.DownloaderConfig{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subCertObjConfig.ModifyHandler = handleCertObjModify
	subCertObjConfig.DeleteHandler = handleCertObjDelete
	ctx.subCertObjConfig = subCertObjConfig
	subCertObjConfig.Activate()

	pubAppImgStatus.SignalRestarted()
	pubBaseOsStatus.SignalRestarted()
	pubCertObjStatus.SignalRestarted()

	// First wait to have some uplinks with addresses
	// Looking at any uplinks since we can do baseOS download over all
	// Also ensure GlobalDownloadConfig has been read
	for types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus) == 0 ||
		ctx.globalConfig.MaxSpace == 0 {
		log.Printf("Waiting for uplink addresses or Global Config\n")

		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subGlobalDownloadConfig.C:
			subGlobalDownloadConfig.ProcessChange(change)
		}
	}
	log.Printf("Have %d uplinks addresses to use\n",
		types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus))

	ctx.dCtx = downloaderInit(&ctx)

	for {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subCertObjConfig.C:
			subCertObjConfig.ProcessChange(change)

		case change := <-subAppImgConfig.C:
			subAppImgConfig.ProcessChange(change)

		case change := <-subBaseOsConfig.C:
			subBaseOsConfig.ProcessChange(change)

		case change := <-subGlobalDownloadConfig.C:
			subGlobalDownloadConfig.ProcessChange(change)

		case <-publishTimer.C:
			err := pub.Publish("global", zedcloud.GetCloudMetrics())
			if err != nil {
				log.Println(err)
			}
		}
	}
}

// Wrappers to add objType for create. The Delete wrappers are merely
// for function name consistency
func handleAppImgModify(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderModify(ctxArg, appImgObj, key, configArg)
}

func handleAppImgDelete(ctxArg interface{}, key string, configArg interface{}) {
	handleDownloaderDelete(ctxArg, key, configArg)
}

func handleBaseOsModify(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderModify(ctxArg, baseOsObj, key, configArg)
}

func handleBaseOsDelete(ctxArg interface{}, key string, configArg interface{}) {
	handleDownloaderDelete(ctxArg, key, configArg)
}

func handleCertObjModify(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderModify(ctxArg, certObj, key, configArg)
}

func handleCertObjDelete(ctxArg interface{}, key string, configArg interface{}) {
	handleDownloaderDelete(ctxArg, key, configArg)
}

// Callers must be careful to publish any changes to DownloaderStatus
func lookupDownloaderStatus(ctx *downloaderContext, objType string,
	key string) *types.DownloaderStatus {

	pub := downloaderPublication(ctx, objType)
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("lookupDownloaderStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastDownloaderStatus(st)
	if status.Key() != key {
		log.Printf("lookupDownloaderStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

// We have one goroutine per provisioned domU object.
// Channel is used to send config (new and updates)
// Channel is closed when the object is deleted
// The go-routine owns writing status for the object
// The key in the map is the objects Key().
type handlers map[string]chan<- interface{}

var handlerMap handlers

func handlersInit() {
	handlerMap = make(handlers)
}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func handleDownloaderModify(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Printf("handleDownloaderModify(%s)\n", key)
	ctx := ctxArg.(*downloaderContext)
	config := cast.CastDownloaderConfig(configArg)
	if config.Key() != key {
		log.Printf("handleDownloaderModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	// Do we have a channel/goroutine?
	h, ok := handlerMap[config.Key()]
	if !ok {
		h1 := make(chan interface{})
		handlerMap[config.Key()] = h1
		go runHandler(ctx, objType, key, h1)
		h = h1
	}
	log.Printf("Sending config to handler\n")
	h <- configArg
	log.Printf("handleDownloaderModify(%s) done\n", key)
}

func handleDownloaderDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Printf("handleDownloaderDelete(%s)\n", key)
	// Do we have a channel/goroutine?
	h, ok := handlerMap[key]
	if ok {
		log.Printf("Closing channel\n")
		close(h)
		delete(handlerMap, key)
	} else {
		log.Printf("handleDownloaderDelete: unknown %s\n", key)
		return
	}
	log.Printf("handleDownloaderDelete(%s) done\n", key)
}

// Server for each domU
func runHandler(ctx *downloaderContext, objType string, key string,
	c <-chan interface{}) {

	log.Printf("runHandler starting\n")

	closed := false
	for !closed {
		select {
		case configArg, ok := <-c:
			if ok {
				config := cast.CastDownloaderConfig(configArg)
				status := lookupDownloaderStatus(ctx,
					objType, key)
				if status == nil {
					handleCreate(ctx, objType, config, key)
				} else {
					handleModify(ctx, key, config, status)
				}
			} else {
				// Closed
				status := lookupDownloaderStatus(ctx,
					objType, key)
				if status != nil {
					handleDelete(ctx, key, status)
				}
				closed = true
			}
		}
	}
	log.Printf("runHandler(%s) DONE\n", key)
}

func handleCreate(ctx *downloaderContext, objType string,
	config types.DownloaderConfig, key string) {

	log.Printf("handleCreate(%v) objType %s for %s\n",
		config.Safename, objType, config.DownloadURL)

	if objType == "" {
		log.Fatalf("handleCreate: No ObjType for %s\n",
			config.Safename)
	}
	// Start by marking with PendingAdd
	status := types.DownloaderStatus{
		Safename:       config.Safename,
		ObjType:        objType,
		RefCount:       config.RefCount,
		DownloadURL:    config.DownloadURL,
		UseFreeUplinks: config.UseFreeUplinks,
		ImageSha256:    config.ImageSha256,
		PendingAdd:     true,
	}
	publishDownloaderStatus(ctx, &status)

	// Check if we have space
	kb := types.RoundupToKB(config.Size)
	if uint(kb) >= ctx.globalStatus.RemainingSpace {
		errString := fmt.Sprintf("Would exceed remaining space %d vs %d\n",
			kb, ctx.globalStatus.RemainingSpace)
		log.Println(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		publishDownloaderStatus(ctx, &status)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return
	}

	// Update reserved space. Keep reserved until doDelete
	// XXX RefCount -> 0 should keep it reserved.
	status.ReservedSpace = uint(types.RoundupToKB(config.Size))
	ctx.globalStatus.ReservedSpace += status.ReservedSpace
	updateRemainingSpace(ctx)

	// If RefCount == 0 then we don't yet download.
	if config.RefCount == 0 {
		// XXX odd to treat as error.
		errString := fmt.Sprintf("RefCount==0; download deferred for %s\n",
			config.DownloadURL)
		log.Println(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		publishDownloaderStatus(ctx, &status)
		log.Printf("handleCreate deferred for %s\n", config.DownloadURL)
		return
	}

	handleSyncOp(ctx, key, config, &status)
}

// Allow to cancel by setting RefCount = 0. Same as delete? RefCount 0->1
// means download. Ignore other changes?
func handleModify(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus) {

	log.Printf("handleModify(%v) objType %s for %s\n",
		status.Safename, status.ObjType, status.DownloadURL)

	if status.ObjType == "" {
		log.Fatalf("handleModify: No ObjType for %s\n",
			status.Safename)
	}
	locDirname := objectDownloadDirname + "/" + status.ObjType

	if config.DownloadURL != status.DownloadURL {
		log.Printf("URL changed - not allowed %s -> %s\n",
			config.DownloadURL, status.DownloadURL)
		return
	}
	// If the sha changes, we treat it as a delete and recreate.
	// Ditto if we had a failure.
	if (status.ImageSha256 != "" && status.ImageSha256 != config.ImageSha256) ||
		status.LastErr != "" {
		reason := ""
		if status.ImageSha256 != config.ImageSha256 {
			reason = "sha256 changed"
		} else {
			reason = "recovering from previous error"
		}
		log.Printf("handleModify %s for %s\n",
			reason, config.DownloadURL)
		doDelete(ctx, key, locDirname, status)
		handleCreate(ctx, status.ObjType, config, key)
		log.Printf("handleModify done for %s\n", config.DownloadURL)
		return
	}

	// XXX do work; look for refcnt -> 0 and delete; cancel any running
	// download
	// If RefCount from zero to non-zero then do install
	if status.RefCount == 0 && config.RefCount != 0 {
		status.PendingModify = true
		log.Printf("handleModify installing %s\n", config.DownloadURL)
		handleCreate(ctx, status.ObjType, config, key)
		status.RefCount = config.RefCount
		status.PendingModify = false
		publishDownloaderStatus(ctx, status)
	} else if status.RefCount != 0 && config.RefCount == 0 {
		log.Printf("handleModify deleting %s\n", config.DownloadURL)
		doDelete(ctx, key, locDirname, status)
	} else if status.RefCount != config.RefCount {
		log.Printf("handleModify RefCount change %s from %d to %d\n",
			config.DownloadURL, status.RefCount, config.RefCount)
		status.RefCount = config.RefCount
		publishDownloaderStatus(ctx, status)
	}
	log.Printf("handleModify done for %s\n", config.DownloadURL)
}

func doDelete(ctx *downloaderContext, key string, locDirname string,
	status *types.DownloaderStatus) {

	log.Printf("doDelete(%v) for %s\n", status.Safename, status.DownloadURL)

	deletefile(locDirname+"/pending", status)
	deletefile(locDirname+"/verifier", status)
	// verifier handles the verified directory

	status.State = types.INITIAL
	ctx.globalStatus.UsedSpace -= uint(types.RoundupToKB(status.Size))
	status.Size = 0

	// XXX Asymmetric; handleCreate reserved on RefCount 0. We unreserve
	// going back to RefCount 0. FIXed
	updateRemainingSpace(ctx)
	publishDownloaderStatus(ctx, status)
}

func deletefile(dirname string, status *types.DownloaderStatus) {
	if status.ImageSha256 != "" {
		dirname = dirname + "/" + status.ImageSha256
	}

	if _, err := os.Stat(dirname); err == nil {
		filename := dirname + "/" + status.Safename
		if _, err := os.Stat(filename); err == nil {
			log.Printf("Deleting %s\n", filename)
			// Remove file
			if err := os.Remove(filename); err != nil {
				log.Printf("Failed to remove %s: err %s\n",
					filename, err)
			}
		}
	}
}

func handleDelete(ctx *downloaderContext, key string,
	status *types.DownloaderStatus) {

	log.Printf("handleDelete(%v) objType %s for %s\n",
		status.Safename, status.ObjType, status.DownloadURL)

	if status.ObjType == "" {
		log.Fatalf("handleDelete: No ObjType for %s\n",
			status.Safename)
	}
	locDirname := objectDownloadDirname + "/" + status.ObjType

	status.PendingDelete = true
	publishDownloaderStatus(ctx, status)

	ctx.globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	ctx.globalStatus.UsedSpace -= uint(types.RoundupToKB(status.Size))
	status.Size = 0

	updateRemainingSpace(ctx)

	publishDownloaderStatus(ctx, status)

	doDelete(ctx, key, locDirname, status)

	status.PendingDelete = false
	publishDownloaderStatus(ctx, status)

	// Write out what we modified to DownloaderStatus aka delete
	unpublishDownloaderStatus(ctx, status)
	log.Printf("handleDelete done for %s, %s\n", status.DownloadURL, locDirname)
}

// helper functions

func downloaderInit(ctx *downloaderContext) *zedUpload.DronaCtx {

	initializeDirs()

	log.Printf("MaxSpace %d\n", ctx.globalConfig.MaxSpace)

	ctx.globalStatus.UsedSpace = 0
	ctx.globalStatus.ReservedSpace = 0
	updateRemainingSpace(ctx)

	// XXX how do we find out when verifier cleans up duplicates etc?
	// XXX run this periodically... What about downloads inprogress
	// when we run it?
	// XXX look at verifier and downloader status which have Size
	// We read objectDownloadDirname/* and determine how much space
	// is used. Place in GlobalDownloadStatus. Calculate remaining space.
	totalUsed := sizeFromDir(objectDownloadDirname)
	ctx.globalStatus.UsedSpace = uint(types.RoundupToKB(totalUsed))
	// Note that the UsedSpace calculated during initialization can exceed
	// MaxSpace, and RemainingSpace is a uint!
	if ctx.globalStatus.UsedSpace > ctx.globalConfig.MaxSpace {
		ctx.globalStatus.UsedSpace = ctx.globalConfig.MaxSpace
	}
	updateRemainingSpace(ctx)

	// create drona interface
	dCtx, err := zedUpload.NewDronaCtx("zdownloader", 0)

	if dCtx == nil {
		log.Printf("context create fail %s\n", err)
		log.Fatal(err)
	}

	return dCtx
}

func handleGlobalDownloadConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := cast.CastGlobalDownloadConfig(configArg)
	if key != "global" {
		log.Printf("handleGlobalDownloadConfigModify: unexpected key %s\n", key)
		return
	}
	log.Printf("handleGlobalDownloadConfigModify for %s\n", key)
	ctx.globalConfig = config
	log.Printf("handleGlobalDownloadConfigModify done for %s\n", key)
}

func initializeDirs() {

	// Remove any files which didn't make it past the verifier.
	// Though verifier owns it, remove them for calculating the
	// total available space
	// XXX instead rely on verifier status
	clearInProgressDownloadDirs(downloaderObjTypes)

	// create the object download directories
	createDownloadDirs(downloaderObjTypes)
}

// XXX here vs. in verifier? Who owns which dirs? Same as deletes from them.
// create object download directories
func createDownloadDirs(objTypes []string) {

	workingDirTypes := []string{"pending", "verifier", "verified"}

	// now create the download dirs
	for _, objType := range objTypes {
		for _, dirType := range workingDirTypes {
			dirName := objectDownloadDirname + "/" + objType + "/" + dirType
			if _, err := os.Stat(dirName); err != nil {
				log.Printf("Create %s\n", dirName)
				if err := os.MkdirAll(dirName, 0700); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

// clear in-progress object download directories
func clearInProgressDownloadDirs(objTypes []string) {

	inProgressDirTypes := []string{"pending", "verifier"}

	// now create the download dirs
	for _, objType := range objTypes {
		for _, dirType := range inProgressDirTypes {
			dirName := objectDownloadDirname + "/" + objType + "/" + dirType
			if _, err := os.Stat(dirName); err == nil {
				if err := os.RemoveAll(dirName); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

func sizeFromDir(dirname string) uint64 {
	var totalUsed uint64 = 0
	locations, err := ioutil.ReadDir(dirname)
	if err != nil {
		log.Fatal(err)
	}
	for _, location := range locations {
		filename := dirname + "/" + location.Name()
		log.Printf("Looking in %s\n", filename)
		if location.IsDir() {
			size := sizeFromDir(filename)
			log.Printf("Dir %s size %d\n", filename, size)
			totalUsed += size
		} else {
			log.Printf("File %s Size %d\n", filename, location.Size())
			totalUsed += uint64(location.Size())
		}
	}
	return totalUsed
}

func updateRemainingSpace(ctx *downloaderContext) {

	ctx.globalStatus.RemainingSpace = ctx.globalConfig.MaxSpace -
		ctx.globalStatus.UsedSpace - ctx.globalStatus.ReservedSpace

	log.Printf("RemainingSpace %d, maxspace %d, usedspace %d, reserved %d\n",
		ctx.globalStatus.RemainingSpace, ctx.globalConfig.MaxSpace,
		ctx.globalStatus.UsedSpace, ctx.globalStatus.ReservedSpace)
	// Create and write
	publishGlobalStatus(ctx)
}

func publishGlobalStatus(ctx *downloaderContext) {
	ctx.pubGlobalDownloadStatus.Publish("global", &ctx.globalStatus)
}

func publishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := downloaderPublication(ctx, status.ObjType)
	key := status.Key()
	log.Printf("publishDownloaderStatus(%s)\n", key)
	pub.Publish(key, status)
}

func unpublishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := downloaderPublication(ctx, status.ObjType)
	key := status.Key()
	log.Printf("unpublishDownloaderStatus(%s)\n", key)
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("unpublishDownloaderStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func downloaderPublication(ctx *downloaderContext, objType string) *pubsub.Publication {
	var pub *pubsub.Publication
	switch objType {
	case appImgObj:
		pub = ctx.pubAppImgStatus
	case baseOsObj:
		pub = ctx.pubBaseOsStatus
	case certObj:
		pub = ctx.pubCertObjStatus
	default:
		log.Fatalf("downloaderPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}

// cloud storage interface functions/APIs

// XXX should we use --cacart? Would assume we know the root CA.
// XXX Set --limit-rate 100k
// XXX continue based on filesize with: -C -
// Note that support for --dns-interface is not compiled in
// Normally "ifname" is the source IP to be consistent with the S3 loop
func doCurl(url string, ifname string, maxsize uint64, destFilename string) error {
	cmd := "curl"
	args := []string{}
	maxsizeStr := strconv.FormatUint(maxsize, 10)
	if ifname != "" {
		args = []string{
			"-q",
			"-4", // XXX due to getting IPv6 ULAs and not IPv4
			"--insecure",
			"--retry",
			"3",
			"--silent",
			"--show-error",
			"--interface",
			ifname,
			"--max-filesize",
			maxsizeStr,
			"-o",
			destFilename,
			url,
		}
	} else {
		args = []string{
			"-q",
			"-4", // XXX due to getting IPv6 ULAs and not IPv4
			"--insecure",
			"--retry",
			"3",
			"--silent",
			"--show-error",
			"--max-filesize",
			maxsizeStr,
			"-o",
			destFilename,
			url,
		}
	}

	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()

	if err != nil {
		log.Println("curl failed ", err)
	} else {
		log.Printf("curl done: output <%s>\n", string(stdoutStderr))
	}
	return err
}

func doS3(ctx *downloaderContext, syncOp zedUpload.SyncOpType,
	apiKey string, password string, dpath string, region string, maxsize uint64,
	ipSrc net.IP, filename string, locFilename string) error {
	auth := &zedUpload.AuthInput{
		AuthType: "s3",
		Uname:    apiKey,
		Password: password,
	}

	trType := zedUpload.SyncAwsTr

	// create Endpoint
	dEndPoint, err := ctx.dCtx.NewSyncerDest(trType, region, dpath, auth)
	if err != nil {
		log.Printf("NewSyncerDest failed: %s\n", err)
		return err
	}
	dEndPoint.WithSrcIpSelection(ipSrc)
	var respChan = make(chan *zedUpload.DronaRequest)

	log.Printf("syncOp for <%s>, <%s>, <%s>\n", dpath, region, filename)
	// create Request
	// Round up from bytes to Mbytes
	maxMB := (maxsize + 1024*1024 - 1) / (1024 * 1024)
	req := dEndPoint.NewRequest(syncOp, filename, locFilename,
		int64(maxMB), true, respChan)
	if req == nil {
		return errors.New("NewRequest failed")
	}

	req.Post()
	resp := <-respChan
	_, err = resp.GetUpStatus()
	if resp.IsError() == false {
		return nil
	} else {
		return err
	}
}

func doSftp(ctx *downloaderContext, syncOp zedUpload.SyncOpType,
	apiKey string, password string, serverUrl string, dpath string, maxsize uint64,
	ipSrc net.IP, filename string, locFilename string) error {
	auth := &zedUpload.AuthInput{
		AuthType: "sftp",
		Uname:    apiKey,
		Password: password,
	}

	trType := zedUpload.SyncSftpTr

	// create Endpoint
	dEndPoint, err := ctx.dCtx.NewSyncerDest(trType, serverUrl, dpath, auth)
	if err != nil {
		log.Printf("NewSyncerDest failed: %s\n", err)
		return err
	}
	dEndPoint.WithSrcIpSelection(ipSrc)
	var respChan = make(chan *zedUpload.DronaRequest)

	log.Printf("syncOp for <%s>, <%s>\n", dpath, filename)
	// create Request
	// Round up from bytes to Mbytes
	maxMB := (maxsize + 1024*1024 - 1) / (1024 * 1024)
	req := dEndPoint.NewRequest(syncOp, filename, locFilename,
		int64(maxMB), true, respChan)
	if req == nil {
		return errors.New("NewRequest failed")
	}

	req.Post()
	resp := <-respChan
	_, err = resp.GetUpStatus()
	if resp.IsError() == false {
		return nil
	} else {
		return err
	}
}

// Drona APIs for object Download

func handleSyncOp(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus) {
	var err error
	var errStr string
	var locFilename string

	var syncOp zedUpload.SyncOpType = zedUpload.SyncOpDownload

	if status.ObjType == "" {
		log.Fatalf("handleSyncOp: No ObjType for %s\n",
			status.Safename)
	}
	locDirname := objectDownloadDirname + "/" + status.ObjType
	locFilename = locDirname + "/pending"

	// update status to DOWNLOAD STARTED
	status.State = types.DOWNLOAD_STARTED
	publishDownloaderStatus(ctx, status)

	if config.ImageSha256 != "" {
		locFilename = locFilename + "/" + config.ImageSha256
	}

	if _, err := os.Stat(locFilename); err != nil {
		log.Printf("Create %s\n", locFilename)
		if err = os.MkdirAll(locFilename, 0755); err != nil {
			log.Fatal(err)
		}
	}

	filename := types.SafenameToFilename(config.Safename)

	locFilename = locFilename + "/" + config.Safename

	log.Printf("Downloading <%s> to <%s> using %v freeuplink\n",
		config.DownloadURL, locFilename, config.UseFreeUplinks)

	var addrCount int
	if config.UseFreeUplinks {
		addrCount = types.CountLocalAddrFree(ctx.deviceNetworkStatus, "")
		log.Printf("Have %d free uplink addresses\n", addrCount)
		err = errors.New("No free IP uplink addresses for download")
	} else {
		addrCount = types.CountLocalAddrAny(ctx.deviceNetworkStatus, "")
		log.Printf("Have %d any uplink addresses\n", addrCount)
		err = errors.New("No IP uplink addresses for download")
	}
	if addrCount == 0 {
		errStr = err.Error()
	}
	metricsUrl := config.DownloadURL
	if config.TransportMethod == zconfig.DsType_DsS3.String() {
		// fake URL for metrics
		metricsUrl = fmt.Sprintf("S3:%s/%s", config.Dpath, filename)
	}

	// Loop through all interfaces until a success
	for addrIndex := 0; addrIndex < addrCount; addrIndex += 1 {
		var ipSrc net.IP
		if config.UseFreeUplinks {
			ipSrc, err = types.GetLocalAddrFree(ctx.deviceNetworkStatus,
				addrIndex, "")
		} else {
			// Note that GetLocalAddrAny has the free ones first
			ipSrc, err = types.GetLocalAddrAny(ctx.deviceNetworkStatus,
				addrIndex, "")
		}
		if err != nil {
			log.Printf("GetLocalAddr failed: %s\n", err)
			errStr = errStr + "\n" + err.Error()
			continue
		}
		ifname := types.GetUplinkFromAddr(ctx.deviceNetworkStatus, ipSrc)
		log.Printf("Using IP source %v if %s transport %v\n",
			ipSrc, ifname, config.TransportMethod)
		switch config.TransportMethod {
		case zconfig.DsType_DsS3.String():
			err = doS3(ctx, syncOp, config.ApiKey,
				config.Password, config.Dpath, config.Region,
				config.Size, ipSrc, filename, locFilename)
			if err != nil {
				log.Printf("Source IP %s failed: %s\n",
					ipSrc.String(), err)
				errStr = errStr + "\n" + err.Error()
				// XXX don't know how much we downloaded!
				// Could have failed half-way. Using zero.
				zedcloud.ZedCloudFailure(ifname,
					metricsUrl, 1024, 0)
			} else {
				// Record how much we downloaded
				info, _ := os.Stat(locFilename)
				size := info.Size()
				zedcloud.ZedCloudSuccess(ifname,
					metricsUrl, 1024, size)
				handleSyncOpResponse(ctx, config, status,
					locFilename, key, "")
				return
			}
		case zconfig.DsType_DsSFTP.String():
			serverUrl := strings.Split(config.DownloadURL, "/")[0]
			err = doSftp(ctx, syncOp, config.ApiKey,
				config.Password, serverUrl, config.Dpath,
				config.Size, ipSrc, filename, locFilename)
			if err != nil {
				log.Printf("Source IP %s failed: %s\n",
					ipSrc.String(), err)
				errStr = errStr + "\n" + err.Error()
				// XXX don't know how much we downloaded!
				// Could have failed half-way. Using zero.
				zedcloud.ZedCloudFailure(ifname,
					metricsUrl, 1024, 0)
			} else {
				// Record how much we downloaded
				info, _ := os.Stat(locFilename)
				size := info.Size()
				zedcloud.ZedCloudSuccess(ifname,
					metricsUrl, 1024, size)
				handleSyncOpResponse(ctx, config, status,
					locFilename, key, "")
				return
			}
		case zconfig.DsType_DsHttp.String(), zconfig.DsType_DsHttps.String(), "":
			err = doCurl(config.DownloadURL, ipSrc.String(),
				config.Size, locFilename)
			if err != nil {
				log.Printf("Source IP %s failed: %s\n",
					ipSrc.String(), err)
				errStr = errStr + "\n" + err.Error()
				zedcloud.ZedCloudFailure(ifname,
					metricsUrl, 1024, 0)
			} else {
				// Record how much we downloaded
				info, _ := os.Stat(locFilename)
				size := info.Size()
				zedcloud.ZedCloudSuccess(ifname,
					metricsUrl, 1024, size)
				handleSyncOpResponse(ctx, config, status,
					locFilename, key, "")
				return
			}
		default:
			log.Fatal("unsupported transport method")
		}
	}
	log.Printf("All source IP addresses failed. All errors:%s\n", errStr)
	handleSyncOpResponse(ctx, config, status, locFilename,
		key, errStr)
}

func handleSyncOpResponse(ctx *downloaderContext, config types.DownloaderConfig,
	status *types.DownloaderStatus, locFilename string,
	key string, errStr string) {

	if status.ObjType == "" {
		log.Fatalf("handleSyncOpResponse: No ObjType for %s\n",
			status.Safename)
	}
	locDirname := objectDownloadDirname + "/" + status.ObjType
	if errStr != "" {
		// Delete file
		doDelete(ctx, key, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errStr
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		publishDownloaderStatus(ctx, status)
		log.Printf("handleSyncOpResponse failed for %s, <%s>\n",
			status.DownloadURL, errStr)
		return
	}

	info, err := os.Stat(locFilename)
	if err != nil {
		log.Printf("handleSyncOpResponse Stat failed for %s <%s>\n",
			status.DownloadURL, err)
		// Delete file
		doDelete(ctx, key, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		publishDownloaderStatus(ctx, status)
		return
	}
	status.Size = uint64(info.Size())

	ctx.globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	ctx.globalStatus.UsedSpace += uint(types.RoundupToKB(status.Size))
	updateRemainingSpace(ctx)

	log.Printf("handleSyncOpResponse successful <%s> <%s>\n",
		config.DownloadURL, locFilename)
	// We do not clear any status.RetryCount, LastErr, etc. The caller
	// should look at State == DOWNLOADED to determine it is done.

	status.ModTime = time.Now()
	status.PendingAdd = false
	status.State = types.DOWNLOADED
	publishDownloaderStatus(ctx, status)
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	status := cast.CastDeviceNetworkStatus(statusArg)
	if key != "global" {
		log.Printf("handleDNSModify: ignoring %s\n", key)
		return
	}

	log.Printf("handleDNSModify for %s\n", key)
	ctx.deviceNetworkStatus = status
	log.Printf("handleDNSModify %d free uplinks addresses; %d any\n",
		types.CountLocalAddrFree(ctx.deviceNetworkStatus, ""),
		types.CountLocalAddrAny(ctx.deviceNetworkStatus, ""))

	devicenetwork.ProxyToEnv(ctx.deviceNetworkStatus.ProxyConfig)
	log.Printf("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	log.Printf("handleDNSDelete for %s\n", key)
	if key != "global" {
		log.Printf("handleDNSDelete: ignoring %s\n", key)
		return
	}
	ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	devicenetwork.ProxyToEnv(ctx.deviceNetworkStatus.ProxyConfig)
	log.Printf("handleDNSDelete done for %s\n", key)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	if key != "global" {
		log.Printf("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Printf("handleGlobalConfigModify for %s\n", key)
	debug = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Printf("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	if key != "global" {
		log.Printf("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Printf("handleGlobalConfigDelete for %s\n", key)
	debug = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Printf("handleGlobalConfigDelete done for %s\n", key)
}
