// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Process input changes from a config directory containing json encoded files
// with DownloaderConfig and compare against DownloaderStatus in the status
// dir.
// ZedManager can stop the download by removing from config directory.
//
// Input directory with config (URL, refcount, maxLength, dstDir)
// Output directory with status (URL, refcount, state, ModTime, lastErr, lastErrTime, retryCount)
// refCount -> 0 means delete from dstDir? Who owns dstDir? Separate mount.

package downloader

import (
	"errors"
	"flag"
	"fmt"
	"github.com/zededa/api/zconfig"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"github.com/zededa/go-provision/zedcloud"
	"github.com/zededa/shared/libs/zedUpload"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
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
}

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	flag.Parse()
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)

	cms := zedcloud.GetCloudMetrics() // Need type of data
	pub, err := pubsub.Publish(agentName, cms)
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

	subDeviceNetworkStatus, err := pubsub.Subscribe("zedrouter",
		types.DeviceNetworkStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	subGlobalDownloadConfig, err := pubsub.Subscribe("",
		types.GlobalDownloadConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalDownloadConfig.ModifyHandler = handleGlobalConfigModify
	ctx.subGlobalDownloadConfig = subGlobalDownloadConfig
	subGlobalDownloadConfig.Activate()

	pubGlobalDownloadStatus, err := pubsub.Publish(agentName,
		types.GlobalDownloadStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubGlobalDownloadStatus = pubGlobalDownloadStatus

	// First wait to have some uplinks with addresses
	// Looking at any uplinks since we can do baseOS download over all
	// Also ensure GlobalDownloadConfig has been read
	for types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus) == 0 ||
		ctx.globalConfig.MaxSpace == 0 {
		log.Printf("Waiting for uplink addresses or Global Config\n")

		select {
		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subGlobalDownloadConfig.C:
			subGlobalDownloadConfig.ProcessChange(change)
		}
	}
	log.Printf("Have %d uplinks addresses to use\n",
		types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus))

	ctx.dCtx = downloaderInit(&ctx)

	// Set up our publications before the subscriptions so ctx is set
	pubAppImgStatus, err := pubsub.PublishScope(agentName, appImgObj,
		types.DownloaderStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppImgStatus = pubAppImgStatus
	pubAppImgStatus.ClearRestarted()

	pubBaseOsStatus, err := pubsub.PublishScope(agentName, baseOsObj,
		types.DownloaderStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubBaseOsStatus = pubBaseOsStatus
	pubBaseOsStatus.ClearRestarted()

	pubCertObjStatus, err := pubsub.PublishScope(agentName, certObj,
		types.DownloaderStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubCertObjStatus = pubCertObjStatus
	pubCertObjStatus.ClearRestarted()

	subAppImgConfig, err := pubsub.SubscribeScope("zedmanager", appImgObj,
		types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgConfig.ModifyHandler = handleAppImgModify
	subAppImgConfig.DeleteHandler = handleAppImgDelete
	ctx.subAppImgConfig = subAppImgConfig
	subAppImgConfig.Activate()

	subBaseOsConfig, err := pubsub.SubscribeScope("zedagent", baseOsObj,
		types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsConfig.ModifyHandler = handleBaseOsModify
	subBaseOsConfig.DeleteHandler = handleBaseOsDelete
	ctx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()

	subCertObjConfig, err := pubsub.SubscribeScope("zedagent", certObj,
		types.DownloaderConfig{}, false, &ctx)
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

	for {
		select {

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

// Wrappers
func handleAppImgModify(ctxArg interface{}, key string,
	configArg interface{}) {

	config := cast.CastDownloaderConfig(configArg)
	ctx := ctxArg.(*downloaderContext)
	if config.Key() != key {
		log.Printf("handleAppImgModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	status := lookupDownloaderStatus(ctx.pubAppImgStatus, key)
	if status == nil {
		handleCreate(ctx, appImgObj, config, key)
	} else {
		handleModify(ctx, key, config, status)
	}
	log.Printf("handleAppImgModify(%s) done\n", key)
}

func handleAppImgDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("handleAppImgDelete(%s)\n", key)
	ctx := ctxArg.(*downloaderContext)
	status := lookupDownloaderStatus(ctx.pubAppImgStatus, key)
	if status == nil {
		log.Printf("handleAppImgDelete: unknown %s\n", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Printf("handleAppImgDelete(%s) done\n", key)
}

func handleBaseOsModify(ctxArg interface{}, key string,
	configArg interface{}) {

	config := cast.CastDownloaderConfig(configArg)
	ctx := ctxArg.(*downloaderContext)
	if config.Key() != key {
		log.Printf("handleBaseOsModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	status := lookupDownloaderStatus(ctx.pubBaseOsStatus, key)
	if status == nil {
		handleCreate(ctx, baseOsObj, config, key)
	} else {
		handleModify(ctx, key, config, status)
	}
	log.Printf("handleBaseOsModify(%s) done\n", key)
}

func handleBaseOsDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("handleBaseOsDelete(%s)\n", key)
	ctx := ctxArg.(*downloaderContext)
	status := lookupDownloaderStatus(ctx.pubBaseOsStatus, key)
	if status == nil {
		log.Printf("handleBaseOsDelete: unknown %s\n", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Printf("handleBaseOsDelete(%s) done\n", key)
}

func handleCertObjModify(ctxArg interface{}, key string,
	configArg interface{}) {

	config := cast.CastDownloaderConfig(configArg)
	ctx := ctxArg.(*downloaderContext)
	if config.Key() != key {
		log.Printf("handleCertObjModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	status := lookupDownloaderStatus(ctx.pubCertObjStatus, key)
	if status == nil {
		handleCreate(ctx, certObj, config, key)
	} else {
		handleModify(ctx, key, config, status)
	}
	log.Printf("handleCertObjModify(%s) done\n", key)
}

func handleCertObjDelete(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("handleCertObjDelete(%s)\n", key)
	ctx := ctxArg.(*downloaderContext)
	status := lookupDownloaderStatus(ctx.pubCertObjStatus, key)
	if status == nil {
		log.Printf("handleCertObjDelete: unknown %s\n", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Printf("handleCertObjDelete(%s) done\n", key)
}

// Callers must be careful to publish any changes to DownloaderStatus
func lookupDownloaderStatus(pub *pubsub.Publication, key string) *types.DownloaderStatus {

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
	updateDownloaderStatus(ctx, &status)

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
		status.State = types.INITIAL
		updateDownloaderStatus(ctx, &status)
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
		status.State = types.INITIAL
		updateDownloaderStatus(ctx, &status)
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
		updateDownloaderStatus(ctx, status)
	} else if status.RefCount != 0 && config.RefCount == 0 {
		log.Printf("handleModify deleting %s\n", config.DownloadURL)
		doDelete(ctx, key, locDirname, status)
	} else if status.RefCount != config.RefCount {
		log.Printf("handleModify RefCount change %s from %d to %d\n",
			config.DownloadURL, status.RefCount, config.RefCount)
		status.RefCount = config.RefCount
		updateDownloaderStatus(ctx, status)
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
	updateDownloaderStatus(ctx, status)
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
	updateDownloaderStatus(ctx, status)

	ctx.globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	ctx.globalStatus.UsedSpace -= uint(types.RoundupToKB(status.Size))
	status.Size = 0

	updateRemainingSpace(ctx)

	updateDownloaderStatus(ctx, status)

	doDelete(ctx, key, locDirname, status)

	status.PendingDelete = false
	updateDownloaderStatus(ctx, status)

	// Write out what we modified to DownloaderStatus aka delete
	removeDownloaderStatus(ctx, status)
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

func handleGlobalConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := cast.CastGlobalDownloadConfig(configArg)
	if key != "global" {
		log.Printf("handleGlobalConfigModify: unexpected key %s\n", key)
		return
	}
	log.Printf("handleGlobalConfigModify for %s\n", key)
	ctx.globalConfig = config
	log.Printf("handleGlobalConfigModify done for %s\n", key)
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
	updateGlobalStatus(ctx)
}

func updateGlobalStatus(ctx *downloaderContext) {
	ctx.pubGlobalDownloadStatus.Publish("global", &ctx.globalStatus)
}

func updateDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	var pub *pubsub.Publication
	switch status.ObjType {
	case appImgObj:
		pub = ctx.pubAppImgStatus
	case baseOsObj:
		pub = ctx.pubBaseOsStatus
	case certObj:
		pub = ctx.pubCertObjStatus
	default:
		log.Fatalf("updateDownloaderStatus: Unknown ObjType %s for %s\n",
			status.ObjType, status.Safename)
	}
	key := status.Key()
	log.Printf("updateDownloaderStatus(%s)\n", key)
	pub.Publish(key, status)
}

func removeDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	var pub *pubsub.Publication
	switch status.ObjType {
	case appImgObj:
		pub = ctx.pubAppImgStatus
	case baseOsObj:
		pub = ctx.pubBaseOsStatus
	case certObj:
		pub = ctx.pubCertObjStatus
	default:
		log.Fatalf("removeDownloaderStatus: Unknown ObjType %s for %s\n",
			status.ObjType, status.Safename)
	}
	key := status.Key()
	log.Printf("removeDownloaderStatus(%s)\n", key)
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("removeDownloaderStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
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
	apiKey string, password string, dpath string, maxsize uint64,
	ipSrc net.IP, filename string, locFilename string) error {
	auth := &zedUpload.AuthInput{
		AuthType: "s3",
		Uname:    apiKey,
		Password: password,
	}

	trType := zedUpload.SyncAwsTr
	// XXX:FIXME , will come as part of data store
	region := "us-west-2"

	// create Endpoint
	dEndPoint, err := ctx.dCtx.NewSyncerDest(trType, region, dpath, auth)
	if err != nil {
		log.Printf("NewSyncerDest failed: %s\n", err)
		return err
	}
	dEndPoint.WithSrcIpSelection(ipSrc)
	var respChan = make(chan *zedUpload.DronaRequest)

	log.Printf("syncOp for <%s>/<%s>\n", dpath, filename)
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
	updateDownloaderStatus(ctx, status)

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
				config.Password, config.Dpath,
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
		status.State = types.INITIAL
		updateDownloaderStatus(ctx, status)
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
		status.State = types.INITIAL
		updateDownloaderStatus(ctx, status)
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
	updateDownloaderStatus(ctx, status)
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
	log.Printf("handleDNSDelete done for %s\n", key)
}
