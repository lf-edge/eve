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
	"encoding/json"
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
	"github.com/zededa/go-provision/watch"
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

	moduleName            = agentName
	zedBaseDirname        = "/var/tmp"
	zedRunDirname         = "/var/run"
	baseDirname           = zedBaseDirname + "/" + moduleName
	runDirname            = zedRunDirname + "/" + moduleName
	persistDir            = "/persist"
	objectDownloadDirname = persistDir + "/downloads"

	downloaderConfigDirname = baseDirname + "/config"
	downloaderStatusDirname = runDirname + "/status"

	// XXX
	baseOsConfigDirname = baseDirname + "/" + baseOsObj + "/config"
	baseOsStatusDirname = runDirname + "/" + baseOsObj + "/status"
)

// Go doesn't like this as a constant
var (
	downloaderObjTypes = []string{appImgObj, baseOsObj, certObj}
)

// Set from Makefile
var Version = "No version specified"

type downloaderContext struct {
	dCtx                   *zedUpload.DronaCtx
	subDeviceNetworkStatus *pubsub.Subscription
	subAppImgConfig        *pubsub.Subscription
	pubAppImgStatus        *pubsub.Publication
	subBaseOsConfig        *pubsub.Subscription
	pubBaseOsStatus        *pubsub.Publication
	subCertObjConfig       *pubsub.Subscription
	pubCertObjStatus       *pubsub.Publication
}

var deviceNetworkStatus types.DeviceNetworkStatus

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
	for _, ot := range downloaderObjTypes {
		watch.CleanupRestartedObj(agentName, ot)
	}

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
	ctx.dCtx = downloaderInit()

	subDeviceNetworkStatus, err := pubsub.Subscribe("zedrouter",
		types.DeviceNetworkStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// First wait to have some uplinks with addresses
	// Looking at any uplinks since we can do baseOS download over all
	for types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus) == 0 {
		select {
		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
		}
	}
	log.Printf("Have %d uplinks addresses to use\n",
		types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus))

	// Set up our publications before the subscriptions so ctx is set
	pubAppImgStatus, err := pubsub.Publish(agentName,
		types.DownloaderStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppImgStatus = pubAppImgStatus
	pubAppImgStatus.ClearRestarted()

	pubBaseOsStatus, err := pubsub.Publish(agentName,
		types.DownloaderStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubBaseOsStatus = pubBaseOsStatus
	pubBaseOsStatus.ClearRestarted()

	pubCertObjStatus, err := pubsub.Publish(agentName,
		types.DownloaderStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubCertObjStatus = pubCertObjStatus
	pubCertObjStatus.ClearRestarted()

	subAppImgConfig, err := pubsub.Subscribe("zedmanager",
		types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgConfig.ModifyHandler = handleAppImgModify
	subAppImgConfig.DeleteHandler = handleDelete
	ctx.subAppImgConfig = subAppImgConfig
	subAppImgConfig.Activate()

	subBaseOsConfig, err := pubsub.Subscribe("zedagent",
		types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsConfig.ModifyHandler = handleBaseOsModify
	subBaseOsConfig.DeleteHandler = handleDelete
	ctx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()

	subCertObjConfig, err := pubsub.Subscribe("zedagent",
		types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subCertObjConfig.ModifyHandler = handleCertObjModify
	subCertObjConfig.DeleteHandler = handleDelete
	ctx.subCertObjConfig = subCertObjConfig
	subCertObjConfig.Activate()

	// XXX remove
	baseOsChanges := make(chan string)
	go watch.WatchConfigStatus(baseOsConfigDirname,
		baseOsStatusDirname, baseOsChanges)

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

		// XXX
		case change := <-baseOsChanges:
			watch.HandleConfigStatusEvent(change, &ctx,
				baseOsConfigDirname,
				baseOsStatusDirname,
				&types.DownloaderConfig{},
				&types.DownloaderStatus{},
				handleBaseOsObjCreate,
				handleModify,
				handleOldDelete, nil)

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

// Callers must be careful to publish any changes to DownloaderStatus
func lookupDownloaderStatus(pub *pubsub.Publication, key string) *types.DownloaderStatus {

	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("lookupDownloaderStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastDownloaderStatus(st)
	if status.Key() != key {
		log.Printf("lookupDownloaderStatus(%s) got %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}


// Object handlers
func handleAppImgObjCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	config := cast.CastDownloaderConfig(configArg)
	ctx := ctxArg.(*downloaderContext)

	handleCreate(ctx, appImgObj, config, key)
}

func handleBaseOsObjCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	config := cast.CastDownloaderConfig(configArg)
	ctx := ctxArg.(*downloaderContext)

	handleCreate(ctx, baseOsObj, config, key)
}

func handleCertObjCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	config := cast.CastDownloaderConfig(configArg)
	ctx := ctxArg.(*downloaderContext)

	handleCreate(ctx, certObj, config, key)
}

func handleCreate(ctx *downloaderContext, objType string,
	config types.DownloaderConfig,
	key string) {

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
	writeDownloaderStatus(&status, key)

	// Check if we have space
	kb := types.RoundupToKB(config.Size)
	if uint(kb) >= globalStatus.RemainingSpace {
		errString := fmt.Sprintf("Would exceed remaining space %d vs %d\n",
			kb, globalStatus.RemainingSpace)
		log.Println(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(&status, key)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return
	}

	// Update reserved space. Keep reserved until doDelete
	// XXX RefCount -> 0 should keep it reserved.
	status.ReservedSpace = uint(types.RoundupToKB(config.Size))
	globalStatus.ReservedSpace += status.ReservedSpace
	updateRemainingSpace()

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
		writeDownloaderStatus(&status, key)
		log.Printf("handleCreate deferred for %s\n", config.DownloadURL)
		return
	}

	handleSyncOp(ctx, key, config, &status)
}

// Allow to cancel by setting RefCount = 0. Same as delete? RefCount 0->1
// means download. Ignore other changes?
// XXX remove extra casts
func handleModify(ctxArg interface{}, key string,
	configArg interface{}, statusArg interface{}) {
	config := cast.CastDownloaderConfig(configArg)
	status := cast.CastDownloaderStatus(statusArg)
	ctx := ctxArg.(*downloaderContext)

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
		doDelete(key, locDirname, &status)
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
		writeDownloaderStatus(&status, key)
	} else if status.RefCount != 0 && config.RefCount == 0 {
		log.Printf("handleModify deleting %s\n", config.DownloadURL)
		doDelete(key, locDirname, &status)
	} else if status.RefCount != config.RefCount {
		log.Printf("handleModify RefCount change %s from %d to %d\n",
			config.DownloadURL, status.RefCount, config.RefCount)
		status.RefCount = config.RefCount
		writeDownloaderStatus(&status, key)
	}
	log.Printf("handleModify done for %s\n", config.DownloadURL)
}

func doDelete(key string, locDirname string, status *types.DownloaderStatus) {

	log.Printf("doDelete(%v) for %s\n", status.Safename, status.DownloadURL)

	deletefile(locDirname+"/pending", status)
	deletefile(locDirname+"/verifier", status)
	// verifier handles the verified directory

	status.State = types.INITIAL
	globalStatus.UsedSpace -= uint(types.RoundupToKB(status.Size))
	status.Size = 0

	// XXX Asymmetric; handleCreate reserved on RefCount 0. We unreserve
	// going back to RefCount 0. FIXed
	updateRemainingSpace()
	writeDownloaderStatus(status, key)
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

// XXX remove
func handleOldDelete(ctxArg interface{}, key string, statusArg interface{}) {
	handleDelete(ctxArg, key)
}

// XXX remove extra casts
func handleDelete(ctxArg interface{}, key string) {
// XXX	statusArg interface{}) {
// XXX	status := cast.CastDownloaderStatus(statusArg)
	status := types.DownloaderStatus{}
   
	log.Printf("handleDelete(%v) objType %s for %s\n",
		status.Safename, status.ObjType, status.DownloadURL)

	if status.ObjType == "" {
		log.Fatalf("handleDelete: No ObjType for %s\n",
			status.Safename)
	}
	locDirname := objectDownloadDirname + "/" + status.ObjType

	status.PendingDelete = true
	writeDownloaderStatus(&status, key)

	globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	globalStatus.UsedSpace -= uint(types.RoundupToKB(status.Size))
	status.Size = 0

	updateRemainingSpace()

	writeDownloaderStatus(&status, key)

	doDelete(key, locDirname, &status)

	status.PendingDelete = false
	writeDownloaderStatus(&status, key)

	// Write out what we modified to DownloaderStatus aka delete
	if err := os.Remove(key); err != nil {
		log.Println(err)
	}
	log.Printf("handleDelete done for %s, %s\n", status.DownloadURL, locDirname)
}

// helper functions

var globalConfig types.GlobalDownloadConfig
var globalStatus types.GlobalDownloadStatus
var globalStatusFilename string

func downloaderInit() *zedUpload.DronaCtx {

	initializeDirs()

	configFilename := downloaderConfigDirname + "/global"
	statusFilename := downloaderStatusDirname + "/global"

	// now start
	globalStatusFilename = statusFilename

	// Read GlobalDownloadConfig to find MaxSpace
	// Then determine currently used space and remaining.
	cb, err := ioutil.ReadFile(configFilename)
	if err != nil {
		log.Printf("%s for %s\n", err, configFilename)
		log.Fatal(err)
	}

	if err := json.Unmarshal(cb, &globalConfig); err != nil {
		log.Printf("%s GlobalDownloadConfig file: %s\n",
			err, configFilename)
		log.Fatal(err)
	}

	log.Printf("MaxSpace %d\n", globalConfig.MaxSpace)

	globalStatus.UsedSpace = 0
	globalStatus.ReservedSpace = 0
	updateRemainingSpace()

	// XXX how do we find out when verifier cleans up duplicates etc?
	// XXX run this periodically... What about downloads inprogress
	// when we run it?
	// XXX look at verifier and downloader status which have Size
	// We read objectDownloadDirname/* and determine how much space
	// is used. Place in GlobalDownloadStatus. Calculate remaining space.
	totalUsed := sizeFromDir(objectDownloadDirname)
	globalStatus.UsedSpace = uint(types.RoundupToKB(totalUsed))
	// Note that the UsedSpace calculated during initialization can exceed
	// MaxSpace, and RemainingSpace is a uint!
	if globalStatus.UsedSpace > globalConfig.MaxSpace {
		globalStatus.UsedSpace = globalConfig.MaxSpace
	}
	updateRemainingSpace()

	// create drona interface
	dCtx, err := zedUpload.NewDronaCtx("zdownloader", 0)

	if dCtx == nil {
		log.Printf("context create fail %s\n", err)
		log.Fatal(err)
	}

	return dCtx
}

func initializeDirs() {

	// Remove any files which didn't make it past the verifier.
	// Though verifier owns it, remove them for calculating the
	// total available space
	// XXX instead rely on verifier status
	clearInProgressDownloadDirs(downloaderObjTypes)

	// create the object based config/status dirs
	// XXX remove
	createConfigStatusDirs(moduleName, downloaderObjTypes)

	// create the object download directories
	createDownloadDirs(downloaderObjTypes)
}

// XXX remove
// create module and object based config/status directories
func createConfigStatusDirs(moduleName string, objTypes []string) {

	jobDirs := []string{"config", "status"}
	zedBaseDirs := []string{zedBaseDirname, zedRunDirname}
	baseDirs := make([]string, len(zedBaseDirs))

	log.Printf("Creating config/status dirs for %s\n", moduleName)

	for idx, dir := range zedBaseDirs {
		baseDirs[idx] = dir + "/" + moduleName
	}

	for idx, baseDir := range baseDirs {

		dirName := baseDir + "/" + jobDirs[idx]
		if _, err := os.Stat(dirName); err != nil {
			log.Printf("Create %s\n", dirName)
			if err := os.MkdirAll(dirName, 0700); err != nil {
				log.Fatal(err)
			}
		}

		// Creating Object based holder dirs
		for _, objType := range objTypes {
			dirName := baseDir + "/" + objType + "/" + jobDirs[idx]
			if _, err := os.Stat(dirName); err != nil {
				log.Printf("Create %s\n", dirName)
				if err := os.MkdirAll(dirName, 0700); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

// XXX here vs. in verifier? Who owns which dirs?
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

func updateRemainingSpace() {

	globalStatus.RemainingSpace = globalConfig.MaxSpace -
		globalStatus.UsedSpace - globalStatus.ReservedSpace

	log.Printf("RemainingSpace %d, maxspace %d, usedspace %d, reserved %d\n",
		globalStatus.RemainingSpace, globalConfig.MaxSpace,
		globalStatus.UsedSpace, globalStatus.ReservedSpace)
	// Create and write
	writeGlobalStatus()
}

func writeGlobalStatus() {

	sb, err := json.Marshal(globalStatus)
	if err != nil {
		log.Fatal(err, "json Marshal GlobalDownloadStatus")
	}
	if err = pubsub.WriteRename(globalStatusFilename, sb); err != nil {
		log.Fatal(err, globalStatusFilename)
	}
}

func writeDownloaderStatus(status *types.DownloaderStatus,
	key string) {
	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal DownloaderStatus")
	}
	err = pubsub.WriteRename(key, b)
	if err != nil {
		log.Fatal(err, key)
	}
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
	writeDownloaderStatus(status, key)

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
		addrCount = types.CountLocalAddrFree(deviceNetworkStatus, "")
		log.Printf("Have %d free uplink addresses\n", addrCount)
		err = errors.New("No free IP uplink addresses for download")
	} else {
		addrCount = types.CountLocalAddrAny(deviceNetworkStatus, "")
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
			ipSrc, err = types.GetLocalAddrFree(deviceNetworkStatus,
				addrIndex, "")
		} else {
			// Note that GetLocalAddrAny has the free ones first
			ipSrc, err = types.GetLocalAddrAny(deviceNetworkStatus,
				addrIndex, "")
		}
		if err != nil {
			log.Printf("GetLocalAddr failed: %s\n", err)
			errStr = errStr + "\n" + err.Error()
			continue
		}
		ifname := types.GetUplinkFromAddr(deviceNetworkStatus, ipSrc)
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
				handleSyncOpResponse(config, status,
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
				handleSyncOpResponse(config, status,
					locFilename, key, "")
				return
			}
		default:
			log.Fatal("unsupported transport method")
		}
	}
	log.Printf("All source IP addresses failed. All errors:%s\n", errStr)
	handleSyncOpResponse(config, status, locFilename,
		key, errStr)
}

func handleSyncOpResponse(config types.DownloaderConfig,
	status *types.DownloaderStatus, locFilename string,
	key string, errStr string) {

	if status.ObjType == "" {
		log.Fatalf("handleSyncOpResponse: No ObjType for %s\n",
			status.Safename)
	}
	locDirname := objectDownloadDirname + "/" + status.ObjType
	if errStr != "" {
		// Delete file
		doDelete(key, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errStr
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(status, key)
		log.Printf("handleSyncOpResponse failed for %s, <%s>\n",
			status.DownloadURL, errStr)
		return
	}

	info, err := os.Stat(locFilename)
	if err != nil {
		log.Printf("handleSyncOpResponse Stat failed for %s <%s>\n",
			status.DownloadURL, err)
		// Delete file
		doDelete(key, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(status, key)
		return
	}
	status.Size = uint64(info.Size())

	globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	globalStatus.UsedSpace += uint(types.RoundupToKB(status.Size))
	updateRemainingSpace()

	log.Printf("handleSyncOpResponse successful <%s> <%s>\n",
		config.DownloadURL, locFilename)
	// We do not clear any status.RetryCount, LastErr, etc. The caller
	// should look at State == DOWNLOADED to determine it is done.

	status.ModTime = time.Now()
	status.PendingAdd = false
	status.State = types.DOWNLOADED
	writeDownloaderStatus(status, key)
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	if key != "global" {
		log.Printf("handleDNSModify: ignoring %s\n", key)
		return
	}

	log.Printf("handleDNSModify for %s\n", key)
	deviceNetworkStatus = status
	log.Printf("handleDNSModify %d free uplinks addresses; %d any\n",
		types.CountLocalAddrFree(deviceNetworkStatus, ""),
		types.CountLocalAddrAny(deviceNetworkStatus, ""))
	log.Printf("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string) {
	log.Printf("handleDNSDelete for %s\n", key)

	if key != "global" {
		log.Printf("handleDNSDelete: ignoring %s\n", key)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Printf("handleDNSDelete done for %s\n", key)
}
