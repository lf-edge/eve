// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of collections of DownloaderConfig structs
// and publish the results as collections of DownloaderStatus structs.
// There are several inputs and outputs based on the objType.

package downloader

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	pubsublegacy "github.com/lf-edge/eve/pkg/pillar/pubsub/legacy"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	agentName = "downloader"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Go doesn't like this as a constant
var (
	debug              = false
	debugOverride      bool                               // From command line arg
	downloadGCTime     = time.Duration(600) * time.Second // Unless from GlobalConfig
	downloadRetryTime  = time.Duration(600) * time.Second // Unless from GlobalConfig
	downloaderObjTypes = []string{types.AppImgObj, types.BaseOsObj, types.CertObj}
	Version            = "No version specified" // Set from Makefile
	nilUUID            uuid.UUID                // should be a const, just the default nil value of uuid.UUID
	dHandler           = makeDownloadHandler()
)

func Run() {
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

	cms := zedcloud.GetCloudMetrics() // Need type of data
	pub, err := pubsublegacy.Publish(agentName, cms)
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

	// set up any state needed by handler functions
	err = ctx.registerHandlers()
	if err != nil {
		log.Fatal(err)
	}

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("processed GlobalConfig")

	// First wait to have some management ports with addresses
	// Looking at any management ports since we can do baseOS download over all
	// Also ensure GlobalDownloadConfig has been read
	for types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus) == 0 ||
		ctx.globalConfig.MaxSpace == 0 {
		log.Infof("Waiting for management port addresses or Global Config\n")

		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)

		case change := <-ctx.subDeviceNetworkStatus.MsgChan():
			ctx.subDeviceNetworkStatus.ProcessChange(change)

		case change := <-ctx.subGlobalDownloadConfig.MsgChan():
			ctx.subGlobalDownloadConfig.ProcessChange(change)

		// This wait can take an unbounded time since we wait for IP
		// addresses. Punch StillRunning
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("Have %d management ports addresses to use\n",
		types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus))

	ctx.dCtx = downloaderInit(&ctx)

	// We will cleanup zero RefCount objects after a while
	// We run timer 10 times more often than the limit on LastUse
	gc := time.NewTicker(downloadGCTime / 10)

	for {
		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)

		case change := <-ctx.subDeviceNetworkStatus.MsgChan():
			ctx.subDeviceNetworkStatus.ProcessChange(change)

		case change := <-ctx.subCertObjConfig.MsgChan():
			ctx.subCertObjConfig.ProcessChange(change)

		case change := <-ctx.subAppImgConfig.MsgChan():
			ctx.subAppImgConfig.ProcessChange(change)

		case change := <-ctx.subBaseOsConfig.MsgChan():
			ctx.subBaseOsConfig.ProcessChange(change)

		case change := <-ctx.subDatastoreConfig.MsgChan():
			ctx.subDatastoreConfig.ProcessChange(change)

		case change := <-ctx.subGlobalDownloadConfig.MsgChan():
			ctx.subGlobalDownloadConfig.ProcessChange(change)

		case <-publishTimer.C:
			start := time.Now()
			err := pub.Publish("global", zedcloud.GetCloudMetrics())
			if err != nil {
				log.Errorln(err)
			}
			pubsub.CheckMaxTimeTopic(agentName, "publishTimer", start,
				warningTime, errorTime)

		case <-gc.C:
			start := time.Now()
			gcObjects(&ctx)
			pubsub.CheckMaxTimeTopic(agentName, "gc", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

// handle the datastore modification
func checkAndUpdateDownloadableObjects(ctx *downloaderContext, dsID uuid.UUID) {
	publications := []pubsub.Publication{
		ctx.pubAppImgStatus,
		ctx.pubBaseOsStatus,
		ctx.pubCertObjStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.DownloaderStatus)
			if status.DatastoreID == dsID {
				config := lookupDownloaderConfig(ctx, status.ObjType, status.Key())
				if config != nil {
					dHandler.modify(ctx, status.ObjType, status.Key(), *config)
				}
			}
		}
	}
}

// Wrappers to add objType for create. The Delete wrappers are merely

// Callers must be careful to publish any changes to DownloaderStatus
func lookupDownloaderStatus(ctx *downloaderContext, objType string,
	key string) *types.DownloaderStatus {

	pub := ctx.publication(objType)
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupDownloaderStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.DownloaderStatus)
	return &status
}

func lookupDownloaderConfig(ctx *downloaderContext, objType string,
	key string) *types.DownloaderConfig {

	sub := ctx.subscription(objType)
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupDownloaderConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.DownloaderConfig)
	return &config
}

// Server for each domU
func runHandler(ctx *downloaderContext, objType string, key string,
	c <-chan interface{}) {

	log.Infof("runHandler starting\n")

	max := float64(downloadRetryTime)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	closed := false
	for !closed {
		select {
		case configArg, ok := <-c:
			if ok {
				config := configArg.(types.DownloaderConfig)
				status := lookupDownloaderStatus(ctx,
					objType, key)
				if status == nil {
					handleCreate(ctx, objType, config, key)
				} else {
					handleModify(ctx, key, config, status)
				}
				// XXX if err start timer
			} else {
				// Closed
				status := lookupDownloaderStatus(ctx,
					objType, key)
				if status != nil {
					handleDelete(ctx, key, status)
				}
				closed = true
				// XXX stop timer
			}
		case <-ticker.C:
			log.Debugf("runHandler(%s) timer\n", key)
			status := lookupDownloaderStatus(ctx, objType, key)
			if status != nil {
				maybeRetryDownload(ctx, status)
			}
		}
	}
	log.Infof("runHandler(%s) DONE\n", key)
}

func maybeRetryDownload(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	if status.LastErr == "" {
		return
	}
	t := time.Now()
	elapsed := t.Sub(status.LastErrTime)
	if elapsed < downloadRetryTime {
		log.Infof("maybeRetryDownload(%s) %d remaining\n",
			status.Key(),
			(downloadRetryTime-elapsed)/time.Second)
		return
	}
	log.Infof("maybeRetryDownload(%s) after %s at %v\n",
		status.Key(), status.LastErr, status.LastErrTime)

	config := lookupDownloaderConfig(ctx, status.ObjType, status.Key())
	if config == nil {
		log.Infof("maybeRetryDownload(%s) no config\n",
			status.Key())
		return
	}
	status.LastErr = ""
	status.LastErrTime = time.Time{}
	status.RetryCount += 1
	// XXX do we need to adjust reservedspace??

	dst, errStr := lookupDatastoreConfig(ctx, config.DatastoreID, config.Name)
	if dst == nil {
		status.LastErr = errStr
		status.LastErrTime = time.Now()
		publishDownloaderStatus(ctx, status)
		return
	}
	handleSyncOp(ctx, status.Key(), *config, status, dst)
}

func handleCreate(ctx *downloaderContext, objType string,
	config types.DownloaderConfig, key string) {

	log.Infof("handleCreate(%s) objType %s for %s\n",
		config.ImageID, objType, config.Name)

	if objType == "" {
		log.Fatalf("handleCreate: No ObjType for %s\n",
			config.ImageID)
	}
	// Start by marking with PendingAdd
	status := types.DownloaderStatus{
		ImageID:          config.ImageID,
		DatastoreID:      config.DatastoreID,
		Name:             config.Name,
		ObjType:          objType,
		IsContainer:      config.IsContainer,
		RefCount:         config.RefCount,
		LastUse:          time.Now(),
		AllowNonFreePort: config.AllowNonFreePort,
		PendingAdd:       true,
	}
	publishDownloaderStatus(ctx, &status)

	// Check if we have space
	// Update reserved space. Keep reserved until doDelete
	// XXX RefCount -> 0 should keep it reserved.
	kb := types.RoundupToKB(config.Size)
	if !tryReserveSpace(ctx, &status, kb) {
		errString := fmt.Sprintf("Would exceed remaining space. "+
			"SizeOfAppImage: %d, RemainingSpace: %d\n",
			kb, ctx.globalStatus.RemainingSpace)
		log.Errorln(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		publishDownloaderStatus(ctx, &status)
		log.Errorf("handleCreate failed for %s\n", config.Name)
		return
	}

	// If RefCount == 0 then we don't yet download.
	if config.RefCount == 0 {
		// XXX odd to treat as error.
		errString := fmt.Sprintf("RefCount==0; download deferred for %s\n",
			config.Name)
		log.Errorln(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		publishDownloaderStatus(ctx, &status)
		log.Errorf("handleCreate deferred for %s\n", config.Name)
		return
	}

	dst, errStr := lookupDatastoreConfig(ctx, config.DatastoreID, config.Name)
	if dst == nil {
		status.PendingAdd = false
		status.LastErr = errStr
		status.LastErrTime = time.Now()
		status.RetryCount++
		publishDownloaderStatus(ctx, &status)
		return
	}
	handleSyncOp(ctx, key, config, &status, dst)
}

// XXX Allow to cancel by setting RefCount = 0? Such a change
// would have to be detected outside of handler since the download is
// single-threaded.
// RefCount 0->1 means download. Ignore other changes?
func handleModify(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus) {

	log.Infof("handleModify(%s) objType %s for %s\n",
		status.ImageID, status.ObjType, status.Name)

	if status.ObjType == "" {
		log.Fatalf("handleModify: No ObjType for %s\n",
			status.ImageID)
	}
	if config.Name != status.Name {
		errStr := fmt.Sprintf("Name changed - not allowed %s -> %s\n",
			config.Name, status.Name)
		log.Error(errStr)
		status.LastErr = errStr
		status.LastErrTime = time.Now()
		publishDownloaderStatus(ctx, status)
		return
	}
	if config.IsContainer != status.IsContainer {
		log.Infof("handleModify: Setting IsContainer to %t for %s",
			config.IsContainer, status.ImageID)
		status.IsContainer = config.IsContainer
		publishDownloaderStatus(ctx, status)
	}
	log.Infof("handleModify(%s) RefCount %d to %d, Expired %v for %s\n",
		status.ImageID, status.RefCount, config.RefCount,
		status.Expired, status.Name)

	// If RefCount from zero to non-zero then do install
	if status.RefCount == 0 && config.RefCount != 0 {
		status.PendingModify = true
		log.Infof("handleModify installing %s\n", config.Name)
		handleCreate(ctx, status.ObjType, config, key)
		status.RefCount = config.RefCount
		status.LastUse = time.Now()
		status.Expired = false
		status.PendingModify = false
		publishDownloaderStatus(ctx, status)
	} else if status.RefCount != config.RefCount {
		status.RefCount = config.RefCount
		status.LastUse = time.Now()
		status.Expired = false
		status.PendingModify = false
		publishDownloaderStatus(ctx, status)
	} else {
		status.PendingModify = false
		publishDownloaderStatus(ctx, status)
	}
	log.Infof("handleModify done for %s\n", config.Name)
}

func doDelete(ctx *downloaderContext, key string, locDirname string,
	status *types.DownloaderStatus) {

	log.Infof("doDelete(%s) for %s\n", status.ImageID, status.Name)

	deletefile(locDirname+"/pending", status)

	status.State = types.INITIAL
	deleteSpace(ctx, types.RoundupToKB(status.Size))
	status.Size = 0

	// XXX Asymmetric; handleCreate reserved on RefCount 0. We unreserve
	// going back to RefCount 0. FIXed
	publishDownloaderStatus(ctx, status)
}

func deletefile(dirname string, status *types.DownloaderStatus) {
	// XXX common routines to determine pathname?
	dirname = dirname + "/" + status.ImageID.String()

	// XXX delete whole directory?
	if _, err := os.Stat(dirname); err == nil {
		log.Infof("Deleting %s\n", dirname)
		// Remove directory
		if err := os.RemoveAll(dirname); err != nil {
			log.Errorf("Failed to remove %s: err %s\n",
				dirname, err)
		}
	}
}

func handleDelete(ctx *downloaderContext, key string,
	status *types.DownloaderStatus) {

	log.Infof("handleDelete(%s) objType %s for %s RefCount %d LastUse %v Expired %v\n",
		status.ImageID, status.ObjType, status.Name,
		status.RefCount, status.LastUse, status.Expired)

	if status.ObjType == "" {
		log.Fatalf("handleDelete: No ObjType for %s\n",
			status.ImageID)
	}
	locDirname := types.DownloadDirname + "/" + status.ObjType

	status.PendingDelete = true
	publishDownloaderStatus(ctx, status)

	// Update globalStatus and status
	unreserveSpace(ctx, status)

	publishDownloaderStatus(ctx, status)

	doDelete(ctx, key, locDirname, status)

	status.PendingDelete = false
	publishDownloaderStatus(ctx, status)

	// Write out what we modified to DownloaderStatus aka delete
	unpublishDownloaderStatus(ctx, status)
	log.Infof("handleDelete done for %s, %s\n", status.Name,
		locDirname)
}

// helper functions

func downloaderInit(ctx *downloaderContext) *zedUpload.DronaCtx {

	initializeDirs()

	log.Infof("MaxSpace %d\n", ctx.globalConfig.MaxSpace)

	// XXX how do we find out when verifier cleans up duplicates etc?
	// XXX run this periodically... What about downloads inprogress
	// when we run it?
	// XXX look at verifier and downloader status which have Size
	// We read types.DownloadDirname/* and determine how much space
	// is used. Place in GlobalDownloadStatus. Calculate remaining space.
	totalUsed := diskmetrics.SizeFromDir(types.DownloadDirname)
	kb := types.RoundupToKB(totalUsed)
	initSpace(ctx, kb)

	// create drona interface
	dCtx, err := zedUpload.NewDronaCtx("zdownloader", 0)

	if dCtx == nil {
		log.Errorf("context create fail %s\n", err)
		log.Fatal(err)
	}

	return dCtx
}

// If an object has a zero RefCount and dropped to zero more than
// downloadGCTime ago, then we delete the Status. That will result in the
// user (zedmanager or baseosmgr) deleting the Config, unless a RefCount
// increase is underway.
// XXX Note that this runs concurrently with the handler.
func gcObjects(ctx *downloaderContext) {
	log.Debugf("gcObjects()\n")
	publications := []pubsub.Publication{
		ctx.pubAppImgStatus,
		ctx.pubBaseOsStatus,
		ctx.pubCertObjStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.DownloaderStatus)
			if status.RefCount != 0 {
				log.Debugf("gcObjects: skipping RefCount %d: %s\n",
					status.RefCount, status.Key())
				continue
			}
			timePassed := time.Since(status.LastUse)
			if timePassed < downloadGCTime {
				log.Debugf("gcObjects: skipping recently used %s remains %d seconds\n",
					status.Key(),
					(timePassed-downloadGCTime)/time.Second)
				continue
			}
			log.Infof("gcObjects: expiring status for %s; LastUse %v now %v\n",
				status.Key(), status.LastUse, time.Now())
			status.Expired = true
			publishDownloaderStatus(ctx, &status)
		}
	}
}

func publishGlobalStatus(ctx *downloaderContext) {
	ctx.pubGlobalDownloadStatus.Publish("global", ctx.globalStatus)
}

func publishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := ctx.publication(status.ObjType)
	key := status.Key()
	log.Debugf("publishDownloaderStatus(%s)\n", key)
	pub.Publish(key, *status)
}

func unpublishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := ctx.publication(status.ObjType)
	key := status.Key()
	log.Debugf("unpublishDownloaderStatus(%s)\n", key)
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishDownloaderStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

// Check for nil UUID (an indication the drive was missing in parseconfig)
// and a missing datastore id.
func lookupDatastoreConfig(ctx *downloaderContext, dsID uuid.UUID,
	name string) (*types.DatastoreConfig, string) {

	if dsID == nilUUID {
		errStr := fmt.Sprintf("lookupDatastoreConfig(%s) for %s: No datastore ID",
			dsID.String(), name)
		log.Errorln(errStr)
		return nil, errStr
	}
	cfg, err := ctx.subDatastoreConfig.Get(dsID.String())
	if err != nil {
		errStr := fmt.Sprintf("lookupDatastoreConfig(%s) for %s: %v",
			dsID.String(), name, err)
		log.Errorln(errStr)
		return nil, errStr
	}
	log.Debugf("Found datastore(%s) for %s\n", dsID, name)
	dst := cfg.(types.DatastoreConfig)
	return &dst, ""
}
