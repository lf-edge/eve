// Copyright (c) 2017-2020 Zededa, Inc.
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
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
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
	debug         = false
	debugOverride bool                               // From command line arg
	retryTime     = time.Duration(600) * time.Second // Unless from GlobalConfig
	Version       = "No version specified"           // Set from Makefile
	nilUUID       uuid.UUID                          // should be a const, just the default nil value of uuid.UUID
	dHandler      = makeDownloadHandler()
	resHandler    = makeResolveHandler()
)

func Run(ps *pubsub.PubSub) {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
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

	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	cms := zedcloud.GetCloudMetrics() // Need type of data
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: cms,
	})
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
	err = ctx.registerHandlers(ps)
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
		log.Infof("Waiting for management port addresses or Global Config")

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
	log.Infof("Have %d management ports addresses to use",
		types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus))

	ctx.dCtx = downloaderInit(&ctx)

	for {
		select {
		case change := <-ctx.decryptCipherContext.SubControllerCert.MsgChan():
			ctx.decryptCipherContext.SubControllerCert.ProcessChange(change)

		case change := <-ctx.decryptCipherContext.SubEdgeNodeCert.MsgChan():
			ctx.decryptCipherContext.SubEdgeNodeCert.ProcessChange(change)

		case change := <-ctx.decryptCipherContext.SubCipherContext.MsgChan():
			ctx.decryptCipherContext.SubCipherContext.ProcessChange(change)

		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)

		case change := <-ctx.subDeviceNetworkStatus.MsgChan():
			ctx.subDeviceNetworkStatus.ProcessChange(change)

		case change := <-ctx.subCertObjConfig.MsgChan():
			ctx.subCertObjConfig.ProcessChange(change)

		case change := <-ctx.subAppImgConfig.MsgChan():
			ctx.subAppImgConfig.ProcessChange(change)

		case change := <-ctx.subContentTreeResolveConfig.MsgChan():
			ctx.subContentTreeResolveConfig.ProcessChange(change)

		case change := <-ctx.subAppImgResolveConfig.MsgChan():
			ctx.subAppImgResolveConfig.ProcessChange(change)

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
		log.Infof("lookupDownloaderStatus(%s) not found", key)
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
		log.Infof("lookupDownloaderConfig(%s) not found", key)
		return nil
	}
	config := c.(types.DownloaderConfig)
	return &config
}

// Server for each domU
func runHandler(ctx *downloaderContext, objType string, key string,
	c <-chan Notify) {

	log.Infof("runHandler starting")

	max := float64(retryTime)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	closed := false
	for !closed {
		select {
		case _, ok := <-c:
			if ok {
				sub := ctx.subscription(objType)
				c, err := sub.Get(key)
				if err != nil {
					log.Errorf("runHandler no config for %s", key)
					continue
				}
				config := c.(types.DownloaderConfig)
				status := lookupDownloaderStatus(ctx,
					objType, key)
				if status == nil {
					handleCreate(ctx, objType, config, status, key)
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
			log.Debugf("runHandler(%s) timer", key)
			status := lookupDownloaderStatus(ctx, objType, key)
			if status != nil {
				maybeRetryDownload(ctx, status)
			}
		}
	}
	log.Infof("runHandler(%s) DONE", key)
}

func maybeRetryDownload(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	// object is either in download progress or,
	// successfully downloaded, nothing to do
	if !status.HasError() {
		return
	}
	t := time.Now()
	elapsed := t.Sub(status.ErrorTime)
	if elapsed < retryTime {
		log.Infof("maybeRetryDownload(%s) %d remaining",
			status.Key(),
			(retryTime-elapsed)/time.Second)
		return
	}
	log.Infof("maybeRetryDownload(%s) after %s at %v",
		status.Key(), status.Error, status.ErrorTime)

	config := lookupDownloaderConfig(ctx, status.ObjType, status.Key())
	if config == nil {
		log.Infof("maybeRetryDownload(%s) no config",
			status.Key())
		return
	}

	// reset Error, to start download again
	status.RetryCount++
	status.ClearError()
	publishDownloaderStatus(ctx, status)

	doDownload(ctx, *config, status)
}

func handleCreate(ctx *downloaderContext, objType string,
	config types.DownloaderConfig, status *types.DownloaderStatus, key string) {

	log.Infof("handleCreate(%s) objType %s for %s",
		config.ImageSha256, objType, config.Name)

	if objType == "" {
		log.Fatalf("handleCreate: No ObjType for %s",
			config.ImageSha256)
	}
	if status == nil {
		// Start by marking with PendingAdd
		status0 := types.DownloaderStatus{
			DatastoreID:      config.DatastoreID,
			Name:             config.Name,
			ImageSha256:      config.ImageSha256,
			ObjType:          objType,
			State:            types.DOWNLOADING,
			RefCount:         config.RefCount,
			Size:             config.Size,
			LastUse:          time.Now(),
			AllowNonFreePort: config.AllowNonFreePort,
			PendingAdd:       true,
		}
		status = &status0
	} else {
		// when refcount moves from 0 to a non-zero number,
		// should trigger a fresh download of the object
		status.DatastoreID = config.DatastoreID
		status.ImageSha256 = config.ImageSha256
		status.State = types.DOWNLOADING
		status.RefCount = config.RefCount
		status.LastUse = time.Now()
		status.Expired = false
		status.ClearError()
	}
	publishDownloaderStatus(ctx, status)

	doDownload(ctx, config, status)
}

// XXX Allow to cancel by setting RefCount = 0? Such a change
// would have to be detected outside of handler since the download is
// single-threaded.
// RefCount 0->1 means download.
// RefCount -> 0 means set Expired to delete
func handleModify(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus) {

	log.Infof("handleModify(%s) objType %s for %s",
		status.ImageSha256, status.ObjType, status.Name)

	status.PendingModify = true
	publishDownloaderStatus(ctx, status)

	if status.ObjType == "" {
		log.Fatalf("handleModify: No ObjType for %s",
			status.ImageSha256)
	}

	log.Infof("handleModify(%s) RefCount %d to %d, Expired %v for %s",
		status.ImageSha256, status.RefCount, config.RefCount,
		status.Expired, status.Name)

	// If RefCount from zero to non-zero and status has error
	// or status is not downloaded then do install
	if config.RefCount != 0 && (status.HasError() || status.State != types.DOWNLOADED) {
		log.Infof("handleModify installing %s", config.Name)
		handleCreate(ctx, status.ObjType, config, status, key)
	} else if status.RefCount != config.RefCount {
		status.RefCount = config.RefCount
	}
	status.LastUse = time.Now()
	status.Expired = (status.RefCount == 0) // Start delete handshake
	status.ClearPendingStatus()
	publishDownloaderStatus(ctx, status)
	log.Infof("handleModify done for %s", config.Name)
}

func doDelete(ctx *downloaderContext, key string, filename string,
	status *types.DownloaderStatus) {

	log.Infof("doDelete(%s) for %s", status.ImageSha256, status.Name)

	if _, err := os.Stat(filename); err == nil {
		log.Infof("Deleting %s", filename)
		if err := os.RemoveAll(filename); err != nil {
			log.Errorf("Failed to remove %s: err %s",
				filename, err)
		}
	}

	status.State = types.INITIAL

	// XXX Asymmetric; handleCreate reserved on RefCount 0. We unreserve
	// going back to RefCount 0. FIXed
	publishDownloaderStatus(ctx, status)
}

// perform download of the object, by reserving storage
func doDownload(ctx *downloaderContext, config types.DownloaderConfig, status *types.DownloaderStatus) {

	// If RefCount == 0 then we don't yet need to download.
	if config.RefCount == 0 {
		errStr := fmt.Sprintf("RefCount==0; download deferred for %s\n",
			config.Name)
		status.RetryCount++
		status.HandleDownloadFail(errStr)
		publishDownloaderStatus(ctx, status)
		log.Errorf("doDownload(%s): deferred with %s", config.Name, errStr)
		return
	}

	dst, errStr := lookupDatastoreConfig(ctx, config.DatastoreID, config.Name)
	if dst == nil {
		status.RetryCount++
		// XXX can we have a faster retry in this case?
		// React when DatastoreConfig changes?
		status.HandleDownloadFail(errStr)
		publishDownloaderStatus(ctx, status)
		log.Errorf("doDownload(%s): deferred with %s", config.Name, errStr)
		return
	}

	handleSyncOp(ctx, status.Key(), config, status, dst)
}

func handleDelete(ctx *downloaderContext, key string,
	status *types.DownloaderStatus) {

	log.Infof("handleDelete(%s) objType %s for %s RefCount %d LastUse %v Expired %v",
		status.ImageSha256, status.ObjType, status.Name,
		status.RefCount, status.LastUse, status.Expired)

	if status.ObjType == "" {
		log.Fatalf("handleDelete: No ObjType for %s",
			status.ImageSha256)
	}

	status.PendingDelete = true
	publishDownloaderStatus(ctx, status)

	doDelete(ctx, key, status.Target, status)

	status.PendingDelete = false
	publishDownloaderStatus(ctx, status)

	// Write out what we modified to DownloaderStatus aka delete
	unpublishDownloaderStatus(ctx, status)
	log.Infof("handleDelete done for %s", status.Name)
}

// helper functions

func downloaderInit(ctx *downloaderContext) *zedUpload.DronaCtx {

	// create drona interface
	dCtx, err := zedUpload.NewDronaCtx("zdownloader", 0)

	if dCtx == nil {
		log.Errorf("context create fail %s", err)
		log.Fatal(err)
	}

	return dCtx
}

func publishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := ctx.publication(status.ObjType)
	key := status.Key()
	log.Debugf("publishDownloaderStatus(%s)", key)
	pub.Publish(key, *status)
}

func unpublishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := ctx.publication(status.ObjType)
	key := status.Key()
	log.Debugf("unpublishDownloaderStatus(%s)", key)
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishDownloaderStatus(%s) not found", key)
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
	log.Debugf("Found datastore(%s) for %s", dsID, name)
	dst := cfg.(types.DatastoreConfig)
	return &dst, ""
}
