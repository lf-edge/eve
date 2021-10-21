// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of collections of DownloaderConfig structs
// and publish the results as collections of DownloaderStatus structs.
// Also process ResolveConfig to produce ResolveStatus

package downloader

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/libs/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "downloader"
	// Time limits for event loop handlers
	errorTime          = 3 * time.Minute
	warningTime        = 40 * time.Second
	downloaderBasePath = types.SealedDirName + "/" + agentName
)

// Go doesn't like this as a constant
var (
	debug          = false
	debugOverride  bool                               // From command line arg
	retryTime      = time.Duration(600) * time.Second // Unless from GlobalConfig
	maxStalledTime = time.Duration(600) * time.Second // Unless from GlobalConfig
	Version        = "No version specified"           // Set from Makefile
	dHandler       = makeDownloadHandler()
	resHandler     = makeResolveHandler()
	logger         *logrus.Logger
	log            *base.LogObject
)

// Run downloader
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return 0
	}
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}
	log.Functionf("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	metricsPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.MetricsMap{},
	})
	if err != nil {
		log.Fatal(err)
	}

	cipherMetricsPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.CipherMetrics{},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Publish metrics for zedagent every 10 seconds
	interval := time.Duration(10 * time.Second)
	max := float64(interval)
	min := max * 0.3
	publishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	// Any state needed by handler functions
	ctx := downloaderContext{
		zedcloudMetrics: zedcloud.NewAgentMetrics(),
		cipherMetrics:   cipher.NewAgentMetrics(agentName),
	}

	// set up any state needed by handler functions
	err = ctx.registerHandlers(ps)
	if err != nil {
		log.Fatal(err)
	}

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	if err := utils.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed Vault Status")
	// First wait to have some management ports with addresses
	// Looking at any management ports since we can do download over all
	for types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus) == 0 {
		log.Functionf("Waiting for management port addresses")

		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)

		case change := <-ctx.subDeviceNetworkStatus.MsgChan():
			ctx.subDeviceNetworkStatus.ProcessChange(change)

		case change := <-ctx.decryptCipherContext.SubEdgeNodeCert.MsgChan():
			ctx.decryptCipherContext.SubEdgeNodeCert.ProcessChange(change)

		// This wait can take an unbounded time since we wait for IP
		// addresses. Punch StillRunning
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("Have %d management ports addresses to use",
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

		case change := <-ctx.subNetworkInstanceStatus.MsgChan():
			ctx.subNetworkInstanceStatus.ProcessChange(change)

		case change := <-ctx.subDownloaderConfig.MsgChan():
			ctx.subDownloaderConfig.ProcessChange(change)

		case change := <-ctx.subResolveConfig.MsgChan():
			ctx.subResolveConfig.ProcessChange(change)

		case change := <-ctx.subDatastoreConfig.MsgChan():
			ctx.subDatastoreConfig.ProcessChange(change)

		case <-publishTimer.C:
			start := time.Now()
			err := ctx.zedcloudMetrics.Publish(log, metricsPub, "global")
			if err != nil {
				log.Errorln(err)
			}
			err = ctx.cipherMetrics.Publish(log, cipherMetricsPub, "global")
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

// handle the datastore modification
func checkAndUpdateDownloadableObjects(ctx *downloaderContext, dsID uuid.UUID) {
	pub := ctx.pubDownloaderStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.DownloaderStatus)
		if status.DatastoreID == dsID {
			config := lookupDownloaderConfig(ctx, status.Key())
			if config != nil {
				dHandler.modify(ctx, status.Key(), *config)
			}
		}
	}
}

// Callers must be careful to publish any changes to DownloaderStatus
func lookupDownloaderStatus(ctx *downloaderContext,
	key string) *types.DownloaderStatus {

	pub := ctx.pubDownloaderStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Functionf("lookupDownloaderStatus(%s) not found", key)
		return nil
	}
	status := st.(types.DownloaderStatus)
	return &status
}

func lookupDownloaderConfig(ctx *downloaderContext, key string) *types.DownloaderConfig {

	sub := ctx.subDownloaderConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Functionf("lookupDownloaderConfig(%s) not found", key)
		return nil
	}
	config := c.(types.DownloaderConfig)
	return &config
}

// runHandler is the server for each DownloaderConfig object aka key
func runHandler(ctx *downloaderContext, key string, updateChan <-chan Notify,
	receiveChan chan<- CancelChannel) {

	log.Functionf("runHandler starting")

	max := float64(retryTime)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	closed := false
	for !closed {
		select {
		case _, ok := <-updateChan:
			if ok {
				sub := ctx.subDownloaderConfig
				c, err := sub.Get(key)
				if err != nil {
					log.Errorf("runHandler no config for %s", key)
					continue
				}
				config := c.(types.DownloaderConfig)
				status := lookupDownloaderStatus(ctx, key)
				if status == nil {
					handleCreate(ctx, config, status, key,
						receiveChan)
				} else {
					handleModify(ctx, key, config, status,
						receiveChan)
				}
			} else {
				// Closed
				status := lookupDownloaderStatus(ctx, key)
				if status != nil {
					handleDelete(ctx, key, status)
				}
				closed = true
			}
		case <-ticker.C:
			log.Tracef("runHandler(%s) timer", key)
			status := lookupDownloaderStatus(ctx, key)
			if status != nil {
				maybeRetryDownload(ctx, status, receiveChan)
			}
		}
	}
	log.Functionf("runHandler(%s) DONE", key)
}

func maybeRetryDownload(ctx *downloaderContext,
	status *types.DownloaderStatus, receiveChan chan<- CancelChannel) {

	// object is either in download progress or,
	// successfully downloaded, nothing to do
	if !status.HasError() {
		return
	}
	config := lookupDownloaderConfig(ctx, status.Key())
	if config == nil {
		log.Functionf("maybeRetryDownload(%s) no config",
			status.Key())
		return
	}
	if config.RefCount == 0 {
		log.Functionf("maybeRetryDownload(%s) RefCount==0",
			status.Key())
		return
	}

	t := time.Now()
	elapsed := t.Sub(status.ErrorTime)
	if elapsed < retryTime {
		log.Functionf("maybeRetryDownload(%s) %d remaining",
			status.Key(),
			(retryTime-elapsed)/time.Second)
		return
	}
	log.Functionf("maybeRetryDownload(%s) after %s at %v",
		status.Key(), status.Error, status.ErrorTime)

	if status.RetryCount == 0 {
		status.OrigError = status.Error
	}
	// Increment count; we defer clearing error until success
	// to avoid confusing the user.
	status.RetryCount++
	severity := types.GetErrorSeverity(status.RetryCount, time.Duration(status.RetryCount)*retryTime)
	errDescription := types.ErrorDescription{
		Error:               status.OrigError,
		ErrorRetryCondition: fmt.Sprintf("Retrying; attempt %d", status.RetryCount),
		ErrorSeverity:       severity,
	}
	status.SetErrorDescription(errDescription)
	publishDownloaderStatus(ctx, status)

	doDownload(ctx, *config, status, receiveChan)
}

func handleCreate(ctx *downloaderContext, config types.DownloaderConfig,
	status *types.DownloaderStatus, key string,
	receiveChan chan<- CancelChannel) {

	log.Functionf("handleCreate(%s) for %s", config.ImageSha256, config.Name)

	if status == nil {
		// Start by marking with PendingAdd
		status0 := types.DownloaderStatus{
			DatastoreID: config.DatastoreID,
			Name:        config.Name,
			ImageSha256: config.ImageSha256,
			State:       types.DOWNLOADING,
			RefCount:    config.RefCount,
			Size:        config.Size,
			LastUse:     time.Now(),
			PendingAdd:  true,
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

	doDownload(ctx, config, status, receiveChan)
}

// RefCount 0->1 means download.
// RefCount -> 0 means set Expired to delete
func handleModify(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus,
	receiveChan chan<- CancelChannel) {

	log.Functionf("handleModify(%s) for %s", status.ImageSha256, status.Name)

	status.PendingModify = true
	publishDownloaderStatus(ctx, status)

	log.Functionf("handleModify(%s) RefCount %d to %d, Expired %v for %s",
		status.ImageSha256, status.RefCount, config.RefCount,
		status.Expired, status.Name)

	// If RefCount from zero to non-zero and status has error
	// or status is not downloaded then do install
	if config.RefCount != 0 && (status.HasError() || status.State != types.DOWNLOADED) {
		log.Functionf("handleModify installing %s", config.Name)
		handleCreate(ctx, config, status, key, receiveChan)
	} else if status.RefCount != config.RefCount {
		log.Functionf("handleModify RefCount change %s from %d to %d",
			config.Name, status.RefCount, config.RefCount)
		status.RefCount = config.RefCount
	}
	status.LastUse = time.Now()
	status.Expired = (status.RefCount == 0) // Start delete handshake
	status.ClearPendingStatus()
	publishDownloaderStatus(ctx, status)
	log.Functionf("handleModify done for %s", config.Name)
}

func doDelete(ctx *downloaderContext, key string, filename string,
	status *types.DownloaderStatus) {

	log.Functionf("doDelete(%s) for %s", status.ImageSha256, status.Name)

	if _, err := os.Stat(filename); err == nil {
		log.Functionf("Deleting %s", filename)
		if err := os.RemoveAll(filename); err != nil {
			log.Errorf("Failed to remove %s: err %s",
				filename, err)
		}
	}

	status.State = types.INITIAL

	publishDownloaderStatus(ctx, status)
}

// perform download of the object, by reserving storage
func doDownload(ctx *downloaderContext, config types.DownloaderConfig, status *types.DownloaderStatus,
	receiveChan chan<- CancelChannel) {

	// If RefCount == 0 then we don't yet need to download.
	if config.RefCount == 0 {
		errStr := fmt.Sprintf("RefCount==0; download deferred for %s\n",
			config.Name)
		status.HandleDownloadFail(errStr, 0, false)
		publishDownloaderStatus(ctx, status)
		log.Errorf("doDownload(%s): deferred with %s", config.Name, errStr)
		return
	}

	dst, err := utils.LookupDatastoreConfig(ctx.subDatastoreConfig, config.DatastoreID)
	if dst == nil {
		errStr := fmt.Sprintf("Will retry when datastore available: %s",
			err.Error())
		status.HandleDownloadFail(errStr, 0, false)
		publishDownloaderStatus(ctx, status)
		log.Errorf("doDownload(%s): deferred with %v", config.Name, err)
		return
	}
	log.Tracef("Found datastore(%s) for %s", config.DatastoreID.String(), config.Name)

	handleSyncOp(ctx, status.Key(), config, status, dst, receiveChan)
}

func handleDelete(ctx *downloaderContext, key string,
	status *types.DownloaderStatus) {

	log.Functionf("handleDelete(%s) for %s RefCount %d LastUse %v Expired %v",
		status.ImageSha256, status.Name,
		status.RefCount, status.LastUse, status.Expired)

	status.PendingDelete = true
	publishDownloaderStatus(ctx, status)

	doDelete(ctx, key, status.Target, status)

	status.PendingDelete = false
	publishDownloaderStatus(ctx, status)

	// Write out what we modified to DownloaderStatus aka delete
	unpublishDownloaderStatus(ctx, status)
	log.Functionf("handleDelete done for %s", status.Name)
}

// helper functions

func downloaderInit(ctx *downloaderContext) *zedUpload.DronaCtx {

	// create drona interface
	dCtx, err := zedUpload.NewDronaCtx("zdownloader", 0)

	if dCtx == nil {
		log.Errorf("context create fail %s", err)
		log.Fatal(err)
	}
	// Remove any files which didn't complete before the device reboot
	clearInProgressDownloadDirs()
	createDownloadDirs()
	return dCtx
}

func publishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := ctx.pubDownloaderStatus
	key := status.Key()
	log.Tracef("publishDownloaderStatus(%s)", key)
	pub.Publish(key, *status)
}

func unpublishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := ctx.pubDownloaderStatus
	key := status.Key()
	log.Tracef("unpublishDownloaderStatus(%s)", key)
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishDownloaderStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}
