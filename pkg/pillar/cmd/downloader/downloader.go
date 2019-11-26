// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of collections of DownloaderConfig structs
// and publish the results as collections of DownloaderStatus structs.
// There are several inputs and outputs based on the objType.

package downloader

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	"github.com/lf-edge/eve/pkg/pillar/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	agentName = "downloader"
	// persistRktLocalConfigBase - Base Dir used for LocalConfigDir for
	//  rkt Container images
	persistRktLocalConfigBase = types.PersistDir + "/rktlocal"
)

// Go doesn't like this as a constant
var (
	downloaderObjTypes = []string{types.AppImgObj, types.BaseOsObj,
		types.CertObj}
)

// Set from Makefile
var Version = "No version specified"
var nilUUID uuid.UUID

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
	subDatastoreConfig      *pubsub.Subscription
	deviceNetworkStatus     types.DeviceNetworkStatus
	globalConfig            types.GlobalDownloadConfig
	globalStatusLock        sync.Mutex
	globalStatus            types.GlobalDownloadStatus
	subGlobalConfig         *pubsub.Subscription
}

var debug = false
var debugOverride bool                                   // From command line arg
var downloadGCTime = time.Duration(600) * time.Second    // Unless from GlobalConfig
var downloadRetryTime = time.Duration(600) * time.Second // Unless from GlobalConfig

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

	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.CreateHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.CreateHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	subGlobalDownloadConfig, err := pubsub.Subscribe("",
		types.GlobalDownloadConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalDownloadConfig.ModifyHandler = handleGlobalDownloadConfigModify
	subGlobalDownloadConfig.CreateHandler = handleGlobalDownloadConfigModify
	ctx.subGlobalDownloadConfig = subGlobalDownloadConfig
	subGlobalDownloadConfig.Activate()

	// Look for DatastoreConfig. We should process this
	// before any download config ( App/baseos/cert). Without DataStore Config,
	// Image Downloads will run into errors.
	subDatastoreConfig, err := pubsub.Subscribe("zedagent",
		types.DatastoreConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subDatastoreConfig.ModifyHandler = handleDatastoreConfigModify
	subDatastoreConfig.CreateHandler = handleDatastoreConfigModify
	subDatastoreConfig.DeleteHandler = handleDatastoreConfigDelete
	ctx.subDatastoreConfig = subDatastoreConfig
	subDatastoreConfig.Activate()

	pubGlobalDownloadStatus, err := pubsub.Publish(agentName,
		types.GlobalDownloadStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubGlobalDownloadStatus = pubGlobalDownloadStatus

	// Set up our publications before the subscriptions so ctx is set
	pubAppImgStatus, err := pubsub.PublishScope(agentName, types.AppImgObj,
		types.DownloaderStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppImgStatus = pubAppImgStatus
	pubAppImgStatus.ClearRestarted()

	pubBaseOsStatus, err := pubsub.PublishScope(agentName, types.BaseOsObj,
		types.DownloaderStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubBaseOsStatus = pubBaseOsStatus
	pubBaseOsStatus.ClearRestarted()

	pubCertObjStatus, err := pubsub.PublishScope(agentName, types.CertObj,
		types.DownloaderStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubCertObjStatus = pubCertObjStatus
	pubCertObjStatus.ClearRestarted()

	subAppImgConfig, err := pubsub.SubscribeScope("zedmanager",
		types.AppImgObj, types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgConfig.ModifyHandler = handleAppImgModify
	subAppImgConfig.CreateHandler = handleAppImgCreate
	subAppImgConfig.DeleteHandler = handleAppImgDelete
	ctx.subAppImgConfig = subAppImgConfig
	subAppImgConfig.Activate()

	subBaseOsConfig, err := pubsub.SubscribeScope("baseosmgr",
		types.BaseOsObj, types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsConfig.ModifyHandler = handleBaseOsModify
	subBaseOsConfig.CreateHandler = handleBaseOsCreate
	subBaseOsConfig.DeleteHandler = handleBaseOsDelete
	ctx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()

	subCertObjConfig, err := pubsub.SubscribeScope("baseosmgr",
		types.CertObj, types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subCertObjConfig.ModifyHandler = handleCertObjModify
	subCertObjConfig.CreateHandler = handleCertObjCreate
	subCertObjConfig.DeleteHandler = handleCertObjDelete
	ctx.subCertObjConfig = subCertObjConfig
	subCertObjConfig.Activate()

	pubAppImgStatus.SignalRestarted()
	pubBaseOsStatus.SignalRestarted()
	pubCertObjStatus.SignalRestarted()

	// First wait to have some management ports with addresses
	// Looking at any management ports since we can do baseOS download over all
	// Also ensure GlobalDownloadConfig has been read
	for types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus) == 0 ||
		ctx.globalConfig.MaxSpace == 0 {
		log.Infof("Waiting for management port addresses or Global Config\n")

		select {
		case change := <-subGlobalConfig.C:
			start := agentlog.StartTime()
			subGlobalConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-subDeviceNetworkStatus.C:
			start := agentlog.StartTime()
			subDeviceNetworkStatus.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-subGlobalDownloadConfig.C:
			start := agentlog.StartTime()
			subGlobalDownloadConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		// This wait can take an unbounded time since we wait for IP
		// addresses. Punch StillRunning
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName)
	}
	log.Infof("Have %d management ports addresses to use\n",
		types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus))

	ctx.dCtx = downloaderInit(&ctx)

	// We will cleanup zero RefCount objects after a while
	// We run timer 10 times more often than the limit on LastUse
	gc := time.NewTicker(downloadGCTime / 10)

	for {
		select {
		case change := <-subGlobalConfig.C:
			start := agentlog.StartTime()
			subGlobalConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-subDeviceNetworkStatus.C:
			start := agentlog.StartTime()
			subDeviceNetworkStatus.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-subCertObjConfig.C:
			start := agentlog.StartTime()
			subCertObjConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-subAppImgConfig.C:
			start := agentlog.StartTime()
			subAppImgConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-subBaseOsConfig.C:
			start := agentlog.StartTime()
			subBaseOsConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-subDatastoreConfig.C:
			start := agentlog.StartTime()
			subDatastoreConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-subGlobalDownloadConfig.C:
			start := agentlog.StartTime()
			subGlobalDownloadConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case <-publishTimer.C:
			start := agentlog.StartTime()
			err := pub.Publish("global", zedcloud.GetCloudMetrics())
			if err != nil {
				log.Errorln(err)
			}
			agentlog.CheckMaxTime(agentName, start)

		case <-gc.C:
			start := agentlog.StartTime()
			gcObjects(&ctx)
			agentlog.CheckMaxTime(agentName, start)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName)
	}
}

// Handles both create and modify events
func handleDatastoreConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := cast.CastDatastoreConfig(configArg)
	log.Infof("handleDatastoreConfigModify for %s\n", key)
	checkAndUpdateDownloadableObjects(ctx, config.UUID)
	log.Infof("handleDatastoreConfigModify for %s, done\n", key)
}

func handleDatastoreConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleDatastoreConfigDelete for %s\n", key)
}

// handle the datastore modification
func checkAndUpdateDownloadableObjects(ctx *downloaderContext, dsID uuid.UUID) {
	publications := []*pubsub.Publication{
		ctx.pubAppImgStatus,
		ctx.pubBaseOsStatus,
		ctx.pubCertObjStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for _, st := range items {
			status := cast.CastDownloaderStatus(st)
			if status.DatastoreID == dsID {
				config := lookupDownloaderConfig(ctx, status.ObjType, status.Key())
				if config != nil {
					handleDownloaderModify(ctx, status.ObjType, status.Key(), config)
				}
			}
		}
	}
}

// Wrappers to add objType for create. The Delete wrappers are merely
// for function name consistency
func handleAppImgModify(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderModify(ctxArg, types.AppImgObj, key, configArg)
}

func handleAppImgCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderCreate(ctxArg, types.AppImgObj, key, configArg)
}

func handleAppImgDelete(ctxArg interface{}, key string, configArg interface{}) {
	handleDownloaderDelete(ctxArg, key, configArg)
}

func handleBaseOsModify(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderModify(ctxArg, types.BaseOsObj, key, configArg)
}

func handleBaseOsCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderCreate(ctxArg, types.BaseOsObj, key, configArg)
}

func handleBaseOsDelete(ctxArg interface{}, key string, configArg interface{}) {
	handleDownloaderDelete(ctxArg, key, configArg)
}

func handleCertObjModify(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderModify(ctxArg, types.CertObj, key, configArg)
}
func handleCertObjCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	handleDownloaderCreate(ctxArg, types.CertObj, key, configArg)
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
		log.Infof("lookupDownloaderStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastDownloaderStatus(st)
	if status.Key() != key {
		log.Errorf("lookupDownloaderStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func lookupDownloaderConfig(ctx *downloaderContext, objType string,
	key string) *types.DownloaderConfig {

	sub := downloaderSubscription(ctx, objType)
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupDownloaderConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastDownloaderConfig(c)
	if config.Key() != key {
		log.Errorf("lookupDownloaderConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
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

	log.Infof("handleDownloaderModify(%s)\n", key)
	config := cast.CastDownloaderConfig(configArg)
	if config.Key() != key {
		log.Errorf("handleDownloaderModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	h, ok := handlerMap[config.Key()]
	if !ok {
		log.Fatalf("handleDownloaderModify called on config that does not exist")
	}
	h <- configArg
}

func handleDownloaderCreate(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Infof("handleDownloaderCreate(%s)\n", key)
	ctx := ctxArg.(*downloaderContext)
	config := cast.CastDownloaderConfig(configArg)
	if config.Key() != key {
		log.Errorf("handleDownloaderCreate key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	h, ok := handlerMap[config.Key()]
	if ok {
		log.Fatalf("handleDownloaderCreate called on config that already exists")
	}
	h1 := make(chan interface{}, 1)
	handlerMap[config.Key()] = h1
	go runHandler(ctx, objType, key, h1)
	h = h1
	h <- configArg
}

func handleDownloaderDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleDownloaderDelete(%s)\n", key)
	// Do we have a channel/goroutine?
	h, ok := handlerMap[key]
	if ok {
		log.Debugf("Closing channel\n")
		close(h)
		delete(handlerMap, key)
	} else {
		log.Debugf("handleDownloaderDelete: unknown %s\n", key)
		return
	}
	log.Infof("handleDownloaderDelete(%s) done\n", key)
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
				config := cast.CastDownloaderConfig(configArg)
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
		log.Infof("maybeRetryDownload(%s) %v remaining\n",
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

	log.Infof("handleCreate(%v) objType %s for %s\n",
		config.Safename, objType, config.Name)

	if objType == "" {
		log.Fatalf("handleCreate: No ObjType for %s\n",
			config.Safename)
	}
	// Start by marking with PendingAdd
	status := types.DownloaderStatus{
		DatastoreID:      config.DatastoreID,
		ImageID:          config.ImageID,
		Safename:         config.Safename,
		Name:             config.Name,
		ObjType:          objType,
		IsContainer:      config.IsContainer,
		RefCount:         config.RefCount,
		LastUse:          time.Now(),
		AllowNonFreePort: config.AllowNonFreePort,
		ImageSha256:      config.ImageSha256,
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

	log.Infof("handleModify(%v) objType %s for %s\n",
		status.Safename, status.ObjType, status.Name)

	if status.ObjType == "" {
		log.Fatalf("handleModify: No ObjType for %s\n",
			status.Safename)
	}
	locDirname := types.DownloadDirname + "/" + status.ObjType

	if config.Name != status.Name {
		log.Errorf("URL changed - not allowed %s -> %s\n",
			config.Name, status.Name)
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
		log.Errorf("handleModify %s for %s\n", reason, config.Name)
		doDelete(ctx, key, locDirname, status)
		handleCreate(ctx, status.ObjType, config, key)
		log.Infof("handleModify done for %s\n", config.Name)
		return
	}

	log.Infof("handleModify(%v) RefCount %d to %d, Expired %v for %s\n",
		status.Safename, status.RefCount, config.RefCount,
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

	log.Infof("doDelete(%v) for %s\n", status.Safename, status.Name)

	deletefile(locDirname+"/pending", status)

	status.State = types.INITIAL
	deleteSpace(ctx, types.RoundupToKB(status.Size))
	status.Size = 0

	// XXX Asymmetric; handleCreate reserved on RefCount 0. We unreserve
	// going back to RefCount 0. FIXed
	publishDownloaderStatus(ctx, status)
}

func deletefile(dirname string, status *types.DownloaderStatus) {
	if status.ImageSha256 != "" {
		dirname = dirname + "/" + status.ImageSha256
	}

	if _, err := os.Stat(dirname); err == nil {
		filename := dirname + "/" + status.Safename
		if _, err := os.Stat(filename); err == nil {
			log.Infof("Deleting %s\n", filename)
			// Remove file
			if err := os.Remove(filename); err != nil {
				log.Errorf("Failed to remove %s: err %s\n",
					filename, err)
			}
		}
	}
}

func handleDelete(ctx *downloaderContext, key string,
	status *types.DownloaderStatus) {

	log.Infof("handleDelete(%v) objType %s for %s RefCount %d LastUse %v Expired %v\n",
		status.Safename, status.ObjType, status.Name,
		status.RefCount, status.LastUse, status.Expired)

	if status.ObjType == "" {
		log.Fatalf("handleDelete: No ObjType for %s\n",
			status.Safename)
	}
	locDirname := types.DownloadDirname + "/" + status.ObjType

	status.PendingDelete = true
	publishDownloaderStatus(ctx, status)

	// If Container, delete LocalConfigDir
	if status.ContainerRktLocalConfigDir != "" {
		if err := os.RemoveAll(status.ContainerRktLocalConfigDir); err != nil {
			log.Fatal(err)
		}
	}

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

// Handles both create and modify events
func handleGlobalDownloadConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	config := cast.CastGlobalDownloadConfig(configArg)
	if key != "global" {
		log.Errorf("handleGlobalDownloadConfigModify: unexpected key %s\n", key)
		return
	}
	log.Infof("handleGlobalDownloadConfigModify for %s\n", key)
	ctx.globalConfig = config
	log.Infof("handleGlobalDownloadConfigModify done for %s\n", key)
}

func initializeDirs() {

	// Remove any files which didn't make it to the verifier.
	// XXX space calculation doesn't take into account files in verifier
	// XXX get space report from verifier??
	clearInProgressDownloadDirs(downloaderObjTypes)

	// create the object download directories
	createDownloadDirs(downloaderObjTypes)
}

// Create the object download directories we own
func createDownloadDirs(objTypes []string) {

	workingDirTypes := []string{"pending"}

	// now create the download dirs
	for _, objType := range objTypes {
		for _, dirType := range workingDirTypes {
			dirName := types.DownloadDirname + "/" + objType + "/" + dirType
			if _, err := os.Stat(dirName); err != nil {
				log.Debugf("Create %s\n", dirName)
				if err := os.MkdirAll(dirName, 0700); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

// clear in-progress object download directories
func clearInProgressDownloadDirs(objTypes []string) {

	inProgressDirTypes := []string{"pending"}

	// now create the download dirs
	for _, objType := range objTypes {
		for _, dirType := range inProgressDirTypes {
			dirName := types.DownloadDirname + "/" + objType +
				"/" + dirType
			if _, err := os.Stat(dirName); err == nil {
				if err := os.RemoveAll(dirName); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

// If an object has a zero RefCount and dropped to zero more than
// downloadGCTime ago, then we delete the Status. That will result in the
// user (zedmanager or baseosmgr) deleting the Config, unless a RefCount
// increase is underway.
// XXX Note that this runs concurrently with the handler.
func gcObjects(ctx *downloaderContext) {
	log.Debugf("gcObjects()\n")
	publications := []*pubsub.Publication{
		ctx.pubAppImgStatus,
		ctx.pubBaseOsStatus,
		ctx.pubCertObjStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for key, st := range items {
			status := cast.CastDownloaderStatus(st)
			if status.Key() != key {
				log.Errorf("gcObjects key/UUID mismatch %s vs %s; ignored %+v\n",
					key, status.Key(), status)
				continue
			}
			if status.RefCount != 0 {
				log.Debugf("gcObjects: skipping RefCount %d: %s\n",
					status.RefCount, key)
				continue
			}
			timePassed := time.Since(status.LastUse)
			if timePassed < downloadGCTime {
				log.Debugf("gcObjects: skipping recently used %s remains %d seconds\n",
					key,
					(timePassed-downloadGCTime)/time.Second)
				continue
			}
			log.Infof("gcObjects: expiring status for %s; LastUse %v now %v\n",
				key, status.LastUse, time.Now())
			status.Expired = true
			publishDownloaderStatus(ctx, &status)
		}
	}
}

func initSpace(ctx *downloaderContext, kb uint64) {
	ctx.globalStatusLock.Lock()
	ctx.globalStatus.UsedSpace = 0
	ctx.globalStatus.ReservedSpace = 0
	updateRemainingSpace(ctx)

	ctx.globalStatus.UsedSpace = kb
	// Note that the UsedSpace calculated during initialization can
	// exceed MaxSpace, and RemainingSpace is a uint!
	if ctx.globalStatus.UsedSpace > ctx.globalConfig.MaxSpace {
		ctx.globalStatus.UsedSpace = ctx.globalConfig.MaxSpace
	}
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

	publishGlobalStatus(ctx)
}

// Returns true if there was space
func tryReserveSpace(ctx *downloaderContext, status *types.DownloaderStatus,
	kb uint64) bool {

	ctx.globalStatusLock.Lock()
	if kb >= ctx.globalStatus.RemainingSpace {
		ctx.globalStatusLock.Unlock()
		return false
	}
	ctx.globalStatus.ReservedSpace += kb
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

	publishGlobalStatus(ctx)
	status.ReservedSpace = kb
	return true
}

func unreserveSpace(ctx *downloaderContext, status *types.DownloaderStatus) {
	ctx.globalStatusLock.Lock()
	ctx.globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	ctx.globalStatus.UsedSpace += types.RoundupToKB(status.Size)

	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

	publishGlobalStatus(ctx)
}

func deleteSpace(ctx *downloaderContext, kb uint64) {
	ctx.globalStatusLock.Lock()
	ctx.globalStatus.UsedSpace -= kb
	updateRemainingSpace(ctx)
	ctx.globalStatusLock.Unlock()

	publishGlobalStatus(ctx)
}

// Caller must hold ctx.globalStatusLock.Lock() but no way to assert in go
func updateRemainingSpace(ctx *downloaderContext) {

	ctx.globalStatus.RemainingSpace = ctx.globalConfig.MaxSpace -
		ctx.globalStatus.UsedSpace - ctx.globalStatus.ReservedSpace

	log.Infof("RemainingSpace %d, maxspace %d, usedspace %d, reserved %d\n",
		ctx.globalStatus.RemainingSpace, ctx.globalConfig.MaxSpace,
		ctx.globalStatus.UsedSpace, ctx.globalStatus.ReservedSpace)
}

func publishGlobalStatus(ctx *downloaderContext) {
	ctx.pubGlobalDownloadStatus.Publish("global", &ctx.globalStatus)
}

func publishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := downloaderPublication(ctx, status.ObjType)
	key := status.Key()
	log.Debugf("publishDownloaderStatus(%s)\n", key)
	pub.Publish(key, status)
}

func unpublishDownloaderStatus(ctx *downloaderContext,
	status *types.DownloaderStatus) {

	pub := downloaderPublication(ctx, status.ObjType)
	key := status.Key()
	log.Debugf("unpublishDownloaderStatus(%s)\n", key)
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishDownloaderStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func downloaderPublication(ctx *downloaderContext, objType string) *pubsub.Publication {
	var pub *pubsub.Publication
	switch objType {
	case types.AppImgObj:
		pub = ctx.pubAppImgStatus
	case types.BaseOsObj:
		pub = ctx.pubBaseOsStatus
	case types.CertObj:
		pub = ctx.pubCertObjStatus
	default:
		log.Fatalf("downloaderPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}

func downloaderSubscription(ctx *downloaderContext, objType string) *pubsub.Subscription {

	var sub *pubsub.Subscription
	switch objType {
	case types.AppImgObj:
		sub = ctx.subAppImgConfig
	case types.BaseOsObj:
		sub = ctx.subBaseOsConfig
	case types.CertObj:
		sub = ctx.subCertObjConfig
	default:
		log.Fatalf("downloaderSubscription: Unknown ObjType %s\n",
			objType)
	}
	return sub
}

// cloud storage interface functions/APIs

func doHttp(ctx *downloaderContext, status *types.DownloaderStatus,
	syncOp zedUpload.SyncOpType, serverUrl, dpath string, maxsize uint64,
	ifname string, ipSrc net.IP, filename, locFilename string) error {

	auth := &zedUpload.AuthInput{
		AuthType: "http",
	}

	trType := zedUpload.SyncHttpTr

	// create Endpoint
	dEndPoint, err := ctx.dCtx.NewSyncerDest(trType, serverUrl, dpath, auth)
	if err != nil {
		log.Errorf("NewSyncerDest failed: %s\n", err)
		return err
	}
	proxyUrl, err := zedcloud.LookupProxy(
		&ctx.deviceNetworkStatus, ifname, serverUrl)
	if err == nil && proxyUrl != nil {
		log.Infof("doHttp: Using proxy %s", proxyUrl.String())
		dEndPoint.WithSrcIpAndProxySelection(ipSrc, proxyUrl)
	} else {
		dEndPoint.WithSrcIpSelection(ipSrc)
	}
	var respChan = make(chan *zedUpload.DronaRequest)

	log.Infof("doHttp syncOp for <%s>, <%s>, <%s>\n", serverUrl, dpath,
		filename)
	// create Request
	// Round up from bytes to Mbytes
	maxMB := (maxsize + 1024*1024 - 1) / (1024 * 1024)
	req := dEndPoint.NewRequest(syncOp, filename, locFilename, int64(maxMB), true, respChan)
	if req == nil {
		return errors.New("NewRequest failed")
	}

	req.Post()
	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				asize := resp.GetAsize()
				osize := resp.GetOsize()
				log.Infof("Update progress for %v: %v/%v",
					resp.GetLocalName(), asize, osize)
				if osize == 0 {
					status.Progress = 0
				} else {
					percent := 100 * asize / osize
					status.Progress = uint(percent)
				}
				publishDownloaderStatus(ctx, status)
				continue
			}
			if !ok {
				errStr := fmt.Sprintf("respChan EOF for <%s>, <%s>",
					serverUrl, filename)
				log.Errorln(errStr)
				return errors.New(errStr)
			}
			if syncOp == zedUpload.SyncOpDownload {
				err = resp.GetDnStatus()
			} else {
				_, err = resp.GetUpStatus()
			}
			if resp.IsError() {
				return err
			} else {
				log.Infof("Done for %v: size %v/%v",
					resp.GetLocalName(),
					resp.GetAsize(), resp.GetOsize())
				status.Progress = 100
				publishDownloaderStatus(ctx, status)
				return nil
			}
		}
	}
}

func doS3(ctx *downloaderContext, status *types.DownloaderStatus,
	syncOp zedUpload.SyncOpType, dnldUrl string, apiKey string, password string,
	dpath string, region string, maxsize uint64, ifname string,
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
		log.Errorf("NewSyncerDest failed: %s\n", err)
		return err
	}
	// check for proxies on the selected management port interface
	proxyUrl, err := zedcloud.LookupProxy(
		&ctx.deviceNetworkStatus, ifname, dnldUrl)
	if err == nil && proxyUrl != nil {
		log.Infof("doS3: Using proxy %s", proxyUrl.String())
		dEndPoint.WithSrcIpAndProxySelection(ipSrc, proxyUrl)
	} else {
		dEndPoint.WithSrcIpSelection(ipSrc)
	}

	var respChan = make(chan *zedUpload.DronaRequest)

	log.Infof("doS3 syncOp for <%s>, <%s>, <%s>\n", dpath, region, filename)
	// create Request
	// Round up from bytes to Mbytes
	maxMB := (maxsize + 1024*1024 - 1) / (1024 * 1024)
	req := dEndPoint.NewRequest(syncOp, filename, locFilename,
		int64(maxMB), true, respChan)
	if req == nil {
		return errors.New("NewRequest failed")
	}

	req.Post()
	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				asize := resp.GetAsize()
				osize := resp.GetOsize()
				log.Infof("Update progress for %v: %v/%v",
					resp.GetLocalName(), asize, osize)
				if osize == 0 {
					status.Progress = 0
				} else {
					percent := 100 * asize / osize
					status.Progress = uint(percent)
				}
				publishDownloaderStatus(ctx, status)
				continue
			}
			if !ok {
				errStr := fmt.Sprintf("respChan EOF for <%s>, <%s>, <%s>",
					dpath, region, filename)
				log.Errorln(errStr)
				return errors.New(errStr)
			}
			if syncOp == zedUpload.SyncOpDownload {
				err = resp.GetDnStatus()
			} else {
				_, err = resp.GetUpStatus()
			}
			if resp.IsError() {
				return err
			} else {
				log.Infof("Done for %v: size %v/%v",
					resp.GetLocalName(),
					resp.GetAsize(), resp.GetOsize())
				status.Progress = 100
				publishDownloaderStatus(ctx, status)
				return nil
			}
		}
	}
}

func doAzureBlob(ctx *downloaderContext, status *types.DownloaderStatus,
	syncOp zedUpload.SyncOpType, dnldURL string, apiKey string, password string,
	dpath string, maxsize uint64, ifname string,
	ipSrc net.IP, filename string, locFilename string) error {

	auth := &zedUpload.AuthInput{
		AuthType: "password",
		Uname:    apiKey,
		Password: password,
	}

	trType := zedUpload.SyncAzureTr

	// create Endpoint
	dEndPoint, err := ctx.dCtx.NewSyncerDest(trType, "", dpath, auth)
	if err != nil {
		log.Errorf("NewSyncerDest failed: %s\n", err)
		return err
	}
	// check for proxies on the selected management port interface
	proxyURL, err := zedcloud.LookupProxy(
		&ctx.deviceNetworkStatus, ifname, dnldURL)
	if err == nil && proxyURL != nil {
		log.Infof("doAzure: Using proxy %s", proxyURL.String())
		dEndPoint.WithSrcIpAndProxySelection(ipSrc, proxyURL)
	} else {
		dEndPoint.WithSrcIpSelection(ipSrc)
	}

	var respChan = make(chan *zedUpload.DronaRequest)

	log.Infof("doAzure syncOp for <%s>, <%s>\n", dpath, filename)
	// create Request
	// Round up from bytes to Mbytes
	maxMB := (maxsize + 1024*1024 - 1) / (1024 * 1024)
	req := dEndPoint.NewRequest(syncOp, filename, locFilename,
		int64(maxMB), true, respChan)
	if req == nil {
		return errors.New("NewRequest failed")
	}

	req.Post()
	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				asize := resp.GetAsize()
				osize := resp.GetOsize()
				log.Infof("Update progress for %v: %v/%v",
					resp.GetLocalName(), asize, osize)
				if osize == 0 {
					status.Progress = 0
				} else {
					percent := 100 * asize / osize
					status.Progress = uint(percent)
				}
				publishDownloaderStatus(ctx, status)
				continue
			}
			if !ok {
				errStr := fmt.Sprintf("respChan EOF for <%s>, <%s>",
					dpath, filename)
				log.Errorln(errStr)
				return errors.New(errStr)
			}
			if syncOp == zedUpload.SyncOpDownload {
				err = resp.GetDnStatus()
			} else {
				_, err = resp.GetUpStatus()
			}
			if resp.IsError() {
				return err
			} else {
				log.Infof("Done for %v: size %v/%v",
					resp.GetLocalName(),
					resp.GetAsize(), resp.GetOsize())
				status.Progress = 100
				publishDownloaderStatus(ctx, status)
				return nil
			}
		}
	}
}

func doSftp(ctx *downloaderContext, status *types.DownloaderStatus,
	syncOp zedUpload.SyncOpType, apiKey string, password string,
	serverUrl string, dpath string, maxsize uint64,
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
		log.Errorf("NewSyncerDest failed: %s\n", err)
		return err
	}
	dEndPoint.WithSrcIpSelection(ipSrc)
	var respChan = make(chan *zedUpload.DronaRequest)

	log.Infof("doSftp syncOp for <%s>, <%s>, <%s>\n", serverUrl, dpath,
		filename)
	// create Request
	// Round up from bytes to Mbytes
	maxMB := (maxsize + 1024*1024 - 1) / (1024 * 1024)
	req := dEndPoint.NewRequest(syncOp, filename, locFilename,
		int64(maxMB), true, respChan)
	if req == nil {
		return errors.New("NewRequest failed")
	}

	req.Post()
	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				asize := resp.GetAsize()
				osize := resp.GetOsize()
				log.Infof("Update progress for %v: %v/%v",
					resp.GetLocalName(), asize, osize)
				if osize == 0 {
					status.Progress = 0
				} else {
					percent := 100 * asize / osize
					status.Progress = uint(percent)
				}
				publishDownloaderStatus(ctx, status)
				continue
			}
			if !ok {
				errStr := fmt.Sprintf("respChan EOF for <%s>, <%s>",
					dpath, filename)
				log.Errorln(errStr)
				return errors.New(errStr)
			}
			_, err = resp.GetUpStatus()
			if resp.IsError() {
				return err
			} else {
				log.Infof("Done for %v: size %v/%v",
					resp.GetLocalName(),
					resp.GetAsize(), resp.GetOsize())
				status.Progress = 100
				publishDownloaderStatus(ctx, status)
				return nil
			}
		}
	}
}

func constructDatastoreContext(config types.DownloaderConfig, status *types.DownloaderStatus, dst *types.DatastoreConfig) *types.DatastoreContext {
	dpath := dst.Dpath
	if status.ObjType == types.CertObj {
		dpath = strings.Replace(dpath, "-images", "-certs", 1)
	}
	downloadURL := config.Name
	if !config.NameIsURL {
		downloadURL = dst.Fqdn
		if len(dpath) > 0 {
			downloadURL = downloadURL + "/" + dpath
		}
		if len(config.Name) > 0 {
			downloadURL = downloadURL + "/" + config.Name
		}
	}
	dsCtx := types.DatastoreContext{
		DownloadURL:     downloadURL,
		TransportMethod: dst.DsType,
		Dpath:           dpath,
		APIKey:          dst.ApiKey,
		Password:        dst.Password,
		Region:          dst.Region,
	}
	return &dsCtx
}

// getContainerRegistry will extract container registry and form download url
// for rktFetch
func getContainerRegistry(url string) (string, string, error) {
	var urlReg, registryReg, downReg *regexp.Regexp
	var registry, downURL string
	var err error
	urlReg, err = regexp.Compile(`^docker:\/\/(?:.*).io\/(?:.*)`)
	if err != nil {
		return "", "", err
	}
	registryReg, err = regexp.Compile(`(?:.*)(?:\.io)`)
	if err != nil {
		return "", "", err
	}
	downReg, err = regexp.Compile(`(?:.*)(?:\.io)\/`)
	if err != nil {
		return "", "", err
	}
	if urlReg.MatchString(url) {
		registry = strings.TrimPrefix(registryReg.FindString(url), "docker://")
		downURL = downReg.ReplaceAllString(url, "docker://")
		return registry, downURL, nil
	}
	return "", "", fmt.Errorf("Download URL is not formed properly")
}

func rktFetch(url string, localConfigDir string, pullPolicy string, imageUUID string, locFilename string) (string, error) {

	// rkt --insecure-options=image fetch <url> --dir=/persist/rkt --full=true
	log.Debugf("rktFetch - url: %s ,  localConfigDir:%s\n",
		url, localConfigDir)
	cmd := "rkt"
	args := []string{
		"--dir=" + types.PersistRktDataDir,
		"--insecure-options=image",
		"fetch",
	}
	if len(localConfigDir) > 0 {
		args = append(args, "--local-config="+localConfigDir)
	}
	if len(pullPolicy) > 0 {
		args = append(args, "--pull-policy="+pullPolicy)
	}
	args = append(args, url)
	args = append(args, "--full=true")

	log.Infof("rktFetch - url: %s ,  localConfigDir:%s, args: %+v\n",
		url, localConfigDir, args)

	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("rkt fetch failed ", err)
		log.Errorln("rkt fetch output ", string(stdoutStderr))
		return "", fmt.Errorf("rkt fetch failed: %s\nImage URL: %s\n",
			string(stdoutStderr), url)
	}
	log.Infof("rktFetch - image fetch successful. stdoutStderr: %s\n",
		stdoutStderr)
	outputStr := string(stdoutStderr)
	log.Debugf("rktFetch - outputStr: %s\n", outputStr)
	outputStrArray := strings.Split(outputStr, "\n")

	log.Debugf("rktFetch - outputStrArray:\n")
	for i, op := range outputStrArray {
		log.Debugf("index:%d, op:%s", i, op)
	}
	log.Debugf("rktFetch - outputStrArray DONE\n")

	// Get ImageID from the oputput. The last line in rkt fetch output
	// with sha12- is the imageID
	imageID := ""
	for i := len(outputStrArray) - 1; i >= 0; i-- {
		imageID = outputStrArray[i]
		if strings.HasPrefix(imageID, "sha512-") {
			break
		}
	}
	log.Infof("rktFetch - imageID: %s\n", imageID)
	if imageID == "" {
		errMsg := "rkt fetch: Can't find imageID.\n Fetch Output: " +
			outputStr
		return "", errors.New(errMsg)
	}

	err = rktImageExport(imageID, imageUUID, locFilename)
	if err != nil {
		return imageID, err
	}

	// XXX:FIXME - we should run "rkt image ls" and verify image fetch
	// went thru without errors.
	return imageID, nil
}

func rktImageExport(imageHash, imageUUID, locFilename string) error {
	var aciDir string
	var aciName string
	cmd := "rkt"
	args := []string{
		"--dir=" + types.PersistRktDataDir,
		"--insecure-options=image",
		"image",
		"export",
		imageHash,
	}
	if strings.HasSuffix(locFilename, "/") {
		aciDir = locFilename + imageUUID
	} else {
		aciDir = locFilename + "/" + imageUUID
	}
	if _, err := os.Stat(aciDir); err != nil {
		log.Debugf("Create %s\n", aciDir)
		if err = os.MkdirAll(aciDir, 0755); err != nil {
			log.Fatal(err)
		}
	}
	aciName = aciDir + "/" + imageHash + ".aci"
	args = append(args, aciName)

	log.Infof("rkt image export args: %+v\n", args)

	_, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("rkt image export failed ", err)
		return err
	}
	log.Infof("rktImageExport - image export successful.")
	return nil
}

// createRktLocalDirAndAuthFile
//  Return Values: localConfigDir, AuthFileName, err
func createRktLocalDirAndAuthFile(imageID uuid.UUID,
	dsCtx types.DatastoreContext, registry string) (string, string, error) {

	if len(strings.TrimSpace(dsCtx.APIKey)) == 0 {
		log.Debugf("createRktLocalDirAndAuthFile: empty APIKey. " +
			"Skipping AuthFile")
		return "", "", nil
	}

	// Create Local Directory with name imageSafeName
	// The directory structure should be:
	// <persistRktLocalConfigBase>/<uuid>/auth.d/rktAuth<appName>.json
	localConfigDir := persistRktLocalConfigBase + "/" + imageID.String()
	authDir := localConfigDir + "/auth.d"
	authFileName := authDir + "/docker.json"
	err := os.MkdirAll(authDir, 0755)
	if err != nil {
		log.Errorf("createRktLocalDirAndAuthFile: empty username." +
			" Skipping AuthFile")
		return "", "", fmt.Errorf("Failed create dir %s, err: %+v\n",
			authDir, err)
	}

	rktAuth := types.RktAuthInfo{
		RktKind:    "dockerAuth",
		RktVersion: "v1",
		Registries: []string{registry},
		Credentials: &types.RktCredentials{
			User:     dsCtx.APIKey,
			Password: dsCtx.Password,
		},
	}
	log.Infof("createRktLocalDirAndAuthFile: created Auth file %s\n"+
		"RktKind: %s, RktVersion: %s, Registries: %+v, \n",
		authFileName, rktAuth.RktKind, rktAuth.RktVersion, rktAuth.Registries)

	rktAuthJSON, err := json.MarshalIndent(rktAuth, "", " ")
	if err != nil {
		return "", "", fmt.Errorf("Failed convert rktAuth to json"+
			"err: %+v\n", err)
	}
	err = ioutil.WriteFile(authFileName, rktAuthJSON, 0644)
	if err != nil {
		return "", "", fmt.Errorf("Failed to create Auth file for"+
			"rkt fetch: %+v\n", err)
	}
	return localConfigDir, authFileName, nil
}

func rktFetchContainerImage(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus,
	dsCtx types.DatastoreContext, pullPolicy, locFilename string) error {
	// update status to DOWNLOAD STARTED
	status.State = types.DOWNLOAD_STARTED
	publishDownloaderStatus(ctx, status)

	imageID := ""
	var authFile, localConfigDir string
	registry, downloadURL, err := getContainerRegistry(dsCtx.DownloadURL)
	if err == nil {
		// Save credentials to Auth file
		log.Infof("rktFetchContainerImage: fetch  <%s>\n", dsCtx.DownloadURL)
		localConfigDir, authFile, err = createRktLocalDirAndAuthFile(
			config.ImageID, dsCtx, registry)
		if err == nil {
			log.Debugf("rktFetchContainerImage: localConfigDir: %s, authFile: %s\n",
				localConfigDir, authFile)
			if len(authFile) == 0 {
				log.Infof("rktFetchContainerImage: no Auth File")
			}
			imageID, err = rktFetch(downloadURL, localConfigDir, pullPolicy, config.ImageID.String(), locFilename)
		} else {
			log.Errorf("rktCreateAuthFile Failed. err: %+v", err)
		}
	} else {
		log.Errorf("getContainerRegistry : registry and download url parsing failed. err: %+v", err)
	}

	if err != nil {
		log.Errorf("rktFetchContainerImage: fetch  Failed. url:%s, "+
			"authFile: %s, Err: %+v\n", dsCtx.DownloadURL, authFile, err)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.RetryCount++
		publishDownloaderStatus(ctx, status)
		return err
	}
	log.Infof("rktFetchContainerImage successful. imageID: <%s>\n",
		imageID)

	// Update globalStatus and status
	unreserveSpace(ctx, status)

	// We do not clear any status.RetryCount, LastErr, etc. The caller
	// should look at State == DOWNLOADED to determine it is done.
	status.ContainerImageID = imageID
	status.ContainerRktLocalConfigDir = localConfigDir
	status.ContainerRktAuthFileName = authFile
	status.ModTime = time.Now()
	status.PendingAdd = false
	status.State = types.DOWNLOADED
	status.Progress = 100 // Just in case
	publishDownloaderStatus(ctx, status)

	return nil
}

// Drona APIs for object Download
func handleSyncOp(ctx *downloaderContext, key string,
	config types.DownloaderConfig, status *types.DownloaderStatus,
	dst *types.DatastoreConfig) {
	var err error
	var errStr string
	var locFilename string
	var syncOp zedUpload.SyncOpType = zedUpload.SyncOpDownload
	var serverURL string

	if status.ObjType == "" {
		log.Fatalf("handleSyncOp: No ObjType for %s\n",
			status.Safename)
	}

	log.Debugf("handleSyncOp: config: %+v", config)
	log.Debugf("handleSyncOp: IsContainer: %v", config.IsContainer)

	// get the datastore context
	dsCtx := constructDatastoreContext(config, status, dst)

	locDirname := types.DownloadDirname + "/" + status.ObjType
	locFilename = locDirname + "/pending"

	if config.IsContainer {
		pullPolicy := "new"
		rktFetchContainerImage(ctx, key, config, status, *dsCtx, pullPolicy, locFilename)
		return
	}

	// update status to DOWNLOAD STARTED
	status.State = types.DOWNLOAD_STARTED
	publishDownloaderStatus(ctx, status)

	if config.ImageSha256 != "" {
		locFilename = locFilename + "/" + config.ImageSha256
	}

	if _, err := os.Stat(locFilename); err != nil {
		log.Debugf("Create %s\n", locFilename)
		if err = os.MkdirAll(locFilename, 0755); err != nil {
			log.Fatal(err)
		}
	}

	filename := types.SafenameToFilename(config.Safename)

	locFilename = locFilename + "/" + config.Safename

	log.Infof("Downloading <%s> to <%s> using %v allow non-free port\n",
		config.Name, locFilename, config.AllowNonFreePort)

	var addrCount int
	if !config.AllowNonFreePort {
		addrCount = types.CountLocalAddrFreeNoLinkLocal(ctx.deviceNetworkStatus)
		log.Infof("Have %d free management port addresses\n", addrCount)
		err = errors.New("No free IP management port addresses for download")
	} else {
		addrCount = types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus)
		log.Infof("Have %d any management port addresses\n", addrCount)
		err = errors.New("No IP management port addresses for download")
	}
	if addrCount == 0 {
		errStr = err.Error()
	}
	metricsUrl := dsCtx.DownloadURL
	if dsCtx.TransportMethod == zconfig.DsType_DsS3.String() {
		// fake URL for metrics
		metricsUrl = fmt.Sprintf("S3:%s/%s", dsCtx.Dpath, filename)
	}

	// Loop through all interfaces until a success
	for addrIndex := 0; addrIndex < addrCount; addrIndex += 1 {
		var ipSrc net.IP
		if !config.AllowNonFreePort {
			ipSrc, err = types.GetLocalAddrFreeNoLinkLocal(ctx.deviceNetworkStatus,
				addrIndex, "")
		} else {
			// Note that GetLocalAddrAny has the free ones first
			ipSrc, err = types.GetLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus,
				addrIndex, "")
		}
		if err != nil {
			log.Errorf("GetLocalAddr failed: %s\n", err)
			errStr = errStr + "\n" + err.Error()
			continue
		}
		ifname := types.GetMgmtPortFromAddr(ctx.deviceNetworkStatus, ipSrc)
		log.Infof("Using IP source %v if %s transport %v\n",
			ipSrc, ifname, dsCtx.TransportMethod)
		switch dsCtx.TransportMethod {
		case zconfig.DsType_DsS3.String():
			err = doS3(ctx, status, syncOp, dsCtx.DownloadURL, dsCtx.APIKey,
				dsCtx.Password, dsCtx.Dpath, dsCtx.Region,
				config.Size, ifname, ipSrc, filename, locFilename)
			if err != nil {
				log.Errorf("Source IP %s failed: %s\n",
					ipSrc.String(), err)
				errStr = errStr + "\n" + err.Error()
				// XXX don't know how much we downloaded!
				// Could have failed half-way. Using zero.
				zedcloud.ZedCloudFailure(ifname,
					metricsUrl, 1024, 0)
			} else {
				// Record how much we downloaded
				size := int64(0)
				info, err := os.Stat(locFilename)
				if err != nil {
					log.Error(err)
				} else {
					size = info.Size()
				}
				zedcloud.ZedCloudSuccess(ifname,
					metricsUrl, 1024, size)
				handleSyncOpResponse(ctx, config, status,
					locFilename, key, "")
				return
			}
		case zconfig.DsType_DsAzureBlob.String():
			// pass in the config.Name instead of 'filename' which
			// does not contain the prefix of the relative path with '/'s
			err = doAzureBlob(ctx, status, syncOp, dsCtx.DownloadURL, dsCtx.APIKey,
				dsCtx.Password, dsCtx.Dpath, config.Size, ifname, ipSrc, config.Name, locFilename)
			if err != nil {
				log.Errorf("Source IP %s failed: %s\n",
					ipSrc.String(), err)
				errStr = errStr + "\n" + err.Error()
				// XXX don't know how much we downloaded!
				// Could have failed half-way. Using zero.
				zedcloud.ZedCloudFailure(ifname,
					metricsUrl, 1024, 0)
			} else {
				// Record how much we downloaded
				size := int64(0)
				info, err := os.Stat(locFilename)
				if err != nil {
					log.Error(err)
				} else {
					size = info.Size()
				}
				zedcloud.ZedCloudSuccess(ifname,
					metricsUrl, 1024, size)
				handleSyncOpResponse(ctx, config, status,
					locFilename, key, "")
				return
			}
		case zconfig.DsType_DsSFTP.String():
			serverURL, err = getServerUrl(dsCtx)
			if err == nil {
				// pass in the config.Name instead of 'filename' which
				// does not contain the prefix of the relative path with '/'s
				err = doSftp(ctx, status, syncOp, dsCtx.APIKey,
					dsCtx.Password, serverURL, dsCtx.Dpath,
					config.Size, ipSrc, config.Name, locFilename)
			}
			if err != nil {
				log.Errorf("Source IP %s failed: %s\n",
					ipSrc.String(), err)
				errStr = errStr + "\n" + err.Error()
				// XXX don't know how much we downloaded!
				// Could have failed half-way. Using zero.
				zedcloud.ZedCloudFailure(ifname,
					metricsUrl, 1024, 0)
			} else {
				// Record how much we downloaded
				size := int64(0)
				info, err := os.Stat(locFilename)
				if err != nil {
					log.Error(err)
				} else {
					size = info.Size()
				}
				zedcloud.ZedCloudSuccess(ifname,
					metricsUrl, 1024, size)
				handleSyncOpResponse(ctx, config, status,
					locFilename, key, "")
				return
			}
		case zconfig.DsType_DsHttp.String(), zconfig.DsType_DsHttps.String(), "":
			serverURL, err = getServerUrl(dsCtx)
			if err == nil {
				// pass in the config.Name instead of 'filename' which
				// does not contain the prefix of the relative path with '/'s
				err = doHttp(ctx, status, syncOp, serverURL, dsCtx.Dpath,
					config.Size, ifname, ipSrc, config.Name, locFilename)
			}
			if err != nil {
				log.Errorf("Source IP %s failed: %s\n",
					ipSrc.String(), err)
				errStr = errStr + "\n" + err.Error()
				zedcloud.ZedCloudFailure(ifname,
					metricsUrl, 1024, 0)
			} else {
				// Record how much we downloaded
				size := int64(0)
				info, err := os.Stat(locFilename)
				if err != nil {
					log.Error(err)
				} else {
					size = info.Size()
				}
				zedcloud.ZedCloudSuccess(ifname,
					metricsUrl, 1024, size)
				handleSyncOpResponse(ctx, config, status,
					locFilename, key, "")
				return
			}
		default:
			errStr = "unsupported transport method " + dsCtx.TransportMethod
		}
	}
	log.Errorf("All source IP addresses failed. All errors:%s\n", errStr)
	handleSyncOpResponse(ctx, config, status, locFilename,
		key, errStr)
}

// DownloadURL format : http://<serverURL>/dpath/filename
func getServerUrl(dsCtx *types.DatastoreContext) (string, error) {
	u, err := url.Parse(dsCtx.DownloadURL)
	if err != nil {
		log.Errorf("URL Parsing failed: %s\n", err)
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

func handleSyncOpResponse(ctx *downloaderContext, config types.DownloaderConfig,
	status *types.DownloaderStatus, locFilename string,
	key string, errStr string) {

	if status.ObjType == "" {
		log.Fatalf("handleSyncOpResponse: No ObjType for %s\n",
			status.Safename)
	}
	locDirname := types.DownloadDirname + "/" + status.ObjType
	if errStr != "" {
		// Delete file
		doDelete(ctx, key, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errStr
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		publishDownloaderStatus(ctx, status)
		log.Errorf("handleSyncOpResponse failed for %s, <%s>\n",
			status.Name, errStr)
		return
	}

	info, err := os.Stat(locFilename)
	if err != nil {
		log.Errorf("handleSyncOpResponse Stat failed for %s <%s>\n",
			status.Name, err)
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

	// Update globalStatus and status
	unreserveSpace(ctx, status)

	log.Infof("handleSyncOpResponse successful <%s> <%s>\n",
		config.Name, locFilename)
	// We do not clear any status.RetryCount, LastErr, etc. The caller
	// should look at State == DOWNLOADED to determine it is done.

	status.ModTime = time.Now()
	status.PendingAdd = false
	status.State = types.DOWNLOADED
	status.Progress = 100 // Just in case
	publishDownloaderStatus(ctx, status)
}

// Handles both create and modify events
func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	status := cast.CastDeviceNetworkStatus(statusArg)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(ctx.deviceNetworkStatus, status) {
		log.Infof("handleDNSModify unchanged\n")
		return
	}
	ctx.deviceNetworkStatus = status
	log.Infof("handleDNSModify %d free management ports addresses; %d any\n",
		types.CountLocalAddrFreeNoLinkLocal(ctx.deviceNetworkStatus),
		types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus))

	log.Infof("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	log.Infof("handleDNSDelete for %s\n", key)
	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Infof("handleDNSDelete done for %s\n", key)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.GlobalConfig
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		if gcp.DownloadGCTime != 0 {
			downloadGCTime = time.Duration(gcp.DownloadGCTime) * time.Second
		}
		if gcp.DownloadRetryTime != 0 {
			downloadRetryTime = time.Duration(gcp.DownloadRetryTime) * time.Second
		}
	}
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
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
	dst := cast.CastDatastoreConfig(cfg)
	return &dst, ""
}
