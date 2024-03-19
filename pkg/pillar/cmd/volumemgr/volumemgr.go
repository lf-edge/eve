// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of a collection of VolumeConfig structs
// from zedmanager and baseosmgr. Publish the status as VolumeStatus

package volumemgr

import (
	"flag"
	"fmt"
	"time"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
	"github.com/sirupsen/logrus"
)

const (
	agentName              = "volumemgr"
	runDirname             = "/run/" + agentName
	ciDirname              = runDirname + "/cloudinit"    // For cloud-init volumes
	volumeEncryptedDirName = types.VolumeEncryptedDirName // We store encrypted VM and OCI volumes here
	volumeClearDirName     = types.VolumeClearDirName     // We store un-encrypted VM and OCI volumes here
	// Time limits for event loop handlers
	errorTime     = 3 * time.Minute
	warningTime   = 40 * time.Second
	casClientType = "containerd"

	blankVolumeFormat = zconfig.Format_RAW // format of blank volume TODO: make configurable
)

// Set from Makefile
var Version = "No version specified"

var volumeFormat = make(map[string]zconfig.Format)

type volumemgrContext struct {
	agentbase.AgentBase
	ps                *pubsub.PubSub
	subGlobalConfig   pubsub.Subscription
	subZedAgentStatus pubsub.Subscription

	pubDownloaderConfig  pubsub.Publication
	subDownloaderStatus  pubsub.Subscription
	pubVerifyImageConfig pubsub.Publication
	subVerifyImageStatus pubsub.Subscription

	subResolveStatus        pubsub.Subscription
	pubResolveConfig        pubsub.Publication
	subContentTreeConfig    pubsub.Subscription
	pubContentTreeStatus    pubsub.Publication
	subVolumeConfig         pubsub.Subscription
	pubVolumeStatus         pubsub.Publication
	subVolumeRefConfig      pubsub.Subscription
	pubVolumeRefStatus      pubsub.Publication
	pubContentTreeToHash    pubsub.Publication
	pubBlobStatus           pubsub.Publication
	pubDiskMetric           pubsub.Publication
	pubAppDiskMetric        pubsub.Publication
	subDatastoreConfig      pubsub.Subscription
	subZVolStatus           pubsub.Subscription
	pubVolumeCreatePending  pubsub.Publication
	subVolumesSnapConfig    pubsub.Subscription
	pubVolumesSnapStatus    pubsub.Publication
	diskMetricsTickerHandle interface{}
	gc                      *time.Ticker
	deferDelete             *time.Ticker

	worker worker.Worker // For background work

	verifierRestarted    bool // Wait for verifier to restart
	contentTreeRestarted bool // Wait to receive all contentTree after restart
	usingConfig          bool // From zedagent
	gcRunning            bool
	initGced             bool // Will be marked true after initObjects are garbage collected

	globalConfig       *types.ConfigItemValueMap
	GCInitialized      bool
	vdiskGCTime        uint32 // In seconds; XXX delete when OldVolumeStatus is deleted
	deferContentDelete uint32 // In seconds
	// Common CAS client which can be used by multiple routines.
	// There is no shared data so its safe to be used by multiple goroutines
	casClient cas.CAS

	volumeConfigCreateDeferredMap map[string]*types.VolumeConfig

	persistType types.PersistType

	capabilities *types.Capabilities

	// cli options
	versionPtr *bool

	// kube mode
	hvTypeKube bool
}

func (ctxPtr *volumemgrContext) lookupVolumeStatusByUUID(id string) *types.VolumeStatus {
	sub := ctxPtr.pubVolumeStatus
	items := sub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.VolumeID.String() == id {
			return &status
		}
	}
	return nil
}

func (ctxPtr *volumemgrContext) GetCasClient() cas.CAS {
	return ctxPtr.casClient
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctxPtr *volumemgrContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctxPtr.versionPtr = flagSet.Bool("v", false, "Version")
}

var logger *logrus.Logger
var log *base.LogObject

// Run - the main function invoked by zedbox
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	// These settings can be overridden by GlobalConfig
	ctx := volumemgrContext{
		ps:                 ps,
		vdiskGCTime:        3600,
		deferContentDelete: 0,
		globalConfig:       types.DefaultConfigItemValueMap(),
		persistType:        vault.ReadPersistType(),
		hvTypeKube:         base.IsHVTypeKube(),
	}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithArguments(arguments))

	if *ctx.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}
	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait until we have been onboarded aka know our own UUID, but we don't use the UUID
	err := utils.WaitForOnboarded(ps, log, agentName, warningTime, errorTime)
	if err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed onboarded")

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	// Look for capabilities
	subCapabilities, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.Capabilities{},
		Activate:      true,
		Ctx:           &ctx,
		CreateHandler: handleCapabilitiesCreate,
		ModifyHandler: handleCapabilitiesModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	// wait for capabilities
	for ctx.capabilities == nil {
		log.Functionf("waiting for Capabilities")
		select {
		case change := <-subCapabilities.MsgChan():
			subCapabilities.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	// we do not expect any changes in capabilities
	if err := subCapabilities.Close(); err != nil {
		log.Errorf("cannot close subCapabilities: %v", err)
	}
	log.Functionf("processed Capabilities")

	if err := utils.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed Vault Status")

	if err := utils.WaitForUserContainerd(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("user containerd ready")

	// wait for kubernetes up if in kube mode, if gets error, move on
	if ctx.hvTypeKube {
		log.Noticef("volumemgr run: wait for kubernetes")
		err := kubeapi.WaitForKubernetes(agentName, ps, stillRunning)
		if err != nil {
			log.Errorf("volumemgr run: wait for kubernetes error %v", err)
		} else {
			log.Noticef("volumemgr run: kubernetes node ready, longhorn ready")
		}

	}

	if ctx.persistType == types.PersistZFS {
		if isZvol, _ := zfs.IsDatasetTypeZvol(types.SealedDataset); isZvol {
			// This code is called only on kubevirt eve
			initializeDirs()
			populateExistingVolumesFormatPVC(&ctx)
		} else {
			// create datasets for volumes
			initializeDatasets()
			// Iterate over volume datasets and prepares map of
			// volume's content format with the volume key
			populateExistingVolumesFormatDatasets(&ctx, types.VolumeEncryptedZFSDataset)
			populateExistingVolumesFormatDatasets(&ctx, types.VolumeClearZFSDataset)
		}
	} else {
		// create the directories
		initializeDirs()
	}
	// Iterate over volume directory and prepares map of
	// volume's content format with the volume key
	populateExistingVolumesFormatObjects(&ctx, volumeEncryptedDirName)
	populateExistingVolumesFormatObjects(&ctx, volumeClearDirName)

	// Create the background worker
	ctx.worker = worker.NewPool(log, &ctx, 20, map[string]worker.Handler{
		workCreate:  {Request: volumeWorker, Response: processVolumeWorkResult},
		workIngest:  {Request: casIngestWorker, Response: processCasIngestWorkResult},
		workPrepare: {Request: volumePrepareWorker, Response: processVolumePrepareResult},
	})

	// Set up our publications before the subscriptions so ctx is set
	pubDownloaderConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DownloaderConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubDownloaderConfig = pubDownloaderConfig

	pubVerifyImageConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VerifyImageConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVerifyImageConfig = pubVerifyImageConfig

	pubResolveConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ResolveConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubResolveConfig = pubResolveConfig

	pubContentTreeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ContentTreeStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubContentTreeStatus = pubContentTreeStatus

	pubVolumeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumeStatus = pubVolumeStatus

	pubVolumeRefStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeRefStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumeRefStatus = pubVolumeRefStatus

	pubContentTreeToHash, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		Persistent: true,
		TopicType:  types.AppAndImageToHash{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubContentTreeToHash = pubContentTreeToHash

	pubBlobStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.BlobStatus{},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubBlobStatus = pubBlobStatus

	pubDiskMetric, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DiskMetric{},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubDiskMetric = pubDiskMetric

	pubAppDiskMetric, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.AppDiskMetric{},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppDiskMetric = pubAppDiskMetric

	// Look for global config such as log levels
	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleZedAgentStatusCreate,
		ModifyHandler: handleZedAgentStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	// Look for DownloaderStatus from downloader
	subDownloaderStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "downloader",
		MyAgentName:   agentName,
		TopicImpl:     types.DownloaderStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleDownloaderStatusCreate,
		ModifyHandler: handleDownloaderStatusModify,
		DeleteHandler: handleDownloaderStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subDownloaderStatus = subDownloaderStatus
	subDownloaderStatus.Activate()

	// Look for VerifyImageStatus from verifier
	subVerifyImageStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "verifier",
		MyAgentName:    agentName,
		TopicImpl:      types.VerifyImageStatus{},
		Activate:       false,
		Ctx:            &ctx,
		CreateHandler:  handleVerifyImageStatusCreate,
		ModifyHandler:  handleVerifyImageStatusModify,
		DeleteHandler:  handleVerifyImageStatusDelete,
		RestartHandler: handleVerifierRestarted,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVerifyImageStatus = subVerifyImageStatus
	subVerifyImageStatus.Activate()

	// Look for ResolveStatus from downloader
	subResolveStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "downloader",
		MyAgentName:   agentName,
		TopicImpl:     types.ResolveStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleResolveStatusCreate,
		ModifyHandler: handleResolveStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subResolveStatus = subResolveStatus
	subResolveStatus.Activate()

	subContentTreeConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler:  handleContentTreeCreate,
		ModifyHandler:  handleContentTreeModify,
		DeleteHandler:  handleContentTreeDelete,
		RestartHandler: handleContentTreeRestart,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
		AgentName:      "zedagent",
		MyAgentName:    agentName,
		TopicImpl:      types.ContentTreeConfig{},
		Ctx:            &ctx,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subContentTreeConfig = subContentTreeConfig
	subContentTreeConfig.Activate()

	ctx.volumeConfigCreateDeferredMap = make(map[string]*types.VolumeConfig)

	subVolumeConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler:  handleVolumeCreate,
		ModifyHandler:  handleVolumeModify,
		DeleteHandler:  handleVolumeDelete,
		RestartHandler: handleVolumeRestart,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
		AgentName:      "zedagent",
		MyAgentName:    agentName,
		TopicImpl:      types.VolumeConfig{},
		Ctx:            &ctx,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVolumeConfig = subVolumeConfig
	subVolumeConfig.Activate()

	subVolumeRefConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleVolumeRefCreate,
		ModifyHandler: handleVolumeRefModify,
		DeleteHandler: handleVolumeRefDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "zedmanager",
		MyAgentName:   agentName,
		TopicImpl:     types.VolumeRefConfig{},
		Ctx:           &ctx,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVolumeRefConfig = subVolumeRefConfig
	subVolumeRefConfig.Activate()

	subDatastoreConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleDatastoreConfigCreate,
		ModifyHandler: handleDatastoreConfigModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "zedagent",
		TopicImpl:     types.DatastoreConfig{},
		Ctx:           &ctx,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subDatastoreConfig = subDatastoreConfig
	subDatastoreConfig.Activate()

	subZVolStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleZVolStatusCreate,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "zfsmanager",
		TopicImpl:     types.ZVolStatus{},
		Ctx:           &ctx,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subZVolStatus = subZVolStatus
	subZVolStatus.Activate()

	subVolumesSnapshotConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleVolumesSnapshotConfigCreate,
		ModifyHandler: handleVolumesSnapshotConfigModify,
		DeleteHandler: handleVolumesSnapshotConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "zedmanager",
		TopicImpl:     types.VolumesSnapshotConfig{},
		Ctx:           &ctx,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVolumesSnapConfig = subVolumesSnapshotConfig
	subVolumesSnapshotConfig.Activate()

	pubVolumesSnapshotStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.VolumesSnapshotStatus{},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumesSnapStatus = pubVolumesSnapshotStatus

	if ctx.casClient, err = cas.NewCAS(casClientType); err != nil {
		err = fmt.Errorf("Run: exception while initializing CAS client: %s", err.Error())
		log.Fatal(err)
	}

	//casClient which is commonly used across volumemgr will be closed when volumemgr exits.
	defer ctx.casClient.CloseClient()

	pubVolumeCreatePending, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.VolumeCreatePending{},
			Persistent: true,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumeCreatePending = pubVolumeCreatePending

	// iterate over saved VolumeCreatePending and remove remaining volumes
	gcPendingCreateVolume(&ctx)

	populateInitBlobStatus(&ctx)

	// First we process the verifierStatus to avoid triggering a download
	// of an image we already have in place.
	// Also we wait for zedagent to send all contentTreeConfig so that we can GC all blobs which
	// doesn't have ConfigTree ref
	for !(ctx.verifierRestarted && ctx.contentTreeRestarted) {
		log.Warnf("Subject to watchdog. Waiting for verifierRestarted")

		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subVerifyImageStatus.MsgChan():
			subVerifyImageStatus.ProcessChange(change)

		case change := <-ctx.subContentTreeConfig.MsgChan():
			ctx.subContentTreeConfig.ProcessChange(change)

		case res := <-ctx.worker.MsgChan():
			res.Process(&ctx, true)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("Handling all inputs. Updating .touch file")

	// We will cleanup zero RefCount volumes which were present at boot
	// after a while.
	// We run timer 10 times more often than the limit on LastUse
	// We start the timer once ZedAgentStatus tells us we are receiving
	// config (or using a saved config) to avoid removing volumes when
	// they might become used.
	// XXX should we instead do this immediately when ZedAgentStatus provides
	// the update?
	duration := time.Duration(ctx.vdiskGCTime / 10)
	ctx.gc = time.NewTicker(duration * time.Second)
	ctx.gc.Stop()

	// Create ticker; set when we get the global config
	ctx.deferDelete = time.NewTicker(time.Hour)
	ctx.deferDelete.Stop()

	// start the metrics reporting task
	diskMetricsTickerHandle := make(chan interface{})
	log.Functionf("Creating %s at %s", "diskMetricsTimerTask", agentlog.GetMyStack())

	go diskMetricsTimerTask(&ctx, diskMetricsTickerHandle)
	ctx.diskMetricsTickerHandle = <-diskMetricsTickerHandle

	for {
		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)

		case change := <-subZedAgentStatus.MsgChan():
			subZedAgentStatus.ProcessChange(change)

		case change := <-subDownloaderStatus.MsgChan():
			subDownloaderStatus.ProcessChange(change)

		case change := <-subVerifyImageStatus.MsgChan():
			subVerifyImageStatus.ProcessChange(change)

		case change := <-subResolveStatus.MsgChan():
			ctx.subResolveStatus.ProcessChange(change)

		case change := <-ctx.subContentTreeConfig.MsgChan():
			ctx.subContentTreeConfig.ProcessChange(change)

		case change := <-ctx.subVolumeConfig.MsgChan():
			ctx.subVolumeConfig.ProcessChange(change)

		case change := <-ctx.subVolumeRefConfig.MsgChan():
			ctx.subVolumeRefConfig.ProcessChange(change)

		case change := <-ctx.subDatastoreConfig.MsgChan():
			ctx.subDatastoreConfig.ProcessChange(change)

		case change := <-ctx.subZVolStatus.MsgChan():
			ctx.subZVolStatus.ProcessChange(change)

		case change := <-ctx.subVolumesSnapConfig.MsgChan():
			ctx.subVolumesSnapConfig.ProcessChange(change)

		case <-ctx.gc.C:
			start := time.Now()
			gcObjects(&ctx, volumeEncryptedDirName)
			gcObjects(&ctx, volumeClearDirName)
			if ctx.persistType == types.PersistZFS {
				gcDatasets(&ctx, types.VolumeEncryptedZFSDataset)
				gcDatasets(&ctx, types.VolumeClearZFSDataset)
			}
			if !ctx.initGced {
				gcUnusedInitObjects(&ctx)
				ctx.initGced = true
			}
			ps.CheckMaxTimeTopic(agentName, "gc", start,
				warningTime, errorTime)

		case <-ctx.deferDelete.C:
			start := time.Now()
			checkDeferredDelete(&ctx)
			ps.CheckMaxTimeTopic(agentName, "deferDelete", start,
				warningTime, errorTime)

		case res := <-ctx.worker.MsgChan():
			res.Process(&ctx, true)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

// gcUnusedInitObjects this method will garbage collect all unused resource during init
func gcUnusedInitObjects(ctx *volumemgrContext) {
	log.Functionf("gcUnusedInitObjects")
	gcBlobStatus(ctx)
	gcVerifyImageConfig(ctx)
	gcImagesFromCAS(ctx)
}

func handleVerifierRestarted(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*volumemgrContext)

	log.Functionf("handleVerifierRestarted(%d)", restartCounter)
	if restartCounter != 0 {
		ctx.verifierRestarted = true
	}
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*volumemgrContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		maybeUpdateConfigItems(ctx, gcp)
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*volumemgrContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

func handleZedAgentStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*volumemgrContext)
	status := statusArg.(types.ZedAgentStatus)
	if status.MaintenanceMode {
		// Do not trigger GC
		return
	}
	switch status.ConfigGetStatus {
	case types.ConfigGetSuccess, types.ConfigGetReadSaved:
		ctx.usingConfig = true
		duration := time.Duration(ctx.vdiskGCTime / 10)
		ctx.gc = time.NewTicker(duration * time.Second)
	}
}

func maybeUpdateConfigItems(ctx *volumemgrContext, newConfigItemValueMap *types.ConfigItemValueMap) {
	log.Functionf("maybeUpdateConfigItems")
	oldConfigItemValueMap := ctx.globalConfig

	if newConfigItemValueMap.GlobalValueInt(types.VdiskGCTime) != 0 &&
		newConfigItemValueMap.GlobalValueInt(types.VdiskGCTime) !=
			oldConfigItemValueMap.GlobalValueInt(types.VdiskGCTime) {
		log.Functionf("maybeUpdateConfigItems: Updating vdiskGCTime from %d to %d",
			oldConfigItemValueMap.GlobalValueInt(types.VdiskGCTime),
			newConfigItemValueMap.GlobalValueInt(types.VdiskGCTime))
		ctx.vdiskGCTime = newConfigItemValueMap.GlobalValueInt(types.VdiskGCTime)
	}

	if newConfigItemValueMap.GlobalValueInt(types.DiskScanMetricInterval) != 0 &&
		newConfigItemValueMap.GlobalValueInt(types.DiskScanMetricInterval) !=
			oldConfigItemValueMap.GlobalValueInt(types.DiskScanMetricInterval) {
		log.Functionf("maybeUpdateConfigItems: Updating DiskScanMetricInterval from %d to %d",
			oldConfigItemValueMap.GlobalValueInt(types.DiskScanMetricInterval),
			newConfigItemValueMap.GlobalValueInt(types.DiskScanMetricInterval))
		if ctx.diskMetricsTickerHandle == nil {
			log.Warnf("maybeUpdateConfigItems: no diskMetricsTickerHandle yet")
		} else {
			diskMetricInterval := time.Duration(newConfigItemValueMap.
				GlobalValueInt(types.DiskScanMetricInterval)) * time.Second
			max := float64(diskMetricInterval)
			min := max * 0.3
			flextimer.UpdateRangeTicker(ctx.diskMetricsTickerHandle,
				time.Duration(min), time.Duration(max))
			// Force an immediate timeout since timer could have decreased
			flextimer.TickNow(ctx.diskMetricsTickerHandle)
		}
	}
	newDC := newConfigItemValueMap.GlobalValueInt(types.DeferContentDelete)
	oldDC := oldConfigItemValueMap.GlobalValueInt(types.DeferContentDelete)
	if newDC != oldDC {
		log.Noticef("maybeUpdateConfigItems: Updating deferContentDelete from %d to %d",
			oldDC, newDC)
		ctx.deferContentDelete = newDC
		if newDC == 0 {
			ctx.deferDelete.Stop()
		} else {
			// Run ten times as often as lifetime
			duration := time.Duration(ctx.deferContentDelete / 10)
			ctx.deferDelete = time.NewTicker(duration * time.Second)
		}
	}
}

func handleCapabilitiesCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleCapabilitiesImpl(ctxArg, key, statusArg)
}

func handleCapabilitiesModify(ctxArg interface{}, key string,
	statusArg, _ interface{}) {
	handleCapabilitiesImpl(ctxArg, key, statusArg)
}

func handleCapabilitiesImpl(ctxArg interface{}, _ string,
	statusArg interface{}) {

	ctx := ctxArg.(*volumemgrContext)
	status, ok := statusArg.(types.Capabilities)
	if !ok {
		log.Fatalf("Unexpected type from subCapabilities: %T", statusArg)
	}
	ctx.capabilities = &status
}

// GetCapabilities returns stored capabilities
func (ctxPtr *volumemgrContext) GetCapabilities() *types.Capabilities {
	return ctxPtr.capabilities
}
