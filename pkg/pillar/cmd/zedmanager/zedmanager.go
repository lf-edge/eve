// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Get AppInstanceConfig from zedagent, drive config to VolumeMgr,
// IdentityMgr, and Zedrouter. Collect status from those services and make
// the combined AppInstanceStatus available to zedagent.

package zedmanager

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/objtonum"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "zedmanager"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// Version can be set from Makefile
var Version = "No version specified"

// State used by handlers
type zedmanagerContext struct {
	agentbase.AgentBase
	subAppInstanceConfig      pubsub.Subscription
	subAppInstanceStatus      pubsub.Subscription // zedmanager both publishes and subscribes to AppInstanceStatus
	subLocalAppInstanceConfig pubsub.Subscription
	pubLocalAppInstanceConfig pubsub.Publication
	pubAppInstanceStatus      pubsub.Publication
	pubAppInstanceSummary     pubsub.Publication
	pubVolumeRefConfig        pubsub.Publication
	subVolumeRefStatus        pubsub.Subscription
	pubAppNetworkConfig       pubsub.Publication
	subAppNetworkStatus       pubsub.Subscription
	pubDomainConfig           pubsub.Publication
	subDomainStatus           pubsub.Subscription
	subGlobalConfig           pubsub.Subscription
	subHostMemory             pubsub.Subscription
	subZedAgentStatus         pubsub.Subscription
	pubVolumesSnapConfig      pubsub.Publication
	subVolumesSnapStatus      pubsub.Subscription
	subAssignableAdapters     pubsub.Subscription
	globalConfig              *types.ConfigItemValueMap
	appToPurgeCounterMap      objtonum.Map
	GCInitialized             bool
	checkFreedResources       bool // Set when app instance has !Activated
	currentProfile            string
	currentTotalMemoryMB      uint64
	// The time from which the configured applications delays should be counted
	delayBaseTime time.Time
	// cli options
	versionPtr *bool
	// hypervisorPtr is the name of the hypervisor to use
	hypervisorPtr      *string
	assignableAdapters *types.AssignableAdapters
	// Is it kubevirt eve
	hvTypeKube bool
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctx *zedmanagerContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctx.versionPtr = flagSet.Bool("v", false, "Version")
	allHypervisors, enabledHypervisors := hypervisor.GetAvailableHypervisors()
	ctx.hypervisorPtr = flagSet.String("h", enabledHypervisors[0], fmt.Sprintf("Current hypervisor %+q", allHypervisors))
}

var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	// Any state needed by handler functions
	ctx := zedmanagerContext{
		globalConfig: types.DefaultConfigItemValueMap(),
		hvTypeKube:   base.IsHVTypeKube(),
	}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithArguments(arguments))

	ctx.assignableAdapters = &types.AssignableAdapters{}

	if *ctx.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait until we have been onboarded aka know our own UUID, but we don't use the UUID
	err := wait.WaitForOnboarded(ps, log, agentName, warningTime, errorTime)
	if err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed onboarded")

	// Create publish for SnapshotConfig
	pubSnapshotConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumesSnapshotConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumesSnapConfig = pubSnapshotConfig
	pubSnapshotConfig.ClearRestarted()

	// Create publish before subscribing and activating subscriptions
	pubAppInstanceStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppInstanceStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppInstanceStatus = pubAppInstanceStatus
	pubAppInstanceStatus.ClearRestarted()

	pubAppInstanceSummary, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppInstanceSummary{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppInstanceSummary = pubAppInstanceSummary
	pubAppInstanceSummary.ClearRestarted()

	pubVolumeRefConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeRefConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumeRefConfig = pubVolumeRefConfig

	pubAppNetworkConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppNetworkConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppNetworkConfig = pubAppNetworkConfig
	pubAppNetworkConfig.ClearRestarted()

	pubDomainConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DomainConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubDomainConfig = pubDomainConfig
	pubDomainConfig.ClearRestarted()

	// Persist purge counter for each application.
	mapPublisher, err := objtonum.NewObjNumPublisher(
		log, ps, agentName, true, &types.UuidToNum{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.appToPurgeCounterMap = objtonum.NewPublishedMap(
		log, mapPublisher, "purgeCmdCounter", objtonum.AllKeys)

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

	// Get AppInstanceConfig from zedagent
	subAppInstanceConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "zedagent",
		MyAgentName:    agentName,
		TopicImpl:      types.AppInstanceConfig{},
		Activate:       false,
		Ctx:            &ctx,
		CreateHandler:  handleCreate,
		ModifyHandler:  handleModify,
		DeleteHandler:  handleAppInstanceConfigDelete,
		RestartHandler: handleConfigRestart,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppInstanceConfig = subAppInstanceConfig
	subAppInstanceConfig.Activate()

	// Get AppInstanceConfig from zedmanager itself
	subLocalAppInstanceConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     agentName,
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceConfig{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleLocalAppInstanceConfigCreate,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subLocalAppInstanceConfig = subLocalAppInstanceConfig
	subLocalAppInstanceConfig.Activate()

	pubLocalAppInstanceConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppInstanceConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubLocalAppInstanceConfig = pubLocalAppInstanceConfig
	pubLocalAppInstanceConfig.ClearRestarted()

	// Look for VolumeRefStatus from volumemgr
	subVolumeRefStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VolumeRefStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleVolumeRefStatusCreate,
		ModifyHandler: handleVolumeRefStatusModify,
		DeleteHandler: handleVolumeRefStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVolumeRefStatus = subVolumeRefStatus
	subVolumeRefStatus.Activate()

	// Get AppNetworkStatus from zedrouter
	subAppNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "zedrouter",
		MyAgentName:    agentName,
		TopicImpl:      types.AppNetworkStatus{},
		Activate:       false,
		Ctx:            &ctx,
		CreateHandler:  handleAppNetworkStatusCreate,
		ModifyHandler:  handleAppNetworkStatusModify,
		DeleteHandler:  handleAppNetworkStatusDelete,
		RestartHandler: handleZedrouterRestarted,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppNetworkStatus = subAppNetworkStatus
	subAppNetworkStatus.Activate()

	// Get DomainStatus from domainmgr
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.DomainStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleDomainStatusCreate,
		ModifyHandler: handleDomainStatusModify,
		DeleteHandler: handleDomainStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	subHostMemory, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.HostMemory{},
		Activate:      true,
		Ctx:           &ctx,
		CreateHandler: handleHostMemoryCreate,
		ModifyHandler: handleHostMemoryModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subHostMemory = subHostMemory

	// subscribe to zedagent status events
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

	// subscribe to zedmanager(myself) to get AppInstancestatus events
	subAppInstanceStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedmanager",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleAppInstanceStatusCreate,
		ModifyHandler: handleAppInstanceStatusModify,
		DeleteHandler: handleAppInstanceStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppInstanceStatus = subAppInstanceStatus
	subAppInstanceStatus.Activate()

	subVolumesSnapshotStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VolumesSnapshotStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleVolumesSnapshotStatusCreate,
		ModifyHandler: handleVolumesSnapshotStatusModify,
		DeleteHandler: handleVolumesSnapshotStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVolumesSnapStatus = subVolumesSnapshotStatus
	_ = subVolumesSnapshotStatus.Activate()

	ctx.subAssignableAdapters, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.AssignableAdapters{},
		Activate:      true,
		Ctx:           &ctx,
		CreateHandler: handleAACreate,
		ModifyHandler: handleAAModify,
		DeleteHandler: handleAADelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

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

	//use timer for free resource checker to run it after stabilising of other changes
	freeResourceChecker := flextimer.NewRangeTicker(5*time.Second, 10*time.Second)

	// The ticker that triggers a check for the applications in the START_DELAYED state
	delayedStartTicker := time.NewTicker(1 * time.Second)

	log.Functionf("Handling all inputs")
	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subVolumeRefStatus.MsgChan():
			subVolumeRefStatus.ProcessChange(change)

		case change := <-subAppNetworkStatus.MsgChan():
			subAppNetworkStatus.ProcessChange(change)

		case change := <-subDomainStatus.MsgChan():
			subDomainStatus.ProcessChange(change)

		case change := <-subHostMemory.MsgChan():
			subHostMemory.ProcessChange(change)

		case change := <-subAppInstanceConfig.MsgChan():
			subAppInstanceConfig.ProcessChange(change)

		case change := <-subLocalAppInstanceConfig.MsgChan():
			subLocalAppInstanceConfig.ProcessChange(change)

		case change := <-subZedAgentStatus.MsgChan():
			subZedAgentStatus.ProcessChange(change)

		case change := <-subAppInstanceStatus.MsgChan():
			subAppInstanceStatus.ProcessChange(change)

		case change := <-subVolumesSnapshotStatus.MsgChan():
			subVolumesSnapshotStatus.ProcessChange(change)

		case change := <-ctx.subAssignableAdapters.MsgChan():
			ctx.subAssignableAdapters.ProcessChange(change)

		case <-freeResourceChecker.C:
			// Did any update above make more resources available for
			// other app instances?
			if ctx.checkFreedResources {
				start := time.Now()
				checkRetry(&ctx)
				ps.CheckMaxTimeTopic(agentName, "checkRetry", start,
					warningTime, errorTime)
				ctx.checkFreedResources = false
			}

		case <-delayedStartTicker.C:
			checkDelayedStartApps(&ctx)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleLocalAppInstanceConfigCreate(ctx interface{}, key string, config interface{}) {
	log.Noticef("handleLocalAppInstanceConfigCreate(%s)", key)
	zedmanagerCtx := ctx.(*zedmanagerContext)
	localConfig := config.(types.AppInstanceConfig)
	oldConfig := lookupAppInstanceConfig(zedmanagerCtx, localConfig.Key(), false)
	if oldConfig == nil {
		log.Fatalf("handleLocalAppInstanceConfigCreate: no regular AppInstanceConfig for %s", key)
	}
	handleModify(ctx, key, localConfig, *oldConfig)
}

func restoreAvailableSnapshots(aiStatus *types.AppInstanceStatus) {
	// List all the directories that are present in snapshots directory
	// and restore the snapshot status for each of them
	snapDir := types.SnapshotsDirname
	dirEntries, err := os.ReadDir(snapDir)
	if err != nil {
		log.Warnf("No %s directory, nothing to restore", snapDir)
		return
	}
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {
			continue
		}
		snapshotID := dirEntry.Name()
		// Figure out the ID of the app that this snapshot belongs to
		aiConfig := deserializeAppInstanceConfigFromSnapshot(snapshotID)
		if aiConfig == nil {
			log.Warnf("cannot deserialize config for snapshot %s", snapshotID)
			continue
		}
		if aiConfig.UUIDandVersion.UUID != aiStatus.UUIDandVersion.UUID {
			// This snapshot is not for this app
			continue
		}
		// Get the metadata for this snapshot
		var availableSnapshot *types.SnapshotInstanceStatus
		availableSnapshot, err = deserializeSnapshotInstanceStatus(snapshotID)
		if err != nil {
			log.Errorf("restoreAvailableSnapshots: %s", err)
			continue
		}
		log.Noticef("restoreAvailableSnapshots: %s", availableSnapshot.Snapshot.SnapshotID)
		// add to the list of the available snapshots
		aiStatus.SnapStatus.AvailableSnapshots = append(aiStatus.SnapStatus.AvailableSnapshots, *availableSnapshot)
	}
}

func checkRetry(ctxPtr *zedmanagerContext) {
	log.Noticef("checkRetry")
	items := ctxPtr.pubAppInstanceStatus.GetAll()
	for _, st := range items {
		status := st.(types.AppInstanceStatus)
		if !status.MissingMemory {
			continue
		}
		config := lookupAppInstanceConfig(ctxPtr, status.Key(), true)
		if config == nil {
			log.Noticef("checkRetry: %s waiting for memory but no config",
				status.Key())
			continue
		}
		if !status.IsErrorSource(types.AppInstanceConfig{}) {
			log.Noticef("checkRetry: %s waiting for memory but no error",
				status.Key())
			continue
		}
		status.ClearErrorWithSource()
		status.MissingMemory = false

		log.Noticef("checkRetry: %s waiting for memory", status.Key())
		handleModify(ctxPtr, status.Key(), *config, *config)
	}
}

// Handle the applications in the START_DELAY state ready to be started.
func checkDelayedStartApps(ctx *zedmanagerContext) {
	configs := ctx.subAppInstanceConfig.GetAll()
	for _, c := range configs {
		config := c.(types.AppInstanceConfig)
		if localConfig := lookupLocalAppInstanceConfig(ctx, config.Key()); localConfig != nil {
			config = *localConfig
		}
		status := lookupAppInstanceStatus(ctx, config.Key())
		// Is the application in the delayed state and ready to be started?
		if status != nil && status.State == types.START_DELAYED && status.StartTime.Before(time.Now()) {
			// Change the state immediately, so we do not enter here twice
			status.State = types.INSTALLED
			doUpdate(ctx, config, status)
			publishAppInstanceStatus(ctx, status)
		}
	}
}

func handleAA(ctx *zedmanagerContext, status types.AssignableAdapters, key string) {
	log.Functionf("handleAA(%s)", status.Key())
	if key != "global" {
		log.Functionf("handleAA: ignoring %s", key)
		return
	}
	log.Functionf("handleAA() %+v", status)
	*ctx.assignableAdapters = status
	log.Functionf("handleAA() done")
}

func handleAACreate(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.AssignableAdapters)
	log.Functionf("handleAACreate(%s)", status.Key())
	handleAA(ctx, status, key)
}

func handleAAModify(ctxArg interface{}, key string, statusArg interface{}, oldStatusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.AssignableAdapters)
	log.Functionf("handleAAModify(%s)", status.Key())
	handleAA(ctx, status, key)
}

func handleAADelete(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.AssignableAdapters)
	log.Functionf("handleAADelete(%s)", status.Key())
	handleAA(ctx, status, key)
}

// After zedagent has waited for its config and set restarted for
// AppInstanceConfig (which triggers this callback) we propagate a sequence of
// restarts so that the agents don't do extra work.
// We propagate a sequence of restarted from the zedmanager config
// to identitymgr, then from identitymgr to zedrouter,
// and finally from zedrouter to domainmgr.
// XXX is that sequence still needed with volumemgr in place?
// Need EIDs before zedrouter ...
func handleConfigRestart(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*zedmanagerContext)
	log.Functionf("handleConfigRestart(%d)", restartCounter)
	if restartCounter != 0 {
		ctx.pubAppNetworkConfig.SignalRestarted()
	}
}

func handleIdentitymgrRestarted(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Functionf("handleIdentitymgrRestarted(%d)", restartCounter)
	if restartCounter != 0 {
		ctx.pubAppNetworkConfig.SignalRestarted()
	}
}

func handleZedrouterRestarted(ctxArg interface{}, restartCounter int) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Functionf("handleZedrouterRestarted(%d)", restartCounter)
	if restartCounter != 0 {
		ctx.pubDomainConfig.SignalRestarted()
	}
}

// handleAppInstanceStatusCreate - Handle AIS create. Publish AppStatusSummary to ledmanager
func handleAppInstanceStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	publishAppInstanceSummary(ctx)
}

// handleAppInstanceStatusModify - Handle AIS modify. Publish AppStatusSummary to ledmanager
func handleAppInstanceStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	publishAppInstanceSummary(ctx)
}

// handleAppInstanceStatusDelete - Handle AIS delete. Publish AppStatusSummary to ledmanager
func handleAppInstanceStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	publishAppInstanceSummary(ctx)
}

func publishAppInstanceSummary(ctxPtr *zedmanagerContext) {

	summary := types.AppInstanceSummary{
		TotalStarting: 0,
		TotalRunning:  0,
		TotalStopping: 0,
		TotalError:    0,
	}
	items := ctxPtr.pubAppInstanceStatus.GetAll()
	for _, st := range items {
		status := st.(types.AppInstanceStatus)
		effectiveActivate := false
		config := lookupAppInstanceConfig(ctxPtr, status.Key(), true)
		if config != nil {
			effectiveActivate = effectiveActivateCurrentProfile(*config, ctxPtr.currentProfile)
		}
		// Only condition we did not count is EffectiveActive = true and Activated = false.
		// That means customer either halted his app or did not activate it yet.
		if len(status.Error) > 0 {
			summary.TotalError++
		} else if effectiveActivate && status.Activated {
			summary.TotalRunning++
		} else if status.Activated {
			summary.TotalStopping++
		} else if effectiveActivate {
			summary.TotalStarting++
		}

	}

	log.Functionf("publishAppInstanceSummary TotalStarting: %d TotalRunning: %d TotalStopping: %d TotalError: %d",
		summary.TotalStarting, summary.TotalRunning, summary.TotalStopping, summary.TotalError)

	pub := ctxPtr.pubAppInstanceSummary

	pub.Publish(summary.Key(), summary)
}

func publishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Tracef("publishAppInstanceStatus(%s)", key)
	pub := ctx.pubAppInstanceStatus
	pub.Publish(key, *status)
}

func unpublishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Tracef("unpublishAppInstanceStatus(%s)", key)
	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishAppInstanceStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleAppInstanceConfigDelete(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := lookupAppInstanceStatus(ctx, key)
	if status == nil {
		log.Functionf("handleAppInstanceConfigDelete: unknown %s", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Functionf("handleAppInstanceConfigDelete(%s) done", key)
}

// Callers must be careful to publish any changes to AppInstanceStatus
func lookupAppInstanceStatus(ctx *zedmanagerContext, key string) *types.AppInstanceStatus {

	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Tracef("lookupAppInstanceStatus(%s) not found", key)
		return nil
	}
	status := st.(types.AppInstanceStatus)
	return &status
}

// lookupAppInstanceConfig returns the AppInstanceConfig for the given key. If checkLocal is true, then the local
// AppInstanceConfig subscription is checked first, not the regular one. The local subscription is used for
// AppInstanceConfig that comes from snapshot during a rollback.
func lookupAppInstanceConfig(ctx *zedmanagerContext, key string, checkLocal bool) *types.AppInstanceConfig {
	if checkLocal {
		sub := ctx.subLocalAppInstanceConfig
		c, _ := sub.Get(key)
		if c != nil {
			config := c.(types.AppInstanceConfig)
			return &config
		}
	}
	sub := ctx.subAppInstanceConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupAppInstanceConfig(%s) not found", key)
		return nil
	}
	config := c.(types.AppInstanceConfig)
	return &config
}

func lookupLocalAppInstanceConfig(ctx *zedmanagerContext, key string) *types.AppInstanceConfig {
	sub := ctx.subLocalAppInstanceConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupLocalAppInstanceConfig(%s) not found", key)
		return nil
	}
	config := c.(types.AppInstanceConfig)
	return &config
}

func isSnapshotRequestedOnUpdate(status *types.AppInstanceStatus, config types.AppInstanceConfig) bool {
	if config.Snapshot.Snapshots == nil {
		return false
	}
	for _, snap := range config.Snapshot.Snapshots {
		// VM should be marked to be snapshotted on update only if there is any snapshot request of the type "on update"
		// that is not handled yet.
		if snap.SnapshotType == types.SnapshotTypeAppUpdate && lookupAvailableSnapshot(status, snap.SnapshotID) == nil {
			return true
		}
	}
	return false
}

// removeNUnpublishedSnapshotRequests removes up to n snapshot requests that have not been triggered yet
func removeNUnpublishedSnapshotRequests(status *types.AppInstanceStatus, n uint32) (removedCount uint32) {
	removedCount = 0
	snapshots := status.SnapStatus.RequestedSnapshots
	for i := 0; i < len(snapshots) && removedCount < n; i++ {
		if snapshots[i].TimeTriggered.IsZero() {
			// Move the last element to the current position and truncate the slice
			snapshots[i] = snapshots[len(snapshots)-1]
			snapshots = snapshots[:len(snapshots)-1]
			// Remove the snapshot from the list of snapshots to be triggered
			removePreparedVolumesSnapshotConfig(status, snapshots[i].Snapshot.SnapshotID)
			i-- // Decrement i to recheck the current index after the swap
			removedCount++
		}
	}
	status.SnapStatus.RequestedSnapshots = snapshots
	return removedCount
}

/* Functions to handle snapshot-related events coming from the controller */

// adjustToMaxSnapshots verifies if the number of snapshots exceeds the set limit. In that case, it marks the oldest
// snapshots for deletion. If the number of snapshots still surpasses the limit, it trims the list of upcoming snapshots
// to fit within the limit. The order in which the lists are considered for deletion is as follows:
// 1) existing snapshots,
// 2) new snapshot requests, and
// 3) snapshots prepared for capture.
func adjustToMaxSnapshots(status *types.AppInstanceStatus, toBeDeleted []types.SnapshotDesc, newRequested []types.SnapshotDesc) ([]types.SnapshotDesc, []types.SnapshotDesc) {
	snapState := &status.SnapStatus
	// If the number of snapshots is less than the limit, then we do not need to delete any snapshots.
	totalSnapshotsRequestedNum := uint32(len(snapState.AvailableSnapshots) + len(snapState.RequestedSnapshots) + len(newRequested) - len(toBeDeleted))
	if totalSnapshotsRequestedNum <= snapState.MaxSnapshots {
		return toBeDeleted, newRequested
	}
	// If the number of snapshots is more than the limit, then we need to report a warning...
	errDesc := types.ErrorDescription{}
	errDesc.Error = fmt.Sprintf("Too many snapshots requested. Max allowed: %d", snapState.MaxSnapshots)
	log.Warnf("adjustToMaxSnapshots: %s", errDesc.Error)
	errDesc.ErrorTime = time.Now()
	errDesc.ErrorSeverity = types.ErrorSeverityWarning
	status.ErrorDescription = errDesc
	// ... and to delete the oldest snapshots ...
	log.Noticef("adjustToMaxSnapshots: Flagging available snapshots for deletion for %s", status.DisplayName)
	snapshotsToBeDeletedNum := totalSnapshotsRequestedNum - snapState.MaxSnapshots

	// Sort the available snapshots by creation time
	sort.Slice(snapState.AvailableSnapshots, func(i, j int) bool {
		return snapState.AvailableSnapshots[i].TimeCreated.Before(snapState.AvailableSnapshots[j].TimeCreated)
	})
	for i := 0; i < len(snapState.AvailableSnapshots) && snapshotsToBeDeletedNum != 0; i++ {
		log.Noticef("Flagging available snapshot %s for deletion", snapState.AvailableSnapshots[i].Snapshot.SnapshotID)
		toBeDeleted = append(toBeDeleted, snapState.AvailableSnapshots[i].Snapshot)
		snapshotsToBeDeletedNum--
	}
	if snapshotsToBeDeletedNum == 0 {
		return toBeDeleted, newRequested
	}

	// ... if we still have snapshots to be deleted, we need to delete them from the requests list ...
	requestsToBeDeleted := len(newRequested)
	if int(snapshotsToBeDeletedNum) < requestsToBeDeleted {
		requestsToBeDeleted = int(snapshotsToBeDeletedNum)
	}
	log.Noticef("Removing %d new snapshot requests for %s", requestsToBeDeleted, status.DisplayName)
	newRequested = newRequested[:len(newRequested)-requestsToBeDeleted]
	snapshotsToBeDeletedNum -= uint32(requestsToBeDeleted)
	if snapshotsToBeDeletedNum == 0 {
		return toBeDeleted, newRequested
	}

	// ... if we still have snapshots to be deleted, we need to delete the unpublished snapshots from the RequestedSnapshots list.
	log.Noticef("Flagging planned but unpublished snapshots for deletion for %s", status.DisplayName)
	removed := removeNUnpublishedSnapshotRequests(status, snapshotsToBeDeletedNum)
	if removed != snapshotsToBeDeletedNum {
		errDesc.Error = fmt.Sprintf("Unexpected error. The number of snapshots to be deleted is more than the number of all snapshots.")
		log.Errorf("adjustToMaxSnapshots: %s", errDesc.Error)
		errDesc.ErrorTime = time.Now()
		errDesc.ErrorSeverity = types.ErrorSeverityWarning
		status.ErrorDescription = errDesc
	}
	return toBeDeleted, newRequested
}

// getSnapshotsToBeDeleted returns the list of snapshots to be deleted
func getSnapshotsToBeDeleted(config types.AppInstanceConfig, status *types.AppInstanceStatus) (snapsToBeDeleted []types.SnapshotDesc) {
	for _, snap := range status.SnapStatus.AvailableSnapshots {
		// Can mark a snapshot for deletion only if it is reported to the controller.
		if snap.Reported {
			// If the config has a list of snapshots, then we need to delete the ones which are not present in the config.
			// If the config does not have a list of snapshots, then we need to delete all the reported snapshots.
			if config.Snapshot.Snapshots == nil || !isSnapshotPresentInConfig(config, snap.Snapshot.SnapshotID) {
				log.Noticef("Flagging snapshot %s for deletion", snap.Snapshot.SnapshotID)
				snapsToBeDeleted = append(snapsToBeDeleted, snap.Snapshot)
			}
		}
	}
	return snapsToBeDeleted
}

// isSnapshotPresentInConfig checks if the snapshot is already present in the list of snapshots
func isSnapshotPresentInConfig(config types.AppInstanceConfig, id string) bool {
	for _, snapDesc := range config.Snapshot.Snapshots {
		if snapDesc.SnapshotID == id {
			return true
		}
	}
	return false
}

// getNewSnapshotRequests returns the list of new snapshot requests
func getNewSnapshotRequests(config types.AppInstanceConfig, status *types.AppInstanceStatus) (snapRequests []types.SnapshotDesc) {
	if config.Snapshot.Snapshots != nil {
		for _, snap := range config.Snapshot.Snapshots {
			if isNewSnapshotRequest(snap.SnapshotID, status) {
				log.Noticef("A new snapshot %s is requested", snap.SnapshotID)
				snapRequests = append(snapRequests, snap)
			}
		}
	}
	return snapRequests
}

// isNewSnapshotRequest checks if the snapshot is already present at least in one of the lists:
// the list of the snapshots to be taken or available snapshots.
func isNewSnapshotRequest(id string, status *types.AppInstanceStatus) bool {
	// Check if the snapshot is already present in the list of the snapshots to be taken.
	for _, snapRequest := range status.SnapStatus.RequestedSnapshots {
		if snapRequest.Snapshot.SnapshotID == id {
			return false
		}
	}
	// Check if the snapshot is already present in the list of the available snapshots.
	for _, snapAvailable := range status.SnapStatus.AvailableSnapshots {
		if snapAvailable.Snapshot.SnapshotID == id {
			return false
		}
	}
	return true
}

// Update the snapshot related fields in the AppInstanceStatus
func updateSnapshotsInAIStatus(status *types.AppInstanceStatus, config types.AppInstanceConfig) {
	status.SnapStatus.SnapshotOnUpgrade = isSnapshotRequestedOnUpdate(status, config)
	//markReportedSnapshots(status, config)
	status.SnapStatus.MaxSnapshots = config.Snapshot.MaxSnapshots
	snapshotsToBeDeleted := getSnapshotsToBeDeleted(config, status)
	snapshotsRequests := getNewSnapshotRequests(config, status)

	// Check if we have reached the max number of snapshots and delete the oldest ones
	snapshotsToBeDeleted, snapshotsRequests = adjustToMaxSnapshots(status, snapshotsToBeDeleted, snapshotsRequests)
	for _, snapshot := range snapshotsRequests {
		log.Noticef("Adding snapshot %s to the list of snapshots to be taken, for %s", snapshot.SnapshotID, config.DisplayName)
		newSnapshotStatus := types.SnapshotInstanceStatus{
			Snapshot:      snapshot,
			Reported:      false,
			AppInstanceID: config.UUIDandVersion.UUID,
			// ConfigVersion is set when the snapshot is triggered
		}
		status.SnapStatus.RequestedSnapshots = append(status.SnapStatus.RequestedSnapshots, newSnapshotStatus)
	}
	// Remove the snapshots marked for deletion from the list of available snapshots
	for _, snapshot := range snapshotsToBeDeleted {
		// If snapshot is not yet in the list of the snapshots to be deleted, add it there
		if !isSnapshotDescInSlice(&status.SnapStatus.SnapshotsToBeDeleted, snapshot.SnapshotID) {
			status.SnapStatus.SnapshotsToBeDeleted = append(status.SnapStatus.SnapshotsToBeDeleted, snapshot)
		}
		_ = removeSnapshotFromSlice(&status.SnapStatus.AvailableSnapshots, snapshot.SnapshotID)
	}
}

// prepareVolumesSnapshotConfigs generates a 'volumesSnapshotConfig' for each pending snapshot request with a prepared configuration.
// Creating and immediately triggering the 'volumesSnapshotConfig' is not possible due to the following reasons:
// - A snapshot can only be initiated post the application stoppage.
// - Upon application termination, the volumes list within the configuration might have already been modified, leading to inconsistencies.
// Hence, we need this function to prepare the 'volumesSnapshotConfig' with the volumes list that was used when the snapshot was requested.
func prepareVolumesSnapshotConfigs(ctx *zedmanagerContext, config types.AppInstanceConfig, status *types.AppInstanceStatus) []types.VolumesSnapshotConfig {
	var volumesSnapshotConfigList []types.VolumesSnapshotConfig
	for _, snapshot := range status.SnapStatus.RequestedSnapshots {
		if snapshot.Snapshot.SnapshotType == types.SnapshotTypeAppUpdate {
			log.Noticef("Creating volumesSnapshotConfig for snapshot %s", snapshot.Snapshot.SnapshotID)
			volumesSnapshotConfig := types.VolumesSnapshotConfig{
				SnapshotID: snapshot.Snapshot.SnapshotID,
				Action:     types.VolumesSnapshotCreate,
				AppUUID:    status.UUIDandVersion.UUID,
			}
			for _, volumeRefConfig := range config.VolumeRefConfigList {
				log.Noticef("Adding volume %s to volumesSnapshotConfig", volumeRefConfig.VolumeID)
				volumesSnapshotConfig.VolumeIDs = append(volumesSnapshotConfig.VolumeIDs, volumeRefConfig.VolumeID)
			}
			volumesSnapshotConfigList = append(volumesSnapshotConfigList, volumesSnapshotConfig)
		}
	}
	return volumesSnapshotConfigList
}

// removePreparedVolumesSnapshotConfig removes the prepared volumesSnapshotConfig from the list of prepared volumesSnapshotConfigs
func removePreparedVolumesSnapshotConfig(status *types.AppInstanceStatus, id string) {
	preparedVolumesSnapshotConfigs := &status.SnapStatus.PreparedVolumesSnapshotConfigs
	for i, volumesSnapshotConfig := range *preparedVolumesSnapshotConfigs {
		if volumesSnapshotConfig.SnapshotID == id {
			// Shift the elements to the right of the index i to fill the gap
			*preparedVolumesSnapshotConfigs = append((*preparedVolumesSnapshotConfigs)[:i], (*preparedVolumesSnapshotConfigs)[i+1:]...)
			break
		}
	}
}

// saveAppInstanceConfigForSnapshot saves the config for the snapshots for which the config has been prepared
func saveAppInstanceConfigForSnapshot(status *types.AppInstanceStatus, config types.AppInstanceConfig) error {
	for i, snapshot := range status.SnapStatus.PreparedVolumesSnapshotConfigs {
		// Set the old config version to the snapshot status
		status.SnapStatus.RequestedSnapshots[i].ConfigVersion = config.UUIDandVersion
		// Serialize the old config and store it in a file
		err := serializeAppInstanceConfigToSnapshot(config, snapshot.SnapshotID)
		if err != nil {
			log.Errorf("Failed to serialize the old config for %s, error: %s", config.DisplayName, err)
			return err
		}
	}
	return nil
}

// serializeAppInstanceConfigToSnapshot serializes the config to a file
func serializeAppInstanceConfigToSnapshot(config types.AppInstanceConfig, snapshotID string) error {
	// Store the old config in a file, so that we can use it to roll back to the previous version
	// if the upgrade fails
	configAsBytes, err := json.Marshal(config)
	if err != nil {
		log.Errorf("Failed to marshal the old config for %s, error: %s", config.DisplayName, err)
		return err
	}
	snapshotDir := types.GetSnapshotDir(snapshotID)
	// Create the directory for storing the old config
	err = os.MkdirAll(snapshotDir, 0755)
	if err != nil {
		log.Errorf("Failed to create the config dir for %s, error: %s", config.DisplayName, err)
		return err
	}
	configFile := types.GetSnapshotAppInstanceConfigFile(snapshotID)
	err = fileutils.WriteRename(configFile, configAsBytes)
	if err != nil {
		log.Errorf("Failed to write the old config for %s, error: %s", config.DisplayName, err)
		return err
	}
	return nil
}

func handleCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	config := configArg.(types.AppInstanceConfig)

	log.Functionf("handleCreate(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	status := types.AppInstanceStatus{
		UUIDandVersion: config.UUIDandVersion,
		DisplayName:    config.DisplayName,
		FixedResources: config.FixedResources,
		State:          types.INITIAL,
	}

	// Calculate the moment when the application should start, taking into account the configured delay
	status.StartTime = ctx.delayBaseTime.Add(config.Delay)

	restoreAvailableSnapshots(&status)

	updateSnapshotsInAIStatus(&status, config)

	// Do we have a PurgeCmd counter from before the reboot?
	// Note that purgeCmdCounter is a sum of the remote and the local purge counter.
	mapKey := types.UuidToNumKey{UUID: config.UUIDandVersion.UUID}
	persistedCounter, _, err := ctx.appToPurgeCounterMap.Get(mapKey)
	configCounter := int(config.PurgeCmd.Counter + config.LocalPurgeCmd.Counter)
	if err == nil {
		if persistedCounter == configCounter {
			log.Functionf("handleCreate(%v) for %s found matching purge counter %d",
				config.UUIDandVersion, config.DisplayName, persistedCounter)
		} else {
			log.Warnf("handleCreate(%v) for %s found different purge counter %d vs. %d",
				config.UUIDandVersion, config.DisplayName, persistedCounter, configCounter)
			status.PurgeInprogress = types.DownloadAndVerify
			status.State = types.PURGING
			status.PurgeStartedAt = time.Now()
			// We persist the PurgeCmd Counter when
			// PurgeInprogress is done
		}
	} else {
		// Save this PurgeCmd.Counter as the baseline
		log.Functionf("handleCreate(%v) for %s saving purge counter %d",
			config.UUIDandVersion, config.DisplayName, configCounter)
		err = ctx.appToPurgeCounterMap.Assign(mapKey, configCounter, true)
		if err != nil {
			log.Errorf("Failed to persist purge counter for app %s-%s: %v",
				config.DisplayName, config.UUIDandVersion.UUID, err)
		}
	}

	status.VolumeRefStatusList = make([]types.VolumeRefStatus,
		len(config.VolumeRefConfigList))
	for i, vrc := range config.VolumeRefConfigList {
		vrs := &status.VolumeRefStatusList[i]
		vrs.VolumeID = vrc.VolumeID
		vrs.GenerationCounter = vrc.GenerationCounter
		vrs.LocalGenerationCounter = vrc.LocalGenerationCounter
		vrs.RefCount = vrc.RefCount
		vrs.MountDir = vrc.MountDir
		vrs.PendingAdd = true
		vrs.State = types.INITIAL
		vrs.VerifyOnly = true
	}

	allErrors := ""
	if len(config.Errors) > 0 {
		// Combine all errors from Config parsing state and send them in Status
		for i, errStr := range config.Errors {
			allErrors += errStr
			log.Errorf("App Instance %s-%s: Error(%d): %s",
				config.DisplayName, config.UUIDandVersion.UUID, i, errStr)
		}
		log.Errorf("App Instance %s-%s: Errors in App Instance Create.",
			config.DisplayName, config.UUIDandVersion.UUID)
	}

	// Do some basic sanity checks.
	if config.FixedResources.Memory == 0 {
		errStr := "Invalid Memory Size - 0\n"
		allErrors += errStr
	}
	if config.FixedResources.VCpus == 0 {
		errStr := "Invalid Cpu count - 0\n"
		allErrors += errStr
	}

	// if some error, return
	if allErrors != "" {
		log.Errorf("AppInstance(Name:%s, UUID:%s): Errors in App Instance "+
			"Create. Error: %s",
			config.DisplayName, config.UUIDandVersion.UUID, allErrors)
		status.SetErrorWithSource(allErrors, types.AppInstanceStatus{},
			time.Now())
		publishAppInstanceStatus(ctx, &status)
		return
	}

	// If there are no errors, go ahead with Instance creation.
	changed := doUpdate(ctx, config, &status)
	if changed {
		log.Functionf("AppInstance(Name:%s, UUID:%s): handleCreate status change.",
			config.DisplayName, config.UUIDandVersion.UUID)
		publishAppInstanceStatus(ctx, &status)
	}
	log.Functionf("handleCreate done for %s", config.DisplayName)
}

func handleModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	config := configArg.(types.AppInstanceConfig)
	oldConfig := oldConfigArg.(types.AppInstanceConfig)
	status := lookupAppInstanceStatus(ctx, key)
	log.Functionf("handleModify(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	localConfig := lookupLocalAppInstanceConfig(ctx, config.Key())
	if localConfig != nil {
		config = *localConfig
	}

	// Check if we need to roll back to a snapshot
	if config.Snapshot.RollbackCmd.Counter > oldConfig.Snapshot.RollbackCmd.Counter {
		log.Noticef("handleModify(%v) for %s: Snapshot to be rolled back: %v",
			config.UUIDandVersion, config.DisplayName, config.Snapshot.ActiveSnapshot)
		status.SnapStatus.ActiveSnapshot = config.Snapshot.ActiveSnapshot
		snappedAppInstanceConfig, err := restoreAppInstanceConfigFromSnapshot(ctx, status, config.Snapshot.ActiveSnapshot)
		if err != nil {
			errStr := fmt.Sprintf("Error restoring config from snapshot %s: %s", config.Snapshot.ActiveSnapshot, err)
			log.Errorf("handleModify(%s) failed: %s", status.Key(), errStr)
			status.SetError(errStr, time.Now())
			return
		}
		// Remove the volume ref statuses that are not in the snapshot. Need to remove the corresponding volumes properly
		removeUnusedVolumeRefStatuses(ctx, snappedAppInstanceConfig, status)
		log.Noticef("handleModify: switch config to snapshot %s, version %s", status.SnapStatus.ActiveSnapshot, snappedAppInstanceConfig.UUIDandVersion.Version)
		status.SnapStatus.HasRollbackRequest = true
		status.SnapStatus.RollbackInProgress = true
		publishAppInstanceStatus(ctx, status)
		config = *snappedAppInstanceConfig
		// Since now the config been handled here and the one in the channel are different, so we need to ignore the config in the channel
		publishLocalAppInstanceConfig(ctx, &config)
		return
	}

	status.StartTime = ctx.delayBaseTime.Add(config.Delay)

	updateSnapshotsInAIStatus(status, config)

	effectiveActivate := effectiveActivateCurrentProfile(config, ctx.currentProfile)

	publishAppInstanceStatus(ctx, status)

	// We handle at least ACL and activate changes. XXX What else?
	// Not checking the version here; assume the microservices can handle
	// some updates.

	// We detect significant changes which require a reboot and/or
	// purge of disk changes, so we can generate errors if it is
	// not a PurgeCmd and RestartCmd, respectively
	// If we are purging then restart is redundant.
	needPurge, needRestart, purgeReason, restartReason := quantifyChanges(config, oldConfig, *status)
	if needPurge {
		needRestart = false
	}
	// A snapshot is deemed necessary whenever the application requires a restart, as this typically
	// indicates a significant change in the application, such as an upgrade.
	if status.SnapStatus.SnapshotOnUpgrade && (needRestart || needPurge) {
		// Save the list of the volumes that need to be backed up. We will use this list to create the snapshot when
		// it's triggered. We cannot trigger the snapshot creation here immediately, as the VM
		// should be stopped first. But we still need to save the list of volumes that are known only at this point.
		status.SnapStatus.PreparedVolumesSnapshotConfigs = prepareVolumesSnapshotConfigs(ctx, oldConfig, status)
		err := saveAppInstanceConfigForSnapshot(status, oldConfig)
		if err != nil {
			log.Errorf("handleModify(%v) for %s: error saving old config for snapshots: %v",
				config.UUIDandVersion, config.DisplayName, err)
			// Do not report it to the controller, as the controller do not expect snapshot-creation related errors
		}
	}

	if config.RestartCmd.Counter != oldConfig.RestartCmd.Counter ||
		config.LocalRestartCmd.Counter != oldConfig.LocalRestartCmd.Counter {

		log.Functionf("handleModify(%v) for %s restartcmd from %d/%d to %d/%d "+
			"needRestart: %v",
			config.UUIDandVersion, config.DisplayName,
			oldConfig.RestartCmd.Counter, oldConfig.LocalRestartCmd.Counter,
			config.RestartCmd.Counter, config.LocalRestartCmd.Counter,
			needRestart)
		if effectiveActivate {
			// Will restart even if we crash/power cycle since that
			// would also restart the app. Hence we can update
			// the status counter here.
			status.RestartInprogress = types.BringDown
			status.State = types.RESTARTING
			status.RestartStartedAt = time.Now()
		} else {
			log.Functionf("handleModify(%v) for %s restartcmd ignored config !Activate",
				config.UUIDandVersion, config.DisplayName)
			oldConfig.RestartCmd.Counter = config.RestartCmd.Counter
			oldConfig.LocalRestartCmd.Counter = config.LocalRestartCmd.Counter
		}
	} else if needRestart {
		errStr := fmt.Sprintf("Need restart due to %s but not a restartCmd",
			restartReason)
		log.Errorf("handleModify(%s) failed: %s", status.Key(), errStr)
		status.SetError(errStr, time.Now())
		publishAppInstanceStatus(ctx, status)
		return
	}

	if config.PurgeCmd.Counter != oldConfig.PurgeCmd.Counter ||
		config.LocalPurgeCmd.Counter != oldConfig.LocalPurgeCmd.Counter ||
		(needPurge && status.SnapStatus.HasRollbackRequest) {
		log.Functionf("handleModify(%v) for %s purgecmd from %d/%d to %d/%d "+
			"needPurge: %v",
			config.UUIDandVersion, config.DisplayName,
			oldConfig.PurgeCmd.Counter, oldConfig.LocalPurgeCmd.Counter,
			config.PurgeCmd.Counter, config.LocalPurgeCmd.Counter,
			needPurge)
		if status.IsErrorSource(types.AppInstanceStatus{}) {
			log.Functionf("Removing error %s", status.Error)
			status.ClearErrorWithSource()
		}
		status.PurgeInprogress = types.DownloadAndVerify
		status.State = types.PURGING
		status.PurgeStartedAt = time.Now()
		// We persist the PurgeCmd Counter when PurgeInprogress is done
	} else if needPurge {
		errStr := fmt.Sprintf("Need purge due to %s but not a purgeCmd",
			purgeReason)
		log.Errorf("handleModify(%s) failed: %s", status.Key(), errStr)
		status.SetError(errStr, time.Now())
		publishAppInstanceStatus(ctx, status)
		return
	}

	status.UUIDandVersion = config.UUIDandVersion
	publishAppInstanceStatus(ctx, status)

	changed := doUpdate(ctx, config, status)
	if changed {
		log.Functionf("handleModify status change for %s", status.Key())
		publishAppInstanceStatus(ctx, status)
	}
	publishAppInstanceStatus(ctx, status)
	log.Functionf("handleModify done for %s", config.DisplayName)
}

func removeUnusedVolumeRefStatuses(ctx *zedmanagerContext, config *types.AppInstanceConfig, status *types.AppInstanceStatus) {
	// Remove any volumeRefStatuses that are no longer referenced by the config
	for _, vrs := range status.VolumeRefStatusList {
		found := false
		for _, vrc := range config.VolumeRefConfigList {
			if vrs.VolumeID == vrc.VolumeID {
				found = true
				break
			}
		}
		if !found {
			log.Functionf("Removing VolumeRefStatus for %s", vrs.VolumeID)
			//remove from the volume ref status list
			for i, vrs1 := range status.VolumeRefStatusList {
				if vrs1.VolumeID == vrs.VolumeID {
					status.VolumeRefStatusList = append(status.VolumeRefStatusList[:i], status.VolumeRefStatusList[i+1:]...)
					break
				}
			}
			//unpublish the volume ref config
			unpublishVolumeRefConfig(ctx, vrs.Key())
		}
	}

}

func unpublishLocalAppInstanceConfig(ctx *zedmanagerContext, key string) {
	log.Noticef("unpublishLocalAppInstanceConfig(%v)", key)
	pub := ctx.pubLocalAppInstanceConfig
	pub.Unpublish(key)
}

func publishLocalAppInstanceConfig(ctx *zedmanagerContext, appInstanceConfig *types.AppInstanceConfig) {
	key := appInstanceConfig.Key()
	log.Noticef("publishLocalAppInstanceConfig(%v)", key)
	pub := ctx.pubLocalAppInstanceConfig
	_ = pub.Publish(key, *appInstanceConfig)
}

func handleDelete(ctx *zedmanagerContext, key string,
	status *types.AppInstanceStatus) {

	log.Functionf("handleDelete(%v) for %s",
		status.UUIDandVersion, status.DisplayName)

	removeAIStatus(ctx, status)
	// Remove the recorded PurgeCmd Counter
	mapKey := types.UuidToNumKey{UUID: status.UUIDandVersion.UUID}
	err := ctx.appToPurgeCounterMap.Delete(mapKey, false)
	if err != nil {
		log.Warnf("Failed to delete persisted purge counter for app %s-%s: %v",
			status.DisplayName, status.UUIDandVersion.UUID, err)
	}
	log.Functionf("handleDelete done for %s", status.DisplayName)
}

// Returns needRestart, needPurge, plus a string for each.
// If there is a change to the disks, adapters, or network interfaces
// it returns needPurge.
// If there is a change to the CPU etc resources it returns needRestart
// Changes to ACLs don't result in either being returned.
func quantifyChanges(config types.AppInstanceConfig, oldConfig types.AppInstanceConfig,
	status types.AppInstanceStatus) (bool, bool, string, string) {

	needPurge := false
	needRestart := false
	var purgeReason, restartReason string
	log.Functionf("quantifyChanges for %s %s",
		config.Key(), config.DisplayName)
	if len(oldConfig.VolumeRefConfigList) != len(config.VolumeRefConfigList) {
		str := fmt.Sprintf("number of volume ref changed from %d to %d",
			len(oldConfig.VolumeRefConfigList),
			len(config.VolumeRefConfigList))
		log.Functionf(str)
		needPurge = true
		purgeReason += str + "\n"
	} else {
		for _, vrc := range config.VolumeRefConfigList {
			vrs := getVolumeRefStatusFromAIStatus(&status, vrc)
			if vrs == nil {
				str := fmt.Sprintf("Missing VolumeRefStatus for "+
					"(VolumeID: %s, GenerationCounter: %d, LocalGenerationCounter: %d)",
					vrc.VolumeID, vrc.GenerationCounter, vrc.LocalGenerationCounter)
				// It can be a part of rollback
				log.Warn(str)
				needPurge = true
				purgeReason += str + "\n"
				continue
			}
		}
	}
	if len(oldConfig.AppNetAdapterList) != len(config.AppNetAdapterList) {
		str := fmt.Sprintf("number of AppNetAdapter changed from %d to %d",
			len(oldConfig.AppNetAdapterList),
			len(config.AppNetAdapterList))
		log.Functionf(str)
		needPurge = true
		purgeReason += str + "\n"
	} else {
		for i, uc := range config.AppNetAdapterList {
			old := oldConfig.AppNetAdapterList[i]
			if old.AppMacAddr.String() != uc.AppMacAddr.String() {
				str := fmt.Sprintf("AppMacAddr changed from %v to %v",
					old.AppMacAddr, uc.AppMacAddr)
				log.Functionf(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if !old.AppIPAddr.Equal(uc.AppIPAddr) {
				str := fmt.Sprintf("AppIPAddr changed from %v to %v",
					old.AppIPAddr, uc.AppIPAddr)
				log.Functionf(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if old.Network != uc.Network {
				str := fmt.Sprintf("Network changed from %v to %v",
					old.Network, uc.Network)
				log.Functionf(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if !cmp.Equal(old.ACLs, uc.ACLs) {
				log.Functionf("FYI ACLs changed: %v",
					cmp.Diff(old.ACLs, uc.ACLs))
			}
		}
	}
	if !cmp.Equal(config.IoAdapterList, oldConfig.IoAdapterList) {
		str := fmt.Sprintf("IoAdapterList changed: %v",
			cmp.Diff(oldConfig.IoAdapterList, config.IoAdapterList))
		log.Functionf(str)
		needPurge = true
		purgeReason += str + "\n"
	}
	if !cmp.Equal(config.FixedResources, oldConfig.FixedResources) {
		str := fmt.Sprintf("FixedResources changed: %v",
			cmp.Diff(oldConfig.FixedResources, config.FixedResources))
		log.Functionf(str)
		needRestart = true
		restartReason += str + "\n"
	}
	log.Functionf("quantifyChanges for %s %s returns %v, %v",
		config.Key(), config.DisplayName, needPurge, needRestart)
	return needPurge, needRestart, purgeReason, restartReason
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

	ctx := ctxArg.(*zedmanagerContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
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
	ctxPtr := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.ZedAgentStatus)
	// When getting the config successfully for the first time (get from the controller or read from the file), consider
	// the device as ready to start apps. Hence, count the app delay timeout from now.
	if status.ConfigGetStatus == types.ConfigGetSuccess || status.ConfigGetStatus == types.ConfigGetReadSaved {
		if ctxPtr.delayBaseTime.IsZero() {
			ctxPtr.delayBaseTime = time.Now()
		}
	}

	if ctxPtr.currentProfile != status.CurrentProfile {
		log.Noticef("handleZedAgentStatusImpl: CurrentProfile changed from %s to %s",
			ctxPtr.currentProfile, status.CurrentProfile)
		oldProfile := ctxPtr.currentProfile
		ctxPtr.currentProfile = status.CurrentProfile
		updateBasedOnProfile(ctxPtr, oldProfile)
	}
	log.Functionf("handleZedAgentStatusImpl(%s) done", key)
}

func handleHostMemoryCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleHostMemoryImpl(ctxArg, key, statusArg)
}

func handleHostMemoryModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleHostMemoryImpl(ctxArg, key, statusArg)
}

func handleHostMemoryImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctxPtr := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.HostMemory)
	if ctxPtr.currentTotalMemoryMB != 0 && status.TotalMemoryMB > ctxPtr.currentTotalMemoryMB {
		// re-check available resources again in case of TotalMemory changed from non-zero to larger values
		ctxPtr.checkFreedResources = true
	}
	if ctxPtr.currentTotalMemoryMB != status.TotalMemoryMB {
		ctxPtr.currentTotalMemoryMB = status.TotalMemoryMB
		log.Functionf("handleHostMemoryImpl(%s) currentTotalMemoryMB changed from %d to %d",
			key, ctxPtr.currentTotalMemoryMB, status.TotalMemoryMB)
	}
	log.Functionf("handleHostMemoryImpl(%s) done", key)
}

// updateBasedOnProfile check all app instances with ctx.currentProfile and oldProfile
// update AppInstance if change in effective activate detected
func updateBasedOnProfile(ctx *zedmanagerContext, oldProfile string) {
	pub := ctx.subAppInstanceConfig
	items := pub.GetAll()
	for _, c := range items {
		config := c.(types.AppInstanceConfig)
		if localConfig := lookupLocalAppInstanceConfig(ctx, config.Key()); localConfig != nil {
			config = *localConfig
		}
		effectiveActivate := effectiveActivateCurrentProfile(config, ctx.currentProfile)
		effectiveActivateOld := effectiveActivateCurrentProfile(config, oldProfile)
		if effectiveActivateOld == effectiveActivate {
			// no changes in effective activate
			continue
		}
		status := lookupAppInstanceStatus(ctx, config.Key())
		if status != nil {
			log.Functionf("updateBasedOnProfile: change activate state for %s from %t to %t",
				config.Key(), effectiveActivateOld, effectiveActivate)
			if doUpdate(ctx, config, status) {
				publishAppInstanceStatus(ctx, status)
			}
		}
	}
}

// returns effective Activate status based on Activate from app instance config and current profile
func effectiveActivateCurrentProfile(config types.AppInstanceConfig, currentProfile string) bool {
	if currentProfile == "" {
		log.Functionf("effectiveActivateCurrentProfile(%s): empty current", config.Key())
		// if currentProfile is empty set activate state from controller
		return config.Activate
	}
	if len(config.ProfileList) == 0 {
		log.Functionf("effectiveActivateCurrentProfile(%s): empty ProfileList", config.Key())
		//we have no profile in list so we should use activate state from the controller
		return config.Activate
	}
	for _, p := range config.ProfileList {
		if p == currentProfile {
			log.Functionf("effectiveActivateCurrentProfile(%s): profile form list (%s) match current (%s)",
				config.Key(), p, currentProfile)
			// pass config.Activate from controller if currentProfile is inside ProfileList
			return config.Activate
		}
	}
	log.Functionf("effectiveActivateCurrentProfile(%s): no match with current (%s)",
		config.Key(), currentProfile)
	return false
}
