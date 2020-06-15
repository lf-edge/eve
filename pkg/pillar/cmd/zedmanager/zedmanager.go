// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Get AppInstanceConfig from zedagent, drive config to VolumeMgr,
// IdentityMgr, and Zedrouter. Collect status from those services and make
// the combined AppInstanceStatus available to zedagent.

package zedmanager

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/uuidtonum"
	log "github.com/sirupsen/logrus"
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
	subAppInstanceConfig   pubsub.Subscription
	pubAppInstanceStatus   pubsub.Publication
	pubVolumeConfig        pubsub.Publication
	subVolumeStatus        pubsub.Subscription
	pubAppNetworkConfig    pubsub.Publication
	subAppNetworkStatus    pubsub.Subscription
	pubDomainConfig        pubsub.Publication
	subDomainStatus        pubsub.Subscription
	pubAppImgResolveConfig pubsub.Publication
	subAppImgResolveStatus pubsub.Subscription
	pubEIDConfig           pubsub.Publication
	subEIDStatus           pubsub.Subscription
	subGlobalConfig        pubsub.Subscription
	globalConfig           *types.ConfigItemValueMap
	pubUuidToNum           pubsub.Publication
	pubAppAndImageToHash   pubsub.Publication
	GCInitialized          bool
}

var debug = false
var debugOverride bool // From command line arg

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

	// Any state needed by handler functions
	ctx := zedmanagerContext{
		globalConfig: types.DefaultConfigItemValueMap(),
	}
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

	pubVolumeConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		AgentScope: types.AppImgObj,
		TopicType:  types.OldVolumeConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumeConfig = pubVolumeConfig

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

	pubEIDConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.EIDConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubEIDConfig = pubEIDConfig
	pubEIDConfig.ClearRestarted()

	pubUuidToNum, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		Persistent: true,
		TopicType:  types.UuidToNum{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubUuidToNum = pubUuidToNum
	pubUuidToNum.ClearRestarted()

	pubAppAndImageToHash, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		Persistent: true,
		TopicType:  types.AppAndImageToHash{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppAndImageToHash = pubAppAndImageToHash

	pubAppImgResolveConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		AgentScope: types.AppImgObj,
		TopicType:  types.ResolveConfig{},
	})
	if err != nil {
		log.Fatal(err)
	}
	pubAppImgResolveConfig.ClearRestarted()
	ctx.pubAppImgResolveConfig = pubAppImgResolveConfig

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleGlobalConfigModify,
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

	// Look for VolumeStatus from volumemgr
	subVolumeStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		AgentScope:    types.AppImgObj,
		TopicImpl:     types.OldVolumeStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleVolumeStatusModify,
		ModifyHandler: handleVolumeStatusModify,
		DeleteHandler: handleVolumeStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVolumeStatus = subVolumeStatus
	subVolumeStatus.Activate()

	// Get AppNetworkStatus from zedrouter
	subAppNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "zedrouter",
		TopicImpl:      types.AppNetworkStatus{},
		Activate:       false,
		Ctx:            &ctx,
		CreateHandler:  handleAppNetworkStatusModify,
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
		TopicImpl:     types.DomainStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleDomainStatusModify,
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

	// Get IdentityStatus from identitymgr
	subEIDStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:      "identitymgr",
		TopicImpl:      types.EIDStatus{},
		Activate:       false,
		Ctx:            &ctx,
		CreateHandler:  handleEIDStatusModify,
		ModifyHandler:  handleEIDStatusModify,
		DeleteHandler:  handleEIDStatusDelete,
		RestartHandler: handleIdentitymgrRestarted,
		WarningTime:    warningTime,
		ErrorTime:      errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subEIDStatus = subEIDStatus
	subEIDStatus.Activate()

	// Look for AppImgResolveStatus from downloader
	subAppImgResolveStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "downloader",
		AgentScope:    types.AppImgObj,
		TopicImpl:     types.ResolveStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleResolveStatusModify,
		ModifyHandler: handleResolveStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppImgResolveStatus = subAppImgResolveStatus
	subAppImgResolveStatus.Activate()

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Infof("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("Handling all inputs")
	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subVolumeStatus.MsgChan():
			subVolumeStatus.ProcessChange(change)

		case change := <-subEIDStatus.MsgChan():
			subEIDStatus.ProcessChange(change)

		case change := <-subAppNetworkStatus.MsgChan():
			subAppNetworkStatus.ProcessChange(change)

		case change := <-subDomainStatus.MsgChan():
			subDomainStatus.ProcessChange(change)

		case change := <-subAppInstanceConfig.MsgChan():
			subAppInstanceConfig.ProcessChange(change)

		case change := <-subAppImgResolveStatus.MsgChan():
			subAppImgResolveStatus.ProcessChange(change)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

// After zedagent has waited for its config and set restarted for
// AppInstanceConfig (which triggers this callback) we propagate a sequence of
// restarts so that the agents don't do extra work.
// We propagate a seqence of restarted from the zedmanager config
// to identitymgr, then from identitymgr to zedrouter,
// and finally from zedrouter to domainmgr.
// XXX is that sequence still needed with volumemgr in place?
// Need EIDs before zedrouter ...
func handleConfigRestart(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Infof("handleConfigRestart(%v)", done)
	if done {
		ctx.pubEIDConfig.SignalRestarted()
	}
}

func handleIdentitymgrRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Infof("handleIdentitymgrRestarted(%v)", done)
	if done {
		ctx.pubAppNetworkConfig.SignalRestarted()
	}
}

func handleZedrouterRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Infof("handleZedrouterRestarted(%v)", done)
	if done {
		ctx.pubDomainConfig.SignalRestarted()
	}
}

func publishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Debugf("publishAppInstanceStatus(%s)", key)
	pub := ctx.pubAppInstanceStatus
	pub.Publish(key, *status)
}

func unpublishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Debugf("unpublishAppInstanceStatus(%s)", key)
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

	log.Infof("handleAppInstanceConfigDelete(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := lookupAppInstanceStatus(ctx, key)
	if status == nil {
		log.Infof("handleAppInstanceConfigDelete: unknown %s", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Infof("handleAppInstanceConfigDelete(%s) done", key)
}

// Callers must be careful to publish any changes to AppInstanceStatus
func lookupAppInstanceStatus(ctx *zedmanagerContext, key string) *types.AppInstanceStatus {

	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupAppInstanceStatus(%s) not found", key)
		return nil
	}
	status := st.(types.AppInstanceStatus)
	return &status
}

func lookupAppInstanceConfig(ctx *zedmanagerContext, key string) *types.AppInstanceConfig {

	sub := ctx.subAppInstanceConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupAppInstanceConfig(%s) not found", key)
		return nil
	}
	config := c.(types.AppInstanceConfig)
	return &config
}

func handleCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	config := configArg.(types.AppInstanceConfig)

	log.Infof("handleCreate(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	status := types.AppInstanceStatus{
		UUIDandVersion:      config.UUIDandVersion,
		DisplayName:         config.DisplayName,
		FixedResources:      config.FixedResources,
		OverlayNetworkList:  config.OverlayNetworkList,
		UnderlayNetworkList: config.UnderlayNetworkList,
		IoAdapterList:       config.IoAdapterList,
		RestartCmd:          config.RestartCmd,
		PurgeCmd:            config.PurgeCmd,
		State:               types.INITIAL,
	}

	// Do we have a PurgeCmd counter from before the reboot?
	c, err := uuidtonum.UuidToNumGet(ctx.pubUuidToNum,
		config.UUIDandVersion.UUID, "purgeCmdCounter")
	if err == nil {
		if uint32(c) == status.PurgeCmd.Counter {
			log.Infof("handleCreate(%v) for %s found matching purge counter %d",
				config.UUIDandVersion, config.DisplayName, c)
		} else {
			log.Warnf("handleCreate(%v) for %s found different purge counter %d vs. %d",
				config.UUIDandVersion, config.DisplayName, c,
				config.PurgeCmd.Counter)
			status.PurgeCmd.Counter = config.PurgeCmd.Counter
			status.PurgeInprogress = types.RecreateVolumes
			status.State = types.PURGING
			// We persist the PurgeCmd Counter when
			// PurgeInprogress is done
		}
	} else {
		// Save this PurgeCmd.Counter as the baseline
		log.Infof("handleCreate(%v) for %s saving purge counter %d",
			config.UUIDandVersion, config.DisplayName,
			config.PurgeCmd.Counter)
		uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum,
			config.UUIDandVersion.UUID, int(config.PurgeCmd.Counter),
			true, "purgeCmdCounter")
	}

	var totalDiskUsage uint64
	status.StorageStatusList = make([]types.StorageStatus,
		len(config.StorageConfigList))
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		ss.UpdateFromStorageConfig(sc)
		if ss.IsContainer {
			// FIXME - We really need a top level flag to tell the app is
			//  a container. Deriving it from Storage seems hacky.
			status.IsContainer = true
		}
		if ss.MaxDownSize == 0 {
			log.Warnf("handleCreate(%s) zero size for %s",
				config.Key(), ss.Name)
		}
		totalDiskUsage += ss.MaxDownSize
	}

	status.EIDList = make([]types.EIDStatusDetails,
		len(config.OverlayNetworkList))

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

	if !ctx.globalConfig.GlobalValueBool(types.IgnoreDiskCheckForApps) {
		// Check disk usage
		remaining, appDiskSizeList, err := getRemainingAppDiskSpace(ctx)
		if err != nil {
			errStr := fmt.Sprintf("getRemainingAppDiskSpace failed: %s\n",
				err)
			allErrors += errStr
		} else if remaining < totalDiskUsage {
			errStr := fmt.Sprintf("Remaining disk space %d app needs %d\n",
				remaining, totalDiskUsage)
			allErrors += errStr
			errStr = fmt.Sprintf("Current app disk size list:\n%s\n",
				appDiskSizeList)
			allErrors += errStr
		}
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
		log.Infof("AppInstance(Name:%s, UUID:%s): handleCreate status change.",
			config.DisplayName, config.UUIDandVersion.UUID)
		publishAppInstanceStatus(ctx, &status)
	}
	log.Infof("handleCreate done for %s", config.DisplayName)
}

func maybeLatchImageSha(ctx *zedmanagerContext, config types.AppInstanceConfig,
	ssPtr *types.StorageStatus) {

	imageSha := lookupAppAndImageHash(ctx, config.UUIDandVersion.UUID,
		ssPtr.ImageID, ssPtr.PurgeCounter)
	if imageSha == "" {
		if ssPtr.IsContainer && ssPtr.ImageSha256 == "" {
			log.Infof("Container app/image %s %s/%s has not (yet) latched sha",
				config.DisplayName, config.UUIDandVersion.UUID,
				ssPtr.ImageID)
		}
		return
	}
	if ssPtr.ImageSha256 == "" {
		log.Infof("Latching %s app/image %s/%s to sha %s",
			config.DisplayName,
			config.UUIDandVersion.UUID, ssPtr.ImageID, imageSha)
		ssPtr.ImageSha256 = imageSha
		if ssPtr.IsContainer {
			newName := maybeInsertSha(ssPtr.Name, imageSha)
			if newName != ssPtr.Name {
				log.Infof("Changing container name from %s to %s",
					ssPtr.Name, newName)
				ssPtr.Name = newName
			}
		}
	} else if ssPtr.ImageSha256 != imageSha {
		// We already catch this change, but logging here in any case
		log.Warnf("App/Image %s %s/%s hash sha %s received %s",
			config.DisplayName,
			config.UUIDandVersion.UUID, ssPtr.ImageID,
			imageSha, ssPtr.ImageSha256)
	}
}

// Check if the OCI name does not include an explicit sha and if not
// return the name with the sha inserted.
// Note that the sha must be lower case in the OCI reference.
func maybeInsertSha(name string, sha string) string {
	if strings.Index(name, "@") != -1 {
		// Already has a sha
		return name
	}
	sha = strings.ToLower(sha)
	last := strings.LastIndex(name, ":")
	if last == -1 {
		return name + "@sha256:" + sha
	}
	return name[:last] + "@sha256:" + sha
}

func handleModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	config := configArg.(types.AppInstanceConfig)
	status := lookupAppInstanceStatus(ctx, key)
	log.Infof("handleModify(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	// We handle at least ACL and activate changes. XXX What else?
	// Not checking the version here; assume the microservices can handle
	// some updates.

	// We detect significant changes which require a reboot and/or
	// purge of disk changes, so we can generate errors if it is
	// not a PurgeCmd and RestartCmd, respectively
	// If we are purging then restart is redundant.
	needPurge, needRestart, purgeReason, restartReason := quantifyChanges(config, *status)
	if needPurge {
		needRestart = false
	}

	if config.RestartCmd.Counter != status.RestartCmd.Counter {

		log.Infof("handleModify(%v) for %s restartcmd from %d to %d "+
			"needRestart: %v",
			config.UUIDandVersion, config.DisplayName,
			status.RestartCmd.Counter, config.RestartCmd.Counter,
			needRestart)
		if config.Activate {
			// Will restart even if we crash/power cycle since that
			// would also restart the app. Hence we can update
			// the status counter here.
			status.RestartCmd.Counter = config.RestartCmd.Counter
			status.RestartInprogress = types.BringDown
			status.State = types.RESTARTING
		} else {
			log.Infof("handleModify(%v) for %s restartcmd ignored config !Activate",
				config.UUIDandVersion, config.DisplayName)
			status.RestartCmd.Counter = config.RestartCmd.Counter
		}
	} else if needRestart {
		errStr := fmt.Sprintf("Need restart due to %s but not a restartCmd",
			restartReason)
		log.Errorf("handleModify(%s) failed: %s", status.Key(), errStr)
		status.SetError(errStr, time.Now())
		publishAppInstanceStatus(ctx, status)
		return
	}

	if config.PurgeCmd.Counter != status.PurgeCmd.Counter {
		log.Infof("handleModify(%v) for %s purgecmd from %d to %d "+
			"needPurge: %v",
			config.UUIDandVersion, config.DisplayName,
			status.PurgeCmd.Counter, config.PurgeCmd.Counter,
			needPurge)
		if !ctx.globalConfig.GlobalValueBool(types.IgnoreDiskCheckForApps) {
			err := checkPurgeDiskSizeFit(ctx, config, *status)
			if err != nil {
				log.Error(err)
				status.SetErrorWithSource(err.Error(),
					types.AppInstanceStatus{}, time.Now())
				publishAppInstanceStatus(ctx, status)
				return
			}
		}
		if status.IsErrorSource(types.AppInstanceStatus{}) {
			log.Infof("Removing error %s", status.Error)
			status.ClearErrorWithSource()
		}
		status.PurgeCmd.Counter = config.PurgeCmd.Counter
		status.PurgeInprogress = types.RecreateVolumes
		status.State = types.PURGING
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
		log.Infof("handleModify status change for %s", status.Key())
		publishAppInstanceStatus(ctx, status)
	}
	status.FixedResources = config.FixedResources
	status.OverlayNetworkList = config.OverlayNetworkList
	status.UnderlayNetworkList = config.UnderlayNetworkList
	status.IoAdapterList = config.IoAdapterList
	publishAppInstanceStatus(ctx, status)
	log.Infof("handleModify done for %s", config.DisplayName)
}

// checkPurgeDiskSizeFit sees if a purge might exceed the remaining space
// Check for change in disk usage for StorageConfig and if increase see if
// sufficient space is available.
// If app instance is Activated then both old and new have to fit since we
// delete old volume after restarting app to minimize outage for application.
func checkPurgeDiskSizeFit(ctxPtr *zedmanagerContext, config types.AppInstanceConfig,
	status types.AppInstanceStatus) error {

	remaining, appDiskSizeList, err := getRemainingAppDiskSpace(ctxPtr)
	if err != nil {
		return fmt.Errorf("getRemainingAppDiskSpace failed: %s", err)
	}
	var oldDisk0Size, newDisk0Size uint64
	if len(config.StorageConfigList) > 0 {
		newDisk0Size = config.StorageConfigList[0].MaxDownSize
	}
	if len(status.StorageStatusList) > 0 {
		oldDisk0Size = status.StorageStatusList[0].MaxDownSize
	}
	if !status.Activated {
		if newDisk0Size > oldDisk0Size &&
			newDisk0Size-oldDisk0Size > remaining {
			errStr := fmt.Sprintf("Remaining disk space %d app needs %d to purge\n",
				remaining, newDisk0Size-oldDisk0Size)
			errStr += fmt.Sprintf("Current app disk size list:\n%s\n",
				appDiskSizeList)
			return errors.New(errStr)
		}
	} else {
		// The oldDisk0Size is already accounted for in remaining
		if newDisk0Size > remaining {
			errStr := fmt.Sprintf("Remaining disk space %d app needs %d to purge while Activated; deactivate then purge\n",
				remaining, newDisk0Size)
			errStr += fmt.Sprintf("Current app disk size list:\n%s\n",
				appDiskSizeList)
			return errors.New(errStr)
		}
	}
	return nil
}

func handleDelete(ctx *zedmanagerContext, key string,
	status *types.AppInstanceStatus) {

	log.Infof("handleDelete(%v) for %s",
		status.UUIDandVersion, status.DisplayName)

	removeAIStatus(ctx, status)
	// Remove the recorded PurgeCmd Counter
	uuidtonum.UuidToNumDelete(ctx.pubUuidToNum, status.UUIDandVersion.UUID)
	purgeAppAndImageHash(ctx, status.UUIDandVersion.UUID)
	log.Infof("handleDelete done for %s", status.DisplayName)
}

// Returns needRestart, needPurge, plus a string for each.
// If there is a change to the disks, adapters, or network interfaces
// it returns needPurge.
// If there is a change to the CPU etc resources it returns needRestart
// Changes to ACLs don't result in either being returned.
func quantifyChanges(config types.AppInstanceConfig,
	status types.AppInstanceStatus) (bool, bool, string, string) {

	needPurge := false
	needRestart := false
	var purgeReason, restartReason string
	log.Infof("quantifyChanges for %s %s",
		config.Key(), config.DisplayName)
	if len(status.StorageStatusList) != len(config.StorageConfigList) {
		str := fmt.Sprintf("number of volumes changed from %d to %d",
			len(status.StorageStatusList),
			len(config.StorageConfigList))
		log.Infof(str)
		needPurge = true
		purgeReason += str + "\n"
	} else {
		for _, sc := range config.StorageConfigList {
			ss := lookupStorageStatus(&status, sc)
			if ss == nil {
				str := fmt.Sprintf("missing StorageStatus for (Name: %s, "+
					"ImageSha256: %s, ImageID: %s, PurgeCounter: %d)",
					sc.Name, sc.ImageSha256, sc.ImageID, sc.PurgeCounter)
				log.Errorf(str)
				needPurge = true
				purgeReason += str + "\n"
				continue
			}
			if ss.ImageID != sc.ImageID {
				str := fmt.Sprintf("storage imageID changed from %s to %s",
					ss.ImageID, sc.ImageID)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if ss.ReadOnly != sc.ReadOnly {
				str := fmt.Sprintf("storage ReadOnly changed from %v to %v for %s",
					ss.ReadOnly, sc.ReadOnly, ss.ImageID)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if ss.Format != sc.Format {
				str := fmt.Sprintf("storage Format changed from %v to %v for %s",
					ss.Format, sc.Format, ss.ImageID)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if ss.MaxVolSize != sc.MaxVolSize {
				str := fmt.Sprintf("storage MaxVolSize changed from %v to %v for %s",
					ss.MaxVolSize, sc.MaxVolSize, ss.ImageID)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if ss.Devtype != sc.Devtype {
				str := fmt.Sprintf("storage Devtype changed from %v to %v for %s",
					ss.Devtype, sc.Devtype, ss.ImageID)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
		}
	}
	// Compare networks without comparing ACLs
	if len(status.OverlayNetworkList) != len(config.OverlayNetworkList) {
		str := fmt.Sprintf("number of overlay interfaces changed from %d to %d",
			len(status.OverlayNetworkList),
			len(config.OverlayNetworkList))
		log.Infof(str)
		needPurge = true
		purgeReason += str + "\n"
	} else {
		for i, oc := range config.OverlayNetworkList {
			os := status.OverlayNetworkList[i]
			if !cmp.Equal(oc.EIDConfigDetails, os.EIDConfigDetails) {
				str := fmt.Sprintf("EIDConfigDetails changed: %v",
					cmp.Diff(oc.EIDConfigDetails, os.EIDConfigDetails))
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if os.AppMacAddr.String() != oc.AppMacAddr.String() {
				str := fmt.Sprintf("AppMacAddr changed from %v to %v",
					os.AppMacAddr, oc.AppMacAddr)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if !os.AppIPAddr.Equal(oc.AppIPAddr) {
				str := fmt.Sprintf("AppIPAddr changed from %v to %v",
					os.AppIPAddr, oc.AppIPAddr)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if os.Network != oc.Network {
				str := fmt.Sprintf("Network changed from %v to %v",
					os.Network, oc.Network)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if !cmp.Equal(oc.ACLs, os.ACLs) {
				log.Infof("FYI ACLs changed: %v",
					cmp.Diff(oc.ACLs, os.ACLs))
			}
		}
	}
	if len(status.UnderlayNetworkList) != len(config.UnderlayNetworkList) {
		str := fmt.Sprintf("number of underlay interfaces changed from %d to %d",
			len(status.UnderlayNetworkList),
			len(config.UnderlayNetworkList))
		log.Infof(str)
		needPurge = true
		purgeReason += str + "\n"
	} else {
		for i, uc := range config.UnderlayNetworkList {
			us := status.UnderlayNetworkList[i]
			if us.AppMacAddr.String() != uc.AppMacAddr.String() {
				str := fmt.Sprintf("AppMacAddr changed from %v to %v",
					us.AppMacAddr, uc.AppMacAddr)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if !us.AppIPAddr.Equal(uc.AppIPAddr) {
				str := fmt.Sprintf("AppIPAddr changed from %v to %v",
					us.AppIPAddr, uc.AppIPAddr)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if us.Network != uc.Network {
				str := fmt.Sprintf("Network changed from %v to %v",
					us.Network, uc.Network)
				log.Infof(str)
				needPurge = true
				purgeReason += str + "\n"
			}
			if !cmp.Equal(uc.ACLs, us.ACLs) {
				log.Infof("FYI ACLs changed: %v",
					cmp.Diff(uc.ACLs, us.ACLs))
			}
		}
	}
	if !cmp.Equal(config.IoAdapterList, status.IoAdapterList) {
		str := fmt.Sprintf("IoAdapterList changed: %v",
			cmp.Diff(config.IoAdapterList, status.IoAdapterList))
		log.Infof(str)
		needPurge = true
		purgeReason += str + "\n"
	}
	if !cmp.Equal(config.FixedResources, status.FixedResources) {
		str := fmt.Sprintf("FixedResources changed: %v",
			cmp.Diff(config.FixedResources, status.FixedResources))
		log.Infof(str)
		needRestart = true
		restartReason += str + "\n"
	}
	log.Infof("quantifyChanges for %s %s returns %v, %v",
		config.Key(), config.DisplayName, needPurge, needRestart)
	return needPurge, needRestart, purgeReason, restartReason
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Infof("handleGlobalConfigDelete done for %s", key)
}
