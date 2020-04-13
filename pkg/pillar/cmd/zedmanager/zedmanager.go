// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Get AppInstanceConfig from zedagent, drive config to VolumeMgr,
// IdentityMgr, and Zedrouter. Collect status from those services and make
// the combined AppInstanceStatus available to zedagent.

package zedmanager

import (
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
	subAppInstanceConfig pubsub.Subscription
	pubAppInstanceStatus pubsub.Publication
	pubVolumeConfig      pubsub.Publication
	subVolumeStatus      pubsub.Subscription
	pubAppNetworkConfig  pubsub.Publication
	subAppNetworkStatus  pubsub.Subscription
	pubDomainConfig      pubsub.Publication
	subDomainStatus      pubsub.Subscription
	pubEIDConfig         pubsub.Publication
	subEIDStatus         pubsub.Subscription
	subGlobalConfig      pubsub.Subscription
	globalConfig         *types.ConfigItemValueMap
	pubUuidToNum         pubsub.Publication
	pubAppAndImageToHash pubsub.Publication
	GCInitialized        bool
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
	log.Infof("Starting %s\n", agentName)

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
		TopicType:  types.VolumeConfig{},
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
		TopicImpl:     types.VolumeStatus{},
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
	log.Infof("Handling all inputs\n")
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

	log.Infof("handleConfigRestart(%v)\n", done)
	if done {
		ctx.pubEIDConfig.SignalRestarted()
	}
}

func handleIdentitymgrRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Infof("handleIdentitymgrRestarted(%v)\n", done)
	if done {
		ctx.pubAppNetworkConfig.SignalRestarted()
	}
}

func handleZedrouterRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Infof("handleZedrouterRestarted(%v)\n", done)
	if done {
		ctx.pubDomainConfig.SignalRestarted()
	}
}

func publishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Debugf("publishAppInstanceStatus(%s)\n", key)
	pub := ctx.pubAppInstanceStatus
	pub.Publish(key, *status)
}

func unpublishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Debugf("unpublishAppInstanceStatus(%s)\n", key)
	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishAppInstanceStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleAppInstanceConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := lookupAppInstanceStatus(ctx, key)
	if status == nil {
		log.Infof("handleAppInstanceConfigDelete: unknown %s\n", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Infof("handleAppInstanceConfigDelete(%s) done\n", key)
}

// Callers must be careful to publish any changes to AppInstanceStatus
func lookupAppInstanceStatus(ctx *zedmanagerContext, key string) *types.AppInstanceStatus {

	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupAppInstanceStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.AppInstanceStatus)
	return &status
}

func lookupAppInstanceConfig(ctx *zedmanagerContext, key string) *types.AppInstanceConfig {

	sub := ctx.subAppInstanceConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupAppInstanceConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.AppInstanceConfig)
	return &config
}

func handleCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	config := configArg.(types.AppInstanceConfig)

	log.Infof("handleCreate(%v) for %s\n",
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
	}

	// Do we have a PurgeCmd counter from before the reboot?
	c, err := uuidtonum.UuidToNumGet(ctx.pubUuidToNum,
		config.UUIDandVersion.UUID, "purgeCmdCounter")
	if err == nil {
		if uint32(c) == status.PurgeCmd.Counter {
			log.Infof("handleCreate(%v) for %s found matching purge counter %d\n",
				config.UUIDandVersion, config.DisplayName, c)
		} else {
			log.Warnf("handleCreate(%v) for %s found different purge counter %d vs. %d\n",
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
		log.Infof("handleCreate(%v) for %s saving purge counter %d\n",
			config.UUIDandVersion, config.DisplayName,
			config.PurgeCmd.Counter)
		uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum,
			config.UUIDandVersion.UUID, int(config.PurgeCmd.Counter),
			true, "purgeCmdCounter")
	}

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
		// XXX before latching we should ResolveConfig to get the sha
		maybeLatchImageSha(ctx, config, ss)
	}

	status.EIDList = make([]types.EIDStatusDetails,
		len(config.OverlayNetworkList))

	if len(config.Errors) > 0 {
		// Combine all errors from Config parsing state and send them in Status
		status.Error = ""
		for i, errStr := range config.Errors {
			status.Error += errStr
			log.Errorf("App Instance %s-%s: Error(%d): %s",
				config.DisplayName, config.UUIDandVersion.UUID, i, errStr)
		}
		log.Errorf("App Instance %s-%s: Errors in App Instance Create.",
			config.DisplayName, config.UUIDandVersion.UUID)
	}

	// Do some basic sanity checks.
	if config.FixedResources.Memory == 0 {
		errStr := "Invalid Memory Size - 0\n"
		status.Error += errStr
	}
	if config.FixedResources.VCpus == 0 {
		errStr := "Invalid Cpu count - 0\n"
		status.Error += errStr
	}
	if status.Error != "" {
		status.SetError(status.Error, "Zedmanager Create Handler",
			time.Now())
	}
	publishAppInstanceStatus(ctx, &status)

	// if some error, return
	if status.Error != "" {
		log.Errorf("AppInstance(Name:%s, UUID:%s): Errors in App Instance "+
			"Create. Error: %s",
			config.DisplayName, config.UUIDandVersion.UUID, status.Error)
		return
	}

	// If there are no errors, go ahead with Instance creation.
	changed := doUpdate(ctx, config, &status)
	if changed {
		log.Infof("AppInstance(Name:%s, UUID:%s): handleCreate status change.",
			config.DisplayName, config.UUIDandVersion.UUID)
		publishAppInstanceStatus(ctx, &status)
	}
	log.Infof("handleCreate done for %s\n", config.DisplayName)
}

func maybeLatchImageSha(ctx *zedmanagerContext, config types.AppInstanceConfig,
	ssPtr *types.StorageStatus) {

	imageSha := lookupAppAndImageHash(ctx, config.UUIDandVersion.UUID,
		ssPtr.ImageID)
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
	log.Infof("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// We handle at least ACL and activate changes. XXX What else?
	// Not checking the version here; assume the microservices can handle
	// some updates.

	// We detect significant changes which require a reboot and/or
	// purge of disk changes, so we can generate errors if it is
	// not a PurgeCmd and RestartCmd, respectively
	needPurge, needRestart := quantifyChanges(config, *status)

	if config.RestartCmd.Counter != status.RestartCmd.Counter {

		log.Infof("handleModify(%v) for %s restartcmd from %d to %d "+
			"needRestart: %v\n",
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
			log.Infof("handleModify(%v) for %s restartcmd ignored config !Activate\n",
				config.UUIDandVersion, config.DisplayName)
			status.RestartCmd.Counter = config.RestartCmd.Counter
		}
	} else if needRestart {
		errStr := "Need restart due to change but not a restartCmd"
		log.Errorf("handleModify(%s) failed: %s", status.Key(), errStr)
		status.SetError(errStr, "", time.Now())
		publishAppInstanceStatus(ctx, status)
		return
	}

	if config.PurgeCmd.Counter != status.PurgeCmd.Counter {
		log.Infof("handleModify(%v) for %s purgecmd from %d to %d "+
			"needPurge: %v\n",
			config.UUIDandVersion, config.DisplayName,
			status.PurgeCmd.Counter, config.PurgeCmd.Counter,
			needPurge)
		status.PurgeCmd.Counter = config.PurgeCmd.Counter
		status.PurgeInprogress = types.RecreateVolumes
		status.State = types.PURGING
		// We persist the PurgeCmd Counter when PurgeInprogress is done
	} else if needPurge {
		errStr := "Need purge due to change but not a purgeCmd"
		log.Errorf("handleModify(%s) failed: %s", status.Key(), errStr)
		status.SetError(errStr, "", time.Now())
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
	log.Infof("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(ctx *zedmanagerContext, key string,
	status *types.AppInstanceStatus) {

	log.Infof("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	removeAIStatus(ctx, status)
	// Remove the recorded PurgeCmd Counter
	uuidtonum.UuidToNumDelete(ctx.pubUuidToNum, status.UUIDandVersion.UUID)
	purgeAppAndImageHash(ctx, status.UUIDandVersion.UUID)
	log.Infof("handleDelete done for %s\n", status.DisplayName)
}

// Returns needRestart, needPurge
// If there is a change to the disks, adapters, or network interfaces
// it returns needPurge.
// If there is a change to the CPU etc resources it returns needRestart
// Changes to ACLs don't result in either being returned.
func quantifyChanges(config types.AppInstanceConfig,
	status types.AppInstanceStatus) (bool, bool) {

	needPurge := false
	needRestart := false
	log.Infof("quantifyChanges for %s %s\n",
		config.Key(), config.DisplayName)
	if len(status.StorageStatusList) != len(config.StorageConfigList) {
		log.Infof("quantifyChanges len storage changed from %d to %d\n",
			len(status.StorageStatusList),
			len(config.StorageConfigList))
		needPurge = true
	} else {
		for _, sc := range config.StorageConfigList {
			ss := lookupStorageStatus(&status, sc)
			if ss == nil {
				log.Errorf("quantifyChanges missing StorageStatus for (Name: %s, "+
					"ImageSha256: %s, ImageID: %s, PurgeCounter: %d)",
					sc.Name, sc.ImageSha256, sc.ImageID, sc.PurgeCounter)
				needPurge = true
				continue
			}
			if ss.ImageID != sc.ImageID {
				log.Infof("quantifyChanges storage imageID changed from %s to %s\n",
					ss.ImageID, sc.ImageID)
				needPurge = true
			}
			if ss.ReadOnly != sc.ReadOnly {
				log.Infof("quantifyChanges storage ReadOnly changed from %v to %v\n",
					ss.ReadOnly, sc.ReadOnly)
				needPurge = true
			}
			if ss.Preserve != sc.Preserve {
				log.Infof("quantifyChanges storage Preserve changed from %v to %v\n",
					ss.Preserve, sc.Preserve)
				needPurge = true
			}
			if ss.Format != sc.Format {
				log.Infof("quantifyChanges storage Format changed from %v to %v\n",
					ss.Format, sc.Format)
				needPurge = true
			}
			if ss.Maxsizebytes != sc.Maxsizebytes {
				log.Infof("quantifyChanges storage Maxsizebytes changed from %v to %v\n",
					ss.Maxsizebytes, sc.Maxsizebytes)
				needPurge = true
			}
			if ss.Devtype != sc.Devtype {
				log.Infof("quantifyChanges storage Devtype changed from %v to %v\n",
					ss.Devtype, sc.Devtype)
				needPurge = true
			}
		}
	}
	// Compare networks without comparing ACLs
	if len(status.OverlayNetworkList) != len(config.OverlayNetworkList) {
		log.Infof("quantifyChanges len storage changed from %d to %d\n",
			len(status.OverlayNetworkList),
			len(config.OverlayNetworkList))
		needPurge = true
	} else {
		for i, oc := range config.OverlayNetworkList {
			os := status.OverlayNetworkList[i]
			if !cmp.Equal(oc.EIDConfigDetails, os.EIDConfigDetails) {
				log.Infof("quantifyChanges EIDConfigDetails changed: %v\n",
					cmp.Diff(oc.EIDConfigDetails, os.EIDConfigDetails))
				needPurge = true
			}
			if os.AppMacAddr.String() != oc.AppMacAddr.String() {
				log.Infof("quantifyChanges AppMacAddr changed from %v to %v\n",
					os.AppMacAddr, oc.AppMacAddr)
				needPurge = true
			}
			if !os.AppIPAddr.Equal(oc.AppIPAddr) {
				log.Infof("quantifyChanges AppIPAddr changed from %v to %v\n",
					os.AppIPAddr, oc.AppIPAddr)
				needPurge = true
			}
			if os.Network != oc.Network {
				log.Infof("quantifyChanges Network changed from %v to %v\n",
					os.Network, oc.Network)
				needPurge = true
			}
			if !cmp.Equal(oc.ACLs, os.ACLs) {
				log.Infof("quantifyChanges FYI ACLs changed: %v\n",
					cmp.Diff(oc.ACLs, os.ACLs))
			}
		}
	}
	if len(status.UnderlayNetworkList) != len(config.UnderlayNetworkList) {
		log.Infof("quantifyChanges len storage changed from %d to %d\n",
			len(status.UnderlayNetworkList),
			len(config.UnderlayNetworkList))
		needPurge = true
	} else {
		for i, uc := range config.UnderlayNetworkList {
			us := status.UnderlayNetworkList[i]
			if us.AppMacAddr.String() != uc.AppMacAddr.String() {
				log.Infof("quantifyChanges AppMacAddr changed from %v to %v\n",
					us.AppMacAddr, uc.AppMacAddr)
				needPurge = true
			}
			if !us.AppIPAddr.Equal(uc.AppIPAddr) {
				log.Infof("quantifyChanges AppIPAddr changed from %v to %v\n",
					us.AppIPAddr, uc.AppIPAddr)
				needPurge = true
			}
			if us.Network != uc.Network {
				log.Infof("quantifyChanges Network changed from %v to %v\n",
					us.Network, uc.Network)
				needPurge = true
			}
			if !cmp.Equal(uc.ACLs, us.ACLs) {
				log.Infof("quantifyChanges FYI ACLs changed: %v\n",
					cmp.Diff(uc.ACLs, us.ACLs))
			}
		}
	}
	if !cmp.Equal(config.IoAdapterList, status.IoAdapterList) {
		log.Infof("quantifyChanges IoAdapterList changed: %v\n",
			cmp.Diff(config.IoAdapterList, status.IoAdapterList))
		needPurge = true
	}
	if !cmp.Equal(config.FixedResources, status.FixedResources) {
		log.Infof("quantifyChanges FixedResources changed: %v\n",
			cmp.Diff(config.FixedResources, status.FixedResources))
		needRestart = true
	}
	log.Infof("quantifyChanges for %s %s returns %v, %v\n",
		config.Key(), config.DisplayName, needPurge, needRestart)
	return needPurge, needRestart
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}
