// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Get AppInstanceConfig from zedagent, drive config to Downloader, Verifier,
// IdentityMgr, and Zedrouter. Collect status from those services and make
// the combined AppInstanceStatus available to zedagent.

package zedmanager

import (
	"flag"
	"fmt"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"os"
)

const (
	appImgObj = "appImg.obj"
	certObj   = "cert.obj"
	agentName = "zedmanager"

	certificateDirname = persistDir + "/certs"
)

// Set from Makefile
var Version = "No version specified"

// State used by handlers
type zedmanagerContext struct {
	configRestarted         bool
	verifierRestarted       bool
	subAppInstanceConfig    *pubsub.Subscription
	pubAppInstanceStatus    *pubsub.Publication
	subDeviceNetworkStatus  *pubsub.Subscription
	pubAppNetworkConfig     *pubsub.Publication
	subAppNetworkStatus     *pubsub.Subscription
	pubDomainConfig         *pubsub.Publication
	subDomainStatus         *pubsub.Subscription
	pubEIDConfig            *pubsub.Publication
	subEIDStatus            *pubsub.Subscription
	subCertObjStatus        *pubsub.Subscription
	pubAppImgDownloadConfig *pubsub.Publication
	subAppImgDownloadStatus *pubsub.Subscription
	pubAppImgVerifierConfig *pubsub.Publication
	subAppImgVerifierStatus *pubsub.Subscription
	subDatastoreConfig      *pubsub.Subscription
	subGlobalConfig         *pubsub.Subscription
}

var deviceNetworkStatus types.DeviceNetworkStatus

var debug = false
var debugOverride bool // From command line arg

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)

	// Any state needed by handler functions
	ctx := zedmanagerContext{}

	// Create publish before subscribing and activating subscriptions
	pubAppInstanceStatus, err := pubsub.PublishWithDebug(agentName,
		types.AppInstanceStatus{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppInstanceStatus = pubAppInstanceStatus
	pubAppInstanceStatus.ClearRestarted()

	pubAppNetworkConfig, err := pubsub.PublishWithDebug(agentName,
		types.AppNetworkConfig{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppNetworkConfig = pubAppNetworkConfig
	pubAppNetworkConfig.ClearRestarted()

	pubDomainConfig, err := pubsub.PublishWithDebug(agentName,
		types.DomainConfig{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubDomainConfig = pubDomainConfig
	pubDomainConfig.ClearRestarted()

	pubEIDConfig, err := pubsub.PublishWithDebug(agentName,
		types.EIDConfig{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubEIDConfig = pubEIDConfig
	pubEIDConfig.ClearRestarted()

	pubAppImgDownloadConfig, err := pubsub.PublishScopeWithDebug(agentName,
		appImgObj, types.DownloaderConfig{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	pubAppImgDownloadConfig.ClearRestarted()
	ctx.pubAppImgDownloadConfig = pubAppImgDownloadConfig

	pubAppImgVerifierConfig, err := pubsub.PublishScopeWithDebug(agentName,
		appImgObj, types.VerifyImageConfig{}, &debug)
	if err != nil {
		log.Fatal(err)
	}
	pubAppImgVerifierConfig.ClearRestarted()
	ctx.pubAppImgVerifierConfig = pubAppImgVerifierConfig

	// Look for global config like debug
	subGlobalConfig, err := pubsub.SubscribeWithDebug("",
		agentlog.GlobalConfig{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Get AppInstanceConfig from zedagent
	subAppInstanceConfig, err := pubsub.SubscribeWithDebug("zedagent",
		types.AppInstanceConfig{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subAppInstanceConfig.ModifyHandler = handleAppInstanceConfigModify
	subAppInstanceConfig.DeleteHandler = handleAppInstanceConfigDelete
	subAppInstanceConfig.RestartHandler = handleConfigRestart
	ctx.subAppInstanceConfig = subAppInstanceConfig
	subAppInstanceConfig.Activate()

	// Look for DatastoreConfig from zedagent
	// No handlers since we look at collection when we need to
	subDatastoreConfig, err := pubsub.SubscribeWithDebug("zedagent",
		types.DatastoreConfig{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subDatastoreConfig.ModifyHandler = handleDatastoreConfigModify
	subDatastoreConfig.DeleteHandler = handleDatastoreConfigDelete
	ctx.subDatastoreConfig = subDatastoreConfig
	subDatastoreConfig.Activate()

	// Get AppNetworkStatus from zedrouter
	subAppNetworkStatus, err := pubsub.SubscribeWithDebug("zedrouter",
		types.AppNetworkStatus{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subAppNetworkStatus.ModifyHandler = handleAppNetworkStatusModify
	subAppNetworkStatus.DeleteHandler = handleAppNetworkStatusDelete
	subAppNetworkStatus.RestartHandler = handleZedrouterRestarted
	ctx.subAppNetworkStatus = subAppNetworkStatus
	subAppNetworkStatus.Activate()

	// Get DomainStatus from domainmgr
	subDomainStatus, err := pubsub.SubscribeWithDebug("domainmgr",
		types.DomainStatus{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subDomainStatus.ModifyHandler = handleDomainStatusModify
	subDomainStatus.DeleteHandler = handleDomainStatusDelete
	ctx.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	// Look for DownloaderStatus from downloader
	subAppImgDownloadStatus, err := pubsub.SubscribeScopeWithDebug("downloader",
		appImgObj, types.DownloaderStatus{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgDownloadStatus.ModifyHandler = handleDownloaderStatusModify
	subAppImgDownloadStatus.DeleteHandler = handleDownloaderStatusDelete
	ctx.subAppImgDownloadStatus = subAppImgDownloadStatus
	subAppImgDownloadStatus.Activate()

	// Look for VerifyImageStatus from verifier
	subAppImgVerifierStatus, err := pubsub.SubscribeScopeWithDebug("verifier",
		appImgObj, types.VerifyImageStatus{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgVerifierStatus.ModifyHandler = handleVerifyImageStatusModify
	subAppImgVerifierStatus.DeleteHandler = handleVerifyImageStatusDelete
	subAppImgVerifierStatus.RestartHandler = handleVerifierRestarted
	ctx.subAppImgVerifierStatus = subAppImgVerifierStatus
	subAppImgVerifierStatus.Activate()

	// Get IdentityStatus from identitymgr
	subEIDStatus, err := pubsub.SubscribeWithDebug("identitymgr",
		types.EIDStatus{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subEIDStatus.ModifyHandler = handleEIDStatusModify
	subEIDStatus.DeleteHandler = handleEIDStatusDelete
	subEIDStatus.RestartHandler = handleIdentitymgrRestarted
	ctx.subEIDStatus = subEIDStatus
	subEIDStatus.Activate()

	subDeviceNetworkStatus, err := pubsub.SubscribeWithDebug("zedrouter",
		types.DeviceNetworkStatus{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Look for CertObjStatus from zedagent
	subCertObjStatus, err := pubsub.SubscribeWithDebug("zedagent",
		types.CertObjStatus{}, false, &ctx, &debug)
	if err != nil {
		log.Fatal(err)
	}
	subCertObjStatus.ModifyHandler = handleCertObjStatusModify
	subCertObjStatus.DeleteHandler = handleCertObjStatusDelete
	ctx.subCertObjStatus = subCertObjStatus
	subCertObjStatus.Activate()

	// First we process the verifierStatus to avoid downloading
	// an image we already have in place.
	log.Printf("Handling initial verifier Status\n")
	for !ctx.verifierRestarted {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subAppImgVerifierStatus.C:
			subAppImgVerifierStatus.ProcessChange(change)
			if ctx.verifierRestarted {
				log.Printf("Verifier reported restarted\n")
			}
		}
	}

	log.Printf("Handling all inputs\n")
	for {
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		// handle cert ObjectsChanges
		case change := <-subCertObjStatus.C:
			subCertObjStatus.ProcessChange(change)

		case change := <-subAppImgDownloadStatus.C:
			subAppImgDownloadStatus.ProcessChange(change)

		case change := <-subAppImgVerifierStatus.C:
			subAppImgVerifierStatus.ProcessChange(change)

		case change := <-subEIDStatus.C:
			subEIDStatus.ProcessChange(change)

		case change := <-subAppNetworkStatus.C:
			subAppNetworkStatus.ProcessChange(change)

		case change := <-subDomainStatus.C:
			subDomainStatus.ProcessChange(change)

		case change := <-subAppInstanceConfig.C:
			subAppInstanceConfig.ProcessChange(change)

		case change := <-subDatastoreConfig.C:
			subDatastoreConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
		}
	}
}

// After zedagent has waited for its config and set restarted for
// AppInstanceConfig (which triggers this callback) we propagate a sequence of
// restarts so that the agents don't do extra work.
// We propagate a seqence of restarted from the zedmanager config
// and verifier status to identitymgr, then from identitymgr to zedrouter,
// and finally from zedrouter to domainmgr.
// This removes the need for extra downloads/verifications and extra copying
// of the rootfs in domainmgr.
func handleConfigRestart(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Printf("handleConfigRestart(%v)\n", done)
	if done {
		ctx.configRestarted = true
		if ctx.verifierRestarted {
			ctx.pubEIDConfig.SignalRestarted()
		}
	}
}

func handleVerifierRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Printf("handleVerifierRestarted(%v)\n", done)
	if done {
		ctx.verifierRestarted = true
		if ctx.configRestarted {
			ctx.pubEIDConfig.SignalRestarted()
		}
	}
}

func handleIdentitymgrRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Printf("handleIdentitymgrRestarted(%v)\n", done)
	if done {
		ctx.pubAppNetworkConfig.SignalRestarted()
	}
}

func handleZedrouterRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Printf("handleZedrouterRestarted(%v)\n", done)
	if done {
		ctx.pubDomainConfig.SignalRestarted()
	}
}

func publishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Printf("publishAppInstanceStatus(%s)\n", key)
	pub := ctx.pubAppInstanceStatus
	pub.Publish(key, status)
}

func unpublishAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Printf("unpublishAppInstanceStatus(%s)\n", key)
	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("unpublishAppInstanceStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

// Determine whether it is an create or modify
func handleAppInstanceConfigModify(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("handleAppInstanceConfigModify(%s)\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	config := cast.CastAppInstanceConfig(configArg)
	if config.Key() != key {
		log.Printf("handleAppInstanceConfigModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	status := lookupAppInstanceStatus(ctx, key)
	if status == nil {
		handleCreate(ctx, key, config)
	} else {
		handleModify(ctx, key, config, status)
	}
	log.Printf("handleAppInstanceConfigModify(%s) done\n", key)
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Printf("handleAppInstanceConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := lookupAppInstanceStatus(ctx, key)
	if status == nil {
		log.Printf("handleAppInstanceConfigDelete: unknown %s\n", key)
		return
	}
	handleDelete(ctx, key, status)
	log.Printf("handleAppInstanceConfigDelete(%s) done\n", key)
}

// Callers must be careful to publish any changes to NetworkObjectStatus
func lookupAppInstanceStatus(ctx *zedmanagerContext, key string) *types.AppInstanceStatus {

	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("lookupAppInstanceStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastAppInstanceStatus(st)
	if status.Key() != key {
		log.Printf("lookupAppInstanceStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func lookupAppInstanceConfig(ctx *zedmanagerContext, key string) *types.AppInstanceConfig {

	sub := ctx.subAppInstanceConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Printf("lookupAppInstanceConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastAppInstanceConfig(c)
	if config.Key() != key {
		log.Printf("lookupAppInstanceConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func handleCreate(ctx *zedmanagerContext, key string,
	config types.AppInstanceConfig) {

	log.Printf("handleCreate(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	status := types.AppInstanceStatus{
		UUIDandVersion:      config.UUIDandVersion,
		DisplayName:         config.DisplayName,
		FixedResources:      config.FixedResources,
		OverlayNetworkList:  config.OverlayNetworkList,
		UnderlayNetworkList: config.UnderlayNetworkList,
		IoAdapterList:       config.IoAdapterList,
	}

	status.StorageStatusList = make([]types.StorageStatus,
		len(config.StorageConfigList))
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		ss.Name = sc.Name
		ss.ImageSha256 = sc.ImageSha256
		ss.ReadOnly = sc.ReadOnly
		ss.Preserve = sc.Preserve
		ss.Format = sc.Format
		ss.Devtype = sc.Devtype
		ss.Target = sc.Target
	}
	status.EIDList = make([]types.EIDStatusDetails,
		len(config.OverlayNetworkList))

	publishAppInstanceStatus(ctx, &status)

	uuidStr := status.Key()
	changed := doUpdate(ctx, uuidStr, config, &status)
	if changed {
		log.Printf("handleCreate status change for %s\n",
			uuidStr)
		publishAppInstanceStatus(ctx, &status)
	}
	log.Printf("handleCreate done for %s\n", config.DisplayName)
}

func handleModify(ctx *zedmanagerContext, key string,
	config types.AppInstanceConfig, status *types.AppInstanceStatus) {
	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	// XXX handle at least ACL and activate changes. What else?
	// Not checking the version here; assume the microservices can handle
	// some updates.

	// XXX detect significant changes which require a reboot and/or
	// purge of disk changes
	needPurge, needReboot := quantifyChanges(config, *status)
	log.Printf("handleModify needReboot %v needPurge %v\n",
		needReboot, needPurge)

	status.UUIDandVersion = config.UUIDandVersion
	publishAppInstanceStatus(ctx, status)

	uuidStr := status.Key()
	changed := doUpdate(ctx, uuidStr, config, status)
	if changed {
		log.Printf("handleModify status change for %s\n",
			uuidStr)
		publishAppInstanceStatus(ctx, status)
	}
	status.FixedResources = config.FixedResources
	status.OverlayNetworkList = config.OverlayNetworkList
	status.UnderlayNetworkList = config.UnderlayNetworkList
	status.IoAdapterList = config.IoAdapterList
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(ctx *zedmanagerContext, key string,
	status *types.AppInstanceStatus) {

	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	removeAIStatus(ctx, status)
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}

// Returns needReboot, needPurge
// XXX return an enum instead?
// If there is a change to the disks, adapters, or network interfaces
// it returns needPurge.
// If there is a change to the CPU etc resources it returns needReboot
// Changes to ACLs don't result in either being returned.
func quantifyChanges(config types.AppInstanceConfig,
	status types.AppInstanceStatus) (bool, bool) {

	needPurge := false
	needReboot := false
	log.Printf("quantifyChanges for %s %s\n",
		config.Key(), config.DisplayName)
	if len(status.StorageStatusList) != len(config.StorageConfigList) {
		log.Printf("quantifyChanges len storage changed from %d to %d\n",
			len(status.StorageStatusList),
			len(config.StorageConfigList))
		needPurge = true
	} else {
		for i, sc := range config.StorageConfigList {
			ss := status.StorageStatusList[i]
			if ss.ImageSha256 != sc.ImageSha256 {
				log.Printf("quantifyChanges storage sha changed from %s to %s\n",
					ss.ImageSha256, sc.ImageSha256)
				needPurge = true
			}
			if ss.ReadOnly != sc.ReadOnly {
				log.Printf("quantifyChanges storage ReadOnly changed from %v to %v\n",
					ss.ReadOnly, sc.ReadOnly)
				needPurge = true
			}
			if ss.Preserve != sc.Preserve {
				log.Printf("quantifyChanges storage Preserve changed from %v to %v\n",
					ss.Preserve, sc.Preserve)
				needPurge = true
			}
			if ss.Format != sc.Format {
				log.Printf("quantifyChanges storage Format changed from %v to %v\n",
					ss.Format, sc.Format)
				needPurge = true
			}
			if ss.Devtype != sc.Devtype {
				log.Printf("quantifyChanges storage Devtype changed from %v to %v\n",
					ss.Devtype, sc.Devtype)
				needPurge = true
			}
		}
	}
	// Compare networks without comparing ACLs
	if len(status.OverlayNetworkList) != len(config.OverlayNetworkList) {
		log.Printf("quantifyChanges len storage changed from %d to %d\n",
			len(status.OverlayNetworkList),
			len(config.OverlayNetworkList))
		needPurge = true
	} else {
		for i, oc := range config.OverlayNetworkList {
			os := status.OverlayNetworkList[i]
			if !cmp.Equal(oc.EIDConfigDetails, os.EIDConfigDetails) {
				log.Printf("quantifyChanges EIDConfigDetails changed: %v\n",
					cmp.Diff(oc.EIDConfigDetails, os.EIDConfigDetails))
				needPurge = true
			}
			if os.AppMacAddr.String() != oc.AppMacAddr.String() {
				log.Printf("quantifyChanges AppMacAddr changed from %v to %v\n",
					os.AppMacAddr, oc.AppMacAddr)
				needPurge = true
			}
			if !os.AppIPAddr.Equal(oc.AppIPAddr) {
				log.Printf("quantifyChanges AppIPAddr changed from %v to %v\n",
					os.AppIPAddr, oc.AppIPAddr)
				needPurge = true
			}
			if os.Network != oc.Network {
				log.Printf("quantifyChanges Network changed from %v to %v\n",
					os.Network, oc.Network)
				needPurge = true
			}
			if !cmp.Equal(oc.ACLs, os.ACLs) {
				log.Printf("quantifyChanges FYI ACLs changed: %v\n",
					cmp.Diff(oc.ACLs, os.ACLs))
			}
		}
	}
	if len(status.UnderlayNetworkList) != len(config.UnderlayNetworkList) {
		log.Printf("quantifyChanges len storage changed from %d to %d\n",
			len(status.UnderlayNetworkList),
			len(config.UnderlayNetworkList))
		needPurge = true
	} else {
		for i, uc := range config.UnderlayNetworkList {
			us := status.UnderlayNetworkList[i]
			if us.AppMacAddr.String() != uc.AppMacAddr.String() {
				log.Printf("quantifyChanges AppMacAddr changed from %v to %v\n",
					us.AppMacAddr, uc.AppMacAddr)
				needPurge = true
			}
			if !us.AppIPAddr.Equal(uc.AppIPAddr) {
				log.Printf("quantifyChanges AppIPAddr changed from %v to %v\n",
					us.AppIPAddr, uc.AppIPAddr)
				needPurge = true
			}
			if us.Network != uc.Network {
				log.Printf("quantifyChanges Network changed from %v to %v\n",
					us.Network, uc.Network)
				needPurge = true
			}
			if !cmp.Equal(uc.ACLs, us.ACLs) {
				log.Printf("quantifyChanges FYI ACLs changed: %v\n",
					cmp.Diff(uc.ACLs, us.ACLs))
			}
		}
	}
	if !cmp.Equal(config.IoAdapterList, status.IoAdapterList) {
		log.Printf("quantifyChanges IoAdapterList changed: %v\n",
			cmp.Diff(config.IoAdapterList, status.IoAdapterList))
		needPurge = true
	}
	if !cmp.Equal(config.FixedResources, status.FixedResources) {
		log.Printf("quantifyChanges FixedResources changed: %v\n",
			cmp.Diff(config.FixedResources, status.FixedResources))
		needReboot = true
	}
	log.Printf("quantifyChanges for %s %s returns %v, %v\n",
		config.Key(), config.DisplayName, needPurge, needReboot)
	return needPurge, needReboot
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	if key != "global" {
		log.Debugf("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Printf("handleDNSModify for %s\n", key)
	deviceNetworkStatus = status
	devicenetwork.ProxyToEnv(deviceNetworkStatus.ProxyConfig)
	log.Printf("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	log.Printf("handleDNSDelete for %s\n", key)
	if key != "global" {
		log.Printf("handleDNSDelete: ignoring %s\n", key)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	devicenetwork.ProxyToEnv(deviceNetworkStatus.ProxyConfig)
	log.Printf("handleDNSDelete done for %s\n", key)
}

func handleDatastoreConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX empty since we look at collection when we need it
	log.Printf("handleDatastoreConfigModify for %s\n", key)
}

func handleDatastoreConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX empty since we look at collection when we need it
	log.Printf("handleDatastoreConfigDelete for %s\n", key)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	if key != "global" {
		log.Printf("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Printf("handleGlobalConfigModify for %s\n", key)
	debug = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Printf("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	if key != "global" {
		log.Printf("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Printf("handleGlobalConfigDelete for %s\n", key)
	debug = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Printf("handleGlobalConfigDelete done for %s\n", key)
}
