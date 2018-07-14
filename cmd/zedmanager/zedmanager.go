// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Get AppInstanceConfig from zedagent, drive config to Downloader, Verifier,
// IdentityMgr, and Zedrouter. Collect status from those services and make
// the combined AppInstanceStatus available to zedagent.

package zedmanager

import (
	"flag"
	"fmt"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"log"
	"os"
)

// XXX remove references to /var/run in comments
// Keeping status in /var/run to be clean after a crash/reboot
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
}

var deviceNetworkStatus types.DeviceNetworkStatus

var debug = false

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
	pubAppInstanceStatus, err := pubsub.Publish(agentName,
		types.AppInstanceStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppInstanceStatus = pubAppInstanceStatus
	pubAppInstanceStatus.ClearRestarted()

	pubAppNetworkConfig, err := pubsub.Publish(agentName,
		types.AppNetworkConfig{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppNetworkConfig = pubAppNetworkConfig
	pubAppNetworkConfig.ClearRestarted()

	pubDomainConfig, err := pubsub.Publish(agentName,
		types.DomainConfig{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubDomainConfig = pubDomainConfig
	pubDomainConfig.ClearRestarted()

	pubEIDConfig, err := pubsub.Publish(agentName,
		types.EIDConfig{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubEIDConfig = pubEIDConfig
	pubEIDConfig.ClearRestarted()

	pubAppImgDownloadConfig, err := pubsub.PublishScope(agentName,
		appImgObj, types.DownloaderConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubAppImgDownloadConfig.ClearRestarted()
	ctx.pubAppImgDownloadConfig = pubAppImgDownloadConfig

	pubAppImgVerifierConfig, err := pubsub.PublishScope(agentName,
		appImgObj, types.VerifyImageConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubAppImgVerifierConfig.ClearRestarted()
	ctx.pubAppImgVerifierConfig = pubAppImgVerifierConfig

	// Get AppInstanceConfig from zedagent
	subAppInstanceConfig, err := pubsub.Subscribe("zedagent",
		types.AppInstanceConfig{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subAppInstanceConfig.ModifyHandler = handleAppInstanceConfigModify
	subAppInstanceConfig.DeleteHandler = handleAppInstanceConfigDelete
	subAppInstanceConfig.RestartHandler = handleConfigRestart
	ctx.subAppInstanceConfig = subAppInstanceConfig
	subAppInstanceConfig.Activate()

	// Get AppNetworkStatus from zedrouter
	subAppNetworkStatus, err := pubsub.Subscribe("zedrouter",
		types.AppNetworkStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subAppNetworkStatus.ModifyHandler = handleAppNetworkStatusModify
	subAppNetworkStatus.DeleteHandler = handleAppNetworkStatusDelete
	subAppNetworkStatus.RestartHandler = handleZedrouterRestarted
	ctx.subAppNetworkStatus = subAppNetworkStatus
	subAppNetworkStatus.Activate()

	// Get DomainStatus from domainmgr
	subDomainStatus, err := pubsub.Subscribe("domainmgr",
		types.DomainStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subDomainStatus.ModifyHandler = handleDomainStatusModify
	subDomainStatus.DeleteHandler = handleDomainStatusDelete
	ctx.subDomainStatus = subDomainStatus
	subDomainStatus.Activate()

	// Look for DownloaderStatus from downloader
	subAppImgDownloadStatus, err := pubsub.SubscribeScope("downloader",
		appImgObj, types.DownloaderStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgDownloadStatus.ModifyHandler = handleDownloaderStatusModify
	subAppImgDownloadStatus.DeleteHandler = handleDownloaderStatusDelete
	ctx.subAppImgDownloadStatus = subAppImgDownloadStatus
	subAppImgDownloadStatus.Activate()

	// Look for VerifyImageStatus from verifier
	subAppImgVerifierStatus, err := pubsub.SubscribeScope("verifier",
		appImgObj, types.VerifyImageStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subAppImgVerifierStatus.ModifyHandler = handleVerifyImageStatusModify
	subAppImgVerifierStatus.DeleteHandler = handleVerifyImageStatusDelete
	subAppImgVerifierStatus.RestartHandler = handleVerifierRestarted
	ctx.subAppImgVerifierStatus = subAppImgVerifierStatus
	subAppImgVerifierStatus.Activate()

	// Get IdentityStatus from identitymgr
	subEIDStatus, err := pubsub.Subscribe("identitymgr",
		types.EIDStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subEIDStatus.ModifyHandler = handleEIDStatusModify
	subEIDStatus.DeleteHandler = handleEIDStatusDelete
	subEIDStatus.RestartHandler = handleIdentitymgrRestarted
	ctx.subEIDStatus = subEIDStatus
	subEIDStatus.Activate()

	subDeviceNetworkStatus, err := pubsub.Subscribe("zedrouter",
		types.DeviceNetworkStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Look for CertObjStatus from zedagent
	subCertObjStatus, err := pubsub.Subscribe("zedagent",
		types.CertObjStatus{}, false, &ctx)
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

func updateAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Printf("updateAppInstanceStatus(%s)\n", key)
	pub := ctx.pubAppInstanceStatus
	pub.Publish(key, status)
}

func removeAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.Key()
	log.Printf("removeAppInstanceStatus(%s)\n", key)
	pub := ctx.pubAppInstanceStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("removeAppInstanceStatus(%s) not found\n", key)
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
		UUIDandVersion: config.UUIDandVersion,
		DisplayName:    config.DisplayName,
	}

	status.StorageStatusList = make([]types.StorageStatus,
		len(config.StorageConfigList))
	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		ss.DownloadURL = sc.DownloadURL
		ss.ImageSha256 = sc.ImageSha256
		ss.Target = sc.Target
	}
	status.EIDList = make([]types.EIDStatusDetails,
		len(config.OverlayNetworkList))

	updateAppInstanceStatus(ctx, &status)

	uuidStr := status.Key()
	changed := doUpdate(ctx, uuidStr, config, &status)
	if changed {
		log.Printf("handleCreate status change for %s\n",
			uuidStr)
		updateAppInstanceStatus(ctx, &status)
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

	status.UUIDandVersion = config.UUIDandVersion
	updateAppInstanceStatus(ctx, status)

	uuidStr := status.Key()
	changed := doUpdate(ctx, uuidStr, config, status)
	if changed {
		log.Printf("handleModify status change for %s\n",
			uuidStr)
		updateAppInstanceStatus(ctx, status)
	}
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(ctx *zedmanagerContext, key string,
	status *types.AppInstanceStatus) {

	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	removeAIStatus(ctx, status)
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	if key != "global" {
		if debug {
			log.Printf("handleDNSModify: ignoring %s\n",
				key)
		}
		return
	}
	log.Printf("handleDNSModify for %s\n", key)
	deviceNetworkStatus = status
	log.Printf("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	log.Printf("handleDNSDelete for %s\n", key)
	if key != "global" {
		log.Printf("handleDNSDelete: ignoring %s\n", key)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Printf("handleDNSDelete done for %s\n", key)
}
