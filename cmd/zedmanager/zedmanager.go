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
	"github.com/zededa/go-provision/watch"
	"log"
	"os"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	appImgObj  = "appImg.obj"
	certObj    = "cert.obj"
	agentName  = "zedmanager"
	moduleName = agentName

	verifierConfigDirname    = "/var/tmp/verifier/config"
	downloaderConfigDirname  = "/var/tmp/downloader/config"
	domainmgrConfigDirname   = "/var/tmp/domainmgr/config"
	zedrouterConfigDirname   = "/var/tmp/zedrouter/config"
	identitymgrConfigDirname = "/var/tmp/identitymgr/config"
	DNSDirname               = "/var/run/zedrouter/DeviceNetworkStatus"
	certificateDirname       = persistDir + "/certs"

	downloaderAppImgObjConfigDirname = "/var/tmp/downloader/" + appImgObj + "/config"
	verifierAppImgObjConfigDirname   = "/var/tmp/verifier/" + appImgObj + "/config"
)

// Set from Makefile
var Version = "No version specified"

// Dummy since we don't have anything to pass to DNS
type dummyContext struct {
}

// State used by handlers
type zedmanagerContext struct {
	configRestarted      bool
	verifierRestarted    bool
	subAppInstanceConfig *pubsub.Subscription
	pubAppInstanceStatus *pubsub.Publication
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
	watch.CleanupRestarted(agentName)
	// XXX either we don't need this, or we need it for each objType
	watch.CleanupRestart("downloader")
	// XXX either we don't need this, or we need it for each objType
	watch.CleanupRestart("verifier")
	watch.CleanupRestart("identitymgr")
	watch.CleanupRestart("zedrouter")
	watch.CleanupRestart("domainmgr")
	watch.CleanupRestart("zedagent")

	verifierStatusDirname := "/var/run/verifier/status"
	downloaderStatusDirname := "/var/run/downloader/status"
	domainmgrStatusDirname := "/var/run/domainmgr/status"
	zedrouterStatusDirname := "/var/run/zedrouter/status"
	identitymgrStatusDirname := "/var/run/identitymgr/status"

	downloaderAppImgObjStatusDirname := "/var/run/downloader/" + appImgObj + "/status"
	verifierAppImgObjStatusDirname := "/var/run/verifier/" + appImgObj + "/status"
	zedagentCertObjStatusDirname := "/var/run/zedagent/" + certObj + "/status"

	dirs := []string{
		identitymgrConfigDirname,
		zedrouterConfigDirname,
		domainmgrConfigDirname,
		downloaderConfigDirname,
		downloaderAppImgObjConfigDirname,
		verifierConfigDirname,
		verifierAppImgObjConfigDirname,
		identitymgrStatusDirname,
		zedrouterStatusDirname,
		domainmgrStatusDirname,
		downloaderAppImgObjStatusDirname,
		downloaderStatusDirname,
		verifierAppImgObjStatusDirname,
		verifierStatusDirname,
		zedagentCertObjStatusDirname,
	}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			log.Printf("Create %s\n", dir)
			if err := os.MkdirAll(dir, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}

	// Tell ourselves to go ahead
	watch.SignalRestart(agentName)

	// Any state needed by handler functions
	ctx := zedmanagerContext{}

	// Get AppInstanceConfig from zedagent
	subAppInstanceConfig, err := pubsub.Subscribe("zedagent",
		types.AppInstanceConfig{}, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subAppInstanceConfig.ModifyHandler = handleAppInstanceConfigModify
	subAppInstanceConfig.DeleteHandler = handleAppInstanceConfigDelete

	ctx.subAppInstanceConfig = subAppInstanceConfig

	pubAppInstanceStatus, err := pubsub.Publish(agentName,
		types.AppInstanceStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppInstanceStatus = pubAppInstanceStatus

	verifierChanges := make(chan string)
	go watch.WatchStatus(verifierAppImgObjStatusDirname, verifierChanges)
	downloaderChanges := make(chan string)
	go watch.WatchStatus(downloaderAppImgObjStatusDirname, downloaderChanges)
	identitymgrChanges := make(chan string)
	go watch.WatchStatus(identitymgrStatusDirname, identitymgrChanges)
	zedrouterChanges := make(chan string)
	go watch.WatchStatus(zedrouterStatusDirname, zedrouterChanges)
	domainmgrChanges := make(chan string)
	go watch.WatchStatus(domainmgrStatusDirname, domainmgrChanges)
	networkStatusChanges := make(chan string)
	go watch.WatchStatus(DNSDirname, networkStatusChanges)
	zedagentCertObjStatusChanges := make(chan string)
	go watch.WatchStatus(zedagentCertObjStatusDirname,
		zedagentCertObjStatusChanges)

	var configRestartFn watch.ConfigRestartHandler = handleConfigRestart
	var verifierRestartedFn watch.StatusRestartHandler = handleVerifierRestarted
	var identitymgrRestartedFn watch.StatusRestartHandler = handleIdentitymgrRestarted
	var zedrouterRestartedFn watch.StatusRestartHandler = handleZedrouterRestarted

	// First we process the verifierStatus to avoid downloading
	// an image we already have in place.
	log.Printf("Handling initial verifier Status\n")
	done := false
	for !done {
		select {
		case change := <-verifierChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					verifierAppImgObjStatusDirname,
					&types.VerifyImageStatus{},
					handleVerifyImageStatusModify,
					handleVerifyImageStatusDelete,
					&verifierRestartedFn)
				if ctx.verifierRestarted {
					log.Printf("Verifier reported restarted\n")
					done = true
					break
				}
			}
		}
	}

	log.Printf("Handling all inputs\n")
	for {
		select {
		// handle cert ObjectsChanges
		case change := <-zedagentCertObjStatusChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					zedagentCertObjStatusDirname,
					&types.CertObjStatus{},
					handleCertObjStatusModify,
					handleCertObjStatusDelete, nil)
			}
		case change := <-downloaderChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					downloaderAppImgObjStatusDirname,
					&types.DownloaderStatus{},
					handleDownloaderStatusModify,
					handleDownloaderStatusDelete, nil)
			}
		case change := <-verifierChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					verifierAppImgObjStatusDirname,
					&types.VerifyImageStatus{},
					handleVerifyImageStatusModify,
					handleVerifyImageStatusDelete,
					&verifierRestartedFn)
			}
		case change := <-identitymgrChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					identitymgrStatusDirname,
					&types.EIDStatus{},
					handleEIDStatusModify,
					handleEIDStatusDelete,
					&identitymgrRestartedFn)
			}
		case change := <-zedrouterChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					zedrouterStatusDirname,
					&types.AppNetworkStatus{},
					handleAppNetworkStatusModify,
					handleAppNetworkStatusDelete,
					&zedrouterRestartedFn)
			}
		case change := <-domainmgrChanges:
			{
				watch.HandleStatusEvent(change, &ctx,
					domainmgrStatusDirname,
					&types.DomainStatus{},
					handleDomainStatusModify,
					handleDomainStatusDelete, nil)
			}
		case change := <-subAppInstanceConfig.C:
			subAppInstanceConfig.ProcessChange(change)
			// XXX where &configRestartFn? XXX add a handler in pubsub?
			configRestartFn(&ctx, true)

		case change := <-networkStatusChanges:
			{
				watch.HandleStatusEvent(change, dummyContext{},
					DNSDirname,
					&types.DeviceNetworkStatus{},
					handleDNSModify, handleDNSDelete,
					nil)
			}
		}
	}
}

// XXX what does zedagent waiting for verifier already solve?
// XXX why do we care about configRestarted? Avoid starting domUs which were
// deleted while we down? But restarted from zedagent isn't sufficient? Need to
// know it got some config...
// Propagate a seqence of restart/restarted from the zedmanager config
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
			watch.SignalRestart("identitymgr")
		}
	}
}

func handleVerifierRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*zedmanagerContext)

	log.Printf("handleVerifierRestarted(%v)\n", done)
	if done {
		ctx.verifierRestarted = true
		if ctx.configRestarted {
			watch.SignalRestart("identitymgr")
		}
	}
}

func handleIdentitymgrRestarted(ctxArg interface{}, done bool) {
	log.Printf("handleIdentitymgrRestarted(%v)\n", done)
	if done {
		watch.SignalRestart("zedrouter")
	}
}

func handleZedrouterRestarted(ctxArg interface{}, done bool) {
	log.Printf("handleZedrouterRestarted(%v)\n", done)
	if done {
		watch.SignalRestart("domainmgr")
	}
}

func updateAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.UUIDandVersion.UUID.String()
	log.Printf("updateAppInstanceStatus(%s)\n", key)
	pub := ctx.pubAppInstanceStatus
	pub.Publish(key, status)
}

func removeAppInstanceStatus(ctx *zedmanagerContext,
	status *types.AppInstanceStatus) {

	key := status.UUIDandVersion.UUID.String()
	log.Printf("removeAppInstanceStatus(%s)\n", key)
	pub := ctx.pubAppInstanceStatus
	pub.Unpublish(key)
}

// Determine whether it is an create or modify
func handleAppInstanceConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	config := cast.CastAppInstanceConfig(configArg)
	if config.UUIDandVersion.UUID.String() != key {
		log.Printf("handleAppInstanceConfigModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.UUIDandVersion.UUID.String(), config)
		return
	}
	status := lookupAppInstanceStatus(ctx, key)
	if status != nil {
		handleModify(ctxArg, key, configArg, status)
	} else {
		handleCreate(ctxArg, key, configArg)
	}
}

func handleAppInstanceConfigDelete(ctxArg interface{}, key string) {
	log.Printf("handleAppInstanceConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := lookupAppInstanceStatus(ctx, key)
	if status == nil {
		log.Printf("handleAppInstanceConfigDelete: unknown %s\n", key)
		return
	}
	handleDelete(ctxArg, key, status)
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
	if status.UUIDandVersion.UUID.String() != key {
		log.Printf("lookupAppInstanceStatus(%s) got %s; ignored %+v\n",
			key, status.UUIDandVersion.UUID.String(), status)
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
	if config.UUIDandVersion.UUID.String() != key {
		log.Printf("lookupAppInstanceConfig(%s) got %s; ignored %+v\n",
			key, config.UUIDandVersion.UUID.String(), config)
		return nil
	}
	return &config
}

func handleCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	config := configArg.(*types.AppInstanceConfig)
	ctx := ctxArg.(*zedmanagerContext)

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

	uuidStr := status.UUIDandVersion.UUID.String()
	changed := doUpdate(uuidStr, *config, &status)
	if changed {
		log.Printf("handleCreate status change for %s\n",
			uuidStr)
		updateAppInstanceStatus(ctx, &status)
	}
	log.Printf("handleCreate done for %s\n", config.DisplayName)
}

func handleModify(ctxArg interface{}, key string,
	configArg interface{}, statusArg interface{}) {
	config := configArg.(*types.AppInstanceConfig)
	status := statusArg.(*types.AppInstanceStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Printf("handleModify(%v) for %s\n",
		config.UUIDandVersion, config.DisplayName)

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, key)
		return
	}

	status.UUIDandVersion = config.UUIDandVersion
	// XXX what updates should we handle?
	updateAppInstanceStatus(ctx, status)

	uuidStr := status.UUIDandVersion.UUID.String()
	changed := doUpdate(uuidStr, *config, status)
	if changed {
		log.Printf("handleModify status change for %s\n",
			uuidStr)
		updateAppInstanceStatus(ctx, status)
	}
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(*types.AppInstanceStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Printf("handleDelete(%v) for %s\n",
		status.UUIDandVersion, status.DisplayName)

	removeAIStatus(ctx, status)
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}

func handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(*types.DeviceNetworkStatus)

	if key != "global" {
		if debug {
			log.Printf("handleDNSModify: ignoring %s\n",
				key)
		}
		return
	}
	log.Printf("handleDNSModify for %s\n", key)
	deviceNetworkStatus = *status
	log.Printf("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string) {
	log.Printf("handleDNSDelete for %s\n", key)

	if key != "global" {
		log.Printf("handleDNSDelete: ignoring %s\n", key)
		return
	}
	deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Printf("handleDNSDelete done for %s\n", key)
}
