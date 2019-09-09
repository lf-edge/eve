// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// baseosmgr orchestrates base os/certs installation
// interfaces with zedagent for configuration update
// interfaces with downloader for basos image/certs download
// interfaces with verifier for image sha/signature verfication

// baswos handles the following orchestration
//   * base os download config/status <downloader> / <baseos> / <config | status>
//   * base os verifier config/status <verifier>   / <baseos> / <config | status>
//   * certs download config/status   <downloader> / <certs>  / <config | status>
// <base os>
//   <zedagent>   <baseos> <config> --> <baseosmgr>   <baseos> <status>
//				<download>...       --> <downloader>  <baseos> <config>
//   <downloader> <baseos> <config> --> <downloader>  <baseos> <status>
//				<downloaded>...     --> <downloader>  <baseos> <status>
//	 <downloader> <baseos> <status> --> <baseosmgr>   <baseos> <status>
//				<verify>    ...     --> <verifier>    <baseos> <config>
//   <verifier> <baseos> <config>   --> <verifier>    <baseos> <status>
//				<verified>  ...     --> <verifier>    <baseos> <status>
//	 <verifier> <baseos> <status>   --> <baseosmgr>   <baseos> <status>
// <certs>
//   <zedagent>   <certs> <config>  --> <baseosmgr>   <certs> <status>
//				<download>...       --> <downloader>  <certs> <config>
//   <downloader> <certs> <config>  --> <downloader>  <certs> <status>
//				<downloaded>...     --> <downloader>  <certs> <status>
//	 <downloader> <baseos> <status> --> <baseosmgr>   <baseos> <status>

package baseosmgr

import (
	"flag"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

const (
	baseOsObj = "baseOs.obj"
	certObj   = "cert.obj"
	agentName = "baseosmgr"

	persistDir            = "/persist"
	objectDownloadDirname = persistDir + "/downloads"
	certificateDirname    = persistDir + "/certs"

	partitionCount = 2
)

// Set from Makefile
var Version = "No version specified"

type baseOsMgrContext struct {
	verifierRestarted        bool // Information from handleVerifierRestarted
	pubBaseOsStatus          *pubsub.Publication
	pubBaseOsDownloadConfig  *pubsub.Publication
	pubBaseOsVerifierConfig  *pubsub.Publication
	pubCertObjStatus         *pubsub.Publication
	pubCertObjDownloadConfig *pubsub.Publication
	pubZbootStatus           *pubsub.Publication

	subGlobalConfig          *pubsub.Subscription
	globalConfig             *types.GlobalConfig
	subBaseOsConfig          *pubsub.Subscription
	subZbootConfig           *pubsub.Subscription
	subCertObjConfig         *pubsub.Subscription
	subBaseOsDownloadStatus  *pubsub.Subscription
	subCertObjDownloadStatus *pubsub.Subscription
	subBaseOsVerifierStatus  *pubsub.Subscription
}

var debug = false
var debugOverride bool // From command line arg

func Run() {
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

	// Context to pass around
	ctx := baseOsMgrContext{
		globalConfig: &types.GlobalConfigDefaults,
	}

	// initialize publishing handles
	initializeSelfPublishHandles(&ctx)

	// initialize module specific subscriber handles
	initializeGlobalConfigHandles(&ctx)
	initializeZedagentHandles(&ctx)
	initializeVerifierHandles(&ctx)
	initializeDownloaderHandles(&ctx)

	// publish zboot partition status
	publishZbootPartitionStatusAll(&ctx)

	// report other agents, about, zboot status availability
	ctx.pubZbootStatus.SignalRestarted()

	// First we process the verifierStatus to avoid downloading
	// an image we already have in place.
	log.Infof("Handling initial verifier Status\n")
	for !ctx.verifierRestarted {
		select {
		case change := <-ctx.subGlobalConfig.C:
			start := agentlog.StartTime()
			ctx.subGlobalConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-ctx.subBaseOsVerifierStatus.C:
			start := agentlog.StartTime()
			ctx.subBaseOsVerifierStatus.ProcessChange(change)
			if ctx.verifierRestarted {
				log.Infof("Verifier reported restarted\n")
			}
			agentlog.CheckMaxTime(agentName, start)
		}
	}

	// start the forever loop for event handling
	for {
		select {
		case change := <-ctx.subGlobalConfig.C:
			start := agentlog.StartTime()
			ctx.subGlobalConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-ctx.subCertObjConfig.C:
			start := agentlog.StartTime()
			ctx.subCertObjConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-ctx.subBaseOsConfig.C:
			start := agentlog.StartTime()
			ctx.subBaseOsConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-ctx.subZbootConfig.C:
			start := agentlog.StartTime()
			ctx.subZbootConfig.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-ctx.subBaseOsDownloadStatus.C:
			start := agentlog.StartTime()
			ctx.subBaseOsDownloadStatus.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-ctx.subBaseOsVerifierStatus.C:
			start := agentlog.StartTime()
			ctx.subBaseOsVerifierStatus.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case change := <-ctx.subCertObjDownloadStatus.C:
			start := agentlog.StartTime()
			ctx.subCertObjDownloadStatus.ProcessChange(change)
			agentlog.CheckMaxTime(agentName, start)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName)
	}
}

func handleVerifierRestarted(ctxArg interface{}, done bool) {
	ctx := ctxArg.(*baseOsMgrContext)
	log.Infof("handleVerifierRestarted(%v)\n", done)
	if done {
		ctx.verifierRestarted = true
	}
}

func handleBaseOsConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleBaseOsConfigDelete(%s)\n", key)
	ctx := ctxArg.(*baseOsMgrContext)
	status := lookupBaseOsStatus(ctx, key)
	if status == nil {
		log.Infof("handleBaseOsConfigDelete: unknown %s\n", key)
		return
	}
	handleBaseOsDelete(ctx, key, status)
	log.Infof("handleBaseOsConfigDelete(%s) done\n", key)
}

// base os config modify event
func handleBaseOsCreate(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("handleBaseOsCreate(%s)\n", key)
	ctx := ctxArg.(*baseOsMgrContext)
	config := cast.CastBaseOsConfig(configArg)
	status := types.BaseOsStatus{
		UUIDandVersion: config.UUIDandVersion,
		BaseOsVersion:  config.BaseOsVersion,
		ConfigSha256:   config.ConfigSha256,
	}

	status.StorageStatusList = make([]types.StorageStatus,
		len(config.StorageConfigList))

	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		ss.Name = sc.Name
		ss.ImageSha256 = sc.ImageSha256
		ss.Target = sc.Target
	}
	// Check image count
	err := validateBaseOsConfig(ctx, config)
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		log.Errorln(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		publishBaseOsStatus(ctx, &status)
		return
	}
	publishBaseOsStatus(ctx, &status)
	baseOsHandleStatusUpdate(ctx, &config, &status)
}

func handleBaseOsModify(ctxArg interface{}, key string, configArg interface{}) {

	log.Infof("handleBaseOsModify(%s)\n", key)
	ctx := ctxArg.(*baseOsMgrContext)
	config := cast.CastBaseOsConfig(configArg)
	status := lookupBaseOsStatus(ctx, key)
	if config.Key() != key {
		log.Errorf("handleBaseOsModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	if status == nil {
		log.Errorf("handleBaseOsModify status not found, ignored %+v\n", key)
		return
	}

	log.Infof("handleBaseOsModify(%s) for %s Activate %v\n",
		config.Key(), config.BaseOsVersion, config.Activate)

	// Check image count
	err := validateBaseOsConfig(ctx, config)
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		log.Errorln(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		publishBaseOsStatus(ctx, status)
		return
	}

	// update the version field, uuids being the same
	status.UUIDandVersion = config.UUIDandVersion
	publishBaseOsStatus(ctx, status)
	baseOsHandleStatusUpdate(ctx, &config, status)
}

// base os config delete event
func handleBaseOsDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(*types.BaseOsStatus)
	if status.Key() != key {
		log.Errorf("handleBaseOsDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*baseOsMgrContext)

	log.Infof("handleBaseOsDelete for %s\n", status.BaseOsVersion)
	removeBaseOsConfig(ctx, status.Key())
}

func handleCertObjConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleCertObjConfigDelete(%s)\n", key)
	ctx := ctxArg.(*baseOsMgrContext)
	status := lookupCertObjStatus(ctx, key)
	if status == nil {
		log.Infof("handleCertObjConfigDelete: unknown %s\n", key)
		return
	}
	handleCertObjDelete(ctx, key, status)
	log.Infof("handleCertObjConfigDelete(%s) done\n", key)
}

// certificate config/status event handlers
// certificate config create event
func handleCertObjCreate(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*baseOsMgrContext)
	config := cast.CastCertObjConfig(configArg)
	log.Infof("handleCertObjCreate for %s\n", key)

	status := types.CertObjStatus{
		UUIDandVersion: config.UUIDandVersion,
		ConfigSha256:   config.ConfigSha256,
	}

	status.StorageStatusList = make([]types.StorageStatus,
		len(config.StorageConfigList))

	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]
		ss.Name = sc.Name
		ss.ImageSha256 = sc.ImageSha256
		ss.FinalObjDir = certificateDirname
	}

	publishCertObjStatus(ctx, &status)

	certObjHandleStatusUpdate(ctx, &config, &status)
}

// certificate config modify event
func handleCertObjModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*baseOsMgrContext)
	config := cast.CastCertObjConfig(configArg)
	status := lookupCertObjStatus(ctx, key)
	uuidStr := config.Key()
	log.Infof("handleCertObjModify for %s\n", uuidStr)

	if config.UUIDandVersion.Version != status.UUIDandVersion.Version {
		log.Infof("handleCertObjModify(%s), New config version %v\n", key,
			config.UUIDandVersion.Version)
		status.UUIDandVersion = config.UUIDandVersion
		publishCertObjStatus(ctx, status)

	}

	// on storage config change, purge and recreate
	if certObjCheckConfigModify(ctx, key, &config, status) {
		removeCertObjConfig(ctx, key)
		handleCertObjCreate(ctx, key, config)
	}
}

// certificate config delete event
func handleCertObjDelete(ctx *baseOsMgrContext, key string,
	status *types.CertObjStatus) {

	uuidStr := status.Key()
	log.Infof("handleCertObjDelete for %s\n", uuidStr)
	removeCertObjConfig(ctx, uuidStr)
}

// base os/certs download status modify event
func handleDownloadStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastDownloaderStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleDownloadStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*baseOsMgrContext)
	log.Infof("handleDownloadStatusModify for %s\n",
		status.Safename)
	updateDownloaderStatus(ctx, &status)
}

// base os/certs download status delete event
func handleDownloadStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastDownloaderStatus(statusArg)
	log.Infof("handleDownloadStatusDelete RefCount %d Expired %v for %s\n",
		status.RefCount, status.Expired, key)
	// Nothing to do
}

// base os verifier status modify event
func handleVerifierStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleVerifierStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*baseOsMgrContext)
	log.Infof("handleVerifierStatusModify for %s\n", status.Safename)
	updateVerifierStatus(ctx, &status)
}

// base os verifier status delete event
func handleVerifierStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	log.Infof("handleVeriferStatusDelete RefCount %d Expired %v for %s\n",
		status.RefCount, status.Expired, key)
	// Nothing to do
}

func appendError(allErrors string, prefix string, lasterr string) string {
	return fmt.Sprintf("%s%s: %s\n\n", allErrors, prefix, lasterr)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*baseOsMgrContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	var gcp *types.GlobalConfig
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		ctx.globalConfig = gcp
	}
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*baseOsMgrContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	*ctx.globalConfig = types.GlobalConfigDefaults
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

func initializeSelfPublishHandles(ctx *baseOsMgrContext) {
	pubBaseOsStatus, err := pubsub.Publish(agentName,
		types.BaseOsStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsStatus.ClearRestarted()
	ctx.pubBaseOsStatus = pubBaseOsStatus

	pubBaseOsDownloadConfig, err := pubsub.PublishScope(agentName,
		baseOsObj, types.DownloaderConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsDownloadConfig.ClearRestarted()
	ctx.pubBaseOsDownloadConfig = pubBaseOsDownloadConfig

	pubBaseOsVerifierConfig, err := pubsub.PublishScope(agentName,
		baseOsObj, types.VerifyImageConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubBaseOsVerifierConfig.ClearRestarted()
	ctx.pubBaseOsVerifierConfig = pubBaseOsVerifierConfig

	pubCertObjStatus, err := pubsub.Publish(agentName,
		types.CertObjStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubCertObjStatus.ClearRestarted()
	ctx.pubCertObjStatus = pubCertObjStatus

	pubCertObjDownloadConfig, err := pubsub.PublishScope(agentName,
		certObj, types.DownloaderConfig{})
	if err != nil {
		log.Fatal(err)
	}
	pubCertObjDownloadConfig.ClearRestarted()
	ctx.pubCertObjDownloadConfig = pubCertObjDownloadConfig

	pubZbootStatus, err := pubsub.Publish(agentName, types.ZbootStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubZbootStatus.ClearRestarted()
	ctx.pubZbootStatus = pubZbootStatus
}

func initializeGlobalConfigHandles(ctx *baseOsMgrContext) {

	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, ctx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()
}

func initializeZedagentHandles(ctx *baseOsMgrContext) {
	// Look for BaseOsConfig , from zedagent
	subBaseOsConfig, err := pubsub.Subscribe("zedagent",
		types.BaseOsConfig{}, false, ctx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsConfig.ModifyHandler = handleBaseOsModify
	subBaseOsConfig.CreateHandler = handleBaseOsCreate
	subBaseOsConfig.DeleteHandler = handleBaseOsConfigDelete
	ctx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()

	// Look for ZbootConfig , from zedagent
	subZbootConfig, err := pubsub.Subscribe("zedagent",
		types.ZbootConfig{}, false, ctx)
	if err != nil {
		log.Fatal(err)
	}
	subZbootConfig.ModifyHandler = handleZbootConfigModify
	subZbootConfig.DeleteHandler = handleZbootConfigDelete
	ctx.subZbootConfig = subZbootConfig
	subZbootConfig.Activate()

	// Look for CertObjConfig, from zedagent
	subCertObjConfig, err := pubsub.Subscribe("zedagent",
		types.CertObjConfig{}, false, ctx)
	if err != nil {
		log.Fatal(err)
	}
	subCertObjConfig.ModifyHandler = handleCertObjModify
	subCertObjConfig.CreateHandler = handleCertObjCreate
	subCertObjConfig.DeleteHandler = handleCertObjConfigDelete
	ctx.subCertObjConfig = subCertObjConfig
	subCertObjConfig.Activate()
}

func initializeDownloaderHandles(ctx *baseOsMgrContext) {
	// Look for BaseOs DownloaderStatus from downloader
	subBaseOsDownloadStatus, err := pubsub.SubscribeScope("downloader",
		baseOsObj, types.DownloaderStatus{}, false, ctx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsDownloadStatus.ModifyHandler = handleDownloadStatusModify
	subBaseOsDownloadStatus.DeleteHandler = handleDownloadStatusDelete
	ctx.subBaseOsDownloadStatus = subBaseOsDownloadStatus
	subBaseOsDownloadStatus.Activate()

	// Look for Certs DownloaderStatus from downloader
	subCertObjDownloadStatus, err := pubsub.SubscribeScope("downloader",
		certObj, types.DownloaderStatus{}, false, ctx)
	if err != nil {
		log.Fatal(err)
	}
	subCertObjDownloadStatus.ModifyHandler = handleDownloadStatusModify
	subCertObjDownloadStatus.DeleteHandler = handleDownloadStatusDelete
	ctx.subCertObjDownloadStatus = subCertObjDownloadStatus
	subCertObjDownloadStatus.Activate()

}

func initializeVerifierHandles(ctx *baseOsMgrContext) {
	// Look for VerifyImageStatus from verifier
	subBaseOsVerifierStatus, err := pubsub.SubscribeScope("verifier",
		baseOsObj, types.VerifyImageStatus{}, false, ctx)
	if err != nil {
		log.Fatal(err)
	}
	subBaseOsVerifierStatus.ModifyHandler = handleVerifierStatusModify
	subBaseOsVerifierStatus.DeleteHandler = handleVerifierStatusDelete
	subBaseOsVerifierStatus.RestartHandler = handleVerifierRestarted
	ctx.subBaseOsVerifierStatus = subBaseOsVerifierStatus
	subBaseOsVerifierStatus.Activate()
}

func handleZbootConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*baseOsMgrContext)
	config := cast.ZbootConfig(configArg)
	status := getZbootStatus(ctx, key)
	if status == nil {
		log.Infof("handleZbootConfigModify: unknown %s\n", key)
		return
	}
	log.Infof("handleZbootModify for %s TestComplete %v\n",
		config.Key(), config.TestComplete)

	if config.TestComplete != status.TestComplete {
		handleZbootTestComplete(ctx, config, *status)
	}

	log.Infof("handleZbootConfigModify(%s) done\n", key)
}

func handleZbootConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleZbootConfigDelete(%s)\n", key)
	ctx := ctxArg.(*baseOsMgrContext)
	status := getZbootStatus(ctx, key)
	if status == nil {
		log.Infof("handleZbootConfigDelete: unknown %s\n", key)
		return
	}
	// Nothing to do. We report ZbootStatus for the IMG* partitions
	// in any case
	log.Infof("handleZbootConfigDelete(%s) done\n", key)
}
