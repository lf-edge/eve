// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of collections of VerifyImageConfig structs
// and publish the results as collections of VerifyImageStatus structs.
//
// Move the file from DownloadDirname/pending/<sha> to
// to DownloadDirname/verifier/<sha> and make RO,
// then attempt to verify sum and optional signature.
// Once sum is verified, move to DownloadDirname/verified/<sha256>

package verifier

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "verifier"
	// Time limits for event loop handlers
	errorTime        = 3 * time.Minute
	warningTime      = 40 * time.Second
	verifierBasePath = types.SealedDirName + "/" + agentName
)

// Go doesn't like this as a constant
var (
	vHandler = makeVerifyHandler()
)

// Set from Makefile
var Version = "No version specified"

// Any state used by handlers goes here
type verifierContext struct {
	subVerifyImageConfig pubsub.Subscription
	pubVerifyImageStatus pubsub.Publication
	subGlobalConfig      pubsub.Subscription

	GCInitialized bool
}

var debug = false
var debugOverride bool // From command line arg
var logger *logrus.Logger
var log *base.LogObject

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

	// Any state needed by handler functions
	ctx := verifierContext{}

	// Set up our publications before the subscriptions so ctx is set
	pubVerifyImageStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.VerifyImageStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVerifyImageStatus = pubVerifyImageStatus

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

	subVerifyImageConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VerifyImageConfig{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleVerifyImageConfigCreate,
		ModifyHandler: handleVerifyImageConfigModify,
		DeleteHandler: handleVerifyImageConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subVerifyImageConfig = subVerifyImageConfig
	subVerifyImageConfig.Activate()

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

	if err := utils.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}

	log.Functionf("processed vault status")

	// create the directories
	initializeDirs()

	// Publish status for any objects that were verified before reboot
	// The signatures and shas can re-checked during handleCreate
	// by inserting code.
	handleInit(&ctx)

	// Report to volumemgr that init is done
	pubVerifyImageStatus.SignalRestarted()
	log.Functionf("SignalRestarted done")

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subVerifyImageConfig.MsgChan():
			subVerifyImageConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleInit(ctx *verifierContext) {

	log.Functionln("handleInit")

	// Create VerifyImageStatus for objects that were verified before reboot
	handleInitVerifiedObjects(ctx)

	log.Functionln("handleInit done")
}

func updateVerifyErrStatus(ctx *verifierContext,
	status *types.VerifyImageStatus, lastErr string) {

	status.SetErrorNow(lastErr)
	status.PendingAdd = false
	publishVerifyImageStatus(ctx, status)
}

func publishVerifyImageStatus(ctx *verifierContext,
	status *types.VerifyImageStatus) {

	log.Tracef("publishVerifyImageStatus(%s)", status.ImageSha256)

	pub := ctx.pubVerifyImageStatus
	key := status.Key()
	pub.Publish(key, *status)
}

func unpublishVerifyImageStatus(ctx *verifierContext,
	status *types.VerifyImageStatus) {

	log.Tracef("publishVerifyImageStatus(%s)", status.ImageSha256)

	pub := ctx.pubVerifyImageStatus
	key := status.Key()
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishVerifyImageStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

// Callers must be careful to publish any changes to VerifyImageStatus
func lookupVerifyImageStatus(ctx *verifierContext,
	key string) *types.VerifyImageStatus {

	pub := ctx.pubVerifyImageStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Functionf("lookupVerifyImageStatus(%s) not found", key)
		return nil
	}
	status := st.(types.VerifyImageStatus)
	return &status
}

// Server for each VerifyImageConfig
func runHandler(ctx *verifierContext, key string, c <-chan Notify) {

	log.Functionf("runHandler starting")

	closed := false
	for !closed {
		select {
		case _, ok := <-c:
			if ok {
				sub := ctx.subVerifyImageConfig
				c, err := sub.Get(key)
				if err != nil {
					log.Errorf("runHandler no config for %s", key)
					continue
				}
				config := c.(types.VerifyImageConfig)
				status := lookupVerifyImageStatus(ctx, key)
				if status == nil {
					handleCreate(ctx, &config)
				} else {
					handleModify(ctx, &config, status)
				}
			} else {
				// Closed
				status := lookupVerifyImageStatus(ctx, key)
				if status != nil {
					handleDelete(ctx, status)
				}
				closed = true
			}
		}
	}
	log.Functionf("runHandler(%s) DONE", key)
}

func handleCreate(ctx *verifierContext,
	config *types.VerifyImageConfig) {

	log.Functionf("handleCreate(%s) for %s", config.ImageSha256, config.Name)

	status := types.VerifyImageStatus{
		Name:        config.Name,
		ImageSha256: config.ImageSha256,
		PendingAdd:  true,
		State:       types.VERIFYING,
		RefCount:    config.RefCount,
	}
	publishVerifyImageStatus(ctx, &status)

	if config.FileLocation == "" {
		err := fmt.Errorf("handleCreate: verifyImageConfig: %s has empty fileLocation", config.ImageSha256)
		log.Errorf(err.Error())
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, &status, cerr)
		return
	}

	// We generate a temporary UUID to avoid conflicts
	// where multiple different objects can have a different claimed sha256
	// Of course, only one of those will pass the verification.
	tmpID, err := uuid.NewV4()
	if err != nil {
		log.Errorf("NewV4 failed: %v", err)
		return
	}
	ok, size := markObjectAsVerifying(ctx, config, &status, tmpID)
	if !ok {
		log.Errorf("handleCreate: markObjectAsVerifying failed for %s", config.Name)
		return
	}
	status.Size = size
	publishVerifyImageStatus(ctx, &status)

	if !verifyObjectSha(ctx, config, &status) {
		log.Errorf("handleCreate: verifyObjectSha failed for %s", config.Name)
		return
	}
	publishVerifyImageStatus(ctx, &status)

	markObjectAsVerified(config, &status, tmpID)
	if status.FileLocation == "" {
		log.Fatalf("handleCreate: Verified but no FileLocation for %s", status.Key())
	}

	status.PendingAdd = false
	status.State = types.VERIFIED
	publishVerifyImageStatus(ctx, &status)
	log.Functionf("handleCreate done for %s", config.Name)
}

func verifyObjectSha(ctx *verifierContext, config *types.VerifyImageConfig, status *types.VerifyImageStatus) bool {

	verifierFilename := status.FileLocation
	log.Functionf("verifyObjectSha: Verifying %s file %s",
		config.Name, verifierFilename)

	_, err := os.Stat(verifierFilename)
	if err != nil {
		e := fmt.Errorf("verifyObjectSha: Unable to find location: %s. %s", verifierFilename, err)
		cerr := fmt.Sprintf("%v", e)
		updateVerifyErrStatus(ctx, status, cerr)
		log.Errorf("verifyObjectSha %s failed %s",
			config.Name, cerr)
		return false
	}

	imageHashB, err := computeShaFile(verifierFilename)
	if err != nil {
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, status, cerr)
		log.Errorf("verifyObjectSha %s failed %s",
			config.Name, cerr)
		return false
	}
	log.Functionf("internal hash consistency validated for %s file %s",
		config.Name, verifierFilename)

	imageHash := fmt.Sprintf("%x", imageHashB)
	configuredHash := strings.ToLower(config.ImageSha256)
	if imageHash != configuredHash {
		log.Errorf("computed   %s", imageHash)
		log.Errorf("configured %s", configuredHash)
		cerr := fmt.Sprintf("computed %s configured %s",
			imageHash, configuredHash)
		status.PendingAdd = false
		updateVerifyErrStatus(ctx, status, cerr)
		log.Errorf("verifyObjectSha %s failed %s",
			config.Name, cerr)
		return false
	}

	log.Functionf("Sha validation successful for %s", config.Name)
	return true
}

// compute the sha for a straight file
func computeShaFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// This merely updates the RefCount and Expired in the status
// Note that verifier will retain the file even if RefCount in VerifyImageConfig
// is set to zero.
func handleModify(ctx *verifierContext, config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) {

	// Note no comparison on version
	changed := false

	log.Functionf("handleModify(%s) for %s, config.RefCount: %d, "+
		"status.RefCount: %d",
		status.ImageSha256, config.Name, config.RefCount,
		status.RefCount)

	// Always update RefCount and Expired
	if status.RefCount != config.RefCount {
		log.Functionf("handleModify RefCount change %s from %d to %d",
			config.Name, status.RefCount, config.RefCount)
		status.RefCount = config.RefCount
		changed = true
	}
	if status.Expired != config.Expired {
		log.Functionf("handleModify Expired change %s from %t to %t",
			config.Name, status.Expired, config.Expired)
		status.Expired = config.Expired
		changed = true
	}

	if changed {
		publishVerifyImageStatus(ctx, status)
	}
	log.Functionf("handleModify done for %s. Status.RefCount=%d, Config.RefCount:%d",
		config.Name, status.RefCount, config.RefCount)
}

// handleDelete means volumemgr wants us to delete the file.
// Note that verifier will retain the file even if RefCount in VerifyImageConfig
// is set to zero.
func handleDelete(ctx *verifierContext, status *types.VerifyImageStatus) {

	log.Functionf("handleDelete(%s) refcount %d",
		status.ImageSha256, status.RefCount)

	if _, err := os.Stat(status.FileLocation); err == nil {
		log.Functionf("handleDelete removing %s",
			status.FileLocation)
		if err := os.RemoveAll(status.FileLocation); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Warnf("handleDelete: Unable to delete %s:  %s",
			status.FileLocation, err)
	}

	unpublishVerifyImageStatus(ctx, status)
	log.Functionf("handleDelete done for %s", status.ImageSha256)
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

	ctx := ctxArg.(*verifierContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*verifierContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

// ImageVerifierFilenames - Returns pendingFilename, verifierFilename, verifiedFilename
// for the image
func ImageVerifierFilenames(infile, sha256, tmpID string) (string, string, string) {
	verifierDirname, verifiedDirname := getVerifierDir(), getVerifiedDir()
	// Handle names which are paths
	verified := tmpID + "." + sha256
	return infile, path.Join(verifierDirname, verified), path.Join(verifiedDirname, sha256)
}

// Returns ok, size of object
func markObjectAsVerifying(ctx *verifierContext,
	config *types.VerifyImageConfig,
	status *types.VerifyImageStatus, tmpID uuid.UUID) (bool, int64) {

	verifierDirname := getVerifierDir()
	pendingFilename, verifierFilename, _ := ImageVerifierFilenames(config.FileLocation, config.ImageSha256, tmpID.String())

	// Move to verifier directory which is RO
	// XXX should have dom0 do this and/or have RO mounts
	log.Functionf("markObjectAsVerifying: Move from %s to %s", pendingFilename, verifierFilename)

	info, err := os.Stat(pendingFilename)
	if err != nil {
		// XXX hits sometimes; attempting to verify before download
		// is complete?
		log.Errorf("markObjectAsVerifying failed %s", err)
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, status, cerr)
		log.Errorf("markObjectAsVerifying failed for %s", config.Name)
		return false, 0
	}

	if _, err := os.Stat(verifierFilename); err == nil {
		log.Warn(verifierFilename + ": file exists")
		if err := os.RemoveAll(verifierFilename); err != nil {
			log.Fatal(err)
		}
	}

	log.Tracef("markObjectAsVerifying: Create %s", verifierDirname)
	if err := os.MkdirAll(verifierDirname, 0700); err != nil {
		log.Fatal(err)
	}

	if err := os.Rename(pendingFilename, verifierFilename); err != nil {
		log.Fatal(err)
	}

	if err := os.Chmod(verifierDirname, 0500); err != nil {
		log.Fatal(err)
	}

	if err := os.Chmod(verifierFilename, 0400); err != nil {
		log.Fatal(err)
	}
	status.FileLocation = verifierFilename
	return true, info.Size()
}

func markObjectAsVerified(config *types.VerifyImageConfig, status *types.VerifyImageStatus, tmpID uuid.UUID) {

	verifiedDirname := getVerifiedDir()
	_, verifierFilename, verifiedFilename := ImageVerifierFilenames(config.FileLocation, config.ImageSha256, tmpID.String())
	// Move directory from DownloadDirname/verifier to
	// DownloadDirname/verified
	// XXX should have dom0 do this and/or have RO mounts
	log.Functionf("markObjectAsVerified: Move from %s to %s", verifierFilename, verifiedFilename)

	if _, err := os.Stat(verifierFilename); err != nil {
		log.Fatal(err)
	}

	if _, err := os.Stat(verifiedFilename); err == nil {
		log.Warn(verifiedFilename + ": file exists")
		if err := os.RemoveAll(verifiedFilename); err != nil {
			log.Fatal(err)
		}
	}

	log.Functionf("markObjectAsVerified: Create %s", verifiedDirname)
	if err := os.MkdirAll(verifiedDirname, 0700); err != nil {
		log.Fatal(err)
	}

	if err := os.Rename(verifierFilename, verifiedFilename); err != nil {
		log.Fatal(err)
	}

	if err := os.Chmod(verifiedDirname, 0500); err != nil {
		log.Fatal(err)
	}

	status.FileLocation = verifiedFilename

	log.Functionf("markObjectAsVerified - DOne. Moved from %s to %s",
		verifierFilename, verifiedFilename)
}

// Recreate VerifyImageStatus for verified files as types.VERIFIED
func handleInitVerifiedObjects(ctx *verifierContext) {

	verifiedDirname := getVerifiedDir()
	if _, err := os.Stat(verifiedDirname); err == nil {
		populateInitialStatusFromVerified(ctx, verifiedDirname, "")
	}
}

func verifyImageStatusFromImageFile(imageFileName string,
	size int64, pathname string) *types.VerifyImageStatus {

	status := types.VerifyImageStatus{
		Name:         imageFileName,
		FileLocation: pathname,
		ImageSha256:  imageFileName,
		Size:         size,
		State:        types.VERIFIED,
		RefCount:     0,
	}
	return &status
}

// Recursive scanning for verified objects,
// to recreate the VerifyImageStatus.
func populateInitialStatusFromVerified(ctx *verifierContext,
	objDirname string, parentDirname string) {

	log.Functionf("populateInitialStatusFromVerified(%s, %s)", objDirname,
		parentDirname)

	locations, err := ioutil.ReadDir(objDirname)

	if err != nil {
		log.Fatal(err)
	}

	log.Tracef("populateInitialStatusFromVerified: processing locations %v", locations)

	for _, location := range locations {

		pathname := objDirname + "/" + location.Name()

		if location.IsDir() {
			log.Tracef("populateInitialStatusFromVerified: Recursively looking in %s",
				pathname)
			if _, err := os.Stat(pathname); err == nil {
				populateInitialStatusFromVerified(ctx,
					pathname, location.Name())
			}
		} else {
			size := int64(0)
			info, err := os.Stat(pathname)
			if err != nil {
				// XXX Delete file?
				log.Error(err)
			} else {
				size = info.Size()
			}
			log.Tracef("populateInitialStatusFromVerified: Processing %s: %d Mbytes",
				pathname, size/(1024*1024))
			status := verifyImageStatusFromImageFile(
				location.Name(), size, pathname)
			if status != nil {
				publishVerifyImageStatus(ctx, status)
			}
		}
	}
}

func getVerifierDir() string {
	return path.Join(verifierBasePath, "verifier")
}

func getVerifiedDir() string {
	return path.Join(verifierBasePath, "verified")
}
