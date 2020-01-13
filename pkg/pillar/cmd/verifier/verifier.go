// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of collections of VerifyImageConfig structs
// and publish the results as collections of VerifyImageStatus structs.
// There are several inputs and outputs based on the objType.
// Process input changes from a config directory containing json encoded files
// with VerifyImageConfig and compare against VerifyImageStatus in the status
// dir.
//
// Move the file from DownloadDirname/pending/<imageID> to
// to DownloadDirname/verifier/<imageID> and make RO,
// then attempt to verify sum.
// Once sum is verified, move to DownloadDirname/verified/<imageID>/<filename> where the filename is the last part of the URL (after the last '/')

package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	agentName = "verifier"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	// If this file is present we don't delete verified files in handleDelete
	preserveFilename = types.TmpDirname + "/preserve"
)

// Go doesn't like this as a constant
var (
	verifierObjTypes = []string{types.AppImgObj, types.BaseOsObj}
	vHandler         = makeVerifyHandler()
)

// Set from Makefile
var Version = "No version specified"

// Any state used by handlers goes here
type verifierContext struct {
	subAppImgConfig       pubsub.Subscription
	pubAppImgStatus       pubsub.Publication
	subBaseOsConfig       pubsub.Subscription
	pubBaseOsStatus       pubsub.Publication
	subGlobalConfig       pubsub.Subscription
	assignableAdapters    *types.AssignableAdapters
	subAssignableAdapters pubsub.Subscription
	gc                    *time.Ticker
	RktGCGracePeriod      uint32
	GCInitialized         bool
}

var debug = false
var debugOverride bool                                // From command line arg
var downloadGCTime = time.Duration(600) * time.Second // Unless from GlobalConfig

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
	logf, err := agentlog.Init(agentName, curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s\n", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	// create the directories
	initializeDirs()

	// Any state needed by handler functions
	aa := types.AssignableAdapters{}
	ctx := verifierContext{
		assignableAdapters: &aa,
	}

	// Set up our publications before the subscriptions so ctx is set
	pubAppImgStatus, err := pubsub.PublishScope(agentName, types.AppImgObj,
		types.VerifyImageStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppImgStatus = pubAppImgStatus
	pubAppImgStatus.ClearRestarted()

	pubBaseOsStatus, err := pubsub.PublishScope(agentName, types.BaseOsObj,
		types.VerifyImageStatus{})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubBaseOsStatus = pubBaseOsStatus
	pubBaseOsStatus.ClearRestarted()

	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &ctx, &pubsub.SubscriptionOptions{
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

	subAppImgConfig, err := pubsub.SubscribeScope("zedmanager",
		types.AppImgObj, types.VerifyImageConfig{}, false, &ctx, &pubsub.SubscriptionOptions{
			CreateHandler: handleAppImgCreate,
			ModifyHandler: handleAppImgModify,
			DeleteHandler: handleAppImgDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppImgConfig = subAppImgConfig
	subAppImgConfig.Activate()

	subBaseOsConfig, err := pubsub.SubscribeScope("baseosmgr",
		types.BaseOsObj, types.VerifyImageConfig{}, false, &ctx, &pubsub.SubscriptionOptions{
			CreateHandler: handleBaseOsCreate,
			ModifyHandler: handleBaseOsModify,
			DeleteHandler: handleBaseOsDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()

	subAssignableAdapters, err := pubsub.Subscribe("domainmgr",
		types.AssignableAdapters{}, false, &ctx, &pubsub.SubscriptionOptions{
			ModifyHandler: handleAAModify,
			DeleteHandler: handleAADelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAssignableAdapters = subAssignableAdapters
	subAssignableAdapters.Activate()

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
	log.Infof("processed GlobalConfig")

	// Publish status for any objects that were verified before reboot
	// The signatures will be re-checked during handleModify for App images.
	handleInit(&ctx)

	// Report to zedmanager that init is done
	pubAppImgStatus.SignalRestarted()
	pubBaseOsStatus.SignalRestarted()
	log.Infof("SignalRestarted done")

	// We will cleanup zero RefCount objects after a while
	// We run timer 10 times more often than the limit on LastUse
	// Here initialize the gc before the select handles it, but stop
	// the timer since it waits until we are connected to the cloud and
	// gets the AA init before declare something is stale and need deletion
	ctx.gc = time.NewTicker(downloadGCTime / 10)
	ctx.gc.Stop()

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subAppImgConfig.MsgChan():
			subAppImgConfig.ProcessChange(change)

		case change := <-subBaseOsConfig.MsgChan():
			subBaseOsConfig.ProcessChange(change)

		case change := <-subAssignableAdapters.MsgChan():
			subAssignableAdapters.ProcessChange(change)

		case <-ctx.gc.C:
			start := time.Now()
			gcVerifiedObjects(&ctx)
			pubsub.CheckMaxTimeTopic(agentName, "gc", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleInit(ctx *verifierContext) {

	log.Infoln("handleInit")

	// mark all status file to PendingDelete
	handleInitWorkinProgressObjects(ctx)

	// Recreate status for objects that were verified before reboot
	handleInitVerifiedObjects(ctx)

	// delete status files marked PendingDelete
	handleInitMarkedDeletePendingObjects(ctx)

	log.Infoln("handleInit done")
}

func initializeDirs() {
	// first the certs directory
	if _, err := os.Stat(types.CertificateDirname); err != nil {
		log.Debugf("Create %s\n", types.CertificateDirname)
		if err := os.MkdirAll(types.CertificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// Remove any files which didn't make it past the verifier.
	// useful for calculating total available space in
	// downloader context
	// XXX when does downloader calculate space?
	clearInProgressDownloadDirs(verifierObjTypes)

	// create the object download directories
	createDownloadDirs(verifierObjTypes)
}

// Mark all existing Status as PendingDelete.
// If they correspond to verified files then in the handleInitVerifiedObjects
// function PendingDelete will be reset. Finally, in
// handleInitMarkedDeletePendingObjects we will delete anything which still
// has PendingDelete set.
func handleInitWorkinProgressObjects(ctx *verifierContext) {

	publications := []pubsub.Publication{
		ctx.pubAppImgStatus,
		ctx.pubBaseOsStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.VerifyImageStatus)
			log.Debugf("Marking with PendingDelete: %s\n", status.Key())
			status.PendingDelete = true
			publishVerifyImageStatus(ctx, &status)
		}
	}
}

// Recreate status files for verified objects as types.DOWNLOADED
// except containers which we mark as types.DELIVERED
func handleInitVerifiedObjects(ctx *verifierContext) {

	for _, objType := range verifierObjTypes {

		verifiedDirname := types.DownloadDirname + "/" + objType + "/verified"
		if _, err := os.Stat(verifiedDirname); err == nil {
			populateInitialStatusFromVerified(ctx, objType,
				verifiedDirname, "")
		}
	}
}

func verifiedImageStatusFromImageFile(
	objType, objDirname, parentDirname, imageFileName string,
	size int64, filename string) *types.VerifyImageStatus {

	status := types.VerifyImageStatus{
		Name:     imageFileName,
		ObjType:  objType,
		State:    types.DOWNLOADED,
		Size:     size,
		RefCount: 0,
		LastUse:  time.Now(),
	}

	// The parentDirname is always the imageID
	imageID, err := uuid.FromString(parentDirname)

	log.Debugf("verifiedImageStatusFromImageFile: objType: %s, "+
		"objDirname: %s, parentDirname: %s, imageFileName: %s, "+
		"imageID: %s", objType, objDirname, parentDirname,
		imageFileName, imageID.String())

	if err != nil {
		log.Errorf("parentDirname %s without valid UUID for %s: %s",
			parentDirname, imageFileName, err)
		return nil
	}
	status.FileLocation = filename
	status.ImageID = imageID
	log.Debugf("verifiedImageStatusFromImageFile: status: %+v", status)
	return &status
}

// Recursive scanning for verified objects,
// to recreate the VerifyImageStatus.
func populateInitialStatusFromVerified(ctx *verifierContext,
	objType string, objDirname string, parentDirname string) {

	log.Infof("populateInitialStatusFromVerified(%s, %s)\n", objDirname,
		parentDirname)

	locations, err := ioutil.ReadDir(objDirname)

	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("populateInitialStatusFromVerified: processing locations %v", locations)

	for _, location := range locations {

		filename := objDirname + "/" + location.Name()

		if location.IsDir() {
			log.Debugf("populateInitialStatusFromVerified: Looking in %s\n", filename)
			if _, err := os.Stat(filename); err == nil {
				populateInitialStatusFromVerified(ctx,
					objType, filename, location.Name())
			}
		} else {
			size := int64(0)
			info, err := os.Stat(filename)
			if err != nil {
				// XXX Delete file?
				log.Error(err)
			} else {
				size = info.Size()
			}
			log.Debugf("populateInitialStatusFromVerified: Processing %s: %d Mbytes\n",
				filename, size/(1024*1024))
			status := verifiedImageStatusFromImageFile(objType, objDirname,
				parentDirname, location.Name(), size, filename)
			if status != nil {
				publishVerifyImageStatus(ctx, status)
			}
		}
	}
}

// remove the status files marked as pending delete
func handleInitMarkedDeletePendingObjects(ctx *verifierContext) {
	publications := []pubsub.Publication{
		ctx.pubAppImgStatus,
		ctx.pubBaseOsStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.VerifyImageStatus)
			if status.PendingDelete {
				log.Infof("still PendingDelete; delete %s\n",
					status.Key())
				unpublishVerifyImageStatus(ctx, &status)
			}
		}
	}
}

// Create the object download directories we own
func createDownloadDirs(objTypes []string) {

	workingDirTypes := []string{"verifier", "verified"}

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

	inProgressDirTypes := []string{"verifier"}

	// Now remove the in-progress dirs
	for _, objType := range objTypes {
		for _, dirType := range inProgressDirTypes {
			dirName := types.DownloadDirname + "/" + objType + "/" + dirType
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
func gcVerifiedObjects(ctx *verifierContext) {
	log.Debugf("gcVerifiedObjects()\n")
	publications := []pubsub.Publication{
		ctx.pubAppImgStatus,
		ctx.pubBaseOsStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.VerifyImageStatus)
			if status.RefCount != 0 {
				log.Debugf("gcVerifiedObjects: skipping RefCount %d: %s\n",
					status.RefCount, status.Key())
				continue
			}
			timePassed := time.Since(status.LastUse)
			if timePassed < downloadGCTime {
				log.Debugf("gcverifiedObjects: skipping recently used %s remains %d seconds\n",
					status.Key(),
					(timePassed-downloadGCTime)/time.Second)
				continue
			}
			log.Infof("gcVerifiedObjects: expiring status for %s; LastUse %v now %v\n",
				status.Key(), status.LastUse, time.Now())
			status.Expired = true
			publishVerifyImageStatus(ctx, &status)
		}
	}

	// Run rkt garbage collect
	rktGc(ctx.RktGCGracePeriod, false)
	rktGc(ctx.RktGCGracePeriod, true)
}

func rktGc(gracePeriod uint32, imageGc bool) {
	log.Infof("rktGc %d\n", gracePeriod)

	gracePeriodOption := fmt.Sprintf("--grace-period=%ds", gracePeriod)
	cmd := "rkt"
	args := []string{}
	if imageGc {
		args = append(args, "image")
	}
	args = append(args, []string{
		"gc",
		"--dir=" + types.PersistRktDataDir,
		gracePeriodOption,
	}...)
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorf("***rkt gc failed: %+v ", err)
		log.Errorf("***rkt gc output: %s", string(stdoutStderr))
		return
	}
	log.Debugf("rkt gc done: %s", string(stdoutStderr))
	return
}

func updateVerifyErrStatus(ctx *verifierContext,
	status *types.VerifyImageStatus, lastErr string) {

	status.LastErr = lastErr
	status.LastErrTime = time.Now()
	status.PendingAdd = false
	publishVerifyImageStatus(ctx, status)
}

func publishVerifyImageStatus(ctx *verifierContext,
	status *types.VerifyImageStatus) {

	log.Debugf("publishVerifyImageStatus(%s, %s)\n",
		status.ObjType, status.ImageID)

	pub := verifierPublication(ctx, status.ObjType)
	key := status.Key()
	pub.Publish(key, *status)
}

func unpublishVerifyImageStatus(ctx *verifierContext,
	status *types.VerifyImageStatus) {

	log.Debugf("publishVerifyImageStatus(%s, %s)\n",
		status.ObjType, status.ImageID)

	pub := verifierPublication(ctx, status.ObjType)
	key := status.Key()
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishVerifyImageStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func verifierPublication(ctx *verifierContext, objType string) pubsub.Publication {
	var pub pubsub.Publication
	switch objType {
	case types.AppImgObj:
		pub = ctx.pubAppImgStatus
	case types.BaseOsObj:
		pub = ctx.pubBaseOsStatus
	default:
		log.Fatalf("verifierPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}

// Callers must be careful to publish any changes to VerifyImageStatus
func lookupVerifyImageStatus(ctx *verifierContext, objType string,
	key string) *types.VerifyImageStatus {

	pub := verifierPublication(ctx, objType)
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupVerifyImageStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.VerifyImageStatus)
	return &status
}

// Server for each domU
func runHandler(ctx *verifierContext, objType string, key string,
	c <-chan interface{}) {

	log.Infof("runHandler starting\n")

	closed := false
	for !closed {
		select {
		case configArg, ok := <-c:
			if ok {
				config := configArg.(types.VerifyImageConfig)
				status := lookupVerifyImageStatus(ctx,
					objType, key)
				if status == nil {
					handleCreate(ctx, objType, &config)
				} else {
					handleModify(ctx, &config, status)
				}
			} else {
				// Closed
				status := lookupVerifyImageStatus(ctx,
					objType, key)
				if status != nil {
					handleDelete(ctx, status)
				}
				closed = true
			}
		}
	}
	log.Infof("runHandler(%s) DONE\n", key)
}

func handleCreate(ctx *verifierContext, objType string,
	config *types.VerifyImageConfig) {

	log.Infof("handleCreate(%s) objType %s for %s\n",
		config.ImageID, objType, config.Name)
	if objType == "" {
		log.Fatalf("handleCreate: No ObjType for %s\n",
			config.ImageID)
	}

	status := types.VerifyImageStatus{
		ImageID:     config.ImageID,
		Name:        config.Name,
		ObjType:     objType,
		ImageSha256: config.ImageSha256,
		PendingAdd:  true,
		State:       types.DOWNLOADED,
		RefCount:    config.RefCount,
		LastUse:     time.Now(),
		IsContainer: config.IsContainer,
	}
	publishVerifyImageStatus(ctx, &status)

	ok, size := markObjectAsVerifying(ctx, config, &status)
	if !ok {
		log.Errorf("handleCreate fail for %s\n", config.Name)
		return
	}
	status.Size = size
	publishVerifyImageStatus(ctx, &status)

	if !verifyObjectSha(ctx, config, &status) {
		log.Errorf("handleCreate fail for %s\n", config.Name)
		return
	}
	publishVerifyImageStatus(ctx, &status)

	markObjectAsVerified(ctx, config, &status)
	status.PendingAdd = false
	status.State = types.DELIVERED
	publishVerifyImageStatus(ctx, &status)
	log.Infof("handleCreate done for %s\n", config.Name)
}

// Returns ok, size of object
func markObjectAsVerifying(ctx *verifierContext,
	config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) (bool, int64) {

	pendingDirname, verifierDirname, _ := status.ImageDownloadDirNames()
	pendingFilename, verifierFilename, _ := status.ImageDownloadFilenames()

	// Move to verifier directory which is RO
	// XXX should have dom0 do this and/or have RO mounts
	log.Infof("Move from %s to %s\n", pendingFilename, verifierFilename)

	info, err := os.Stat(pendingFilename)
	if err != nil {
		// XXX hits sometimes; attempting to verify before download
		// is complete?
		log.Errorf("markObjectAsVerifying failed %s\n", err)
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, status, cerr)
		log.Errorf("markObjectAsVerifying failed for %s\n", config.Name)
		return false, 0
	}

	if _, err := os.Stat(verifierFilename); err == nil {
		log.Fatal(err)
	}

	if _, err := os.Stat(verifierDirname); err == nil {
		if err := os.RemoveAll(verifierDirname); err != nil {
			log.Fatal(err)
		}
	}
	log.Debugf("Create %s\n", verifierDirname)
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
	// Clean up empty directory
	if err := os.RemoveAll(pendingDirname); err != nil {
		log.Fatal(err)
	}
	return true, info.Size()
}

func verifyObjectSha(ctx *verifierContext, config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) bool {

	_, verifierFilename, _ := status.ImageDownloadFilenames()
	log.Infof("Verifying URL %s file %s\n", config.Name, verifierFilename)

	imageHashB, err := computeShaFileByType(verifierFilename, status.IsContainer)
	if err != nil {
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, status, cerr)
		log.Errorf("verifyObjectSha %s failed %s\n",
			config.Name, cerr)
		return false
	}
	log.Infof("internal hash consistency validated for URL %s file %s", config.Name, verifierFilename)

	imageHash := fmt.Sprintf("%x", imageHashB)
	configuredHash := strings.ToLower(config.ImageSha256)
	// XXX: the ImageSha256 property should never be filled with anything
	// other than a sha256 hash of the image. It should be valid as blank,
	// which means "do not verify, as I have nothing to verify against."
	// Unfortunately, some parts of the code assume that ImageSha256 alwats will
	// have something, so containers override it with the imageUUID. Once that is
	// changed, this code should go away.
	if _, err := uuid.FromString(config.ImageSha256); err == nil {
		configuredHash = ""
	}

	if configuredHash == "" {
		log.Infof("no image hash provided, skipping root validation")
	} else if imageHash != configuredHash {
		log.Errorf("computed   %s\n", imageHash)
		log.Errorf("configured %s\n", configuredHash)
		cerr := fmt.Sprintf("computed %s configured %s",
			imageHash, configuredHash)
		status.PendingAdd = false
		updateVerifyErrStatus(ctx, status, cerr)
		log.Errorf("verifyObjectSha %s failed %s\n",
			config.Name, cerr)
		return false
	}

	log.Infof("Sha validation successful for %s\n", config.Name)

	// we only do this for non-OCI images for now, as we do not have hash signing
	if !status.IsContainer {
		if cerr := verifyObjectShaSignature(status, config, imageHashB); cerr != "" {
			updateVerifyErrStatus(ctx, status, cerr)
			log.Errorf("Signature validation failed for %s, %s\n",
				config.Name, cerr)
			return false
		}
	}
	return true
}

// compute the hash for different file types. If the file itself contains
// sub-dependencies with hashes as well, example inside a tar file, validate
// those hashes as well.
// Returns the hash of the file itself, or the root of the dependencies.
func computeShaFileByType(filename string, container bool) ([]byte, error) {
	if container {
		return computeShaOCITar(filename)
	}
	return computeShaFile(filename)
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

func verifyObjectShaSignature(status *types.VerifyImageStatus, config *types.VerifyImageConfig, imageHash []byte) string {

	// XXX:FIXME if Image Signature is absent, skip
	// mark it as verified; implicitly assuming,
	// if signature is filled in, marking this object
	//  as valid may not hold good always!!!
	if (config.ImageSignature == nil) ||
		(len(config.ImageSignature) == 0) {
		log.Infof("No signature to verify for %s\n",
			config.Name)
		return ""
	}

	log.Infof("Validating %s using cert %s sha %s\n",
		config.Name, config.SignatureKey,
		config.ImageSha256)

	//Read the server certificate
	//Decode it and parse it
	//And find out the puplic key and it's type
	//we will use this certificate for both cert chain verification
	//and signature verification...

	//This func literal will take care of writing status during
	//cert chain and signature verification...

	serverCertName := types.UrlToFilename(config.SignatureKey)
	serverCertificate, err := ioutil.ReadFile(types.CertificateDirname + "/" + serverCertName)
	if err != nil {
		cerr := fmt.Sprintf("unable to read the certificate %s: %s", serverCertName, err)
		return cerr
	}

	block, _ := pem.Decode(serverCertificate)
	if block == nil {
		cerr := fmt.Sprintf("unable to decode server certificate")
		return cerr
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		cerr := fmt.Sprintf("unable to parse certificate: %s", err)
		return cerr
	}

	//Verify chain of certificates. Chain contains
	//root, server, intermediate certificates ...

	certificateNameInChain := config.CertificateChain

	//Create the set of root certificates...
	roots := x509.NewCertPool()

	// Read the root cerificates from /config
	rootCertificate, err := ioutil.ReadFile(types.RootCertFileName)
	if err != nil {
		log.Errorln(err)
		cerr := fmt.Sprintf("failed to find root certificate: %s", err)
		return cerr
	}

	if ok := roots.AppendCertsFromPEM(rootCertificate); !ok {
		cerr := fmt.Sprintf("failed to parse root certificate")
		return cerr
	}

	for _, certUrl := range certificateNameInChain {

		certName := types.UrlToFilename(certUrl)

		bytes, err := ioutil.ReadFile(types.CertificateDirname + "/" + certName)
		if err != nil {
			cerr := fmt.Sprintf("failed to read certificate Directory %s: %s",
				certName, err)
			return cerr
		}

		if ok := roots.AppendCertsFromPEM(bytes); !ok {
			cerr := fmt.Sprintf("failed to parse intermediate certificate")
			return cerr
		}
	}

	opts := x509.VerifyOptions{Roots: roots}
	if _, err := cert.Verify(opts); err != nil {
		cerr := fmt.Sprintf("failed to verify certificate chain: %s",
			err)
		return cerr
	}

	log.Infof("certificate options verified for %s\n", config.Name)

	//Read the signature from config file...
	imgSig := config.ImageSignature

	switch pub := cert.PublicKey.(type) {

	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, imageHash, imgSig)
		if err != nil {
			cerr := fmt.Sprintf("rsa image signature verification failed: %s", err)
			return cerr
		}
		log.Infof("VerifyPKCS1v15 successful for %s\n",
			config.Name)
	case *ecdsa.PublicKey:
		imgSignature, err := base64.StdEncoding.DecodeString(string(imgSig))
		if err != nil {
			cerr := fmt.Sprintf("DecodeString failed: %v ", err)
			return cerr
		}

		log.Debugf("Decoded imgSignature (len %d): % x\n",
			len(imgSignature), imgSignature)
		rbytes := imgSignature[0:32]
		sbytes := imgSignature[32:]
		log.Debugf("Decoded r %d s %d\n", len(rbytes), len(sbytes))
		r := new(big.Int)
		s := new(big.Int)
		r.SetBytes(rbytes)
		s.SetBytes(sbytes)
		log.Debugf("Decoded r, s: %v, %v\n", r, s)
		ok := ecdsa.Verify(pub, imageHash, r, s)
		if !ok {
			cerr := fmt.Sprintf("ecdsa image signature verification failed")
			return cerr
		}
		log.Infof("ecdsa Verify successful for %s\n",
			config.Name)
	default:
		cerr := fmt.Sprintf("unknown type of public key")
		return cerr
	}
	return ""
}

func markObjectAsVerified(ctx *verifierContext, config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) {

	_, verifierDirname, verifiedDirname := status.ImageDownloadDirNames()
	_, verifierFilename, verifiedFilename := status.ImageDownloadFilenames()
	// Move directory from DownloadDirname/verifier to
	// DownloadDirname/verified
	// XXX should have dom0 do this and/or have RO mounts
	log.Infof("Move from %s to %s\n", verifierFilename, verifiedFilename)

	if _, err := os.Stat(verifierFilename); err != nil {
		log.Fatal(err)
	}

	if _, err := os.Stat(verifiedFilename); err == nil {
		log.Warn(verifiedFilename + ": file exists")
		if err := os.RemoveAll(verifiedFilename); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(verifiedDirname); err == nil {
		log.Warn(verifiedDirname + ": directory exists")
		if err := os.RemoveAll(verifiedDirname); err != nil {
			log.Fatal(err)
		}
	}

	log.Infof("Create %s\n", verifiedDirname)
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

	// Clean up empty directory
	if err := os.RemoveAll(verifierDirname); err != nil {
		log.Fatal(err)
	}
	log.Infof("markObjectAsVerified - DOne. Moved from %s to %s\n",
		verifierFilename, verifiedFilename)
}

func handleModify(ctx *verifierContext, config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) {

	// Note no comparison on version
	changed := false

	log.Infof("handleModify(%s) objType %s for %s, config.RefCount: %d, "+
		"status.RefCount: %d, isContainer: %t",
		status.ImageID, status.ObjType, config.Name, config.RefCount,
		status.RefCount, config.IsContainer)

	if status.ObjType == "" {
		log.Fatalf("handleModify: No ObjType for %s\n",
			status.ImageID)
	}

	if config.IsContainer != status.IsContainer {
		log.Infof("handleModify: Setting IsContainer to %t for %s",
			config.IsContainer, status.ImageID)
		status.IsContainer = config.IsContainer
		changed = true
	}
	if status.ImageSha256 == "" && config.ImageSha256 != "" {
		log.Infof("handleModify: Setting ImageSha256 to %s for %s",
			config.ImageSha256, status.ImageID)
		status.ImageSha256 = config.ImageSha256
		changed = true
	}

	if status.IsContainer {
		if status.State == types.DOWNLOADED {
			// No verification supported for Containers. So mark it as delivered.
			log.Debugf("handleModify - Container image (%s) state set to ."+
				"DELIVERED", status.ImageID)
			status.State = types.DELIVERED
			publishVerifyImageStatus(ctx, status)
		}
	} else if status.State == types.DOWNLOADED {
		// VM Modify request, but status is in DOWNLOADED state. This happens
		// during reboot. Compute the SHA
		_, _, verifiedFilename := status.ImageDownloadFilenames()
		imageHash, err := computeShaFile(verifiedFilename)
		if err != nil {
			cerr := fmt.Sprintf("%s", err)
			updateVerifyErrStatus(ctx, status, cerr)
			log.Errorf("computeShaFile %s failed %s\n",
				verifiedFilename, cerr)
			log.Infof("handleModify: Done for %s", config.Name)
			return
		}
		got := fmt.Sprintf("%x", imageHash)
		if got == strings.ToLower(status.ImageSha256) {
			log.Infof("handleModify - %s verification succeeded",
				verifiedFilename)
			status.State = types.DELIVERED
			publishVerifyImageStatus(ctx, status)
		} else {
			// Withdraw status as if it never existed
			// New download and verification will follow
			err = fmt.Errorf("Verification Failed after rebot. "+
				"verifiedFilename: %s\ncomputed: %s\nconfigured: %s",
				verifiedFilename, got, strings.ToLower(status.ImageSha256))
			log.Errorf(err.Error())
			doDelete(status)
			unpublishVerifyImageStatus(ctx, status)
		}
	}

	// Always update RefCount
	if status.RefCount != config.RefCount {
		log.Infof("handleModify RefCount change %s from %d to %d Expired %v\n",
			config.Name, status.RefCount, config.RefCount,
			status.Expired)
		status.RefCount = config.RefCount
		status.Expired = false
		changed = true
	}

	if status.RefCount == 0 {
		// GC timer will clean up by marking status Expired
		// and some point in time.
		// Then user (zedmanager/baseosmgr) will delete config.
		status.PendingModify = true
		status.LastUse = time.Now()
		status.PendingModify = false
		publishVerifyImageStatus(ctx, status)
		log.Infof("handleModify: RefCount = 0. Done for %s\n", config.Name)
		return
	}

	if changed {
		publishVerifyImageStatus(ctx, status)
	}
	log.Infof("handleModify done for %s. Status.RefCount=%d, Config.RefCount:%d",
		config.Name, status.RefCount, config.RefCount)
}

func handleDelete(ctx *verifierContext, status *types.VerifyImageStatus) {

	log.Infof("handleDelete(%s) objType %s refcount %d lastUse %v Expired %v\n",
		status.ImageID, status.ObjType, status.RefCount,
		status.LastUse, status.Expired)

	if status.ObjType == "" {
		log.Fatalf("handleDelete: No ObjType for %s\n",
			status.ImageID)
	}

	doDelete(status)

	unpublishVerifyImageStatus(ctx, status)
	log.Infof("handleDelete done for %s\n", status.ImageID)
}

// Remove the file from any of the three directories
// Only if it verified (state DELIVERED) do we delete the final. Needed
// to avoid deleting a different verified file with same sha as this claimed
// to have
func doDelete(status *types.VerifyImageStatus) {
	log.Infof("doDelete(%s)\n", status.ImageID)

	_, verifierDirname, verifiedDirname := status.ImageDownloadDirNames()

	_, err := os.Stat(verifierDirname)
	if err == nil {
		log.Infof("doDelete removing verifier %s\n", verifierDirname)
		if err := os.RemoveAll(verifierDirname); err != nil {
			log.Fatal(err)
		}
	}
	_, err = os.Stat(verifiedDirname)
	if err == nil && status.State == types.DELIVERED {
		if _, err := os.Stat(preserveFilename); err != nil {
			log.Infof("doDelete removing %s\n", verifiedDirname)
			if err := os.RemoveAll(verifiedDirname); err != nil {
				log.Fatal(err)
			}
		} else {
			log.Infof("doDelete preserving %s\n", verifiedDirname)
		}
	}
	log.Infof("doDelete(%s) done\n", status.ImageID)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*verifierContext)
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
		if gcp.RktGCGracePeriod != 0 {
			ctx.RktGCGracePeriod = gcp.RktGCGracePeriod
		}
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*verifierContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

func handleAAModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*verifierContext)
	status := statusArg.(types.AssignableAdapters)
	if key != "global" {
		log.Infof("handleAAModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleAAModify() %+v\n", status)
	*ctx.assignableAdapters = status
	// the AA iniializing starts the GC timer, and need to reset the
	// LastUse timestamp
	if ctx.assignableAdapters.Initialized {
		ctx.gc = time.NewTicker(downloadGCTime / 10)
		gcResetObjectLastUse(ctx)
		log.Infof("handleAAModify: AA initialized. verifier set gc timer\n")
	}
	log.Infof("handleAAModify() done\n")
}

func handleAADelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*verifierContext)
	if key != "global" {
		log.Infof("handleAADelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleAADelete()\n")
	ctx.assignableAdapters.Initialized = false
	log.Infof("handleAADelete() done\n")
}

// gc timer just started, reset the LastUse timestamp to now if the refcount is zero
func gcResetObjectLastUse(ctx *verifierContext) {
	publications := []pubsub.Publication{
		ctx.pubAppImgStatus,
		ctx.pubBaseOsStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.VerifyImageStatus)
			if status.RefCount == 0 {
				status.LastUse = time.Now()
				log.Infof("gcResetObjectLastUse: reset %v LastUse to now\n", status.Key())
				publishVerifyImageStatus(ctx, &status)
			}
		}
	}
}
