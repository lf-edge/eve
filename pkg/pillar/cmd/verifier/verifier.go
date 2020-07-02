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
// Once sum is verified, move to DownloadDirname/verified/<sha256>/<filename> where the
// filename is the last part of the URL (after the last '/')

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
	"path"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

const (
	agentName = "verifier"
	// Time limits for event loop handlers
	errorTime        = 3 * time.Minute
	warningTime      = 40 * time.Second
	verifierBasePath = "/persist/downloads"
)

// Go doesn't like this as a constant
var (
	vHandler = makeVerifyHandler()
)

// Set from Makefile
var Version = "No version specified"

// Any state used by handlers goes here
type verifierContext struct {
	subAppImgConfig pubsub.Subscription
	pubAppImgStatus pubsub.Publication
	subBaseOsConfig pubsub.Subscription
	pubBaseOsStatus pubsub.Publication
	subGlobalConfig pubsub.Subscription

	GCInitialized bool
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
	agentlog.Init(agentName)

	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Infof("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName, warningTime, errorTime)

	// create the directories
	initializeDirs()

	// Any state needed by handler functions
	ctx := verifierContext{}

	// Set up our publications before the subscriptions so ctx is set
	pubAppImgStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			AgentScope: types.AppImgObj,
			TopicType:  types.VerifyImageStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubAppImgStatus = pubAppImgStatus

	pubBaseOsStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			AgentScope: types.BaseOsObj,
			TopicType:  types.VerifyImageStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubBaseOsStatus = pubBaseOsStatus

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

	subAppImgConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		AgentScope:    types.AppImgObj,
		TopicImpl:     types.VerifyImageConfig{},
		Activate:      false,
		Ctx:           &ctx,
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

	subBaseOsConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		AgentScope:    types.BaseOsObj,
		TopicImpl:     types.VerifyImageConfig{},
		Activate:      false,
		Ctx:           &ctx,
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
	// The signatures and shas can re-checked during handleCreate
	// by inserting code.
	handleInit(&ctx)

	// Report to volumemgr that init is done
	pubAppImgStatus.SignalRestarted()
	pubBaseOsStatus.SignalRestarted()
	log.Infof("SignalRestarted done")

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subAppImgConfig.MsgChan():
			subAppImgConfig.ProcessChange(change)

		case change := <-subBaseOsConfig.MsgChan():
			subBaseOsConfig.ProcessChange(change)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName, warningTime, errorTime)
	}
}

func handleInit(ctx *verifierContext) {

	log.Infoln("handleInit")

	// Create VerifyImageStatus for objects that were verified before reboot
	handleInitVerifiedObjects(ctx)

	log.Infoln("handleInit done")
}

func updateVerifyErrStatus(ctx *verifierContext,
	status *types.VerifyImageStatus, lastErr string) {

	status.SetErrorNow(lastErr)
	status.PendingAdd = false
	publishVerifyImageStatus(ctx, status)
}

func publishVerifyImageStatus(ctx *verifierContext,
	status *types.VerifyImageStatus) {

	log.Debugf("publishVerifyImageStatus(%s, %s)",
		status.ObjType, status.ImageID)

	pub := verifierPublication(ctx, status.ObjType)
	key := status.Key()
	pub.Publish(key, *status)
}

func unpublishVerifyImageStatus(ctx *verifierContext,
	status *types.VerifyImageStatus) {

	log.Debugf("publishVerifyImageStatus(%s, %s)",
		status.ObjType, status.ImageID)

	pub := verifierPublication(ctx, status.ObjType)
	key := status.Key()
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishVerifyImageStatus(%s) not found", key)
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
		log.Fatalf("verifierPublication: Unknown ObjType %s",
			objType)
	}
	return pub
}

func verifierSubscription(ctx *verifierContext, objType string) pubsub.Subscription {
	var sub pubsub.Subscription
	switch objType {
	case types.AppImgObj:
		sub = ctx.subAppImgConfig
	case types.BaseOsObj:
		sub = ctx.subBaseOsConfig
	default:
		log.Fatalf("verifierSubscription: Unknown ObjType %s",
			objType)
	}
	return sub
}

// Callers must be careful to publish any changes to VerifyImageStatus
func lookupVerifyImageStatus(ctx *verifierContext, objType string,
	key string) *types.VerifyImageStatus {

	pub := verifierPublication(ctx, objType)
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupVerifyImageStatus(%s) not found", key)
		return nil
	}
	status := st.(types.VerifyImageStatus)
	return &status
}

// Server for each VerifyImageConfig
func runHandler(ctx *verifierContext, objType string, key string,
	c <-chan Notify) {

	log.Infof("runHandler starting")

	closed := false
	for !closed {
		select {
		case _, ok := <-c:
			if ok {
				sub := verifierSubscription(ctx, objType)
				c, err := sub.Get(key)
				if err != nil {
					log.Errorf("runHandler no config for %s", key)
					continue
				}
				config := c.(types.VerifyImageConfig)
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
	log.Infof("runHandler(%s) DONE", key)
}

func handleCreate(ctx *verifierContext, objType string,
	config *types.VerifyImageConfig) {

	log.Infof("handleCreate(%s) objType %s for %s",
		config.ImageID, objType, config.Name)
	if objType == "" {
		log.Fatalf("handleCreate: No ObjType for %s",
			config.ImageID)
	}

	status := types.VerifyImageStatus{
		ImageID:     config.ImageID,
		Name:        config.Name,
		ObjType:     objType,
		ImageSha256: config.ImageSha256,
		PendingAdd:  true,
		State:       types.VERIFYING,
		RefCount:    config.RefCount,
		IsContainer: config.IsContainer,
	}
	publishVerifyImageStatus(ctx, &status)

	if config.FileLocation == "" {
		err := fmt.Errorf("handleCreate: verifyImageConfig: %s has empty fileLocation", config.ImageSha256)
		log.Errorf(err.Error())
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, &status, cerr)
		return
	}

	ok, size := markObjectAsVerifying(ctx, config, &status)
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

	markObjectAsVerified(config, &status)
	if status.FileLocation == "" {
		log.Fatalf("handleCreate: Verified but no FileLocation for %s", status.Key())
	}

	status.PendingAdd = false
	status.State = types.VERIFIED
	publishVerifyImageStatus(ctx, &status)
	log.Infof("handleCreate done for %s", config.Name)
}

func verifyObjectSha(ctx *verifierContext, config *types.VerifyImageConfig, status *types.VerifyImageStatus) bool {

	verifierFilename := status.FileLocation
	log.Infof("verifyObjectSha: Verifying URL %s file %s", config.Name, verifierFilename)

	_, err := os.Stat(verifierFilename)
	if err != nil {
		e := fmt.Errorf("verifyObjectSha: Unable to find location: %s. %s", verifierFilename, err)
		cerr := fmt.Sprintf("%v", e)
		updateVerifyErrStatus(ctx, status, cerr)
		log.Errorf("verifyObjectSha %s failed %s",
			config.Name, cerr)
		return false
	}

	imageHashB, err := computeShaFileByType(verifierFilename, status.IsContainer)
	if err != nil {
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(ctx, status, cerr)
		log.Errorf("verifyObjectSha %s failed %s",
			config.Name, cerr)
		return false
	}
	log.Infof("internal hash consistency validated for URL %s file %s", config.Name, verifierFilename)

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

	log.Infof("Sha validation successful for %s", config.Name)

	// we only do this for non-OCI images for now, as we do not have hash signing
	if !status.IsContainer {
		if cerr := verifyObjectShaSignature(status, config, imageHashB); cerr != "" {
			updateVerifyErrStatus(ctx, status, cerr)
			log.Errorf("Signature validation failed for %s, %s",
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
		log.Infof("No signature to verify for %s",
			config.Name)
		return ""
	}

	log.Infof("Validating %s using cert %s sha %s",
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

	// Read the signing root cerificates from /config
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

		// XXX must put these in Intermediates not Rootfs
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

	log.Infof("certificate options verified for %s", config.Name)

	//Read the signature from config file...
	imgSig := config.ImageSignature

	switch pub := cert.PublicKey.(type) {

	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, imageHash, imgSig)
		if err != nil {
			cerr := fmt.Sprintf("rsa image signature verification failed: %s", err)
			return cerr
		}
		log.Infof("VerifyPKCS1v15 successful for %s",
			config.Name)
	case *ecdsa.PublicKey:
		imgSignature, err := base64.StdEncoding.DecodeString(string(imgSig))
		if err != nil {
			cerr := fmt.Sprintf("DecodeString failed: %v ", err)
			return cerr
		}

		log.Debugf("Decoded imgSignature (len %d): % x",
			len(imgSignature), imgSignature)
		rbytes := imgSignature[0:32]
		sbytes := imgSignature[32:]
		log.Debugf("Decoded r %d s %d", len(rbytes), len(sbytes))
		r := new(big.Int)
		s := new(big.Int)
		r.SetBytes(rbytes)
		s.SetBytes(sbytes)
		log.Debugf("Decoded r, s: %v, %v", r, s)
		ok := ecdsa.Verify(pub, imageHash, r, s)
		if !ok {
			cerr := fmt.Sprintf("ecdsa image signature verification failed")
			return cerr
		}
		log.Infof("ecdsa Verify successful for %s",
			config.Name)
	default:
		cerr := fmt.Sprintf("unknown type of public key")
		return cerr
	}
	return ""
}

// This merely updates the RefCount and Expired in the status
// Note that verifier will retain the file even if RefCount in VerifyImageConfig
// is set to zero.
func handleModify(ctx *verifierContext, config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) {

	// Note no comparison on version
	changed := false

	log.Infof("handleModify(%s) objType %s for %s, config.RefCount: %d, "+
		"status.RefCount: %d, isContainer: %t",
		status.ImageID, status.ObjType, config.Name, config.RefCount,
		status.RefCount, config.IsContainer)

	if status.ObjType == "" {
		log.Fatalf("handleModify: No ObjType for %s",
			status.ImageID)
	}

	// Always update RefCount and Expired
	if status.RefCount != config.RefCount {
		log.Infof("handleModify RefCount change %s from %d to %d",
			config.Name, status.RefCount, config.RefCount)
		status.RefCount = config.RefCount
		changed = true
	}
	if status.Expired != config.Expired {
		log.Infof("handleModify Expired change %s from %t to %t",
			config.Name, status.Expired, config.Expired)
		status.Expired = config.Expired
		changed = true
	}

	if changed {
		publishVerifyImageStatus(ctx, status)
	}
	log.Infof("handleModify done for %s. Status.RefCount=%d, Config.RefCount:%d",
		config.Name, status.RefCount, config.RefCount)
}

// handleDelete means volumemgr wants us to delete the file.
// Note that verifier will retain the file even if RefCount in VerifyImageConfig
// is set to zero.
func handleDelete(ctx *verifierContext, status *types.VerifyImageStatus) {

	log.Infof("handleDelete(%s) objType %s refcount %d",
		status.ImageID, status.ObjType, status.RefCount)

	if status.ObjType == "" {
		log.Fatalf("handleDelete: No ObjType for %s",
			status.ImageID)
	}
	_, err := os.Stat(status.FileLocation)
	if err == nil {
		log.Infof("handleDelete removing %s",
			status.FileLocation)
		if err := os.RemoveAll(status.FileLocation); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Errorf("handleDelete: Unable to delete %s:  %s",
			status.FileLocation, err)
	}

	unpublishVerifyImageStatus(ctx, status)
	log.Infof("handleDelete done for %s", status.ImageID)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*verifierContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*verifierContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s", key)
}

// ImageVerifierDirNames - Returns pendingDirname, verifierDirname, verifiedDirname
// for the image.
func ImageVerifierDirNames(objType, ImageID, ImageSha256 string, config *types.VerifyImageConfig) (string, string, string) {

	var pendingDirname, verifierDirname, verifiedDirname string
	pendingDirname = path.Dir(config.FileLocation)
	verifierDirname = getVerifierDir(objType) + "/" + ImageID
	verifiedDirname = getVerifiedDir(objType) + "/" + ImageSha256
	return pendingDirname, verifierDirname, verifiedDirname
}

// ImageVerifierFilenames - Returns pendingFilename, verifierFilename, verifiedFilename
// for the image
func ImageVerifierFilenames(objType, ImageID, ImageSha256 string, config *types.VerifyImageConfig) (string, string, string) {
	var pendingFilename, verifierFilename, verifiedFilename string

	_, verifierDirname, verifiedDirname := ImageVerifierDirNames(objType, ImageID, ImageSha256, config)
	// Handle names which are paths
	filename := path.Base(config.FileLocation)
	pendingFilename = config.FileLocation
	verifierFilename = verifierDirname + "/" + filename
	verifiedFilename = verifiedDirname + "/" + filename
	return pendingFilename, verifierFilename, verifiedFilename
}

// Returns ok, size of object
func markObjectAsVerifying(ctx *verifierContext,
	config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) (bool, int64) {

	pendingDirname, verifierDirname, _ := ImageVerifierDirNames(status.ObjType, status.ImageID.String(), status.ImageSha256, config)
	pendingFilename, verifierFilename, _ := ImageVerifierFilenames(status.ObjType, status.ImageID.String(), status.ImageSha256, config)

	// Move to verifier directory which is RO
	// XXX should have dom0 do this and/or have RO mounts
	log.Infof("markObjectAsVerifying: Move from %s to %s", pendingFilename, verifierFilename)

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

	if _, err := os.Stat(verifierDirname); err == nil {
		if err := os.RemoveAll(verifierDirname); err != nil {
			log.Fatal(err)
		}
	}
	log.Debugf("markObjectAsVerifying: Create %s", verifierDirname)
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
	config.FileLocation = verifierFilename
	// Clean up empty directory
	if err := os.RemoveAll(pendingDirname); err != nil {
		log.Fatal(err)
	}
	return true, info.Size()
}

func markObjectAsVerified(config *types.VerifyImageConfig, status *types.VerifyImageStatus) {

	_, verifierDirname, verifiedDirname := ImageVerifierDirNames(status.ObjType, status.ImageID.String(), status.ImageSha256, config)
	_, verifierFilename, verifiedFilename := ImageVerifierFilenames(status.ObjType, status.ImageID.String(), status.ImageSha256, config)
	// Move directory from DownloadDirname/verifier to
	// DownloadDirname/verified
	// XXX should have dom0 do this and/or have RO mounts
	log.Infof("markObjectAsVerified: Move from %s to %s", verifierFilename, verifiedFilename)

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

	log.Infof("markObjectAsVerified: Create %s", verifiedDirname)
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
	log.Infof("markObjectAsVerified - DOne. Moved from %s to %s",
		verifierFilename, verifiedFilename)
}

// Recreate VerifyImageStatus for verified files as types.VERIFIED
func handleInitVerifiedObjects(ctx *verifierContext) {

	for _, objType := range verifierObjTypes {

		verifiedDirname := getVerifiedDir(objType)
		if _, err := os.Stat(verifiedDirname); err == nil {
			populateInitialStatusFromVerified(ctx, objType,
				verifiedDirname, "")
		}
	}
}

func verifyImageStatusFromImageFile(
	objType, objDirname, parentDirname, imageFileName string,
	size int64, filename string) *types.VerifyImageStatus {

	status := types.VerifyImageStatus{
		Name:         imageFileName,
		ObjType:      objType,
		FileLocation: filename,
		ImageSha256:  parentDirname,
		Size:         size,
		RefCount:     0,
	}

	log.Debugf("verifyImageStatusFromImageFile: objType: %s, "+
		"objDirname: %s, parentDirname: %s, imageFileName: %s",
		objType, objDirname, parentDirname, imageFileName)

	log.Debugf("verifyImageStatusFromImageFile: status: %+v", status)
	return &status
}

// Recursive scanning for verified objects,
// to recreate the VerifyImageStatus.
func populateInitialStatusFromVerified(ctx *verifierContext,
	objType string, objDirname string, parentDirname string) {

	log.Infof("populateInitialStatusFromVerified(%s, %s)", objDirname,
		parentDirname)

	locations, err := ioutil.ReadDir(objDirname)

	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("populateInitialStatusFromVerified: processing locations %v", locations)

	for _, location := range locations {

		filename := objDirname + "/" + location.Name()

		if location.IsDir() {
			log.Debugf("populateInitialStatusFromVerified: Looking in %s", filename)
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
			log.Debugf("populateInitialStatusFromVerified: Processing %s: %d Mbytes",
				filename, size/(1024*1024))
			status := verifyImageStatusFromImageFile(objType, objDirname,
				parentDirname, location.Name(), size, filename)
			if status != nil {
				publishVerifyImageStatus(ctx, status)
			}
		}
	}
}

func getVerifierDir(objType string) string {
	return verifierBasePath + "/" + objType + "/" + "verifier"
}

func getVerifiedDir(objType string) string {
	return verifierBasePath + "/" + objType + "/" + "verified"
}
