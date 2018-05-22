// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Process input changes from a config directory containing json encoded files
// with VerifyImageConfig and compare against VerifyImageStatus in the status
// dir.
// Move the file from objectDownloadDirname/pending/<claimedsha>/<safename> to
// to objectDownloadDirname/verifier/<claimedsha>/<safename> and make RO,
// then attempt to verify sum.
// Once sum is verified, move to objectDownloadDirname/verified/<sha>/<filename>// where the filename is the last part of the URL (after the last '/')
// Note that different URLs for same file will download to the same <sha>
// directory. We delete duplicates assuming the file content will be the same.

package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	appImgObj = "appImg.obj"
	baseOsObj = "baseOs.obj"
	agentName = "verifier"

	moduleName            = agentName
	zedBaseDirname        = "/var/tmp"
	zedRunDirname         = "/var/run"
	baseDirname           = zedBaseDirname + "/" + moduleName
	runDirname            = zedRunDirname + "/" + moduleName
	configDirname         = baseDirname + "/config"
	statusDirname         = runDirname + "/status"
	persistDir            = "/persist"
	objectDownloadDirname = persistDir + "/downloads"

	rootCertDirname    = "/config"
	rootCertFileName   = rootCertDirname + "/root-certificate.pem"
	certificateDirname = persistDir + "/certs"

	// If this file is present we don't delete verified files in handleDelete
	preserveFilename = configDirname + "/preserve"

	appImgConfigDirname = baseDirname + "/" + appImgObj + "/config"
	appImgStatusDirname = runDirname + "/" + appImgObj + "/status"

	baseOsConfigDirname = baseDirname + "/" + baseOsObj + "/config"
	baseOsStatusDirname = runDirname + "/" + baseOsObj + "/status"
)

// Go doesn't like this as a constant
var (
	verifierObjTypes = []string{appImgObj, baseOsObj}
)

// Set from Makefile
var Version = "No version specified"

// Any state used by handlers goes here
type verifierContext struct {
}

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	flag.Parse()
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)

	for _, ot := range verifierObjTypes {
		watch.CleanupRestartedObj(agentName, ot)
	}
	handleInit()

	// Report to zedmanager that init is done
	for _, ot := range verifierObjTypes {
		watch.SignalRestartedObj(agentName, ot)
	}

	// Any state needed by handler functions
	ctx := verifierContext{}

	appImgChanges := make(chan string)
	baseOsChanges := make(chan string)

	go watch.WatchConfigStatusAllowInitialConfig(appImgConfigDirname,
		appImgStatusDirname, appImgChanges)

	go watch.WatchConfigStatusAllowInitialConfig(baseOsConfigDirname,
		baseOsStatusDirname, baseOsChanges)

	// We will cleanup zero RefCount objects after a while
	// XXX hard-coded at 10 minutes
	gc := time.NewTimer(10 * time.Minute)

	for {
		select {
		case change := <-appImgChanges:
			{
				watch.HandleConfigStatusEvent(change, &ctx,
					appImgConfigDirname,
					appImgStatusDirname,
					&types.VerifyImageConfig{},
					&types.VerifyImageStatus{},
					handleAppImgObjCreate,
					handleModify,
					handleDelete, nil)
			}
		case change := <-baseOsChanges:
			{
				watch.HandleConfigStatusEvent(change, &ctx,
					baseOsConfigDirname,
					baseOsStatusDirname,
					&types.VerifyImageConfig{},
					&types.VerifyImageStatus{},
					handleBaseOsObjCreate,
					handleModify,
					handleDelete, nil)
			}
		case <-gc.C:
			gcVerifiedObjects()
		}
	}
}

func handleInit() {

	log.Println("handleInit")

	// create the directories
	initializeDirs()

	// mark all status file to PendingDelete
	handleInitWorkinProgressObjects()

	// recreate status files for verified objects
	handleInitVerifiedObjects()

	// delete status files marked PendingDelete
	handleInitMarkedDeletePendingObjects()

	log.Println("handleInit done")
}

func initializeDirs() {
	// first the certs directory
	if _, err := os.Stat(certificateDirname); err != nil {
		log.Printf("Create %s\n", certificateDirname)
		if err := os.MkdirAll(certificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// Remove any files which didn't make it past the verifier.
	// useful for calculating total available space in
	// downloader context
	clearInProgressDownloadDirs(verifierObjTypes)

	// create the object based config/status dirs
	createConfigStatusDirs(moduleName, verifierObjTypes)

	// create the object download directories
	createDownloadDirs(verifierObjTypes)
}

// Mark all existing Status as PendingDelete.
// If they correspond to verified files then in the handleInitVerifiedObjects
// function PendingDelete will be reset. Finally, in
// handleInitMarkedDeletePendingObjects we will delete anything which still
// has PendingDelete set.

// XXX if we read existing status files into collection first.
// then we can iterate over collection
func handleInitWorkinProgressObjects() {
	for _, objType := range verifierObjTypes {
		statusDirname := runDirname + "/" + objType + "/status"
		if _, err := os.Stat(statusDirname); err == nil {

			// Don't remove directory since there is a watch on it
			locations, err := ioutil.ReadDir(statusDirname)
			if err != nil {
				log.Fatal(err)
			}
			// Mark as PendingDelete and later purge such entries
			for _, location := range locations {

				if !strings.HasSuffix(location.Name(), ".json") {
					continue
				}
				status := types.VerifyImageStatus{}
				statusFile := statusDirname + "/" + location.Name()
				cb, err := ioutil.ReadFile(statusFile)
				if err != nil {
					log.Printf("%s for %s\n", err, statusFile)
					continue
				}
				if err := json.Unmarshal(cb, &status); err != nil {
					log.Printf("%s file: %s\n",
						err, statusFile)
					continue
				}
				log.Printf("Marking with PendingDelete: %s\n",
					statusFile)
				status.PendingDelete = true
				updateVerifyObjectStatus(&status)
			}
		}
	}
}

// recreate status files for verified objects
func handleInitVerifiedObjects() {
	for _, objType := range verifierObjTypes {

		verifiedDirname := objectDownloadDirname + "/" + objType + "/verified"
		if _, err := os.Stat(verifiedDirname); err == nil {
			populateInitialStatusFromVerified(objType,
				verifiedDirname, "")
		}
	}
}

// recursive scanning for verified objects,
// to recreate the status files
func populateInitialStatusFromVerified(objType string, objDirname string,
	parentDirname string) {

	log.Printf("populateInitialStatusFromVerified(%s, %s)\n", objDirname,
		parentDirname)

	locations, err := ioutil.ReadDir(objDirname)

	if err != nil {
		log.Fatal(err)
	}

	for _, location := range locations {

		filename := objDirname + "/" + location.Name()

		if location.IsDir() {
			log.Printf("populateInitialStatusFromVerified: Looking in %s\n", filename)
			if _, err := os.Stat(filename); err == nil {
				populateInitialStatusFromVerified(objType, filename,
					location.Name())
			}
		} else {
			info, _ := os.Stat(filename)
			log.Printf("populateInitialStatusFromVerified: Processing %d Mbytes %s \n",
				info.Size()/(1024*1024), filename)

			// XXX should really re-verify the image on reboot/restart
			// We don't know the URL; Pick a name which is unique
			sha := parentDirname
			safename := location.Name() + "." + sha

			status := types.VerifyImageStatus{
				Safename:    safename,
				ObjType:     objType,
				ImageSha256: sha,
				State:       types.DELIVERED,
				Size:        info.Size(),
			}

			updateVerifyObjectStatus(&status)
		}
	}
}

// remove the status files marked as pending delete
func handleInitMarkedDeletePendingObjects() {
	for key, status := range verifierStatusMap {
		if status.PendingDelete {
			log.Printf("still PendingDelete; delete %s\n", key)
			removeVerifyObjectStatus(&status)
		}
	}
}

// create module and object based config/status directories
func createConfigStatusDirs(moduleName string, objTypes []string) {

	jobDirs := []string{"config", "status"}
	zedBaseDirs := []string{zedBaseDirname, zedRunDirname}
	baseDirs := make([]string, len(zedBaseDirs))

	log.Printf("Creating config/status dirs for %s\n", moduleName)

	for idx, dir := range zedBaseDirs {
		baseDirs[idx] = dir + "/" + moduleName
	}

	for idx, baseDir := range baseDirs {

		dirName := baseDir + "/" + jobDirs[idx]
		if _, err := os.Stat(dirName); err != nil {
			log.Printf("Create %s\n", dirName)
			if err := os.MkdirAll(dirName, 0700); err != nil {
				log.Fatal(err)
			}
		}

		// Creating object based holder dirs
		for _, objType := range objTypes {
			dirName := baseDir + "/" + objType + "/" + jobDirs[idx]
			if _, err := os.Stat(dirName); err != nil {
				log.Printf("Create %s\n", dirName)
				if err := os.MkdirAll(dirName, 0700); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

// Create object download directories
func createDownloadDirs(objTypes []string) {

	workingDirTypes := []string{"pending", "verifier", "verified"}

	// now create the download dirs
	for _, objType := range objTypes {
		for _, dirType := range workingDirTypes {
			dirName := objectDownloadDirname + "/" + objType + "/" + dirType
			if _, err := os.Stat(dirName); err != nil {
				log.Printf("Create %s\n", dirName)
				if err := os.MkdirAll(dirName, 0700); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

// clear in-progress object download directories
func clearInProgressDownloadDirs(objTypes []string) {

	inProgressDirTypes := []string{"pending", "verifier"}

	// now cremove the in-progress dirs
	for _, objType := range objTypes {
		for _, dirType := range inProgressDirTypes {
			dirName := objectDownloadDirname + "/" + objType + "/" + dirType
			if _, err := os.Stat(dirName); err == nil {
				if err := os.RemoveAll(dirName); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

// Look for and delete objects and status where the RefCount is still zero
func gcVerifiedObjects() {
	log.Printf("gcVerifiedObjects()\n")
	for key, status := range verifierStatusMap {
		if status.RefCount != 0 {
			log.Printf("gcVerifiedObjects: skipping RefCount %d: %s\n",
				status.RefCount, key)
			continue
		}
		log.Printf("gcVerifiedObjects: removing %s\n", key)
		objType := status.ObjType
		if objType == "" {
			log.Fatalf("gcVerifiedObjects: No ObjType for %s\n",
				key)
		}
		doDelete(&status)
		removeVerifyObjectStatus(&status)
	}
}

func updateVerifyErrStatus(status *types.VerifyImageStatus,
	lastErr string) {
	status.LastErr = lastErr
	status.LastErrTime = time.Now()
	status.PendingAdd = false
	status.State = types.INITIAL
	updateVerifyObjectStatus(status)
}

func verifyObjectConfigFilename(objType string, safename string) string {
	return fmt.Sprintf("%s/%s/config/%s.json",
		baseDirname, objType, safename)
}

func verifyObjectStatusFilename(objType string, safename string) string {
	return fmt.Sprintf("%s/%s/status/%s.json",
		runDirname, objType, safename)
}

var verifierStatusMap map[string]types.VerifyImageStatus

func updateVerifyObjectStatus(status *types.VerifyImageStatus) {
	log.Printf("updateVerifyObjectStatus(%s, %s)\n",
		status.ObjType, status.Safename)

	key := status.Safename
	if status.ObjType == "" {
		log.Fatalf("updateVerifyObjectStatus: No ObjType for %s\n",
			key)
	}

	if verifierStatusMap == nil {
		verifierStatusMap = make(map[string]types.VerifyImageStatus)
	}
	verifierStatusMap[key] = *status

	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal VerifyImageStatus")
	}
	statusFilename := verifyObjectStatusFilename(status.ObjType,
		status.Safename)
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func removeVerifyObjectStatus(status *types.VerifyImageStatus) {
	log.Printf("removeVerifyObjectStatus(%s, %s)\n",
		status.ObjType, status.Safename)
	key := status.Safename
	if status.ObjType == "" {
		log.Fatalf("removeVerifyObjectStatus: No ObjType for %s\n",
			key)
	}
	if _, ok := verifierStatusMap[key]; !ok {
		log.Fatalf("removeVerifyObjectStatus(%s): key does not exist/n",
			key)
	}
	delete(verifierStatusMap, key)

	statusFilename := verifyObjectStatusFilename(status.ObjType,
		status.Safename)
	if err := os.Remove(statusFilename); err != nil {
		log.Fatal(err)
	}
}

func handleAppImgObjCreate(ctxArg interface{}, statusFilename string,
	configArg interface{}) {
	config := configArg.(*types.VerifyImageConfig)
	ctx := ctxArg.(*verifierContext)

	log.Printf("handleCreate(%v) for %s\n",
		config.Safename, config.DownloadURL)
	handleCreate(ctx, appImgObj, config)
}

func handleBaseOsObjCreate(ctxArg interface{}, statusFilename string,
	configArg interface{}) {
	config := configArg.(*types.VerifyImageConfig)
	ctx := ctxArg.(*verifierContext)

	handleCreate(ctx, baseOsObj, config)
}

func handleCreate(ctx *verifierContext, objType string,
	config *types.VerifyImageConfig) {

	log.Printf("handleCreate(%v) objType %s for %s\n",
		config.Safename, objType, config.DownloadURL)
	if objType == "" {
		log.Fatalf("handleCreate: No ObjType for %s\n",
			config.Safename)
	}

	status := types.VerifyImageStatus{
		Safename:    config.Safename,
		ObjType:     objType,
		ImageSha256: config.ImageSha256,
		PendingAdd:  true,
		State:       types.DOWNLOADED,
		RefCount:    config.RefCount,
	}
	updateVerifyObjectStatus(&status)

	ok, size := markObjectAsVerifying(config, &status)
	if !ok {
		log.Printf("handleCreate fail for %s\n", config.DownloadURL)
		return
	}
	status.Size = size
	updateVerifyObjectStatus(&status)

	if !verifyObjectSha(config, &status) {
		log.Printf("handleCreate fail for %s\n", config.DownloadURL)
		return
	}
	updateVerifyObjectStatus(&status)

	markObjectAsVerified(config, &status)
	status.PendingAdd = false
	status.State = types.DELIVERED
	updateVerifyObjectStatus(&status)
	log.Printf("handleCreate done for %s\n", config.DownloadURL)
}

// Returns ok, size of object
func markObjectAsVerifying(config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) (bool, int64) {

	// Form the unique filename in
	// objectDownloadDirname/<objType>/pending/
	// based on the claimed Sha256 and safename, and the same name
	// in objectDownloadDirname/<objType>/verifier/. Form a shorter name for
	// objectDownloadDirname/<objType/>verified/.

	objType := status.ObjType
	downloadDirname := objectDownloadDirname + "/" + objType
	pendingDirname := downloadDirname + "/pending/" + status.ImageSha256
	verifierDirname := downloadDirname + "/verifier/" + status.ImageSha256

	pendingFilename := pendingDirname + "/" + config.Safename
	verifierFilename := verifierDirname + "/" + config.Safename

	// Move to verifier directory which is RO
	// XXX should have dom0 do this and/or have RO mounts
	log.Printf("Move from %s to %s\n", pendingFilename, verifierFilename)

	info, err := os.Stat(pendingFilename)
	if err != nil {
		// XXX hits sometimes; attempting to verify before download
		// is complete?
		log.Printf("%s\n", err)
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(status, cerr)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
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
	log.Printf("Create %s\n", verifierDirname)
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

	// Clean up empty directory
	if err := os.RemoveAll(pendingDirname); err != nil {
		log.Fatal(err)
	}
	return true, info.Size()
}

func verifyObjectSha(config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) bool {

	objType := status.ObjType
	downloadDirname := objectDownloadDirname + "/" + objType
	verifierDirname := downloadDirname + "/verifier/" + status.ImageSha256
	verifierFilename := verifierDirname + "/" + config.Safename

	log.Printf("Verifying URL %s file %s\n",
		config.DownloadURL, verifierFilename)

	f, err := os.Open(verifierFilename)
	if err != nil {
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(status, cerr)
		log.Printf("%s for %s\n", cerr, config.DownloadURL)
		return false
	}
	defer f.Close()

	// compute sha256 of the image and match it
	// with the one in config file...
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		cerr := fmt.Sprintf("%v", err)
		updateVerifyErrStatus(status, cerr)
		log.Printf("%s for %s\n", cerr, config.DownloadURL)
		return false
	}

	imageHash := h.Sum(nil)
	got := fmt.Sprintf("%x", h.Sum(nil))
	if got != strings.ToLower(config.ImageSha256) {
		log.Printf("computed   %s\n", got)
		log.Printf("configured %s\n", strings.ToLower(config.ImageSha256))
		cerr := fmt.Sprintf("computed %s configured %s",
			got, config.ImageSha256)
		status.PendingAdd = false
		updateVerifyErrStatus(status, cerr)
		log.Printf("%s for %s\n", cerr, config.DownloadURL)
		return false
	}

	log.Printf("Sha validation successful for %s\n", config.DownloadURL)

	if cerr := verifyObjectShaSignature(status, config, imageHash); cerr != "" {
		updateVerifyErrStatus(status, cerr)
		log.Printf("Signature validation failed for %s, %s\n",
			config.DownloadURL, cerr)
		return false
	}
	return true
}

func verifyObjectShaSignature(status *types.VerifyImageStatus, config *types.VerifyImageConfig, imageHash []byte) string {

	// XXX:FIXME if Image Signature is absent, skip
	// mark it as verified; implicitly assuming,
	// if signature is filled in, marking this object
	//  as valid may not hold good always!!!
	if (config.ImageSignature == nil) ||
		(len(config.ImageSignature) == 0) {
		log.Printf("No signature to verify for %s\n",
			config.DownloadURL)
		return ""
	}

	log.Printf("Validating %s using cert %s sha %s\n",
		config.DownloadURL, config.SignatureKey,
		config.ImageSha256)

	//Read the server certificate
	//Decode it and parse it
	//And find out the puplic key and it's type
	//we will use this certificate for both cert chain verification
	//and signature verification...

	//This func literal will take care of writing status during
	//cert chain and signature verification...

	serverCertName := types.UrlToFilename(config.SignatureKey)
	serverCertificate, err := ioutil.ReadFile(certificateDirname + "/" + serverCertName)
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
	rootCertificate, err := ioutil.ReadFile(rootCertFileName)
	if err != nil {
		log.Println(err)
		cerr := fmt.Sprintf("failed to find root certificate: %s", err)
		return cerr
	}

	if ok := roots.AppendCertsFromPEM(rootCertificate); !ok {
		cerr := fmt.Sprintf("failed to parse root certificate")
		return cerr
	}

	for _, certUrl := range certificateNameInChain {

		certName := types.UrlToFilename(certUrl)

		bytes, err := ioutil.ReadFile(certificateDirname + "/" + certName)
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

	log.Printf("certificate options verified for %s\n", config.DownloadURL)

	//Read the signature from config file...
	imgSig := config.ImageSignature

	switch pub := cert.PublicKey.(type) {

	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, imageHash, imgSig)
		if err != nil {
			cerr := fmt.Sprintf("rsa image signature verification failed: %s", err)
			return cerr
		}
		log.Printf("VerifyPKCS1v15 successful for %s\n",
			config.DownloadURL)
	case *ecdsa.PublicKey:
		log.Printf("pub is of type ecdsa: ", pub)
		imgSignature, err := base64.StdEncoding.DecodeString(string(imgSig))
		if err != nil {
			cerr := fmt.Sprintf("DecodeString failed: %v ", err)
			return cerr
		}

		log.Printf("Decoded imgSignature (len %d): % x\n",
			len(imgSignature), imgSignature)
		rbytes := imgSignature[0:32]
		sbytes := imgSignature[32:]
		log.Printf("Decoded r %d s %d\n", len(rbytes), len(sbytes))
		r := new(big.Int)
		s := new(big.Int)
		r.SetBytes(rbytes)
		s.SetBytes(sbytes)
		log.Printf("Decoded r, s: %v, %v\n", r, s)
		ok := ecdsa.Verify(pub, imageHash, r, s)
		if !ok {
			cerr := fmt.Sprintf("ecdsa image signature verification failed")
			return cerr
		}
		log.Printf("ecdsa Verify successful for %s\n",
			config.DownloadURL)
	default:
		cerr := fmt.Sprintf("unknown type of public key")
		return cerr
	}
	return ""
}

func markObjectAsVerified(config *types.VerifyImageConfig,
	status *types.VerifyImageStatus) {

	objType := status.ObjType
	downloadDirname := objectDownloadDirname + "/" + objType
	verifierDirname := downloadDirname + "/verifier/" + status.ImageSha256
	verifiedDirname := downloadDirname + "/verified/" + config.ImageSha256

	verifierFilename := verifierDirname + "/" + config.Safename
	verifiedFilename := verifiedDirname + "/" + config.Safename

	// Move directory from objectDownloadDirname/verifier to
	// objectDownloadDirname/verified
	// XXX should have dom0 do this and/or have RO mounts
	filename := types.SafenameToFilename(config.Safename)
	verifiedFilename = verifiedDirname + "/" + filename
	log.Printf("Move from %s to %s\n", verifierFilename, verifiedFilename)

	if _, err := os.Stat(verifierFilename); err != nil {
		log.Fatal(err)
	}

	if _, err := os.Stat(verifiedFilename); err == nil {
		log.Fatal(verifiedFilename + ": file exists")
	}

	// XXX change log.Fatal to something else?
	if _, err := os.Stat(verifiedDirname); err == nil {
		// Directory exists thus we have a sha256 collision presumably
		// due to multiple safenames (i.e., URLs) for the same content.
		// Delete existing to avoid wasting space.
		locations, err := ioutil.ReadDir(verifiedDirname)
		if err != nil {
			log.Fatal(err)
		}
		for _, location := range locations {
			log.Printf("Identical sha256 (%s) for safenames %s and %s; deleting old\n",
				config.ImageSha256, location.Name(),
				config.Safename)
		}
		if err := os.RemoveAll(verifiedDirname); err != nil {
			log.Fatal(err)
		}
	}

	log.Printf("Create %s\n", verifiedDirname)
	if err := os.MkdirAll(verifiedDirname, 0700); err != nil {
		log.Fatal(err)
	}

	if err := os.Rename(verifierFilename, verifiedFilename); err != nil {
		log.Fatal(err)
	}

	if err := os.Chmod(verifiedDirname, 0500); err != nil {
		log.Fatal(err)
	}

	// Clean up empty directory
	if err := os.RemoveAll(verifierDirname); err != nil {
		log.Fatal(err)
	}
}

func handleModify(ctxArg interface{}, statusFilename string,
	configArg interface{}, statusArg interface{}) {
	config := configArg.(*types.VerifyImageConfig)
	status := statusArg.(*types.VerifyImageStatus)
	ctx := ctxArg.(*verifierContext)

	// Note no comparison on version
	changed := false

	log.Printf("handleModify(%v) objType %s for %s\n",
		status.Safename, status.ObjType, config.DownloadURL)

	if status.ObjType == "" {
		log.Fatalf("handleModify: No ObjType for %s\n",
			status.Safename)
	}

	// Always update RefCount
	if status.RefCount != config.RefCount {
		log.Printf("handleModify RefCount change %s from %d to %d\n",
			config.DownloadURL, status.RefCount, config.RefCount)
		status.RefCount = config.RefCount
		changed = true
	}

	if status.RefCount == 0 {
		status.PendingModify = true
		updateVerifyObjectStatus(status)
		doDelete(status)
		status.PendingModify = false
		status.State = 0 // XXX INITIAL implies failure
		updateVerifyObjectStatus(status)
		log.Printf("handleModify done for %s\n", config.DownloadURL)
		return
	}

	// If identical we do nothing. Otherwise we do a delete and create.
	if config.Safename == status.Safename &&
		config.ImageSha256 == status.ImageSha256 {
		if changed {
			updateVerifyObjectStatus(status)
		}
		log.Printf("handleModify: no (other) change for %s\n",
			config.DownloadURL)
		return
	}

	status.PendingModify = true
	updateVerifyObjectStatus(status)
	handleDelete(ctx, statusFilename, status)
	handleCreate(ctx, status.ObjType, config)
	status.PendingModify = false
	updateVerifyObjectStatus(status)
	log.Printf("handleModify done for %s\n", config.DownloadURL)
}

func handleDelete(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.VerifyImageStatus)

	log.Printf("handleDelete(%v) objType %s\n",
		status.Safename, status.ObjType)

	if status.ObjType == "" {
		log.Fatalf("handleDelete: No ObjType for %s\n",
			status.Safename)
	}

	doDelete(status)

	// Write out what we modified to VerifyImageStatus aka delete
	removeVerifyObjectStatus(status)
	log.Printf("handleDelete done for %s\n", status.Safename)
}

// Remove the file from any of the three directories
// Only if it verified (state DELIVERED) do we delete the final. Needed
// to avoid deleting a different verified file with same sha as this claimed
// to have
func doDelete(status *types.VerifyImageStatus) {
	log.Printf("doDelete(%v)\n", status.Safename)

	objType := status.ObjType
	downloadDirname := objectDownloadDirname + "/" + objType
	pendingDirname := downloadDirname + "/pending/" + status.ImageSha256
	verifierDirname := downloadDirname + "/verifier/" + status.ImageSha256
	verifiedDirname := downloadDirname + "/verified/" + status.ImageSha256

	if _, err := os.Stat(pendingDirname); err == nil {
		log.Printf("doDelete removing %s\n", pendingDirname)
		if err := os.RemoveAll(pendingDirname); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(verifierDirname); err == nil {
		log.Printf("doDelete removing %s\n", verifierDirname)
		if err := os.RemoveAll(verifierDirname); err != nil {
			log.Fatal(err)
		}
	}
	_, err := os.Stat(verifiedDirname)
	if err == nil && status.State == types.DELIVERED {
		if _, err := os.Stat(preserveFilename); err != nil {
			log.Printf("doDelete removing %s\n", verifiedDirname)
			if err := os.RemoveAll(verifiedDirname); err != nil {
				log.Fatal(err)
			}
		} else {
			log.Printf("doDelete preserving %s\n", verifiedDirname)
		}
	}
	log.Printf("doDelete(%v) done\n", status.Safename)
}
