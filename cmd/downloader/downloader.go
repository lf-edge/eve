// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Process input changes from a config directory containing json encoded files
// with DownloaderConfig and compare against DownloaderStatus in the status
// dir.
// XXX NOT Tries to download the items in the config directory repeatedly until
// there is a complete download. (XXX detect eof/short file or not?)
// ZedManager can stop the download by removing from config directory.
//
// Input directory with config (URL, refcount, maxLength, dstDir)
// Output directory with status (URL, refcount, state, ModTime, lastErr, lastErrTime, retryCount)
// refCount -> 0 means delete from dstDir? Who owns dstDir? Separate mount.
// Check length against Content-Length.

// Should retrieve length somewhere first. Should that be in the catalogue?
// Content-Length is set!
// nordmark@bobo:~$ curl -I  https://cloud-images.ubuntu.com/releases/16.04/release/ubuntu-16.04-server-cloudimg-arm64-root.tar.gz
// HTTP/1.1 200 OK
// Date: Sat, 03 Jun 2017 04:28:38 GMT
// Server: Apache
// Last-Modified: Tue, 16 May 2017 15:31:53 GMT
// ETag: "b15553f-54fa5defeec40"
// Accept-Ranges: bytes
// Content-Length: 185947455
// Content-Type: application/x-gzip

package main

import (
	"encoding/json"
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"github.com/zededa/go-provision/wrap"
	"zc/libs/zedUpload"
	"github.com/zededa/api/zconfig"
	"io/ioutil"
	"log"
	"os"
	"time"
)

var (
	dCtx	*zedUpload.DronaCtx
)

func main() {

	log.Printf("Starting downloader\n")
	watch.CleanupRestarted("downloader")

	downloaderInit()

	go checkImageUpdates()

	handleCertUpdates()
}

// Object handlers
func checkImageUpdates() {

	baseDirname := "/var/tmp/downloader"
	runDirname  := "/var/run/downloader"

	sanitizeDirs(baseDirname, runDirname)

	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"

	fileChanges := make(chan string)

	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)

	for {
		change := <-fileChanges

		watch.HandleConfigStatusEvent(change, configDirname, statusDirname,
			&types.DownloaderConfig{},
			&types.DownloaderStatus{},
			handleImageCreate,
			handleImageModify,
			handleImageDelete, nil)
	}
}

func handleCertUpdates() {

	baseDirname := "/var/tmp/downloader/cert.obj"
	runDirname  := "/var/run/downloader/cert.obj"

	sanitizeDirs(baseDirname, runDirname)

	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"
	fileChanges   := make(chan string)

	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)

	for {
		change := <-fileChanges

		watch.HandleConfigStatusEvent(change,
			configDirname, statusDirname,
			&types.DownloaderConfig{},
			&types.DownloaderStatus{},
			handleCertObjCreate,
			handleCertObjModify,
			handleCertObjDelete, nil)
	}
}

func handleImageCreate(statusFilename string, configArg interface{}) {

	var config *types.DownloaderConfig

	switch configArg.(type) {

	default:
		log.Fatal("Can only handle DownloaderConfig")

	case *types.DownloaderConfig:
		config = configArg.(*types.DownloaderConfig)
	}

	handleCreate (*config, statusFilename)
}

func handleImageModify(statusFilename string, configArg interface{},
	statusArg interface{}) {

	var config *types.DownloaderConfig
	var status *types.DownloaderStatus

	switch configArg.(type) {

	default:
		log.Fatal("Can only handle DownloaderConfig")

	case *types.DownloaderConfig:
		config = configArg.(*types.DownloaderConfig)
	}

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle DownloaderStatus")
	case *types.DownloaderStatus:
		status = statusArg.(*types.DownloaderStatus)
	}

	handleModify (*config, *status, statusFilename)
}

func handleImageDelete(statusFilename string, statusArg interface{}) {

	var status *types.DownloaderStatus

	switch statusArg.(type) {

	default:
		log.Fatal("Can only handle DownloaderStatus")

	case *types.DownloaderStatus:
		status = statusArg.(*types.DownloaderStatus)
	}

	handleDelete (*status, statusFilename)
}

func handleCertObjCreate(statusFilename string, configArg interface{}) {

	var config *types.DownloaderConfig

	switch configArg.(type) {

	default:
		log.Fatal("Can only handle DownloaderConfig")

	case *types.DownloaderConfig:
		config = configArg.(*types.DownloaderConfig)
	}

	handleCreate (*config, statusFilename)
}

func handleCertObjModify(statusFilename string, configArg interface{},
	statusArg interface{}) {

	var config *types.DownloaderConfig
	var status *types.DownloaderStatus

	switch configArg.(type) {

	default:
		log.Fatal("Can only handle DownloaderConfig")

	case *types.DownloaderConfig:
		config = configArg.(*types.DownloaderConfig)
	}

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle DownloaderStatus")
	case *types.DownloaderStatus:
		status = statusArg.(*types.DownloaderStatus)
	}

	handleModify (*config, *status, statusFilename)
}

func handleCertObjDelete(statusFilename string, statusArg interface{}) {
	var status *types.DownloaderStatus

	switch statusArg.(type) {

	default:
		log.Fatal("Can only handle DownloaderStatus")

	case *types.DownloaderStatus:
		status = statusArg.(*types.DownloaderStatus)
	}

	handleDelete(*status, statusFilename)
}

func handleCreate(config types.DownloaderConfig, statusFilename string) {

	var syncOp zedUpload.SyncOpType = zedUpload.SyncOpDownload

	// Start by marking with PendingAdd
	status := types.DownloaderStatus{
		Safename:		config.Safename,
		RefCount:		config.RefCount,
		DownloadURL:	config.DownloadURL,
		ImageSha256:	config.ImageSha256,
		DownloadObjDir:	config.DownloadObjDir,
		VerifiedObjDir:	config.VerifiedObjDir,
		PendingAdd:		true,
	}
	writeDownloaderStatus(&status, statusFilename)

	// Check if we have space
	if config.MaxSize >= globalStatus.RemainingSpace {
		errString := fmt.Sprintf("Would exceed remaining space %d vs %d\n",
			config.MaxSize, globalStatus.RemainingSpace)
		log.Println(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(&status, statusFilename)
		log.Printf("handleCreate failed for %s\n", config.DownloadURL)
		return
	}

	// Update reserved space. Keep reserved until doDelete
	// XXX RefCount -> 0 should keep it reserved.
	status.ReservedSpace = config.MaxSize
	globalStatus.ReservedSpace += status.ReservedSpace
	updateRemainingSpace()

	// If RefCount == 0 then we don't yet download.
	if config.RefCount == 0 {
		// XXX odd to treat as error.
		errString := fmt.Sprintf("RefCount==0; download deferred for %s\n",
			config.DownloadURL)
		log.Println(errString)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(&status, statusFilename)
		log.Printf("handleCreate deferred for %s\n", config.DownloadURL)
		return
	}

	handleSyncOp(syncOp, statusFilename, config, &status)
}

// Allow to cancel by setting RefCount = 0. Same as delete? RefCount 0->1
// means download. Ignore other changes?
func handleModify(config types.DownloaderConfig,
	status types.DownloaderStatus, statusFilename string) {

	locDirname := config.DownloadObjDir

	log.Printf("handleModify(%v) for %s\n",
		config.Safename, config.DownloadURL)

	if config.DownloadURL != status.DownloadURL {
		fmt.Printf("URL changed - not allowed %s -> %s\n",
			config.DownloadURL, status.DownloadURL)
		return
	}
	// If the sha changes, we treat it as a delete and recreate.
	// Ditto if we had a failure.
	if (status.ImageSha256 != "" && status.ImageSha256 != config.ImageSha256) ||
		 status.LastErr != "" {
		reason := ""
		if status.ImageSha256 != config.ImageSha256 {
			reason = "sha256 changed"
		} else {
			reason = "recovering from previous error"
		}
		log.Printf("handleModify %s for %s\n",
			reason, config.DownloadURL)
		doDelete(statusFilename, locDirname, &status)
		handleCreate(config, statusFilename)
		log.Printf("handleModify done for %s\n", config.DownloadURL)
		return
	}

	// XXX do work; look for refcnt -> 0 and delete; cancel any running
	// download
	// If RefCount from zero to non-zero then do install
	if status.RefCount == 0 && config.RefCount != 0 {

		log.Printf("handleModify installing %s\n", config.DownloadURL)
		handleCreate(config, statusFilename)
		status.RefCount = config.RefCount
		status.PendingModify = false
		writeDownloaderStatus(&status, statusFilename)
	} else if status.RefCount != 0 && config.RefCount == 0 {
		log.Printf("handleModify deleting %s\n", config.DownloadURL)
		doDelete(statusFilename, locDirname, &status)
	} else {
		status.RefCount = config.RefCount
		status.PendingModify = false
		writeDownloaderStatus(&status, statusFilename)
	}
	log.Printf("handleModify done for %s\n", config.DownloadURL)
}

func doDelete(statusFilename string, locDirname string, status *types.DownloaderStatus) {

	log.Printf("doDelete(%v) for %s\n", status.Safename, status.DownloadURL)

	locFilename := locDirname + "/pending"

	if status.ImageSha256  != "" {
		locFilename = locFilename + "/" + status.ImageSha256
	}

	if _, err := os.Stat(locFilename); err == nil {

		locFilename := locFilename + "/" + status.Safename
		log.Printf("Deleting %s\n", locFilename)

		if _, err := os.Stat(locFilename); err == nil {

			// Remove file
			if err := os.Remove(locFilename); err != nil {
				log.Printf("Failed to remove %s: err %s\n",
					locFilename, err)
			}
		}
	}

	status.State = types.INITIAL
	globalStatus.UsedSpace -= status.Size
	status.Size = 0

	// XXX Asymmetric; handleCreate reserved on RefCount 0. We unreserve
	// going back to RefCount 0. FIXed
	updateRemainingSpace()
	writeDownloaderStatus(status, statusFilename)
}

func handleDelete(status types.DownloaderStatus, statusFilename string) {

	locDirname := status.DownloadObjDir

	log.Printf("handleDelete(%v) for %s, %s\n",
		status.Safename, status.DownloadURL, locDirname)

	status.PendingDelete = true
	writeDownloaderStatus(&status, statusFilename)

	globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	globalStatus.UsedSpace -= status.Size
	status.Size = 0

	updateRemainingSpace()

	writeDownloaderStatus(&status, statusFilename)

	doDelete(statusFilename, locDirname, &status)

	status.PendingDelete = false
	writeDownloaderStatus(&status, statusFilename)

	// Write out what we modified to DownloaderStatus aka delete
	if err := os.Remove(statusFilename); err != nil {
		log.Println(err)
	}
	log.Printf("handleDelete done for %s, %s\n", status.DownloadURL, locDirname)
}

// helper functions

var globalConfig types.GlobalDownloadConfig
var globalStatus types.GlobalDownloadStatus
var globalStatusFilename string

func downloaderInit() {

	baseDirname		:= "/var/tmp/downloader"
	runDirname		:= "/var/run/downloader"

	configDirname	:= baseDirname + "/config"
	statusDirname	:= runDirname  + "/status"

	configFilename	:= configDirname + "/global"
	statusFilename	:= statusDirname + "/global"

	locDirname		:= "/var/tmp/zedmanager/downloads/"

	pendingDirname	:= locDirname + "/pending"
	verifierDirname	:= locDirname + "/verifier"

	if _, err := os.Stat(baseDirname); err != nil {
		if err := os.Mkdir(baseDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(runDirname); err != nil {
		if err := os.Mkdir(runDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(configDirname); err != nil {
		if err := os.Mkdir(configDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(statusDirname); err != nil {
		if err := os.Mkdir(statusDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(locDirname); err != nil {
		if err := os.Mkdir(locDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// Remove any files which didn't make it past the verifier
	if err := os.RemoveAll(pendingDirname); err != nil {
		log.Fatal(err)
	}

	// Note that verifier owns this but we remove before looking
	// for space used.
	if err := os.RemoveAll(verifierDirname); err != nil {
		log.Fatal(err)
	}

	if _, err := os.Stat(pendingDirname); err != nil {
		if err := os.Mkdir(pendingDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	// now start
	globalStatusFilename = statusFilename

	// Read GlobalDownloadConfig to find MaxSpace
	// Then determine currently used space and remaining.
	cb, err := ioutil.ReadFile(configFilename)
	if err != nil {
		log.Printf("%s for %s\n", err, configFilename)
		log.Fatal(err)
	}

	if err := json.Unmarshal(cb, &globalConfig); err != nil {
		log.Printf("%s GlobalDownloadConfig file: %s\n",
			err, configFilename)
		log.Fatal(err)
	}

	log.Printf("MaxSpace %d\n", globalConfig.MaxSpace)

	globalStatus.UsedSpace = 0
	globalStatus.ReservedSpace = 0
	updateRemainingSpace()

	// XXX how do we find out when verifier cleans up duplicates etc?
	// We read /var/tmp/zedmanager/downloads/* and determine how much space
	// is used. Place in GlobalDownloadStatus. Calculate remaining space.
	totalUsed := sizeFromDir(locDirname)
	globalStatus.UsedSpace = uint((totalUsed + 1023) / 1024)
	updateRemainingSpace()

	// create drona interface
	ctx,err := zedUpload.NewDronaCtx("zdownloader", 0)

	if ctx == nil {
		log.Printf("context create fail %s\n", err)
		log.Fatal(err)
	}

	dCtx = ctx
}

func sanitizeDirs (baseDirname string, runDirname string) {

	configDirname := baseDirname + "/config"
	statusDirname := runDirname  + "/status"

	if _, err := os.Stat(baseDirname); err != nil {

		if err := os.MkdirAll(baseDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(runDirname); err != nil {

		if err := os.MkdirAll(runDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(configDirname); err != nil {

		if err := os.MkdirAll(configDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(statusDirname); err != nil {

		if err := os.MkdirAll(statusDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}
}

func sizeFromDir(dirname string) int64 {
	var totalUsed int64 = 0
	locations, err := ioutil.ReadDir(dirname)
	if err != nil {
		log.Fatal(err)
	}
	for _, location := range locations {
		filename := dirname + "/" + location.Name()
		fmt.Printf("Looking in %s\n", filename)
		if location.IsDir() {
			size := sizeFromDir(filename)
			fmt.Printf("Dir %s size %d\n", filename, size)
			totalUsed += size
		} else {
			fmt.Printf("File %s Size %d\n", filename, location.Size())
			totalUsed += location.Size()
		}
	}
	return totalUsed
}

func updateRemainingSpace() {

	globalStatus.RemainingSpace = globalConfig.MaxSpace -
		globalStatus.UsedSpace - globalStatus.ReservedSpace

	log.Printf("RemaingSpace %d, maxspace %d, usedspace %d, reserved %d\n",
	globalStatus.RemainingSpace, globalConfig.MaxSpace,
	globalStatus.UsedSpace,	globalStatus.ReservedSpace)
	// Create and write
	writeGlobalStatus()
}

func writeGlobalStatus() {

	sb, err := json.Marshal(globalStatus)
	if err != nil {
		log.Fatal(err, "json Marshal GlobalDownloadStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	if err = ioutil.WriteFile(globalStatusFilename, sb, 0644); err != nil {
		log.Fatal(err, globalStatusFilename)
	}
}

func writeDownloaderStatus(status *types.DownloaderStatus,
	statusFilename string) {
	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal DownloaderStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

func writeFile(sFilename string, dFilename string) {

	log.Printf("Writing <%s> file to <%s>\n", sFilename, dFilename)

	if _, err := os.Stat(sFilename); err == nil {
		sb, err := ioutil.ReadFile(sFilename)
		if err == nil {

			if err = ioutil.WriteFile(dFilename, sb, 0644); err != nil {
				log.Printf("Failed to write %s: err %s\n",
				dFilename, err)
			}
		} else {
			log.Printf("Failed to read %s: err %s\n",
				sFilename)
		}
	} else {
		log.Printf("Failed to stat %s: err %s\n",
			sFilename, err)
	}
}

// cloud storage interface functions/APIs

// XXX Should we set        --limit-rate=100k
// XXX Can we safely try a continue?
// XXX wget seems to have no way to limit download size for single file!
// XXX temporary options since and wierd free.fr dns behavior with AAAA and A.
// Added  -4 --no-check-certificate
func doWget(url string, destFilename string) error {

	cmd := "wget"
	args := []string{
		"-q",
		"-c",
		"-4", // XXX due to getting IPv6 ULAs and not IPv4
		"--no-check-certificate",
		"--tries=3",
		"-O",
		destFilename,
		url,
	}

	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()

	if err != nil {
		log.Println("wget failed ", err)
	} else {
		log.Printf("wget done: output %s\n", string(stdoutStderr))
	}
	return err
}

// Drona APIs for object Download

func handleSyncOp(syncOp zedUpload.SyncOpType,
	 statusFilename string, config types.DownloaderConfig, status *types.DownloaderStatus) {

	var err error
	var locFilename string

	locDirname := "/var/tmp/downloader/downloads"

	// XXX:FIXME define a proper destination for certs
	if config.VerifiedObjDir != "" {
		locFilename = config.VerifiedObjDir
	} else {
		if config.DownloadObjDir != "" {
			locDirname = config.DownloadObjDir
		}
		locFilename = locDirname + "/pending"
	}

	// update status to DOWNLOAD STARTED
	status.State = types.DOWNLOAD_STARTED
	writeDownloaderStatus(status, statusFilename)


	if config.ImageSha256 != "" {
		locFilename = locFilename + "/" + config.ImageSha256
	} else {
	}

	if _, err = os.Stat(locFilename); err != nil {

		if err = os.MkdirAll(locFilename, 0755); err != nil {
			log.Fatal(err)
		}
	}

	filename := types.SafenameToFilename(config.Safename)

	if config.ImageSha256 != "" {
		locFilename = locFilename + "/" + config.Safename
	} else {
		locFilename = locFilename + "/" + filename
	}

	log.Printf("Downloading <%s> to <%s>\n", config.DownloadURL, locFilename)

	switch config.TransportMethod {
	case zconfig.DsType_DsS3.String() :
		{

			auth := &zedUpload.AuthInput{AuthType: "s3",
					 Uname :config.ApiKey,
					 Password:config.Password}

			trType := zedUpload.SyncAwsTr
			// XXX:FIXME , will come as part of data store
			region := "us-west-2"

			// create Endpoint
			dEndPoint, err := dCtx.NewSyncerDest(trType, region, config.Dpath, auth)

			if err == nil && dEndPoint != nil {
				var respChan = make(chan * zedUpload.DronaRequest);

				log.Printf("syncOp for <%s>/<%s>\n", config.Dpath, filename)

				// create Request
				req := dEndPoint.NewRequest(syncOp, filename, locFilename,
					int64(config.MaxSize / 1024), true, respChan)

				if req != nil {
					req.Post()
				        select {
				                case resp := <-respChan:
							_, err = resp.GetUpStatus()

							if resp.IsError () == false {
								err = nil
							}
				        }
				}
			}
		}
		handleSyncOpResponse(config, status, statusFilename, err)
		break

	case zconfig.DsType_DsHttp.String() :
	case zconfig.DsType_DsHttps.String() :
		err = doWget(config.DownloadURL, locFilename)
		handleSyncOpResponse(config, status, statusFilename, err)
	default:
		log.Fatal("unsupported transport method")
	}
}

func handleSyncOpResponse(config types.DownloaderConfig,
	 status *types.DownloaderStatus, statusFilename string,
	 err error) {

	locDirname := "/var/tmp/downloader/downloads"

	// XXX:FIXME 
	if config.VerifiedObjDir != "" {
		locDirname = config.VerifiedObjDir
	} else {
		if config.DownloadObjDir != "" {
			locDirname = config.DownloadObjDir
		}
	}

	if err != nil {
		// Delete file
		doDelete(statusFilename, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(status, statusFilename)
		log.Printf("handleCreate failed for %s, <%s>\n", status.DownloadURL, err)
		return
	}

	// XXX:FIXME 
	locFilename := locDirname

	if config.VerifiedObjDir == "" {
		locFilename = locDirname + "/pending"
	}


	if status.ImageSha256 != "" {
		locFilename = locFilename + "/" + status.ImageSha256
	}

	filename := types.SafenameToFilename(config.Safename)

	if config.ImageSha256 != "" {
		locFilename = locFilename + "/" + config.Safename
	} else {
		locFilename = locFilename + "/" + filename
	}

	info, err := os.Stat(locFilename)
	if err != nil {
		// Delete file
		doDelete(statusFilename, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = fmt.Sprintf("%v", err)
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(status, statusFilename)
		log.Printf("handleCreate failed for %s <%s>\n", status.DownloadURL, err)
		return
	}

	// XXX Compare against MaxSize and reject? Already wasted the space?
	status.Size = uint((info.Size() + 1023)/1024)

	if status.Size > config.MaxSize {
		// Delete file
		errString := fmt.Sprintf("Size exceeds MaxSize; %d vs. %d for %s\n",
			status.Size, config.MaxSize, status.DownloadURL)
		log.Println(errString)
		// Delete file
		doDelete(statusFilename, locDirname, status)
		status.PendingAdd = false
		status.Size = 0
		status.LastErr = errString
		status.LastErrTime = time.Now()
		status.RetryCount += 1
		status.State = types.INITIAL
		writeDownloaderStatus(status, statusFilename)
		log.Printf("handleCreate failed for %s, <%s>\n", status.DownloadURL, err)
		return
	}

	globalStatus.ReservedSpace -= status.ReservedSpace
	status.ReservedSpace = 0
	globalStatus.UsedSpace += status.Size
	updateRemainingSpace()

	log.Printf("handleCreate successful <%s> <%s>\n", config.DownloadURL, locFilename)
	// We do not clear any status.RetryCount, LastErr, etc. The caller
	// should look at State == DOWNLOADED to determine it is done.

	status.ModTime = time.Now()
	status.PendingAdd = false
	status.State = types.DOWNLOADED
	writeDownloaderStatus(status, statusFilename)
}
