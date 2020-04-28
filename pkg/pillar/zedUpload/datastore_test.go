// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload_test

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/zedUpload"
)

const (
	// parameters for AWS S3 datastore
	awsBucket      = ""
	intf           = "eth1"
	key            = ""
	secret         = ""
	awsRegion      = ""
	awsUploadFile  = "./test/input/zedupload_test.img"
	awsDownloadDir = "./test/output/awsDownload/"
	// parameters for AZURE datastore
	azureContainer   = ""
	azureAccountName = ""
	azureAccountKey  = ""
	azureUploadFile  = "./test/input/zedupload_test.img"
	azureDownloadDir = "./test/output/azureDownload/"
	// parameters for SFTP datastore
	sftpDir         = ""
	uname           = ""
	pass            = ""
	sftpRegion      = ""
	sftpUploadFile  = "./test/input/zedupload_test.img"
	sftpDownloadDir = "./test/output/sftpDownload/"
	// parameters for HTTP datastore
	httpPostRegion  = "http://ptsv2.com/t/httptest/post"
	httpURL         = "http://download.cirros-cloud.net"
	httpURL2        = "http://cloud-images.ubuntu.com/"
	httpDir         = "0.4.0/"
	httpDir2        = "releases"
	httpUploadFile  = "./test/input/zedupload_test.img"
	httpDownloadDir = "./test/output/httpDownload/"
	// global parameters
	uploadDir = "./test/input/"
)

func operationAwsS3(t *testing.T, objloc string, objkey string, operation zedUpload.SyncOpType) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	awsAuth := &zedUpload.AuthInput{AuthType: "s3", Uname: key, Password: secret}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncAwsTr, awsRegion, awsBucket, awsAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(operation, objkey, objloc, 0, true, respChan)
		if req != nil {
			req.Post()
		} else {
			return true, "New datastore request creation failed"
		}
	} else {
		return true, "New datastore context creation failed"
	}

	for {
		select {
		case resp, _ := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			return resp.IsError(), resp.GetStatus()
		}
	}
}

func operationAwsS3Negative(t *testing.T, s3Key string, s3Secret string, operation zedUpload.SyncOpType) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	awsAuth := &zedUpload.AuthInput{AuthType: "s3", Uname: s3Key, Password: s3Secret}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncAwsTr, awsRegion, awsBucket, awsAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(operation, "s3teststuff", awsUploadFile, 0, true, respChan)
		if req != nil {
			req.Post()
		} else {
			return true, "New datastore request creation failed"
		}
	} else {
		return true, "New datastore context creation failed"
	}

	for {
		select {
		case resp, _ := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			return resp.IsError(), resp.GetStatus()
		}
	}
}

func listAwsS3Files(t *testing.T, bucket string) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	ctx, err := zedUpload.NewDronaCtx("zlister", 0)
	if ctx == nil {
		return true, err.Error()
	}

	awsAuth := &zedUpload.AuthInput{AuthType: "password", Uname: key, Password: secret}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncAwsTr, awsRegion, bucket, awsAuth)

	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(zedUpload.SyncOpList, "", "", 0, true, respChan)
		if req != nil {
			req.Post()
		} else {
			return true, "New datastore request creation failed"
		}
	} else {
		return true, "New datastore context creation failed"
	}

	for {
		select {
		case resp, _ := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			return resp.IsError(), resp.GetStatus()
		}
	}
}

func getAwsS3ObjectMetaData(t *testing.T, objloc string, objkey string) (bool, string, int64, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	awsAuth := &zedUpload.AuthInput{AuthType: "s3", Uname: key, Password: secret}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error(), 0, ""
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncAwsTr, awsRegion, awsBucket, awsAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(zedUpload.SyncOpGetObjectMetaData, objkey, objloc, 0, true, respChan)
		if req != nil {
			req.Post()
		} else {
			return true, "New datastore request creation failed", 0, ""
		}
	} else {
		return true, "New datastore context creation failed", 0, ""
	}

	for {
		select {
		case resp, _ := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			return resp.IsError(), resp.GetStatus(), resp.GetContentLength(), resp.GetRemoteFileMD5()
		}
	}
}

func operationAzureBlob(t *testing.T, objloc string, objkey string, operation zedUpload.SyncOpType) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	azureAuth := &zedUpload.AuthInput{AuthType: "s3", Uname: azureAccountName, Password: azureAccountKey}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncAzureTr, awsRegion, azureContainer, azureAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(operation, objkey, objloc, 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}

	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus()
			}
			return resp.IsError(), resp.GetStatus()
		}
	}
}

func operationAzureBlobNegative(t *testing.T, azureName string, azureKey string, operation zedUpload.SyncOpType) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	azureAuth := &zedUpload.AuthInput{AuthType: "s3", Uname: azureName, Password: azureKey}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncAzureTr, awsRegion, azureContainer, azureAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(operation, "azureteststuff", azureUploadFile, 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}

	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus()
			}
			return resp.IsError(), resp.GetStatus()
		}
	}
}

func listAzureBlobFiles(t *testing.T, container string) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	ctx, err := zedUpload.NewDronaCtx("zlister", 0)
	if ctx == nil {
		return true, err.Error()
	}

	azureAuth := &zedUpload.AuthInput{AuthType: "s3", Uname: azureAccountName, Password: azureAccountKey}
	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncAzureTr, awsRegion, container, azureAuth)

	if err == nil && dEndPoint != nil {

		// create Request
		req := dEndPoint.NewRequest(zedUpload.SyncOpList, "", "", 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}
	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus()
			}
			return resp.IsError(), resp.GetStatus()
		}
	}
}

func getAzureBlobMetaData(t *testing.T, objloc string, objkey string) (bool, string, int64, string) {
	respChan := make(chan *zedUpload.DronaRequest)
	azureAuth := &zedUpload.AuthInput{AuthType: "s3", Uname: azureAccountName, Password: azureAccountKey}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error(), 0, ""
	}
	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncAzureTr, awsRegion, azureContainer, azureAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(zedUpload.SyncOpGetObjectMetaData, objkey, objloc, 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}
	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus(), resp.GetContentLength(), resp.GetRemoteFileMD5()
			}
			return resp.IsError(), resp.GetStatus(), resp.GetContentLength(), resp.GetRemoteFileMD5()
		}
	}
}

func operationHTTP(t *testing.T, objloc string, objkey string, url, dir string, operation zedUpload.SyncOpType) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	httpAuth := &zedUpload.AuthInput{AuthType: "http"}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncHttpTr, url, dir, httpAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(operation, objkey, objloc, 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}

	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus()
			}
			return resp.IsError(), resp.GetStatus()
		}
	}
}

func listHTTPFiles(t *testing.T, url, dir string) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	httpAuth := &zedUpload.AuthInput{AuthType: "http"}
	ctx, err := zedUpload.NewDronaCtx("zlister", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncHttpTr, url, dir, httpAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(zedUpload.SyncOpList, "", "", 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}

	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus()
			}

			return resp.IsError(), resp.GetStatus()
		}
	}
}

func getHTTPObjectMetaData(t *testing.T, objloc string, objkey string, url, dir string) (bool, string, int64) {
	respChan := make(chan *zedUpload.DronaRequest)

	httpAuth := &zedUpload.AuthInput{AuthType: "http"}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error(), 0
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncHttpTr, url, dir, httpAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(zedUpload.SyncOpGetObjectMetaData, objkey, objloc, 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}

	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus(), resp.GetContentLength()
			}

			return resp.IsError(), resp.GetStatus(), resp.GetContentLength()
		}
	}
}

func operationSFTP(t *testing.T, objloc string, objkey string, operation zedUpload.SyncOpType) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	sftpAuth := &zedUpload.AuthInput{AuthType: "password", Uname: uname, Password: pass}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncSftpTr, sftpRegion, sftpDir, sftpAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(operation, objkey, objloc, 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}

	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus()
			}

			return resp.IsError(), resp.GetStatus()
		}
	}
}

func operationSFTPNegative(t *testing.T, sftpName string, sftpPass string, operation zedUpload.SyncOpType) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	sftpAuth := &zedUpload.AuthInput{AuthType: "password", Uname: sftpName, Password: sftpPass}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncSftpTr, sftpRegion, sftpDir, sftpAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(operation, "sftpteststuff", sftpUploadFile, 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}

	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus()
			}

			return resp.IsError(), resp.GetStatus()
		}
	}
}

func listSFTPFiles(t *testing.T, path string) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	sftpAuth := &zedUpload.AuthInput{AuthType: "password", Uname: uname, Password: pass}
	ctx, err := zedUpload.NewDronaCtx("zlister", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncSftpTr, sftpRegion, path, sftpAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(zedUpload.SyncOpList, "", "", 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}

	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus()
			}

			return resp.IsError(), resp.GetStatus()
		}
	}
}

func getSFTPObjectMetaData(t *testing.T, objloc string, objkey string) (bool, string, int64) {
	respChan := make(chan *zedUpload.DronaRequest)

	sftpAuth := &zedUpload.AuthInput{AuthType: "password", Uname: uname, Password: pass}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error(), 0
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncSftpTr, sftpRegion, sftpDir, sftpAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(zedUpload.SyncOpGetObjectMetaData, objkey, objloc, 0, true, respChan)
		if req != nil {
			req.Post()
		}
	}

	for {
		select {
		case resp, ok := <-respChan:
			if resp.IsDnUpdate() {
				continue
			}
			if !ok {
				return resp.IsError(), resp.GetStatus(), resp.GetContentLength()
			}

			return resp.IsError(), resp.GetStatus(), resp.GetContentLength()
		}
	}
}

func testAzureBlobWithFile(t *testing.T, objloc string, objkey string) error {
	statusUpload, msgUpload := operationAzureBlob(t, objloc, objkey, zedUpload.SyncOpUpload)
	if statusUpload {
		return fmt.Errorf(msgUpload)
	}
	statusMeta, msgMeta, size, remoteFileMD5 := getAzureBlobMetaData(t, objloc, objkey)
	if statusMeta {
		return fmt.Errorf(msgMeta)
	}
	stat, err := os.Stat(objloc)
	if err == nil {
		if size != stat.Size() {
			return fmt.Errorf("upload size didn't match %v - %v", size, stat.Size())
		}
	} else {
		return err
	}
	localFileMD5, err := hashFileMd5(objloc)
	if err != nil {
		return err
	}
	if remoteFileMD5 != localFileMD5 {
		return fmt.Errorf("upload md5 didn't match %v - %v", remoteFileMD5, localFileMD5)
	}
	statusDownload, msgDownload := operationAzureBlob(t, azureDownloadDir+objkey, objkey, zedUpload.SyncOpDownload)
	if statusDownload {
		return fmt.Errorf(msgDownload)
	}
	downloadFileMD5, err := hashFileMd5(azureDownloadDir + objkey)
	if err != nil {
		return err
	}
	if downloadFileMD5 != localFileMD5 {
		return fmt.Errorf("download md5 didn't match %v - %v", downloadFileMD5, localFileMD5)
	}
	statusDelete, msgDelete := operationAzureBlob(t, objloc, objkey, zedUpload.SyncOpDelete)
	if statusDelete {
		return fmt.Errorf(msgDelete)
	}
	return nil

}

func testAwsS3ObjectWithFile(t *testing.T, objloc string, objkey string) error {
	statusUpload, msgUpload := operationAwsS3(t, objloc, objkey, zedUpload.SyncOpUpload)
	if statusUpload {
		return fmt.Errorf(msgUpload)
	}
	statusMeta, msgMeta, size, remoteFileMD5 := getAwsS3ObjectMetaData(t, objloc, objkey)
	if statusMeta {
		return fmt.Errorf(msgMeta)
	}
	stat, err := os.Stat(objloc)
	if err == nil {
		if size != stat.Size() {
			return fmt.Errorf("upload size didn't match %v - %v", size, stat.Size())
		}
	} else {
		return err
	}
	localFileMD5, err := calculateMd5(objloc, 5242880)
	if err != nil {
		return err
	}
	if remoteFileMD5 != localFileMD5 {
		return fmt.Errorf("upload md5 didn't match %v - %v", remoteFileMD5, localFileMD5)
	}
	statusDownload, msgDownload := operationAwsS3(t, awsDownloadDir+objkey, objkey, zedUpload.SyncOpDownload)
	if statusDownload {
		return fmt.Errorf(msgDownload)
	}
	downloadFileMD5, err := calculateMd5(awsDownloadDir+objkey, 5242880)
	if err != nil {
		return err
	}
	if downloadFileMD5 != localFileMD5 {
		return fmt.Errorf("download md5 didn't match %v - %v", downloadFileMD5, localFileMD5)
	}
	statusDelete, msgDelete := operationAwsS3(t, objloc, objkey, zedUpload.SyncOpDelete)
	if statusDelete {
		return fmt.Errorf(msgDelete)
	}
	return nil

}

func testHTTPObjectWithFile(t *testing.T, objloc, objkey, url, dir string) error {
	statusMeta, msgMeta, size := getHTTPObjectMetaData(t, objloc, objkey, url, dir)
	if statusMeta {
		return fmt.Errorf(msgMeta)
	}
	statusDownload, msgDownload := operationHTTP(t, objloc, objkey, url, dir, zedUpload.SyncOpDownload)
	if statusDownload {
		return fmt.Errorf(msgDownload)
	}
	stat, err := os.Stat(objloc)
	if err == nil {
		if size != stat.Size() {
			return fmt.Errorf("Download size didn't match %v - %v", size, stat.Size())
		}
	} else {
		return err
	}
	return nil

}

func testSFTPObjectWithFile(t *testing.T, objloc string, objkey string) error {
	statusUpload, msgUpload := operationSFTP(t, objloc, objkey, zedUpload.SyncOpUpload)
	if statusUpload {
		return fmt.Errorf(msgUpload)
	}
	statusMeta, msgMeta, size := getSFTPObjectMetaData(t, objloc, objkey)
	if statusMeta {
		return fmt.Errorf(msgMeta)
	}
	stat, err := os.Stat(objloc)
	if err == nil {
		if size != stat.Size() {
			return fmt.Errorf("upload size didn't match %v - %v", size, stat.Size())
		}
	} else {
		return err
	}
	statusDownload, msgDownload := operationSFTP(t, sftpDownloadDir+objkey, objkey, zedUpload.SyncOpDownload)
	if statusDownload {
		return fmt.Errorf(msgDownload)
	}
	downloadFileStat, err := os.Stat(sftpDownloadDir + objkey)
	if err == nil {
		if downloadFileStat.Size() != stat.Size() {
			return fmt.Errorf("Download size didn't match %v - %v", downloadFileStat.Size(), stat.Size())
		}
	} else {
		return err
	}
	statusDelete, msgDelete := operationSFTP(t, objloc, objkey, zedUpload.SyncOpDelete)
	if statusDelete {
		return fmt.Errorf(msgDelete)
	}
	return nil
}

func hashFileMd5(filePath string) (string, error) {
	//Initialize variable returnMD5String now in case an error has to be returned
	var returnMD5String string

	//Open the passed argument and check for any error
	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}

	//Tell the program to call the following function when the current function returns
	defer file.Close()

	//Open a new hash interface to write to
	hash := md5.New()

	//Copy the file in the hash interface and check for any error
	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}

	//Get the 16 bytes hash
	hashInBytes := hash.Sum(nil)[:16]

	//Convert the bytes to a string
	returnMD5String = hex.EncodeToString(hashInBytes)

	return returnMD5String, nil

}

func calculateMd5(filename string, chunkSize int64) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	dataSize, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return "", err
	}

	var (
		sumOfSums []byte
		parts     int
	)
	for i := int64(0); i < dataSize; i += chunkSize {
		length := chunkSize
		if i+chunkSize > dataSize {
			length = dataSize - i
		}
		sum, err := md5sum(f, i, length)
		if err != nil {
			return "", err
		}
		sumOfSums = append(sumOfSums, sum...)
		parts++
	}

	var finalSum []byte

	if parts == 1 {
		finalSum = sumOfSums
	} else {
		h := md5.New()
		_, err := h.Write(sumOfSums)
		if err != nil {
			return "", err
		}
		finalSum = h.Sum(nil)
	}
	sumHex := hex.EncodeToString(finalSum)

	if parts > 1 {
		sumHex += "-" + strconv.Itoa(parts)
	}

	return sumHex, nil
}

func md5sum(r io.ReadSeeker, start, length int64) ([]byte, error) {
	r.Seek(start, io.SeekStart)
	h := md5.New()
	if _, err := io.CopyN(h, r, length); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func TestAwsS3DatastoreAPI(t *testing.T) {
	t.Run("Upload=0", func(t *testing.T) {
		status, msg := operationAwsS3(t, awsUploadFile, "s3teststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=0", func(t *testing.T) {
		status, msg, _, _ := getAwsS3ObjectMetaData(t, awsUploadFile, "s3teststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Upload=1", func(t *testing.T) {
		status, msg := operationAwsS3(t, awsUploadFile, "release/s3teststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=1", func(t *testing.T) {
		status, msg, _, _ := getAwsS3ObjectMetaData(t, awsUploadFile, "release/s3teststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Upload=2", func(t *testing.T) {
		status, msg := operationAwsS3(t, awsUploadFile, "release/1.0/s3teststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=2", func(t *testing.T) {
		status, msg, _, _ := getAwsS3ObjectMetaData(t, awsUploadFile, "release/1.0/s3teststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=0", func(t *testing.T) {
		status, msg := operationAwsS3(t, awsDownloadDir+"file0", "s3teststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=1", func(t *testing.T) {
		status, msg := operationAwsS3(t, awsDownloadDir+"file1", "release/s3teststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=2", func(t *testing.T) {
		status, msg := operationAwsS3(t, awsDownloadDir+"file2", "release/1.0/s3teststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=0", func(t *testing.T) {
		status, _ := listAwsS3Files(t, "randombucket")
		if !status {
			t.Errorf("Non-existent bucket seems to exist")
		}
	})
	t.Run("List=1", func(t *testing.T) {
		status, msg := listAwsS3Files(t, "zedtest123")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=2", func(t *testing.T) {
		status, msg := listAwsS3Files(t, "zedtest123")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=0", func(t *testing.T) {
		status, msg := operationAwsS3(t, "", "s3teststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=1", func(t *testing.T) {
		status, msg := operationAwsS3(t, "", "release/s3teststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=2", func(t *testing.T) {
		status, msg := operationAwsS3(t, "", "release/1.0/s3teststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=2", func(t *testing.T) {
		status, msg := listAwsS3Files(t, "zedtest123")
		if status {
			t.Errorf("%v", msg)
		}
	})
}

func TestAzureBlobDatastoreAPI(t *testing.T) {
	t.Run("Upload=0", func(t *testing.T) {
		status, msg := operationAzureBlob(t, azureUploadFile, "azureteststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=0", func(t *testing.T) {
		status, msg, _, _ := getAzureBlobMetaData(t, azureUploadFile, "azureteststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Upload=1", func(t *testing.T) {
		status, msg := operationAzureBlob(t, azureUploadFile, "release/azureteststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=1", func(t *testing.T) {
		status, msg, _, _ := getAzureBlobMetaData(t, azureUploadFile, "release/azureteststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Upload=2", func(t *testing.T) {
		status, msg := operationAzureBlob(t, azureUploadFile, "release/1.0/azureteststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=2", func(t *testing.T) {
		status, msg, _, _ := getAzureBlobMetaData(t, azureUploadFile, "release/1.0/azureteststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=0", func(t *testing.T) {
		status, msg := operationAzureBlob(t, azureDownloadDir+"file0", "azureteststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=1", func(t *testing.T) {
		status, msg := operationAzureBlob(t, azureDownloadDir+"file1", "release/azureteststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=2", func(t *testing.T) {
		status, msg := operationAzureBlob(t, azureDownloadDir+"file2", "release/1.0/azureteststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=0", func(t *testing.T) {
		status, _ := listAzureBlobFiles(t, "randomcontainer")
		if !status {
			t.Errorf("Non-existent container seems to exist")
		}
	})
	t.Run("List=1", func(t *testing.T) {
		status, msg := listAzureBlobFiles(t, "zedtest123")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=2", func(t *testing.T) {
		status, msg := listAzureBlobFiles(t, "zedtest123")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=0", func(t *testing.T) {
		status, msg := operationAzureBlob(t, "", "azureteststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=1", func(t *testing.T) {
		status, msg := operationAzureBlob(t, "", "release/azureteststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=2", func(t *testing.T) {
		status, msg := operationAzureBlob(t, "", "release/1.0/azureteststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=2", func(t *testing.T) {
		status, msg := listAzureBlobFiles(t, "zedtest123")
		if status {
			t.Errorf("%v", msg)
		}
	})
}

func TestHTTPDatastoreAPI(t *testing.T) {
	t.Run("Upload=0", func(t *testing.T) {
		status, msg := operationHTTP(t, httpUploadFile, "httpteststuff", httpPostRegion, "", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	//t.Run("Upload=1", func(t *testing.T) { operationHTTP(t, httpUploadFile, "release/httpteststuff", httpPostRegion, zedUpload.SyncOpUpload) })
	//t.Run("Upload=2", func(t *testing.T) {
	//	operationHTTP(t, httpUploadFile, "release/1.0/httpteststuff", httpPostRegion, zedUpload.SyncOpUpload)
	//})
	t.Run("Download=0", func(t *testing.T) {
		operationHTTP(t, httpDownloadDir+"file0", "cirros-0.4.0-x86_64-disk.img", httpURL, httpDir, zedUpload.SyncOpDownload)
	})
	t.Run("Download=1", func(t *testing.T) {
		status, msg := operationHTTP(t, httpDownloadDir+"file1", "buildroot_rootfs/buildroot-0.4.0-x86_64.tar.gz", httpURL, httpDir, zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=2", func(t *testing.T) {
		status, msg := operationHTTP(t, httpDownloadDir+"file2", "16.04/release/ubuntu-16.04-server-cloudimg-amd64-disk1.img", httpURL2, httpDir2, zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=0", func(t *testing.T) {
		status, _ := listHTTPFiles(t, "http://1.2.3.4:80", "randompath")
		if !status {
			t.Errorf("Non-existent URL seems to exist")
		}
	})
	//t.Run("List=1", func(t *testing.T) { listHTTPFiles(t, "http://192.168.0.147:80") })
	t.Run("List=2", func(t *testing.T) {
		status, msg := listHTTPFiles(t, httpURL, httpDir)
		if status {
			t.Errorf("%v", msg)
		}
	})
	//t.Run("Delete=0", func(t *testing.T) { operationHTTP(t, "", "httpteststuff", zedUpload.SyncOpDelete) })
	//t.Run("Delete=1", func(t *testing.T) { operationHTTP(t, "", "release/httpteststuff", zedUpload.SyncOpDelete) })
	//t.Run("Delete=2", func(t *testing.T) { operationHTTP(t, "", "release/1.0/httpteststuff", zedUpload.SyncOpDelete) })
}

func TestSFTPDatastoreAPI(t *testing.T) {
	t.Run("Upload=0", func(t *testing.T) {
		status, msg := operationSFTP(t, sftpUploadFile, "sftpteststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=0", func(t *testing.T) {
		status, msg, _ := getSFTPObjectMetaData(t, sftpUploadFile, "sftpteststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Upload=1", func(t *testing.T) {
		status, msg := operationSFTP(t, sftpUploadFile, "release/sftpteststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=1", func(t *testing.T) {
		status, msg, _ := getSFTPObjectMetaData(t, sftpUploadFile, "release/sftpteststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Upload=2", func(t *testing.T) {
		status, msg := operationSFTP(t, sftpUploadFile, "release/1.0/sftpteststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=2", func(t *testing.T) {
		status, msg, _ := getSFTPObjectMetaData(t, sftpUploadFile, "release/1.0/sftpteststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=0", func(t *testing.T) {
		status, msg := operationSFTP(t, sftpDownloadDir+"file0", "sftpteststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=1", func(t *testing.T) {
		status, msg := operationSFTP(t, sftpDownloadDir+"file1", "release/sftpteststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=2", func(t *testing.T) {
		status, msg := operationSFTP(t, sftpDownloadDir+"file2", "release/1.0/sftpteststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=0", func(t *testing.T) {
		status, _ := listSFTPFiles(t, "randompath")
		if !status {
			t.Errorf("Non-existent directory seems to exist")
		}
	})
	t.Run("List=1", func(t *testing.T) {
		status, msg := listSFTPFiles(t, "test/empty")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=2", func(t *testing.T) {
		status, msg := listSFTPFiles(t, "test")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=0", func(t *testing.T) {
		status, msg := operationSFTP(t, "", "sftpteststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=1", func(t *testing.T) {
		status, msg := operationSFTP(t, "", "release/sftpteststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=2", func(t *testing.T) {
		status, msg := operationSFTP(t, "", "release/1.0/sftpteststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=2", func(t *testing.T) {
		status, msg := listSFTPFiles(t, "test")
		if status {
			t.Errorf("%v", msg)
		}
	})
}

func TestAwsS3DatastoreFunctional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping AWS S3 Extended test suite.")
	} else {
		t.Log("Running AWS S3 Extended test suite.")
		t.Run("XtraSmall=0", func(t *testing.T) {
			err := testAwsS3ObjectWithFile(t, uploadDir+"zedupload_test.img", "xtrasmall")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
		t.Run("Small=1", func(t *testing.T) {
			err := testAwsS3ObjectWithFile(t, uploadDir+"zedupload_test_small.img", "small")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func TestAzureBlobDatastoreFunctional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Azure Blob Extended test suite.")
	} else {
		t.Log("Running Azure Blob Extended test suite.")
		t.Run("XtraSmall=0", func(t *testing.T) {
			err := testAzureBlobWithFile(t, uploadDir+"zedupload_test.img", "xtrasmall")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
		t.Run("Small=1", func(t *testing.T) {
			err := testAzureBlobWithFile(t, uploadDir+"zedupload_test_small.img", "small")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func TestHTTPDatastoreFunctional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping HTTP Extended test suite.")
	} else {
		t.Log("Running HTTP Extended test suite.")
		t.Run("XtraSmall=0", func(t *testing.T) {
			err := testHTTPObjectWithFile(t, httpDownloadDir+"file1", "cirros-0.4.0-x86_64-disk.img", httpURL, httpDir)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
		t.Run("Small=0", func(t *testing.T) {
			err := testHTTPObjectWithFile(t, httpDownloadDir+"file2", "cirros-0.4.0-ppc64le-disk.img", httpURL, httpDir)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func TestSFTPDatastoreFunctional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SFTP Extended test suite.")
	} else {
		t.Log("Running SFTP Extended test suite.")
		t.Run("XtraSmall=0", func(t *testing.T) {
			err := testSFTPObjectWithFile(t, uploadDir+"zedupload_test.img", "xtrasmall")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
		t.Run("Small=1", func(t *testing.T) {
			err := testSFTPObjectWithFile(t, uploadDir+"zedupload_test_small.img", "small")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func TestAwsS3DatastoreNegative(t *testing.T) {
	t.Run("InvalidTransport=0", func(t *testing.T) {
		status, _ := operationAwsS3(t, awsUploadFile, "s3teststuff", zedUpload.SyncOpUnknown)
		if !status {
			t.Errorf("Processing invalid transporter")
		}
	})
	t.Run("InvalidUpload=0", func(t *testing.T) {
		status, _ := operationAwsS3(t, uploadDir+"InvalidFile", "s3teststuff", zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Uploading non existent file")
		}
	})
	t.Run("InvalidDownload=0", func(t *testing.T) {
		status, _ := operationAwsS3(t, awsDownloadDir+"file0", "InvalidFile", zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Downloading non existent file")
		}
	})
	t.Run("InvalidKey=0", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, "RandomKey", secret, zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Aws S3 logged in with invalid key")
		}
	})
	t.Run("InvalidKey=1", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, "RandomKey", secret, zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Aws S3 logged in with invalid key")
		}
	})
	t.Run("InvalidKey=2", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, "RandomKey", secret, zedUpload.SyncOpGetObjectMetaData)
		if !status {
			t.Errorf("Aws S3 logged in with invalid key")
		}
	})
	t.Run("InvalidKey=3", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, "RandomKey", secret, zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("Aws S3 logged in with invalid key")
		}
	})
	t.Run("InvalidKey=4", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, "RandomKey", secret, zedUpload.SyncOpList)
		if !status {
			t.Errorf("Aws S3 logged in with invalid key")
		}
	})
	t.Run("InvalidSecret=0", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, key, "InvalidSecret", zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Aws S3 logged in with invalid secret")
		}
	})
	t.Run("InvalidSecret=1", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, key, "InvalidSecret", zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Aws S3 logged in with invalid secret")
		}
	})
	t.Run("InvalidSecret=2", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, key, "InvalidSecret", zedUpload.SyncOpGetObjectMetaData)
		if !status {
			t.Errorf("Aws S3 logged in with invalid secret")
		}
	})
	t.Run("InvalidSecret=3", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, key, "InvalidSecret", zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("Aws S3 logged in with invalid secret")
		}
	})
	t.Run("InvalidSecret=4", func(t *testing.T) {
		status, _ := operationAwsS3Negative(t, key, "InvalidSecret", zedUpload.SyncOpList)
		if !status {
			t.Errorf("Aws S3 logged in with invalid secret")
		}
	})
}

func TestAzureBlobDatastoreNegative(t *testing.T) {
	t.Run("InvalidTransport=0", func(t *testing.T) {
		status, _ := operationAzureBlob(t, azureUploadFile, "azureteststuff", zedUpload.SyncOpUnknown)
		if !status {
			t.Errorf("Processing Invalid transporter")
		}
	})
	t.Run("InvalidUpload=0", func(t *testing.T) {
		status, _ := operationAzureBlob(t, uploadDir+"InvalidFile", "azureteststuff", zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Uploading non existent file")
		}
	})
	t.Run("InvalidDownload=0", func(t *testing.T) {
		status, _ := operationAzureBlob(t, azureDownloadDir+"file0", "InvalidFile", zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Downloading non existent file")
		}
	})
	t.Run("InvalidDelete=0", func(t *testing.T) {
		status, _ := operationAzureBlob(t, "", "InvalidFile", zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("Deleting non existent file")
		}
	})
	t.Run("InvalidKey=0", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, "RandomAccountName", azureAccountKey, zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Azure blob logged in with invalid account name")
		}
	})
	t.Run("InvalidKey=1", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, "RandomAccountName", azureAccountKey, zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Azure blob logged in with invalid account name")
		}
	})
	t.Run("InvalidKey=2", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, "RandomAccountName", azureAccountKey, zedUpload.SyncOpGetObjectMetaData)
		if !status {
			t.Errorf("Azure blob logged in with invalid account name")
		}
	})
	t.Run("InvalidKey=3", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, "RandomAccountName", azureAccountKey, zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("Azure blob logged in with invalid account name")
		}
	})
	t.Run("InvalidKey=4", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, "RandomAccountName", azureAccountKey, zedUpload.SyncOpList)
		if !status {
			t.Errorf("Azure blob logged in with invalid account name")
		}
	})
	t.Run("InvalidSecret=0", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, azureAccountName, "InvalidAccountKey", zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Azure blob logged in with invalid account key")
		}
	})
	t.Run("InvalidSecret=1", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, azureAccountName, "InvalidAccountKey", zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Azure blob logged in with invalid account key")
		}
	})
	t.Run("InvalidSecret=2", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, azureAccountName, "InvalidAccountKey", zedUpload.SyncOpGetObjectMetaData)
		if !status {
			t.Errorf("Azure blob logged in with invalid account key")
		}
	})
	t.Run("InvalidSecret=3", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, azureAccountName, "InvalidAccountKey", zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("Azure blob logged in with invalid account key")
		}
	})
	t.Run("InvalidSecret=4", func(t *testing.T) {
		status, _ := operationAzureBlobNegative(t, azureAccountName, "InvalidAccountKey", zedUpload.SyncOpList)
		if !status {
			t.Errorf("Azure blob logged in with invalid account key")
		}
	})
}

func TestHTTPDatastoreNegative(t *testing.T) {
	t.Run("InvalidTransport=0", func(t *testing.T) {
		status, _ := operationHTTP(t, httpUploadFile, "httpteststuff", httpPostRegion, "", zedUpload.SyncOpUnknown)
		if !status {
			t.Errorf("Processing invalid transporter")
		}
	})
	t.Run("InvalidUpload=0", func(t *testing.T) {
		status, _ := operationHTTP(t, uploadDir+"InvalidFile", "httpteststuff", httpPostRegion, "", zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Uploading non existent file")
		}
	})
	t.Run("InvalidDownload=0", func(t *testing.T) {
		status, _ := operationHTTP(t, httpDownloadDir+"file0", "InvalidFile", httpURL, httpDir, zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Downloading non existent file")
		}
	})
}

func TestSFTPDatastoreNegative(t *testing.T) {
	t.Run("InvalidTransport=0", func(t *testing.T) {
		status, _ := operationSFTP(t, sftpUploadFile, "sftpteststuff", zedUpload.SyncOpUnknown)
		if !status {
			t.Errorf("Processing invalid transporter")
		}
	})
	t.Run("InvalidUpload=0", func(t *testing.T) {
		status, _ := operationSFTP(t, uploadDir+"InvalidFile", "sftpteststuff", zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Uploading non existent file")
		}
	})
	t.Run("InvalidDownload=0", func(t *testing.T) {
		status, _ := operationSFTP(t, sftpDownloadDir+"file0", "InvalidFile", zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Downloading non existent file")
		}
	})
	t.Run("InvalidDelete=0", func(t *testing.T) {
		status, _ := operationSFTP(t, "", "InvalidFile", zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("Deleting non existent file")
		}
	})
	t.Run("InvalidKey=0", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, "RandomUserName", pass, zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Sftp logged in with non existent user")
		}
	})
	t.Run("InvalidKey=1", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, "RandomUserName", pass, zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Sftp logged in with non existent user")
		}
	})
	t.Run("InvalidKey=2", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, "RandomUserName", pass, zedUpload.SyncOpGetObjectMetaData)
		if !status {
			t.Errorf("Sftp logged in with non existent user")
		}
	})
	t.Run("InvalidKey=3", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, "RandomUserName", pass, zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("Azure blob logged in with invalid account name")
		}
	})
	t.Run("InvalidKey=4", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, "RandomUserName", pass, zedUpload.SyncOpList)
		if !status {
			t.Errorf("Sftp logged in with non existent user")
		}
	})
	t.Run("InvalidSecret=0", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, uname, "InvalidPass", zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Sftp logged in with invalid password")
		}
	})
	t.Run("InvalidSecret=1", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, uname, "InvalidPass", zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Sftp logged in with invalid password")
		}
	})
	t.Run("InvalidSecret=2", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, uname, "InvalidPass", zedUpload.SyncOpGetObjectMetaData)
		if !status {
			t.Errorf("Sftp logged in with invalid password")
		}
	})
	t.Run("InvalidSecret=3", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, uname, "InvalidPass", zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("Sftp logged in with invalid password")
		}
	})
	t.Run("InvalidSecret=4", func(t *testing.T) {
		status, _ := operationSFTPNegative(t, uname, "InvalidPass", zedUpload.SyncOpList)
		if !status {
			t.Errorf("Sftp logged in with invalid password")
		}
	})
}
