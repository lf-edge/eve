package zedUpload_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/lf-edge/eve/libs/zedUpload"
)

const (
	awsUploadFile  = uploadFile
	awsDownloadDir = "./test/output/awsDownload/"
)

var (
	// parameters for AWS S3 datastore
	awsBucket = os.Getenv("TEST_AWS_BUCKET")
	key       = os.Getenv("TEST_AWS_KEY")
	secret    = os.Getenv("TEST_AWS_SECRET")
	awsRegion = os.Getenv("TEST_AWS_REGION")
)

func TestAwsS3Datastore(t *testing.T) {
	if err := setup(); err != nil {
		t.Fatalf("setup error: %v", err)
	}
	if err := os.MkdirAll(awsDownloadDir, 0755); err != nil {
		t.Fatalf("unable to make download directory: %v", err)
	}
	if awsBucket != "" && key != "" && secret != "" && awsRegion != "" {
		t.Run("API", testAwsS3DatastoreAPI)
		t.Run("Negative", testAwsS3DatastoreNegative)
		t.Run("Functional", testAwsS3DatastoreFunctional)
	}
}

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
			_ = req.Post()
		} else {
			return true, "New datastore request creation failed"
		}
	} else {
		return true, "New datastore context creation failed"
	}

	var (
		isErr  bool
		status string
	)
	for resp := range respChan {
		if resp.IsDnUpdate() {
			continue
		}
		isErr, status = resp.IsError(), resp.GetStatus()
		break
	}
	return isErr, status
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
			_ = req.Post()
		} else {
			return true, "New datastore request creation failed"
		}
	} else {
		return true, "New datastore context creation failed"
	}

	var (
		isErr  bool
		status string
	)
	for resp := range respChan {
		if resp.IsDnUpdate() {
			continue
		}
		isErr, status = resp.IsError(), resp.GetStatus()
		break
	}
	return isErr, status
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
			_ = req.Post()
		} else {
			return true, "New datastore request creation failed"
		}
	} else {
		return true, "New datastore context creation failed"
	}

	var (
		isErr  bool
		status string
	)
	for resp := range respChan {
		if resp.IsDnUpdate() {
			continue
		}
		isErr, status = resp.IsError(), resp.GetStatus()
		break
	}
	return isErr, status
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
			_ = req.Post()
		} else {
			return true, "New datastore request creation failed", 0, ""
		}
	} else {
		return true, "New datastore context creation failed", 0, ""
	}

	var (
		isErr  bool
		status string
		length int64
		md5    string
	)
	for resp := range respChan {
		if resp.IsDnUpdate() {
			continue
		}
		isErr, status, length, md5 = resp.IsError(), resp.GetStatus(), resp.GetContentLength(), resp.GetRemoteFileMD5()
		break
	}
	return isErr, status, length, md5
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

func testAwsS3DatastoreAPI(t *testing.T) {
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

func testAwsS3DatastoreFunctional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping AWS S3 Extended test suite.")
	} else {
		t.Log("Running AWS S3 Extended test suite.")
		t.Run("XtraSmall=0", func(t *testing.T) {
			err := testAwsS3ObjectWithFile(t, uploadFile, "xtrasmall")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
		t.Run("Small=1", func(t *testing.T) {
			err := testAwsS3ObjectWithFile(t, uploadFileSmall, "small")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func testAwsS3DatastoreNegative(t *testing.T) {
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
