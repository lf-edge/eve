package zedUpload_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/lf-edge/eve/libs/zedUpload"
)

const (
	azureUploadFile  = uploadFile
	azureDownloadDir = "./test/output/azureDownload/"
)

var (
	// parameters for AZURE datastore
	azureContainer   = os.Getenv("TEST_AZURE_CONTAINER")
	azureAccountName = os.Getenv("TEST_AZURE_ACCOUNT_NAME")
	azureAccountKey  = os.Getenv("TEST_AZURE_ACCOUNT_KEY")
)

func TestAzureBlobDatastore(t *testing.T) {
	if err := setup(); err != nil {
		t.Fatalf("setup error: %v", err)
	}
	if err := os.MkdirAll(azureDownloadDir, 0755); err != nil {
		t.Fatalf("unable to make download directory: %v", err)
	}
	if azureContainer != "" && azureAccountName != "" && azureAccountKey != "" {
		t.Run("API", testAzureBlobDatastoreAPI)
		t.Run("Negative", testAzureBlobDatastoreNegative)
		t.Run("Functional", testAzureBlobDatastoreFunctional)
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
			_ = req.Post()
		}
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
			_ = req.Post()
		}
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
			_ = req.Post()
		}
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
			_ = req.Post()
		}
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

func testAzureBlobDatastoreAPI(t *testing.T) {
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

func testAzureBlobDatastoreFunctional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Azure Blob Extended test suite.")
	} else {
		t.Log("Running Azure Blob Extended test suite.")
		t.Run("XtraSmall=0", func(t *testing.T) {
			err := testAzureBlobWithFile(t, uploadFile, "xtrasmall")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
		t.Run("Small=1", func(t *testing.T) {
			err := testAzureBlobWithFile(t, uploadFileSmall, "small")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func testAzureBlobDatastoreNegative(t *testing.T) {
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
