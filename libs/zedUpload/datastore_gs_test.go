package zedUpload_test

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/lf-edge/eve/libs/zedUpload"
)

const (
	gsUploadFile  = uploadFile
	gsDownloadDir = "./test/output/gsDownload/"
)

var (
	// parameters for Google Storage datastore
	gsBucket  = os.Getenv("TEST_GS_BUCKET")
	gsAPIKey  = os.Getenv("TEST_GS_API_KEY")
	gsProject = os.Getenv("TEST_GS_PROJECT")
)

func TestGSDatastore(t *testing.T) {
	if err := setup(); err != nil {
		t.Fatalf("setup error: %v", err)
	}
	if err := os.MkdirAll(gsDownloadDir, 0755); err != nil {
		t.Fatalf("unable to make download directory: %v", err)
	}
	if gsBucket != "" && gsAPIKey != "" && gsProject != "" {
		t.Run("API", testGSDatastoreAPI)
		t.Run("Negative", testGSDatastoreNegative)
		t.Run("Functional", testGSDatastoreFunctional)
	}
}

func operationGS(t *testing.T, objloc string, objkey string, operation zedUpload.SyncOpType) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	gsAuth := &zedUpload.AuthInput{AuthType: "gs", Uname: gsProject, Password: gsAPIKey}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncGSTr, "", gsBucket, gsAuth)
	if err == nil && dEndPoint != nil {
		// use custom http client for testing same behaviour as in EVE
		_ = dEndPoint.WithSrcIP(net.ParseIP("0.0.0.0"))
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

func operationGSNegative(t *testing.T, gsProject, gsAPIKey string, operation zedUpload.SyncOpType) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	gsAuth := &zedUpload.AuthInput{AuthType: "gs", Uname: gsProject, Password: gsAPIKey}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncGSTr, "", gsBucket, gsAuth)
	if err == nil && dEndPoint != nil {
		// create Request
		req := dEndPoint.NewRequest(operation, "gsteststuff", gsUploadFile, 0, true, respChan)
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

func listGSFiles(t *testing.T, bucket string) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	ctx, err := zedUpload.NewDronaCtx("zlister", 0)
	if ctx == nil {
		return true, err.Error()
	}

	gsAuth := &zedUpload.AuthInput{AuthType: "gs", Uname: gsProject, Password: gsAPIKey}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncGSTr, "", bucket, gsAuth)

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

func getGSObjectMetaData(t *testing.T, objloc string, objkey string) (bool, string, int64, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	gsAuth := &zedUpload.AuthInput{AuthType: "gs", Uname: gsProject, Password: gsAPIKey}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error(), 0, ""
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncGSTr, "", gsBucket, gsAuth)
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

func testGSObjectWithFile(t *testing.T, objloc string, objkey string) error {
	statusUpload, msgUpload := operationGS(t, objloc, objkey, zedUpload.SyncOpUpload)
	if statusUpload {
		return fmt.Errorf(msgUpload)
	}
	statusMeta, msgMeta, size, remoteFileMD5 := getGSObjectMetaData(t, objloc, objkey)
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
	statusDownload, msgDownload := operationGS(t, gsDownloadDir+objkey, objkey, zedUpload.SyncOpDownload)
	if statusDownload {
		return fmt.Errorf(msgDownload)
	}
	downloadFileMD5, err := calculateMd5(gsDownloadDir+objkey, 5242880)
	if err != nil {
		return err
	}
	if downloadFileMD5 != localFileMD5 {
		return fmt.Errorf("download md5 didn't match %v - %v", downloadFileMD5, localFileMD5)
	}
	statusDelete, msgDelete := operationGS(t, objloc, objkey, zedUpload.SyncOpDelete)
	if statusDelete {
		return fmt.Errorf(msgDelete)
	}
	return nil

}

func testGSDatastoreAPI(t *testing.T) {
	t.Run("Upload=0", func(t *testing.T) {
		status, msg := operationGS(t, gsUploadFile, "gsteststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=0", func(t *testing.T) {
		status, msg, _, _ := getGSObjectMetaData(t, gsUploadFile, "gsteststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Upload=1", func(t *testing.T) {
		status, msg := operationGS(t, gsUploadFile, "release/gsteststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=1", func(t *testing.T) {
		status, msg, _, _ := getGSObjectMetaData(t, gsUploadFile, "release/gsteststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Upload=2", func(t *testing.T) {
		status, msg := operationGS(t, gsUploadFile, "release/1.0/gsteststuff", zedUpload.SyncOpUpload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("ObjectMetadata=2", func(t *testing.T) {
		status, msg, _, _ := getGSObjectMetaData(t, gsUploadFile, "release/1.0/gsteststuff")
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=0", func(t *testing.T) {
		status, msg := operationGS(t, gsDownloadDir+"file0", "gsteststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=1", func(t *testing.T) {
		status, msg := operationGS(t, gsDownloadDir+"file1", "release/gsteststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=2", func(t *testing.T) {
		status, msg := operationGS(t, gsDownloadDir+"file2", "release/1.0/gsteststuff", zedUpload.SyncOpDownload)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=0", func(t *testing.T) {
		status, _ := listGSFiles(t, "randombucket")
		if !status {
			t.Errorf("Non-existent bucket seems to exist")
		}
	})
	t.Run("List=1", func(t *testing.T) {
		status, msg := listGSFiles(t, gsBucket)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("List=2", func(t *testing.T) {
		status, msg := listGSFiles(t, gsBucket)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=0", func(t *testing.T) {
		status, msg := operationGS(t, "", "gsteststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=1", func(t *testing.T) {
		status, msg := operationGS(t, "", "release/gsteststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Delete=2", func(t *testing.T) {
		status, msg := operationGS(t, "", "release/1.0/gsteststuff", zedUpload.SyncOpDelete)
		if status {
			t.Errorf("%v", msg)
		}
	})
}

func testGSDatastoreFunctional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping GS Extended test suite.")
	} else {
		t.Log("Running GS Extended test suite.")
		t.Run("XtraSmall=0", func(t *testing.T) {
			err := testGSObjectWithFile(t, uploadFile, "xtrasmall")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
		t.Run("Small=1", func(t *testing.T) {
			err := testGSObjectWithFile(t, uploadFileSmall, "small")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func testGSDatastoreNegative(t *testing.T) {
	t.Run("InvalidTransport=0", func(t *testing.T) {
		status, _ := operationGS(t, gsUploadFile, "gsteststuff", zedUpload.SyncOpUnknown)
		if !status {
			t.Errorf("Processing invalid transporter")
		}
	})
	t.Run("InvalidUpload=0", func(t *testing.T) {
		status, _ := operationGS(t, uploadDir+"InvalidFile", "gsteststuff", zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("Uploading non existent file")
		}
	})
	t.Run("InvalidDownload=0", func(t *testing.T) {
		status, _ := operationGS(t, gsDownloadDir+"file0", "InvalidFile", zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("Downloading non existent file")
		}
	})
	t.Run("InvalidKey=0", func(t *testing.T) {
		status, _ := operationGSNegative(t, gsProject, "RandomKey", zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("GS logged in with invalid key")
		}
	})
	t.Run("InvalidKey=1", func(t *testing.T) {
		status, _ := operationGSNegative(t, gsProject, "RandomKey", zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("GS logged in with invalid key")
		}
	})
	t.Run("InvalidKey=2", func(t *testing.T) {
		status, _ := operationGSNegative(t, gsProject, "RandomKey", zedUpload.SyncOpGetObjectMetaData)
		if !status {
			t.Errorf("GS logged in with invalid key")
		}
	})
	t.Run("InvalidKey=3", func(t *testing.T) {
		status, _ := operationGSNegative(t, gsProject, "RandomKey", zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("GS logged in with invalid key")
		}
	})
	t.Run("InvalidKey=4", func(t *testing.T) {
		status, _ := operationGSNegative(t, gsProject, "RandomKey", zedUpload.SyncOpList)
		if !status {
			t.Errorf("GS logged in with invalid key")
		}
	})
	t.Run("InvalidProject=0", func(t *testing.T) {
		status, _ := operationGSNegative(t, "RandomProject", gsAPIKey, zedUpload.SyncOpUpload)
		if !status {
			t.Errorf("GS logged in with invalid project")
		}
	})
	t.Run("InvalidProject=1", func(t *testing.T) {
		status, _ := operationGSNegative(t, "RandomProject", gsAPIKey, zedUpload.SyncOpDownload)
		if !status {
			t.Errorf("GS logged in with invalid project")
		}
	})
	t.Run("InvalidProject=2", func(t *testing.T) {
		status, _ := operationGSNegative(t, "RandomProject", gsAPIKey, zedUpload.SyncOpGetObjectMetaData)
		if !status {
			t.Errorf("GS logged in with invalid project")
		}
	})
	t.Run("InvalidProject=3", func(t *testing.T) {
		status, _ := operationGSNegative(t, "RandomProject", gsAPIKey, zedUpload.SyncOpDelete)
		if !status {
			t.Errorf("GS logged in with invalid project")
		}
	})
}
