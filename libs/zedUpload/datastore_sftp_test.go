package zedUpload_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/lf-edge/eve/libs/zedUpload"
)

const (
	sftpUploadFile  = uploadFile
	sftpDownloadDir = "./test/output/sftpDownload/"
)

var (
	// parameters for SFTP datastore
	sftpDir    = os.Getenv("TEST_SFTP_DIR")
	uname      = os.Getenv("TEST_SFTP_USER")
	pass       = os.Getenv("TEST_SFTP_PASS")
	sftpRegion = os.Getenv("TEST_SFTP_REGION")
)

func TestSFTPDatastore(t *testing.T) {
	if err := setup(); err != nil {
		t.Fatalf("setup error: %v", err)
	}
	if err := os.MkdirAll(sftpDownloadDir, 0755); err != nil {
		t.Fatalf("unable to make download directory: %v", err)
	}
	if sftpDir != "" && uname != "" && pass != "" && sftpRegion != "" {
		t.Run("API", testSFTPDatastoreAPI)
		t.Run("Negative", testSFTPDatastoreNegative)
		t.Run("Functional", testSFTPDatastoreFunctional)
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
			_ = req.Post()
		}
	}

	var (
		isErr  bool
		status string
		length int64
	)
	for resp := range respChan {
		if resp.IsDnUpdate() {
			continue
		}
		isErr, status, length = resp.IsError(), resp.GetStatus(), resp.GetContentLength()
		break
	}
	return isErr, status, length
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

func testSFTPDatastoreAPI(t *testing.T) {
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

func testSFTPDatastoreFunctional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SFTP Extended test suite.")
	} else {
		t.Log("Running SFTP Extended test suite.")
		t.Run("XtraSmall=0", func(t *testing.T) {
			err := testSFTPObjectWithFile(t, uploadFile, "xtrasmall")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
		t.Run("Small=1", func(t *testing.T) {
			err := testSFTPObjectWithFile(t, uploadFileSmall, "small")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func testSFTPDatastoreNegative(t *testing.T) {
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
