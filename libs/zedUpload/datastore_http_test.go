package zedUpload_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/lf-edge/eve/libs/zedUpload"
)

const (
	// parameters for HTTP datastore
	httpPostRegion  = "http://ptsv2.com/t/httptest/post"
	httpURL         = "http://download.cirros-cloud.net"
	httpURL2        = "http://cloud-images.ubuntu.com/"
	httpDir         = "0.4.0/"
	httpDir2        = "releases"
	httpUploadFile  = uploadFile
	httpDownloadDir = "./test/output/httpDownload/"
)

func TestHTTPDatastore(t *testing.T) {
	if err := setup(); err != nil {
		t.Fatalf("setup error: %v", err)
	}
	if err := os.MkdirAll(httpDownloadDir, 0755); err != nil {
		t.Fatalf("unable to make download directory: %v", err)
	}
	t.Run("API", testHTTPDatastoreAPI)
	t.Run("Negative", testHTTPDatastoreNegative)
	t.Run("Functional", testHTTPDatastoreFunctional)
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

func testHTTPDatastoreAPI(t *testing.T) {
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

func testHTTPDatastoreFunctional(t *testing.T) {
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

func testHTTPDatastoreNegative(t *testing.T) {
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
