package zedUpload_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/libs/zedUpload"
)

const (
	// parameters for HTTP datastore
	httpPostRegion  = "http://ptsv2.com/t/httptest/post"
	httpURL         = "http://cloud-images.ubuntu.com"
	httpDir         = "releases"
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
	t.Run("Repeat", testHTTPDatastoreRepeat)
}

func operationHTTP(t *testing.T, objloc string, objkey string, url, dir string, operation zedUpload.SyncOpType, local bool) (bool, string) {
	respChan := make(chan *zedUpload.DronaRequest)

	httpAuth := &zedUpload.AuthInput{AuthType: "http"}
	ctx, err := zedUpload.NewDronaCtx("zuploader", 0)
	if ctx == nil {
		return true, err.Error()
	}

	// create Endpoint
	dEndPoint, err := ctx.NewSyncerDest(zedUpload.SyncHttpTr, url, dir, httpAuth)
	if err == nil && dEndPoint != nil {
		if local {
			var lIP net.IP
			err = lIP.UnmarshalText([]byte("127.0.0.1"))
			if err != nil {
				return true, err.Error()
			}
			err = dEndPoint.WithSrcIP(lIP)
			if err != nil {
				return true, err.Error()
			}
		}
		// create Request
		req := dEndPoint.NewRequest(operation, objkey, objloc, 0, true, respChan)
		if req != nil {
			_ = req.Post()
		}
	}

	var (
		isErr           bool
		status          string
		lastCurrentSize int64
		lastUpdate      = time.Now()
	)
	for resp := range respChan {
		if resp.IsDnUpdate() {
			currentSize, totalSize, _ := resp.Progress()
			if currentSize != lastCurrentSize {
				t.Logf("Update progress for %v: %v/%v",
					resp.GetLocalName(), currentSize, totalSize)
				lastCurrentSize = currentSize
				lastUpdate = time.Now()
			}
			if time.Now().After(lastUpdate.Add(20 * time.Minute)) {
				t.Errorf("No update during 20 minutes")
				break
			}
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
	statusDownload, msgDownload := operationHTTP(t, objloc, objkey, url, dir, zedUpload.SyncOpDownload, false)
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
		status, msg := operationHTTP(t, httpUploadFile, "httpteststuff", httpPostRegion, "", zedUpload.SyncOpUpload, false)
		if status {
			t.Errorf("%v", msg)
		}
	})
	//t.Run("Upload=1", func(t *testing.T) { operationHTTP(t, httpUploadFile, "release/httpteststuff", httpPostRegion, zedUpload.SyncOpUpload) })
	//t.Run("Upload=2", func(t *testing.T) {
	//	operationHTTP(t, httpUploadFile, "release/1.0/httpteststuff", httpPostRegion, zedUpload.SyncOpUpload)
	//})
	t.Run("Download=0", func(t *testing.T) {
		status, msg := operationHTTP(t, httpDownloadDir+"file0", "bionic/release-20210804/ubuntu-18.04-server-cloudimg-s390x-lxd.tar.xz", httpURL, httpDir, zedUpload.SyncOpDownload, false)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=1", func(t *testing.T) {
		status, msg := operationHTTP(t, httpDownloadDir+"file1", "minimal/releases/bionic/release-20210803/ubuntu-18.04-minimal-cloudimg-amd64-root.tar.xz", httpURL, "", zedUpload.SyncOpDownload, false)
		if status {
			t.Errorf("%v", msg)
		}
	})
	t.Run("Download=2", func(t *testing.T) {
		status, msg := operationHTTP(t, httpDownloadDir+"file2", "xenial/release/ubuntu-16.04-server-cloudimg-amd64-disk1.img", httpURL, httpDir, zedUpload.SyncOpDownload, false)
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
		status, msg := listHTTPFiles(t, httpURL, httpDir+"/")
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
			err := testHTTPObjectWithFile(t, httpDownloadDir+"file1", "minimal/releases/bionic/release-20210803/ubuntu-18.04-minimal-cloudimg-amd64-lxd.tar.xz", httpURL, "")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
		t.Run("Small=0", func(t *testing.T) {
			err := testHTTPObjectWithFile(t, httpDownloadDir+"file2", "minimal/releases/bionic/release-20210803/ubuntu-18.04-minimal-cloudimg-amd64-root.tar.xz", httpURL, "")
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func testHTTPDatastoreNegative(t *testing.T) {
	t.Run("InvalidTransport=0", func(t *testing.T) {
		status, _ := operationHTTP(t, httpUploadFile, "httpteststuff", httpPostRegion, "", zedUpload.SyncOpUnknown, false)
		if !status {
			t.Errorf("Processing invalid transporter")
		}
	})
	t.Run("InvalidUpload=0", func(t *testing.T) {
		status, _ := operationHTTP(t, uploadDir+"InvalidFile", "httpteststuff", httpPostRegion, "", zedUpload.SyncOpUpload, false)
		if !status {
			t.Errorf("Uploading non existent file")
		}
	})
	t.Run("InvalidDownload=0", func(t *testing.T) {
		status, _ := operationHTTP(t, httpDownloadDir+"file0", "InvalidFile", httpURL, httpDir, zedUpload.SyncOpDownload, false)
		if !status {
			t.Errorf("Downloading non existent file")
		}
	})
}

func testHTTPDatastoreRepeat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping HTTP repeat test suite.")
	} else {
		t.Log("Running HTTP repeat test suite.")

		go func() {
			err := newUnstableProxyStart(9999, 80, "cloud-images.ubuntu.com", 1024*1024*100, 40*time.Second, 100)
			if err != nil {
				t.Error(err)
			}
		}()

		status, msg := operationHTTP(t, httpDownloadDir+"repeat2", "releases/focal/release/ubuntu-20.04.2-preinstalled-server-riscv64.img.xz", "http://127.0.0.1:9999", "", zedUpload.SyncOpDownload, true)
		if status {
			t.Errorf("%v", msg)
		}
		hashSum, err := sha256File(httpDownloadDir + "repeat2")
		if err != nil {
			t.Errorf("%v", err)
		} else {
			if hashSum != "cd8d892bfff2b7167e51395f462b6096f657e61de325acd97da2272769efa761" {
				t.Errorf("hash mismatch")
			}
		}
	}
}

func sha256File(filePath string) (string, error) {
	hasher := sha256.New()
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
