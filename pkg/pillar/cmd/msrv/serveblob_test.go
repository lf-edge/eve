// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func serveBlobTestMsrv() *Msrv {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "msrv-serveblob-test", 0)
	return &Msrv{Log: log, Logger: logger}
}

// TestServeBinaryBlobRegularFile is the regression guard for file/qcow-backed
// volumes: os.Stat().Size() is correct for a regular file, so serveBinaryBlob
// must defer to http.ServeFile and return the whole file with a matching
// Content-Length.
func TestServeBinaryBlobRegularFile(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	content := []byte("hello patch envelope content")
	path := filepath.Join(t.TempDir(), "blob.bin")
	g.Expect(os.WriteFile(path, content, 0600)).To(gomega.Succeed())

	blob := types.BinaryBlobCompleted{
		FileName: "blob.bin",
		URL:      path,
		Size:     int64(len(content)),
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/eve/v1/patch/download/p/blob.bin", nil)
	serveBlobTestMsrv().serveBinaryBlob(rr, req, blob)

	g.Expect(rr.Code).To(gomega.Equal(http.StatusOK))
	g.Expect(rr.Body.Bytes()).To(gomega.Equal(content))
	g.Expect(rr.Result().ContentLength).To(gomega.Equal(int64(len(content))))
}

// TestServeBinaryBlobBlockDeviceSized exercises the ZFS zvol scenario. A zvol
// is a block device whose os.Stat().Size() reports 0 (so http.ServeFile would
// answer Content-Length: 0) and whose readable length is rounded up to the
// volume block size (so reading to EOF would append padding and corrupt the
// artifact's checksum).
//
// A FIFO reproduces both properties without needing a real block device (root):
// Mode().IsRegular() is false and Stat().Size() is 0. We write content plus
// trailing padding and assert serveBinaryBlob returns exactly blob.Size content
// bytes - no Content-Length: 0, and no padding.
func TestServeBinaryBlobBlockDeviceSized(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	content := []byte(strings.Repeat("A", 4096))
	// Simulate the zvol being rounded up past the real content length.
	padding := make([]byte, 512)

	fifo := filepath.Join(t.TempDir(), "zvol.fifo")
	g.Expect(syscall.Mkfifo(fifo, 0600)).To(gomega.Succeed())

	// Opening a FIFO blocks until the other end is opened, so the writer must
	// run concurrently with serveBinaryBlob's os.Open. content+padding stays
	// well under the pipe buffer, so the Write returns even though the reader
	// consumes only blob.Size bytes - no deadlock, no goroutine leak.
	writeErr := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			writeErr <- err
			return
		}
		defer f.Close()
		_, err = f.Write(append(append([]byte{}, content...), padding...))
		writeErr <- err
	}()

	blob := types.BinaryBlobCompleted{
		FileName: "zvol.fifo",
		URL:      fifo,
		Size:     int64(len(content)),
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/eve/v1/patch/download/p/zvol.fifo", nil)
	serveBlobTestMsrv().serveBinaryBlob(rr, req, blob)

	g.Expect(rr.Code).To(gomega.Equal(http.StatusOK))
	g.Expect(rr.Header().Get("Content-Length")).To(gomega.Equal(strconv.Itoa(len(content))))
	g.Expect(rr.Body.Len()).To(gomega.Equal(len(content)))
	g.Expect(rr.Body.Bytes()).To(gomega.Equal(content))

	g.Eventually(writeErr).Should(gomega.Receive(gomega.BeNil()))
}

// TestServeBinaryBlobNonRegularUnknownSize verifies we fail loudly rather than
// silently serving an empty body when the backing is a non-regular file but the
// content length is unknown.
func TestServeBinaryBlobNonRegularUnknownSize(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	fifo := filepath.Join(t.TempDir(), "zvol.fifo")
	g.Expect(syscall.Mkfifo(fifo, 0600)).To(gomega.Succeed())

	blob := types.BinaryBlobCompleted{
		FileName: "zvol.fifo",
		URL:      fifo,
		Size:     0,
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/eve/v1/patch/download/p/zvol.fifo", nil)
	serveBlobTestMsrv().serveBinaryBlob(rr, req, blob)

	g.Expect(rr.Code).To(gomega.Equal(http.StatusInternalServerError))
}
