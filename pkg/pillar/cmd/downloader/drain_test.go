// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve-libs/zedUpload"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// testBlobSize is the size of the blob the tests download.
const testBlobSize = 64 * 1024

// blobServer serves testBlobSize bytes at any path. It sends the first half at
// once and the second half only after the transport's progress reporter has
// had time to post an update; with stall set it never sends the second half
// and holds the connection until the client gives up.
func blobServer(t *testing.T, stall bool) *httptest.Server {
	blob := bytes.Repeat([]byte("x"), testBlobSize)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(testBlobSize))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(blob[:testBlobSize/2])
		w.(http.Flusher).Flush()
		if stall {
			<-r.Context().Done()
			return
		}
		time.Sleep(zedUpload.StatsUpdateTicker + 200*time.Millisecond)
		_, _ = w.Write(blob[testBlobSize/2:])
	}))
	t.Cleanup(srv.Close)
	return srv
}

// progressRecorder is the Status of a test download. Like the downloader's
// PublishStatus it reports a change only when the numbers moved.
type progressRecorder struct {
	progress               uint
	currentSize, totalSize int64
}

func (r *progressRecorder) Progress(p uint, currentSize, totalSize int64) bool {
	if r.progress == p && r.currentSize == currentSize && r.totalSize == totalSize {
		return false
	}
	r.progress, r.currentSize, r.totalSize = p, currentSize, totalSize
	return true
}

// runDownload downloads the blob from srv through the downloader's own
// download function, over a fresh transport, and returns the local file and
// what the function returned.
func runDownload(t *testing.T, srv *httptest.Server) (string, error) {
	t.Helper()
	transport, err := zedUpload.NewDronaCtx("test", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &downloaderContext{
		dCtx:         transport,
		globalConfig: *pillartypes.DefaultConfigItemValueMap(),
	}
	localFile := filepath.Join(t.TempDir(), "blob")
	// download reports its cancel channel here and takes it back when done.
	receiveChan := make(chan CancelChannel, 2)
	_, _, _, err = download(ctx, zedUpload.SyncHttpTr, &progressRecorder{},
		zedUpload.SyncOpDownload, srv.URL, "", nil, "", "", 0, "", nil, "blob",
		localFile, nil, false, nil, receiveChan)
	return localFile, err
}

// requireDownloaded fails unless the whole blob has arrived in localFile.
func requireDownloaded(t *testing.T, localFile string) {
	t.Helper()
	info, err := os.Stat(localFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != testBlobSize {
		t.Fatalf("downloaded %d of %d bytes", info.Size(), testBlobSize)
	}
}

// transportSenders counts the transport goroutines that are posting on a
// request's response channel, or would be once their turn comes.
func transportSenders() int {
	var buf bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&buf, 2)
	senders := 0
	for _, stack := range strings.Split(buf.String(), "\n\n") {
		if strings.Contains(stack, "zedUpload.(*DronaCtx).post") ||
			strings.Contains(stack, "zedUpload.statsUpdater") {
			senders++
		}
	}
	return senders
}

// requireNoTransportSenders fails unless every transport goroutine of the
// request has finished within a few seconds.
func requireNoTransportSenders(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for transportSenders() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d transport goroutines are still trying to post a response",
				transportSenders())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A completed download leaves no transport goroutine parked on the response
// channel, although the transport may post once or twice after the final
// response.
func TestTransportSendersFinishAfterDownload(t *testing.T) {
	localFile, err := runDownload(t, blobServer(t, false))
	if err != nil {
		t.Fatal(err)
	}
	requireDownloaded(t, localFile)
	requireNoTransportSenders(t)
}

// A download the downloader gives up on, here for making no progress, leaves
// no transport goroutine parked either: the transport is still busy when the
// downloader returns and posts its final response only after the cancelled
// request has failed.
func TestTransportSendersFinishAfterGivingUp(t *testing.T) {
	defer func(d time.Duration) { maxStalledTime = d }(maxStalledTime)
	maxStalledTime = 1500 * time.Millisecond
	_, err := runDownload(t, blobServer(t, true))
	if err == nil || !strings.Contains(err.Error(), "no progress") {
		t.Fatalf("expected the download to be given up for making no progress, got: %v", err)
	}
	requireNoTransportSenders(t)
}
