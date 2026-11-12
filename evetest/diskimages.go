// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
)

// fetchImageTimeout bounds downloading one image in FetchAndServeImageFile.
// Generous: some pinned cloud images run into the hundreds of megabytes.
const fetchImageTimeout = 5 * time.Minute

// fetchImageMaxAttempts and fetchImageRetryBackoff bound retries in
// FetchAndServeImageFile against transient failures (TLS handshake
// timeouts, connection resets, ...) reaching a public CDN from wherever
// the evetest harness process itself runs.
const (
	fetchImageMaxAttempts  = 3
	fetchImageRetryBackoff = 10 * time.Second
)

// CreateBlankImageFile creates an empty disk image of the given format and
// size, served by evetest's built-in image server (both over HTTP and
// SFTP), and returns its filename (for ImageRelativePath) together with the
// hex-encoded SHA256 of the resulting file's content (for ImageSHA256).
//
// Requires qemu-img to be available inside the evetest container (already a
// build dependency of the broker).
func CreateBlankImageFile(
	name string, format eveconfig.Format, sizeBytes uint64) (relativePath, sha256Hex string) {
	th := getTestHarness()
	formatStr, ok := qemuImgFormat(format)
	if !ok {
		th.t.Fatalf(
			"unsupported disk image format for CreateBlankImageFile: %v", format)
	}
	path := filepath.Join(th.imgServerDir, name)
	cmd := exec.Command("qemu-img", "create", "-f", formatStr,
		path, strconv.FormatUint(sizeBytes, 10))
	if out, err := cmd.CombinedOutput(); err != nil {
		th.t.Fatalf("qemu-img create -f %s %s %d failed: %v: %s",
			formatStr, path, sizeBytes, err, out)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		th.t.Fatalf("failed to read back created disk image %s: %v", path, err)
	}
	sum := sha256.Sum256(content)
	return name, hex.EncodeToString(sum[:])
}

// CreateRandomImageFile creates a file of sizeBytes random bytes, served by
// evetest's built-in image server (see AddImageServerFile), and returns its
// filename (for ImageRelativePath) together with the hex-encoded SHA256 of
// its content (for ImageSHA256).
//
// Random (non-blank) content makes ImageSHA256 verification meaningful: a
// blank file's checksum can't distinguish "downloaded correctly" from
// "downloaded as all zeros/corrupted-but-still-blank" -- a corrupted
// download of random content is vanishingly unlikely to still match the
// checksum computed here.
func CreateRandomImageFile(name string, sizeBytes uint64) (relativePath, sha256Hex string) {
	th := getTestHarness()
	content := make([]byte, sizeBytes)
	if _, err := rand.Read(content); err != nil {
		th.t.Fatalf("failed to generate random content for %s: %v", name, err)
	}
	sum := sha256.Sum256(content)
	relativePath = AddImageServerFile(name, content)
	return relativePath, hex.EncodeToString(sum[:])
}

// AddImageServerFile writes content to a file served by evetest's built-in
// image server (both over HTTP and SFTP), returning its filename for use as
// HTTPStorage.ImageRelativePath / SFTPStorage.ImageRelativePath.
func AddImageServerFile(name string, content []byte) string {
	th := getTestHarness()
	path := filepath.Join(th.imgServerDir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		th.t.Fatalf("failed to write image server file %s: %v", name, err)
	}
	return name
}

// ImageServerRequest describes one request received by evetest's built-in
// image server over HTTP or HTTPS.
type ImageServerRequest struct {
	// Method is the HTTP method of the request, e.g. "GET".
	Method string
	// RequestURI is the path and the query string of the request, e.g.
	// "/image.bin?sig=token".
	RequestURI string
}

// GetImageServerRequests returns the requests which evetest's built-in image
// server has received so far over HTTP and HTTPS for the file with the given
// name (as returned by AddImageServerFile; a query string is not part of it),
// oldest first. A test can thus tell at the datastore whether, how often and
// with which URL a device has asked for a file, instead of inferring it from
// the state the device reports. Requests over SFTP and TFTP are not recorded.
//
// A request is recorded when it arrives, whether or not the file exists and
// whether or not the download completes, and a device may send more than one
// request for a single download. The image server lives as long as the test
// suite, so the requests of earlier tests of the suite for a file of the same
// name are included.
func GetImageServerRequests(name string) []ImageServerRequest {
	return getTestHarness().imgServerRequests.requestsFor(name)
}

// imgServerRequestLog records the requests received by the image server over
// HTTP and HTTPS. The zero value is ready to use.
type imgServerRequestLog struct {
	mu sync.Mutex
	// requests holds, per requested path relative to the image server's root,
	// the requests received for it, oldest first.
	requests map[string][]ImageServerRequest
}

// record returns a handler which records every request it receives and then
// passes it on to next.
func (requestLog *imgServerRequestLog) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		requestLog.mu.Lock()
		if requestLog.requests == nil {
			requestLog.requests = make(map[string][]ImageServerRequest)
		}
		requestLog.requests[name] = append(requestLog.requests[name], ImageServerRequest{
			Method:     r.Method,
			RequestURI: r.URL.RequestURI(),
		})
		requestLog.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// requestsFor returns a copy of the requests recorded for the given file.
func (requestLog *imgServerRequestLog) requestsFor(name string) []ImageServerRequest {
	requestLog.mu.Lock()
	defer requestLog.mu.Unlock()
	return append([]ImageServerRequest(nil), requestLog.requests[name]...)
}

// FetchAndServeImageFile downloads url over the evetest container's own
// network and re-serves it from evetest's built-in image server, so a
// device with no outbound Internet reachability can still download it as a
// normal HTTP datastore -- just a local one instead of the remote url.
// Retries a few times on transient network failures (observed in practice:
// TLS handshake timeouts reaching a public CDN), since this whole path is
// otherwise fully deterministic. Returns name, for use as
// HTTPStorage.ImageRelativePath.
func FetchAndServeImageFile(url, name, sha256Hex string) string {
	th := getTestHarness()
	var content []byte
	var err error
	for attempt := 1; attempt <= fetchImageMaxAttempts; attempt++ {
		content, err = fetchImage(th, url)
		if err == nil {
			break
		}
		if attempt == fetchImageMaxAttempts {
			th.t.Fatalf("FetchAndServeImageFile: GET %s: %v (after %d attempts)",
				url, err, attempt)
		}
		th.log.Warnf("FetchAndServeImageFile: GET %s: attempt %d/%d failed: %v, retrying in %s",
			url, attempt, fetchImageMaxAttempts, err, fetchImageRetryBackoff)
		time.Sleep(fetchImageRetryBackoff)
	}
	sum := sha256.Sum256(content)
	if got := hex.EncodeToString(sum[:]); got != sha256Hex {
		th.t.Fatalf("FetchAndServeImageFile: %s: SHA256 mismatch: got %s, want %s",
			url, got, sha256Hex)
	}
	return AddImageServerFile(name, content)
}

// fetchImage performs one GET attempt for FetchAndServeImageFile.
//
// The dial's local address is pinned to GetSrcIPv4ForInternetAccess():
// the container's default route goes via evetest's own SDN tunnel (see
// setupSDNTunnelRoutes in setup.go), which exists to carry EVE/App/SDN
// traffic, not arbitrary outbound connections from the harness process
// itself -- a plain http.DefaultClient GET over that path can complete the
// TCP handshake but then hang indefinitely on the TLS handshake. Binding
// the source address instead engages the policy route setupSDNTunnelRoutes
// already installs for exactly this ("Test <-> Internet"), which goes out
// via the container's real docker-network path.
func fetchImage(th *TestHarness, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(th.ctx, fetchImageTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: GetSrcIPv4ForInternetAccess()}}
	client := http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return content, nil
}

// qemuImgFormat maps an eveconfig.Format to the "-f" format name accepted by
// qemu-img.
func qemuImgFormat(format eveconfig.Format) (string, bool) {
	switch format {
	case eveconfig.Format_RAW:
		return "raw", true
	case eveconfig.Format_QCOW:
		return "qcow", true
	case eveconfig.Format_QCOW2:
		return "qcow2", true
	case eveconfig.Format_VHD:
		return "vpc", true // qemu-img calls the VHD format "vpc"
	case eveconfig.Format_VMDK:
		return "vmdk", true
	case eveconfig.Format_VHDX:
		return "vhdx", true
	default:
		return "", false
	}
}
