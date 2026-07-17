// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import "testing"

// Datastore tests verify that EVE can pull application images from the various
// datastore backends supported by the EVE API (HTTP, HTTPS, AWS S3, SFTP, Azure
// Blob, container registries). They focus on the network/datastore plumbing
// (correct datastore URL construction, authentication, certificate handling,
// download progress reporting, error propagation), not on the application
// runtime — once the image is downloaded and verified, the test can stop.
//
// Reusable scenario shape
// -----------------------
//
// All these tests follow the same structure:
//
//  1. Setup a single-port mgmt device (netmodels.SingleEthWithDHCP). Internet
//     connectivity is required only for tests that talk to a real cloud
//     datastore (AWS/Azure); HTTP/HTTPS/SFTP can be fully self-contained inside
//     SDN.
//  2. Build a device config with:
//     - one DHCP network on eth0 (mgmt+app),
//     - a Local NI for the test application,
//     - one application referencing a small image stored in the datastore
//     under test.
//  3. Drive the test by `device.WatchContentTreeInfo(ctUUID)` and
//     `device.WatchVolumeInfo(volUUID)`:
//     - Assert that the content tree progresses through DOWNLOAD_STARTED ->
//     DOWNLOADED -> VERIFIED -> LOADED, with download progress strictly
//     monotonic (this also catches stalled downloads from a misbehaving
//     datastore endpoint).
//     - Assert that the resulting volume reaches CREATED_VOLUME.
//     - Assert that the application reaches RUNNING (use WaitUntilAppIsRunning
//     — it already handles download stalls and excludes download time from
//     the timeout budget; see edgedevice.go).
//  4. As a sanity check on networking, run a short script inside the app
//     (RunShellScriptInsideApp) printing hostname/IP, but the primary
//     assertions are about download/verification, not application semantics.
//  5. Negative-path variants where appropriate (see per-test sections):
//     - wrong SHA256 -> content tree should reach ERROR with descriptive
//     err description.
//     - bad credentials -> ditto.
//     - server cert not trusted (HTTPS) -> ditto.
//
// Why we still want a deployed app rather than just a content tree + datastore:
// downloading and verifying alone is implemented in volumemgr/downloader, but
// EVE only triggers the download when there is a concrete consumer. The
// simplest way to guarantee that is to declare an application that volume-refs
// the content tree. The app does not need to do anything useful — a tiny
// container image is sufficient. Once support for "datastore + content-tree
// without app" is confirmed possible (volumemgr will pre-download referenced
// content trees), these tests can be simplified to skip the app deployment.
//
// Test images
// -----------
//
//   - For HTTP/HTTPS/SFTP: prefer pushing/serving a tiny, fixed Linux image (a
//     few-MB Alpine qcow2 or a hand-crafted busybox container tarball) from
//     within the SDN environment. This keeps the tests hermetic and fast.
//     This requires extending the SDN/HTTPServer endpoint to serve binary
//     content (currently it only serves the small "Paths" map) and adding a
//     simple SFTPServer endpoint type to evetest's grpcapi/sdn.proto. Both
//     enhancements are scoped to evetest and do NOT touch EVE itself.
//     Until that exists, point HTTP-only tests at a public, very small,
//     versioned image and accept the external dependency.
//     -> suggestion: download Tiny core linux (https://gns3.com/tiny-core-linux)
//     from inside the test. If it fails, mark the test as skipped.
//     Note that both HTTPS and SFTP tests also download this image -- perhaps
//     store/reuse it from a fixed /tmp location.
//     Then upload to SDN and have it served hy HTTP server inside the SDN.
//     (this requires enhancements inside SDN to support uploading and serving binary data)
//
//   - For AWS S3 / Azure Blob: parameterize via EVETEST_AWS_* / EVETEST_AZURE_*
//     environment variables (test parameters). Skip the test if the parameters
//     are not set, rather than failing -- these tests should be opt-in.
//
//   - For container registries: use a small public image. lfedge/evetest-*
//     test images are already used elsewhere; reuse the smallest one.
//
// TestHTTPDatastore validates that EVE can download a content tree served over
// plain HTTP.
//
// Recommended approach: extend SDN to host a binary file via an HTTPServer
// endpoint (or add a new SDN HTTPFileServer endpoint type), then point the
// device config at "http://http-server.test/<image>" with the matching
// SHA256. With the SDN-internal server the test is fully self-contained.
//
// Variants worth exercising:
//   - Happy path: known SHA256, known size -> RUNNING.
//   - SHA256 mismatch: content tree reaches ERROR; the error description must
//     mention checksum/verification failure (the exact wording can be
//     captured in a regexp matcher).
//   - Server returns 404: content tree ERROR; description should reference
//     the HTTP status.
//   - Slow server: configure SDN port TrafficControl with rate_limit (a few
//     hundred KB/s) and confirm WaitUntilAppIsRunning's "download stall"
//     watchdog still considers progress valid (this exercises the
//     downloadStalledTimeout path).
func TestHTTPDatastore(test *testing.T) {
	test.Skip("not yet implemented")
}

// TestHTTPSDatastore is identical to TestHTTPDatastore except the image is
// served over HTTPS, and the test exercises the certificate trust plumbing.
//
// Recommended approach: have SDN host the file behind an HTTPS endpoint with
// a self-signed certificate. The test passes the CA in PEM form to EVE via
// HTTPStorage.HTTPSTrustedCACertsPEM, and verifies a successful download.
// The HTTPServer endpoint type in SDN already supports HTTPS-style serving.
//
// Suggestion: download Tiny core linux (https://gns3.com/tiny-core-linux)
// from inside the test. If it fails, mark the test as skipped.
// Note that both HTTP and SFTP tests also download this image -- perhaps
// store/reuse it from a fixed /tmp location.
// Then upload to SDN and have it served hy HTTPS server inside the SDN.
// (this requires enhancements inside SDN to support uploading and serving binary data)
//
// Variants:
//   - Happy path with the test-provided CA in HTTPSTrustedCACertsPEM.
//   - CA missing / wrong: download must ERROR with an x509-related message.
//   - Server cert expired: ERROR with the expected description.
func TestHTTPSDatastore(test *testing.T) {
	test.Skip("not yet implemented")
}

// TestAWSDatastore validates EVE's S3 datastore code path. Because EVE talks
// to actual AWS S3 in this case, the test is opt-in: it skips itself unless
// the user has supplied credentials and a bucket via test parameters.
//
// Test parameters (TestParameterDefinition):
//   - EVETEST_AWS_REGION        (e.g. "us-east-1")
//   - EVETEST_AWS_BUCKET        (existing bucket the user controls)
//   - EVETEST_AWS_KEY           (relative path of a small image inside the bucket)
//   - EVETEST_AWS_ACCESS_KEY_ID
//   - EVETEST_AWS_SECRET        (encrypted via cipher infra after onboarding)
//   - EVETEST_AWS_SHA256        (SHA256 of the image)
//
// Skip behavior: if any required parameter is empty, t.Skip with a clear
// "set EVETEST_AWS_* to enable" message.
//
// Variants:
//   - Happy path with valid credentials -> RUNNING.
//   - Wrong secret access key -> ERROR; description should mention auth/403.
//   - Wrong key (object missing) -> ERROR; description should mention 404 /
//     NoSuchKey.
//
// Network model: SingleEthWithDHCP + RequireInternetConnectivity{}.
func TestAWSDatastore(test *testing.T) {
	test.Skip("not yet implemented")
}

// TestSFTPDatastore validates the SFTP datastore code path.
//
// Recommended approach: add an SFTPServer endpoint to SDN
// (evetest/grpcapi/proto/sdn.proto) hosting a small image with username /
// password authentication. This keeps the test hermetic. Until that exists,
// gate the test on EVETEST_SFTP_* parameters analogous to the AWS test.
//
//	-> suggestion: download Tiny core linux (https://gns3.com/tiny-core-linux)
//	from inside the test. If it fails, mark the test as skipped.
//	Note that both HTTP and HTTPS tests also download this image -- perhaps
//	store/reuse it from a fixed /tmp location.
//	Then upload to SDN and have it served hy SFTP server inside the SDN.
//	(this requires enhancements inside SDN to support uploading and serving binary data
//	 and the support for SFTP itself)
//
// Variants:
//   - Happy path -> RUNNING.
//   - Wrong password -> ERROR with auth-failure description.
//   - Wrong path -> ERROR with file-not-found description.
func TestSFTPDatastore(test *testing.T) {
	test.Skip("not yet implemented")
}

// TestAzureDatastore validates Azure Blob storage as a datastore. Like AWS, it
// is opt-in via test parameters since hosting Azure-compatible storage inside
// SDN is not feasible.
//
// Test parameters:
//   - EVETEST_AZURE_ACCOUNT_NAME, EVETEST_AZURE_ACCOUNT_KEY,
//     EVETEST_AZURE_CONTAINER, EVETEST_AZURE_BLOB_PATH,
//     EVETEST_AZURE_SHA256.
//
// Variants:
//   - Happy path.
//   - Wrong account key -> ERROR.
//   - Missing blob -> ERROR.
//
// Network model: SingleEthWithDHCP + RequireInternetConnectivity{}.
func TestAzureDatastore(test *testing.T) {
	test.Skip("not yet implemented")
}

// TestContainerRegistry validates that EVE can pull a container image from a
// public registry (Docker Hub by default).
//
// Recommended image: a small, fixed-tag image already used by other evetest
// tests, e.g. lfedge/evetest-ubuntu-ctr:1.0 or an even smaller test
// image (busybox). Keep the tag pinned to avoid reproducibility regressions
// when the registry mutates :latest.
//
// Variants:
//   - Happy path: deploy a tiny container app, confirm content-tree reaches
//     LOADED and app reaches RUNNING. Verify that the configured registry
//     mirror (EVETEST_REGISTRY_MIRROR_DOCKER) is honored — when the mirror is
//     set, the actual upstream Docker Hub should not be contacted (see the
//     mirror plumbing in devconfig.go DockerContainer.toProto).
//   - Wrong tag -> content tree ERROR.
//   - Wrong (or missing) credentials when pulling a private image: the test
//     can be parameterized with EVETEST_DOCKER_PRIVATE_* to additionally
//     cover this.
//
// Network model: SingleEthWithDHCP + RequireInternetConnectivity{}.
func TestContainerRegistry(test *testing.T) {
	test.Skip("not yet implemented")
}
