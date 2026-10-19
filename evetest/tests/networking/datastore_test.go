// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Datastore tests verify that EVE can pull volume content from the various
// datastore backends supported by the EVE API (HTTP, HTTPS, AWS S3, SFTP,
// Azure Blob, container registries). They focus on the network/datastore
// plumbing (correct datastore URL construction, authentication, certificate
// handling, download progress reporting, error propagation) -- not on any
// application runtime.
//
// No application is needed. volumemgr fully creates a volume -- including
// the ContentTree download, verification, and (for archive formats) format
// conversion. So these tests are simpler than they might first appear: declare
// a standalone volume via EdgeDeviceConfig.AddVolume with the datastore under
// test as its Image, and watch it reach ZSwState_CREATED_VOLUME (or ZSwState_ERROR
// for negative variants) via device.WatchVolumeInfo. No NI, no app, no
// WaitUntilAppIsRunning.
//
// Reusable scenario shape
// -----------------------
//
// All these tests follow the same structure:
//
//  1. Setup a single-port mgmt device (netmodels.SingleEthWithDHCP). Add
//     RequireInternetConnectivity{} only for tests that talk to a real
//     external datastore (AWS/Azure); HTTP/HTTPS/SFTP/container-registry
//     against evetest's own built-in servers (see "Test images" below) need
//     no Internet access at all.
//  2. Build a device config with just the one DHCP network on eth0
//     (mgmt+app) -- no NI, no application.
//  3. devConfig.AddVolume(displayName, image, sizeBytes) with image set to
//     the datastore under test (HTTPStorage/SFTPStorage/DockerContainer/
//     AwsS3Bucket/AzureBlob -- see devconfig.go's ApplicationImageStorage
//     implementations). Watch it via device.WatchVolumeInfo(volUUID):
//     - Happy path: assert State reaches ZSwState_CREATED_VOLUME.
//     ZInfoVolume.ProgressPercentage can be asserted strictly monotonic
//     along the way if the test wants to catch a stalled download.
//     - Negative-path variants (wrong checksum, bad credentials, server
//     returns an error, untrusted cert, ...): assert State reaches
//     ZSwState_ERROR (or stays non-CREATED_VOLUME while VolumeErr becomes
//     non-empty) with a VolumeErr description matching what's expected
//     (matchers.SatisfyPredicate against info.GetVolumeErr().GetDescription()).
//  4. Cleanup: devConfig.DeleteVolume(volUUID); no application, no NI, to
//     tear down.
//
// Test images
// -----------
//
//   - For HTTP/HTTPS/SFTP: evetest already runs its own HTTP, HTTPS, and SFTP
//     servers on the same interface and directory (see GetImageServerIPv4/
//     GetImageServerPort/GetImageServerHTTPSPort/GetImageServerSFTPPort/
//     DefaultSFTPUsername/DefaultSFTPPassword/GetCACertPEM in harness.go/
//     sftpserver.go). Use CreateRandomImageFile (a file of random bytes plus
//     its SHA256, for exercising checksum verification), AddImageServerFile
//     (writes arbitrary bytes), or CreateBlankImageFile (a real
//     qcow2/qcow/vmdk/vhdx/raw disk image via qemu-img, for testing
//     format-conversion) to serve content, and HTTPStorage/SFTPStorage
//     pointing at it. This keeps HTTP/HTTPS/SFTP tests fully self-contained
//     and needs no external network access and no SDN changes.
//
//   - For AWS S3 / Azure Blob: parameterize via EVETEST_AWS_* / EVETEST_AZURE_*
//     environment variables (test parameters). Skip the test if the parameters
//     are not set, rather than failing -- these tests should be opt-in.
//
//   - For container registries: evetest runs its own embedded OCI registry
//     alongside the HTTP/HTTPS/SFTP servers (same interface, see
//     PushDockerImageToLocalRegistry in localregistry.go). A small, fixed-tag
//     image already used elsewhere (lfedge/evetest-ubuntu-ctr:1.0) is pulled
//     into the local Docker daemon if not already present, then republished
//     there -- so the test needs no real, externally reachable registry.

package networking_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestHTTPDatastore verifies that EVE can download and verify a standalone
// volume's content over plain HTTP, using evetest's own built-in HTTP image
// server -- no external network access, no SDN changes.
//
// As with TestSFTPDatastore, the content is a few MiB of random (non-blank)
// bytes rather than a blank disk image (see CreateRandomImageFile), so that
// ImageSHA256 verification is meaningful (a blank file's checksum can't
// distinguish "downloaded correctly" from "downloaded as all
// zeros/corrupted-but-still-blank").
//
// Phases
// ------
//  1. Set up a device with a single DHCP mgmt port. No application or
//     network instance is needed -- volumemgr creates standalone
//     (app-unreferenced) volumes on its own.
//  2. Generate a random-content file (CreateRandomImageFile). Declare a
//     standalone volume (AddVolume) downloading it over HTTP (HTTPStorage,
//     ImageSHA256 set to the file's checksum).
//  3. Wait for the volume to reach ZSwState_CREATED_VOLUME -- since
//     ImageSHA256 was set, this only happens if EVE's downloader verified
//     the content against it, i.e. proves the download was not corrupted.
//  4. Delete the volume and wait for it to be reported as ZSwState_INVALID
//     (fully removed).
//  5. Negative-path variants, each via expectDownloadError:
//     - Wrong ImageSHA256: VolumeErr contains "computed" and "configured"
//     (pillar's verifier reports the mismatching hashes in that form).
//     - Wrong ImageRelativePath (a file that was never written): the
//     built-in HTTP server returns 404, and VolumeErr contains
//     "bad response code" and "404" (the HTTP status is propagated
//     verbatim by the downloader).
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestHTTPDatastore(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("mgmt-network-ready")
	log := evetest.Logger()

	const contentSize = 4 * evetest.MiB
	imgFile, sha256Hex := evetest.CreateRandomImageFile(
		"http-datastore-test.bin", contentSize)

	volUUID := devConfig.AddVolume("http-datastore-test", evetest.HTTPStorage{
		ImageFormat:       eveconfig.Format_RAW,
		ImageRelativePath: imgFile,
		ImageSHA256:       sha256Hex,
		ServerAddress:     evetest.GetImageServerIPv4().String(),
		ServerPort:        evetest.GetImageServerPort(),
	}, contentSize)

	volUpdates, stopVolWatch := device.WatchVolumeInfo(volUUID)
	defer stopVolWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("http-volume-config-applied")

	timeout := 10 * time.Minute
	t.Eventually(volUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"volume is delivered over HTTP and passes SHA256 verification",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_CREATED_VOLUME
		}).StopIf(volumeHasError)))
	evetest.Checkpoint("http-volume-delivered")

	// Delete the volume and verify it is fully removed.
	devConfig.DeleteVolume(volUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(volUpdates, 5*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"volume is gone",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))

	// Variant: wrong ImageSHA256 must be detected, not silently accepted.
	log.Infof("Verifying a SHA256 mismatch is detected")
	expectDownloadError(t, device, devConfig,
		"http-datastore-bad-sha256", evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_RAW,
			ImageRelativePath: imgFile,
			ImageSHA256:       strings.Repeat("0", 64), // deliberately wrong
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerPort(),
		}, contentSize, "computed", "configured")

	// Variant: a path that was never written must be reported as missing.
	log.Infof("Verifying a nonexistent remote path is reported as missing")
	expectDownloadError(t, device, devConfig,
		"http-datastore-bad-path", evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_RAW,
			ImageRelativePath: "does-not-exist.bin",
			ImageSHA256:       sha256Hex,
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerPort(),
		}, contentSize, "bad response code", "404")
}

// TestHTTPSDatastore verifies that EVE can download and verify a standalone
// volume's content over HTTPS, exercising the certificate-trust plumbing.
// evetest runs a built-in HTTPS listener alongside its plain HTTP image
// server (same interface and directory), serving a certificate signed by
// the harness's own CA (see GetCACertPEM, GetImageServerHTTPSPort) -- no
// external network access, no SDN changes.
//
// Phases
// ------
//  1. Set up a device with a single DHCP mgmt port. No application or
//     network instance is needed -- volumemgr creates standalone
//     (app-unreferenced) volumes on its own.
//  2. Generate a random-content file (CreateRandomImageFile). Declare a
//     standalone volume (AddVolume) downloading it over HTTPS (HTTPStorage
//     with UseHTTPS: true and HTTPSTrustedCACertsPEM set to the harness's
//     own CA certificate, ImageSHA256 set to the file's checksum).
//  3. Wait for the volume to reach ZSwState_CREATED_VOLUME -- proves both
//     that the TLS certificate was trusted and that the download was not
//     corrupted.
//  4. Delete the volume and wait for it to be reported as ZSwState_INVALID
//     (fully removed).
//  5. Negative-path variant, via expectDownloadError: omitting
//     HTTPSTrustedCACertsPEM leaves EVE unable to validate the image
//     server's certificate; VolumeErr contains "certificate signed by
//     unknown authority" (Go's standard x509 verification error,
//     propagated verbatim).
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestHTTPSDatastore(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("mgmt-network-ready")
	log := evetest.Logger()

	const contentSize = 4 * evetest.MiB
	imgFile, sha256Hex := evetest.CreateRandomImageFile(
		"https-datastore-test.bin", contentSize)
	caCertPEM := string(evetest.GetCACertPEM())

	volUUID := devConfig.AddVolume("https-datastore-test", evetest.HTTPStorage{
		ImageFormat:            eveconfig.Format_RAW,
		ImageRelativePath:      imgFile,
		ImageSHA256:            sha256Hex,
		ServerAddress:          evetest.GetImageServerIPv4().String(),
		ServerPort:             evetest.GetImageServerHTTPSPort(),
		UseHTTPS:               true,
		HTTPSTrustedCACertsPEM: []string{caCertPEM},
	}, contentSize)

	volUpdates, stopVolWatch := device.WatchVolumeInfo(volUUID)
	defer stopVolWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("https-volume-config-applied")

	timeout := 10 * time.Minute
	t.Eventually(volUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"volume is delivered over HTTPS and passes SHA256 verification",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_CREATED_VOLUME
		}).StopIf(volumeHasError)))
	evetest.Checkpoint("https-volume-delivered")

	// Delete the volume and verify it is fully removed.
	devConfig.DeleteVolume(volUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(volUpdates, 5*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"volume is gone",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))

	// Variant: without the trusted CA, the certificate must be rejected.
	log.Infof("Verifying an untrusted server certificate is rejected")
	expectDownloadError(t, device, devConfig,
		"https-datastore-untrusted", evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_RAW,
			ImageRelativePath: imgFile,
			ImageSHA256:       sha256Hex,
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerHTTPSPort(),
			UseHTTPS:          true,
			// HTTPSTrustedCACertsPEM intentionally omitted.
		}, contentSize, "certificate signed by unknown authority")
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
//   - Happy path with valid credentials -> ZSwState_CREATED_VOLUME.
//   - Wrong secret access key -> ZSwState_ERROR; VolumeErr should mention
//     auth/403.
//   - Wrong key (object missing) -> ZSwState_ERROR; VolumeErr should mention
//     404 / NoSuchKey.
//
// Network model: SingleEthWithDHCP + RequireInternetConnectivity{}.
func TestAWSDatastore(test *testing.T) {
	test.Skip("not yet implemented")
}

// TestSFTPDatastore validates the SFTP datastore code path: EVE can download
// and verify a standalone volume's content over SFTP, using evetest's own
// built-in SFTP server (no external network access).
//
// The content is a few MiB of random (non-blank) bytes rather than a blank
// disk image: this makes ImageSHA256 verification meaningful (a blank file's
// checksum can't distinguish "downloaded correctly" from "downloaded as all
// zeros/corrupted-but-still-blank"), giving direct evidence that the
// downloaded content matches byte-for-byte, not just that some volume was
// created.
//
// Phases
// ------
//  1. Set up a device with a single DHCP mgmt port. No application or
//     network instance is needed -- volumemgr creates standalone
//     (app-unreferenced) volumes on its own.
//  2. Generate a random-content file (CreateRandomImageFile). Declare a
//     standalone volume (AddVolume) downloading it over SFTP (SFTPStorage,
//     evetest.DefaultSFTPUsername/Password, ImageSHA256 set to the file's
//     checksum).
//  3. Wait for the volume to reach ZSwState_CREATED_VOLUME -- since
//     ImageSHA256 was set, this only happens if EVE's downloader verified
//     the content against it, i.e. proves the download was not corrupted.
//  4. Delete the volume and wait for it to be reported as ZSwState_INVALID
//     (fully removed).
//  5. Negative-path variants, each via expectDownloadError (create a
//     standalone volume expected to fail, wait for a VolumeErr description
//     containing specific substrings, then delete it and wait for it to be
//     gone):
//     - Wrong ImageSHA256: VolumeErr contains "computed" and "configured"
//     (pillar's verifier reports the mismatching hashes in that form).
//     - Wrong Username/Password: VolumeErr contains
//     "ssh: unable to authenticate" (the SSH handshake failure is
//     propagated verbatim).
//     - Wrong ImageRelativePath (a file that was never written): VolumeErr
//     contains "file does not exist" (pkg/sftp's Open error for the
//     server's SSH_FX_NO_SUCH_FILE response, propagated verbatim).
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestSFTPDatastore(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("mgmt-network-ready")
	log := evetest.Logger()

	const contentSize = 4 * evetest.MiB
	imgFile, sha256Hex := evetest.CreateRandomImageFile(
		"sftp-datastore-test.bin", contentSize)

	volUUID := devConfig.AddVolume("sftp-datastore-test", evetest.SFTPStorage{
		ImageFormat:       eveconfig.Format_RAW,
		ImageRelativePath: imgFile,
		ImageSHA256:       sha256Hex,
		ServerAddress:     evetest.GetImageServerIPv4().String(),
		ServerPort:        evetest.GetImageServerSFTPPort(),
		Username:          evetest.DefaultSFTPUsername,
		Password:          evetest.DefaultSFTPPassword,
	}, contentSize)

	volUpdates, stopVolWatch := device.WatchVolumeInfo(volUUID)
	defer stopVolWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("sftp-volume-config-applied")

	timeout := 10 * time.Minute
	t.Eventually(volUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"volume is delivered over SFTP and passes SHA256 verification",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_CREATED_VOLUME
		}).StopIf(volumeHasError)))
	evetest.Checkpoint("sftp-volume-delivered")

	// Delete the volume and verify it is fully removed.
	devConfig.DeleteVolume(volUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(volUpdates, 5*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"volume is gone",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))

	// Variant: wrong ImageSHA256 must be detected, not silently accepted.
	log.Infof("Verifying a SHA256 mismatch is detected")
	expectDownloadError(t, device, devConfig,
		"sftp-datastore-bad-sha256", evetest.SFTPStorage{
			ImageFormat:       eveconfig.Format_RAW,
			ImageRelativePath: imgFile,
			ImageSHA256:       strings.Repeat("0", 64), // deliberately wrong
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerSFTPPort(),
			Username:          evetest.DefaultSFTPUsername,
			Password:          evetest.DefaultSFTPPassword,
		}, contentSize, "computed", "configured")

	// Variant: wrong credentials must be rejected.
	log.Infof("Verifying a wrong SFTP password is rejected")
	expectDownloadError(t, device, devConfig,
		"sftp-datastore-bad-password", evetest.SFTPStorage{
			ImageFormat:       eveconfig.Format_RAW,
			ImageRelativePath: imgFile,
			ImageSHA256:       sha256Hex,
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerSFTPPort(),
			Username:          evetest.DefaultSFTPUsername,
			Password:          "wrong-password",
		}, contentSize, "ssh: unable to authenticate")

	// Variant: a path that was never written must be reported as missing.
	log.Infof("Verifying a nonexistent remote path is reported as missing")
	expectDownloadError(t, device, devConfig,
		"sftp-datastore-bad-path", evetest.SFTPStorage{
			ImageFormat:       eveconfig.Format_RAW,
			ImageRelativePath: "does-not-exist.bin",
			ImageSHA256:       sha256Hex,
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerSFTPPort(),
			Username:          evetest.DefaultSFTPUsername,
			Password:          evetest.DefaultSFTPPassword,
		}, contentSize, "file does not exist")
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
//   - Wrong account key -> ZSwState_ERROR.
//   - Missing blob -> ZSwState_ERROR.
//
// Network model: SingleEthWithDHCP + RequireInternetConnectivity{}.
func TestAzureDatastore(test *testing.T) {
	test.Skip("not yet implemented")
}

// TestContainerRegistry verifies that EVE can pull a standalone volume's
// content from an OCI container registry.
//
// The registry is evetest's own, not a real external one: evetest pulls
// lfedge/evetest-ubuntu-ctr:1.0 into the local Docker daemon if not already
// present there (from a previous pull or build), then republishes it via
// PushDockerImageToLocalRegistry, and EVE pulls it back from evetest over
// that. This is what a "docker://" pull actually exercises end to end
// (image resolution, auth, layer/manifest download, verification) without
// depending on a real, externally reachable registry or Internet access.
//
// Unlike the HTTP/HTTPS/SFTP datastore tests, there is no ImageSHA256 check
// here: container images are content-addressed and verified against their
// own manifest/layer digests as part of the pull itself, so a corrupted
// download is already caught by that mechanism, independent of anything
// this test configures.
//
// Phases
// ------
//  1. Set up a device with a single DHCP mgmt port. No application or
//     network instance is needed -- volumemgr creates standalone
//     (app-unreferenced) volumes on its own.
//  2. Push lfedge/evetest-ubuntu-ctr:1.0 to evetest's local OCI registry
//     (PushDockerImageToLocalRegistry) -- a small, fixed-tag image already
//     used by other evetest tests (the pinned tag avoids reproducibility
//     regressions from a mutating :latest). Declare a standalone volume
//     (AddVolume) sourced from the returned DockerContainer.
//  3. Wait for the volume to reach ZSwState_CREATED_VOLUME.
//  4. Delete the volume and wait for it to be reported as ZSwState_INVALID
//     (fully removed).
//  5. Negative-path variant, via expectDownloadError: a nonexistent tag is
//     rejected; VolumeErr contains "MANIFEST_UNKNOWN" (the OCI distribution
//     spec's registry API error code for a missing manifest/reference,
//     propagated verbatim).
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestContainerRegistry(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("mgmt-network-ready")
	log := evetest.Logger()

	registryImage, err := evetest.PushDockerImageToLocalRegistry(
		"lfedge/evetest-ubuntu-ctr:1.0")
	if err != nil {
		test.Fatalf("Failed to publish test image to evetest's local OCI registry: %v", err)
	}
	volUUID := devConfig.AddVolume("container-registry-test", registryImage, 0)

	volUpdates, stopVolWatch := device.WatchVolumeInfo(volUUID)
	defer stopVolWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("registry-volume-config-applied")

	timeout := 10 * time.Minute
	t.Eventually(volUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"volume is delivered from the container registry",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_CREATED_VOLUME
		}).StopIf(volumeHasError)))
	evetest.Checkpoint("registry-volume-delivered")

	// Delete the volume and verify it is fully removed.
	devConfig.DeleteVolume(volUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(volUpdates, 5*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"volume is gone",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))

	// Variant: a nonexistent tag must be rejected. Reuses registryImage's
	// Domain/TrustedCACertsPEM (the repo itself exists there) with a tag that
	// was never pushed.
	log.Infof("Verifying a nonexistent image tag is reported as missing")
	badTagImage := registryImage
	badTagImage.Tag = "nonexistent-tag-does-not-exist"
	expectDownloadError(t, device, devConfig,
		"container-registry-bad-tag", badTagImage, 0, "MANIFEST_UNKNOWN")
}

// expectDownloadError declares a standalone volume expected to fail to
// download, waits for its VolumeErr description to contain every one of
// wantErrSubstrings, then deletes it and waits for it to be gone.
func expectDownloadError(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, displayName string,
	image evetest.ApplicationImageStorage, sizeBytes uint64,
	wantErrSubstrings ...string) {
	volUUID := devConfig.AddVolume(displayName, image, sizeBytes)
	updates, stop := device.WatchVolumeInfo(volUUID)
	defer stop()
	device.ApplyConfig(devConfig, false, false)

	timeout := 5 * time.Minute
	t.Eventually(updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		fmt.Sprintf("volume %s reports the expected error", displayName),
		func(info *eveinfo.ZInfoVolume) bool {
			desc := info.GetVolumeErr().GetDescription()
			if desc == "" {
				return false
			}
			for _, want := range wantErrSubstrings {
				if !strings.Contains(desc, want) {
					return false
				}
			}
			return true
		})))

	devConfig.DeleteVolume(volUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(updates, 5*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		fmt.Sprintf("volume %s is gone", displayName),
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
}

// volumeHasError reports whether info carries a VolumeErr, for use as a
// StopIf fast-fail condition on Eventually assertions waiting on volume state.
func volumeHasError(info *eveinfo.ZInfoVolume) (string, bool) {
	if desc := info.GetVolumeErr().GetDescription(); desc != "" {
		return "Volume reports an error: " + desc, true
	}
	return "", false
}
