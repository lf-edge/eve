// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/evetest/broker/provider"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/sirupsen/logrus"
)

const testInstallerSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeStrategyProvider is a DeviceProvider that only answers
// DiskImageStrategy, the one provider call BuildImage makes. Any other call
// panics on the nil embedded interface, which fails the test loudly.
type fakeStrategyProvider struct {
	provider.DeviceProvider
	strategy provider.DiskImageStrategy
}

func (p fakeStrategyProvider) DiskImageStrategy() provider.DiskImageStrategy {
	return p.strategy
}

func testImageRef() *api.ImageRef {
	return &api.ImageRef{
		Repo:       "lfedge/eve",
		Version:    "0.0.0-test",
		Hypervisor: api.HypervisorType_HV_KVM,
		Arch:       api.ArchType_ARCH_AMD64,
	}
}

func rawInstallerRequest() *api.BuildImageRequest {
	return &api.BuildImageRequest{
		ClientId:       "client1",
		DeviceName:     "dev1",
		Image:          testImageRef(),
		MakeInstaller:  true,
		InstallerMedia: api.InstallerMedia_INSTALLER_MEDIA_RAW,
		DiskBytes:      64 << 20,
		LocalInstallerImage: &api.LocalInstallerImageRef{
			Sha256: testInstallerSHA256,
		},
	}
}

// asNetInstaller turns a request into the shape a NET installer takes: the
// network_boot flag instead of make_installer.
func asNetInstaller(r *api.BuildImageRequest) {
	r.InstallerMedia = api.InstallerMedia_INSTALLER_MEDIA_NET
	r.MakeInstaller = false
	r.NetworkBoot = true
}

// TestParseLocalImageRequest covers what a broker accepts as a local image
// request. Each refusal is final: building the device from the EVE container
// instead would test a different EVE than the one the client reports on.
func TestParseLocalImageRequest(t *testing.T) {
	overlay := provider.DiskImageOverlay
	cases := []struct {
		name     string
		strategy provider.DiskImageStrategy
		mutate   func(*api.BuildImageRequest)
		wantErr  string // empty: accepted
		// notWant must not appear in the error: a hint that would not help.
		notWant string
	}{
		{name: "raw installer is accepted", strategy: overlay,
			mutate: func(*api.BuildImageRequest) {}},
		{name: "raw installer on a standalone provider is accepted",
			strategy: provider.DiskImageStandalone, mutate: func(*api.BuildImageRequest) {}},
		{name: "ISO is not supported yet", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.InstallerMedia = api.InstallerMedia_INSTALLER_MEDIA_ISO
			},
			wantErr: "broker does not support local ISO installer images",
			// The container path cannot build an ISO either.
			notWant: "EVETEST_EVE_LIVE_IMAGE"},
		{name: "NET is not supported yet", strategy: overlay, mutate: asNetInstaller,
			wantErr: "broker does not support local NET installer images (it is not " +
				"implemented yet); unset EVETEST_EVE_LIVE_IMAGE"},
		{name: "an unspecified medium is refused", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.InstallerMedia = api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED
			},
			wantErr: "without installer_media"},
		{name: "an unknown medium is refused", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.InstallerMedia = api.InstallerMedia(42)
			},
			wantErr: "unknown installer medium"},
		{name: "a legacy-build provider cannot consume one",
			strategy: provider.DiskImageLegacyBuild, mutate: func(*api.BuildImageRequest) {},
			wantErr: "per-device container build path"},
		{name: "a raw installer needs make_installer", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.MakeInstaller = false
			},
			wantErr: "needs make_installer"},
		{name: "a raw installer cannot be network-booted", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.NetworkBoot = true
			},
			wantErr: "no network_boot"},
		{name: "a NET installer needs network_boot", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				asNetInstaller(r)
				r.MakeInstaller = true
			},
			wantErr: "needs network_boot"},
		{name: "a malformed hash is refused", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.LocalInstallerImage.Sha256 = "nothex"
			},
			wantErr: "invalid live image sha256"},
		{name: "live and installer images together are refused", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.LiveImage = &api.LiveImageRef{Sha256: testInstallerSHA256}
			},
			wantErr: "both a local live image and a local installer image"},
		{name: "a source without an image is refused", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.LocalInstallerImage = nil
				r.LocalInstallerSource = &api.LocalInstallerImageSource{
					ImagePath: "/dist/installer.evetest.qcow2"}
			},
			wantErr: "local installer source without a local installer image"},
		{name: "an ISO from the container image is refused", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.LocalInstallerImage = nil
				r.InstallerMedia = api.InstallerMedia_INSTALLER_MEDIA_ISO
			},
			wantErr: "cannot be built from the EVE container image yet"},
		// The combination an older harness sends for an installer device with the
		// live transport on: still refused, as before.
		{name: "a live image with make_installer is refused", strategy: overlay,
			mutate: func(r *api.BuildImageRequest) {
				r.LocalInstallerImage = nil
				r.InstallerMedia = api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED
				r.LiveImage = &api.LiveImageRef{Sha256: testInstallerSHA256}
			},
			wantErr: "which a local live image cannot provide"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := rawInstallerRequest()
			c.mutate(req)
			got, err := parseLocalImageRequest(
				req, c.strategy, fakeStrategyProvider{strategy: c.strategy})
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got == nil || !got.installer || got.sha256 != testInstallerSHA256 ||
					got.media != api.InstallerMedia_INSTALLER_MEDIA_RAW {
					t.Fatalf("parsed request = %+v, want a raw installer", got)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q, got %+v", c.wantErr, got)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not contain %q", err, c.wantErr)
			}
			if c.notWant != "" && strings.Contains(err.Error(), c.notWant) {
				t.Fatalf("error %q should not mention %q", err, c.notWant)
			}
		})
	}
}

// TestParseLocalImageRequestPassesThrough covers the two requests that are not
// local installer requests: one from the EVE container (nil) and one for a
// local live image, which must parse exactly as before.
func TestParseLocalImageRequestPassesThrough(t *testing.T) {
	prov := fakeStrategyProvider{strategy: provider.DiskImageOverlay}
	containers := map[string]*api.BuildImageRequest{
		"live": {DeviceName: "dev1", Image: testImageRef()},
		"raw installer, medium implied": {
			DeviceName: "dev1", Image: testImageRef(), MakeInstaller: true},
		"raw installer, medium named": {
			DeviceName: "dev1", Image: testImageRef(), MakeInstaller: true,
			InstallerMedia: api.InstallerMedia_INSTALLER_MEDIA_RAW},
		"network boot, medium named": {
			DeviceName: "dev1", Image: testImageRef(), NetworkBoot: true,
			InstallerMedia: api.InstallerMedia_INSTALLER_MEDIA_NET},
	}
	for name, container := range containers {
		if got, err := parseLocalImageRequest(container, provider.DiskImageOverlay, prov); err != nil || got != nil {
			t.Fatalf("container request (%s) parsed as (%+v, %v), want (nil, nil)",
				name, got, err)
		}
	}

	src := &api.LocalLiveImageSource{DiskPath: "/dist/live.qcow2"}
	live := &api.BuildImageRequest{
		DeviceName:      "dev1",
		Image:           testImageRef(),
		LiveImage:       &api.LiveImageRef{Sha256: testInstallerSHA256},
		LiveImageSource: src,
	}
	got, err := parseLocalImageRequest(live, provider.DiskImageOverlay, prov)
	if err != nil {
		t.Fatalf("live request: %v", err)
	}
	if got.installer || got.media != api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED ||
		got.source != src {
		t.Fatalf("live request parsed as %+v", got)
	}
}

// TestParseLocalImageRequestMapsSource covers the translation of an installer
// source into the live source shape the template readers take, and that a size
// no file can have makes the source unusable rather than an error.
func TestParseLocalImageRequestMapsSource(t *testing.T) {
	prov := fakeStrategyProvider{strategy: provider.DiskImageOverlay}
	req := rawInstallerRequest()
	req.LocalInstallerSource = &api.LocalInstallerImageSource{
		ImagePath:     "/dist/amd64/v/installer.evetest.qcow2",
		ImageBytes:    1234,
		ConfigImgPath: "/dist/amd64/v/installer/config.img",
		FirmwareDir:   "/dist/amd64/v/installer/firmware",
	}
	got, err := parseLocalImageRequest(req, provider.DiskImageOverlay, prov)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := &api.LocalLiveImageSource{
		DiskPath:      "/dist/amd64/v/installer.evetest.qcow2",
		DiskBytes:     1234,
		ConfigImgPath: "/dist/amd64/v/installer/config.img",
		FirmwareDir:   "/dist/amd64/v/installer/firmware",
	}
	if got.source.GetDiskPath() != want.DiskPath || got.source.GetDiskBytes() != want.DiskBytes ||
		got.source.GetConfigImgPath() != want.ConfigImgPath ||
		got.source.GetFirmwareDir() != want.FirmwareDir {
		t.Fatalf("source = %+v, want %+v", got.source, want)
	}

	req.LocalInstallerSource.ImageBytes = -1
	got, err = parseLocalImageRequest(req, provider.DiskImageOverlay, prov)
	if err != nil {
		t.Fatalf("parse with a negative size: %v", err)
	}
	if got.source != nil {
		t.Fatalf("a negative size must leave no usable source, got %+v", got.source)
	}
}

// newTestBroker returns a broker with one client session, enough for
// BuildImage. A legacy-build provider is never consulted beyond its strategy
// on the paths tested here.
func newTestBroker(t *testing.T, strategy provider.DiskImageStrategy) *broker {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	dir := t.TempDir()
	return &broker{
		globalLog:      logger,
		provider:       fakeStrategyProvider{strategy: strategy},
		imageDir:       dir,
		supportedArchs: []api.ArchType{api.ArchType_ARCH_AMD64},
		templates:      newTemplateCache(dir, logger),
		sessions: map[string]*session{
			"client1": {clientID: "client1", log: logrus.NewEntry(logger)},
		},
	}
}

// TestBuildImageRefusesUnsupportedInstallerMedia is the broker half of the
// capability gate: a client that sends a medium anyway gets a clear error,
// never a device built from the EVE container image.
func TestBuildImageRefusesUnsupportedInstallerMedia(t *testing.T) {
	for _, media := range []api.InstallerMedia{
		api.InstallerMedia_INSTALLER_MEDIA_ISO, api.InstallerMedia_INSTALLER_MEDIA_NET,
	} {
		t.Run(media.String(), func(t *testing.T) {
			b := newTestBroker(t, provider.DiskImageOverlay)
			req := rawInstallerRequest()
			req.InstallerMedia = media
			if media == api.InstallerMedia_INSTALLER_MEDIA_NET {
				asNetInstaller(req)
			}
			resp, err := b.BuildImage(context.Background(), req)
			if err == nil {
				t.Fatalf("BuildImage accepted %v media: %+v", media, resp)
			}
			if !strings.Contains(err.Error(), "broker does not support local") {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(b.sessions["client1"].eveDevices) != 0 {
				t.Fatal("a refused request must not register a device")
			}
		})
	}
}

// writeFakeRawInstaller writes the files the harness hands a broker for a raw
// installer: a qcow2 disk with a GPT CONFIG partition, a FAT config.img and a
// firmware directory. It returns the source and the disk's sha256.
func writeFakeRawInstaller(t *testing.T, dir string) (*api.LocalInstallerImageSource, string) {
	t.Helper()
	const cfgFirstLBA = 2048           // 1 MiB
	const cfgSectors = (5 << 20) / 512 // the 5 MiB CONFIG partition
	head := buildTestGPT(t, []struct {
		Name     string
		FirstLBA uint64
		LastLBA  uint64
	}{{Name: gptConfigPartName, FirstLBA: cfgFirstLBA, LastLBA: cfgFirstLBA + cfgSectors - 1}})
	raw := make([]byte, 8<<20)
	copy(raw, head)
	disk := qcow2FromRaw(t, raw)
	diskPath := filepath.Join(dir, "installer.evetest.qcow2")
	if err := os.WriteFile(diskPath, disk, 0o600); err != nil {
		t.Fatalf("write disk: %v", err)
	}

	cfgPath := filepath.Join(dir, "config.img")
	if err := os.Truncate(createEmpty(t, cfgPath), 5<<20); err != nil {
		t.Fatalf("size config.img: %v", err)
	}
	cmd := exec.Command("mformat", "-i", cfgPath, "-v", "CONFIG", "::")
	cmd.Env = append(os.Environ(), "MTOOLS_SKIP_CHECK=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("mformat is not available to build a FAT config.img: %v: %s", err, out)
	}

	fwDir := filepath.Join(dir, "firmware")
	if err := os.MkdirAll(fwDir, 0o755); err != nil {
		t.Fatalf("mkdir firmware: %v", err)
	}
	for _, f := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		if err := os.WriteFile(filepath.Join(fwDir, f), []byte("fw"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	return &api.LocalInstallerImageSource{
		ImagePath:     diskPath,
		ImageBytes:    int64(len(disk)),
		ConfigImgPath: cfgPath,
		FirmwareDir:   fwDir,
	}, liveTarDiskSHA256(map[string][]byte{templateDiskFile: disk})
}

func createEmpty(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	f.Close()
	return path
}

// requireDiskTools skips a test that drives BuildImage through the template
// path, which shells out to qemu-img, qemu-io and mtools.
func requireDiskTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"qemu-img", "qemu-io", "mcopy", "mformat", "mtype"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available: %v", tool, err)
		}
	}
}

// fakeInstallerVirtualBytes is the virtual size of writeFakeRawInstaller's disk.
const fakeInstallerVirtualBytes = 8 << 20

// virtualSize reads a qcow2's virtual size the way a provider would see it.
func virtualSize(t *testing.T, path string) int64 {
	t.Helper()
	out, err := exec.Command("qemu-img", "info", "--output=json", path).CombinedOutput()
	if err != nil {
		t.Fatalf("qemu-img info %s: %v: %s", path, err, out)
	}
	var info struct {
		VirtualSize int64 `json:"virtual-size"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		t.Fatalf("parse qemu-img info of %s: %v", path, err)
	}
	return info.VirtualSize
}

// TestBuildImageLocalInstallerRaw drives BuildImage end to end for a raw
// installer: the miss, the install from the client's files, the device's
// installer-first disk layout with the device's config in the installer's
// CONFIG partition, and a second device served from the cached template even
// though the client's files are no longer readable -- the cache hit that
// depends on the miss check and the build using the same template key.
//
// The requested disk size is deliberately below the installer's own: the
// installer is never resized (it is not the device's disk, and shrinking it
// would fail), while the target disk is created at exactly the requested size.
func TestBuildImageLocalInstallerRaw(t *testing.T) {
	requireDiskTools(t)
	ctx := context.Background()
	b := newTestBroker(t, provider.DiskImageOverlay)
	src, sha := writeFakeRawInstaller(t, t.TempDir())
	const diskBytes = 4 << 20
	if diskBytes >= fakeInstallerVirtualBytes {
		t.Fatal("test bug: the requested size must be below the installer's")
	}

	// No source, nothing staged, no template: the broker asks for the upload.
	req := rawInstallerRequest()
	req.DiskBytes = diskBytes
	req.LocalInstallerImage.Sha256 = sha
	resp, err := b.BuildImage(ctx, req)
	if err != nil {
		t.Fatalf("BuildImage without a source: %v", err)
	}
	if !resp.GetMissingEveLiveImage() {
		t.Fatalf("BuildImage without a source = %+v, want missing_eve_live_image", resp)
	}

	// With a readable source the template is installed in place.
	req.LocalInstallerSource = src
	resp, err = b.BuildImage(ctx, req)
	if err != nil {
		t.Fatalf("BuildImage with a source: %v", err)
	}
	if resp.GetMissingEveLiveImage() {
		t.Fatal("BuildImage reported the image missing despite a readable source")
	}
	dev := b.sessions["client1"].eveDevices["dev1"]
	if dev == nil || dev.installerImage == nil {
		t.Fatalf("device registered without an installer image: %+v", dev)
	}
	if dev.installerImage.Media != provider.DiskImageMediaDisk {
		t.Errorf("raw installer Media = %v, want %v",
			dev.installerImage.Media, provider.DiskImageMediaDisk)
	}
	if len(dev.Disks) != 2 || dev.Disks[0] != *dev.installerImage ||
		filepath.Base(dev.Disks[1].Path) != "installed.qcow2" {
		t.Fatalf("first-boot disks = %+v, want the installer then installed.qcow2", dev.Disks)
	}
	if len(dev.disks) != 1 || dev.disks[0] != dev.Disks[1] {
		t.Fatalf("post-install disks = %+v, want only the target disk", dev.disks)
	}
	if got := virtualSize(t, dev.installerImage.Path); got != fakeInstallerVirtualBytes {
		t.Errorf("installer overlay virtual size = %d, want the template's %d: "+
			"the installer must never be resized", got, fakeInstallerVirtualBytes)
	}
	if got := virtualSize(t, dev.disks[0].Path); got != diskBytes {
		t.Errorf("target disk virtual size = %d, want the requested %d", got, diskBytes)
	}
	wantKey := computeTemplateKey(
		localTemplateKeyParams(sha, api.ArchType_ARCH_AMD64, 0, true))
	if dev.templateKey != wantKey {
		t.Errorf("templateKey = %q, want the installer key %q", dev.templateKey, wantKey)
	}
	meta, err := loadTemplateMeta(b.templates.templateDir(wantKey))
	if err != nil {
		t.Fatalf("load template meta: %v", err)
	}
	if !meta.Installer || meta.LiveImageSHA256 != sha {
		t.Errorf("template meta = %+v, want an installer template of %s", meta, sha)
	}
	assertSoftSerialInjected(t, dev.installerImage.Path)

	// A second device, with the client's files gone and nothing staged: only a
	// cache hit under the same key can serve it.
	if err := os.Remove(src.GetImagePath()); err != nil {
		t.Fatalf("remove source disk: %v", err)
	}
	req2 := rawInstallerRequest()
	req2.DeviceName = "dev2"
	req2.DiskBytes = diskBytes
	req2.LocalInstallerImage.Sha256 = sha
	req2.LocalInstallerSource = src
	resp, err = b.BuildImage(ctx, req2)
	if err != nil {
		t.Fatalf("BuildImage for the second device: %v", err)
	}
	if resp.GetMissingEveLiveImage() {
		t.Fatal("the second device missed the cache: the miss check and the " +
			"build disagree on the installer template key")
	}
	if got := b.sessions["client1"].eveDevices["dev2"].templateKey; got != wantKey {
		t.Errorf("second device templateKey = %q, want %q", got, wantKey)
	}
}

// rawInstallerUploadTar packs a raw installer's files the way the harness
// streams them to PushEVELiveImage: disk.qcow2, config.img and firmware/*.
func rawInstallerUploadTar(t *testing.T, src *api.LocalInstallerImageSource) []byte {
	t.Helper()
	read := func(path string) []byte {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return data
	}
	members := map[string][]byte{
		templateDiskFile:      read(src.GetImagePath()),
		templateConfigImgFile: read(src.GetConfigImgPath()),
	}
	for _, f := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		members[templateFirmwareDir+"/"+f] = read(filepath.Join(src.GetFirmwareDir(), f))
	}
	tarPath := filepath.Join(t.TempDir(), "upload.tar")
	writeLiveTar(t, tarPath, members)
	return read(tarPath)
}

// TestBuildImageLocalInstallerRawUpload drives the remote-broker sequence for
// a raw installer: the broker cannot read the client's files, so the client
// uploads them with PushEVELiveImage -- which stages by content hash alone --
// and retries BuildImage with no source. The staged tar must be installed as
// an installer template, and removed once consumed.
func TestBuildImageLocalInstallerRawUpload(t *testing.T) {
	requireDiskTools(t)
	ctx := context.Background()
	b := newTestBroker(t, provider.DiskImageOverlay)
	src, sha := writeFakeRawInstaller(t, t.TempDir())
	tarBytes := rawInstallerUploadTar(t, src)

	req := rawInstallerRequest()
	req.LocalInstallerImage.Sha256 = sha
	resp, err := b.BuildImage(ctx, req)
	if err != nil {
		t.Fatalf("BuildImage before the upload: %v", err)
	}
	if !resp.GetMissingEveLiveImage() {
		t.Fatalf("BuildImage before the upload = %+v, want missing_eve_live_image", resp)
	}

	// The upload, in chunks as the harness sends it.
	msgs := []*api.PushLiveImageChunk{{Payload: &api.PushLiveImageChunk_Request{
		Request: &api.PushLiveImageRequest{
			ClientId:  "client1",
			LiveImage: &api.LiveImageRef{Sha256: sha},
		}}}}
	const chunk = 1 << 20
	for off := 0; off < len(tarBytes); off += chunk {
		end := min(off+chunk, len(tarBytes))
		msgs = append(msgs, &api.PushLiveImageChunk{
			Payload: &api.PushLiveImageChunk_DataChunk{DataChunk: tarBytes[off:end]}})
	}
	stream := &fakeLiveImageStream{msgs: msgs}
	if err := b.PushEVELiveImage(stream); err != nil {
		t.Fatalf("PushEVELiveImage: %v", err)
	}
	if stream.resp == nil || stream.resp.GetAlreadyExists() {
		t.Fatalf("PushEVELiveImage response = %+v, want a fresh upload", stream.resp)
	}
	tarPath := liveUploadPath(b.imageDir, sha)
	if _, err := os.Stat(tarPath); err != nil {
		t.Fatalf("upload was not staged at %s: %v", tarPath, err)
	}

	// The retry, with no source: only the staged upload can serve it.
	resp, err = b.BuildImage(ctx, req)
	if err != nil {
		t.Fatalf("BuildImage after the upload: %v", err)
	}
	if resp.GetMissingEveLiveImage() {
		t.Fatal("BuildImage after the upload still reports the image missing")
	}
	dev := b.sessions["client1"].eveDevices["dev1"]
	if dev == nil || dev.installerImage == nil {
		t.Fatalf("device registered without an installer image: %+v", dev)
	}
	meta, err := loadTemplateMeta(b.templates.templateDir(dev.templateKey))
	if err != nil {
		t.Fatalf("load template meta: %v", err)
	}
	if !meta.Installer || meta.LiveImageSHA256 != sha {
		t.Errorf("template meta = %+v, want an installer template of %s", meta, sha)
	}
	if _, err := os.Stat(tarPath); !os.IsNotExist(err) {
		t.Errorf("the consumed upload %s is still staged (stat: %v)", tarPath, err)
	}
	assertSoftSerialInjected(t, dev.installerImage.Path)
}

// assertSoftSerialInjected checks that a device's config reached the CONFIG
// partition of its installer disk, where the installer copies it from: the
// soft serial BuildImage generates is the one file always present.
func assertSoftSerialInjected(t *testing.T, diskPath string) {
	t.Helper()
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "disk.raw")
	if out, err := exec.Command("qemu-img", "convert", "-f", "qcow2", "-O", "raw",
		diskPath, rawPath).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img convert: %v: %s", err, out)
	}
	raw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatalf("read raw disk: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.img")
	if err := os.WriteFile(cfgPath, raw[1<<20:6<<20], 0o600); err != nil {
		t.Fatalf("write extracted config partition: %v", err)
	}
	cmd := exec.Command("mtype", "-i", cfgPath, "::/soft_serial")
	cmd.Env = append(os.Environ(), "MTOOLS_SKIP_CHECK=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("no soft_serial in the installer's CONFIG partition: %v: %s", err, out)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		t.Fatal("soft_serial in the installer's CONFIG partition is empty")
	}
}
