// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/spf13/viper"
)

// fakeBuildImages are the deliverable images writeFakeBuild lays out by
// default, next to installer/: the live image and the installer on each of its
// media, each with distinct content.
var fakeBuildImages = map[string]string{
	"live.qcow2":    "qcow",
	"installer.raw": "raw installer",
	"installer.iso": "iso installer",
	"installer.net": "net installer",
}

// writeFakeBuild lays out a dist tree like `make live` and the `make
// installer-*` targets produce and returns the version directory it created.
func writeFakeBuild(t *testing.T, root, version string, cfgSize int) string {
	t.Helper()
	return writeFakeBuildWith(t, root, version, cfgSize, fakeBuildImages)
}

// writeFakeBuildWith is writeFakeBuild with only the given images, to model a
// build made with a single make target.
func writeFakeBuildWith(t *testing.T, root, version string, cfgSize int,
	images map[string]string) string {
	t.Helper()
	verDir := filepath.Join(root, "amd64", version)
	fw := filepath.Join(verDir, "installer", "firmware")
	if err := os.MkdirAll(fw, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, f := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		if err := os.WriteFile(filepath.Join(fw, f), []byte("x"), 0o600); err != nil {
			t.Fatalf("write firmware: %v", err)
		}
	}
	for name, content := range images {
		if err := os.WriteFile(filepath.Join(verDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write image %s: %v", name, err)
		}
	}
	cfg := filepath.Join(verDir, "installer", "config.img")
	if err := os.WriteFile(cfg, make([]byte, cfgSize), 0o600); err != nil {
		t.Fatalf("write config.img: %v", err)
	}
	link := filepath.Join(root, "amd64", "current")
	os.Remove(link)
	if err := os.Symlink(verDir, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	return verDir
}

// TestResolveLocalLiveImageTransportOff covers the transport switch: anything
// falsy (including unset) means the container transport, and no dist tree is
// consulted at all.
func TestResolveLocalLiveImageTransportOff(t *testing.T) {
	defer viper.Set(constants.EVELiveImageEnv, "")
	for _, setting := range []string{"", "false", "False", "FALSE", "0", "f", "F"} {
		t.Run("setting="+setting, func(t *testing.T) {
			viper.Set(constants.EVELiveImageEnv, setting)
			img, err := resolveLocalLiveImage("amd64", "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if img != nil {
				t.Fatalf("expected nil for the container transport, got %+v", img)
			}
		})
	}
}

// TestResolveLocalLiveImageRejectsNonBoolean covers the semantics this variable
// used to have: it carried a path, and a leftover path in someone's environment
// must say what to do instead of being silently treated as "on" or "off".
func TestResolveLocalLiveImageRejectsNonBoolean(t *testing.T) {
	viper.Set(constants.EVELiveImageEnv, "/home/dev/eve/dist/amd64/current/live.qcow2")
	defer viper.Set(constants.EVELiveImageEnv, "")

	_, err := resolveLocalLiveImage("amd64", "")
	if err == nil {
		t.Fatal("expected an error for a non-boolean value")
	}
	if !strings.Contains(err.Error(), constants.EVEVersionEnv) {
		t.Errorf("the error should point at %s as the way to pick a build, got: %v",
			constants.EVEVersionEnv, err)
	}
	if !LocalLiveImageRequested() {
		t.Error("an unparsable value must still count as requested, so the " +
			"caller surfaces the error instead of silently using containers")
	}
}

func TestResolveLocalLiveImageCurrent(t *testing.T) {
	root := t.TempDir()
	const version = "0.0.0-branch-abcd1234-k-amd64-v6.12.49-gcc"
	verDir := writeFakeBuild(t, root, version, 5<<20)

	img, err := resolveLocalLiveImageIn(root, "amd64", "", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if img.DiskPath != filepath.Join(verDir, "live.qcow2") {
		t.Errorf("DiskPath = %q", img.DiskPath)
	}
	if img.ConfigImgPath != filepath.Join(verDir, "installer", "config.img") {
		t.Errorf("ConfigImgPath = %q", img.ConfigImgPath)
	}
	if img.FirmwareDir != filepath.Join(verDir, "installer", "firmware") {
		t.Errorf("FirmwareDir = %q", img.FirmwareDir)
	}
	if img.Version != version {
		t.Errorf("Version = %q, want %q", img.Version, version)
	}
}

// TestResolveLocalLiveImageRequestedVersion covers the version axis: a version
// the operator asked for selects that build's directory, not the newest one.
func TestResolveLocalLiveImageRequestedVersion(t *testing.T) {
	root := t.TempDir()
	const wanted = "0.0.0-x-1111-k-amd64-v1-gcc"
	wantedDir := writeFakeBuild(t, root, wanted, 5<<20)
	// A newer build exists and owns the `current` symlink, so resolving the
	// requested version proves the symlink was not used.
	writeFakeBuild(t, root, "0.0.0-x-2222-k-amd64-v1-gcc", 5<<20)

	img, err := resolveLocalLiveImageIn(root, "amd64", wanted, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if img.DiskPath != filepath.Join(wantedDir, "live.qcow2") {
		t.Errorf("DiskPath = %q, want the requested version's image", img.DiskPath)
	}
	if img.Version != wanted {
		t.Errorf("Version = %q, want %q", img.Version, wanted)
	}
}

// TestResolveLocalLiveImageUnbuiltVersionFails is the rule that keeps the two
// axes honest: the operator asked for a version *and* for the live transport,
// and that version is not built here. Falling back to the container transport
// would run a different set of bits than the request describes, so this fails
// instead -- and the error has to name the version and the path it looked in.
func TestResolveLocalLiveImageUnbuiltVersionFails(t *testing.T) {
	root := t.TempDir()
	writeFakeBuild(t, root, "0.0.0-x-2222-k-amd64-v1-gcc", 5<<20)

	_, err := resolveLocalLiveImageIn(root, "amd64", "16.0.0-lts", "")
	if err == nil {
		t.Fatal("expected an error for a version that is not built locally")
	}
	for _, want := range []string{"16.0.0-lts", "make live",
		unbuiltVersionContainerHint, unbuiltVersionCurrentHint} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestResolveLocalLiveImageFirmwareOverride(t *testing.T) {
	root := t.TempDir()
	writeFakeBuild(t, root, "0.0.0-x-2222-k-amd64-v1-gcc", 5<<20)
	other := t.TempDir()
	for _, f := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		if err := os.WriteFile(filepath.Join(other, f), []byte("y"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	img, err := resolveLocalLiveImageIn(root, "amd64", "", other)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if img.FirmwareDir != other {
		t.Errorf("FirmwareDir = %q, want the override %q", img.FirmwareDir, other)
	}
}

func TestResolveLocalLiveImageRequiresDistDir(t *testing.T) {
	viper.Set(constants.EVELiveImageEnv, "true")
	viper.Set(constants.EVEDistDirEnv, "")
	defer func() {
		viper.Set(constants.EVELiveImageEnv, "")
		viper.Set(constants.EVEDistDirEnv, "")
	}()

	_, err := resolveLocalLiveImage("amd64", "")
	if err == nil {
		t.Fatal("expected an error when the live transport is on and EVE_DIST_DIR is unset")
	}
	if !strings.Contains(err.Error(), constants.EVEDistDirEnv) {
		t.Fatalf("expected the error to name %s, got: %v", constants.EVEDistDirEnv, err)
	}
}

func TestResolveLocalLiveImageMissingImage(t *testing.T) {
	_, err := resolveLocalLiveImageIn(t.TempDir(), "amd64", "", "")
	if err == nil {
		t.Fatal("expected an error when no local build exists")
	}
}

func TestResolveLocalLiveImageWrongConfigSize(t *testing.T) {
	root := t.TempDir()
	writeFakeBuild(t, root, "0.0.0-x-3333-k-amd64-v1-gcc", 1024)
	_, err := resolveLocalLiveImageIn(root, "amd64", "", "")
	if err == nil {
		t.Fatal("expected an error for a config.img that is not 5 MiB")
	}
}

// TestResolveLocalLiveImageUnversionedDir covers a `current` symlink pointing at
// a directory whose name is not version-shaped: the image is still usable, but
// nothing can be reported as its version.
func TestResolveLocalLiveImageUnversionedDir(t *testing.T) {
	root := t.TempDir()
	verDir := writeFakeBuild(t, root, "some-scratch-build", 5<<20)

	img, err := resolveLocalLiveImageIn(root, "amd64", "", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if img.DiskPath != filepath.Join(verDir, "live.qcow2") {
		t.Errorf("DiskPath = %q", img.DiskPath)
	}
	if img.Version != "" {
		t.Errorf("Version = %q, want empty for a non-version-shaped dir", img.Version)
	}
}

// TestUseLocalBuild covers which devices the local transport serves and with
// what: an explicitly requested EVE version always wins (it is the strongest
// signal a test can give about which build a device should boot), and
// otherwise the policy picks the live image or one of the installer media.
func TestUseLocalBuild(t *testing.T) {
	const (
		live = api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED
		raw  = api.InstallerMedia_INSTALLER_MEDIA_RAW
		iso  = api.InstallerMedia_INSTALLER_MEDIA_ISO
		net  = api.InstallerMedia_INSTALLER_MEDIA_NET
	)
	cases := []struct {
		name        string
		req         RequireEdgeDevice
		transportOn bool
		want        bool
		wantMedia   api.InstallerMedia
	}{
		{
			name:        "explicit version never uses the local build",
			req:         RequireEdgeDevice{WithEVEVersion: "16.0.0-lts"},
			transportOn: true,
			want:        false,
		},
		{
			name:        "explicit version wins over an installer policy too",
			req:         RequireEdgeDevice{WithEVEVersion: "16.0.0-lts", DeviceReusePolicy: CreateFromScratchWithInstaller},
			transportOn: true,
			want:        false,
		},
		{
			name:        "no explicit version uses the live image",
			req:         RequireEdgeDevice{},
			transportOn: true,
			want:        true,
			wantMedia:   live,
		},
		{
			name:        "the live image policy uses the live image",
			req:         RequireEdgeDevice{DeviceReusePolicy: CreateFromScratchWithLiveImage},
			transportOn: true,
			want:        true,
			wantMedia:   live,
		},
		{
			name:        "transport off, nothing local regardless of version",
			req:         RequireEdgeDevice{},
			transportOn: false,
			want:        false,
		},
		{
			name:        "transport off, an installer device takes the container path",
			req:         RequireEdgeDevice{DeviceReusePolicy: CreateFromScratchWithInstaller},
			transportOn: false,
			want:        false,
		},
		{
			name:        "the installer policy uses the raw installer",
			req:         RequireEdgeDevice{DeviceReusePolicy: CreateFromScratchWithInstaller},
			transportOn: true,
			want:        true,
			wantMedia:   raw,
		},
		{
			name:        "the installer ISO policy uses the ISO",
			req:         RequireEdgeDevice{DeviceReusePolicy: CreateFromScratchWithInstallerISO},
			transportOn: true,
			want:        true,
			wantMedia:   iso,
		},
		{
			// Formerly sent to the container path; now the local netboot bundle,
			// and gated on CAPABILITY_LOCAL_INSTALLER_NET like any other medium.
			name:        "a network-boot device uses the local netboot bundle",
			req:         RequireEdgeDevice{DeviceReusePolicy: CreateFromScratchWithNetworkBoot},
			transportOn: true,
			want:        true,
			wantMedia:   net,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, media := useLocalBuild(c.req, c.transportOn)
			if got != c.want || (got && media != c.wantMedia) {
				t.Errorf("useLocalBuild(%+v, %v) = (%v, %v), want (%v, %v)",
					c.req, c.transportOn, got, media, c.want, c.wantMedia)
			}
		})
	}
}

// TestCheckLocalImageCapability is the harness half of the capability gate: a
// medium the broker does not advertise fails with an error that names it,
// rather than being sent to a broker that might ignore it and build the device
// from the EVE container image.
func TestCheckLocalImageCapability(t *testing.T) {
	stepOneBroker := []api.Capability{
		api.Capability_CAPABILITY_TPM,
		api.Capability_CAPABILITY_LOCAL_LIVE_IMAGE,
		api.Capability_CAPABILITY_LOCAL_INSTALLER_RAW,
	}
	oldBroker := []api.Capability{api.Capability_CAPABILITY_LOCAL_LIVE_IMAGE}
	futureBroker := append(append([]api.Capability{}, stepOneBroker...),
		api.Capability_CAPABILITY_LOCAL_INSTALLER_ISO,
		api.Capability_CAPABILITY_LOCAL_INSTALLER_NET)

	cases := []struct {
		name    string
		caps    []api.Capability
		media   api.InstallerMedia
		wantErr string
	}{
		{"live on a live-capable broker", oldBroker,
			api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED, ""},
		{"live on a broker without the capability", nil,
			api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED,
			"does not support the live image transport"},
		{"raw on a raw-capable broker", stepOneBroker,
			api.InstallerMedia_INSTALLER_MEDIA_RAW, ""},
		{"raw on a broker predating installers", oldBroker,
			api.InstallerMedia_INSTALLER_MEDIA_RAW,
			"broker does not support local raw installer images"},
		{"ISO", stepOneBroker, api.InstallerMedia_INSTALLER_MEDIA_ISO,
			"this evetest harness does not deliver local ISO installer images yet " +
				"(nor does the broker advertise CAPABILITY_LOCAL_INSTALLER_ISO)"},
		{"NET", stepOneBroker, api.InstallerMedia_INSTALLER_MEDIA_NET,
			"this evetest harness does not deliver local NET installer images yet " +
				"(nor does the broker advertise CAPABILITY_LOCAL_INSTALLER_NET)"},
		// The harness half of the gate: a future broker advertising a medium this
		// harness does not deliver must not make it send one -- for NET it would
		// pair the local image with a netboot bundle built from the container.
		{"ISO on a broker advertising it", futureBroker,
			api.InstallerMedia_INSTALLER_MEDIA_ISO,
			"this evetest harness does not deliver local ISO installer images yet " +
				"(whatever the broker advertises)"},
		{"NET on a broker advertising it", futureBroker,
			api.InstallerMedia_INSTALLER_MEDIA_NET,
			"this evetest harness does not deliver local NET installer images yet " +
				"(whatever the broker advertises)"},
		{"raw on a broker advertising every medium", futureBroker,
			api.InstallerMedia_INSTALLER_MEDIA_RAW, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkLocalImageCapability(c.caps, c.media)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}

// TestHarnessLocalInstallerMedia pins what this harness delivers from a local
// build: the raw installer only. Extending the list is what turns a medium on
// in the harness, together with the code that actually delivers it.
func TestHarnessLocalInstallerMedia(t *testing.T) {
	want := []api.InstallerMedia{api.InstallerMedia_INSTALLER_MEDIA_RAW}
	if !slices.Equal(harnessLocalInstallerMedia, want) {
		t.Fatalf("harnessLocalInstallerMedia = %v, want %v", harnessLocalInstallerMedia, want)
	}
	for _, media := range harnessLocalInstallerMedia {
		if _, ok := installerArtifacts[media]; !ok {
			t.Errorf("medium %v is delivered but has no artifact", media)
		}
	}
}

// TestResolveLocalInstallerImage covers the resolver per medium: each finds its
// own artifact next to installer/, keeps collecting the config.img, firmware
// and version files every medium needs, and records the medium.
func TestResolveLocalInstallerImage(t *testing.T) {
	root := t.TempDir()
	const version = "0.0.0-branch-abcd1234-kvm-amd64-v6.12.49-gcc"
	verDir := writeFakeBuild(t, root, version, 5<<20)
	if err := os.WriteFile(filepath.Join(verDir, "installer", "eve_version"),
		[]byte("0.0.0-branch-abcd1234-kvm-amd64\n"), 0o600); err != nil {
		t.Fatalf("write eve_version: %v", err)
	}

	for media, file := range map[api.InstallerMedia]string{
		api.InstallerMedia_INSTALLER_MEDIA_RAW: "installer.raw",
		api.InstallerMedia_INSTALLER_MEDIA_ISO: "installer.iso",
		api.InstallerMedia_INSTALLER_MEDIA_NET: "installer.net",
	} {
		t.Run(media.String(), func(t *testing.T) {
			img, err := resolveLocalInstallerImageIn(root, "amd64", "", "", media)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if img.Media != media {
				t.Errorf("Media = %v, want %v", img.Media, media)
			}
			if img.DiskPath != filepath.Join(verDir, file) {
				t.Errorf("DiskPath = %q, want the %s next to installer/", img.DiskPath, file)
			}
			if img.DiskBytes != int64(len(fakeBuildImages[file])) {
				t.Errorf("DiskBytes = %d, want %d", img.DiskBytes, len(fakeBuildImages[file]))
			}
			if img.ConfigImgPath != filepath.Join(verDir, "installer", "config.img") ||
				img.FirmwareDir != filepath.Join(verDir, "installer", "firmware") {
				t.Errorf("ConfigImgPath = %q, FirmwareDir = %q", img.ConfigImgPath, img.FirmwareDir)
			}
			if img.Version != version || img.ShortVersion != "0.0.0-branch-abcd1234-kvm-amd64" {
				t.Errorf("Version = %q, ShortVersion = %q", img.Version, img.ShortVersion)
			}
		})
	}
}

// TestResolveLocalInstallerImageWithoutLiveImage covers a build made with only
// `make installer-raw`: it has no live.qcow2, which an installer device does
// not need, while a live device still reports what to build.
func TestResolveLocalInstallerImageWithoutLiveImage(t *testing.T) {
	root := t.TempDir()
	writeFakeBuildWith(t, root, "0.0.0-x-1111-kvm-amd64-v1-gcc", 5<<20,
		map[string]string{"installer.raw": "raw installer"})

	if _, err := resolveLocalInstallerImageIn(root, "amd64", "", "",
		api.InstallerMedia_INSTALLER_MEDIA_RAW); err != nil {
		t.Fatalf("a raw installer build must resolve without live.qcow2: %v", err)
	}
	_, err := resolveLocalLiveImageIn(root, "amd64", "", "")
	if err == nil || !strings.Contains(err.Error(), "make live") {
		t.Fatalf("live resolve error = %v, want one pointing at `make live`", err)
	}
	_, err = resolveLocalInstallerImageIn(root, "amd64", "", "",
		api.InstallerMedia_INSTALLER_MEDIA_ISO)
	if err == nil || !strings.Contains(err.Error(), "make installer-iso") {
		t.Fatalf("ISO resolve error = %v, want one pointing at `make installer-iso`", err)
	}
}

// TestResolveLocalInstallerImageUnbuiltVersionFails is the version rule for
// installers: a requested version that is not built locally fails, naming the
// artifact and the target that builds it, rather than running something else.
func TestResolveLocalInstallerImageUnbuiltVersionFails(t *testing.T) {
	root := t.TempDir()
	writeFakeBuild(t, root, "0.0.0-x-2222-kvm-amd64-v1-gcc", 5<<20)

	_, err := resolveLocalInstallerImageIn(root, "amd64", "16.0.0-lts", "",
		api.InstallerMedia_INSTALLER_MEDIA_RAW)
	if err == nil {
		t.Fatal("expected an error for a version that is not built locally")
	}
	for _, want := range []string{"16.0.0-lts", "installer.raw", "make installer-raw",
		unbuiltVersionContainerHint, unbuiltVersionCurrentHint} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// The two ways out of a requested version that is not built locally, each
// tied to the setting that produces it: dropping the transport runs that
// version from a container image, dropping the version runs the newest local
// build.
const (
	unbuiltVersionContainerHint = "unset " + constants.EnvPrefix + constants.EVELiveImageEnv +
		" to run that version from a container image"
	unbuiltVersionCurrentHint = "unset " + constants.EnvPrefix + constants.EVEVersionEnv +
		" to use whatever is in current"
)

func TestResolveLocalInstallerImageWrongConfigSize(t *testing.T) {
	root := t.TempDir()
	writeFakeBuild(t, root, "0.0.0-x-3333-kvm-amd64-v1-gcc", 1024)
	_, err := resolveLocalInstallerImageIn(root, "amd64", "", "",
		api.InstallerMedia_INSTALLER_MEDIA_RAW)
	if err == nil {
		t.Fatal("expected an error for a config.img that is not 5 MiB")
	}
}

func TestInstallerMediaForPolicy(t *testing.T) {
	cases := map[ExistingEdgeDeviceReusePolicy]api.InstallerMedia{
		CreateFromScratchWithInstaller:    api.InstallerMedia_INSTALLER_MEDIA_RAW,
		CreateFromScratchWithInstallerISO: api.InstallerMedia_INSTALLER_MEDIA_ISO,
		CreateFromScratchWithNetworkBoot:  api.InstallerMedia_INSTALLER_MEDIA_NET,
		CreateFromScratchWithLiveImage:    api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED,
		UseAsIs:                           api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED,
		ReonboardEdgeDevice:               api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED,
	}
	for policy, want := range cases {
		if got := installerMediaForPolicy(policy); got != want {
			t.Errorf("installerMediaForPolicy(%d) = %v, want %v", policy, got, want)
		}
	}
}

func TestLocalImageSHA256IsStable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// sha256("hello")
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	got, err := localImageSHA256(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if got != want {
		t.Fatalf("sha256 = %q, want %q", got, want)
	}
	sidecar := f + ".sha256"
	if _, err := os.Stat(sidecar); err != nil {
		t.Fatalf("expected sidecar %q to be written: %v", sidecar, err)
	}
	again, err := localImageSHA256(f)
	if err != nil || again != want {
		t.Fatalf("cached read = %q, %v", again, err)
	}
}

// TestLocalImageSHA256UsesTheSidecar proves a cached hash is actually reused
// while the file is unchanged -- by planting a recognisably wrong one -- so the
// multi-gigabyte image is not read again on every run.
func TestLocalImageSHA256UsesTheSidecar(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := localImageSHA256(f); err != nil {
		t.Fatalf("hash: %v", err)
	}
	data, err := os.ReadFile(f + ".sha256")
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	fields := strings.Fields(string(data))
	planted := strings.Repeat("a", 64) + "  " + fields[1] + "  " + fields[2] + "\n"
	if err := os.WriteFile(f+".sha256", []byte(planted), 0o644); err != nil {
		t.Fatalf("plant sidecar: %v", err)
	}
	got, err := localImageSHA256(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if got != strings.Repeat("a", 64) {
		t.Fatalf("hash = %q: the sidecar of an unchanged file was not used", got)
	}
}

// TestLocalImageSHA256SidecarPerFile covers a build directory holding several
// deliverable images: each keeps its own cached hash, so hashing one never
// overwrites the other's -- which a single per-directory sidecar did.
func TestLocalImageSHA256SidecarPerFile(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.qcow2")
	installer := filepath.Join(dir, installerRawQcow2)
	if err := os.WriteFile(live, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(installer, []byte("installer"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	liveSum, err := localImageSHA256(live)
	if err != nil {
		t.Fatalf("hash live: %v", err)
	}
	installerSum, err := localImageSHA256(installer)
	if err != nil {
		t.Fatalf("hash installer: %v", err)
	}
	if liveSum == installerSum {
		t.Fatal("two different files hashed the same")
	}
	for path, want := range map[string]string{live: liveSum, installer: installerSum} {
		data, err := os.ReadFile(path + ".sha256")
		if err != nil {
			t.Fatalf("expected a sidecar for %q: %v", path, err)
		}
		if !strings.HasPrefix(string(data), want) {
			t.Errorf("sidecar of %q = %q, want its own hash %s", path, data, want)
		}
	}
	if again, err := localImageSHA256(live); err != nil || again != liveSum {
		t.Fatalf("live hash after hashing the installer = %q, %v; want %q",
			again, err, liveSum)
	}
}

// TestLocalImageSHA256SidecarIsWorldReadable guards against the sidecar
// landing 0600 root:root when the harness runs as root inside the evetest
// container against the developer's bind-mounted dist tree -- a plain hash
// file the developer cannot read is strictly worse than the opaque cache it
// replaced.
func TestLocalImageSHA256SidecarIsWorldReadable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := localImageSHA256(f); err != nil {
		t.Fatalf("hash: %v", err)
	}
	sidecar := f + ".sha256"
	info, err := os.Stat(sidecar)
	if err != nil {
		t.Fatalf("expected sidecar %q to be written: %v", sidecar, err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o644); got != want {
		t.Fatalf("sidecar mode = %o, want %o", got, want)
	}
}

// TestLocalImageSHA256InvalidatesOnChange covers a rebuilt image: content of a
// different length must not return the old hash.
func TestLocalImageSHA256InvalidatesOnChange(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	first, err := localImageSHA256(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := os.WriteFile(f, []byte("goodbye"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	second, err := localImageSHA256(f)
	if err != nil {
		t.Fatalf("rehash: %v", err)
	}
	if first == second {
		t.Fatal("hash did not change after the file changed; the cache is stale")
	}
}

// TestLocalImageSHA256InvalidatesOnSameSizeRebuild covers a rebuild in place
// that lands on exactly the same size (`LIVE_UPDATE=1 make live` can): the
// changed mtime alone must invalidate the cached hash.
func TestLocalImageSHA256InvalidatesOnSameSizeRebuild(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	first, err := localImageSHA256(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := os.WriteFile(f, []byte("jello"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(f, later, later); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	second, err := localImageSHA256(f)
	if err != nil {
		t.Fatalf("rehash: %v", err)
	}
	if first == second {
		t.Fatal("hash did not change after a same-size rebuild; the cache is stale")
	}
}

// writeRawInstaller writes a fake installer.raw into a fresh build directory
// and returns the localImage resolving it would produce.
func writeRawInstaller(t *testing.T, content string) *localImage {
	t.Helper()
	dir := t.TempDir()
	raw := filepath.Join(dir, "installer.raw")
	if err := os.WriteFile(raw, []byte(content), 0o600); err != nil {
		t.Fatalf("write installer.raw: %v", err)
	}
	return &localImage{
		Media:     api.InstallerMedia_INSTALLER_MEDIA_RAW,
		DiskPath:  raw,
		DiskBytes: int64(len(content)),
	}
}

// countingConverter is a qcow2Converter that writes a recognisable "qcow2"
// and counts its calls.
type countingConverter struct{ calls int }

func (c *countingConverter) convert(_ context.Context, src, dst string) error {
	c.calls++
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, append([]byte("qcow2:"), data...), 0o644)
}

// TestPrepareLocalInstallerRawConvertsOnce covers the conversion cache: the
// raw installer is converted next to itself on first use, and reused while it
// is unchanged -- a 2.5 GiB conversion per run would cost more than the
// upload it saves.
func TestPrepareLocalInstallerRawConvertsOnce(t *testing.T) {
	ctx := context.Background()
	img := writeRawInstaller(t, "raw installer")
	rawPath := img.DiskPath
	conv := &countingConverter{}

	converted, err := prepareLocalInstallerRaw(ctx, img, conv.convert)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	wantPath := filepath.Join(filepath.Dir(rawPath), installerRawQcow2)
	if !converted || conv.calls != 1 {
		t.Fatalf("first prepare: converted=%v calls=%d, want a conversion", converted, conv.calls)
	}
	if img.DiskPath != wantPath || img.DiskBytes != int64(len("qcow2:raw installer")) {
		t.Fatalf("image = %q (%d bytes), want the converted %q", img.DiskPath, img.DiskBytes, wantPath)
	}

	again := &localImage{Media: img.Media, DiskPath: rawPath}
	converted, err = prepareLocalInstallerRaw(ctx, again, conv.convert)
	if err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	if converted || conv.calls != 1 {
		t.Fatalf("second prepare: converted=%v calls=%d, want the cached conversion",
			converted, conv.calls)
	}
	if again.DiskPath != wantPath {
		t.Fatalf("second prepare points at %q, want %q", again.DiskPath, wantPath)
	}
	if matches, _ := filepath.Glob(wantPath + ".tmp-*"); len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
	}
}

// TestPrepareLocalInstallerRawReconverts covers every reason a cached
// conversion is stale: a rebuilt installer.raw (a new size, or only a new
// mtime) and a qcow2 that has gone missing.
func TestPrepareLocalInstallerRawReconverts(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		change func(t *testing.T, rawPath, qcowPath string)
	}{
		{"a rebuild with a new size", func(t *testing.T, rawPath, _ string) {
			if err := os.WriteFile(rawPath, []byte("a longer raw installer"), 0o600); err != nil {
				t.Fatalf("rewrite: %v", err)
			}
		}},
		{"a rebuild of the same size", func(t *testing.T, rawPath, _ string) {
			later := time.Now().Add(time.Minute)
			if err := os.Chtimes(rawPath, later, later); err != nil {
				t.Fatalf("chtimes: %v", err)
			}
		}},
		{"the converted image removed", func(t *testing.T, _, qcowPath string) {
			if err := os.Remove(qcowPath); err != nil {
				t.Fatalf("remove: %v", err)
			}
		}},
		{"the stamp removed", func(t *testing.T, _, qcowPath string) {
			if err := os.Remove(qcowPath + installerRawStampSuffix); err != nil {
				t.Fatalf("remove: %v", err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := writeRawInstaller(t, "raw installer")
			rawPath := img.DiskPath
			conv := &countingConverter{}
			if _, err := prepareLocalInstallerRaw(ctx, img, conv.convert); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			c.change(t, rawPath, img.DiskPath)
			again := &localImage{Media: img.Media, DiskPath: rawPath}
			converted, err := prepareLocalInstallerRaw(ctx, again, conv.convert)
			if err != nil {
				t.Fatalf("second prepare: %v", err)
			}
			if !converted || conv.calls != 2 {
				t.Fatalf("converted=%v calls=%d, want a second conversion", converted, conv.calls)
			}
		})
	}
}

// TestPrepareLocalInstallerRawFailureLeavesNothing covers a failed conversion:
// it is reported, and neither a partial image nor a stamp is left that a later
// run could take for a finished conversion.
func TestPrepareLocalInstallerRawFailureLeavesNothing(t *testing.T) {
	img := writeRawInstaller(t, "raw installer")
	dir := filepath.Dir(img.DiskPath)
	failing := func(_ context.Context, _, dst string) error {
		_ = os.WriteFile(dst, []byte("partial"), 0o644)
		return errors.New("disk full")
	}
	if _, err := prepareLocalInstallerRaw(context.Background(), img, failing); err == nil {
		t.Fatal("expected the conversion failure to be reported")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("dir holds %v after a failed conversion, want only installer.raw", names)
	}
}

// TestPrepareLocalInstallerRawSweepsLeftovers covers a conversion that was
// killed: its temporary file is removed by the next conversion, while one
// still being written -- by another evetest instance, say -- is left alone.
func TestPrepareLocalInstallerRawSweepsLeftovers(t *testing.T) {
	img := writeRawInstaller(t, "raw installer")
	qcowPath := filepath.Join(filepath.Dir(img.DiskPath), installerRawQcow2)
	leftover := qcowPath + ".tmp-dead"
	inProgress := qcowPath + ".tmp-live"
	for _, path := range []string{leftover, inProgress} {
		if err := os.WriteFile(path, []byte("partial"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	old := time.Now().Add(-2 * staleConversionAge)
	if err := os.Chtimes(leftover, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	conv := &countingConverter{}
	if _, err := prepareLocalInstallerRaw(context.Background(), img, conv.convert); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Errorf("the leftover %s survived the conversion (stat: %v)", leftover, err)
	}
	if _, err := os.Stat(inProgress); err != nil {
		t.Errorf("the in-progress %s was removed: %v", inProgress, err)
	}
}

// TestStaleLocalInstallerWarning covers the one staleness a build directory
// shows: an installer older than the rootfs.img beside it, left behind when
// the rootfs was rebuilt in place.
func TestStaleLocalInstallerWarning(t *testing.T) {
	root := t.TempDir()
	verDir := writeFakeBuild(t, root, "0.0.0-x-4444-kvm-amd64-v1-gcc", 5<<20)
	rootfs := filepath.Join(verDir, "installer", "rootfs.img")
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o600); err != nil {
		t.Fatalf("write rootfs.img: %v", err)
	}
	img, err := resolveLocalInstallerImageIn(root, "amd64", "", "",
		api.InstallerMedia_INSTALLER_MEDIA_RAW)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	now := time.Now()
	setTimes := func(installer, rootfsTime time.Time) {
		t.Helper()
		if err := os.Chtimes(img.DiskPath, installer, installer); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
		if err := os.Chtimes(rootfs, rootfsTime, rootfsTime); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}

	setTimes(now, now.Add(-time.Hour))
	if w := staleLocalInstallerWarning(img); w != "" {
		t.Errorf("an installer newer than its rootfs got a warning: %s", w)
	}
	setTimes(now.Add(-time.Hour), now)
	w := staleLocalInstallerWarning(img)
	for _, want := range []string{"installer.raw", "rootfs.img", "make installer-raw"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning %q should mention %q", w, want)
		}
	}

	live := &localImage{DiskPath: img.DiskPath, RootfsPath: rootfs}
	if w := staleLocalInstallerWarning(live); w != "" {
		t.Errorf("a live image got an installer warning: %s", w)
	}
	noRootfs := *img
	noRootfs.RootfsPath = ""
	if w := staleLocalInstallerWarning(&noRootfs); w != "" {
		t.Errorf("a build without rootfs.img got a warning: %s", w)
	}
}

// TestQemuImgCompressProducesQcow2 runs the real converter, which is what the
// rest of the pipeline relies on: its output must be a qcow2 qemu-img reads
// back with the raw image's virtual size.
func TestQemuImgCompressProducesQcow2(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skipf("qemu-img is not available: %v", err)
	}
	img := writeRawInstaller(t, strings.Repeat("eve", 1<<16))
	if err := os.Truncate(img.DiskPath, 4<<20); err != nil {
		t.Fatalf("size installer.raw: %v", err)
	}
	if _, err := prepareLocalInstallerRaw(context.Background(), img, qemuImgCompress); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	out, err := exec.Command("qemu-img", "info", "--output=json", img.DiskPath).CombinedOutput()
	if err != nil {
		t.Fatalf("qemu-img info: %v: %s", err, out)
	}
	if !strings.Contains(string(out), `"format": "qcow2"`) ||
		!strings.Contains(string(out), `"virtual-size": 4194304`) {
		t.Fatalf("converted image is not a 4 MiB qcow2: %s", out)
	}
}

// TestLiveImageHypervisor covers reading the flavor out of the version EVE
// reports, which is the only place a build records it -- the build directory's
// name does not.
func TestLiveImageHypervisor(t *testing.T) {
	cases := []struct {
		shortVersion string
		want         Hypervisor
		known        bool
	}{
		{"0.0.0-branch-abc1234-kvm-amd64", HypervisorKVM, true},
		{"0.0.0-branch-abc1234-k-amd64", HypervisorKubevirt, true},
		{"0.0.0-branch-abc1234-xen-amd64", HypervisorXen, true},
		// eve-k builds carry "-k-amd64" mid-string too; only the suffix counts.
		{"0.0.0-b-abc-k-amd64-v6.12.49-generic-core-deadbeef-user-gcc-k-amd64",
			HypervisorKubevirt, true},
		{"16.0.0-lts-kvm-arm64", HypervisorKVM, true},
		{"", HypervisorUndefined, false},
		{"0.0.0-no-flavor-here", HypervisorUndefined, false},
	}
	for _, c := range cases {
		t.Run(c.shortVersion, func(t *testing.T) {
			got, known := liveImageHypervisor(c.shortVersion)
			if known != c.known || got != c.want {
				t.Errorf("liveImageHypervisor(%q) = (%v, %v), want (%v, %v)",
					c.shortVersion, got, known, c.want, c.known)
			}
		})
	}
}

// TestLiveImageSatisfies pins the one substitution that is allowed: eve-k is KVM
// plus kubevirt orchestration, so it serves a KVM requirement, while a KVM build
// can never serve a test that needs kubevirt.
func TestLiveImageSatisfies(t *testing.T) {
	cases := []struct {
		required, build Hypervisor
		want            bool
	}{
		{HypervisorKVM, HypervisorKVM, true},
		{HypervisorKubevirt, HypervisorKubevirt, true},
		{HypervisorUndefined, HypervisorKubevirt, true},
		{HypervisorKVM, HypervisorKubevirt, true},
		{HypervisorKubevirt, HypervisorKVM, false},
		{HypervisorXen, HypervisorKVM, false},
		{HypervisorKVM, HypervisorXen, false},
	}
	for _, c := range cases {
		name := c.required.String() + "-on-" + c.build.String()
		t.Run(name, func(t *testing.T) {
			if got := liveImageSatisfies(c.required, c.build); got != c.want {
				t.Errorf("liveImageSatisfies(%v, %v) = %v, want %v",
					c.required, c.build, got, c.want)
			}
		})
	}
}
