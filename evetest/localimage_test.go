// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/spf13/viper"
)

// writeFakeBuild lays out a dist tree like `make live` produces and returns
// the version directory it created.
func writeFakeBuild(t *testing.T, root, version string, cfgSize int) string {
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
	if err := os.WriteFile(filepath.Join(verDir, "live.qcow2"), []byte("qcow"), 0o600); err != nil {
		t.Fatalf("write image: %v", err)
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
	for _, want := range []string{"16.0.0-lts", constants.EVEVersionEnv} {
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

// TestUseLocalLiveImage covers the precedence between an explicitly requested
// EVE version (RequireEdgeDevice.WithEVEVersion) and a configured local live
// image: the explicit version must always win, since it is the strongest
// signal a test can give about which build a device should boot.
func TestUseLocalLiveImage(t *testing.T) {
	img := &localLiveImage{DiskPath: "/dist/amd64/current/live.qcow2"}

	cases := []struct {
		name string
		req  RequireEdgeDevice
		img  *localLiveImage
		want bool
	}{
		{
			name: "explicit version never uses the live image",
			req:  RequireEdgeDevice{WithEVEVersion: "16.0.0-lts"},
			img:  img,
			want: false,
		},
		{
			name: "no explicit version uses the configured live image",
			req:  RequireEdgeDevice{},
			img:  img,
			want: true,
		},
		{
			name: "no image configured, nothing to use regardless of version",
			req:  RequireEdgeDevice{},
			img:  nil,
			want: false,
		},
		{
			name: "network-boot device never uses the live image, even with no explicit version",
			req:  RequireEdgeDevice{DeviceReusePolicy: CreateFromScratchWithNetworkBoot},
			img:  img,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := useLocalLiveImage(c.req, c.img); got != c.want {
				t.Errorf("useLocalLiveImage(%+v, %v) = %v, want %v",
					c.req, c.img != nil, got, c.want)
			}
		})
	}
}

func TestLiveImageSHA256IsStable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// sha256("hello")
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	got, err := liveImageSHA256(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if got != want {
		t.Fatalf("sha256 = %q, want %q", got, want)
	}
	sidecar := filepath.Join(filepath.Dir(f), "image-sha")
	if _, err := os.Stat(sidecar); err != nil {
		t.Fatalf("expected sidecar %q to be written: %v", sidecar, err)
	}
	again, err := liveImageSHA256(f)
	if err != nil || again != want {
		t.Fatalf("cached read = %q, %v", again, err)
	}
}

// TestLiveImageSHA256SidecarIsWorldReadable guards against the sidecar
// landing 0600 root:root when the harness runs as root inside the evetest
// container against the developer's bind-mounted dist tree -- a plain hash
// file the developer cannot read is strictly worse than the opaque cache it
// replaced.
func TestLiveImageSHA256SidecarIsWorldReadable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := liveImageSHA256(f); err != nil {
		t.Fatalf("hash: %v", err)
	}
	sidecar := filepath.Join(filepath.Dir(f), "image-sha")
	info, err := os.Stat(sidecar)
	if err != nil {
		t.Fatalf("expected sidecar %q to be written: %v", sidecar, err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o644); got != want {
		t.Fatalf("sidecar mode = %o, want %o", got, want)
	}
}

// TestLiveImageSHA256InvalidatesOnChange covers a rebuilt image: the cache is
// keyed on the recorded size, so content of a different length must not
// return the old hash.
func TestLiveImageSHA256InvalidatesOnChange(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	first, err := liveImageSHA256(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := os.WriteFile(f, []byte("goodbye"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	second, err := liveImageSHA256(f)
	if err != nil {
		t.Fatalf("rehash: %v", err)
	}
	if first == second {
		t.Fatal("hash did not change after the file changed; the cache is stale")
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
