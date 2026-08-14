// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/spf13/viper"
)

// configPartitionBytes is the fixed size of EVE's CONFIG partition. A
// config.img of any other size could not be written into it.
const configPartitionBytes = 5 << 20

// liveImageCurrent is the dist symlink pointing at the newest local build. Used
// when no EVE version is requested.
const liveImageCurrent = "current"

// eveVersionDir matches a dist version directory, which is what `make live`
// names after the EVE version. Used only to decide whether a directory name is
// worth reporting as the version.
var eveVersionDir = regexp.MustCompile(`^\d+\.\d+\.\d+-`)

// localLiveImage is a locally built EVE live image and the files that go with
// it. Every path field exists by the time this is returned.
type localLiveImage struct {
	DiskPath      string
	DiskBytes     int64
	ConfigImgPath string
	FirmwareDir   string
	// Version is the build directory's name, i.e. the EVE version without the
	// hypervisor/arch suffix a container tag carries.
	Version string
	// RootfsPath is installer/rootfs.img, the raw base OS image an upgrade
	// installs. Empty when this build has none.
	RootfsPath string
	// ShortVersion is installer/eve_version: the version string EVE itself
	// reports in ZInfoDevice.SwList, which is Version plus that suffix. Empty
	// when the build does not record one.
	ShortVersion string
}

// resolveLocalLiveImage resolves the live artifacts of a local EVE build, or
// returns (nil, nil) when the live transport is off and the container transport
// should be used.
//
// EVETEST_EVE_LIVE_IMAGE selects the transport and nothing else: it is a plain
// boolean, deliberately carrying no filesystem detail, because which build to
// run is the version's business (EVETEST_EVE_VERSION), not the transport's.
// eveVersion is that version, empty when none was requested.
func resolveLocalLiveImage(zarch, eveVersion string) (*localLiveImage, error) {
	setting := viper.GetString(constants.EVELiveImageEnv)
	if setting == "" {
		return nil, nil
	}
	live, err := strconv.ParseBool(setting)
	if err != nil {
		return nil, fmt.Errorf(
			"%s must be a boolean (true/false), got %q: to run a specific EVE "+
				"version set %s instead",
			constants.EnvPrefix+constants.EVELiveImageEnv, setting,
			constants.EnvPrefix+constants.EVEVersionEnv)
	}
	if !live {
		return nil, nil
	}
	distRoot := viper.GetString(constants.EVEDistDirEnv)
	if distRoot == "" {
		return nil, fmt.Errorf(
			"%s is not set: it must point at the EVE dist directory to deliver a "+
				"locally built image (normally set for you by `make evetest`)",
			constants.EnvPrefix+constants.EVEDistDirEnv)
	}
	return resolveLocalLiveImageIn(distRoot, zarch, eveVersion,
		viper.GetString(constants.EVEFirmwareDirEnv))
}

// resolveLocalLiveImageIn is resolveLocalLiveImage past the transport decision,
// with the dist root, the requested version and the firmware override injected
// so it can be tested without touching the environment. eveVersion selects the
// dist subdirectory; empty means the `current` symlink.
func resolveLocalLiveImageIn(distRoot, zarch, eveVersion, firmwareOverride string) (
	*localLiveImage, error) {

	verDirName := eveVersion
	if verDirName == "" {
		verDirName = liveImageCurrent
	}
	diskPath := filepath.Join(distRoot, zarch, verDirName, "live.qcow2")
	resolved, err := filepath.EvalSymlinks(diskPath)
	if err != nil {
		if eveVersion == "" {
			return nil, fmt.Errorf(
				"no local EVE build at %q: %w (run `make live`)", diskPath, err)
		}
		// Failing rather than quietly falling back to the container transport:
		// the operator asked for this version *and* for the live transport, and
		// silently delivering a different build -- or the same version from a
		// registry -- is the kind of thing that costs an afternoon to notice.
		return nil, fmt.Errorf(
			"EVE version %q is not built locally: no live image at %q (run "+
				"`make live` for it, unset %s to run that version from a container "+
				"image, or unset %s to use whatever is in %s)",
			eveVersion, diskPath,
			constants.EnvPrefix+constants.EVEVersionEnv,
			constants.EnvPrefix+constants.EVELiveImageEnv, liveImageCurrent)
	}

	diskInfo, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("cannot stat the local EVE live image %q: %w",
			resolved, err)
	}

	verDir := filepath.Dir(resolved)
	img := &localLiveImage{
		DiskPath:      resolved,
		DiskBytes:     diskInfo.Size(),
		ConfigImgPath: filepath.Join(verDir, "installer", "config.img"),
		FirmwareDir:   filepath.Join(verDir, "installer", "firmware"),
	}
	if firmwareOverride != "" {
		img.FirmwareDir = firmwareOverride
	}
	if base := filepath.Base(verDir); eveVersionDir.MatchString(base) {
		img.Version = base
	}
	// Both are only needed to deliver this build as an upgrade target, so a
	// build without them is still perfectly usable for a fresh device; whoever
	// needs them reports their absence.
	rootfs := filepath.Join(verDir, "installer", "rootfs.img")
	if info, err := os.Stat(rootfs); err == nil && info.Mode().IsRegular() {
		img.RootfsPath = rootfs
	}
	if data, err := os.ReadFile(filepath.Join(verDir, "installer", "eve_version")); err == nil {
		img.ShortVersion = strings.TrimSpace(string(data))
	}

	info, err := os.Stat(img.ConfigImgPath)
	if err != nil {
		return nil, fmt.Errorf("local EVE build is incomplete, no config.img at %q: %w",
			img.ConfigImgPath, err)
	}
	if info.Size() != configPartitionBytes {
		return nil, fmt.Errorf("config.img at %q is %d bytes, expected %d",
			img.ConfigImgPath, info.Size(), configPartitionBytes)
	}
	for _, f := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		if _, err := os.Stat(filepath.Join(img.FirmwareDir, f)); err != nil {
			return nil, fmt.Errorf("local EVE build is missing firmware %q: %w", f, err)
		}
	}
	return img, nil
}

// liveImageHypervisor reports which hypervisor flavor a local build was built
// for, read from the last two components of the version EVE reports for it
// ("…-kvm-amd64", "…-k-amd64"): that suffix is the only place the flavor is
// recorded, since the build directory's name does not carry it.
//
// Returns false when the suffix is not a flavor this framework knows, so the
// caller can proceed rather than reject a build over an unrecognised name.
func liveImageHypervisor(shortVersion string) (Hypervisor, bool) {
	parts := strings.Split(shortVersion, "-")
	if len(parts) < 2 {
		return HypervisorUndefined, false
	}
	switch parts[len(parts)-2] {
	case "kvm":
		return HypervisorKVM, true
	case "xen":
		return HypervisorXen, true
	case "k":
		return HypervisorKubevirt, true
	}
	return HypervisorUndefined, false
}

// liveImageSatisfies reports whether a build of flavor buildHV can serve a
// device that asked for requiredHV.
//
// Exact matches aside, the one flavor that substitutes for another is eve-k: it
// is KVM plus kubevirt orchestration, so it satisfies a plain KVM requirement
// (verified: the networking tests, which pin KVM, pass against an eve-k build).
// The reverse cannot work -- a KVM build has no k3s or kubevirt at all, so a
// test that needs them would not fail until its cluster assertions time out
// twenty minutes later, which is exactly the kind of thing worth refusing up
// front.
func liveImageSatisfies(requiredHV, buildHV Hypervisor) bool {
	if requiredHV == HypervisorUndefined || requiredHV == buildHV {
		return true
	}
	return requiredHV == HypervisorKVM && buildHV == HypervisorKubevirt
}

// hvMakeFlavor is the HV= value that builds a given hypervisor flavor, which is
// not always the flavor's own name ("kubevirt" is built as HV=k).
func hvMakeFlavor(h Hypervisor) string {
	if h == HypervisorKubevirt {
		return "k"
	}
	if h == HypervisorUndefined {
		return "kvm"
	}
	return h.String()
}

// useLocalLiveImage reports whether a device should boot the configured local
// EVE live image rather than the container path. A device with an explicit
// EVE version requirement (RequireEdgeDevice.WithEVEVersion) must take the
// container path instead, since that is the only path that can produce an
// arbitrary requested version; the local live image always carries whatever
// version happens to be built. A network-boot device
// (CreateFromScratchWithNetworkBoot) must also take the container path: the
// live image is a pre-built bootable disk, the opposite of what a
// network-boot device needs -- it has to pull (and buildNetworkBootImage has
// to extract firmware from) the actual target docker image instead.
func useLocalLiveImage(req RequireEdgeDevice, img *localLiveImage) bool {
	return img != nil && req.WithEVEVersion == "" &&
		req.DeviceReusePolicy != CreateFromScratchWithNetworkBoot
}

// LocalLiveImageRequested reports whether the operator selected the live
// transport (EVETEST_EVE_LIVE_IMAGE). An unparsable value counts as requested,
// so the caller surfaces the same error resolveLocalLiveImage would rather than
// silently treating a typo as "off".
func LocalLiveImageRequested() bool {
	setting := viper.GetString(constants.EVELiveImageEnv)
	if setting == "" {
		return false
	}
	live, err := strconv.ParseBool(setting)
	return err != nil || live
}

// liveImageShaSidecar is the name of the hash cache file written next to the
// image. `make live` creates a new version directory per build, so a build
// this file doesn't already know about naturally has no sidecar yet -- that
// absence is the invalidation, no mtime bookkeeping needed. Format is one
// greppable line: "<hex sha256>  <size in bytes>\n".
const liveImageShaSidecar = "image-sha"

// liveImageSHA256 returns the hex sha256 of path, reusing the value recorded
// in the sidecar file when its recorded size still matches the file's
// current size. EVETEST_EVE_LIVE_IMAGE may point at an arbitrary path outside
// a dist version directory, where content can change without a new
// directory, so the size check guards against reusing a stale hash there.
//
// A cache read or write failure only costs time (falls back to recomputing);
// it never becomes an error.
func liveImageSHA256(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat %q: %w", path, err)
	}
	cachePath := filepath.Join(filepath.Dir(path), liveImageShaSidecar)

	if data, err := os.ReadFile(cachePath); err == nil {
		if sum, size, ok := parseLiveImageShaSidecar(data); ok && size == info.Size() {
			return sum, nil
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open %q: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to read %q: %w", path, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))

	line := fmt.Sprintf("%s  %d\n", sum, info.Size())
	// World-readable: it's a content hash, nothing secret, and the harness
	// may be writing it as root inside a container into the developer's own
	// bind-mounted dist tree.
	// A cache write failure only costs time on the next run.
	_ = os.WriteFile(cachePath, []byte(line), 0o644)
	chownToHostUser(cachePath)
	return sum, nil
}

// chownToHostUser hands path back to the developer when running inside the
// evetest container as root. EVETEST_HOST_UID/EVETEST_HOST_GID are set by the
// container runtime (see evetest/Makefile), not user-facing configuration, so
// they are read directly rather than via a constants.* env var. A chown
// failure -- including the common case of running outside the container,
// where the variables are unset -- only costs the developer a `sudo chown`;
// it is not an error.
func chownToHostUser(path string) {
	uid, uidErr := strconv.Atoi(os.Getenv("EVETEST_HOST_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("EVETEST_HOST_GID"))
	if uidErr != nil || gidErr != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}

// parseLiveImageShaSidecar parses the "<hex sha256>  <size>\n" sidecar format.
func parseLiveImageShaSidecar(data []byte) (sum string, size int64, ok bool) {
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return "", 0, false
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return fields[0], size, true
}
