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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
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

// localArtifact names a local build's artifact and the make target that
// builds it, so an error about a missing artifact can say how to produce it.
type localArtifact struct {
	// File is the artifact's name in the build directory, a sibling of
	// installer/.
	File string
	// MakeTarget builds it.
	MakeTarget string
}

// liveArtifact is what a device booting the live image is delivered from.
var liveArtifact = localArtifact{File: "live.qcow2", MakeTarget: "live"}

// installerArtifacts maps each installer medium to the artifact it is
// delivered from. All three are written next to installer/, which holds the
// config.img and firmware every medium needs too.
var installerArtifacts = map[api.InstallerMedia]localArtifact{
	api.InstallerMedia_INSTALLER_MEDIA_RAW: {File: "installer.raw", MakeTarget: "installer-raw"},
	api.InstallerMedia_INSTALLER_MEDIA_ISO: {File: "installer.iso", MakeTarget: "installer-iso"},
	api.InstallerMedia_INSTALLER_MEDIA_NET: {File: "installer.net", MakeTarget: "installer-net"},
}

// localArtifactFor returns the artifact a device on the given installer medium
// boots; INSTALLER_MEDIA_UNSPECIFIED means the live image.
func localArtifactFor(media api.InstallerMedia) (localArtifact, error) {
	if media == api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED {
		return liveArtifact, nil
	}
	art, ok := installerArtifacts[media]
	if !ok {
		return localArtifact{}, fmt.Errorf("unknown installer medium %v", media)
	}
	return art, nil
}

// localImage is a locally built EVE image -- the live image, or an installer
// on one of its media -- and the files that go with it. Every path field
// exists by the time this is returned.
type localImage struct {
	// Media is the installer medium DiskPath holds, or
	// INSTALLER_MEDIA_UNSPECIFIED for the live image.
	Media api.InstallerMedia
	// DiskPath is the image delivered to the broker. For a raw installer it is
	// installer.raw as resolved, and the qcow2 it is converted to once
	// prepareLocalInstallerRaw has run.
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

// localImageTransport reports whether EVETEST_EVE_LIVE_IMAGE selects the
// local build as the way EVE's bits reach a device.
//
// EVETEST_EVE_LIVE_IMAGE selects the transport and nothing else: it is a plain
// boolean, deliberately carrying no filesystem detail, because which build to
// run is the version's business (EVETEST_EVE_VERSION), not the transport's.
// Which of the build's artifacts a device boots is the business of its
// DeviceReusePolicy (see useLocalBuild).
func localImageTransport() (bool, error) {
	setting := viper.GetString(constants.EVELiveImageEnv)
	if setting == "" {
		return false, nil
	}
	live, err := strconv.ParseBool(setting)
	if err != nil {
		return false, fmt.Errorf(
			"%s must be a boolean (true/false), got %q: to run a specific EVE "+
				"version set %s instead",
			constants.EnvPrefix+constants.EVELiveImageEnv, setting,
			constants.EnvPrefix+constants.EVEVersionEnv)
	}
	return live, nil
}

// resolveLocalLiveImage resolves the live artifacts of a local EVE build, or
// returns (nil, nil) when the live transport is off and the container transport
// should be used. eveVersion is the requested version, empty when none was.
func resolveLocalLiveImage(zarch, eveVersion string) (*localImage, error) {
	return resolveLocalImage(zarch, eveVersion,
		api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED)
}

// resolveLocalImage resolves the artifacts of a local EVE build a device on
// the given installer medium boots (INSTALLER_MEDIA_UNSPECIFIED: the live
// image), or returns (nil, nil) when the local transport is off.
func resolveLocalImage(zarch, eveVersion string, media api.InstallerMedia) (
	*localImage, error) {
	on, err := localImageTransport()
	if err != nil || !on {
		return nil, err
	}
	distRoot := viper.GetString(constants.EVEDistDirEnv)
	if distRoot == "" {
		return nil, fmt.Errorf(
			"%s is not set: it must point at the EVE dist directory to deliver a "+
				"locally built image (normally set for you by `make evetest`)",
			constants.EnvPrefix+constants.EVEDistDirEnv)
	}
	fwOverride := viper.GetString(constants.EVEFirmwareDirEnv)
	if media == api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED {
		return resolveLocalLiveImageIn(distRoot, zarch, eveVersion, fwOverride)
	}
	return resolveLocalInstallerImageIn(distRoot, zarch, eveVersion, fwOverride, media)
}

// resolveLocalLiveImageIn is resolveLocalLiveImage past the transport decision,
// with the dist root, the requested version and the firmware override injected
// so it can be tested without touching the environment. eveVersion selects the
// dist subdirectory; empty means the `current` symlink.
func resolveLocalLiveImageIn(distRoot, zarch, eveVersion, firmwareOverride string) (
	*localImage, error) {
	return resolveLocalBuildIn(distRoot, zarch, eveVersion, firmwareOverride, liveArtifact)
}

// resolveLocalInstallerImageIn is resolveLocalLiveImageIn for an installer on
// the given medium. It needs that medium's artifact, and not live.qcow2: a
// build made with only `make installer-raw` serves an installer device fine.
func resolveLocalInstallerImageIn(distRoot, zarch, eveVersion, firmwareOverride string,
	media api.InstallerMedia) (*localImage, error) {
	art, ok := installerArtifacts[media]
	if !ok {
		return nil, fmt.Errorf("unknown installer medium %v", media)
	}
	img, err := resolveLocalBuildIn(distRoot, zarch, eveVersion, firmwareOverride, art)
	if err != nil {
		return nil, err
	}
	img.Media = media
	return img, nil
}

// resolveLocalBuildIn resolves one artifact of a local build, plus the files
// every artifact needs: installer/config.img and the firmware. eveVersion
// selects the dist subdirectory; empty means the `current` symlink.
func resolveLocalBuildIn(distRoot, zarch, eveVersion, firmwareOverride string,
	art localArtifact) (*localImage, error) {

	verDirName := eveVersion
	if verDirName == "" {
		verDirName = liveImageCurrent
	}
	diskPath := filepath.Join(distRoot, zarch, verDirName, art.File)
	resolved, err := filepath.EvalSymlinks(diskPath)
	if err != nil {
		if eveVersion == "" {
			return nil, fmt.Errorf(
				"no local EVE build at %q: %w (run `make %s`)", diskPath, err, art.MakeTarget)
		}
		// Failing rather than quietly falling back to the container transport:
		// the operator asked for this version *and* for the live transport, and
		// silently delivering a different build -- or the same version from a
		// registry -- is the kind of thing that costs an afternoon to notice.
		return nil, fmt.Errorf(
			"EVE version %q is not built locally: no %s at %q (run "+
				"`make %s` for it, unset %s to run that version from a container "+
				"image, or unset %s to use whatever is in %s)",
			eveVersion, art.File, diskPath, art.MakeTarget,
			constants.EnvPrefix+constants.EVELiveImageEnv,
			constants.EnvPrefix+constants.EVEVersionEnv, liveImageCurrent)
	}

	diskInfo, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("cannot stat the local EVE image %q: %w",
			resolved, err)
	}
	if !diskInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("the local EVE image %q is not a regular file", resolved)
	}

	verDir := filepath.Dir(resolved)
	img := &localImage{
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

// installerMediaForPolicy is the installer medium a reuse policy boots EVE
// from, or INSTALLER_MEDIA_UNSPECIFIED for a policy that boots the live image.
func installerMediaForPolicy(policy ExistingEdgeDeviceReusePolicy) api.InstallerMedia {
	switch policy {
	case CreateFromScratchWithInstaller:
		return api.InstallerMedia_INSTALLER_MEDIA_RAW
	case CreateFromScratchWithInstallerISO:
		return api.InstallerMedia_INSTALLER_MEDIA_ISO
	case CreateFromScratchWithNetworkBoot:
		return api.InstallerMedia_INSTALLER_MEDIA_NET
	}
	return api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED
}

// useLocalBuild reports whether a device boots the local EVE build
// (transportOn: EVETEST_EVE_LIVE_IMAGE) rather than an EVE container image,
// and if so on which installer medium -- INSTALLER_MEDIA_UNSPECIFIED meaning
// the live image.
//
// The transport decides only *that* the local build is used; the device's
// policy decides *which* of its artifacts. A device with an explicit EVE
// version requirement (RequireEdgeDevice.WithEVEVersion) always takes the
// container path instead, since that is the only path that can produce an
// arbitrary requested version; the local build always carries whatever version
// happens to be built.
func useLocalBuild(req RequireEdgeDevice, transportOn bool) (bool, api.InstallerMedia) {
	if !transportOn || req.WithEVEVersion != "" {
		return false, api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED
	}
	return true, installerMediaForPolicy(req.DeviceReusePolicy)
}

// harnessLocalInstallerMedia lists the installer media this harness delivers
// from a local build. It is the harness's half of the gate, independent of
// what any broker advertises: for a medium not listed here the harness has no
// local delivery at all -- for NET it would even build the netboot bundle
// itself, from the EVE container image (buildNetbootArtifacts) -- so sending
// the broker a local installer image for it would pair the local bits with
// container-built ones, the silent wrong-build fallback this gate exists to
// rule out.
var harnessLocalInstallerMedia = []api.InstallerMedia{
	api.InstallerMedia_INSTALLER_MEDIA_RAW,
}

// checkLocalImageCapability fails a local delivery that this harness, or the
// broker, cannot serve. The harness must implement the medium
// (harnessLocalInstallerMedia), and the broker must advertise
// CAPABILITY_LOCAL_LIVE_IMAGE for the live image or the medium's own
// CAPABILITY_LOCAL_INSTALLER_* for an installer.
//
// Mandatory, never a fallback: a broker that predates a medium ignores the
// request fields describing it and could build the device from the EVE
// container image instead -- silently testing a different EVE build than the
// one the operator asked for.
func checkLocalImageCapability(brokerCaps []api.Capability, media api.InstallerMedia) error {
	if media == api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED {
		if generics.ContainsItem(brokerCaps, api.Capability_CAPABILITY_LOCAL_LIVE_IMAGE) {
			return nil
		}
		return fmt.Errorf("the broker does not support the live image transport "+
			"(%s%s=true): either it predates this feature and must be updated, or "+
			"its device provider builds images per device and cannot consume one",
			constants.EnvPrefix, constants.EVELiveImageEnv)
	}
	capability, ok := utils.InstallerMediaCapability(media)
	if !ok {
		return fmt.Errorf("unknown installer medium %v", media)
	}
	brokerHas := generics.ContainsItem(brokerCaps, capability)
	var err error
	switch {
	case !generics.ContainsItem(harnessLocalInstallerMedia, media):
		brokerState := "nor does the broker advertise " + capability.String()
		if brokerHas {
			brokerState = "whatever the broker advertises"
		}
		err = fmt.Errorf("this evetest harness does not deliver local %s installer "+
			"images yet (%s)", utils.InstallerMediaName(media), brokerState)
	case !brokerHas:
		err = fmt.Errorf("broker does not support local %s installer images "+
			"(it does not advertise %s): the broker or its device provider does not "+
			"implement this medium yet, or the broker predates it and must be updated",
			utils.InstallerMediaName(media), capability)
	default:
		return nil
	}
	if media == api.InstallerMedia_INSTALLER_MEDIA_ISO {
		// The container path cannot build an ISO yet either, so there is no
		// alternative to suggest.
		return err
	}
	return fmt.Errorf("%w; unset %s%s to run the installer from an EVE container image",
		err, constants.EnvPrefix, constants.EVELiveImageEnv)
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

// imageShaSidecarSuffix names the hash cache file written beside each image
// the harness hashes: live.qcow2.sha256, installer.evetest.qcow2.sha256. One
// per file, because a build directory holds several deliverable images, which
// a single per-directory cache would let overwrite each other. Format is one
// greppable line: "<hex sha256>  <size in bytes>  <mtime in ns>\n".
const imageShaSidecarSuffix = ".sha256"

// fileStamp identifies a version of a file well enough to tell whether a
// value derived from it -- its hash, or the qcow2 converted from it -- is
// stale: a rebuild that writes a new file changes the size, the mtime or both.
// Both, rather than the size alone, because a rebuild in place
// (`LIVE_UPDATE=1 make live`) can land on exactly the same size.
type fileStamp struct {
	Size    int64
	ModTime int64 // nanoseconds since the epoch
}

func stampOf(info os.FileInfo) fileStamp {
	return fileStamp{Size: info.Size(), ModTime: info.ModTime().UnixNano()}
}

// localImageSHA256 returns the hex sha256 of path, reusing the value recorded
// in its sidecar (path + imageShaSidecarSuffix) when the recorded size and
// mtime still match the file's.
//
// A cache read or write failure only costs time (falls back to recomputing);
// it never becomes an error.
func localImageSHA256(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat %q: %w", path, err)
	}
	stamp := stampOf(info)
	cachePath := path + imageShaSidecarSuffix

	if data, err := os.ReadFile(cachePath); err == nil {
		if sum, recorded, ok := parseImageShaSidecar(data); ok && recorded == stamp {
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

	line := fmt.Sprintf("%s  %d  %d\n", sum, stamp.Size, stamp.ModTime)
	// World-readable: it's a content hash, nothing secret, and the harness
	// may be writing it as root inside a container into the developer's own
	// bind-mounted dist tree.
	// A cache write failure only costs time on the next run.
	_ = os.WriteFile(cachePath, []byte(line), 0o644)
	chownToHostUser(cachePath)
	return sum, nil
}

// parseImageShaSidecar parses the "<hex sha256>  <size>  <mtime ns>\n"
// sidecar format.
func parseImageShaSidecar(data []byte) (sum string, stamp fileStamp, ok bool) {
	fields := strings.Fields(string(data))
	if len(fields) != 3 {
		return "", fileStamp{}, false
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", fileStamp{}, false
	}
	mtime, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return "", fileStamp{}, false
	}
	return fields[0], fileStamp{Size: size, ModTime: mtime}, true
}

// installerRawQcow2 is what a raw installer is delivered as: installer.raw
// converted to a compressed qcow2, written next to it.
//
// installer.raw is about 2.5 GiB, most of it a 2 GiB EFI system partition
// that is largely empty. The upload to a remote broker is a plain tar that
// would carry every one of those bytes, and everything that handles a template
// disk afterwards -- the per-device overlay, the CONFIG partition injection,
// the GPT read -- expects qcow2. Converted once, the installer travels exactly
// as live.qcow2 does.
const installerRawQcow2 = "installer.evetest.qcow2"

// installerRawStampSuffix names the file recording which installer.raw the
// qcow2 was converted from, as "<size>  <mtime ns>\n" of the raw image.
const installerRawStampSuffix = ".source"

// qcow2Converter converts the raw image at src into a compressed qcow2 at dst.
type qcow2Converter func(ctx context.Context, src, dst string) error

// qemuImgCompress is the qcow2Converter the harness uses: `qemu-img convert
// -c`, the same compression `make live` applies to live.qcow2.
func qemuImgCompress(ctx context.Context, src, dst string) error {
	out, err := exec.CommandContext(ctx, "qemu-img", "convert", "-c",
		"-f", "raw", "-O", "qcow2", src, dst).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img convert of %q failed: %v: %s", src, err, out)
	}
	return nil
}

// prepareLocalInstallerRaw points img, a resolved raw installer, at the qcow2
// it is delivered as, converting installer.raw only when it changed since the
// last conversion: the size and mtime it had then are recorded beside the
// qcow2, and the conversion is redone when either differs or the qcow2 is
// gone. Reports whether a conversion ran.
//
// The qcow2 is converted under a temporary name and renamed into place, so an
// interrupted conversion never leaves a truncated image that a later run would
// take for a finished one.
func prepareLocalInstallerRaw(ctx context.Context, img *localImage,
	convert qcow2Converter) (converted bool, err error) {

	rawPath := img.DiskPath
	rawInfo, err := os.Stat(rawPath)
	if err != nil {
		return false, fmt.Errorf("failed to stat %q: %w", rawPath, err)
	}
	want := stampOf(rawInfo)
	qcowPath := filepath.Join(filepath.Dir(rawPath), installerRawQcow2)
	stampPath := qcowPath + installerRawStampSuffix

	if !installerRawConversionCurrent(qcowPath, stampPath, want) {
		sweepStaleConversions(qcowPath, time.Now())
		suffix := make([]byte, 4)
		if _, err := rand.Read(suffix); err != nil {
			return false, fmt.Errorf("failed to name a temporary file: %w", err)
		}
		tmpPath := fmt.Sprintf("%s.tmp-%s", qcowPath, hex.EncodeToString(suffix))
		if err := convert(ctx, rawPath, tmpPath); err != nil {
			_ = os.Remove(tmpPath)
			return false, err
		}
		if err := os.Rename(tmpPath, qcowPath); err != nil {
			_ = os.Remove(tmpPath)
			return false, fmt.Errorf("failed to install the converted installer %q: %w",
				qcowPath, err)
		}
		chownToHostUser(qcowPath)
		// A stamp write failure only costs a conversion on the next run.
		_ = os.WriteFile(stampPath,
			[]byte(fmt.Sprintf("%d  %d\n", want.Size, want.ModTime)), 0o644)
		chownToHostUser(stampPath)
		converted = true
	}

	qcowInfo, err := os.Stat(qcowPath)
	if err != nil {
		return converted, fmt.Errorf("failed to stat %q: %w", qcowPath, err)
	}
	img.DiskPath = qcowPath
	img.DiskBytes = qcowInfo.Size()
	return converted, nil
}

// staleConversionAge is how long a temporary conversion file must have gone
// unwritten before sweepStaleConversions takes it for a leftover. A conversion
// in progress writes to its file continuously, so one this old belongs to a
// run that was killed; a younger one may be another evetest instance's
// conversion of the same build, which removing would break.
const staleConversionAge = 10 * time.Minute

// sweepStaleConversions removes the temporary files that interrupted
// conversions to qcowPath left behind (qcowPath + ".tmp-*"), so a killed run
// does not leave a half-written image in the build directory for good. A
// removal failure only leaves the file for the next sweep.
func sweepStaleConversions(qcowPath string, now time.Time) {
	matches, err := filepath.Glob(qcowPath + ".tmp-*")
	if err != nil {
		return
	}
	for _, path := range matches {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || now.Sub(info.ModTime()) < staleConversionAge {
			continue
		}
		_ = os.Remove(path)
	}
}

// staleLocalInstallerWarning returns a warning when an installer artifact is
// older than its build's installer/rootfs.img, and "" otherwise (including
// when either time cannot be read). A build normally writes the rootfs first
// and the installer from it, so an older installer means the rootfs was
// rebuilt in place afterwards -- `make live` or `make rootfs` into the same
// version directory -- and the installer may still carry the previous EVE.
// Only a warning: an installer rebuilt from an unchanged rootfs is just as
// current, and only the operator knows which happened.
func staleLocalInstallerWarning(img *localImage) string {
	if img.Media == api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED || img.RootfsPath == "" {
		return ""
	}
	installer, err := os.Stat(img.DiskPath)
	if err != nil {
		return ""
	}
	rootfs, err := os.Stat(img.RootfsPath)
	if err != nil || !installer.ModTime().Before(rootfs.ModTime()) {
		return ""
	}
	art := installerArtifacts[img.Media]
	return fmt.Sprintf("the local installer %q (%s) is older than the build's "+
		"%q (%s): the rootfs was rebuilt after the installer, which may still "+
		"carry the previous EVE; run `make %s` to rebuild it",
		img.DiskPath, installer.ModTime().UTC().Format(time.RFC3339),
		img.RootfsPath, rootfs.ModTime().UTC().Format(time.RFC3339), art.MakeTarget)
}

// installerRawConversionCurrent reports whether the qcow2 at qcowPath was
// converted from the installer.raw whose stamp is want.
func installerRawConversionCurrent(qcowPath, stampPath string, want fileStamp) bool {
	info, err := os.Stat(qcowPath)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	data, err := os.ReadFile(stampPath)
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return false
	}
	size, sizeErr := strconv.ParseInt(fields[0], 10, 64)
	mtime, mtimeErr := strconv.ParseInt(fields[1], 10, 64)
	return sizeErr == nil && mtimeErr == nil &&
		(fileStamp{Size: size, ModTime: mtime}) == want
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
