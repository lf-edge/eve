// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/lf-edge/eve/evetest/broker/provider"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/sirupsen/logrus"
)

// buildSdnImage builds an SDN disk image by running the evetest-sdn Docker image
// for a given architecture.
//
// Parameters:
//   - imageDirPath: Path to the output directory.
//   - dockerImageName: Name of the (multi-arch) evetest-sdn Docker image to run.
//   - arch: Target architecture for which to build the image.
//
// Steps:
//  1. Ensures the target directory exists.
//  2. Run the given multi-arch SDN docker image under the specified architecture.
//  3. Runs the Docker container with appropriate args and mounts to generate the SDN image.
//
// Returns an error if the build or any Docker operation fails.
func buildSdnImage(ctx context.Context, log *logrus.Entry, imageDirPath,
	dockerImageName string, arch api.ArchType) (disks []provider.DiskImage, err error) {

	// Ensure the target directory exists.
	if err = os.MkdirAll(imageDirPath, 0o755); err != nil {
		err = fmt.Errorf("failed to create SDN image directory %q: %w", imageDirPath, err)
		return nil, err
	}
	defer func() {
		if err != nil {
			if removeErr := os.RemoveAll(imageDirPath); removeErr != nil {
				log.Warnf("Failed to remove SDN image directory %q : %v",
					imageDirPath, removeErr)
			}
		}
	}()

	// Determine Docker platform string for the given architecture.
	var platform string
	switch arch {
	case api.ArchType_ARCH_AMD64:
		platform = "linux/amd64"
	case api.ArchType_ARCH_ARM64:
		platform = "linux/arm64"
	default:
		err = fmt.Errorf("unsupported architecture: %s", arch)
		return nil, err
	}

	// Construct the command to run inside the container.
	cmd := "-f qcow2 image"

	// Build the volume mapping: container target → host source.
	volumeMap := map[string]string{
		"/out": imageDirPath,
	}

	// Run the SDN docker container to build the SDN Qcow2 image.
	imagePath := filepath.Join(imageDirPath, "evetest-sdn.img.qcow2")
	log.Infof("Building SDN image into the file %q", imagePath)
	result, err := utils.RunDockerCommand(
		ctx, log, dockerImageName, cmd, volumeMap, platform)
	if err != nil {
		err = fmt.Errorf("failed to run docker command for SDN image build: %w", err)
		return nil, err
	}

	// Check that the generated image file exists and is non-empty
	info, statErr := os.Stat(imagePath)
	if statErr != nil {
		log.Infof("Docker output:\n%s", result)
		err = fmt.Errorf("expected SDN image file %q not found: %w",
			imagePath, statErr)
		return nil, err
	}
	if info.Size() == 0 {
		log.Infof("Docker output:\n%s", result)
		err = fmt.Errorf("SDN image file %q is empty", imagePath)
		return nil, err
	}

	log.Infof("Successfully built SDN image from %s for %s: %s",
		dockerImageName, arch, imagePath)
	log.Debugf("Docker output:\n%s", result)
	disks = []provider.DiskImage{
		{Format: provider.DiskImageFormatQcow2, Path: imagePath},
	}
	return disks, nil
}

// buildEVEImageParams groups the inputs to buildEVEImage.
type buildEVEImageParams struct {
	// imageDirPath is the path to the output directory.
	imageDirPath string
	// dockerImageName is the name of the EVE Docker image to build from.
	dockerImageName string
	// config provides server, certificates, keys, and JSON configs. May be nil.
	config *api.EveConfig
	// proxyCACerts is an optional slice of PEM blocks containing trusted proxy CA
	// certificates to include in the image.
	proxyCACerts []*pem.Block
	// diskSize is the desired disk size in bytes. Zero means use the image default.
	diskSize uint64
	// installer, when true, builds a RAW installer image instead of a live QCOW2 image.
	installer bool
	// softSerial is the device's soft serial number. Always non-empty; see
	// resolveSoftSerial.
	softSerial string
}

// buildEVEImageResult holds the outputs of either device-image producer
// (buildEVEImage, the legacy per-device build, or makeDeviceImage, the
// template-backed overlay build) excluding the error.
type buildEVEImageResult struct {
	// installerImage is non-nil only for installer builds. It is prepended to
	// disks for the first (installer) boot, then discarded — subsequent boots
	// use only disks. Its Format depends on which producer filled this struct:
	// RAW from the legacy buildEVEImage path, QCOW2 from the template-backed
	// makeDeviceImage path, where it must be QCOW2 to be a template overlay.
	installerImage *provider.DiskImage
	// disks is the list of persistent disk images for the device. Currently always
	// a single disk (live QCOW2 for live builds, blank target QCOW2 for installer
	// builds), but structured as a slice to accommodate multiple disks in the future.
	disks []provider.DiskImage
	// firmwareDir is the path to the directory containing the extracted UEFI firmware
	// (OVMF_CODE.fd, OVMF_VARS.fd).
	firmwareDir string
}

// buildEVEImage builds an EVE image (QCOW2 or RAW) using EVE Docker image as the builder.
// It extracts UEFI firmware, mounts configuration files, and invokes the EVE container
// to produce the final disk image. For installer builds it also creates a blank target
// disk.
func buildEVEImage(ctx context.Context, log *logrus.Entry,
	params buildEVEImageParams) (result buildEVEImageResult, err error) {

	// Ensure the target directory exists.
	if err = os.MkdirAll(params.imageDirPath, 0o755); err != nil {
		err = fmt.Errorf("failed to create EVE image directory %q: %w",
			params.imageDirPath, err)
		return result, err
	}
	defer func() {
		if err != nil {
			if removeErr := os.RemoveAll(params.imageDirPath); removeErr != nil {
				log.Warnf("Failed to remove EVE image directory %q : %v",
					params.imageDirPath, removeErr)
			}
		}
	}()

	// Extract UEFI firmware (needed for both live and post-installation boots).
	result.firmwareDir = filepath.Join(params.imageDirPath, "firmware")
	err = utils.ExtractFromDockerImage(ctx, log,
		params.dockerImageName, params.imageDirPath, "/bits/firmware")
	if err != nil {
		err = fmt.Errorf("failed to extract UEFI firmware from EVE image %s: %w",
			params.dockerImageName, err)
		return result, err
	}

	// Build the volume mapping: container target → host source.
	// The config dir is created under imageDirPath so that, when the broker
	// runs inside a container, the path also exists on the host (it's bind-
	// mounted at the same path) and can be passed to docker-out-of-docker.
	var configDir string
	configDir, err = makeEVEConfigDir(
		params.imageDirPath, params.config, params.proxyCACerts, params.softSerial)
	if err != nil {
		err = fmt.Errorf("failed to prepare EVE config dir: %w", err)
		return result, err
	}
	volumeMap := map[string]string{
		"/out": params.imageDirPath,
	}
	if configDir != "" {
		volumeMap["/in"] = configDir
		defer os.RemoveAll(configDir)
	}

	// Run the EVE docker container to build the EVE disk image.
	// Disk size is appended for live images only; the installer image has a fixed size.
	var builtImagePath string
	var cmd string
	if !params.installer {
		builtImagePath = filepath.Join(params.imageDirPath, "live.raw.qcow2")
		cmd = "-f qcow2 live"
		if params.diskSize != 0 {
			cmd += fmt.Sprintf(" %d", params.diskSize>>20)
		}
	} else {
		builtImagePath = filepath.Join(params.imageDirPath, "installer.raw")
		cmd = "-f raw installer_raw"
	}

	log.Infof("Building EVE image into the file %q", builtImagePath)
	dockerOutput, err := utils.RunDockerCommand(
		ctx, log, params.dockerImageName, cmd, volumeMap, "")
	if err != nil {
		err = fmt.Errorf("failed to run docker command for EVE image build: %w", err)
		return result, err
	}

	const maxOutputLen = 256
	truncateOutput := func(output string) string {
		if len(output) <= maxOutputLen {
			return output
		}
		return output[:maxOutputLen] + "…"
	}

	// Check that the generated image file exists and is non-empty.
	info, statErr := os.Stat(builtImagePath)
	truncatedOutput := truncateOutput(dockerOutput)

	if statErr != nil {
		log.Infof("Docker output (truncated to %d chars):\n%s",
			maxOutputLen, truncatedOutput)
		err = fmt.Errorf("expected EVE image file %q not found: %w",
			builtImagePath, statErr)
		return result, err
	}
	if info.Size() == 0 {
		log.Infof("Docker output (truncated to %d chars):\n%s",
			maxOutputLen, truncatedOutput)
		err = fmt.Errorf("EVE image file %q is empty", builtImagePath)
		return result, err
	}

	log.Infof("Successfully built EVE image from %s: %s", params.dockerImageName,
		builtImagePath)
	log.Debugf("Docker output:\n%s", dockerOutput)

	if !params.installer {
		result.disks = []provider.DiskImage{
			{Format: provider.DiskImageFormatQcow2, Path: builtImagePath},
		}
		return result, nil
	}

	// For installer mode, create a blank target disk that EVE will be installed onto.
	// The installer image is prepended to disks for the first boot only.
	if params.diskSize == 0 {
		err = fmt.Errorf("diskSize must be non-zero for installer builds")
		return result, err
	}
	targetDiskPath := filepath.Join(params.imageDirPath, "installed.qcow2")
	diskSizeMiB := params.diskSize >> 20
	log.Infof("Creating blank target disk for EVE installation: %s (%d MiB)",
		targetDiskPath, diskSizeMiB)
	out, err2 := exec.CommandContext(ctx, "qemu-img", "create", "-f", "qcow2",
		targetDiskPath, fmt.Sprintf("%dM", diskSizeMiB)).CombinedOutput()
	if err2 != nil {
		err = fmt.Errorf("failed to create installer target disk %q: %v: %s",
			targetDiskPath, err2, out)
		return result, err
	}
	log.Infof("Created blank target disk for EVE installation: %s", targetDiskPath)

	installerImage := provider.DiskImage{
		Format: provider.DiskImageFormatRaw, Path: builtImagePath}
	result.installerImage = &installerImage
	result.disks = []provider.DiskImage{
		{Format: provider.DiskImageFormatQcow2, Path: targetDiskPath},
	}
	return result, nil
}

// makeEVEConfigDir creates a temporary directory containing EVE configuration
// files derived from the provided EveConfig. Each non-empty field is written
// into a specific file under the directory structure expected by EVE.
//
// The directory is created under parentDir so that, when the broker runs
// inside a container, the path also exists on the host and can be bind-mounted
// into a docker-out-of-docker container.
//
// Certificates are validated before writing. Proxy CA certificates passed in
// proxyCACerts are appended to v2tlsbaseroot-certificates.pem.
//
// softSerial is passed separately rather than read from config because it is
// never empty: see resolveSoftSerial.
func makeEVEConfigDir(parentDir string, config *api.EveConfig,
	proxyCACerts []*pem.Block, softSerial string) (dirPath string, err error) {

	if config == nil && len(proxyCACerts) == 0 && softSerial == "" {
		return "", nil
	}

	dirPath, err = os.MkdirTemp(parentDir, "eve-config-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary config directory: %w", err)
	}
	// Ensure cleanup on error
	defer func() {
		if err != nil {
			os.RemoveAll(dirPath)
		}
	}()

	// Helper to write a file only if data is non-empty
	writeFile := func(relPath string, data []byte) error {
		if len(data) == 0 {
			return nil
		}
		fullPath := filepath.Join(dirPath, relPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return fmt.Errorf("failed to create directory for %q: %w", fullPath, err)
		}
		if err := os.WriteFile(fullPath, data, 0o600); err != nil {
			return fmt.Errorf("failed to write file %q: %w", fullPath, err)
		}
		return nil
	}

	err = writeFile("soft_serial", []byte(softSerial))
	if err != nil {
		return "", err
	}
	err = writeFile("server", []byte(config.GetServerName()))
	if err != nil {
		return "", err
	}

	if len(config.GetOnboardCertPem()) > 0 {
		_, err = utils.ValidatePEMCerts([]byte(config.GetOnboardCertPem()), true)
		if err != nil {
			return "", fmt.Errorf("onboard certificate invalid: %w", err)
		}
		err = writeFile("onboard.cert.pem", []byte(config.GetOnboardCertPem()))
		if err != nil {
			return "", err
		}
	}
	if len(config.GetOnboardKeyPem()) > 0 {
		err = utils.ValidatePEMPrivateKeyECDSA([]byte(config.GetOnboardKeyPem()))
		if err != nil {
			return "", fmt.Errorf("onboard key invalid: %w", err)
		}
		err = writeFile("onboard.key.pem", []byte(config.GetOnboardKeyPem()))
		if err != nil {
			return "", err
		}
	}

	if len(config.GetRootCertPem()) > 0 {
		_, err = utils.ValidatePEMCerts([]byte(config.GetRootCertPem()), true)
		if err != nil {
			return "", fmt.Errorf("root certificate invalid: %w", err)
		}
		err = writeFile("root-certificate.pem", []byte(config.GetRootCertPem()))
		if err != nil {
			return "", err
		}
	}

	// Handle V2 TLS certs and append proxy CA certs
	var certDataBuilder strings.Builder
	writeV2TLS := false

	// Validate and append V2TlsCertsPem
	for _, pemStr := range config.GetV2TlsCertsPem() {
		_, err = utils.ValidatePEMCerts([]byte(pemStr), true)
		if err != nil {
			return "", fmt.Errorf("v2 TLS certificate invalid: %w", err)
		}
		certDataBuilder.WriteString(pemStr)
		if !strings.HasSuffix(pemStr, "\n") {
			certDataBuilder.WriteString("\n")
		}
		writeV2TLS = true
	}

	// Append validated proxy CA certificates
	for _, block := range proxyCACerts {
		writeV2TLS = true
		certPEM := pem.EncodeToMemory(block)
		certDataBuilder.Write(certPEM)
		if len(certPEM) > 0 && certPEM[len(certPEM)-1] != '\n' {
			certDataBuilder.WriteString("\n")
		}
	}

	if writeV2TLS {
		certData := []byte(certDataBuilder.String())
		err = writeFile("v2tlsbaseroot-certificates.pem", certData)
		if err != nil {
			return "", err
		}
	}

	if len(config.GetSshKeys()) > 0 {
		keysData := strings.Join(config.GetSshKeys(), "\n")
		err = writeFile("authorized_keys", []byte(keysData))
		if err != nil {
			return "", err
		}
	}

	if len(config.GetGrubOptions()) > 0 {
		grubConfig := strings.Join(config.GetGrubOptions(), "\n")
		err = writeFile("grub.cfg", []byte(grubConfig))
		if err != nil {
			return "", err
		}
	}

	err = writeFile("GlobalConfig/global.json", []byte(config.GetGlobalJson()))
	if err != nil {
		return "", err
	}
	err = writeFile("DevicePortConfig/override.json", []byte(config.GetOverrideJson()))
	if err != nil {
		return "", err
	}
	if len(config.GetBootstrapConfigPb()) > 0 {
		err = writeFile("bootstrap-config.pb", config.GetBootstrapConfigPb())
		if err != nil {
			return "", err
		}
	}

	return dirPath, nil
}

// resolveSoftSerial returns the soft serial number to write into a device's
// config partition.
//
// pkg/eve/runme.sh:158-162 generates one whenever /bits/config.img has none,
// but that runs once per *template* now rather than once per device, so every
// device would otherwise inherit the same serial. Generating here keeps cluster
// nodes distinct. A serial explicitly requested by the test (RequireEdgeDevice.
// WithSoftSerial) is passed through unchanged.
func resolveSoftSerial(requested string) string {
	if requested != "" {
		return requested
	}
	return uuid.NewString()
}

// resizeDeviceDisk grows a device's disk to wantBytes, whether that disk is a
// QCOW2 overlay on a template or a standalone copy of one. For an overlay the
// backing template is untouched -- verified: growing an overlay leaves the
// backing file's virtual size unchanged and allocates nothing, and reads past
// the backing file's end return zeros. Shrinking is refused because it would
// truncate the GPT and data.
func resizeDeviceDisk(ctx context.Context, diskPath string, wantBytes, haveBytes int64) error {
	if wantBytes == 0 || wantBytes == haveBytes {
		return nil
	}
	if wantBytes < haveBytes {
		return fmt.Errorf(
			"requested disk size %d is smaller than the EVE image's %d; shrinking "+
				"would truncate the partition table", wantBytes, haveBytes)
	}
	out, err := exec.CommandContext(ctx, "qemu-img", "resize",
		diskPath, strconv.FormatInt(wantBytes, 10)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img resize of %q failed: %v: %s", diskPath, err, out)
	}
	return nil
}

// mcopyArgs builds the mtools invocation that overlays a device's config files
// onto a copy of the pristine config partition image. It mirrors
// pkg/eve/runme.sh:337 -- `mcopy -o -i /bits/config.img -s /in/* ::/` -- with
// the shell glob replaced by an explicit list, so no shell is involved.
func mcopyArgs(cfgImgPath string, configDirEntries []string) []string {
	args := make([]string, 0, len(configDirEntries)+5)
	args = append(args, "-o", "-i", cfgImgPath, "-s")
	args = append(args, configDirEntries...)
	return append(args, "::/")
}

// writeConfigPartition produces the device's config partition image at outPath:
// a copy of the template's pristine config.img with the device's config files
// overlaid onto it.
func writeConfigPartition(ctx context.Context, log *logrus.Entry,
	templateConfigImg, configDir, outPath string) (err error) {

	if err = utils.CopyFile(templateConfigImg, outPath); err != nil {
		return fmt.Errorf("failed to copy config partition image: %w", err)
	}
	defer func() {
		if err != nil {
			if removeErr := os.Remove(outPath); removeErr != nil {
				log.Warnf("Failed to remove config partition image %q: %v",
					outPath, removeErr)
			}
		}
	}()
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return fmt.Errorf("failed to read config dir %q: %w", configDir, err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("config dir %q is empty", configDir)
	}
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		paths = append(paths, filepath.Join(configDir, e.Name()))
	}
	cmd := exec.CommandContext(ctx, "mcopy", mcopyArgs(outPath, paths)...)
	// The 5 MiB FAT image has a geometry mtools considers suspicious; the EVE
	// build sets the same skip in /etc/mtools.conf (pkg/mkconf/make-config).
	cmd.Env = append(os.Environ(), "MTOOLS_SKIP_CHECK=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mcopy into %q failed: %v: %s", outPath, err, out)
	}
	log.Debugf("Wrote config partition image %q from %d config entries",
		outPath, len(paths))
	return nil
}

// injectConfigPartition writes a config partition image into the CONFIG
// partition of a QCOW2 disk. qemu-io is used rather than nbd or libguestfs
// because it needs no kernel module, no /dev access and no privileged
// container -- and it ships in the same Alpine qemu-img package as qemu-img.
func injectConfigPartition(ctx context.Context, log *logrus.Entry,
	diskPath, cfgImgPath string, part gptPartition) error {

	info, err := os.Stat(cfgImgPath)
	if err != nil {
		return fmt.Errorf("failed to stat config partition image: %w", err)
	}
	if info.Size() > part.Length {
		return fmt.Errorf(
			"config partition image is %d bytes, larger than the %d-byte CONFIG partition",
			info.Size(), part.Length)
	}
	// qemu-io tokenizes the -c argument itself, so a path containing
	// whitespace would be split into separate arguments.
	if strings.ContainsAny(cfgImgPath, " \t") {
		return fmt.Errorf("config partition image path %q contains whitespace", cfgImgPath)
	}
	script := fmt.Sprintf("write -s %s %d %d", cfgImgPath, part.Offset, info.Size())
	out, err := exec.CommandContext(ctx, "qemu-io",
		"-f", "qcow2", "-c", script, diskPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-io write into %q failed: %v: %s", diskPath, err, out)
	}
	log.Debugf("Injected %d bytes of config partition at offset %d of %q",
		info.Size(), part.Offset, diskPath)
	return nil
}

// buildTemplateDisk runs the EVE container once to produce a
// configuration-independent disk image, and extracts the pristine config
// partition image and UEFI firmware alongside it. This is the expensive step
// the template cache exists to avoid repeating.
//
// No /in volume is mounted, so the disk carries the EVE image's default config
// partition; per-device configuration is written into the working copy later.
func buildTemplateDisk(ctx context.Context, log *logrus.Entry,
	dockerImageName string, diskSize uint64, installer bool,
	dstDir string) (gptPartition, error) {

	var none gptPartition

	err := utils.ExtractFromDockerImage(ctx, log, dockerImageName, dstDir, "/bits/firmware")
	if err != nil {
		return none, fmt.Errorf("failed to extract UEFI firmware from %s: %w",
			dockerImageName, err)
	}
	err = utils.ExtractFromDockerImage(ctx, log, dockerImageName, dstDir, "/bits/config.img")
	if err != nil {
		return none, fmt.Errorf("failed to extract config partition image from %s: %w",
			dockerImageName, err)
	}

	var builtName, cmd string
	if installer {
		// Built as QCOW2 rather than RAW so it can back an overlay -- and so a
		// sparse 8 GiB installer stops materialising in full per device.
		builtName = "installer.raw.qcow2"
		cmd = "-f qcow2 installer_raw"
	} else {
		builtName = "live.raw.qcow2"
		cmd = "-f qcow2 live"
		if diskSize != 0 {
			cmd += fmt.Sprintf(" %d", diskSize>>20)
		}
	}

	log.Infof("Building EVE image template disk in %q", dstDir)
	dockerOutput, err := utils.RunDockerCommand(
		ctx, log, dockerImageName, cmd, map[string]string{"/out": dstDir}, "")
	if err != nil {
		return none, fmt.Errorf("failed to run docker command for EVE image build: %w", err)
	}
	builtPath := filepath.Join(dstDir, builtName)
	info, err := os.Stat(builtPath)
	if err != nil {
		log.Infof("Docker output:\n%s", dockerOutput)
		return none, fmt.Errorf("expected EVE image file %q not found: %w", builtPath, err)
	}
	if info.Size() == 0 {
		log.Infof("Docker output:\n%s", dockerOutput)
		return none, fmt.Errorf("EVE image file %q is empty", builtPath)
	}
	diskPath := filepath.Join(dstDir, templateDiskFile)
	if err := os.Rename(builtPath, diskPath); err != nil {
		return none, fmt.Errorf("failed to rename %q to %q: %w", builtPath, diskPath, err)
	}

	head, err := readDiskHead(ctx, diskPath)
	if err != nil {
		return none, fmt.Errorf("failed to read GPT of %q: %w", diskPath, err)
	}
	part, err := findGPTPartition(head, gptConfigPartName)
	if err != nil {
		return none, fmt.Errorf("failed to locate the CONFIG partition in %q: %w", diskPath, err)
	}
	cfgInfo, err := os.Stat(filepath.Join(dstDir, templateConfigImgFile))
	if err != nil {
		return none, fmt.Errorf("failed to stat the extracted config partition image: %w", err)
	}
	if cfgInfo.Size() > part.Length {
		return none, fmt.Errorf(
			"config partition image is %d bytes but the CONFIG partition is only %d",
			cfgInfo.Size(), part.Length)
	}
	log.Infof("EVE image template disk built: CONFIG partition at offset %d, length %d",
		part.Offset, part.Length)
	return part, nil
}

// makeDeviceImageParams groups the inputs to makeDeviceImage.
type makeDeviceImageParams struct {
	// imageDirPath is the per-device output directory.
	imageDirPath string
	// dockerImageName is the EVE container image to build the template from.
	dockerImageName string
	// dockerImageID is that image's content ID, which the template is keyed on.
	dockerImageID string
	// arch is the device architecture.
	arch api.ArchType
	// config provides server, certificates, keys and JSON configs. May be nil.
	config *api.EveConfig
	// proxyCACerts are trusted proxy CA certificates to add to the image.
	proxyCACerts []*pem.Block
	// softSerial is the device's soft serial. Always non-empty.
	softSerial string
	// diskSize is the desired disk size in bytes. Zero means the image default.
	diskSize uint64
	// installer, when true, produces an installer image plus a blank target disk.
	installer bool
	// overlay selects a QCOW2 backing-file working copy over a standalone copy.
	overlay bool
	// liveImageSHA256, when non-empty, selects the live path: the template is
	// installed by unpacking liveTarPath instead of running the EVE container,
	// and dockerImageName/dockerImageID are ignored.
	liveImageSHA256 string
	// liveTarPath is the staged upload to unpack when liveImageSHA256 is set.
	liveTarPath string
	// liveSource, when set, points at the client's own live image files, which
	// this broker can read directly; the template is installed from those and
	// liveTarPath is never touched.
	liveSource *api.LocalLiveImageSource
}

// makeDeviceImage derives a device's disk image from a cached template: it
// creates the working copy, assembles the device's config partition and writes
// it into the disk's CONFIG partition. The returned templateKey must be passed
// to templateCache.removeRef when the device is torn down.
func makeDeviceImage(ctx context.Context, log *logrus.Entry, cache *templateCache,
	refName string, params makeDeviceImageParams) (
	result buildEVEImageResult, templateKey string, err error) {

	build := func(ctx context.Context, log *logrus.Entry, dstDir string) (gptPartition, error) {
		return buildTemplateDisk(ctx, log, params.dockerImageName,
			params.diskSize, params.installer, dstDir)
	}
	keyParams := templateKeyParams{
		DockerImageID: params.dockerImageID,
		DiskBytes:     params.diskSize,
		Installer:     params.installer,
		Arch:          params.arch,
	}
	if params.liveImageSHA256 != "" {
		build = unpackLiveTemplate(params.liveTarPath, params.liveImageSHA256)
		if params.liveSource != nil {
			build = installLocalLiveTemplate(params.liveSource, params.liveImageSHA256)
		}
		keyParams = liveTemplateKeyParams(
			params.liveImageSHA256, params.arch, params.diskSize)
	}

	tmpl, err := cache.ensureTemplate(ctx, log, keyParams, build)
	if params.liveImageSHA256 != "" {
		// Removed on both success and failure: a tar that failed to install is
		// unusable and must not wedge this hash for every later request until the
		// broker restarts. Attempted even when the template came from the client's
		// own files, so an earlier run's upload of this same hash does not sit
		// there unclaimed. On a cache hit, or with no upload involved at all, no
		// tar was staged for this call, so the miss is expected and silent;
		// anything else is worth a warning.
		if rmErr := os.Remove(params.liveTarPath); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Warnf("Failed to remove staged live image upload %q: %v",
				params.liveTarPath, rmErr)
		}
	}
	if err != nil {
		return result, "", err
	}

	if err = os.MkdirAll(params.imageDirPath, 0o755); err != nil {
		return result, "", fmt.Errorf("failed to create device image dir %q: %w",
			params.imageDirPath, err)
	}
	// From here on the device dir and the template ref are both owned by the
	// caller's teardown path only once we return successfully.
	defer func() {
		if err != nil {
			if rmErr := os.RemoveAll(params.imageDirPath); rmErr != nil {
				log.Warnf("Failed to remove device image dir %q: %v",
					params.imageDirPath, rmErr)
			}
			if rmErr := cache.removeRef(tmpl.Key, refName); rmErr != nil {
				log.Warnf("Failed to release template ref: %v", rmErr)
			}
		}
	}()
	if err = cache.addRef(tmpl.Key, refName); err != nil {
		return result, "", err
	}

	diskPath := filepath.Join(params.imageDirPath, "disk.qcow2")
	if params.overlay {
		out, cmdErr := exec.CommandContext(ctx, "qemu-img", "create",
			"-f", "qcow2", "-b", tmpl.diskPath(), "-F", "qcow2", diskPath).CombinedOutput()
		if cmdErr != nil {
			err = fmt.Errorf("failed to create overlay %q: %v: %s", diskPath, cmdErr, out)
			return result, "", err
		}
	} else if err = utils.CopyFile(tmpl.diskPath(), diskPath); err != nil {
		err = fmt.Errorf("failed to copy template disk to %q: %w", diskPath, err)
		return result, "", err
	}
	// Only the live path needs this, and it needs it for a standalone copy just
	// as much as for an overlay: a live template is deliberately keyed without
	// the disk size (see liveTemplateKeyParams), so one template serves every
	// requested size and the per-device disk is what carries it. A template built
	// from the EVE container is already built at params.diskSize.
	if params.liveImageSHA256 != "" {
		if resizeErr := resizeDeviceDisk(ctx, diskPath,
			int64(params.diskSize), tmpl.Meta.DiskVirtualBytes); resizeErr != nil {
			err = resizeErr
			return result, "", err
		}
	}

	var configDir string
	configDir, err = makeEVEConfigDir(
		params.imageDirPath, params.config, params.proxyCACerts, params.softSerial)
	if err != nil {
		err = fmt.Errorf("failed to prepare EVE config dir: %w", err)
		return result, "", err
	}
	defer os.RemoveAll(configDir)

	// The config partition image is staged outside the device directory: its
	// path is passed through qemu-io's own tokenizer, and the device directory
	// name embeds a test-supplied device name.
	var cfgDir string
	cfgDir, err = os.MkdirTemp("", "evetest-cfgpart-*")
	if err != nil {
		err = fmt.Errorf("failed to create temp dir for the config partition: %w", err)
		return result, "", err
	}
	defer os.RemoveAll(cfgDir)
	cfgImgPath := filepath.Join(cfgDir, "config.img")
	if err = writeConfigPartition(ctx, log, tmpl.configImgPath(), configDir, cfgImgPath); err != nil {
		return result, "", err
	}
	if err = injectConfigPartition(ctx, log, diskPath, cfgImgPath, tmpl.configPartition()); err != nil {
		return result, "", err
	}

	// OVMF_VARS.fd is attached as libvirt NVRAM and written by the running VM,
	// so each device needs its own copy of the firmware directory.
	result.firmwareDir = filepath.Join(params.imageDirPath, templateFirmwareDir)
	if err = utils.CopyFolder(tmpl.firmwareDir(), result.firmwareDir); err != nil {
		err = fmt.Errorf("failed to copy UEFI firmware: %w", err)
		return result, "", err
	}

	if !params.installer {
		result.disks = []provider.DiskImage{
			{Format: provider.DiskImageFormatQcow2, Path: diskPath},
		}
		return result, tmpl.Key, nil
	}

	if params.diskSize == 0 {
		err = fmt.Errorf("diskSize must be non-zero for installer builds")
		return result, "", err
	}
	targetDiskPath := filepath.Join(params.imageDirPath, "installed.qcow2")
	diskSizeMiB := params.diskSize >> 20
	out, cmdErr := exec.CommandContext(ctx, "qemu-img", "create", "-f", "qcow2",
		targetDiskPath, fmt.Sprintf("%dM", diskSizeMiB)).CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("failed to create installer target disk %q: %v: %s",
			targetDiskPath, cmdErr, out)
		return result, "", err
	}
	installerImage := provider.DiskImage{
		Format: provider.DiskImageFormatQcow2, Path: diskPath}
	result.installerImage = &installerImage
	result.disks = []provider.DiskImage{
		{Format: provider.DiskImageFormatQcow2, Path: targetDiskPath},
	}
	return result, tmpl.Key, nil
}
