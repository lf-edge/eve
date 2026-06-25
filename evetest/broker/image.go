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
	"strings"

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
}

// buildEVEImageResult holds the outputs of buildEVEImage (excluding the error).
type buildEVEImageResult struct {
	// installerImage is non-nil only for installer builds. It points to the RAW
	// installer image that is prepended to disks for the first (installer) boot,
	// then discarded — subsequent boots use only disks.
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
		params.imageDirPath, params.config, params.proxyCACerts)
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
func makeEVEConfigDir(parentDir string,
	config *api.EveConfig, proxyCACerts []*pem.Block) (dirPath string, err error) {

	if config == nil && len(proxyCACerts) == 0 {
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

	err = writeFile("server", []byte(config.ServerName))
	if err != nil {
		return "", err
	}
	err = writeFile("soft_serial", []byte(config.SoftSerial))
	if err != nil {
		return "", err
	}

	if len(config.OnboardCertPem) > 0 {
		_, err = utils.ValidatePEMCerts([]byte(config.OnboardCertPem), true)
		if err != nil {
			return "", fmt.Errorf("onboard certificate invalid: %w", err)
		}
		err = writeFile("onboard.cert.pem", []byte(config.OnboardCertPem))
		if err != nil {
			return "", err
		}
	}
	if len(config.OnboardKeyPem) > 0 {
		err = utils.ValidatePEMPrivateKeyECDSA([]byte(config.OnboardKeyPem))
		if err != nil {
			return "", fmt.Errorf("onboard key invalid: %w", err)
		}
		err = writeFile("onboard.key.pem", []byte(config.OnboardKeyPem))
		if err != nil {
			return "", err
		}
	}

	if len(config.RootCertPem) > 0 {
		_, err = utils.ValidatePEMCerts([]byte(config.RootCertPem), true)
		if err != nil {
			return "", fmt.Errorf("root certificate invalid: %w", err)
		}
		err = writeFile("root-certificate.pem", []byte(config.RootCertPem))
		if err != nil {
			return "", err
		}
	}

	// Handle V2 TLS certs and append proxy CA certs
	var certDataBuilder strings.Builder
	writeV2TLS := false

	// Validate and append V2TlsCertsPem
	for _, pemStr := range config.V2TlsCertsPem {
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

	if len(config.SshKeys) > 0 {
		keysData := strings.Join(config.SshKeys, "\n")
		err = writeFile("authorized_keys", []byte(keysData))
		if err != nil {
			return "", err
		}
	}

	if len(config.GrubOptions) > 0 {
		grubConfig := strings.Join(config.GrubOptions, "\n")
		err = writeFile("grub.cfg", []byte(grubConfig))
		if err != nil {
			return "", err
		}
	}

	err = writeFile("GlobalConfig/global.json", []byte(config.GlobalJson))
	if err != nil {
		return "", err
	}
	err = writeFile("DevicePortConfig/override.json", []byte(config.OverrideJson))
	if err != nil {
		return "", err
	}
	if len(config.BootstrapConfigPb) > 0 {
		err = writeFile("bootstrap-config.pb", config.BootstrapConfigPb)
		if err != nil {
			return "", err
		}
	}

	return dirPath, nil
}
