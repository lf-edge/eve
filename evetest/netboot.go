// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/utils"
	"google.golang.org/protobuf/proto"
)

const netbootArtifactBuildTimeout = 15 * time.Minute

// buildNetbootArtifacts builds the same artifact bundle that `make
// installer-net` produces (see docs/BOOT-INSTALLER.md's "PXE" section and
// pkg/eve/runme.sh's do_installer_net) for dev's target EVE image, with the
// device's onboarding cert/bootstrap config/grub options injected via the
// "/in" volume mount, and stages it at the harness's own image server root.
// This runs in the main evetest process rather than through the broker,
// using the local Docker daemon directly.
//
// The whole bundle -- including installer.iso -- is shared by every
// CreateFromScratchWithNetworkBoot device in the test, called once for a
// representative device (see Setup): they all share one onboarding
// certificate (see prepareEVEDeviceForOnboarding) and are told apart only by
// their hardware serial number, exactly like production iPXE deployments, so
// there is nothing left to make installer.iso device-specific. Devices are
// required to share the same EVE image/config too (see
// verifyNetbootDeviceMatches).
func (th *TestHarness) buildNetbootArtifacts(dev *deviceState) {
	ctx, cancel := context.WithTimeout(th.ctx, netbootArtifactBuildTimeout)
	defer cancel()
	logger := th.log.WithField("component", "netboot")

	if err := utils.PullDockerImage(ctx, logger, dev.imageName); err != nil {
		th.t.Fatalf("Failed to pull EVE image %s for netboot artifacts: %v",
			dev.imageName, err)
	}

	archStr := "amd64"
	if dev.imageRef.GetArch() == api.ArchType_ARCH_ARM64 {
		archStr = "arm64"
	}
	platform := "linux/" + archStr

	configDir, err := utils.MakeEVEConfigDir(
		th.imgServerDir, th.buildEveConfig(dev), nil, "")
	if err != nil {
		th.t.Fatalf("Failed to prepare EVE config dir for netboot artifacts: %v", err)
	}
	if configDir != "" {
		defer func() {
			if err := os.RemoveAll(configDir); err != nil {
				th.log.Warnf("Failed to remove config dir %s: %v", configDir, err)
			}
		}()
	}

	th.log.Infof("Building netboot artifacts from %s", dev.imageName)
	volumeMap := map[string]string{"/out": th.imgServerDir}
	if configDir != "" {
		volumeMap["/in"] = configDir
	}
	if _, err := utils.RunDockerCommand(ctx, logger, dev.imageName, "installer_net",
		volumeMap, platform); err != nil {
		th.t.Fatalf("Failed to build the installer_net bundle from %s: %v",
			dev.imageName, err)
	}

	bundleTar := filepath.Join(th.imgServerDir, "installer.net")
	f, err := os.Open(bundleTar)
	if err != nil {
		th.t.Fatalf("Failed to open the built installer.net bundle %s: %v",
			bundleTar, err)
	}
	if err := utils.ExtractFromTar(f, th.imgServerDir); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			th.log.Warnf("Failed to close netboot tar file %s: %v", bundleTar, closeErr)
		}
		th.t.Fatalf("Failed to extract the installer.net bundle into %s: %v",
			th.imgServerDir, err)
	}
	if closeErr := f.Close(); closeErr != nil {
		th.log.Warnf("Failed to close netboot tar file %s: %v", bundleTar, closeErr)
	}
	if err := os.Remove(bundleTar); err != nil {
		th.t.Fatalf("Failed to remove extracted bundle tar %s: %v", bundleTar, err)
	}

	if _, err := findGrubEFIName(th.imgServerDir); err != nil {
		th.t.Fatalf("%v", err)
	}
	if err := setIpxeScriptURL(th.imgServerDir); err != nil {
		th.t.Fatalf("%v", err)
	}
	if err := switchGrubCfgInstallerToHTTP(th.imgServerDir); err != nil {
		th.t.Fatalf("%v", err)
	}

	th.log.Infof("Netboot artifacts for %s staged at %s", dev.imageName, th.imgServerDir)
}

// verifyNetbootDeviceMatches fatals unless dev requests the same EVE image
// and configuration as ref, the device buildNetbootArtifacts was already run
// for. All CreateFromScratchWithNetworkBoot devices in a test share one
// artifact bundle (including installer.iso) and one onboarding certificate,
// so they cannot differ in image version or injected configuration.
func (th *TestHarness) verifyNetbootDeviceMatches(ref, dev *deviceState) {
	if dev.imageName != ref.imageName {
		th.t.Fatalf("Device %q requests EVE image %q, but netboot artifacts "+
			"were already built for device %q using image %q -- all "+
			"CreateFromScratchWithNetworkBoot devices in a test must use "+
			"the same EVE image", dev.name, dev.imageName, ref.name, ref.imageName)
	}
	if !proto.Equal(th.buildEveConfig(ref), th.buildEveConfig(dev)) {
		th.t.Fatalf("Device %q requests a different EVE configuration than "+
			"netboot device %q -- all CreateFromScratchWithNetworkBoot "+
			"devices in a test must use the same configuration (grub "+
			"options, bootstrap config, injected properties, etc.)",
			dev.name, ref.name)
	}
}

// ipxeScriptFilename is EVE's boot script inside the extracted netboot
// bundle. dnsmasq always answers DHCP with ipxe.efi itself as the boot
// filename (see sdn/vm/pkg/configitems/dhcpSrv.go), including ipxe.efi's own
// re-DHCP once it boots; ipxe.efi's embedded script (pkg/ipxe/embedded.cfg)
// is what derives and chainloads "${filename}.cfg" from there, landing on
// this file.
const ipxeScriptFilename = "ipxe.efi.cfg"

// setIpxeScriptURL prepends a "set url ..." line to the extracted
// ipxe.efi.cfg, pointing every chainload it performs (EFI/BOOT/BOOTX64.EFI
// and on) at the image server's root. The stock script ships with no
// "set url ..." of its own -- docs/DEPLOYMENT.md documents editing this
// line by hand as a deployment step; this does the same edit
// programmatically.
func setIpxeScriptURL(imgServerDir string) error {
	scriptPath := filepath.Join(imgServerDir, ipxeScriptFilename)
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", scriptPath, err)
	}
	shebang, rest, ok := bytes.Cut(content, []byte("\n"))
	if !ok || string(shebang) != "#!ipxe" {
		return fmt.Errorf("%s does not start with the expected #!ipxe shebang",
			scriptPath)
	}
	url := fmt.Sprintf("tftp://%s/", GetImageServerIPv4())
	var patched bytes.Buffer
	patched.Write(shebang)
	patched.WriteString("\nset url ")
	patched.WriteString(url)
	patched.WriteByte('\n')
	patched.Write(rest)
	if err := os.WriteFile(scriptPath, patched.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write patched %s: %w", scriptPath, err)
	}
	return nil
}

// switchGrubCfgInstallerToHTTP patches EFI/BOOT/grub.cfg in place, prepending
// a "set cmddevice=http,<image-server-ip>" line so grub fetches installer.iso
// over HTTP instead of TFTP.
func switchGrubCfgInstallerToHTTP(imgServerDir string) error {
	path := filepath.Join(imgServerDir, "EFI", "BOOT", "grub.cfg")
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	patched := append(
		[]byte(fmt.Sprintf("set cmddevice=http,%s\n", GetImageServerIPv4())), content...)
	if err := os.WriteFile(path, patched, 0644); err != nil {
		return fmt.Errorf("failed to write patched %s: %w", path, err)
	}
	return nil
}

// findGrubEFIName returns the basename of the single arch-specific
// EFI/BOOT/BOOT*.EFI grub bootloader inside an extracted installer.net bundle
// (e.g. BOOTX64.EFI, BOOTAA64.EFI). Only used to fail fast with a clear error
// if the bundle turns out not to contain it; ipxe.efi.cfg itself already
// picks the right name at runtime based on ${buildarch}.
func findGrubEFIName(bundleDir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(bundleDir, "EFI", "BOOT", "BOOT*.EFI"))
	if err != nil {
		return "", fmt.Errorf("failed to glob for the grub EFI bootloader: %w", err)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf(
			"expected exactly one EFI/BOOT/BOOT*.EFI file in %s, found %d",
			bundleDir, len(matches))
	}
	return filepath.Base(matches[0]), nil
}
