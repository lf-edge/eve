// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"encoding/base64"
	"fmt"
	"path"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/evetest"
	uuid "github.com/satori/go.uuid"
)

// vmImage is a pinned Alpine cloud-init qcow2 image for the VM app.
type vmImage struct {
	url       string
	sha256    string
	sizeBytes uint64
}

// Alpine 3.24.1 cloud images, the ones tests/security/vcom_test.go boots. amd64
// takes the BIOS variant because pillar attaches UEFI firmware on amd64 only for
// VmMode_FML, and this VM is HVM; arm64 always gets UEFI.
var vmImages = map[string]vmImage{
	"amd64": {
		url:       "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2",
		sha256:    "6e2e6fe0572b6632527f268d3659e8fccebda4e1ee470fafe2c4d7b85b6a4df6",
		sizeBytes: 183697408,
	},
	"arm64": {
		url:       "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-aarch64-uefi-cloudinit-r0.qcow2",
		sha256:    "3059a6280977c2122982632e0317c5ddbd39069d46ca1e60480de283091f720f",
		sizeBytes: 239271936,
	},
}

// vmAuth logs into the VM app; vmCloudConfig enables it.
var vmAuth = evetest.UsernamePasswordAuth{Username: "root", Password: "testpassword"}

var vmCloudConfig = fmt.Sprintf(`#cloud-config
ssh_pwauth: true
chpasswd:
  list: |
    root:%s
  expire: false
write_files:
  - path: /etc/ssh/sshd_config.d/99-allow-root-password.conf
    content: |
      PermitRootLogin yes
runcmd:
  - rc-service sshd restart
`, vmAuth.Password)

// vmMarkerPath is where the VM app's marker lives, on its boot disk.
const vmMarkerPath = "/root/konvert-marker"

// addTestVM adds an Alpine VM app on niUUID. Its image is fetched by the harness
// and served from the image server, so the device needs no Internet access, and
// becomes the app's boot disk: a downloaded, non-container volume.
func addTestVM(t Gomega, device *evetest.EdgeDevice, devConfig *evetest.EdgeDeviceConfig,
	displayName string, niUUID uuid.UUID) uuid.UUID {
	image, ok := vmImages[device.GetArch()]
	t.Expect(ok).To(BeTrue(), "no VM image for arch %s", device.GetArch())
	served := evetest.FetchAndServeImageFile(image.url, path.Base(image.url), image.sha256)
	return devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: displayName,
		Activate:    true,
		Image: evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_QCOW2,
			ImageSHA256:       image.sha256,
			MaxDownloadBytes:  image.sizeBytes,
			ImageRelativePath: served,
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerPort(),
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		UserData:           base64.StdEncoding.EncodeToString([]byte(vmCloudConfig)),
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				ACLAllowRules: []evetest.ACLAllowRule{
					{Protocol: evetest.NetworkProtocolAny, RemoteSubnet: evetest.IPSubnet("0.0.0.0/0")},
				},
			},
		},
	})
}

// assertVMReady waits for the VM app to run and then to answer SSH, which takes
// cloud-init's first-boot pass on top of the boot.
func assertVMReady(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	runningTimeout time.Duration) {
	device.WaitUntilAppIsRunning(appUUID, runningTimeout)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, vmAuth, "hostname", sshTimeout, 0)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).NotTo(BeEmpty())
	}, 8*time.Minute, 10*time.Second).Should(Succeed())
}

// writeVMMarker writes marker onto the VM app's boot disk and flushes it.
func writeVMMarker(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, marker string) {
	script := fmt.Sprintf("echo %q > %s && sync && echo WROTE-OK", marker, vmMarkerPath)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, vmAuth, script, 60*time.Second, 0)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring("WROTE-OK"))
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

// assertVMMarker asserts marker is still on the VM app's boot disk. The guest
// mounts its own root, so unlike a container data volume there is no mount to
// be missing.
func assertVMMarker(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID, marker string) {
	script := fmt.Sprintf("grep -qxF %q %s && echo MARKER-OK || { echo MARKER-LOST; cat %s; exit 1; }",
		marker, vmMarkerPath, vmMarkerPath)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, vmAuth, script, 60*time.Second, 0)
		g.Expect(err).NotTo(HaveOccurred(), "VM marker %q lost:\n%s", marker, out)
		g.Expect(out).To(ContainSubstring("MARKER-OK"))
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
}

// vmAppParameter declares whether VolumeMigration also carries a VM app.
func vmAppParameter() evetest.TestParameterDefinition {
	return evetest.TestParameterDefinition{
		Key:          vmAppParamKey,
		DefaultValue: true,
		Description: evetest.TestParameterDescription{
			Summary: "Also carry an Alpine VM app, whose boot disk is a downloaded qcow2",
			Default: "true",
		},
	}
}
