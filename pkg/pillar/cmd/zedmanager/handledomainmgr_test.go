// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"testing"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
)

func TestSetBootDefaults(t *testing.T) {
	ctr := []types.DiskConfig{{Format: zconfig.Format_CONTAINER}}
	vm := []types.DiskConfig{{Format: zconfig.Format_QCOW2}}
	tests := []struct {
		name, arch            string
		disks                 []types.DiskConfig
		mode                  types.VmMode
		boot, ramdisk         string
		wantBoot, wantRamdisk string
	}{
		{"legacy Xen SeaBIOS path", "amd64", ctr, types.HVM, "/usr/lib/xen/boot/seabios.bin", "", LegacyBIOS, RunxInitrd},
		{"legacy SeaBIOS path", "amd64", vm, types.HVM, "/usr/share/qemu-xen/qemu/bios-256k.bin", "", LegacyBIOS, ""},
		{"legacy ovmf-pvh.bin path", "amd64", vm, types.HVM, "/usr/lib/xen/boot/ovmf-pvh.bin", "", OVMFBIOSCombined, ""},
		{"legacy ovmf.bin path", "arm64", vm, types.HVM, "/usr/lib/xen/boot/ovmf.bin", "", OVMFBIOSCombined, ""},
		{"legacy OVMF_CODE path", "amd64", vm, types.FML, "/usr/lib/xen/boot/OVMF_CODE.fd", "", OVMFBIOSCode, ""},
		{"legacy runx-initrd path", "amd64", ctr, types.HVM, "", "/usr/lib/xen/boot/runx-initrd", LegacyBIOS, RunxInitrd},
		{"unknown paths kept", "amd64", vm, types.HVM, "/persist/fw.fd", "/persist/rd", "/persist/fw.fd", "/persist/rd"},
		{"pygrub dropped", "amd64", vm, types.HVM, "/usr/bin/pygrub", "", "", ""},
		{"container on amd64", "amd64", ctr, types.HVM, "", "", LegacyBIOS, RunxInitrd},
		{"container on arm64", "arm64", ctr, types.HVM, "", "", OVMFBIOSCombined, RunxInitrd},
		{"FML VM", "amd64", vm, types.FML, "", "", OVMFBIOSCode, ""},
		{"HVM VM on amd64 boots QEMU's own BIOS", "amd64", vm, types.HVM, "", "", "", ""},
		{"HVM VM on arm64", "arm64", vm, types.HVM, "", "", OVMFBIOSCombined, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := types.DomainConfig{
				DiskConfigList: tt.disks,
				VmConfig: types.VmConfig{
					VirtualizationMode: tt.mode,
					BootLoader:         tt.boot,
					Ramdisk:            tt.ramdisk,
				},
			}
			setBootDefaults(&dc, tt.arch)
			assert.Equal(t, tt.wantBoot, dc.BootLoader)
			assert.Equal(t, tt.wantRamdisk, dc.Ramdisk)
		})
	}
}
