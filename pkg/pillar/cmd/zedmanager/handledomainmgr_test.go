// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"testing"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
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

// TestMaybeAddDomainConfigTakesCurrentImageName checks where a native
// container's image name comes from. On EVE-k doActivate holds the app
// until volumemgr's VolumeRefStatus names the image, which volumemgr does
// only once the content tree has its digest, possibly after the volume
// was created. The copy of that status in the AppInstanceStatus stops
// following volumemgr once the volumes are created, so it can still have
// no name when the hold is released: the DomainConfig must take the name
// from the VolumeRefStatus that doActivate waited on.
func TestMaybeAddDomainConfigTakesCurrentImageName(t *testing.T) {
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	volumeID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	const imageName = "docker.io/33333333-3333-3333-3333-333333333333-" +
		"lfedge/evetest-logger-ctr@sha256:" +
		"9e27c1d1bdf65a0d6a4aa0f4c7cd7d0b5b8e2e5c2a6b0f86a3c1f8e9d7b6a5c4"

	current := types.VolumeRefStatus{
		VolumeID:           volumeID,
		AppUUID:            appUUID,
		State:              types.CREATED_VOLUME,
		ActiveFileLocation: "/persist/vault/volumes/test",
		ContentFormat:      zconfig.Format_CONTAINER,
		ReferenceName:      imageName,
	}
	ctx := newDoInstallTestContext(t, []types.VolumeRefStatus{current})
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.DomainStatus{},
	})
	assert.NoError(t, err)
	assert.NoError(t, subDomainStatus.Activate())
	ctx.subDomainStatus = subDomainStatus

	config := types.AppInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID, Version: "1"},
		FixedResources: types.VmConfig{VirtualizationMode: types.NOHYPER},
		VolumeRefConfigList: []types.VolumeRefConfig{
			{VolumeID: volumeID, AppUUID: appUUID},
		},
	}
	copied := current
	copied.ReferenceName = ""
	status := types.AppInstanceStatus{
		UUIDandVersion:      config.UUIDandVersion,
		State:               types.START_DELAYED,
		VolumeRefStatusList: []types.VolumeRefStatus{copied},
	}

	dc, err := MaybeAddDomainConfig(ctx, config, status, nil)
	if assert.NoError(t, err) {
		assert.Equal(t, imageName, dc.KubeImageName)
	}
}
