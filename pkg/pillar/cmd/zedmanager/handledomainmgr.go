// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// MaybeAddDomainConfig makes sure we have a DomainConfig
// Note that it does not publish it since caller often tweaks it; caller must
// call publishDomainConfig() when done with tweaks.
func MaybeAddDomainConfig(ctx *zedmanagerContext,
	aiConfig types.AppInstanceConfig,
	aiStatus types.AppInstanceStatus,
	ns *types.AppNetworkStatus) (*types.DomainConfig, error) {

	key := aiConfig.Key()
	displayName := aiConfig.DisplayName
	log.Functionf("MaybeAddDomainConfig for %s displayName %s", key,
		displayName)

	m := lookupDomainConfig(ctx, key)
	if m != nil {
		// Always update to pick up new disks, vifs, Activate etc
		log.Functionf("Domain config already exists for %s", key)
	} else {
		log.Functionf("Domain config add for %s", key)
	}
	AppNum := 0
	if ns != nil {
		AppNum = ns.AppNum
	}

	dc := types.DomainConfig{
		UUIDandVersion:    aiConfig.UUIDandVersion,
		DisplayName:       aiConfig.DisplayName,
		Activate:          aiStatus.EffectiveActivate,
		AppNum:            AppNum,
		VmConfig:          aiConfig.FixedResources,
		IoAdapterList:     aiConfig.IoAdapterList,
		CloudInitUserData: aiConfig.CloudInitUserData,
		CipherBlockStatus: aiConfig.CipherBlockStatus,
		GPUConfig:         "legacy",
		MetaDataType:      aiConfig.MetaDataType,
	}

	dc.DiskConfigList = make([]types.DiskConfig, 0, len(aiStatus.VolumeRefStatusList))
	for _, vrc := range aiConfig.VolumeRefConfigList {
		vrs := getVolumeRefStatusFromAIStatus(&aiStatus, vrc)
		if vrs == nil {
			log.Errorf("Missing VolumeRefStatus for (VolumeID: %s, GenerationCounter: %d)",
				vrc.VolumeID, vrc.GenerationCounter)
			continue
		}
		location := vrs.ActiveFileLocation
		if location == "" {
			errStr := fmt.Sprintf("No ActiveFileLocation for %s", vrs.DisplayName)
			log.Error(errStr)
			return nil, errors.New(errStr)
		}
		disk := types.DiskConfig{}
		disk.VolumeKey = vrs.Key()
		disk.FileLocation = location
		disk.ReadOnly = vrs.ReadOnly
		disk.Format = vrs.ContentFormat
		disk.MountDir = vrs.MountDir
		disk.DisplayName = vrs.DisplayName
		dc.DiskConfigList = append(dc.DiskConfigList, disk)
	}
	// let's fill some of the default values (arguably we may want controller
	// to do this for us and give us complete config, but it is easier to
	// fudge DomainConfig for now on our side)
	if dc.BootLoader == "/usr/bin/pygrub" {
		// FIXME: pygrub is deprecated but the controller keeps sending it to us
		// This hack means that the user won't be able to set pygrub explicitly,
		// but nobody in their right mind should do it anyway.
		dc.BootLoader = ""
	}
	if dc.GetOCIConfigDir() != "" {
		if dc.Kernel == "" {
			dc.Kernel = "/hostfs/boot/kernel"
		}
		if dc.Ramdisk == "" {
			dc.Ramdisk = "/usr/lib/xen/boot/runx-initrd"
		}
		if dc.ExtraArgs == "" {
			dc.ExtraArgs = "console=hvc0 root=9p dhcp=1"
		}
		if dc.EnableVnc {
			dc.ExtraArgs += " console=tty0"
		} else {
			dc.GPUConfig = ""
		}
		if dc.BootLoader == "" {
			if runtime.GOARCH == "amd64" {
				dc.BootLoader = "/usr/lib/xen/boot/seabios.bin"
			} else {
				dc.BootLoader = "/usr/lib/xen/boot/ovmf.bin"
			}
		}
	}
	if dc.BootLoader == "" && (dc.VirtualizationModeOrDefault() == types.FML || runtime.GOARCH == "arm64") {
		dc.BootLoader = "/usr/lib/xen/boot/ovmf.bin"
	}
	if ns != nil {
		ulNum := len(ns.UnderlayNetworkList)

		dc.VifList = make([]types.VifInfo, ulNum)
		// Put UL before OL
		for i, ul := range ns.UnderlayNetworkList {
			dc.VifList[i] = ul.VifInfo
		}
	}
	log.Functionf("MaybeAddDomainConfig done for %s", key)
	return &dc, nil
}

func lookupDomainConfig(ctx *zedmanagerContext, key string) *types.DomainConfig {

	pub := ctx.pubDomainConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupDomainConfig(%s) not found", key)
		return nil
	}
	config := c.(types.DomainConfig)
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupDomainStatus(ctx *zedmanagerContext, key string) *types.DomainStatus {
	sub := ctx.subDomainStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Tracef("lookupDomainStatus(%s) not found", key)
		return nil
	}
	status := st.(types.DomainStatus)
	return &status
}

func publishDomainConfig(ctx *zedmanagerContext,
	status *types.DomainConfig) {

	key := status.Key()
	log.Tracef("publishDomainConfig(%s)", key)
	pub := ctx.pubDomainConfig
	pub.Publish(key, *status)
}

func unpublishDomainConfig(ctx *zedmanagerContext, uuidStr string) {

	key := uuidStr
	log.Tracef("unpublishDomainConfig(%s)", key)
	pub := ctx.pubDomainConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishDomainConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func handleDomainStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDomainStatusImpl(ctxArg, key, statusArg)
}

func handleDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDomainStatusImpl(ctxArg, key, statusArg)
}

func handleDomainStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.DomainStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Functionf("handleDomainStatusImpl for %s", key)
	// Record DomainStatus.State even if Pending() to capture HALTING

	updateAIStatusUUID(ctx, status.Key())
	log.Functionf("handleDomainStatusImpl done for %s", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleDomainStatusDelete for %s", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusUUID(ctx, key)
	log.Functionf("handleDomainStatusDelete done for %s", key)
}
