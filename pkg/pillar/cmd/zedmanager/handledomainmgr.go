// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

const (
	persistDir            = "/persist"
	objectDownloadDirname = persistDir + "/downloads"
	imgCatalogDirname     = objectDownloadDirname + "/" + appImgObj
	pendingDirname        = imgCatalogDirname + "/pending"
	verifierDirname       = imgCatalogDirname + "/verifier"
	finalDirname          = imgCatalogDirname + "/verified"
)

func MaybeAddDomainConfig(ctx *zedmanagerContext,
	aiConfig types.AppInstanceConfig,
	aiStatus *types.AppInstanceStatus,
	ns *types.AppNetworkStatus) error {

	key := aiConfig.Key()
	displayName := aiConfig.DisplayName
	log.Infof("MaybeAddDomainConfig for %s displayName %s\n", key,
		displayName)

	changed := false
	m := lookupDomainConfig(ctx, key)
	if m != nil {
		// XXX any other change? Compare nothing else changed?
		if m.Activate != aiConfig.Activate {
			log.Infof("Domain config: Activate changed %s\n", key)
			changed = true
		} else {
			log.Infof("Domain config already exists for %s\n", key)
		}
	} else {
		log.Infof("Domain config add for %s\n", key)
		changed = true
	}
	if !changed {
		log.Infof("MaybeAddDomainConfig done for %s\n", key)
		return nil
	}
	AppNum := 0
	if ns != nil {
		AppNum = ns.AppNum
	}

	dc := types.DomainConfig{
		UUIDandVersion:    aiConfig.UUIDandVersion,
		DisplayName:       aiConfig.DisplayName,
		Activate:          aiConfig.Activate,
		AppNum:            AppNum,
		IsContainer:       aiStatus.IsContainer,
		VmConfig:          aiConfig.FixedResources,
		IoAdapterList:     aiConfig.IoAdapterList,
		CloudInitUserData: aiConfig.CloudInitUserData,
		URL:               aiStatus.ContainerUrl,
	}

	// Determine number of "disk" targets in list
	numDisks := 0
	for _, sc := range aiConfig.StorageConfigList {
		if sc.Target == "" || sc.Target == "disk" {
			numDisks++
		} else {
			log.Infof("Not allocating disk for Target %s\n",
				sc.Target)
		}
	}
	dc.DiskConfigList = make([]types.DiskConfig, numDisks)
	i := 0
	for _, sc := range aiConfig.StorageConfigList {
		// Check that file is verified
		locationDir := finalDirname + "/" + sc.ImageSha256
		location, err := locationFromDir(locationDir)
		if err != nil {
			return err
		}
		switch sc.Target {
		case "", "disk":
			disk := &dc.DiskConfigList[i]
			disk.ImageSha256 = sc.ImageSha256
			disk.ReadOnly = sc.ReadOnly
			disk.Preserve = sc.Preserve
			disk.Format = sc.Format
			disk.Maxsizebytes = sc.Maxsizebytes
			disk.Devtype = sc.Devtype
			i++
		case "kernel":
			if dc.Kernel != "" {
				log.Infof("Overriding kernel %s with location %s\n",
					dc.Kernel, location)
			}
			dc.Kernel = location
		case "ramdisk":
			if dc.Ramdisk != "" {
				log.Infof("Overriding ramdisk %s with location %s\n",
					dc.Ramdisk, location)
			}
			dc.Ramdisk = location
		case "device_tree":
			if dc.DeviceTree != "" {
				log.Infof("Overriding device_tree %s with location %s\n",
					dc.DeviceTree, location)
			}
			dc.DeviceTree = location
		default:
			errStr := fmt.Sprintf("Unknown target %s for %s",
				sc.Target, displayName)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
	}
	if ns != nil {
		olNum := len(ns.OverlayNetworkList)
		ulNum := len(ns.UnderlayNetworkList)

		dc.VifList = make([]types.VifInfo, olNum+ulNum)
		// Put UL before OL
		for i, ul := range ns.UnderlayNetworkList {
			dc.VifList[i] = ul.VifInfo
		}
		for i, ol := range ns.OverlayNetworkList {
			dc.VifList[i+ulNum] = ol.VifInfo
		}
	}
	publishDomainConfig(ctx, &dc)

	log.Infof("MaybeAddDomainConfig done for %s\n", key)
	return nil
}

func lookupDomainConfig(ctx *zedmanagerContext, key string) *types.DomainConfig {

	pub := ctx.pubDomainConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupDomainConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastDomainConfig(c)
	if config.Key() != key {
		log.Errorf("lookupDomainConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupDomainStatus(ctx *zedmanagerContext, key string) *types.DomainStatus {
	sub := ctx.subDomainStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupDomainStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastDomainStatus(st)
	if status.Key() != key {
		log.Errorf("lookupDomainStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func publishDomainConfig(ctx *zedmanagerContext,
	status *types.DomainConfig) {

	key := status.Key()
	log.Debugf("publishDomainConfig(%s)\n", key)
	pub := ctx.pubDomainConfig
	pub.Publish(key, status)
}

func unpublishDomainConfig(ctx *zedmanagerContext, uuidStr string) {

	key := uuidStr
	log.Debugf("unpublishDomainConfig(%s)\n", key)
	pub := ctx.pubDomainConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishDomainConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func handleDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastDomainStatus(statusArg)
	ctx := ctxArg.(*zedmanagerContext)
	if status.Key() != key {
		log.Errorf("handleDomainStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	log.Infof("handleDomainStatusModify for %s\n", key)
	// Record DomainStatus.State even if Pending() to capture HALTING

	updateAIStatusUUID(ctx, status.Key())
	log.Infof("handleDomainStatusModify done for %s\n", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDomainStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusUUID(ctx, key)
	log.Infof("handleDomainStatusDelete done for %s\n", key)
}

func locationFromDir(locationDir string) (string, error) {
	if _, err := os.Stat(locationDir); err != nil {
		log.Errorf("Missing directory: %s, %s\n", locationDir, err)
		return "", err
	}
	// locationDir is a directory. Need to find single file inside
	// which the verifier ensures.
	locations, err := ioutil.ReadDir(locationDir)
	if err != nil {
		log.Errorln(err)
		return "", err
	}
	if len(locations) != 1 {
		log.Errorf("Multiple files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("Multiple files in %s\n",
			locationDir))
	}
	if len(locations) == 0 {
		log.Errorf("No files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("No files in %s\n",
			locationDir))
	}
	return locationDir + "/" + locations[0].Name(), nil
}
