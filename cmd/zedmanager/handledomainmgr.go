// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedmanager

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"os"
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
	aiConfig types.AppInstanceConfig, ns *types.AppNetworkStatus) error {

	key := aiConfig.Key()
	displayName := aiConfig.DisplayName
	log.Printf("MaybeAddDomainConfig for %s displayName %s\n", key,
		displayName)

	changed := false
	m := lookupDomainConfig(ctx, key)
	if m != nil {
		// XXX any other change? Compare nothing else changed?
		if m.Activate != aiConfig.Activate {
			log.Printf("Domain config: Activate changed %s\n", key)
			changed = true
		} else {
			log.Printf("Domain config already exists for %s\n", key)
		}
	} else {
		log.Printf("Domain config add for %s\n", key)
		changed = true
	}
	if !changed {
		log.Printf("MaybeAddDomainConfig done for %s\n", key)
		return nil
	}
	AppNum := 0
	if ns != nil {
		AppNum = ns.AppNum
	}

	dc := types.DomainConfig{
		UUIDandVersion: aiConfig.UUIDandVersion,
		DisplayName:    aiConfig.DisplayName,
		Activate:       aiConfig.Activate,
		AppNum:         AppNum,
		VmConfig:       aiConfig.FixedResources,
		IoAdapterList:  aiConfig.IoAdapterList,
	}

	// Determine number of "disk" targets in list
	numDisks := 0
	for _, sc := range aiConfig.StorageConfigList {
		if sc.Target == "" || sc.Target == "disk" {
			numDisks++
		} else {
			log.Printf("Not allocating disk for Target %s\n",
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
			disk.Devtype = sc.Devtype
			i++
		case "kernel":
			if dc.Kernel != "" {
				log.Printf("Overriding kernel %s with location %s\n",
					dc.Kernel, location)
			}
			dc.Kernel = location
		case "ramdisk":
			if dc.Ramdisk != "" {
				log.Printf("Overriding ramdisk %s with location %s\n",
					dc.Ramdisk, location)
			}
			dc.Ramdisk = location
		case "device_tree":
			if dc.DeviceTree != "" {
				log.Printf("Overriding device_tree %s with %s location %s\n",
					dc.DeviceTree, location)
			}
			dc.DeviceTree = location
		default:
			errStr := fmt.Sprintf("Unknown target %s for %s",
				sc.Target, displayName)
			log.Println(errStr)
			return errors.New(errStr)
		}
	}
	if ns != nil {
		dc.VifList = make([]types.VifInfo, ns.OlNum+ns.UlNum)
		// Put UL before OL
		for i, ul := range ns.UnderlayNetworkList {
			dc.VifList[i] = ul.VifInfo
		}
		for i, ol := range ns.OverlayNetworkList {
			dc.VifList[i+ns.UlNum] = ol.VifInfo
		}
	}
	publishDomainConfig(ctx, &dc)

	log.Printf("MaybeAddDomainConfig done for %s\n", key)
	return nil
}

func lookupDomainConfig(ctx *zedmanagerContext, key string) *types.DomainConfig {

	pub := ctx.pubDomainConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Printf("lookupDomainConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastDomainConfig(c)
	if config.Key() != key {
		log.Printf("lookupDomainConfig key/UUID mismatch %s vs %s; ignored %+v\n",
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
		log.Printf("lookupDomainStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastDomainStatus(st)
	if status.Key() != key {
		log.Printf("lookupDomainStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func publishDomainConfig(ctx *zedmanagerContext,
	status *types.DomainConfig) {

	key := status.Key()
	log.Printf("publishDomainConfig(%s)\n", key)
	pub := ctx.pubDomainConfig
	pub.Publish(key, status)
}

func unpublishDomainConfig(ctx *zedmanagerContext, uuidStr string) {

	key := uuidStr
	log.Printf("unpublishDomainConfig(%s)\n", key)
	pub := ctx.pubDomainConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Printf("unpublishDomainConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func handleDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastDomainStatus(statusArg)
	ctx := ctxArg.(*zedmanagerContext)
	if status.Key() != key {
		log.Printf("handleDomainStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	log.Printf("handleDomainStatusModify for %s\n", key)
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Printf("handleDomainstatusModify skipped due to Pending* for %s\n",
			key)
		return
	}
	updateAIStatusUUID(ctx, status.Key())
	log.Printf("handleDomainStatusModify done for %s\n", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleDomainStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusUUID(ctx, key)
	log.Printf("handleDomainStatusDelete done for %s\n", key)
}

func locationFromDir(locationDir string) (string, error) {
	if _, err := os.Stat(locationDir); err != nil {
		log.Printf("Missing directory: %s, %s\n", locationDir, err)
		return "", err
	}
	// locationDir is a directory. Need to find single file inside
	// which the verifier ensures.
	locations, err := ioutil.ReadDir(locationDir)
	if err != nil {
		log.Println(err)
		return "", err
	}
	if len(locations) != 1 {
		log.Printf("Multiple files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("Multiple files in %s\n",
			locationDir))
	}
	if len(locations) == 0 {
		log.Printf("No files in %s\n", locationDir)
		return "", errors.New(fmt.Sprintf("No files in %s\n",
			locationDir))
	}
	return locationDir + "/" + locations[0].Name(), nil
}
