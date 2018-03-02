// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// go-provision baseOs partition table management routines

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"os"
	"time"
)


// Partition Map Management routines

// read from the map file, for a partition
func readPartitionInfo(partName string) *types.PartitionInfo {

	validatePartitionName(partName)

	mapFilename := configDir + "/" + partName + ".json"
	if _, err := os.Stat(mapFilename); err != nil {
		return nil
	}

	bytes, err := ioutil.ReadFile(mapFilename)
	if err != nil {
		return nil
	}

	partInfo := &types.PartitionInfo{}
	if err := json.Unmarshal(bytes, partInfo); err != nil {
		return nil
	}
	return partInfo
}

// its always the other partition
// write to map file, for a partition
func writePartitionInfo(partName string,
			 partInfo *types.PartitionInfo) error {

	validatePartitionName(partName)

	mapFilename := configDir + "/" + partName + ".json"

	bytes, err := json.Marshal(partInfo)
	if err != nil {
		errStr := fmt.Sprintf("%s, marshalling error %s\n", partName, err)
		log.Println(errStr)
		return errors.New(errStr)
	}

	log.Println(partInfo)

	if err := ioutil.WriteFile(mapFilename, bytes, 0644); err != nil {
		errStr := fmt.Sprintf("%s, file write error %s\n", partName, err)
		log.Println(errStr)
		return errors.New(errStr)
	}
	return nil
}

// delete the map file, for a partition
// its always the other partition
func deletePartitionInfo(partName string) {

	validatePartitionName(partName)
	if !isOtherPartition(partName) {
		return
	}

	mapFilename := configDir + "/" + partName + ".json"
	if err := os.Remove(mapFilename); err != nil {
		log.Printf("%v for %s\n", err, mapFilename)
	}
}

// read current partition map
func readCurrentPartitionInfo() *types.PartitionInfo {
	partName := getCurrentPartition()
	return readPartitionInfo(partName)
}

// read other partition map
func readOtherPartitionInfo() *types.PartitionInfo {
	partName := getOtherPartition()
	return readPartitionInfo(partName)
}

// write to current partition map
func writeCurrentPartitionInfo(partInfo *types.PartitionInfo) error {
	partName := getCurrentPartition()
	return writePartitionInfo(partName, partInfo)
}

// write to other partition map
func writeOtherPartitionInfo(partInfo *types.PartitionInfo) error {
	partName := getOtherPartition()
	return writePartitionInfo(partName, partInfo)
}

// reset the parition map info
// adjust the base os config/status files
// always other partition
func clearPartitionMap(partName string, partInfo *types.PartitionInfo) bool {

	validatePartitionName(partName)

	if !isOtherPartition(partName) {
		return false
	}

	otherPartInfo := readOtherPartitionInfo()
	if otherPartInfo == nil {
		return false
	}

	// if same UUID, return
	if partInfo != nil &&
		partInfo.UUIDandVersion == otherPartInfo.UUIDandVersion {
		return true
	}

	// old map entry, nuke it
	uuidStr := otherPartInfo.UUIDandVersion.UUID.String()

	// find the baseOs config/status map entries
	// reset the partition information
	config := baseOsConfigGet(uuidStr)
	if config != nil {
		log.Printf("%s, reset old config\n", uuidStr)
		configFilename := zedagentBaseOsConfigDirname +
			"/" + uuidStr + ".json"
		config.PartitionLabel = ""
		for _, sc := range config.StorageConfigList {
			sc.FinalObjDir = ""
		}
		writeBaseOsConfig(config, configFilename)
	}

	// and mark status as DELIVERED
	status := baseOsStatusGet(uuidStr)
	if status != nil {
		log.Printf("%s, reset old status\n", uuidStr)
		statusFilename := zedagentBaseOsStatusDirname +
			"/" + uuidStr + ".json"
		status.State = types.DELIVERED
		errStr := fmt.Sprintf("uninstalled from %s",
			otherPartInfo.PartitionLabel)
		status.Error = errStr
		status.ErrorTime = time.Now()
		status.PartitionLabel = ""
		writeBaseOsStatus(status, statusFilename)
	}

	deletePartitionInfo(partName)
	return false
}

// get the partition map for a baseOS
func getPersistentPartitionInfo(uuidStr string, imageSha256 string) *types.PartitionInfo {

	var isCurrentPart, isOtherPart bool

	curPartInfo := readCurrentPartitionInfo()
	otherPartInfo := readOtherPartitionInfo()

	if curPartInfo != nil {
		curUuidStr := curPartInfo.UUIDandVersion.UUID.String()
		if curUuidStr == uuidStr {
			isCurrentPart = true
		} else {
			if imageSha256 != "" &&
				imageSha256 == curPartInfo.ImageSha256 {
				isCurrentPart = true
			}
		}
	}

	if otherPartInfo != nil {
		otherUuidStr := otherPartInfo.UUIDandVersion.UUID.String()
		if otherUuidStr == uuidStr {
			isOtherPart = true
		} else {
			if imageSha256 != "" &&
				imageSha256 == otherPartInfo.ImageSha256 {
				isOtherPart = true
			}
		}
	}

	if isCurrentPart == true &&
		isCurrentPart == isOtherPart {
		log.Fatal("same baseOs %s, on both Partitions\n", uuidStr)
	}

	if isCurrentPart == true {
		return curPartInfo
	}

	if isOtherPart == true {
		return otherPartInfo
	}
	return nil
}

// set/create the partition map for a baseOs
// always the other partition
func setPersistentPartitionInfo(uuidStr string, config types.BaseOsConfig,
		 status *types.BaseOsStatus) error {

	partName := config.PartitionLabel
	log.Printf("%s, set partition %s\n", uuidStr, partName)

	if ret := isOtherPartition(partName); ret == false {
		errStr := fmt.Sprintf("%s: not other partition", partName)
		log.Println(errStr)
		return errors.New(errStr)
	}

	// new partition mapping
	partInfo := &types.PartitionInfo{}
	partInfo.UUIDandVersion = config.UUIDandVersion
	partInfo.ImageSha256 = baseOsGetImageSha(config)
	partInfo.BaseOsVersion = config.BaseOsVersion
	partInfo.PartitionLabel = partName
	partInfo.State = status.State
	partInfo.RetryCount = config.RetryCount

	// replicate Error Info
	if !status.ErrorTime.IsZero() {
		partInfo.Error = status.Error
		partInfo.ErrorTime = status.ErrorTime
	}

	// set these values in BaseOs status
	status.PartitionDevice = getPartitionDevname(partName)
	status.PartitionState = getPartitionState(partName)

	// remove old partition mapping
	if match := clearPartitionMap(partName, nil); match == true {
		log.Printf("Updating existing Partition Map Status %s\n", partName)
	}

	// XXX:FIXME, Take care of retry count
	return writeOtherPartitionInfo(partInfo)
}

// reset the partition map for a baseOs
// always the other partition
func resetPersistentPartitionInfo(uuidStr string) error {

	log.Printf("%s, reset partition\n", uuidStr)
	config := baseOsConfigGet(uuidStr)
	if config == nil {
		errStr := fmt.Sprintf("%s, config absent\n", uuidStr)
		err := errors.New(errStr)
		return err
	}

	if isOtherPartition(config.PartitionLabel) {
		clearPartitionMap(config.PartitionLabel, nil)
	}
	return nil
}

func initializePartitionMap() {
	resetPartitionMapState(getCurrentPartition())
	resetPartitionMapState(getOtherPartition())
}

func resetPartitionMapState(partName string) {
	// reset state, if not installed
	partInfo := readPartitionInfo(partName)
	if partInfo != nil && partInfo.State != types.INSTALLED {
		partInfo.State = 0
		writePartitionInfo(partName, partInfo)
	}
}

func normalizePartitionMap(baseOsList []*types.BaseOsConfig) bool {

	if !isZbootAvailable() {
		return true
	}
	curPart := getCurrentPartition()
	otherPart := getOtherPartition()

	currActiveState := isCurrentPartitionStateActive()
	otherActiveState := isOtherPartitionStateActive()

	// if not current partition config does not have
	// activation flag set, switch to other partition
	if currActiveState && otherActiveState {
		log.Printf("Both partitions are Active %s, %s", curPart, otherPart)
		if isCurPartActivateSet(baseOsList) {
			log.Printf("Mark other partition %s, unused\n", otherPart)
			setOtherPartitionStateUnused()
			return true
		}
		if isOtherPartActivateSet(baseOsList) {
			log.Printf("Mark current partition %s, unused\n", curPart)
			log.Printf("and Schedule Reboot\n")
			setCurrentPartitionStateUnused()
			startExecReboot()
			return false
		}
	}
	return true
}

// check is this is current partition and activate is set
// for the config
func isCurPartActivateSet(baseOsList []*types.BaseOsConfig) bool {

	for _, baseOsConfig := range baseOsList {

		if baseOsConfig.PartitionLabel != "" &&
			isCurrentPartition(baseOsConfig.PartitionLabel) {
			return baseOsConfig.Activate
		}
	}

	return false
}

func isOtherPartActivateSet(baseOsList []*types.BaseOsConfig) bool {

	for _, baseOsConfig := range baseOsList {

		if baseOsConfig.PartitionLabel != "" &&
			isOtherPartition(baseOsConfig.PartitionLabel) {
			return baseOsConfig.Activate
		}
	}

	return false
}
