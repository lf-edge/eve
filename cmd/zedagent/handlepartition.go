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
// keeping the option open for current partition
// map delete
func deletePartitionInfo(partName string) {

	validatePartitionName(partName)
	if !isOtherPartition(partName) ||
	 	!isCurrentPartition(partName) {
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
// may be one case, wherein we want to 
// clear current partition, like we receive
// two new base os image configuration
func clearOtherPartitionMap(partName string) {

	validatePartitionName(partName)

	if !isOtherPartition(partName) {
		return
	}

	if partInfo := readOtherPartitionInfo(); partInfo != nil {
		clearPartitionMap(partName, partInfo)
	}
}

func clearCurrentPartitionMap(partName string) {

	validatePartitionName(partName)

	if !isCurrentPartition(partName) {
		return
	}

	if partInfo := readOtherPartitionInfo(); partInfo != nil {
		clearPartitionMap(partName, partInfo)
	}
}

func clearPartitionMap(partName string, partInfo * types.PartitionInfo) {

	// old map entry, nuke it
	uuidStr := partInfo.UUIDandVersion.UUID.String()

	// find the baseOs config/status map entries
	// reset the partition information
	config := baseOsConfigGet(uuidStr)
	if config != nil {
		log.Printf("%s, reset old config\n", uuidStr)
		config.PartitionLabel = ""
		for _, sc := range config.StorageConfigList {
			sc.FinalObjDir = ""
		}
		writeBaseOsConfig(config, uuidStr)
	}

	// and mark status as DELIVERED, if it has been installed
	status := baseOsStatusGet(uuidStr)
	if status != nil {
		log.Printf("%s, reset old status\n", uuidStr)
		if status.State == types.INSTALLED {
			status.State = types.DELIVERED
			for i,_ := range status.StorageStatusList {
				ss := &status.StorageStatusList[i]
				ss.State = types.DELIVERED
			}
		}
		errStr := fmt.Sprintf("uninstalled from %s",
			partInfo.PartitionLabel)
		status.Error = errStr
		status.ErrorTime = time.Now()
		status.PartitionLabel = ""
		writeBaseOsStatus(status, uuidStr)
	}

	deletePartitionInfo(partName)
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

	partName := status.PartitionLabel
	log.Printf("%s, set partition %s\n", uuidStr, partName)

	if partName == "" {
		errStr := fmt.Sprintf("%s, unssigned partition", uuidStr)
		log.Println(errStr)
		return errors.New(errStr)
	}

	if ret := isOtherPartition(partName); ret == false {
		errStr := fmt.Sprintf("%s, not other partition %s", uuidStr, partName)
		log.Println(errStr)
		return errors.New(errStr)
	}

	// remove old partition mapping, if any
	if partInfo := readOtherPartitionInfo(); partInfo != nil {
		if partInfo.BaseOsVersion != config.BaseOsVersion {
			clearOtherPartitionMap(partName)
		}
	}

	// new partition mapping
	partInfo := &types.PartitionInfo{}
	partInfo.UUIDandVersion = status.UUIDandVersion
	partInfo.ImageSha256 = baseOsGetImageSha(config)
	partInfo.BaseOsVersion = config.BaseOsVersion
	partInfo.PartitionLabel = partName
	partInfo.State = status.State
	partInfo.Activate = config.Activate
	partInfo.RetryCount = config.RetryCount

	// replicate Error Info
	if !status.ErrorTime.IsZero() {
		partInfo.Error = status.Error
		partInfo.ErrorTime = status.ErrorTime
	}

	// set these values in BaseOs status
	status.PartitionDevice = getPartitionDevname(partName)
	status.PartitionState = getPartitionState(partName)

	// XXX:FIXME, Take care of retry count
	return writeOtherPartitionInfo(partInfo)
}

// reset the partition map for baseOs
// always the other partition
func resetPersistentPartitionInfo(uuidStr string) error {

	log.Printf("%s, reset partition\n", uuidStr)
	config := baseOsConfigGet(uuidStr)
	if config == nil {
		errStr := fmt.Sprintf("%s, resetting partition, config absent\n", uuidStr)
		err := errors.New(errStr)
		return err
	}
	if config.PartitionLabel == "" {
		errStr := fmt.Sprintf("%s, resetting partition map, unassigned \n", uuidStr)
		err := errors.New(errStr)
		return err
	}

	if isOtherPartition(config.PartitionLabel) {
		clearOtherPartitionMap(config.PartitionLabel)
		return nil
	}

	errStr := fmt.Sprintf("%s, cannot reset current partition\n",	
		 uuidStr, config.PartitionLabel)
	err := errors.New(errStr)
	return err
}

func initializePartitionMap() {
	normalizePartitionMap()
	resetPartitionMapState(getCurrentPartition())
	resetPartitionMapState(getOtherPartition())
}

// reset state, if not installed
func resetPartitionMapState(partName string) {
	partInfo := readPartitionInfo(partName)
	if partInfo != nil && partInfo.State != types.INSTALLED {
		partInfo.State = 0
		writePartitionInfo(partName, partInfo)
	}
}

func normalizePartitionMap() {

	if !isZbootAvailable() {
		return
	}
	curPart := getCurrentPartition()
	otherPart := getOtherPartition()

	curActiveState := isCurrentPartitionStateActive()
	otherActiveState := isOtherPartitionStateActive()

	log.Printf("Partition State (current:%s, %v), (other:%s, %v)\n",
		curPart, curActiveState, otherPart, otherActiveState)

	// if not current partition config does not have
	// activation flag set, switch to other partition
	if curActiveState && otherActiveState {
		log.Printf("Both partitions are Active %s, %s\n", curPart, otherPart)
		if isCurPartConfigActivateSet() {
			log.Printf("Mark other partition %s, unused\n", otherPart)
			setOtherPartitionStateUnused()
			return
		}
		if isOtherPartConfigActivateSet() {
			log.Printf("Mark current partition %s, unused\n", curPart)
			log.Printf("Schedule Reboot\n")
			setCurrentPartitionStateUnused()
			startExecReboot()
			return
		}
	} 
	return
}

// check activate flag for current partition
// for the config
func isCurPartConfigActivateSet() bool {
	if partInfo := readCurrentPartitionInfo(); partInfo != nil {
		return partInfo.Activate
	}
	return false
}

// check activate flag for other partition
func isOtherPartConfigActivateSet() bool {

	if partInfo := readOtherPartitionInfo(); partInfo != nil {
		return partInfo.Activate
	}
	return false
}
