// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// zboot APIs for IMGA  & IMGB

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	tmpDir        = "/var/tmp/zededa"
	imgAPartition = tmpDir + "/IMGAPart"
	imgBPartition = tmpDir + "/IMGBPart"
)

// reset routine
func zbootReset() {
	rebootCmd := exec.Command("zboot", "reset")
	_, err := rebootCmd.Output()
	if err != nil {
		log.Println(err)
	}
}

// partition routines
func getCurrentPartition() string {
	curPartCmd := exec.Command("zboot", "curpart")
	ret, err := curPartCmd.Output()
	if err != nil {
		log.Printf("zboot curpart: err %v\n", err)
		return ""
	}

	partName := string(ret)
	partName = strings.TrimSpace(partName)
	switch partName {
	case "IMGA":
		partName = "IMGA"
	case "IMGB":
		partName = "IMGB"
	default:
		partName = ""
	}
	return partName
}

func getOtherPartition() string {

	partName := getCurrentPartition()

	switch partName {
	case "IMGA":
		partName = "IMGB"
	case "IMGB":
		partName = "IMGA"
	default:
		partName = ""
	}
	return partName
}

func validatePartitionName(partName string) (bool, error) {

	if partName == "IMGA" || partName == "IMGB" {
		return true, nil
	}
	errStr := fmt.Sprintf("invalid partition %s", partName)
	err := errors.New(errStr)
	return false, err
}

func validatePartitionState(partState string) (bool, error) {

	if partState == "active" || partState == "inprogress" ||
		partState == "unused" || partState == "updating" {
		return true, nil
	}
	errStr := fmt.Sprintf("part-state %s invalid", partState)
	err := errors.New(errStr)
	return false, err
}

func isCurrentPartition(partName string) (bool, error) {
	if ret, err := validatePartitionName(partName); ret == false {
		return ret, err
	}
	curPartName := getCurrentPartition()
	if curPartName != partName {
		return false, nil
	}
	return true, nil
}

func isOtherPartition(partName string) (bool, error) {
	if ret, err := validatePartitionName(partName); ret == false {
		return ret, err
	}
	otherPartName := getOtherPartition()
	if otherPartName != partName {
		return false, nil
	}
	return true, nil
}

//  get/set api routines
func getPartitionState(partName string) (string, error) {

	if ret, err := validatePartitionName(partName); ret == false {
		return "", err
	}

	partStateCmd := exec.Command("zboot", "partstate", partName)
	ret, err := partStateCmd.Output()
	if err != nil {
		log.Printf("zboot partstate %s: err %v\n", partName, err)
		return "", err
	}
	partState := string(ret)
	partState = strings.TrimSpace(partState)
	log.Printf("partstate %s: %v\n", partName, partState)
	return partState, nil
}

func isPartitionState(partName string, partState string) (bool, error) {

	if ret, err := validatePartitionName(partName); ret == false {
		return ret, err
	}

	if ret, err := validatePartitionState(partState); ret == false {
		return ret, err
	}

	curPartState, err := getPartitionState(partName)
	if err != nil {
		return false, err
	}

	log.Printf("%s, is-partstate: %v, %v\n", partName, curPartState, partState)

	if curPartState != partState {
		return false, nil
	}
	return true, nil
}

func setPartitionState(partName string, partState string) (bool, error) {

	if ret, err := validatePartitionName(partName); ret == false {
		return ret, err
	}

	if ret, err := validatePartitionState(partState); ret == false {
		return ret, err
	}

	setPartStateCmd := exec.Command("zboot", "set_partstate",
		partName, partState)
	if _, err := setPartStateCmd.Output(); err != nil {
		log.Printf("zboot partstate %s %s: err %v\n",
			partName, partState, err)
		return false, err
	}
	return true, nil
}

func getPartitionDevname(partName string) (string, error) {

	if ret, err := validatePartitionName(partName); ret == false {
		return "", err
	}
	getPartDevCmd := exec.Command("zboot", "partdev", partName)
	ret, err := getPartDevCmd.Output()
	if err != nil {
		log.Printf("zboot partdev %s: err %v\n", partName, err)
		return "", err
	}

	devName := string(ret)
	devName = strings.TrimSpace(devName)
	return devName, nil
}

// set routines
func setPartitionStateActive(partName string) (bool, error) {
	return setPartitionState(partName, "active")
}

func setPartitionStateInProgress(partName string) (bool, error) {
	return setPartitionState(partName, "inprogress")
}

func setPartitionStateUnused(partName string) (bool, error) {
	return setPartitionState(partName, "unused")
}

func setPartitionStateUpdating(partName string) (bool, error) {
	return setPartitionState(partName, "updating")
}

// check routines, for current partition
func isCurrentPartitionStateActive() (bool, error) {
	partName := getCurrentPartition()
	return isPartitionState(partName, "active")
}

func isCurrentPartitionStateInProgress() (bool, error) {
	partName := getCurrentPartition()
	return isPartitionState(partName, "inprogress")
}

func isCurrentPartitionStateUpdating() (bool, error) {
	partName := getCurrentPartition()
	return isPartitionState(partName, "updating")
}

// check routines, for other partition
func isOtherPartitionStateActive() (bool, error) {
	partName := getOtherPartition()
	return isPartitionState(partName, "active")
}

func isOtherPartitionStateInProgress() (bool, error) {
	partName := getOtherPartition()
	return isPartitionState(partName, "inprogress")
}

func isOtherPartitionStateUnused() (bool, error) {
	partName := getOtherPartition()
	return isPartitionState(partName, "unused")
}

func isOtherPartitionStateUpdating() (bool, error) {
	partName := getOtherPartition()
	return isPartitionState(partName, "updating")
}

// set routines, for current partition
func setCurrentPartitionStateInProgress() (bool, error) {
	partName := getCurrentPartition()
	return setPartitionState(partName, "inprogress")
}

func setCurrentPartitionStateActive() (bool, error) {
	partName := getCurrentPartition()
	return setPartitionState(partName, "active")
}

func setCurrentPartitionStateUpdating() (bool, error) {
	partName := getCurrentPartition()
	return setPartitionState(partName, "updating")
}

func setCurrentPartitionStateUnused() (bool, error) {
	partName := getCurrentPartition()
	return setPartitionState(partName, "unused")
}

// set routines, for other partition
func setOtherPartitionStateInProgress() (bool, error) {
	partName := getOtherPartition()
	return setPartitionState(partName, "inprogress")
}

func setOtherPartitionStateActive() (bool, error) {
	partName := getOtherPartition()
	return setPartitionState(partName, "active")
}

func setOtherPartitionStateUpdating() (bool, error) {
	partName := getOtherPartition()
	return setPartitionState(partName, "updating")
}

func setOtherPartitionStateUnused() (bool, error) {
	partName := getOtherPartition()
	return setPartitionState(partName, "unused")
}

func getCurrentPartitionDevName() (string, error) {
	partName := getCurrentPartition()
	return getPartitionDevname(partName)
}

func getOtherPartitionDevName() (string, error) {
	partName := getOtherPartition()
	return getPartitionDevname(partName)
}

func zbootWriteToPartition(srcFilename string, partName string) (bool, error) {

	log.Printf("WriteToPartition %s: %v\n", partName, srcFilename)

	if ret, err := isOtherPartition(partName); ret == false {
		log.Printf("not other Partition %s: %v\n", partName, err)
		return ret, err
	}

	if ret, _ := isOtherPartitionStateUnused(); ret == false {
		errStr := fmt.Sprintf("%s: Not an unused partition", partName)
		err := errors.New(errStr)
		log.Printf("partName %s: %v\n", partName, err)
		return ret, err
	}

	devName, err := getPartitionDevname(partName)
	if err != nil || devName == "" {
		log.Printf("partName %s: %v\n", partName, err)
		return false, err
	}

	// write the image to target partition
	ddCmd := exec.Command("dd", "if="+srcFilename, "of="+devName, "bs=8M")
	if _, err := ddCmd.Output(); err != nil {
		log.Printf("Writing to Partition %s, Failed %v\n", partName, err)
		return false, err
	}

	return true, nil
}

func partitionInit() (bool, error) {

	curPart := getCurrentPartition()
	otherPart := getOtherPartition()

	currActiveState, _ := isCurrentPartitionStateActive()
	otherActiveState, _ := isOtherPartitionStateActive()

	if currActiveState == true && otherActiveState == true {
		log.Printf("Both partitions are Active %s, %s n", curPart, otherPart)
		log.Printf("Mark other partition %s, unused\n", otherPart)
		if ret, err := setOtherPartitionStateUnused(); ret == false {
			errStr := fmt.Sprintf("Marking other partition %s unused, %v\n",
				otherPart, err)
			err = errors.New(errStr)
			return ret, err
		}
	}
	return true, nil
}

func markPartitionStateActive() (bool, error) {

	curPart := getCurrentPartition()
	otherPart := getOtherPartition()

	log.Printf("Check current partition %s, for inProgress state\n", curPart)
	if ret, err := isCurrentPartitionStateInProgress(); ret == false {
		errStr := fmt.Sprintf("Current partition %s, is not inProgress %v\n",
			curPart, err)
		err = errors.New(errStr)
		return ret, err
	}

	log.Printf("Mark the current partition %s, active\n", curPart)
	if ret, err := setCurrentPartitionStateActive(); ret == false {
		errStr := fmt.Sprintf("Marking current partition %s active, %v\n",
			curPart, err)
		err = errors.New(errStr)
		return ret, err
	}

	log.Printf("Check other partition %s for active state\n", otherPart)
	if ret, err := isOtherPartitionStateActive(); ret == false {
		errStr := fmt.Sprintf("Other partition %s, is not active %v\n",
			otherPart, err)
		err = errors.New(errStr)
		return ret, err
	}

	log.Printf("Mark other partition %s, unused\n", otherPart)
	if ret, err := setOtherPartitionStateUnused(); ret == false {
		errStr := fmt.Sprintf("Marking other partition %s unused, %v\n",
			otherPart, err)
		err = errors.New(errStr)
		return ret, err
	}
	return true, nil
}

// Partition Map Management routines
func readPartitionInfo(partName string) (*types.PartitionInfo, error) {

	if ret, err := validatePartitionName(partName); ret == false {
		return nil, err
	}

	mapFilename := configDir + "/" + partName + ".json"
	if _, err := os.Stat(mapFilename); err != nil { 
		return nil, err
	}

	bytes, err := ioutil.ReadFile(mapFilename)
	if err != nil {
		return nil, err
	}

	partInfo := &types.PartitionInfo{}
	if err := json.Unmarshal(bytes, partInfo); err != nil {
		return nil, err
	}
	return partInfo, nil
}

func readCurrentPartitionInfo() (*types.PartitionInfo, error) {
	partName := getCurrentPartition()
	return readPartitionInfo(partName)
}

func readOtherPartitionInfo() (*types.PartitionInfo, error) {
	partName := getOtherPartition()
	return readPartitionInfo(partName)
}

// haas to be always other partition
func removePartitionMap(mapFilename string, partInfo *types.PartitionInfo) (bool, error) {
	otherPartInfo, err := readOtherPartitionInfo()
	if err != nil {
		return false, err
	}

	// if same UUID, return
	if partInfo != nil &&
		partInfo.UUIDandVersion == otherPartInfo.UUIDandVersion {
		return false, nil
	}

	// old map entry, nuke it
	uuidStr := otherPartInfo.UUIDandVersion.UUID.String()

	// find the baseOs config/status map entries

	// reset the partition information
	config := baseOsConfigGet(uuidStr)
	if config != nil {
		configFilename := zedagentBaseOsConfigDirname + 
			"/" + uuidStr + ".json"
		config.PartitionLabel = ""
		for _, sc := range config.StorageConfigList {
			sc.FinalObjDir = ""
		}
		writeBaseOsConfig(*config, configFilename)
	}

	// and mark status as DELIVERED
	status := baseOsStatusGet(uuidStr)
	if status != nil {
		statusFilename := zedagentBaseOsStatusDirname + 
			"/" + uuidStr + ".json"
		status.State = types.DELIVERED
		errStr := fmt.Sprintf("uninstalled from %s",
			 otherPartInfo.PartitionLabel)
		status.Error = errStr
		status.ErrorTime = time.Now()
		writeBaseOsStatus(status, statusFilename)
	}

	partMapFilename := configDir + "/" + otherPartInfo.PartitionLabel + ".json"
	if err := os.Remove(partMapFilename); err != nil {
		log.Printf("%v for %s\n", err, partMapFilename)
		return false, err
	}

	return true, nil
}

// check the partition table, for this baseOs
func getPersistentPartitionInfo(uuidStr string, imageSha256 string) string {

	var isCurrentPart, isOtherPart bool

	if partInfo, err := readCurrentPartitionInfo(); err == nil {
		curUuidStr := partInfo.UUIDandVersion.UUID.String()
		if curUuidStr == uuidStr {
			isCurrentPart = true
		} else {
			if imageSha256 != "" &&
				imageSha256 == partInfo.ImageSha256 {
				isCurrentPart = true
			}
		}
	}

	if partInfo, err := readOtherPartitionInfo(); err == nil {
		otherUuidStr := partInfo.UUIDandVersion.UUID.String()
		if otherUuidStr == uuidStr {
			isOtherPart = true
		} else {
			if imageSha256 != "" &&
				imageSha256 == partInfo.ImageSha256 {
				isOtherPart = true
			}
		}
	}

	if isCurrentPart == true && 
		isCurrentPart == isOtherPart {
		log.Fatal("Both partitions assigned with the same BaseOs %s\n", uuidStr)
	}

	if isCurrentPart == true {
		return getCurrentPartition()
	}

	if isOtherPart == true {
		return getOtherPartition()
	}
	return ""
}

// can only be done to the other partition
func setPersistentPartitionInfo(uuidStr string, config types.BaseOsConfig) (bool, error) {
	log.Printf("%s, set partition %s\n", uuidStr, config.PartitionLabel)

	if ret, err := isOtherPartition(config.PartitionLabel); ret == false {
		return false, err
	}

	// new partition mapping
	partInfo := &types.PartitionInfo{}
	partInfo.UUIDandVersion = config.UUIDandVersion
	partInfo.PartitionLabel = config.PartitionLabel
	partInfo.ImageSha256    = getBaseOsImageSha(config)

	// remove old partition mapping
	mapFilename := configDir + "/" + config.PartitionLabel + ".json"
	removePartitionMap(mapFilename, partInfo)

	bytes, err := json.Marshal(partInfo)
	if  err != nil {
		log.Printf("%s, marshalling error %s\n", uuidStr, err)
		return false, err
	}

	if err := ioutil.WriteFile(mapFilename, bytes, 0644); err != nil {
		log.Printf("%s, file write error %s\n", uuidStr, err)
		return false, err
	}
	return true, nil
}

func resetPersistentPartitionInfo(uuidStr string) (bool, error) {

	log.Printf("%s, reset partition\n", uuidStr)
	config := baseOsConfigGet(uuidStr)
	if config == nil {
		errStr := fmt.Sprintf("%s, config absent\n", uuidStr)
		err := errors.New(errStr)
		return false, err 
	}

	if ret, err := isOtherPartition(config.PartitionLabel); ret == false {
		return true, err
	}
	mapFilename := configDir + "/" + config.PartitionLabel + ".json"
	return removePartitionMap(mapFilename, nil)
}
