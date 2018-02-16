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
	//log.Printf("zboot curpart: %s\n", partName)
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
	//log.Printf("zboot otherpart: %s\n", partName)
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
	errStr := fmt.Sprintf("invalid state %s", partState)
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
	return partState, nil
}

func isPartitionState(partName string, partState string) (bool, error) {

	if ret, err := validatePartitionName(partName); ret == false {
		return ret, err
	}

	if ret, err := validatePartitionState(partState); ret == false {
		return ret, err
	}

	partStateCmd := exec.Command("zboot", "partstate", partName)
	ret, err := partStateCmd.Output()
	if err != nil {
		errStr := fmt.Sprintf("zboot partstate %s: err %v\n", partName, err)
		err := errors.New(errStr)
		return false, err
	}
	curPartState := string(ret)
	curPartState = strings.TrimSpace(partState)

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

func getPersitentPartitionInfo(uuidStr string) string {

	var partitionInfo = &types.PartitionInfo{}

	filename := configDir + "/" + uuidStr + ".json"
	if _, err := os.Stat(filename); err == nil {
		bytes, err := ioutil.ReadFile(filename)
		if err == nil {
			err = json.Unmarshal(bytes, partitionInfo)
		}
		return partitionInfo.PartitionLabel
	}
	return ""
}

func setPersitentPartitionInfo(uuidStr string, config *types.BaseOsConfig) {

	log.Printf("%s, set partition %s\n", uuidStr, config.PartitionLabel)

	if config.PartitionLabel != "" {

		var partitionInfo = &types.PartitionInfo{}
		partitionInfo.UUIDandVersion = config.UUIDandVersion
		partitionInfo.PartitionLabel = config.PartitionLabel

		filename := configDir + "/" + uuidStr + ".json"
		bytes, err := json.Marshal(partitionInfo)
		if err == nil {
			err = ioutil.WriteFile(filename, bytes, 0644)
		}
	}
}

func zbootWriteToPartition(srcFilename string, partName string) (bool, error) {

	if ret, err := isOtherPartition(partName); ret == false {
		return ret, err
	}

	if ret, _ := isOtherPartitionStateUnused(); ret == false {
		errStr := fmt.Sprintf("not an unused partition %s", partName)
		err := errors.New(errStr)
		return false, err
	}

	devName, err := getPartitionDevname(partName)
	if err != nil || devName == "" {
		return false, err
	}

	// XXX:FIXME checkpoint, make sure, only one write to a partition
	// cleanup, if it fails, or the attached baseOs config is deleted

	ddCmd := exec.Command("dd", "if="+srcFilename, "of="+devName, "bs=8M")
	if _, err := ddCmd.Output(); err != nil {
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

	log.Printf("Mark the current partition %s, active\n", curPart)
	if ret, err := setCurrentPartitionStateActive(); ret == false {
		errStr := fmt.Sprintf("Marking current partition %s active, %v\n",
			curPart, err)
		err = errors.New(errStr)
		return ret, err
	}

	log.Printf("Check other partition %s, active\n", otherPart)
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
