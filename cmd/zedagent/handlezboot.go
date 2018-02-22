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
		log.Fatalf("zboot reset: err %v\n", err)
	}
}

// tell watchdog we are fine
func zbootWatchdogOK() {
	_, err := exec.Command("zboot", "watchdog").Output()
	if err != nil {
		log.Fatalf("zboot watchdog: err %v\n", err)
	}
}

// partition routines
func getCurrentPartition() string {
	curPartCmd := exec.Command("zboot", "curpart")
	ret, err := curPartCmd.Output()
	if err != nil {
		log.Fatalf("zboot curpart: err %v\n", err)
	}

	partName := string(ret)
	partName = strings.TrimSpace(partName)
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
		log.Fatalf("getOtherPartition unknow partName %s\n", partName)
	}
	//log.Printf("zboot otherpart: %s\n", partName)
	return partName
}

func validatePartitionName(partName string) {

	if partName == "IMGA" || partName == "IMGB" {
		return
	}
	errStr := fmt.Sprintf("invalid partition %s", partName)
	log.Fatal(errStr)
}

func validatePartitionState(partState string) {
	if partState == "active" || partState == "inprogress" ||
		partState == "unused" || partState == "updating" {
		return
	}
	errStr := fmt.Sprintf("invalid partition state %s", partState)
	log.Fatal(errStr)
}

func isCurrentPartition(partName string) bool {
	validatePartitionName(partName)
	curPartName := getCurrentPartition()
	return curPartName == partName
}

func isOtherPartition(partName string) bool {
	validatePartitionName(partName)
	otherPartName := getOtherPartition()
	return otherPartName == partName
}

//  get/set api routines
func getPartitionState(partName string) string {

	validatePartitionName(partName)

	partStateCmd := exec.Command("zboot", "partstate", partName)
	ret, err := partStateCmd.Output()
	if err != nil {
		log.Fatalf("zboot partstate %s: err %v\n", partName, err)
	}
	partState := string(ret)
	partState = strings.TrimSpace(partState)
	log.Printf("zboot partstate %s: %v\n", partName, partState)
	return partState
}

func isPartitionState(partName string, partState string) bool {

	validatePartitionName(partName)
	validatePartitionState(partState)

	curPartState := getPartitionState(partName)
	res := curPartState == partState
	if res {
		log.Printf("isPartitionState(%s, %s) TRUE\n",
			partName, partState)
	} else {
		log.Printf("isPartitionState(%s, %s) FALSE - is %s\n",
			partName, partState, curPartState)
	}
	return res
}

func setPartitionState(partName string, partState string) {
	log.Printf("setPartitionState(%s, %s)\n", partName, partState)

	validatePartitionName(partName)
	validatePartitionState(partState)

	setPartStateCmd := exec.Command("zboot", "set_partstate",
		partName, partState)
	if _, err := setPartStateCmd.Output(); err != nil {
		log.Fatalf("zboot set_partstate %s %s: err %v\n",
			partName, partState, err)
	}
}

func getPartitionDevname(partName string) string {

	validatePartitionName(partName)
	getPartDevCmd := exec.Command("zboot", "partdev", partName)
	ret, err := getPartDevCmd.Output()
	if err != nil {
		log.Fatalf("zboot partdev %s: err %v\n", partName, err)
	}

	devName := string(ret)
	devName = strings.TrimSpace(devName)
	return devName
}

// set routines
func setPartitionStateActive(partName string) {
	setPartitionState(partName, "active")
}

func setPartitionStateUnused(partName string) {
	setPartitionState(partName, "unused")
}

func setPartitionStateUpdating(partName string) {
	setPartitionState(partName, "updating")
}

// check routines, for current partition
func isCurrentPartitionStateActive() bool {
	partName := getCurrentPartition()
	return isPartitionState(partName, "active")
}

func isCurrentPartitionStateInProgress() bool {
	partName := getCurrentPartition()
	return isPartitionState(partName, "inprogress")
}

func isCurrentPartitionStateUpdating() bool {
	partName := getCurrentPartition()
	return isPartitionState(partName, "updating")
}

// check routines, for other partition
func isOtherPartitionStateActive() bool {
	partName := getOtherPartition()
	return isPartitionState(partName, "active")
}

func isOtherPartitionStateInProgress() bool {
	partName := getOtherPartition()
	return isPartitionState(partName, "inprogress")
}

func isOtherPartitionStateUnused() bool {
	partName := getOtherPartition()
	return isPartitionState(partName, "unused")
}

func isOtherPartitionStateUpdating() bool {
	partName := getOtherPartition()
	return isPartitionState(partName, "updating")
}

func setCurrentPartitionStateActive() {
	partName := getCurrentPartition()
	setPartitionState(partName, "active")
}

func setCurrentPartitionStateUpdating() {
	partName := getCurrentPartition()
	setPartitionState(partName, "updating")
}

func setCurrentPartitionStateUnused() {
	partName := getCurrentPartition()
	setPartitionState(partName, "unused")
}

// set routines, for other partition
func setOtherPartitionStateActive() {
	partName := getOtherPartition()
	setPartitionState(partName, "active")
}

func setOtherPartitionStateUpdating() {
	partName := getOtherPartition()
	setPartitionState(partName, "updating")
}

func setOtherPartitionStateUnused() {
	partName := getOtherPartition()
	setPartitionState(partName, "unused")
}

func getCurrentPartitionDevName() string {
	partName := getCurrentPartition()
	return getPartitionDevname(partName)
}

func getOtherPartitionDevName() string {
	partName := getOtherPartition()
	return getPartitionDevname(partName)
}

// This returns "" if no file which happens when no PartitionLabel was set
// for setPersistentPartitionInfo
func getPersistentPartitionInfo(uuidStr string) string {

	var partitionInfo = &types.PartitionInfo{}

	filename := configDir + "/" + uuidStr + ".json"
	if _, err := os.Stat(filename); err == nil {
		bytes, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		err = json.Unmarshal(bytes, partitionInfo)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("getPersistentPartitionInfo(%s) for %s label %s\n",
			partitionInfo.BaseOsVersion, uuidStr,
			partitionInfo.PartitionLabel)
		return partitionInfo.PartitionLabel
	}
	return ""
}

func setPersistentPartitionInfo(uuidStr string, config *types.BaseOsConfig) {

	log.Printf("setPersistentPartitionInfo(%s) for %s label %s\n",
		config.BaseOsVersion, uuidStr, config.PartitionLabel)

	if config.PartitionLabel != "" {

		var partitionInfo = &types.PartitionInfo{}
		partitionInfo.UUIDandVersion = config.UUIDandVersion
		partitionInfo.BaseOsVersion = config.BaseOsVersion
		partitionInfo.PartitionLabel = config.PartitionLabel

		filename := configDir + "/" + uuidStr + ".json"
		bytes, err := json.Marshal(partitionInfo)
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile(filename, bytes, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func zbootWriteToPartition(srcFilename string, partName string) error {

	if !isOtherPartition(partName) {
		errStr := fmt.Sprintf("not other partition %s", partName)
		log.Printf("WriteToPartition failed %s\n", errStr)
		return errors.New(errStr)
	}

	if !isOtherPartitionStateUnused() {
		errStr := fmt.Sprintf("%s: Not an unused partition", partName)
		log.Printf("WriteToPartition failed %s\n", errStr)
		return errors.New(errStr)
	}

	log.Printf("WriteToPartition %s: %v\n", partName, srcFilename)
	devName := getPartitionDevname(partName)
	if devName == "" {
		errStr := fmt.Sprintf("null devname for partition %s", partName)
		log.Printf("WriteToPartition failed %s\n", errStr)
		return errors.New(errStr)
	}
	// XXX how can we set this before we complete the dd?
	// If crash during dd the image would be corrupt.
	setOtherPartitionStateUpdating()

	// XXX:FIXME checkpoint, make sure, only one write to a partition
	// cleanup, if it fails, or the attached baseOs config is deleted

	ddCmd := exec.Command("dd", "if="+srcFilename, "of="+devName, "bs=8M")
	if _, err := ddCmd.Output(); err != nil {
		log.Printf("WriteToPartition failed %s\n", err)
		setOtherPartitionStateUnused()
		return err
	}

	return nil
}

func partitionInit() {

	curPart := getCurrentPartition()
	otherPart := getOtherPartition()

	currActiveState := isCurrentPartitionStateActive()
	otherActiveState := isOtherPartitionStateActive()

	if currActiveState && otherActiveState {
		log.Printf("Both partitions are Active %s, %s n", curPart, otherPart)
		log.Printf("Mark other partition %s, unused\n", otherPart)
		setOtherPartitionStateUnused()
	}
}

func markPartitionStateActive() error {

	curPart := getCurrentPartition()
	otherPart := getOtherPartition()

	log.Printf("Mark the current partition %s, active\n", curPart)
	setCurrentPartitionStateActive()

	log.Printf("Check other partition %s, active\n", otherPart)
	if !isOtherPartitionStateActive() {
		errStr := fmt.Sprintf("Other partition %s, is not active\n",
			otherPart)
		return errors.New(errStr)
	}

	log.Printf("Mark other partition %s, unused\n", otherPart)
	setOtherPartitionStateUnused()
	return nil
}
