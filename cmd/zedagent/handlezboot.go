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
	"syscall"
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
		log.Fatalf("zboot reset: err %v\n", err)
	}
}

// tell watchdog we are fine
func zbootWatchdogOK() {
	if !isZbootAvailable() {
		return
	}
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

	ddCmd := exec.Command("dd", "if="+srcFilename, "of="+devName, "bs=8M")
	if _, err := ddCmd.Output(); err != nil {
		log.Printf("WriteToPartition failed %s\n", err)
		log.Printf("partName : %v\n", err)
		return err
	}
	return nil
}

func InitializePartitionTable(baseOsList []types.BaseOsConfig) {

	if !isZbootAvailable() {
		return
	}
	curPart := getCurrentPartition()
	otherPart := getOtherPartition()

	currActiveState := isCurrentPartitionStateActive()
	otherActiveState := isOtherPartitionStateActive()

	// if not current partition config does not have
	// activation flag set, switch to other partition
	if currActiveState && otherActiveState {
		log.Printf("Both partitions are Active %s, %s n", curPart, otherPart)
		log.Printf("Mark other partition %s, unused\n", otherPart)
		if isCurPartActivateSet(baseOsList) {
			setOtherPartitionStateUnused()
		} else {
			setCurrentPartitionStateUnused()
			startExecReboot()
		}
	}
}

// check is this is current partition and activate is set
// for the config
func isCurPartActivateSet(baseOsList []types.BaseOsConfig) bool {

	for _, baseOsConfig := range baseOsList {

		if baseOsConfig.PartitionLabel != "" &&
			isCurrentPartition(baseOsConfig.PartitionLabel) {
			return baseOsConfig.Activate
		}
	}

	return false
}

func markPartitionStateActive() error {

	curPart := getCurrentPartition()
	otherPart := getOtherPartition()

	log.Printf("Check current partition %s, for inProgress state\n", curPart)
	if ret := isCurrentPartitionStateInProgress(); ret == false {
		errStr := fmt.Sprintf("Current partition %s, is not inProgress",
			curPart)
		return errors.New(errStr)
	}

	log.Printf("Mark the current partition %s, active\n", curPart)
	setCurrentPartitionStateActive()

	log.Printf("Check other partition %s for active state\n", otherPart)
	if ret := isOtherPartitionStateActive(); ret == false {
		errStr := fmt.Sprintf("Other partition %s, is not active",
			otherPart)
		return errors.New(errStr)
	}

	log.Printf("Mark other partition %s, unused\n", otherPart)
	setOtherPartitionStateUnused()
	return nil
}

// Partition Map Management routines
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

func readCurrentPartitionInfo() *types.PartitionInfo {
	partName := getCurrentPartition()
	return readPartitionInfo(partName)
}

func readOtherPartitionInfo() *types.PartitionInfo {
	partName := getOtherPartition()
	return readPartitionInfo(partName)
}

// has to be always other partition
func removePartitionMap(mapFilename string, partInfo *types.PartitionInfo) bool {
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
		writeBaseOsConfig(*config, configFilename)
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
		writeBaseOsStatus(status, statusFilename)
	}

	partMapFilename := configDir + "/" + otherPartInfo.PartitionLabel + ".json"
	if err := os.Remove(partMapFilename); err != nil {
		log.Printf("%v for %s\n", err, partMapFilename)
	}
	return false
}

// check the partition table, for this baseOs
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

// can only be done to the other partition
func setPersistentPartitionInfo(uuidStr string, config types.BaseOsConfig, status *types.BaseOsStatus) error {
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
	mapFilename := configDir + "/" + config.PartitionLabel + ".json"

	if match := removePartitionMap(mapFilename, partInfo); match == true {
		log.Printf("Updating existing Partition Map Status\n", partName)
	}

	// XXX:FIXME, Take care of retry count

	bytes, err := json.Marshal(partInfo)
	if err != nil {
		errStr := fmt.Sprintf("%s, marshalling error %s\n", uuidStr, err)
		log.Println(errStr)
		return errors.New(errStr)
	}

	if err := ioutil.WriteFile(mapFilename, bytes, 0644); err != nil {
		errStr := fmt.Sprintf("%s, file write error %s\n", uuidStr, err)
		log.Println(errStr)
		return errors.New(errStr)
	}
	return nil
}

func resetPersistentPartitionInfo(uuidStr string) error {

	log.Printf("%s, reset partition\n", uuidStr)
	config := baseOsConfigGet(uuidStr)
	if config == nil {
		errStr := fmt.Sprintf("%s, config absent\n", uuidStr)
		err := errors.New(errStr)
		return err
	}

	if !isOtherPartition(config.PartitionLabel) {
		return nil
	}
	mapFilename := configDir + "/" + config.PartitionLabel + ".json"
	removePartitionMap(mapFilename, nil)
	return nil
}

// XXX known pathnames for the version file and the zededa-tools container
const (
	shortVersionFile = "/opt/zededa/bin/versioninfo"
	longVersionFile  = "XXX"
	otherPrefix      = "/containers/services/zededa-tools/lower"
)

func GetShortVersion(part string) string {
	return getVersion(part, shortVersionFile)
}

// XXX add longversion once we have a filename
func GetLongVersion(part string) string {
	return ""
}

func getVersion(part string, filename string) string {
	isCurrent := (part == getCurrentPartition())
	if isCurrent {
		version, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		return string(version)
	} else {
		devname := getPartitionDevname(part)
		target, err := ioutil.TempDir("/var/run", "tmpmnt")
		if err != nil {
			log.Fatal(err)
		}
		defer os.RemoveAll(target)
		// Mount failure is ok; might not have a filesystem in the
		// other partition
		// XXX hardcoded file system type squashfs
		err = syscall.Mount(devname, target, "squashfs",
			syscall.MS_RDONLY, "")
		if err != nil {
			log.Printf("Mount of %s failed: %s\n", devname, err)
			return ""
		}
		defer syscall.Unmount(target, 0)

		version, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		return string(version)
	}
}

// XXX temporary? Needed to run on hikey's with no zboot yet.
func isZbootAvailable() bool {
	filename := "/usr/bin/zboot"
	if _, err := os.Stat(filename); err != nil {
		log.Printf("zboot not available on this platform: %s\n", err)
		return false
	} else {
		return true
	}
}
