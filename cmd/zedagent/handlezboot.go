// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// zboot APIs for IMGA  & IMGB

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

const (
	tmpDir        = "/var/tmp/zededa"
	imgAPartition = tmpDir + "/IMGAPart"
	imgBPartition = tmpDir + "/IMGBPart"
)

// mutex for zboot/dd APIs
var zbootMutex *sync.Mutex

func zbootInit() {
	zbootMutex = new(sync.Mutex)
	if zbootMutex == nil {
		log.Fatal("Mutex Init")
	}
}

// reset routine
func zbootReset() {
	zbootMutex.Lock() // we are going to reboot
	rebootCmd := exec.Command("zboot", "reset")
	zbootMutex.Unlock()
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
	zbootMutex.Lock()
	watchDogCmd := exec.Command("zboot", "watchdog")
	zbootMutex.Unlock()
	_, err := watchDogCmd.Output()
	if err != nil {
		log.Fatalf("zboot watchdog: err %v\n", err)
	}
}

// partition routines
func getCurrentPartition() string {
	zbootMutex.Lock()
	curPartCmd := exec.Command("zboot", "curpart")
	zbootMutex.Unlock()
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
		log.Fatalf("getOtherPartition unknown partName %s\n", partName)
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

	zbootMutex.Lock()
	partStateCmd := exec.Command("zboot", "partstate", partName)
	zbootMutex.Unlock()
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

	zbootMutex.Lock()
	setPartStateCmd := exec.Command("zboot", "set_partstate",
		partName, partState)
	zbootMutex.Unlock()
	if _, err := setPartStateCmd.Output(); err != nil {
		log.Fatalf("zboot set_partstate %s %s: err %v\n",
			partName, partState, err)
	}
}

func getPartitionDevname(partName string) string {

	validatePartitionName(partName)
	zbootMutex.Lock()
	getPartDevCmd := exec.Command("zboot", "partdev", partName)
	zbootMutex.Unlock()
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
	if !isZbootAvailable() {
		return false
	}
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

	devName := getPartitionDevname(partName)
	if devName == "" {
		errStr := fmt.Sprintf("null devname for partition %s", partName)
		log.Printf("WriteToPartition failed %s\n", errStr)
		return errors.New(errStr)
	}

	log.Printf("WriteToPartition %s, %s: %v\n", partName, devName, srcFilename)

	zbootMutex.Lock()
	ddCmd := exec.Command("dd", "if="+srcFilename, "of="+devName, "bs=8M")
	zbootMutex.Unlock()
	if _, err := ddCmd.Output(); err != nil {
		errStr := fmt.Sprintf("WriteToPartition %s failed %v\n", partName, err)
		log.Fatal(errStr)
		return err
	}
	return nil
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

		fullname := fmt.Sprintf("%s/%s/%s",
			target, otherPrefix, filename)
		version, err := ioutil.ReadFile(fullname)
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
