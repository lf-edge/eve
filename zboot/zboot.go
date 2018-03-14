// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// zboot APIs for IMGA  & IMGB

package zboot

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

// XXX use?
const (
	tmpDir        = "/var/tmp/zededa"
	imgAPartition = tmpDir + "/IMGAPart"
	imgBPartition = tmpDir + "/IMGBPart"
)

// mutex for zboot/dd APIs
var zbootMutex *sync.Mutex

func init() {
	zbootMutex = new(sync.Mutex)
	if zbootMutex == nil {
		log.Fatal("Mutex Init")
	}
}

// reset routine
func Reset() {
	zbootMutex.Lock() // we are going to reboot
	rebootCmd := exec.Command("zboot", "reset")
	zbootMutex.Unlock()
	_, err := rebootCmd.Output()
	if err != nil {
		log.Fatalf("zboot reset: err %v\n", err)
	}
}

// tell watchdog we are fine
func WatchdogOK() {
	if !IsAvailable() {
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
func GetCurrentPartition() string {
	zbootMutex.Lock()
	curPartCmd := exec.Command("zboot", "curpart")
	zbootMutex.Unlock()
	ret, err := curPartCmd.Output()
	if err != nil {
		log.Fatalf("zboot curpart: err %v\n", err)
	}

	partName := string(ret)
	partName = strings.TrimSpace(partName)
	validatePartitionName(partName)
	return partName
}

func GetOtherPartition() string {

	partName := GetCurrentPartition()

	switch partName {
	case "IMGA":
		partName = "IMGB"
	case "IMGB":
		partName = "IMGA"
	default:
		log.Fatalf("GetOtherPartition unknown partName %s\n", partName)
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

func IsCurrentPartition(partName string) bool {
	validatePartitionName(partName)
	curPartName := GetCurrentPartition()
	return curPartName == partName
}

func IsOtherPartition(partName string) bool {
	validatePartitionName(partName)
	otherPartName := GetOtherPartition()
	return otherPartName == partName
}

//  get/set api routines
func GetPartitionState(partName string) string {

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

func IsPartitionState(partName string, partState string) bool {

	validatePartitionName(partName)
	validatePartitionState(partState)

	curPartState := GetPartitionState(partName)
	res := curPartState == partState
	if res {
		log.Printf("IsPartitionState(%s, %s) TRUE\n",
			partName, partState)
	} else {
		log.Printf("IsPartitionState(%s, %s) FALSE - is %s\n",
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

func GetPartitionDevname(partName string) string {

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
func IsCurrentPartitionStateActive() bool {
	partName := GetCurrentPartition()
	return IsPartitionState(partName, "active")
}

func IsCurrentPartitionStateInProgress() bool {
	partName := GetCurrentPartition()
	return IsPartitionState(partName, "inprogress")
}

func IsCurrentPartitionStateUpdating() bool {
	partName := GetCurrentPartition()
	return IsPartitionState(partName, "updating")
}

// check routines, for other partition
func IsOtherPartitionStateActive() bool {
	partName := GetOtherPartition()
	return IsPartitionState(partName, "active")
}

func IsOtherPartitionStateInProgress() bool {
	partName := GetOtherPartition()
	return IsPartitionState(partName, "inprogress")
}

func IsOtherPartitionStateUnused() bool {
	partName := GetOtherPartition()
	return IsPartitionState(partName, "unused")
}

func IsOtherPartitionStateUpdating() bool {
	if !IsAvailable() {
		return false
	}
	partName := GetOtherPartition()
	return IsPartitionState(partName, "updating")
}

func setCurrentPartitionStateActive() {
	partName := GetCurrentPartition()
	setPartitionState(partName, "active")
}

func setCurrentPartitionStateUpdating() {
	partName := GetCurrentPartition()
	setPartitionState(partName, "updating")
}

func setCurrentPartitionStateUnused() {
	partName := GetCurrentPartition()
	setPartitionState(partName, "unused")
}

// set routines, for other partition
func setOtherPartitionStateActive() {
	partName := GetOtherPartition()
	setPartitionState(partName, "active")
}

func SetOtherPartitionStateUpdating() {
	partName := GetOtherPartition()
	setPartitionState(partName, "updating")
}

func setOtherPartitionStateUnused() {
	partName := GetOtherPartition()
	setPartitionState(partName, "unused")
}

func GetCurrentPartitionDevName() string {
	partName := GetCurrentPartition()
	return GetPartitionDevname(partName)
}

func GetOtherPartitionDevName() string {
	partName := GetOtherPartition()
	return GetPartitionDevname(partName)
}

func WriteToPartition(srcFilename string, partName string) error {

	if !IsOtherPartition(partName) {
		errStr := fmt.Sprintf("not other partition %s", partName)
		log.Printf("WriteToPartition failed %s\n", errStr)
		return errors.New(errStr)
	}

	if !IsOtherPartitionStateUnused() {
		errStr := fmt.Sprintf("%s: Not an unused partition", partName)
		log.Printf("WriteToPartition failed %s\n", errStr)
		return errors.New(errStr)
	}

	devName := GetPartitionDevname(partName)
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

// XXX mark which partition? Add to name?
func MarkPartitionStateActive() error {

	curPart := GetCurrentPartition()
	otherPart := GetOtherPartition()

	log.Printf("Check current partition %s, for inProgress state\n", curPart)
	if ret := IsCurrentPartitionStateInProgress(); ret == false {
		errStr := fmt.Sprintf("Current partition %s, is not inProgress",
			curPart)
		return errors.New(errStr)
	}

	log.Printf("Mark the current partition %s, active\n", curPart)
	setCurrentPartitionStateActive()

	log.Printf("Check other partition %s for active state\n", otherPart)
	if ret := IsOtherPartitionStateActive(); ret == false {
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

func GetShortVersion(partName string) string {
	return getVersion(partName, shortVersionFile)
}

// XXX add longversion once we have a filename
func GetLongVersion(part string) string {
	return ""
}

func getVersion(part string, verFilename string) string {
	if !IsAvailable() {
		return ""
	}
	validatePartitionName(part)

	if part == GetCurrentPartition() {
		filename := verFilename
		version, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		versionStr := string(version)
		versionStr = strings.TrimSpace(versionStr)
		log.Printf("%s, readCurVersion %s\n", part, versionStr)
		return versionStr
	} else {
		devname := GetPartitionDevname(part)
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
		filename := fmt.Sprintf("%s/%s/%s",
			target, otherPrefix, verFilename)
		version, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		versionStr := string(version)
		versionStr = strings.TrimSpace(versionStr)
		log.Printf("%s, readOtherVersion %s\n", part, versionStr)
		return versionStr
	}
}

// XXX temporary? Needed to run on hikey's with no zboot yet.
func IsAvailable() bool {
	filename := "/usr/bin/zboot"
	if _, err := os.Stat(filename); err != nil {
		log.Printf("zboot not available on this platform: %s\n", err)
		return false
	} else {
		return true
	}
}
