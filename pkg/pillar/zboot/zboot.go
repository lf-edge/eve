// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// zboot APIs for IMGA  & IMGB

package zboot

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// MountFlags used in zbootMount calls
type MountFlags uint

const (
	// MountFlagRDONLY readOnly mount
	MountFlagRDONLY MountFlags = 0x01
)

// mutex for zboot/dd APIs
// XXX not bullet proof since this can be invoked by different agents/processes
var zbootMutex *sync.Mutex

func init() {
	zbootMutex = new(sync.Mutex)
	if zbootMutex == nil {
		log.Fatal("Mutex Init")
	}
}

// reset routine
func Reset() {
	log.Infof("Reset..\n")
	if !IsAvailable() {
		log.Infof("no zboot; can't do reset\n")
		return
	}
	_, err := execWithRetry(true, "zboot", "reset")
	if err != nil {
		log.Fatalf("zboot reset: err %v\n", err)
	}
}

func execWithRetry(dolog bool, command string, args ...string) ([]byte, error) {
	for {
		out, done, err := execWithTimeout(dolog, command, args...)
		if err != nil {
			return out, err
		}
		if done {
			return out, nil
		}
		log.Errorf("Retrying %s %v", command, args)
	}
}

func execWithTimeout(dolog bool, command string, args ...string) ([]byte, bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(),
		10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)

	if dolog {
		log.Infof("Waiting for zbootMutex.lock for %s %+v\n",
			command, args)
	}
	zbootMutex.Lock()
	if dolog {
		log.Infof("Got zbootMutex.lock. Executing %s %+v\n",
			command, args)
	}

	out, err := cmd.Output()

	zbootMutex.Unlock()
	if dolog {
		log.Infof("Released zbootMutex.lock for %s %+v\n",
			command, args)
	}

	if ctx.Err() == context.DeadlineExceeded {
		return nil, false, nil
	}
	return out, true, err
}

// Cache since it never changes on a running system
// XXX lsblk seems to hang in kernel so avoid calling zboot curpart more
// than once per process.
var currentPartition string

func SetCurpart(curpart string) {
	currentPartition = curpart
}

// partition routines
func GetCurrentPartition() string {
	if !IsAvailable() {
		return "IMGA"
	}
	if currentPartition != "" {
		return currentPartition
	}
	log.Debugf("calling zboot curpart - not in cache\n")
	ret, err := execWithRetry(false, "zboot", "curpart")
	if err != nil {
		log.Fatalf("zboot curpart: err %v\n", err)
	}

	partName := string(ret)
	partName = strings.TrimSpace(partName)
	validatePartitionName(partName)
	currentPartition = partName
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
	if !IsAvailable() {
		if partName == "IMGA" {
			return "active"
		} else {
			return "unused"
		}
	}
	ret, err := execWithRetry(false, "zboot", "partstate", partName)
	if err != nil {
		log.Fatalf("zboot partstate %s: err %v\n", partName, err)
	}
	partState := string(ret)
	partState = strings.TrimSpace(partState)
	return partState
}

func IsPartitionState(partName string, partState string) bool {

	validatePartitionName(partName)
	validatePartitionState(partState)

	curPartState := GetPartitionState(partName)
	res := curPartState == partState
	return res
}

func setPartitionState(partName string, partState string) {

	log.Infof("setPartitionState(%s, %s)\n", partName, partState)
	validatePartitionName(partName)
	validatePartitionState(partState)

	_, err := execWithRetry(true, "zboot", "set_partstate",
		partName, partState)
	if err != nil {
		log.Fatalf("zboot set_partstate %s %s: err %v\n",
			partName, partState, err)
	}
}

// Cache - doesn't change in running system
var partDev = make(map[string]string)

func GetPartitionDevname(partName string) string {
	validatePartitionName(partName)
	if !IsAvailable() {
		return ""
	}
	dev, ok := partDev[partName]
	if ok {
		return dev
	}
	log.Debugf("calling zboot partdev %s - not in cache\n", partName)

	ret, err := execWithRetry(false, "zboot", "partdev", partName)
	if err != nil {
		log.Fatalf("zboot partdev %s: err %v\n", partName, err)
	}

	devName := string(ret)
	devName = strings.TrimSpace(devName)
	partDev[partName] = devName
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

func SetOtherPartitionStateUnused() {
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
		log.Errorf("WriteToPartition failed %s\n", errStr)
		return errors.New(errStr)
	}

	devName := GetPartitionDevname(partName)
	if devName == "" {
		errStr := fmt.Sprintf("null devname for partition %s", partName)
		log.Errorf("WriteToPartition failed %s\n", errStr)
		return errors.New(errStr)
	}

	log.Infof("WriteToPartition %s, %s: %v\n", partName, devName, srcFilename)

	ddCmd := exec.Command("dd", "if="+srcFilename, "of="+devName, "bs=8M")
	zbootMutex.Lock()
	_, err := ddCmd.Output()
	zbootMutex.Unlock()
	if err != nil {
		errStr := fmt.Sprintf("WriteToPartition %s failed %v\n", partName, err)
		log.Fatal(errStr)
		return err
	}
	return nil
}

// Transition current from inprogress to active, and other from active/inprogress
// to unused
func MarkCurrentPartitionStateActive() error {

	curPart := GetCurrentPartition()
	otherPart := GetOtherPartition()

	log.Infof("Check current partition %s, for inProgress state\n", curPart)
	if ret := IsCurrentPartitionStateInProgress(); ret == false {
		errStr := fmt.Sprintf("Current partition %s, is not inProgress",
			curPart)
		return errors.New(errStr)
	}

	log.Infof("Mark the current partition %s, active\n", curPart)
	setCurrentPartitionStateActive()

	log.Infof("Check other partition %s for active state or inprogress\n",
		otherPart)
	state := GetPartitionState(otherPart)
	switch state {
	case "active":
		// Normal case
	case "inprogress":
		// Activated what was already on the other partition
	default:
		errStr := fmt.Sprintf("Other partition %s, is %s not active/inprogress",
			otherPart, state)
		return errors.New(errStr)
	}

	log.Infof("Mark other partition %s, unused\n", otherPart)
	SetOtherPartitionStateUnused()
	return nil
}

// XXX known pathnames for the version file and the zededa-tools container
const (
	newVersionFile = "/hostfs/etc/eve-release"
	// XXX remove use of shortVersionFile in container once the deployed
	// images all have newVersionFile
	shortVersionFile = "/opt/zededa/bin/versioninfo"
	longVersionFile  = "XXX"
	otherPrefix      = "/containers/services/pillar/lower"
	// XXX handle baseimage-update by looking for old names
	otherPrefixOld = "/containers/services/zededa-tools/lower"
)

func GetShortVersion(partName string) string {
	ver := getVersion(partName, newVersionFile, false)
	if ver != "" {
		return ver
	}
	return getVersion(partName, shortVersionFile, true)
}

// XXX add longversion once we have a filename above
func GetLongVersion(part string) string {
	return ""
}

// XXX explore a loopback mount to be able to read version
// from a downloaded image file
func getVersion(part string, verFilename string, inContainer bool) string {
	validatePartitionName(part)

	if part == GetCurrentPartition() {
		filename := verFilename
		version, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		versionStr := string(version)
		versionStr = strings.TrimSpace(versionStr)
		log.Infof("%s, readCurVersion %s\n", part, versionStr)
		return versionStr
	} else {
		if !IsAvailable() {
			return ""
		}
		devname := GetPartitionDevname(part)
		target, err := ioutil.TempDir("/var/run", "tmpmnt")
		if err != nil {
			log.Fatal(err)
		}
		defer os.RemoveAll(target)
		// Mount failure is ok; might not have a filesystem in the
		// other partition
		// XXX hardcoded file system type squashfs
		mountFlags := MountFlagRDONLY
		err = zbootMount(devname, target, "squashfs", mountFlags, "")
		if err != nil {
			log.Errorf("Mount of %s failed: %s\n", devname, err)
			return ""
		}
		defer syscall.Unmount(target, 0)
		var filename string
		if inContainer {
			filename = fmt.Sprintf("%s/%s/%s",
				target, otherPrefix, verFilename)
		} else {
			filename = fmt.Sprintf("%s/%s",
				target, verFilename)
		}
		version, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Warn(err)
			if !inContainer {
				return ""
			}
			filename := fmt.Sprintf("%s/%s/%s",
				target, otherPrefixOld, verFilename)
			version, err = ioutil.ReadFile(filename)
			if err != nil {
				log.Warn(err)
				return ""
			}
		}
		versionStr := string(version)
		versionStr = strings.TrimSpace(versionStr)
		log.Infof("%s, readOtherVersion %s\n", part, versionStr)
		return versionStr
	}
}

// XXX temporary? Needed to run on hikey's with no zboot yet.
func IsAvailable() bool {
	filename := "/usr/bin/zboot"
	if _, err := os.Stat(filename); err != nil {
		return false
	} else {
		return true
	}
}
