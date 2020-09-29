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

	"github.com/lf-edge/edge-containers/pkg/registry"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus" // Used for log.Fatal only
)

// MountFlags used in zbootMount calls
type MountFlags uint

const (
	// MountFlagRDONLY readOnly mount
	MountFlagRDONLY MountFlags = 0x01
	casClientType              = "containerd"
)

// mutex for zboot/dd APIs
// XXX not bullet proof since this can be invoked by different agents/processes
var zbootMutex *sync.Mutex

func init() {
	zbootMutex = new(sync.Mutex)
	if zbootMutex == nil {
		logrus.Fatal("Mutex Init")
	}
}

// reset routine
func Reset(log *base.LogObject) {
	_, err := execWithRetry(log, "zboot", "reset")
	if err != nil {
		logrus.Fatalf("zboot reset: err %v\n", err)
	}
}

// If log is nil there is no logging
func execWithRetry(log *base.LogObject, command string, args ...string) ([]byte, error) {
	for {
		out, done, err := execWithTimeout(log, command, args...)
		if err != nil {
			return out, err
		}
		if done {
			return out, nil
		}
		if log != nil {
			log.Errorf("Retrying %s %v", command, args)
		}
	}
}

// If log is nil there is no logging
func execWithTimeout(log *base.LogObject, command string, args ...string) ([]byte, bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(),
		10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)

	if log != nil {
		log.Infof("Waiting for zbootMutex.lock for %s %+v\n",
			command, args)
	}
	zbootMutex.Lock()
	if log != nil {
		log.Infof("Got zbootMutex.lock. Executing %s %+v\n",
			command, args)
	}

	out, err := cmd.Output()

	zbootMutex.Unlock()
	if log != nil {
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
	if currentPartition != "" {
		return currentPartition
	}
	ret, err := execWithRetry(nil, "zboot", "curpart")
	if err != nil {
		logrus.Fatalf("zboot curpart: err %v\n", err)
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
		logrus.Fatalf("GetOtherPartition unknown partName %s\n", partName)
	}
	return partName
}

func validatePartitionName(partName string) {

	if partName == "IMGA" || partName == "IMGB" {
		return
	}
	errStr := fmt.Sprintf("invalid partition %s", partName)
	logrus.Fatal(errStr)
}

func validatePartitionState(partState string) {
	if partState == "active" || partState == "inprogress" ||
		partState == "unused" || partState == "updating" {
		return
	}
	errStr := fmt.Sprintf("invalid partition state %s", partState)
	logrus.Fatal(errStr)
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
	ret, err := execWithRetry(nil, "zboot", "partstate", partName)
	if err != nil {
		logrus.Fatalf("zboot partstate %s: err %v\n", partName, err)
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

func setPartitionState(log *base.LogObject, partName string, partState string) {

	log.Infof("setPartitionState(%s, %s)\n", partName, partState)
	validatePartitionName(partName)
	validatePartitionState(partState)

	_, err := execWithRetry(log, "zboot", "set_partstate",
		partName, partState)
	if err != nil {
		logrus.Fatalf("zboot set_partstate %s %s: err %v\n",
			partName, partState, err)
	}
}

// Cache - doesn't change in running system
var partDev = make(map[string]string)

func GetPartitionDevname(partName string) string {
	validatePartitionName(partName)
	dev, ok := partDev[partName]
	if ok {
		return dev
	}
	ret, err := execWithRetry(nil, "zboot", "partdev", partName)
	if err != nil {
		logrus.Fatalf("zboot partdev %s: err %v\n", partName, err)
	}

	devName := string(ret)
	devName = strings.TrimSpace(devName)
	partDev[partName] = devName
	return devName
}

// set routines
func setPartitionStateActive(log *base.LogObject, partName string) {
	setPartitionState(log, partName, "active")
}

func setPartitionStateUnused(log *base.LogObject, partName string) {
	setPartitionState(log, partName, "unused")
}

func setPartitionStateUpdating(log *base.LogObject, partName string) {
	setPartitionState(log, partName, "updating")
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
	partName := GetOtherPartition()
	return IsPartitionState(partName, "updating")
}

func setCurrentPartitionStateActive(log *base.LogObject) {
	partName := GetCurrentPartition()
	setPartitionState(log, partName, "active")
}

func setCurrentPartitionStateUpdating(log *base.LogObject) {
	partName := GetCurrentPartition()
	setPartitionState(log, partName, "updating")
}

func setCurrentPartitionStateUnused(log *base.LogObject) {
	partName := GetCurrentPartition()
	setPartitionState(log, partName, "unused")
}

// set routines, for other partition
func setOtherPartitionStateActive(log *base.LogObject) {
	partName := GetOtherPartition()
	setPartitionState(log, partName, "active")
}

func SetOtherPartitionStateUpdating(log *base.LogObject) {
	partName := GetOtherPartition()
	setPartitionState(log, partName, "updating")
}

func SetOtherPartitionStateUnused(log *base.LogObject) {
	partName := GetOtherPartition()
	setPartitionState(log, partName, "unused")
}

func GetCurrentPartitionDevName() string {
	partName := GetCurrentPartition()
	return GetPartitionDevname(partName)
}

func GetOtherPartitionDevName() string {
	partName := GetOtherPartition()
	return GetPartitionDevname(partName)
}

func WriteToPartition(log *base.LogObject, image string, partName string) error {

	var (
		casClient cas.CAS
		err       error
	)

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

	log.Infof("WriteToPartition %s, %s: %v\n", partName, devName, image)

	// use the edge-containers library to extract the data we need
	puller := registry.Puller{
		Image: image,
	}
	if casClient, err = cas.NewCAS(casClientType); err != nil {
		err = fmt.Errorf("Run: exception while initializing CAS client: %s", err.Error())
		log.Fatal(err)
	}

	defer casClient.CloseClient()

	resolver, err := casClient.Resolver()
	if err != nil {
		errStr := fmt.Sprintf("error getting CAS resolver: %v", err)
		log.Error(errStr)
		return errors.New(errStr)
	}

	// Make sure we have nothing mounted on the target
	for {
		if err := syscall.Unmount(devName, 0); err != nil {
			break
		}
		log.Warnf("Successfully umounted %s", devName)
	}
	// create a writer for the file where we want
	// Avoid holding the lock since this can take a long time.
	f, err := os.OpenFile(devName,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		errStr := fmt.Sprintf("error writing to partition device at %s: %v", devName, err)
		log.Error(errStr)
		return errors.New(errStr)
	}
	defer f.Close()

	if _, _, err := puller.Pull(registry.FilesTarget{Root: f}, false, os.Stderr, resolver); err != nil {
		errStr := fmt.Sprintf("error pulling %s from containerd: %v", image, err)
		log.Error(errStr)
		return errors.New(errStr)
	}
	return nil
}

// Transition current from inprogress to active, and other from active/inprogress
// to unused
func MarkCurrentPartitionStateActive(log *base.LogObject) error {

	curPart := GetCurrentPartition()
	otherPart := GetOtherPartition()

	log.Infof("Check current partition %s, for inProgress state\n", curPart)
	if ret := IsCurrentPartitionStateInProgress(); ret == false {
		errStr := fmt.Sprintf("Current partition %s, is not inProgress",
			curPart)
		return errors.New(errStr)
	}

	log.Infof("Mark the current partition %s, active\n", curPart)
	setCurrentPartitionStateActive(log)

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
	SetOtherPartitionStateUnused(log)
	return nil
}

// XXX known pathnames for the version file and the zededa-tools container
const (
	otherPartVersionFile = "/etc/eve-release"
)

func GetShortVersion(log *base.LogObject, partName string) (string, error) {
	ver, err := getVersion(log, partName, types.EveVersionFile)
	return ver, err
}

// XXX add longversion once we have a filename above
func GetLongVersion(part string) string {
	return ""
}

// XXX explore a loopback mount to be able to read version
// from a downloaded image file
func getVersion(log *base.LogObject, part string, verFilename string) (string, error) {
	validatePartitionName(part)

	if part == GetCurrentPartition() {
		filename := verFilename
		version, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Errorln(err)
			return "", err
		}
		versionStr := string(version)
		versionStr = strings.TrimSpace(versionStr)
		log.Infof("%s, readCurVersion %s\n", part, versionStr)
		return versionStr, nil
	} else {
		verFilename = otherPartVersionFile
		devname := GetPartitionDevname(part)
		target, err := ioutil.TempDir("/run/baseosmgr", "tmpmnt")
		if err != nil {
			log.Errorln(err)
			return "", err
		}
		defer func() {
			log.Noticef("Remove(%s)", target)
			if err := os.Remove(target); err != nil {
				log.Errorf("Remove(%s) failed %s", target, err)
			}
		}()
		// Mount failure is ok; might not have a filesystem in the
		// other partition
		// XXX hardcoded file system type squashfs
		mountFlags := MountFlagRDONLY
		err = zbootMount(devname, target, "squashfs", mountFlags, "")
		if err != nil {
			errStr := fmt.Sprintf("Mount of %s failed: %s", devname, err)
			log.Errorln(errStr)
			return "", errors.New(errStr)
		}
		log.Noticef("Mounted %s on %s", devname, target)
		defer func() {
			log.Noticef("Unmount(%s)", target)
			err := syscall.Unmount(target, 0)
			if err != nil {
				errStr := fmt.Sprintf("Unmount of %s failed: %s", target, err)
				logrus.Error(errStr)
			} else {
				log.Noticef("Unmounted %s", target)
			}
		}()
		filename := fmt.Sprintf("%s/%s",
			target, verFilename)
		version, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Warn(err)
			return "", err
		}
		versionStr := string(version)
		versionStr = strings.TrimSpace(versionStr)
		log.Infof("%s, readOtherVersion %s\n", part, versionStr)
		return versionStr, nil
	}
}
