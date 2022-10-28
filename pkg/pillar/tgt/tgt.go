// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// package contains functions to configure Linux kernel target

package tgt

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	tgtPath    = "/hostfs/sys/kernel/config/target"
	iBlockPath = tgtPath + "/core/iblock_0"
	naaPrefix  = "5001405" // from rtslib-fb
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func waitForFile(fileName string) error {
	maxDelay := time.Second * 5
	delay := time.Millisecond * 500
	var waited time.Duration
	for {
		if delay != 0 {
			time.Sleep(delay)
			waited += delay
		}
		if _, err := os.Stat(fileName); err == nil {
			return nil
		} else {
			if waited > maxDelay {
				return fmt.Errorf("file not found: error %v", err)
			}
			delay = 2 * delay
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

// CheckTargetIBlock check target iblock exists
func CheckTargetIBlock(tgtName string) bool {
	targetRoot := filepath.Join(iBlockPath, tgtName)
	if _, err := os.Stat(targetRoot); err == nil {
		return true
	}
	return false
}

// TargetCreateIBlock - Create iblock target for device
func TargetCreateIBlock(dev, tgtName, serial string) error {
	targetRoot := filepath.Join(iBlockPath, tgtName)
	err := os.MkdirAll(targetRoot, os.ModeDir)
	if err != nil {
		return fmt.Errorf("cannot create fileio: %v", err)
	}
	if err := waitForFile(filepath.Join(targetRoot, "control")); err != nil {
		return fmt.Errorf("error waitForFile: %v", err)
	}
	controlCommand := fmt.Sprintf("udev_path=%s", dev)
	if err := ioutil.WriteFile(filepath.Join(targetRoot, "control"), []byte(controlCommand), 0660); err != nil {
		return fmt.Errorf("error set control: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(targetRoot, "wwn", "vpd_unit_serial"), []byte(serial), 0660); err != nil {
		return fmt.Errorf("error set vpd_unit_serial: %v", err)
	}
	if err := waitForFile(filepath.Join(targetRoot, "enable")); err != nil {
		return fmt.Errorf("error waitForFile: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(targetRoot, "enable"), []byte("1"), 0660); err != nil {
		return fmt.Errorf("error set enable: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(targetRoot, "attrib", "emulate_tpu"), []byte("1"), 0660); err != nil {
		return fmt.Errorf("error set emulate_tpu: %v", err)
	}
	return nil
}

// generateSerial generates naa serial
func generateSerial() string {
	return fmt.Sprintf("%s%09x", naaPrefix, rand.Uint32())
}

// GetNaaSerial returns prefixed serial
func GetNaaSerial(serial string) string {
	return fmt.Sprintf("naa.%s", serial)
}

// VHostCreateIBlock - Create vHost fabric
func VHostCreateIBlock(tgtName, wwn string) error {
	targetRoot := filepath.Join(iBlockPath, tgtName)
	if _, err := os.Stat(targetRoot); err != nil {
		return fmt.Errorf("tgt access error (%s): %s", targetRoot, err)
	}
	vhostRoot := filepath.Join(tgtPath, "vhost", wwn, "tpgt_1")
	vhostLun := filepath.Join(vhostRoot, "lun", "lun_0")
	err := os.MkdirAll(vhostLun, os.ModeDir)
	if err != nil {
		return fmt.Errorf("cannot create vhost: %v", err)
	}
	controlCommand := "scsi_host_id=1,scsi_channel_id=0,scsi_target_id=0,scsi_lun_id=0"
	if err := ioutil.WriteFile(filepath.Join(targetRoot, "control"), []byte(controlCommand), 0660); err != nil {
		return fmt.Errorf("error set control: %v", err)
	}
	if err := waitForFile(filepath.Join(vhostRoot, "nexus")); err != nil {
		return fmt.Errorf("error waitForFile: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(vhostRoot, "nexus"), []byte(wwn), 0660); err != nil {
		return fmt.Errorf("error set nexus: %v", err)
	}
	if _, err := os.Stat(filepath.Join(vhostLun, "iblock")); os.IsNotExist(err) {
		if err := os.Symlink(targetRoot, filepath.Join(vhostLun, "iblock")); err != nil {
			return fmt.Errorf("error create symlink: %v", err)
		}
	}
	return nil
}

// GetSerialTarget returns serial from target
func GetSerialTarget(tgtName string) (string, error) {
	targetRoot := filepath.Join(iBlockPath, tgtName)
	//it returns something like "T10 VPD Unit Serial Number: 5001405043a8fbf4"
	serial, err := ioutil.ReadFile(filepath.Join(targetRoot, "wwn", "vpd_unit_serial"))
	if err != nil {
		return "", fmt.Errorf("GetSerialTarget for %s: %s", targetRoot, err)
	}
	parts := strings.Fields(strings.TrimSpace(string(serial)))
	if len(parts) == 0 {
		return "", fmt.Errorf("GetSerialTarget for %s: empty line", targetRoot)
	}
	return parts[len(parts)-1], nil
}

// CheckVHostIBlock check target vhost exists
func CheckVHostIBlock(tgtName string) bool {
	serial, err := GetSerialTarget(tgtName)
	if err != nil {
		logrus.Errorf("CheckVHostIBlock (%s): %v", tgtName, err)
		return false
	}
	vhostRoot := filepath.Join(tgtPath, "vhost", GetNaaSerial(serial), "tpgt_1")
	vhostLun := filepath.Join(vhostRoot, "lun", "lun_0")
	if _, err := os.Stat(filepath.Join(vhostLun, "iblock")); err == nil {
		return true
	}
	return false
}

// VHostDeleteIBlock - delete
func VHostDeleteIBlock(wwn string) error {
	vhostRoot := filepath.Join(tgtPath, "vhost", wwn, "tpgt_1")
	vhostLun := filepath.Join(vhostRoot, "lun", "lun_0")
	if _, err := os.Stat(vhostLun); os.IsNotExist(err) {
		return fmt.Errorf("vHost do not exists for wwn %s: %s", wwn, err)
	}
	if err := os.Remove(filepath.Join(vhostLun, "iblock")); err != nil {
		return fmt.Errorf("error delete symlink: %v", err)
	}
	if err := os.RemoveAll(vhostLun); err != nil {
		return fmt.Errorf("error delete lun: %v", err)
	}
	if err := os.RemoveAll(vhostRoot); err != nil {
		return fmt.Errorf("error delete lun: %v", err)
	}
	if err := os.RemoveAll(filepath.Dir(vhostRoot)); err != nil {
		return fmt.Errorf("error delete lun: %v", err)
	}
	return nil
}

// TargetDeleteIBlock - Delete iblock target
func TargetDeleteIBlock(tgtName string) error {
	targetRoot := filepath.Join(iBlockPath, tgtName)
	if _, err := os.Stat(targetRoot); os.IsNotExist(err) {
		return fmt.Errorf("tgt do not exists for tgtName %s: %s", tgtName, err)
	}
	if err := os.RemoveAll(targetRoot); err != nil {
		return fmt.Errorf("error delete tgt: %v", err)
	}
	return nil
}

// CreateTargetVhost creates target and vhost for device using information from VolumeStatus
// and returns wwn to use for mounting
func CreateTargetVhost(device string, key string) (string, error) {
	serial := generateSerial()
	wwn := GetNaaSerial(serial)
	err := TargetCreateIBlock(device, key, serial)
	if err != nil {
		return "", fmt.Errorf("TargetCreateFileIODev(%s, %s, %s): %w",
			device, key, serial, err)
	}
	if !CheckVHostIBlock(key) {
		err = VHostCreateIBlock(key, wwn)
		if err != nil {
			errString := fmt.Sprintf("VHostCreateIBlock: %v", err)
			err = VHostDeleteIBlock(wwn)
			if err != nil {
				errString = fmt.Sprintf("%s; VHostDeleteIBlock: %v",
					errString, err)
			}
			return "", fmt.Errorf("VHostCreateIBlock(%s, %s): %s",
				key, wwn, errString)
		}
	}
	return wwn, nil
}
