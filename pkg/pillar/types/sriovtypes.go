// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

const (
	NicLinuxPath     = "/sys/class/net/"
	NumvfsDevicePath = "/device/sriov_numvfs"
	VfCountFieldName = "sriov-vf-count"
)

// Must match fields of EthVF in devcommon.proto
type EthVF struct {
	Index   uint8
	PciLong string // BFD notation
	Mac     string
	VlanId  uint16
}

// VFList is list of VF for given PF (Eth device)
type VFList struct {
	Count uint8
	Data  []EthVF
}

func (vfl *VFList) GetInfo(idx uint8) *EthVF {
	for _, el := range vfl.Data {
		if el.Index == idx {
			return &el
		}
	}
	return nil
}

// GetVf retrieve information about VFs for NIC given
func GetVf(device string) (*VFList, error) {
	var res []EthVF
	virtfnRe := regexp.MustCompile("(virtfn)(\\d{1,})")
	pciBdfRe := regexp.MustCompile("[0-9a-f]{4}:[0-9a-f]{2,4}:[0-9a-f]{2}\\.[0-9a-f]$")
	devPath := filepath.Join(NicLinuxPath, device, "/device")

	_, err := os.Stat(filepath.Join(NicLinuxPath, device))

	devInfo, err := os.Stat(devPath)
	if err != nil {
		return nil, fmt.Errorf("vfInfo failed. Cannot obtain get %s path info. Error: %s", devPath, err)
	}
	physfnInfo, err := os.Lstat(filepath.Join(devPath, "/physfn"))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("physfn folder exists on path  %s path. Error: %s", filepath.Join(devPath, "/physfn"), err)
	}

	if devInfo.IsDir() && (os.IsNotExist(err) || physfnInfo.Mode()&os.ModeSymlink == 0) {
		devices, err := ioutil.ReadDir(devPath)
		if err != nil {
			return nil, fmt.Errorf("vfInfo failed. Cannot obtain list of %s directory. Error %s", devPath, err)
		}
		for _, device := range devices {
			match := virtfnRe.FindStringSubmatch(device.Name())
			if len(match) > 2 {
				pci_path, err := filepath.EvalSymlinks(filepath.Join(devPath, device.Name()))
				if err != nil {
					return nil, fmt.Errorf("Cannot evaluate symlink for %s device. Error %s", device.Name(), err)
				}
				pci_addr := pciBdfRe.FindString(pci_path)
				if pci_addr == "" {
					return nil, fmt.Errorf("Cannot evaluate symlink for %s device. Error %s", device.Name(), err)
				}
				vf_idx, err := strconv.ParseUint(match[2], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("vfInfo failed. Cannot convert VF index %s to uint16 . Error %s", match[2], err)
				}

				res = append(res, EthVF{PciLong: pci_addr, Index: uint8(vf_idx)})
			}
		}
	}
	return &VFList{Data: res}, nil
}
