// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package sriov

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/vishvananda/netlink"
)

// constants for Linux paths for devices
const (
	NicLinuxPath     = "/sys/class/net/"
	NumVfsDevicePath = "/device/sriov_numvfs"
	VfCountFieldName = "sriov-vf-count"
	MaxVfCount       = 255
)

// CreateVF creates Virtual Functions of given count for given Physical Function
func CreateVF(device string, vfCount uint8) error {
	name := filepath.Join(NicLinuxPath, device, NumVfsDevicePath)
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(strconv.Itoa(int(vfCount))))
	if err1 := f.Sync(); err1 != nil && err == nil {
		err = err1
	}
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}

// GetVfIfaceName returns formatted VF name
func GetVfIfaceName(index uint8, ifname string) string {
	return fmt.Sprintf("%svf%d", ifname, index)
}

// ParseVfIfaceName returns index of VF and its PF from name
func ParseVfIfaceName(ifname string) (uint8, string, error) {
	var iface string
	var index uint8
	n, err := fmt.Sscanf(ifname, "%svf%d", &iface, &index)
	if n != 2 {
		err = fmt.Errorf("ParseVfIfaceName: could not parse all arguments expected 2, got %d", n)
	}
	return index, iface, err
}

// GetVf retrieve information about VFs for NIC given
func GetVf(device string) (*VFList, error) { //nolint:gocyclo
	var res []EthVF
	virtfnRe := regexp.MustCompile(`(virtfn)(\d{1,})`)
	pciBdfRe := regexp.MustCompile(`[0-9a-f]{4}:[0-9a-f]{2,4}:[0-9a-f]{2}\.[0-9a-f]$`)
	devPath := filepath.Join(NicLinuxPath, device, "/device")

	_, err := os.Stat(filepath.Join(NicLinuxPath, device))
	if err != nil {
		return nil, fmt.Errorf("NIC filepath does not exist %w", err)
	}

	devInfo, err := os.Stat(devPath)
	if err != nil {
		return nil, fmt.Errorf("vfInfo failed. Cannot obtain get %s path info. Error: %w", devPath, err)
	}
	physfnInfo, err := os.Lstat(filepath.Join(devPath, "/physfn"))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("physfn folder exists on path  %s path. Error: %w", filepath.Join(devPath, "/physfn"), err)
	}

	if devInfo.IsDir() && (os.IsNotExist(err) || physfnInfo.Mode()&os.ModeSymlink == 0) {
		devices, err := os.ReadDir(devPath)
		if err != nil {
			return nil, fmt.Errorf("vfInfo failed. Cannot obtain list of %s directory. Error %w", devPath, err)
		}
		for _, device := range devices {
			match := virtfnRe.FindStringSubmatch(device.Name())
			if len(match) > 2 {
				pciPath, err := filepath.EvalSymlinks(filepath.Join(devPath, device.Name()))
				if err != nil {
					return nil, fmt.Errorf("Cannot evaluate symlink for %s device. Error %w", device.Name(), err)
				}
				pciAddr := pciBdfRe.FindString(pciPath)
				if pciAddr == "" {
					return nil, fmt.Errorf("Cannot evaluate symlink for %s device. Error %w", device.Name(), err)
				}
				vfIdx, err := strconv.ParseUint(match[2], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("vfInfo failed. Cannot convert VF index %s to uint16 . Error %w", match[2], err)
				}

				res = append(res, EthVF{PciLong: pciAddr, Index: uint8(vfIdx)})
			}
		}
	}
	return &VFList{Data: res}, nil
}

// GetVfByTimeout returns Vf for given PF by timeout
func GetVfByTimeout(timeout time.Duration, device string, expectedVfCount uint8) (*VFList, error) {
	toCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := AsyncGetVF(toCtx, device, expectedVfCount)
	for {
		select {
		case answer := <-c:
			return answer, nil
		case <-toCtx.Done():
			return nil, fmt.Errorf("getVfByTimeout reached timeout %v", timeout)
		}
	}
}

// AsyncGetVF returns Vf for given PF asynchronously
func AsyncGetVF(ctx context.Context, device string, expectedVfCount uint8) chan *VFList {
	ch := make(chan *VFList)
	go func() {
		select {
		default:
			time.Sleep(1 * time.Second)
			vfs, _ := GetVf(device)
			if len(vfs.Data) == int(expectedVfCount) {
				ch <- vfs
				break
			}
		case <-ctx.Done():
			return
		}
	}()
	return ch
}

// EthVF must match EthVF structure in devcommon.proto
type EthVF struct {
	Index   uint8
	PciLong string // BFD notation
	Mac     string
	VlanID  uint16
}

// VFList is list of VF for given PF (Eth device)
type VFList struct {
	Count uint8
	Data  []EthVF
}

// GetInfo get information on VF for given VF
func (vfl *VFList) GetInfo(idx uint8) *EthVF {
	for _, el := range vfl.Data {
		if el.Index == idx {
			return &el
		}
	}
	return nil
}

// SetupVfHardwareAddr sets up MAC address for the given VF
// of the given PF
func SetupVfHardwareAddr(iface string, mac string, index uint8) error {
	pf, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Failed to find physical function %s: %w", iface, err)
	}
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("Failed to parse mac address %s: %w", mac, err)
	}
	if err = netlink.LinkSetVfHardwareAddr(pf, int(index), macAddr); err != nil {
		return fmt.Errorf("Failed to set vf %d mac address: %w", index, err)
	}

	return nil
}

// SetupVfVlan setups VLANID for the given VF of the given PF
func SetupVfVlan(iface string, index uint8, vlanID uint16) error {
	if vlanID == 0 {
		// Either vlan is not initialized or not used
		return nil
	}
	pf, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Failed to find physical function %s: %w", iface, err)
	}

	if err = netlink.LinkSetVfVlan(pf, int(index), int(vlanID)); err != nil {
		return fmt.Errorf("Failed to set vf %d vlan: %w", index, err)
	}
	return nil
}
