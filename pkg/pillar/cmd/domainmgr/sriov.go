// Copyright (c) 2017-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

const (
	nicLinuxPath     = "/sys/class/net/"
	numVfsDevicePath = "/device/sriov_numvfs"
	vfCountFieldName = "sriov-vf-count"
	maxVfCount       = 255
)

// getVf retrieve information about VFs for NIC given
func getVf(device string) (*types.VFList, error) {
	var res []types.EthVF
	virtfnRe := regexp.MustCompile("(virtfn)(\\d{1,})")
	pciBdfRe := regexp.MustCompile("[0-9a-f]{4}:[0-9a-f]{2,4}:[0-9a-f]{2}\\.[0-9a-f]$")
	devPath := filepath.Join(nicLinuxPath, device, "/device")

	_, err := os.Stat(filepath.Join(nicLinuxPath, device))
	if err != nil {
		return nil, fmt.Errorf("NIC filepath does not exist %s", err)
	}

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
				pciPath, err := filepath.EvalSymlinks(filepath.Join(devPath, device.Name()))
				if err != nil {
					return nil, fmt.Errorf("Cannot evaluate symlink for %s device. Error %s", device.Name(), err)
				}
				pciAddr := pciBdfRe.FindString(pciPath)
				if pciAddr == "" {
					return nil, fmt.Errorf("Cannot evaluate symlink for %s device. Error %s", device.Name(), err)
				}
				vfIdx, err := strconv.ParseUint(match[2], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("vfInfo failed. Cannot convert VF index %s to uint16 . Error %s", match[2], err)
				}

				res = append(res, types.EthVF{PciLong: pciAddr, Index: uint8(vfIdx)})
			}
		}
	}
	return &types.VFList{Data: res}, nil
}

func createVF(device string, vfCount uint8) error {
	name := filepath.Join(nicLinuxPath, device, numVfsDevicePath)
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

func getVfByTimeout(timeout time.Duration, device string, expectedVfCount uint8) (*types.VFList, error) {
	toCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := asyncGetVF(toCtx, device, expectedVfCount)
	for {
		select {
		case answer := <-c:
			return answer, nil
		case <-toCtx.Done():
			return nil, fmt.Errorf("getVfByTimeout reached timeout %v", timeout)
		}
	}
}

func asyncGetVF(ctx context.Context, device string, expectedVfCount uint8) chan *types.VFList {
	ch := make(chan *types.VFList)
	go func() {
		select {
		default:
			time.Sleep(1 * time.Second)
			vfs, _ := getVf(device)
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

func setupVfHardwareAddr(iface string, mac string, index uint8) error {
	pf, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Failed to find physical function %s: %v", iface, err)
	}
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("Failed to parse mac address %s: %v", mac, err)
	}
	if err = netlink.LinkSetVfHardwareAddr(pf, int(index), macAddr); err != nil {
		return fmt.Errorf("Failed to set vf %d mac address: %v", index, err)
	}

	return nil
}

func setupVfVlan(iface string, index uint8, vlanID uint16) error {
	if vlanID == 0 {
		// Either vlan is not initialized or not used
		return nil
	}
	pf, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Failed to find physical function %s: %v", iface, err)
	}

	if err = netlink.LinkSetVfVlan(pf, int(index), int(vlanID)); err != nil {
		return fmt.Errorf("Failed to set vf %d vlan: %v", index, err)
	}
	return nil
}
