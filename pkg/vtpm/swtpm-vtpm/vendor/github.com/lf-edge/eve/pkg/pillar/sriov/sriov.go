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
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/vishvananda/netlink"
)

// constants for Linux paths for devices
const (
	NicLinuxPath      = "/sys/class/net/"
	NumVfsDevicePath  = "/device/sriov_numvfs"
	TotalVfsPath      = "/device/sriov_totalvfs"
	AutoprobePath     = "/device/sriov_drivers_autoprobe"
	VfCountFieldName  = "sriov-vf-count"
	MaxVfCount        = 255
	VfCreationTimeout = 150 * time.Second
)

// CreateVF creates Virtual Functions of given count for given Physical Function
func CreateVF(device string, vfCount uint8, log *base.LogObject) error {
	numVfsPath := filepath.Join(NicLinuxPath, device, NumVfsDevicePath)
	autoprobePath := filepath.Join(NicLinuxPath, device, AutoprobePath)
	totalVfsPath := filepath.Join(NicLinuxPath, device, TotalVfsPath)

	totalBuf, err := os.ReadFile(totalVfsPath)
	if err != nil {
		return fmt.Errorf("could not read max VFs: %w", err)
	}
	totalMax, _ := strconv.Atoi(strings.TrimSpace(string(totalBuf)))
	if int(vfCount) > totalMax {
		return fmt.Errorf("requested %d VFs, but hardware only supports %d", vfCount, totalMax)
	}

	if _, err := os.Stat(autoprobePath); err == nil {
		if err := os.WriteFile(autoprobePath, []byte("0"), 0); err != nil {
			log.Warnf("Warning: could not disable autoprobe on %s: %s", device, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking autoprobe: %w", err)
	}

	currentBuf, err := os.ReadFile(numVfsPath)
	if err != nil {
		return fmt.Errorf("could not read current VFs: %w", err)
	}
	currentVal := strings.TrimSpace(string(currentBuf))

	if currentVal == strconv.Itoa(int(vfCount)) {
		return nil
	}

	if currentVal != "0" {
		if err := os.WriteFile(numVfsPath, []byte("0"), 0); err != nil {
			return fmt.Errorf("failed to reset VFs to 0 (check if VFs are in use): %w", err)
		}
		if err := pollNumVfs(numVfsPath, "0", 2*time.Second, 50*time.Millisecond); err != nil {
			return fmt.Errorf("VFs did not deallocate in time: %w", err)
		}
	}

	if vfCount > 0 {
		if err := os.WriteFile(numVfsPath, []byte(strconv.Itoa(int(vfCount))), 0); err != nil {
			return fmt.Errorf("kernel rejected VF count %d: %w", vfCount, err)
		}

		expected := strconv.Itoa(int(vfCount))
		if err := pollNumVfs(numVfsPath, expected, 5*time.Second, 100*time.Millisecond); err != nil {
			return fmt.Errorf("write succeeded but kernel reverted VFs (check dmesg): %w", err)
		}
	}

	// After VF manipulation the PF can go operstate=down; detect and recover.
	if err := ensurePFLinkUp(device); err != nil {
		return fmt.Errorf("PF link recovery failed for %s: %w", device, err)
	}

	return nil
}

func pollNumVfs(path, expected string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		buf, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if strings.TrimSpace(string(buf)) == expected {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s to become %s (current: %s)",
				path, expected, strings.TrimSpace(string(buf)))
		}
		time.Sleep(interval)
	}
}

// ensurePFLinkUp checks if the PF interface is down and brings it up if needed.
// device is the interface name directly (e.g. "enp3s0f0").
func ensurePFLinkUp(device string) error {
	link, err := netlink.LinkByName(device)
	if err != nil {
		return fmt.Errorf("netlink: could not find interface %s: %w", device, err)
	}

	if link.Attrs().OperState == netlink.OperUp {
		return nil
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("netlink: failed to bring %s up: %w", device, err)
	}

	if err := pollLinkUp(device, 3*time.Minute, 100*time.Millisecond); err != nil {
		return fmt.Errorf("PF %s did not come up after LinkSetUp: %w", device, err)
	}

	return nil
}

func pollLinkUp(device string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		link, err := netlink.LinkByName(device)
		if err != nil {
			return fmt.Errorf("netlink: lookup %s: %w", device, err)
		}
		if link.Attrs().OperState == netlink.OperUp {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s operstate to become up (current: %s)",
				device, link.Attrs().OperState)
		}
		time.Sleep(interval)
	}
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
		err = fmt.Errorf("ParseVfIfaceName: could not parse all arguments for %s expected 2, got %d", ifname, n)
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
	return &VFList{Count: uint8(len(res)), Data: res}, nil
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
