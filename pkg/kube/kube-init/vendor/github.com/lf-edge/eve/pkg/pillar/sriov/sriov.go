// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package sriov

import (
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

// NicLinuxPath is the sysfs root for network devices. It is a var rather than
// a const so tests can repoint GetVf at a fake sysfs tree.
var NicLinuxPath = "/sys/class/net/"

// constants for Linux paths for devices
const (
	PciDevicesPath    = "/sys/bus/pci/devices/"
	NumVfsDevicePath  = "/device/sriov_numvfs"
	TotalVfsPath      = "/device/sriov_totalvfs"
	AutoprobePath     = "/device/sriov_drivers_autoprobe"
	VfCountFieldName  = "sriov-vf-count"
	MaxVfCount        = 255
	VfCreationTimeout = 150 * time.Second
)

// CreateVF creates Virtual Functions of given count for the Physical Function
// at the given PCI BDF.
//
// The sysfs writes go through /sys/bus/pci/devices/<bdf>/sriov_* rather than
// /sys/class/net/<dev>/device/sriov_* because the latter is sensitive to the
// kernel netdev name.  In the EVE-K path NIM renames a PF netdev (e.g.
// eth2 -> keth2) when it bridges it; if that rename overlaps with our sysfs
// poll, the /sys/class/net/<old-name> path disappears mid-call and the whole
// operation fails.  The PCI BDF is stable across renames, so anchoring on it
// makes CreateVF robust against this race.
func CreateVF(pciBDF string, vfCount uint8, log *base.LogObject) error {
	devBase := filepath.Join(PciDevicesPath, pciBDF)
	numVfsPath := filepath.Join(devBase, "sriov_numvfs")
	autoprobePath := filepath.Join(devBase, "sriov_drivers_autoprobe")
	totalVfsPath := filepath.Join(devBase, "sriov_totalvfs")

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
			log.Warnf("Warning: could not disable autoprobe on %s: %s", pciBDF, err)
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
		// numvfs already at target — still ensure the PF is up before
		// returning, in case a prior CreateVF aborted between the kernel
		// allocating VFs and the link recovery step.
		if err := ensurePFAdminUp(pciBDF); err != nil {
			return fmt.Errorf("PF admin-up recovery failed for %s: %w", pciBDF, err)
		}
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

	// Bumping sriov_numvfs can clear IFF_UP on some drivers; restore it.
	// Do not wait for carrier — cable-less passthrough PFs are valid.
	if err := ensurePFAdminUp(pciBDF); err != nil {
		return fmt.Errorf("PF admin-up recovery failed for %s: %w", pciBDF, err)
	}

	return nil
}

// resolvePFIfnameFromBDF returns the current netdev name of the PF at the
// given PCI BDF.  Reading /sys/bus/pci/devices/<bdf>/net/ is BDF-anchored and
// always reflects the current kernel name, so a rename (e.g. eth2 -> keth2)
// that races with our caller is observed on the next call rather than
// blowing up an already-cached name.
func resolvePFIfnameFromBDF(pciBDF string) (string, error) {
	netDir := filepath.Join(PciDevicesPath, pciBDF, "net")
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return "", fmt.Errorf("readdir %s: %w", netDir, err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("no netdev under %s", netDir)
	}
	return entries[0].Name(), nil
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

// ensurePFAdminUp makes sure the PF netdev has the IFF_UP admin flag set.
//
// Bumping sriov_numvfs causes some drivers (ixgbe, i40e) to reset the PF and
// clear IFF_UP; VF creation itself succeeds but downstream operations that
// expect an admin-up PF (per-VF MAC/VLAN via netlink) will fail until we
// restore the flag.
//
// IMPORTANT: this checks IFF_UP only, NOT OperState.  Many SR-IOV PFs are
// intentionally cable-less — used purely as a VF source for app passthrough,
// with no host traffic ever flowing on them.  Waiting for OperState=OperUp
// would block forever (or until the cable poll timeout) on those PFs.  The
// kernel allows VF allocation and per-VF config on an IFF_UP / no-carrier PF
// just fine, so that's all we need to guarantee here.
//
// pciBDF (not the netdev name) is the input because NIM may rename the PF
// (e.g. eth2 -> keth2 when bridging) concurrently with this call; the BDF is
// stable and lets us look up the current netdev name at the moment of use.
func ensurePFAdminUp(pciBDF string) error {
	ifname, err := resolvePFIfnameFromBDF(pciBDF)
	if err != nil {
		return fmt.Errorf("resolve PF ifname for %s: %w", pciBDF, err)
	}
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("netlink: could not find interface %s (pci %s): %w",
			ifname, pciBDF, err)
	}
	if link.Attrs().Flags&net.FlagUp != 0 {
		return nil
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("netlink: failed to bring %s (pci %s) admin-up: %w",
			ifname, pciBDF, err)
	}
	return nil
}

// GetVfIfaceName returns formatted VF name
func GetVfIfaceName(index uint8, ifname string) string {
	return fmt.Sprintf("%svf%d", ifname, index)
}

// BindVFToVfioPCI binds the VF at the given PCI BDF to the vfio-pci driver.
//
// EVE sets sriov_drivers_autoprobe=0 on the PF before bumping sriov_numvfs so
// freshly created VFs arrive driverless.  But this is not guaranteed in every
// path: a previous boot may have left numvfs already at the target (in which
// case CreateVF's early-return skips the autoprobe write) and the resident PF
// VF driver (ixgbevf / iavf / igbvf) will have grabbed the VFs the first time
// they appeared.  The upstream sriov-network-device-plugin's `drivers: vfio-pci`
// selector won't match anything bound to those host drivers, so we have to
// actively rebind here — driver_override + drivers_probe alone is a no-op on
// an already-bound device.
//
// Sequence (mirrors what hypervisor.PCIReserveGeneric does for PF passthrough):
//  1. If <vf>/driver already points at vfio-pci, return — nothing to do.
//  2. Write "vfio-pci" to <vf>/driver_override so the next probe pins the
//     driver match to vfio-pci, regardless of vendor:device tables.
//  3. If <vf>/driver exists (bound to host driver), write the BDF to
//     <vf>/driver/unbind to detach it.
//  4. Write the BDF to /sys/bus/pci/drivers_probe to trigger probing.
//  5. Verify <vf>/driver now resolves to .../drivers/vfio-pci.  drivers_probe
//     does NOT return an error if the override driver is missing or no driver
//     ends up bound, so a post-bind check is the only way to catch a kernel
//     that doesn't have vfio-pci registered (or a probe race that failed).
func BindVFToVfioPCI(vfBDF string) error {
	devDir := filepath.Join("/sys/bus/pci/devices", vfBDF)
	driverLink := filepath.Join(devDir, "driver")
	overridePath := filepath.Join(devDir, "driver_override")

	if isVfioPCIBound(driverLink) {
		return nil
	}

	if err := os.WriteFile(overridePath, []byte("vfio-pci"), 0); err != nil {
		return fmt.Errorf("write driver_override for %s: %w", vfBDF, err)
	}

	// Unbind whatever host driver is currently attached.  The driver symlink
	// only exists when a driver is bound, so Stat tells us whether to skip.
	if _, err := os.Stat(driverLink); err == nil {
		unbindPath := filepath.Join(driverLink, "unbind")
		if err := os.WriteFile(unbindPath, []byte(vfBDF), 0); err != nil {
			return fmt.Errorf("unbind %s from current driver: %w", vfBDF, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", driverLink, err)
	}

	if err := os.WriteFile("/sys/bus/pci/drivers_probe", []byte(vfBDF), 0); err != nil {
		return fmt.Errorf("write drivers_probe for %s: %w", vfBDF, err)
	}

	if !isVfioPCIBound(driverLink) {
		// Look at what (if anything) ended up bound so the operator can tell
		// "vfio-pci not in this kernel" from "some other driver re-grabbed it".
		actual, _ := os.Readlink(driverLink)
		return fmt.Errorf("VF %s did not bind to vfio-pci after probe "+
			"(current driver: %q) — check that the kernel has CONFIG_VFIO_PCI "+
			"and that no other driver re-grabbed the device",
			vfBDF, filepath.Base(actual))
	}
	return nil
}

// isVfioPCIBound returns true iff the device's "driver" symlink resolves to
// the vfio-pci driver directory.  Reading the link target is more reliable
// than Stat: SameFile would also work but adds a second Stat for nothing.
func isVfioPCIBound(driverLink string) bool {
	target, err := os.Readlink(driverLink)
	if err != nil {
		return false
	}
	return filepath.Base(target) == "vfio-pci"
}

// GetPFIfaceFromVFBDF returns the kernel netdev name of the Physical Function
// that owns the given Virtual Function PCI BDF.
//
// Path: /sys/bus/pci/devices/<vf-bdf>/physfn/net/<ifname>
//   - "physfn" is a symlink the kernel maintains on every VF, pointing back
//     to its parent PF.
//   - "net/<ifname>" lists the netdev(s) attached to the PF.  A normal SR-IOV
//     PF has exactly one netdev so picking the first entry is unambiguous.
func GetPFIfaceFromVFBDF(vfBDF string) (string, error) {
	netDir := filepath.Join("/sys/bus/pci/devices", vfBDF, "physfn", "net")
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return "", fmt.Errorf("readdir %s: %w", netDir, err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("no netdev under %s", netDir)
	}
	return entries[0].Name(), nil
}

// ParseVfIfaceName splits a VF iface/phylabel like "eth2vf5" into its PF name
// ("eth2") and VF index (5).  Mirrors the inverse of GetVfIfaceName.
//
// Implementation note: the previous version used fmt.Sscanf with format
// "%svf%d", which is broken — Go's %s verb is greedy and consumes the entire
// input, leaving nothing for the literal "vf" or the trailing %d to match.
// Sscanf returns an error and zero values for both fields.  Use a manual
// split on the LAST "vf" occurrence instead, so "eth2vf5" parses correctly
// and the (extremely unusual) case of a PF named "...vf..." is handled by
// only treating the final "vf<digits>" as the suffix.
func ParseVfIfaceName(ifname string) (uint8, string, error) {
	// Scan backwards for the last "vf" that's followed by a valid uint8.
	// i is the position where the digit suffix begins; we need at least
	// two characters before it (for "vf") and at least one char after.
	for i := len(ifname) - 1; i >= 2; i-- {
		if ifname[i-2:i] != "vf" {
			continue
		}
		suffix := ifname[i:]
		if suffix == "" {
			continue
		}
		idx, err := strconv.ParseUint(suffix, 10, 8)
		if err != nil {
			continue
		}
		pf := ifname[:i-2]
		if pf == "" {
			return 0, "", fmt.Errorf("ParseVfIfaceName: empty PF in %q", ifname)
		}
		return uint8(idx), pf, nil
	}
	return 0, "", fmt.Errorf("ParseVfIfaceName: no 'vf<digits>' suffix in %q", ifname)
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
	deadline := time.Now().Add(timeout)
	for {
		vfs, err := GetVf(device)
		if err == nil && vfs != nil && len(vfs.Data) == int(expectedVfCount) {
			return vfs, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("getVfByTimeout reached timeout %v", timeout)
		}
		time.Sleep(1 * time.Second)
	}
}

// EthVF must match EthVF structure in devcommon.proto
type EthVF struct {
	Index   uint8  `json:",omitempty"`
	PciLong string `json:",omitempty"` // BFD notation
	Mac     string `json:",omitempty"`
	VlanID  uint16 `json:",omitempty"`
}

// VFList is list of VF for given PF (Eth device)
type VFList struct {
	Count uint8   `json:",omitempty"`
	Data  []EthVF `json:",omitempty"`
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

// ClearVFAdminMAC zeroes the per-VF admin MAC programmed on the PF's VF
// table.  Called on VM stop/delete/cleanup so the next tenant of this VF
// doesn't inherit the previous VM's admin MAC.
//
// Background: sriov-cni programs the admin MAC on the PF via netlink on pod
// ADD, and is supposed to clear it on pod DEL.  In practice — when the VF is
// pre-bound to vfio-pci (EVE's model) — sriov-cni's DEL path doesn't always
// reach the admin-MAC clear because the VF has no kernel netdev to operate
// on.  Without an explicit clear here, the admin MAC entry on the PF
// persists across VM stops and the next VM that lands on this VF sees the
// previous tenant's MAC programmed on the host side.
//
// Uses the PF ifname (not VF) because LinkSetVfHardwareAddr operates on the
// PF link with a VF index.  Caller passes both because the VF ifname is
// usually torn down once the VF is bound to vfio-pci.
//
// All-zeros MAC is what `ip link set <pf> vf <idx> mac 00:00:00:00:00:00`
// writes; the kernel interprets it as "no admin MAC, let the VF use its
// default" — which is exactly the post-cleanup state we want.
func ClearVFAdminMAC(pfIface string, index uint8) error {
	pf, err := netlink.LinkByName(pfIface)
	if err != nil {
		return fmt.Errorf("ClearVFAdminMAC: find PF %s: %w", pfIface, err)
	}
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	if err := netlink.LinkSetVfHardwareAddr(pf, int(index), zero); err != nil {
		return fmt.Errorf("ClearVFAdminMAC: clear PF %s VF %d: %w",
			pfIface, index, err)
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
