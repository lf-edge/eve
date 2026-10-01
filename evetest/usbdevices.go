// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"
)

// appUSBListTimeout bounds the SSH command behind ListUSBDevicesInsideApp;
// reaching an application goes through a port forward and sshd inside it.
const appUSBListTimeout = 20 * time.Second

// USBControllerBus is the QEMU bus name of the USB 3.0 (xHCI) controller that
// every EVE device VM has on the qemu and proxmox providers, for device_add.
const USBControllerBus = "evxhci.0"

// USBDeviceInfo is one USB device as EVE's kernel enumerates it under
// /sys/bus/usb/devices. (USBDevice, the vendor/product pair, is a requirement
// type; see requirements.go.)
type USBDeviceInfo struct {
	Bus       uint16 // kernel-assigned bus number, not stable across boots
	Port      string // port path below the root hub, e.g. "2" or "2.3"
	VendorID  uint16
	ProductID uint16
	Serial    string // empty when the device reports none
}

// String formats the device as "<bus>-<port> <vendor>:<product>", the sysfs
// name followed by the ids as lsusb prints them, plus the serial if any.
func (d USBDeviceInfo) String() string {
	s := fmt.Sprintf("%d-%s %04x:%04x", d.Bus, d.Port, d.VendorID, d.ProductID)
	if d.Serial != "" {
		s += " serial=" + d.Serial
	}
	return s
}

// USBDeviceList is what ListUSBDevices returns. It prints itself, so it can be
// the subject of matchers.SatisfyPredicate.
type USBDeviceList []USBDeviceInfo

func (l USBDeviceList) String() string {
	if len(l) == 0 {
		return "no USB devices"
	}
	parts := make([]string, len(l))
	for i, d := range l {
		parts[i] = d.String()
	}
	return strings.Join(parts, ", ")
}

// FindBySerial returns the device with the given serial number, or nil.
func (l USBDeviceList) FindBySerial(serial string) *USBDeviceInfo {
	for i := range l {
		if l[i].Serial == serial {
			return &l[i]
		}
	}
	return nil
}

// listUSBDevicesScript prints one line per USB device: its sysfs name
// (<bus>-<port>), vendor id, product id and serial number. Root hubs are named
// usbN and interfaces carry a colon (<bus>-<port>:<config>.<iface>), so
// neither is listed. Serial numbers are printed as they are, so one containing
// whitespace would not parse; none of the devices tests plug in has one.
const listUSBDevicesScript = `for d in /sys/bus/usb/devices/*-*; do
  n="${d##*/}"
  case "$n" in *:*) continue;; esac
  [ -r "$d/idVendor" ] || continue
  printf '%s %s %s %s\n' "$n" "$(cat "$d/idVendor")" "$(cat "$d/idProduct")" \
    "$(cat "$d/serial" 2>/dev/null)"
done`

// ListUSBDevices returns the USB devices EVE sees, read from
// /sys/bus/usb/devices over SSH. It returns an error instead of failing the
// test, so it can be polled from Eventually while a device is still
// enumerating.
func (d *EdgeDevice) ListUSBDevices() (USBDeviceList, error) {
	stdout, _, err := d.RunShellScript(listUSBDevicesScript, quickSSHCommandTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("ListUSBDevices: SSH command failed: %w", err)
	}
	return parseUSBDeviceList(stdout)
}

// WaitForUSBDevice polls ListUSBDevices until a device with the serial number
// is enumerated and returns it, failing the test through t if timeout passes
// first. A listing error counts as not enumerated yet and is retried.
func (d *EdgeDevice) WaitForUSBDevice(t gomega.Gomega, serial string,
	timeout, polling time.Duration) *USBDeviceInfo {
	var found *USBDeviceInfo
	t.Eventually(d.ListUSBDevices, timeout, polling).Should(gomega.Satisfy(
		func(list USBDeviceList) bool {
			found = list.FindBySerial(serial)
			return found != nil
		}), "EVE enumerates a USB device with serial %q", serial)
	return found
}

// ListUSBDevicesInsideApp is ListUSBDevices for the guest of an application:
// the USB devices its kernel enumerates, read over SSH into the application
// (see RunShellScriptInsideApp for how it is reached). A device passed
// through from EVE shows up here with the ids and serial number it has on
// EVE, but on the guest's own bus and port.
func (d *EdgeDevice) ListUSBDevicesInsideApp(appUUID uuid.UUID,
	auth AuthMethod) (USBDeviceList, error) {
	stdout, _, err := d.RunShellScriptInsideApp(appUUID, auth, listUSBDevicesScript,
		appUSBListTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("ListUSBDevicesInsideApp: SSH command failed: %w", err)
	}
	return parseUSBDeviceList(stdout)
}

// parseUSBDeviceList parses the output of listUSBDevicesScript.
func parseUSBDeviceList(stdout string) (USBDeviceList, error) {
	var list USBDeviceList
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 3 || len(fields) > 4 {
			return nil, fmt.Errorf("unexpected USB device line %q", line)
		}
		bus, port, ok := strings.Cut(fields[0], "-")
		busNum, err := strconv.ParseUint(bus, 10, 16)
		if !ok || err != nil || port == "" {
			return nil, fmt.Errorf("unexpected USB device name %q", fields[0])
		}
		vendor, err := strconv.ParseUint(fields[1], 16, 16)
		if err != nil {
			return nil, fmt.Errorf("unexpected USB vendor id %q: %w", fields[1], err)
		}
		product, err := strconv.ParseUint(fields[2], 16, 16)
		if err != nil {
			return nil, fmt.Errorf("unexpected USB product id %q: %w", fields[2], err)
		}
		dev := USBDeviceInfo{
			Bus:       uint16(busNum),
			Port:      port,
			VendorID:  uint16(vendor),
			ProductID: uint16(product),
		}
		if len(fields) == 4 {
			dev.Serial = fields[3]
		}
		list = append(list, dev)
	}
	return list, nil
}

// usbStorageUnplugTimeout bounds how long DetachUSBStorage waits for QEMU to
// release the drive's block node after device_del.
const usbStorageUnplugTimeout = 10 * time.Second

// AttachUSBStorage plugs a blank USB flash drive of the given size into the
// running device: a scratch image on the hypervisor host, a raw block node on
// top of it and a usb-storage device on the VM's xHCI controller
// (USBControllerBus). id is the QEMU device id, the block node name, the
// scratch image name and the drive's USB serial number, so that ListUSBDevices
// finds the drive with FindBySerial(id). Fails the test on error, undoing the
// steps already done.
//
// The drive goes into the lowest free port of the controller, and a drive
// re-plugged under the same id goes back into the port it left while that is
// free (see usbPortAllocator), like a physical re-plug into the same
// receptacle; a device-model entry claiming it by bus and port thus keeps
// matching. The controller has four ports on both providers.
//
// Requires RequireCapabilities{CAPABILITY_QMP}.
func (d *EdgeDevice) AttachUSBStorage(id string, sizeBytes uint64) {
	hostPath := d.CreateScratchImage(id, sizeBytes)
	_, err := d.TryExecuteQMP("blockdev-add", map[string]any{
		"driver":    "raw",
		"node-name": id,
		"file":      map[string]any{"driver": "file", "filename": hostPath},
	})
	if err != nil {
		if delErr := d.tryDeleteScratchImage(id); delErr != nil {
			Logger().Warnf("AttachUSBStorage: cleanup failed: %v", delErr)
		}
		d.th.t.Fatalf("AttachUSBStorage: %v", err)
	}
	port := d.claimUSBPort(id)
	_, err = d.TryExecuteQMP("device_add", map[string]any{
		"driver": "usb-storage",
		"id":     id,
		"bus":    USBControllerBus,
		"port":   port,
		"drive":  id,
		"serial": id,
	})
	if err != nil {
		d.releaseUSBPort(id)
		if _, delErr := d.TryExecuteQMP("blockdev-del", map[string]any{"node-name": id}); delErr != nil {
			Logger().Warnf("AttachUSBStorage: cleanup failed: %v", delErr)
		}
		if delErr := d.tryDeleteScratchImage(id); delErr != nil {
			Logger().Warnf("AttachUSBStorage: cleanup failed: %v", delErr)
		}
		d.th.t.Fatalf("AttachUSBStorage: %v", err)
	}
	Logger().Infof("Attached USB flash drive %q (%d bytes) to port %s of device %q",
		id, sizeBytes, port, d.devName)
}

// claimUSBPort picks the xHCI port for the drive id (see usbPortAllocator).
func (d *EdgeDevice) claimUSBPort(id string) string {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	return d.th.devices[d.devName].usbPorts.claim(id)
}

// releaseUSBPort frees the xHCI port of the drive id once it is unplugged.
func (d *EdgeDevice) releaseUSBPort(id string) {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	d.th.devices[d.devName].usbPorts.release(id)
}

// DetachUSBStorage unplugs a drive attached by AttachUSBStorage and deletes
// its image. device_del completes asynchronously, so releasing the block node
// is retried for a short while.
func (d *EdgeDevice) DetachUSBStorage(id string) {
	d.ExecuteQMP("device_del", map[string]any{"id": id})
	deadline := time.Now().Add(usbStorageUnplugTimeout)
	for {
		_, err := d.TryExecuteQMP("blockdev-del", map[string]any{"node-name": id})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			d.th.t.Fatalf("DetachUSBStorage: block node %q still in use %v after device_del: %v",
				id, usbStorageUnplugTimeout, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	d.DeleteScratchImage(id)
	d.releaseUSBPort(id)
	Logger().Infof("Detached USB flash drive %q from device %q", id, d.devName)
}

// usbPortAllocator chooses the xHCI ports that AttachUSBStorage plugs drives
// into. Left to QEMU, a drive gets the head of the bus's free-port list, and a
// released port goes back to its tail, so a re-plugged drive would land on a
// different port and stop matching a device-model entry that claims it by bus
// and port. This allocator hands out the lowest free port instead and
// remembers each id's port, so a re-plugged drive gets the port it left for
// as long as that is free. Not safe for concurrent use; the harness locks.
type usbPortAllocator struct {
	byID map[string]string // id -> port, remembered across release
	used map[string]string // port -> id currently holding it
}

// claim returns the port for id: the one it holds or last held if free,
// otherwise the lowest free port.
func (a *usbPortAllocator) claim(id string) string {
	if a.byID == nil {
		a.byID = make(map[string]string)
		a.used = make(map[string]string)
	}
	if port, ok := a.byID[id]; ok {
		if holder, taken := a.used[port]; !taken || holder == id {
			a.used[port] = id
			return port
		}
	}
	for n := 1; ; n++ {
		port := strconv.Itoa(n)
		if _, taken := a.used[port]; !taken {
			a.used[port] = id
			a.byID[id] = port
			return port
		}
	}
}

// release frees the port id holds; id keeps its claim on it for a re-plug.
func (a *usbPortAllocator) release(id string) {
	if port, ok := a.byID[id]; ok && a.used[port] == id {
		delete(a.used, port)
	}
}
