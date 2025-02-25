// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Framebuffer driver information
type fbDriver struct {
	name  string // Driver name
	sysfs string // Driver's sysfs path
}

// Virtual Terminal (VT) console information
type vtInfo struct {
	index int    // VT index
	name  string // VT name
	bound bool   // Is bound?
	sysfs string // Driver's sysfs path
}

// Constants taken from Linux kernel header: linux/vt.h
//
//revive:disable:var-naming
const (
	VT_OPENQRY    = 0x5600 // Query for a free Virtual Terminal
	VT_ACTIVATE   = 0x5606 // Activate Virtual Terminal
	VT_WAITACTIVE = 0x5607 // Wait for Virtual Terminal
)

// Global list of Virtual Terminal (VT) consoles
var deviceVTs []vtInfo
var mutex sync.Mutex

// Execute ioctl(). In case of error, close fd before return
func doIOCTL(fd int, req uint, value int) error {
	err := unix.IoctlSetInt(fd, req, value)
	if err != nil {
		if err := unix.Close(fd); err != nil {
			log.Errorf("Cannot close file descriptor: %v", err)
		}
		return err
	}
	return nil
}

// Read from a file
func sysfsRead(file string) (string, error) {
	contents, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return string(contents), nil
}

// Write to a file
func sysfsWrite(file string, contents string) error {
	return os.WriteFile(file, []byte(contents), 0)
}

// Unbind video framebuffer from framebuffer driver
func (fbDrv fbDriver) unbind() error {
	return sysfsWrite(path.Join(fbDrv.sysfs, "unbind"), fbDrv.name)
}

// Bind video framebuffer to framebuffer driver
func (fbDrv fbDriver) bind() error {
	return sysfsWrite(path.Join(fbDrv.sysfs, "bind"), fbDrv.name)
}

// Get a list of all framebuffer drivers available at sysfs
func getFBDrvs() ([]fbDriver, error) {
	fbDir := "/sys/bus/platform/drivers"
	sysfb := os.DirFS(fbDir)
	fbDrvsPaths, err := fs.Glob(sysfb, "*-framebuffer")

	if err != nil {
		return nil, err
	}

	drvs := make([]fbDriver, 0, len(fbDrvsPaths))
	for _, v := range fbDrvsPaths {
		drv := fbDriver{
			name:  fmt.Sprintf("%s.0", v),
			sysfs: path.Join(fbDir, v),
		}
		drvs = append(drvs, drv)
	}

	return drvs, nil
}

// Unbind all framebuffer drivers
// Our kernel has FRAMEBUFFER_CONSOLE_DETECT_PRIMARY enabled, which
// means that framebuffer console will automatically select the
// primary display device (if supported by the architecture).
// Otherwise, the framebuffer console will always select the first
// framebuffer driver that is loaded (default behavior). However,
// this can be changed by fbcon=map: kernel boot option. In
// a nutshell, so far we don't have a reliable way to detect which
// framebuffer driver needs to be unbound, so we just try to unbind all
// available drivers without care with errors.
func fbUnbindAll() error {
	fbDrvs, err := getFBDrvs()
	if err != nil {
		return err
	}
	for _, fb := range fbDrvs {
		// If the driver is not bound, the unbind will fail (for now we
		// don't care, let's just log a warning)
		log.Noticef("Unbind framebuffer driver: %s\n", fb.name)
		if err := fb.unbind(); err != nil {
			log.Warnf("Fail to unbind framebuffer driver %s: %v", fb.name, err)
		}
	}

	return nil
}

// Like fbUnbindAll(), we don't know which drivers are needed or not, so
// just try to bind them in order
func fbBindAll() error {
	fbDrvs, err := getFBDrvs()
	if err != nil {
		return err
	}
	for _, fb := range fbDrvs {
		// If the driver is not bind, the unbind will fail (for now we
		// don't care)
		log.Noticef("Bind framebuffer driver: %s\n", fb.name)
		if err := fb.bind(); err != nil {
			log.Warnf("Fail to bind framebuffer driver %s: %v", fb.name, err)
		}
	}

	return nil
}

// Unbind Virtual Terminal (VT) console
func (vt vtInfo) unbind() error {
	return sysfsWrite(path.Join(vt.sysfs, "bind"), "0")
}

// Bind Virtual Terminal (VT) console
func (vt vtInfo) bind() error {
	return sysfsWrite(path.Join(vt.sysfs, "bind"), "1")
}

// Get next free virtual terminal console
func findFreeVT() (int, error) {
	// Open default console file device
	fd, err := unix.Open("/dev/tty0", unix.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

	// Execute IOCTL
	vt, err := unix.IoctlGetInt(fd, VT_OPENQRY)
	if err != nil {
		if err := unix.Close(fd); err != nil {
			log.Errorf("Cannot close file descriptor: %v", err)
		}
		return -1, err
	}

	// Close the console file device
	err = unix.Close(fd)
	if err != nil {
		return vt, err
	}
	return vt, err
}

// Switch virtual terminal console
func chvt(vt int) error {
	// Open default console file device
	fd, err := unix.Open("/dev/tty0", unix.O_RDWR, 0)
	if err != nil {
		return err
	}

	// Execute IOCTLs
	if err := doIOCTL(fd, VT_ACTIVATE, vt); err != nil {
		return err
	}
	if err := doIOCTL(fd, VT_WAITACTIVE, vt); err != nil {
		return err
	}

	// Close the console file device
	err = unix.Close(fd)
	if err != nil {
		return err
	}
	return err
}

// Return the active tty device
func getActiveTTY() (string, error) {
	return sysfsRead("/sys/devices/virtual/tty/tty0/active")
}

// Get a list of all VT consoles from sysfs
func listAllVTConsoles() ([]vtInfo, error) {
	vtdir := "/sys/class/vtconsole"
	sysvt := os.DirFS(vtdir)
	vtDrvs, err := fs.Glob(sysvt, "vtcon*")

	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile("vtcon([0-9]+)$")

	var drvs []vtInfo
	for _, v := range vtDrvs {
		match := re.FindStringSubmatch(v)
		if len(match) != 2 {
			continue
		}
		// Index is the only field really important for unbind/bind
		index, err := strconv.Atoi(match[1])
		if err != nil {
			return nil, err
		}
		// Other fields are not critical, so let's not fail in case of
		// error
		name, err := sysfsRead(path.Join(vtdir, v, "name"))
		if err != nil {
			log.Errorf("Cannot read VT %v driver's name: %v", v, err)
		}
		bind, err := sysfsRead(path.Join(vtdir, v, "bind"))
		if err != nil {
			log.Errorf("Cannot read VT %v bind state: %v", v, err)
		}
		bound, err := strconv.ParseBool(strings.TrimRight(bind, "\n"))
		if err != nil {
			log.Errorf("Cannot convert VT %v bind state: %v", v, err)
		}

		drv := vtInfo{
			index: index,
			name:  name,
			bound: bound,
			sysfs: path.Join(vtdir, v),
		}
		drvs = append(drvs, drv)
	}

	return drvs, nil
}

// Unbind all active VT consoles
// This function will first scan the system to retrieve all available VT
// consoles and it will save the current state into a global list of VTs.
// Then it will unbind all active VTs (i.e., when sysfs bind file == 1).
// If the global list of VTs is not empty, that means VTs were already
// unbound and an error is returned.
func vtUnbindAll() error {
	mutex.Lock()
	defer mutex.Unlock()
	var err error
	if len(deviceVTs) > 0 {
		return fmt.Errorf("VTs are already unbound. Please, bind them again before try to unbind.")
	}

	// Retrieve VT consoles
	deviceVTs, err = listAllVTConsoles()
	if err != nil {
		return fmt.Errorf("Cannot retrieve available VTs: %v", err)
	}

	// Unbind only active VTs
	for _, vt := range deviceVTs {
		if vt.bound {
			if err := vt.unbind(); err != nil {
				return err
			}
		}
	}

	return nil
}

// Bind all activated VT consoles
// This function run through the global list of VTs and will re-bind all
// VTs that were activated before unbind. The list will be cleared at the
// end so it can be populated on a next call of vtUnbindAll()
func vtBindAll() error {
	mutex.Lock()
	defer mutex.Unlock()
	if len(deviceVTs) == 0 {
		return fmt.Errorf("No saved VTs to bind")
	}
	for _, vt := range deviceVTs {
		if vt.bound {
			if err := vt.bind(); err != nil {
				deviceVTs = nil // Clear the global list before return
				return fmt.Errorf("Fail to bind VT console: %v", vt.name)
			}
		}
	}

	// Clear the global list
	deviceVTs = nil
	return nil
}
