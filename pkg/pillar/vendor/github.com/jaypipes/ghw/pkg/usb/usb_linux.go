// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package usb

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jaypipes/ghw/pkg/linuxpath"
	"github.com/jaypipes/ghw/pkg/option"
)

var pciBDFRe = regexp.MustCompile(`(?i)\b([0-9a-f]{4}):([0-9a-f]{2}):([0-9a-f]{2})\.([0-7])\b`)

func (i *Info) load(opts *option.Options) error {
	var errs []error

	i.Devices, errs = usbs(opts)

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("error(s) happened during reading usb info: %+v", errs)
}

func fillUSBFromUevent(dir string, dev *Device) (err error) {
	ueventFp, err := os.Open(filepath.Join(dir, "uevent"))
	if err != nil {
		return
	}
	defer func() {
		err = ueventFp.Close()
	}()

	sc := bufio.NewScanner(ueventFp)
	for sc.Scan() {
		line := sc.Text()

		splits := strings.SplitN(line, "=", 2)
		if len(splits) != 2 {
			continue
		}

		key := strings.ToUpper(splits[0])
		val := splits[1]

		switch key {
		case "DRIVER":
			dev.Driver = val
		case "TYPE":
			dev.Type = val
		case "PRODUCT":
			splits := strings.SplitN(val, "/", 3)
			if len(splits) != 3 {
				continue
			}
			dev.VendorID = splits[0]
			dev.ProductID = splits[1]
			dev.RevisionID = splits[2]
		}
	}
	return nil
}

func slurp(path string) string {
	bs, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	return string(bytes.TrimSpace(bs))
}

func usbs(opts *option.Options) ([]*Device, []error) {
	paths := linuxpath.New(opts)
	devs := make([]*Device, 0)
	errs := []error{}

	usbDevicesDirs, err := os.ReadDir(paths.SysBusUsbDevices)
	if err != nil {
		return devs, []error{err}
	}

	acsCache := make(map[string]bool)

	for _, dir := range usbDevicesDirs {
		// Skip interfaces, only want root devices
		if strings.Contains(dir.Name(), ":") {
			continue
		}

		fullDir, err := os.Readlink(filepath.Join(paths.SysBusUsbDevices, dir.Name()))
		if err != nil {
			continue
		}
		if !filepath.IsAbs(fullDir) {
			fullDir, err = filepath.Abs(filepath.Join(paths.SysBusUsbDevices, fullDir))
			if err != nil {
				continue
			}
		}

		dev := Device{}

		err = fillUSBFromUevent(fullDir, &dev)
		if err != nil {
			errs = append(errs, err)
		}

		dev.Interface = slurp(filepath.Join(fullDir, "interface"))
		dev.Product = slurp(filepath.Join(fullDir, "product"))
		dev.Busnum = slurp(filepath.Join(fullDir, "busnum"))
		dev.Devnum = slurp(filepath.Join(fullDir, "devnum"))
		dev.Class = slurp(filepath.Join(fullDir, "bDeviceClass"))
		dev.Subclass = slurp(filepath.Join(fullDir, "bDeviceSubClass"))
		dev.Protocol = slurp(filepath.Join(fullDir, "bDeviceProtocol"))

		// Parent logic
		parentDir := filepath.Dir(fullDir)
		// Check if parent is USB
		if _, err := os.Stat(filepath.Join(parentDir, "busnum")); err == nil {
			// It's a USB parent
			bus := slurp(filepath.Join(parentDir, "busnum"))
			devnum := slurp(filepath.Join(parentDir, "devnum"))
			dev.Parent = &BusParent{
				USB: &USBAddress{Bus: bus, Devnum: devnum},
			}
		} else {
			// Check if parent is PCI
			parentName := filepath.Base(parentDir)
			if m := pciBDFRe.FindStringSubmatch(parentName); m != nil {
				dev.Parent = &BusParent{
					PCI: &PCIAddress{
						Domain:   m[1],
						Bus:      m[2],
						Device:   m[3],
						Function: m[4],
					},
				}
			}
		}

		// ACS Logic
		pciAddr := findPCIAddress(fullDir)
		if pciAddr != "" {
			if enabled, ok := acsCache[pciAddr]; ok {
				dev.ACSEnabled = enabled
			} else {
				enabled = checkACSEnabled(pciAddr)
				acsCache[pciAddr] = enabled
				dev.ACSEnabled = enabled
			}
		}

		devs = append(devs, &dev)
	}

	return devs, errs
}

func findPCIAddress(dir string) string {
	for {
		base := filepath.Base(dir)
		if pciBDFRe.MatchString(base) {
			return base
		}
		if base == "devices" || base == "/" || base == "." || dir == "/" {
			return ""
		}
		dir = filepath.Dir(dir)
	}
}

func checkACSEnabled(addr string) bool {
	path, err := exec.LookPath("lspci")
	if err != nil {
		return false
	}
	cmd := exec.Command(path, "-vv", "-s", addr)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Access Control Services")
}
