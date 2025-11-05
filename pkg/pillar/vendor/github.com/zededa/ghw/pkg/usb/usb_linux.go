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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/zededa/ghw/pkg/linuxpath"
	"github.com/zededa/ghw/pkg/option"
	"github.com/zededa/ghw/pkg/pci"
	pciAddress "github.com/zededa/ghw/pkg/pci/address"
	usbAddress "github.com/zededa/ghw/pkg/usb/address"
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

func fillUSBFromUevent(dev *Device) (err error) {
	ueventFp, err := os.Open(dev.UEventFilePath)
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

	// filter out USB devices with the same address
	// this happens if a USB device has several "functions"
	// as functions cannot be passed-through separately,
	// we ignore these
	seen := map[usbAddress.Address]struct{}{}
	for _, dir := range usbDevicesDirs {
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

		dev.UEventFilePath = filepath.Join(fullDir, "uevent")
		if opts.USBUeventPath != "" && opts.USBUeventPath != dev.UEventFilePath {
			continue
		}

		err = fillUSBFromUevent(&dev)
		if err != nil {
			errs = append(errs, err)
		}

		dev.Interface = slurp(filepath.Join(fullDir, "interface"))
		dev.Product = slurp(filepath.Join(fullDir, "product"))
		dev.Devnum = slurp(filepath.Join(fullDir, "devnum"))
		dev.Busnum, dev.Port, err = ExtractUSBBusnumPort(fullDir)
		if err != nil {
			continue
		}
		_, found := seen[dev.Address]
		if found {
			continue
		}
		seen[dev.Address] = struct{}{}
		dev.Class = slurp(filepath.Join(fullDir, "bDeviceClass"))
		dev.Subclass = slurp(filepath.Join(fullDir, "bDeviceSubClass"))
		dev.Protocol = slurp(filepath.Join(fullDir, "bDeviceProtocol"))

		// Parent logic
		parentDir := filepath.Dir(fullDir)
		// Check if parent is USB
		if _, err := os.Stat(filepath.Join(parentDir, "busnum")); err == nil {
			busnum, port, err := ExtractUSBBusnumPort(parentDir)
			if err == nil && port != "" && port != dev.Port {
				dev.Parent.USB = &usbAddress.Address{
					Busnum: busnum,
					Port:   port,
				}
			}
		}

		sysLessFullDir := strings.TrimPrefix(fullDir, paths.SysBlock)
		pciAddr := pci.FindPCIAddress(sysLessFullDir)
		if m := pciBDFRe.FindStringSubmatch(pciAddr); m != nil {
			dev.Parent.PCI = &pciAddress.Address{
				Domain:   m[1],
				Bus:      m[2],
				Device:   m[3],
				Function: m[4],
			}
		}

		devs = append(devs, &dev)
	}

	return devs, errs
}

// ExtractUSBBusnumPort extracts busnum and port number out of a sysfs device path
func ExtractUSBBusnumPort(path string) (uint16, string, error) {
	var busnum uint16

	re := regexp.MustCompile(`\/usb\d+(\/\d+\-[\d\.]+)*(\/(\d+)\-([\d\.]+))`)

	matches := re.FindStringSubmatch(path)
	if len(matches) < 3 {
		return busnum, "", fmt.Errorf("could not extract usb portnum from %s", path)
	}
	port := matches[len(matches)-1]
	busnumString := matches[len(matches)-2]
	busnum64, err := strconv.ParseUint(busnumString, 10, 16)
	if err != nil {
		return 0, port, fmt.Errorf("could not extract usb busnum from %s", path)
	}
	busnum = uint16(busnum64)

	return busnum, port, nil
}
