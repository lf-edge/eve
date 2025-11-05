//go:build linux && !gousb
// +build linux,!gousb

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
	"strings"

	"github.com/jaypipes/ghw/pkg/context"
	"github.com/jaypipes/ghw/pkg/linuxpath"
)

func (i *Info) load() error {
	var errs []error

	i.USBs, errs = usbs(i.ctx)

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("error(s) happened during reading usb info: %+v", errs)
}

func fillUSBFromUevent(dir string, usb *USB) (err error) {
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
		case "BUSNUM":
			usb.Busnum = val
		case "DEVNUM":
			usb.Devnum = val
		case "DRIVER":
			usb.Driver = val
		case "TYPE":
			usb.Type = val
		case "PRODUCT":
			splits := strings.SplitN(val, "/", 3)
			if len(splits) != 3 {
				continue
			}
			usb.VendorID = splits[0]
			usb.ProductID = splits[1]
			usb.RevisionID = splits[2]
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

// this comes from https://github.com/lf-edge/eve/blob/master/pkg/pillar/cmd/usbmanager/scanusb.go#L24
func extractPCIAddressFromSysfsPath(path string) string {
	re := regexp.MustCompile(`\/?devices\/pci[\d:.]*\/(\d{4}:[a-f\d:\.]+)\/`)

	matches := re.FindStringSubmatch(path)
	if len(matches) != 2 {
		return ""
	}
	pciAddress := matches[1]

	return pciAddress
}

func usbs(ctx *context.Context) ([]*USB, []error) {
	usbs := make([]*USB, 0)
	errs := []error{}

	paths := linuxpath.New(ctx)
	usbDevicesDirs, err := os.ReadDir(paths.SysBusUsbDevices)
	if err != nil {
		return usbs, []error{err}
	}

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

		usb := USB{}

		err = fillUSBFromUevent(fullDir, &usb)
		if usb.Busnum == "" || usb.Devnum == "" {
			continue
		}
		if err != nil {
			errs = append(errs, err)
		}

		parentFullDir := filepath.Dir(fullDir)
		parentUsb := USB{}
		err = fillUSBFromUevent(parentFullDir, &parentUsb)
		if err == nil && parentUsb.Busnum != "" && parentUsb.Devnum != "" {
			usb.ParentBusnum = parentUsb.Busnum
			usb.ParentDevnum = parentUsb.Devnum
		}

		usb.Interface = slurp(filepath.Join(fullDir, "interface"))
		usb.Product = slurp(filepath.Join(fullDir, "product"))

		pciAddress := extractPCIAddressFromSysfsPath(strings.TrimPrefix(fullDir, paths.SysRoot))
		// not every USB controller is on PCI bus, f.e. Raspberry Pi
		usb.PCIAddress = pciAddress

		usbs = append(usbs, &usb)
	}

	return usbs, errs
}
