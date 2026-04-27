// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package serial

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zededa/ghw/pkg/bus"
	"github.com/zededa/ghw/pkg/linuxpath"
	"github.com/zededa/ghw/pkg/option"
	"github.com/zededa/ghw/pkg/pci"
	pciAddress "github.com/zededa/ghw/pkg/pci/address"
	"github.com/zededa/ghw/pkg/usb"
	usbAddress "github.com/zededa/ghw/pkg/usb/address"
)

func (i *Info) load(opts *option.Options) error {
	var errs []error

	i.Devices, errs = serials(opts)

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("error(s) happened during reading serial info: %+v", errs)
}

func serials(opts *option.Options) ([]*Device, []error) {
	paths := linuxpath.New(opts)
	ttyClass := paths.SysClassTty
	entries, err := os.ReadDir(ttyClass)
	if err != nil {
		return nil, []error{err}
	}

	var out []*Device
	id := 1
	for _, entry := range entries {
		tty := entry.Name() // ttyS1
		sp, ok, err := serialPortFromTTY(paths.SysRoot, ttyClass, tty)
		if err != nil {
			continue
		}
		if ok {
			sp.Name = fmt.Sprintf("COM%d", id)
			out = append(out, sp)
			id++
		}
	}
	return out, nil
}

func serialPortFromTTY(sysfs, ttyClass, tty string) (*Device, bool, error) {
	ttyDir := filepath.Join(ttyClass, tty)

	// Must have /sys/class/tty/<tty>/device symlink to be hardware-backed.
	devLink := filepath.Join(ttyDir, "device")
	devSys, err := filepath.EvalSymlinks(devLink)
	if err != nil {
		return nil, false, nil
	}

	irq, _ := readUintDecimal(filepath.Join(ttyDir, "irq"))
	ioType, _ := readUintDecimal(filepath.Join(ttyDir, "io_type"))
	portBase, portOK := readUintHex(filepath.Join(ttyDir, "port"))

	ioRange := ""
	if portOK && isIOPortUART(ioType) {
		start := portBase
		end := portBase + 7 // 8250 register block: 8 bytes

		// Optional: clamp to containing PCI IO BAR if we can find it.
		if pciDir, ok := findPCIDeviceDirFromResolvedDevice(sysfs, devSys); ok {
			if barStart, barEnd, ok := findContainingPCIIoBAR(pciDir, start); ok {
				if start < barStart {
					start = barStart
				}
				if end > barEnd {
					end = barEnd
				}
			}
		}

		ioRange = fmt.Sprintf("%04x-%04x", start, end)
	}

	pciAddrString := pci.FindPCIAddress(devSys)
	var parent bus.BusParent
	if pciAddr := pciAddress.FromString(pciAddrString); pciAddr != nil {
		parent.PCI = pciAddr
	}
	bus, port, err := usb.ExtractUSBBusnumPort(devSys)
	if err == nil {
		parent.USB = &usbAddress.Address{
			Busnum: bus,
			Port:   port,
		}
	}

	sp := &Device{
		Address: "/dev/" + tty,
		IO:      ioRange,
		IRQ:     fmt.Sprintf("%d", irq),
		Parent:  parent,
	}
	return sp, true, nil
}

func isIOPortUART(ioType uint64) bool {
	// For ttyS* this is commonly 0 for IO port access.
	return ioType == 0
}

func findPCIDeviceDirFromResolvedDevice(sysfs, devSys string) (string, bool) {
	addr := pciAddress.FromString(devSys)
	if addr == nil {
		return "", false
	}

	// Common layout:
	// /sys/devices/pci0000:00/0000:00:02.0
	pciRoot := fmt.Sprintf("pci%s:%s", addr.Domain, addr.Bus)
	bdf := fmt.Sprintf("%s:%s:%s.%s", addr.Domain, addr.Bus, addr.Device, addr.Function)
	candidate := filepath.Join(sysfs, "devices", pciRoot, bdf)
	if statOK(candidate) {
		return candidate, true
	}

	// Fallback: walk up from devSys looking for base == BDF.
	cur := devSys
	for i := 0; i < 32; i++ {
		if filepath.Base(cur) == bdf && statOK(cur) {
			return cur, true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return "", false
}

func readUintDecimal(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	return strconv.ParseUint(s, 10, 64)
}

func readUintHex(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "0" {
		return 0, false
	}
	s = strings.TrimPrefix(s, "0x")
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func statOK(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Parse <pci>/resource and find the IO BAR that contains port.
// resource format: "start end flags" per line, hex.
func findContainingPCIIoBAR(pciDevDir string, port uint64) (start, end uint64, ok bool) {
	f, err := os.Open(filepath.Join(pciDevDir, "resource"))
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()

	const IORESOURCE_IO = 0x00000100

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		st, err0 := parseHex(fields[0])
		en, err1 := parseHex(fields[1])
		fl, err2 := parseHex(fields[2])
		if err0 != nil || err1 != nil || err2 != nil {
			continue
		}
		if st == 0 && en == 0 {
			continue
		}
		if (fl & IORESOURCE_IO) == 0 {
			continue
		}
		if port >= st && port <= en {
			return st, en, true
		}
	}
	return 0, 0, false
}

func parseHex(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	return strconv.ParseUint(s, 16, 64)
}
