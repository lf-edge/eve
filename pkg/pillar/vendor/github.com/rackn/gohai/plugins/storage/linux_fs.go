package storage

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// At some point, also need to add mode block device oriented information here

type Volume struct {
	BackingDevice string
	Filesystem    string
	Name          string
	Options       string
	Virtual       bool
	Blocks        struct {
		Size  int64
		Total uint64
		Free  uint64
		Avail uint64
	}
}

type LogicalDisk struct {
	Name       string // Name - /dev/sda
	Vendor     string // Vendor - "ATA"
	Product    string // Product - "INTEL SSDSC2BB12"
	BusInfo    string // BusInfo - "scsi@0:0.0.0"
	Dev        string // Dev - "8:0"
	Size       int64  // Size - 120034123776
	Serial     string // Serial
	Removable  bool   // Removable
	ReadOnly   bool   // ReadOnly
	Rotational bool   // Rotational
}

type Info struct {
	Volumes     []Volume
	Disks       []LogicalDisk
	Controllers []interface{}
}

func (i *Info) Class() string {
	return "Storage"
}

func getStringFromFile(file, def string) string {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return def
	}
	return strings.TrimSpace(string(data))
}

func getInt64FromFile(file string, def int64) int64 {
	s := getStringFromFile(file, "BAD")
	if s == "BAD" {
		return def
	}
	a, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return def
	}
	return a
}

// assumes 0 is false and other is true
func getBoolFromFile(file string, def bool) bool {
	idef := int64(0)
	if def {
		idef = 1
	}
	if ii := getInt64FromFile(file, idef); ii == 0 {
		return false
	}
	return true
}

func Gather() (*Info, error) {
	res := &Info{
		Volumes:     []Volume{},
		Disks:       []LogicalDisk{},
		Controllers: []interface{}{},
	}

	mounts, err := os.Open("/proc/self/mounts")
	if err != nil {
		return nil, err
	}
	defer mounts.Close()
	mountLines := bufio.NewScanner(mounts)
	for mountLines.Scan() {
		line := mountLines.Text()
		fields := strings.Split(line, " ")
		if len(fields) != 6 {
			continue
		}
		vol := Volume{
			Name:          fields[1],
			BackingDevice: fields[0],
			Filesystem:    fields[2],
			Options:       fields[3],
		}
		stat, err := os.Stat(vol.BackingDevice)
		if err == nil {
			vol.Virtual = !(stat.Mode()&os.ModeDevice > 0)
		}
		fsStat := &syscall.Statfs_t{}
		if err := syscall.Statfs(vol.Name, fsStat); err == nil {
			vol.Blocks.Size = int64(fsStat.Bsize)
			vol.Blocks.Total = fsStat.Blocks
			vol.Blocks.Free = fsStat.Bfree
			vol.Blocks.Avail = fsStat.Bavail
		}
		res.Volumes = append(res.Volumes, vol)
	}

	files, err := ioutil.ReadDir("/sys/block")
	if err == nil {
		disks := []LogicalDisk{}
		for _, fi := range files {
			file := fi.Name()
			_, err := os.Stat(fmt.Sprintf("/sys/block/%s/device", file))
			if os.IsNotExist(err) {
				continue
			}
			dtype := getInt64FromFile(fmt.Sprintf("/sys/block/%s/device/type", file), 0)
			switch dtype {
			case 0, 12, 13, 7:
				// These are good.
			default:
				continue
			}

			disk := LogicalDisk{}
			disk.Name = fmt.Sprintf("/dev/%s", file)
			disk.Removable = getBoolFromFile(fmt.Sprintf("/sys/block/%s/removable", file), false)
			disk.ReadOnly = getBoolFromFile(fmt.Sprintf("/sys/block/%s/ro", file), false)
			disk.Rotational = getBoolFromFile(fmt.Sprintf("/sys/block/%s/queue/rotational", file), false)
			disk.Dev = getStringFromFile(fmt.Sprintf("/sys/block/%s/dev", file), "0:0")
			ii := getInt64FromFile(fmt.Sprintf("/sys/block/%s/size", file), 0)
			disk.Size = ii * 512
			disk.Product = getStringFromFile(fmt.Sprintf("/sys/block/%s/device/model", file), "UNKNOWN")
			disk.Vendor = getStringFromFile(fmt.Sprintf("/sys/block/%s/device/vendor", file), "UNKNOWN")

			dir, err := os.Readlink(fmt.Sprintf("/sys/block/%s", file))
			if err != nil {
				dir = "../devices/pci/UNKNOWN"
			}
			parts := strings.Split(dir, "/")
			if len(parts) < 4 {
				disk.BusInfo = "UNKNOWN"
			} else {
				answer := parts[3]
				if strings.Contains(parts[2], "pci") {
					answer = fmt.Sprintf("pci@%s", parts[3])
				}
				disk.BusInfo = answer
			}

			data, err := ioutil.ReadFile(fmt.Sprintf("/sys/block/%s/device/vpd_pg80", file))
			if err == nil {
				len := binary.BigEndian.Uint16(data[2:])
				s := string(data[4:(len - 1)])
				disk.Serial = s
			} else {
				disk.Serial = "UNKNOWN"
			}
			disks = append(disks, disk)
		}
		res.Disks = disks
	}

	// We have lshw - use it.
	if _, err := exec.Command("lshw", "--help").CombinedOutput(); err == nil {
		objs, err := getLSHWPiece("storage")
		if err != nil {
			return nil, err
		}
		res.Controllers = objs
	}
	return res, nil
}

var missingComma = regexp.MustCompile(`\n[ \t]*}[ \t]*{[ \t]*\n`)
var trailingComma = regexp.MustCompile(`},$`)

func getLSHWPiece(class string) ([]interface{}, error) {

	out, err := exec.Command("lshw", "-quiet", "-c", class, "-json").CombinedOutput()
	if err != nil {
		return nil, err
	}

	objs := []interface{}{}

	// Sometimes it doesn't have a wrapping array parts
	sout := string(out)
	sout = strings.TrimSpace(sout)
	sout = trailingComma.ReplaceAllString(sout, "}")
	if len(sout) == 0 || sout[0] != '[' {
		sout = fmt.Sprintf("[%s]", sout)
	}
	// Sometimes it misses commas
	sout = missingComma.ReplaceAllString(sout, "\n},{\n")

	err = json.Unmarshal([]byte(sout), &objs)
	if err != nil {
		return nil, err
	}

	return objs, nil
}
