package system

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Processor struct {
	ID             int64
	Vendor         string
	Family         int64
	ModelCode      int64
	Model          string
	Stepping       int64
	Microcode      int64
	Speed          string
	CacheSize      string
	PhysID         int64
	Sibligs        int64
	CoreID         int64
	Cores          int64
	FPU            bool
	WriteProtect   bool
	Flags          []string
	Bugs           []string
	CacheAlignment int64
	AddressSizes   struct {
		Physical int64
		Virtual  int64
	}
}

type Info struct {
	OS     string
	Arch   string
	Kernel string
	Memory struct {
		Total     int64
		Free      int64
		Available int64
	}
	ProcessorCount int
	Processors     []Processor
}

func (i *Info) Class() string {
	return "System"
}

func mPI(s string, size int) int64 {
	res, err := strconv.ParseInt(s, 0, size)
	if err != nil {
		panic("Failed to parse int")
	}
	return res
}

func fillLinux(i *Info) error {
	vbytes, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		return err
	}
	fields := bytes.Split(vbytes, []byte(" "))
	i.Kernel = string(fields[2])
	memInfo, err := os.Open("/proc/meminfo")
	if err != nil {
		return err
	}
	defer memInfo.Close()
	lines := bufio.NewScanner(memInfo)
	for lines.Scan() {
		frags := strings.SplitN(lines.Text(), ":", 2)
		szPart := strings.Split(strings.TrimSpace(frags[1]), " ")[0]
		sz, err := strconv.ParseInt(szPart, 10, 64)
		if err != nil {
			return err
		}
		switch frags[0] {
		case "MemTotal":
			i.Memory.Total = sz << 10
		case "MemFree":
			i.Memory.Free = sz << 10
		case "MemAvailable":
			i.Memory.Available = sz << 10
		default:
			break
		}
	}
	cpuInfo, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return err
	}
	defer cpuInfo.Close()
	i.Processors = []Processor{}
	lines = bufio.NewScanner(cpuInfo)
	var proc Processor
	for lines.Scan() {
		frags := strings.SplitN(lines.Text(), ":", 2)
		if len(frags) != 2 {
			i.Processors = append(i.Processors, proc)
			continue
		}
		k, v := strings.TrimSpace(frags[0]), strings.TrimSpace(frags[1])

		switch k {
		case "processor":
			proc = Processor{}
			proc.ID = mPI(v, 64)
			i.ProcessorCount += 1
		case "vendor_id":
			proc.Vendor = v
		case "cpu family":
			proc.Family = mPI(v, 64)
		case "model":
			proc.ModelCode = mPI(v, 64)
		case "model name":
			proc.Model = v
		case "stepping":
			proc.Stepping = mPI(v, 64)
		case "microcode":
			proc.Microcode = mPI(v, 64)
		case "cpu MHz":
			proc.Speed = v
		case "cache size":
			proc.CacheSize = v
		case "physical id":
			proc.PhysID = mPI(v, 64)
		case "siblings":
			proc.Sibligs = mPI(v, 64)
		case "core id":
			proc.CoreID = mPI(v, 64)
		case "cpu cores":
			proc.Cores = mPI(v, 64)
		case "fpu":
			proc.FPU = v == "yes"
		case "wp":
			proc.WriteProtect = v == "yes"
		case "flags":
			proc.Flags = strings.Split(v, " ")
		case "bugs":
			if len(v) == 0 {
				proc.Bugs = []string{}
			} else {
				proc.Bugs = strings.Split(v, " ")
			}
		case "cache_alignment":
			proc.CacheAlignment = mPI(v, 64)
		case "address sizes":
			aParts := strings.Split(v, " ")
			proc.AddressSizes.Physical = mPI(aParts[0], 64)
			proc.AddressSizes.Virtual = mPI(aParts[3], 64)
		}
	}
	return nil
}

func Gather() (*Info, error) {
	res := &Info{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
	switch res.OS {
	case "linux":
		return res, fillLinux(res)
	}
	return res, nil
}
