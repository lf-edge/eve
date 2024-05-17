// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/sirupsen/logrus"
)

// Hypervisor provides methods for manipulating domains on the host
type Hypervisor interface {
	Name() string
	Task(*types.DomainStatus) types.Task

	PCIReserve(string) error
	PCIRelease(string) error
	PCISameController(string, string) bool

	GetHostCPUMem() (types.HostMemory, error)
	GetDomsCPUMem() (map[string]types.DomainMetric, error)

	GetCapabilities() (*types.Capabilities, error)

	CountMemOverhead(domainName string, domainUUID uuid.UUID, domainRAMSize int64, vmmMaxMem int64,
		domainMaxCpus int64, domainVCpus int64, domainIoAdapterList []types.IoAdapter, aa *types.AssignableAdapters,
		globalConfig *types.ConfigItemValueMap) (uint64, error)
}

type hypervisorDesc struct {
	constructor       func() Hypervisor
	enabled           func() bool
	hvTypeFileContent string
}

var knownHypervisors = map[string]hypervisorDesc{
	XenHypervisorName:        {constructor: newXen, enabled: func() bool { return fileutils.FileExists(nil, "/proc/xen") }, hvTypeFileContent: "xen"},
	KVMHypervisorName:        {constructor: newKvm, enabled: func() bool { return fileutils.FileExists(nil, "/dev/kvm") && !base.IsHVTypeKube() }, hvTypeFileContent: "kvm"},
	KubevirtHypervisorName:   {constructor: newKubevirt, enabled: func() bool { return fileutils.FileExists(nil, "/dev/kvm") && base.IsHVTypeKube() }, hvTypeFileContent: "kubevirt"},
	ACRNHypervisorName:       {constructor: newAcrn, enabled: func() bool { return fileutils.FileExists(nil, "/dev/acrn") }, hvTypeFileContent: "acrn"},
	ContainerdHypervisorName: {constructor: newContainerd, enabled: func() bool { return fileutils.FileExists(nil, "/run/containerd/containerd.sock") }},
	NullHypervisorName:       {constructor: newNull, enabled: func() bool { return fileutils.DirExists(nil, "/") }},
}

// this is a priority order to pick a default hypervisor if multiple are available (more to less likely)
var hypervisorPriority = []string{
	XenHypervisorName, KVMHypervisorName, KubevirtHypervisorName, ACRNHypervisorName, ContainerdHypervisorName, NullHypervisorName,
}

// GetHypervisor returns a particular hypervisor implementation
func GetHypervisor(hint string) (Hypervisor, error) {
	if _, found := knownHypervisors[hint]; !found {
		return nil, fmt.Errorf("Unknown hypervisor %s", hint)
	} else {
		return knownHypervisors[hint].constructor(), nil
	}
}

func bootTimeHypervisorWithHVFilePath(hvFilePath string) Hypervisor {
	hvFileContentBytes, err := os.ReadFile(hvFilePath)
	if err != nil {
		logrus.Errorf("could not open %s: %v", hvFilePath, err)
		return nil
	}

	hvFileContent := string(hvFileContentBytes)
	hvFileContent = strings.TrimSpace(hvFileContent)

	for _, knownHypervisor := range knownHypervisors {
		if knownHypervisor.hvTypeFileContent == hvFileContent {
			return knownHypervisor.constructor()
		}
	}

	logrus.Errorf("no hypervisor found for %s", hvFileContent)

	return nil
}

// BootTimeHypervisor returns the hypervisor according to /run/eve-hv-type
func BootTimeHypervisor() Hypervisor {
	return bootTimeHypervisorWithHVFilePath("/run/eve-hv-type")
}

// GetAvailableHypervisors returns a list of all available hypervisors plus
// the one that is enabled on the system. Note that you don't have to follow
// the advice of this function and always ask for the enabled one.
func GetAvailableHypervisors() (all []string, enabled []string) {
	all = hypervisorPriority
	for _, v := range all {
		if knownHypervisors[v].enabled() {
			enabled = append(enabled, v)
		}
	}
	return
}

func selfDomCPUMem() (types.HostMemory, error) {
	hm := types.HostMemory{}
	vm, err := mem.VirtualMemory()
	if err != nil {
		return hm, err
	}
	hm.TotalMemoryMB = roundFromBytesToMbytes(vm.Total)
	hm.FreeMemoryMB = roundFromBytesToMbytes(vm.Available)
	usage, err := types.GetEveMemoryUsageInBytes()
	if err != nil {
		logrus.Error(err)
	} else {
		hm.UsedEveMB = roundFromBytesToMbytes(usage)
	}
	kmemUsage, err := types.GetEveKmemUsageInBytes()
	if err != nil {
		logrus.Error(err)
	} else {
		hm.KmemUsedEveMB = roundFromBytesToMbytes(kmemUsage)
	}
	hm.UsedEveMB = roundFromBytesToMbytes(usage + kmemUsage)
	// /hostfs/sys/fs/cgroup/memory/eve/memory.kmem.usage_in_bytes
	// /hostfs/sys/fs/cgroup/memory/eve/memory.usage_in_bytes
	info, err := cpu.Info()
	if err != nil {
		return hm, err
	}
	hm.Ncpus = uint32(len(info))
	return hm, nil
}

func roundFromBytesToMbytes(byteCount uint64) uint64 {
	const kbyte = 1024

	kbytes := (byteCount + kbyte/2) / kbyte
	return (kbytes + kbyte/2) / kbyte
}

func roundFromKbytesToMbytes(byteCount uint64) uint64 {
	const kbyte = 1024

	return (byteCount + kbyte/2) / kbyte
}

func logError(format string, a ...interface{}) error {
	logrus.Errorf(format, a...)
	return fmt.Errorf(format, a...)
}

// PCIReserveGeneric : Common Reserve function used by both kvm and kubevirt
func PCIReserveGeneric(long string) error {
	logrus.Infof("PCIReserve long addr is %s", long)

	overrideFile := filepath.Join(sysfsPciDevices, long, "driver_override")
	driverPath := filepath.Join(sysfsPciDevices, long, "driver")
	unbindFile := filepath.Join(driverPath, "unbind")

	//Check if already bound to vfio-pci
	driverPathInfo, driverPathErr := os.Stat(driverPath)
	vfioDriverPathInfo, vfioDriverPathErr := os.Stat(vfioDriverPath)
	if driverPathErr == nil && vfioDriverPathErr == nil &&
		os.SameFile(driverPathInfo, vfioDriverPathInfo) {
		logrus.Infof("Driver for %s is already bound to vfio-pci, skipping unbind", long)
		return nil
	}

	//map vfio-pci as the driver_override for the device
	if err := os.WriteFile(overrideFile, []byte("vfio-pci"), 0644); err != nil {
		return logError("driver_override failure for PCI device %s: %v",
			long, err)
	}

	//Unbind the current driver, whatever it is, if there is one
	if _, err := os.Stat(unbindFile); err == nil {
		if err := os.WriteFile(unbindFile, []byte(long), 0644); err != nil {
			return logError("unbind failure for PCI device %s: %v",
				long, err)
		}
	}

	if err := os.WriteFile(sysfsPciDriversProbe, []byte(long), 0644); err != nil {
		return logError("drivers_probe failure for PCI device %s: %v",
			long, err)
	}

	return nil
}

// PCIReleaseGeneric :  Common function used by kvm and kubevirt
func PCIReleaseGeneric(long string) error {
	logrus.Infof("PCIRelease long addr is %s", long)

	overrideFile := filepath.Join(sysfsPciDevices, long, "driver_override")
	unbindFile := filepath.Join(sysfsPciDevices, long, "driver/unbind")

	//Write Empty string, to clear driver_override for the device
	if err := os.WriteFile(overrideFile, []byte("\n"), 0644); err != nil {
		logrus.Fatalf("driver_override failure for PCI device %s: %v",
			long, err)
	}

	//Unbind vfio-pci, if unbind file is present
	if _, err := os.Stat(unbindFile); err == nil {
		if err := os.WriteFile(unbindFile, []byte(long), 0644); err != nil {
			logrus.Fatalf("unbind failure for PCI device %s: %v",
				long, err)
		}
	}

	//Write PCI DDDD:BB:DD.FF to /sys/bus/pci/drivers_probe,
	//as a best-effort to bring back original driver
	if err := os.WriteFile(sysfsPciDriversProbe, []byte(long), 0644); err != nil {
		logrus.Fatalf("drivers_probe failure for PCI device %s: %v",
			long, err)
	}

	return nil
}

// PCISameControllerGeneric : Common function for kvm and kubevirt
func PCISameControllerGeneric(id1 string, id2 string) bool {
	tag1, err := types.PCIGetIOMMUGroup(id1)
	if err != nil {
		return types.PCISameController(id1, id2)
	}

	tag2, err := types.PCIGetIOMMUGroup(id2)
	if err != nil {
		return types.PCISameController(id1, id2)
	}

	return tag1 == tag2
}
