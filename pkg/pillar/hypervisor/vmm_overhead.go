// Copyright (c) 2017-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// vmmOverhead returns VMM memory overhead in bytes.
// It respects the following priority:
//  1. Global node setting (types.VmmMemoryLimitInMiB) if > 0
//  2. Per-app setting (vmmMaxMem in KiB) if > 0
//  3. Automatic estimation via estimatedVMMOverhead()
func vmmOverhead(domainName string, domainUUID uuid.UUID, domainRAMSize int64, vmmMaxMem int64, domainMaxCpus int64, domainVCpus int64, domainIoAdapterList []types.IoAdapter, aa *types.AssignableAdapters, globalConfig *types.ConfigItemValueMap) (int64, error) {
	var overhead int64

	// Fetch VMM max memory setting (aka vmm overhead)
	overhead = vmmMaxMem << 10

	// Global node setting has a higher priority.
	// Note: globalConfig can be nil only in unit tests.
	if globalConfig != nil {
		VmmOverheadOverrideCfgItem, ok := globalConfig.GlobalSettings[types.VmmMemoryLimitInMiB]
		if !ok {
			return 0, logError("Missing key %s", string(types.VmmMemoryLimitInMiB))
		}
		if VmmOverheadOverrideCfgItem.IntValue > 0 {
			overhead = int64(VmmOverheadOverrideCfgItem.IntValue) << 20
		}
	}

	if overhead == 0 {
		overhead, err := estimatedVMMOverhead(domainName, aa, domainIoAdapterList, domainUUID, domainRAMSize, domainMaxCpus, domainVCpus)
		if err != nil {
			return 0, logError("estimatedVMMOverhead() failed for domain %s: %v",
				domainName, err)
		}
		return overhead, nil
	}

	return overhead, nil
}

func estimatedVMMOverhead(domainName string, aa *types.AssignableAdapters, domainAdapterList []types.IoAdapter,
	domainUUID uuid.UUID, domainRAMSize int64, domainMaxCpus int64, domainVcpus int64) (int64, error) {
	var overhead int64

	mmioOverhead, err := mmioVMMOverhead(domainName, aa, domainAdapterList, domainUUID)
	if err != nil {
		return 0, logError("mmioVMMOverhead() failed for domain %s: %v",
			domainName, err)
	}
	overhead = undefinedVMMOverhead() + ramVMMOverhead(domainRAMSize) +
		qemuVMMOverhead() + cpuVMMOverhead(domainMaxCpus, domainVcpus) + mmioOverhead

	return overhead, nil
}

func ramVMMOverhead(ramMemory int64) int64 {
	// 0.224% of the total RAM allocated for VM in bytes
	// this formula is precise and well explained in the following QEMU issue:
	// https://gitlab.com/qemu-project/qemu/-/issues/1003
	// This is a best case scenario because it assumes that all PTEs are allocated
	// sequentially. In reality, there will be some fragmentation and the overhead
	// for now 2.5% (~10x) is a good approximation until we have a better way to
	// predict the memory usage of the VM.
	return ramMemory * 1024 * 25 / 1000
}

// overhead for qemu binaries and libraries
func qemuVMMOverhead() int64 {
	return 20 << 20 // Mb in bytes
}

// overhead for VMM memory mapped IO
// it fluctuates between 0.66 and 0.81 % of MMIO total size
// for all mapped devices. Set it to 1% to be on the safe side
// this can be a pretty big number for GPUs with very big
// aperture size (e.g. 64G for NVIDIA A40)
func mmioVMMOverhead(domainName string, aa *types.AssignableAdapters, domainAdapterList []types.IoAdapter,
	domainUUID uuid.UUID) (int64, error) {
	var pciAssignments []pciDevice
	var mmioSize uint64

	for _, adapter := range domainAdapterList {
		logrus.Debugf("mmioVMMOverhead: processing adapter %d %s for overhead estimation (not reserving) for domain %s (UUID: %s)",
			adapter.Type, adapter.Name, domainName, domainUUID)
		aaList := aa.LookupIoBundleAny(adapter.Name)
		if len(aaList) == 0 {
			return 0, logError("mmioVMMOverhead: IoBundle not found %d %s for domain %s (UUID: %s)\n",
				adapter.Type, adapter.Name, domainName, domainUUID)
		}
		for _, ib := range aaList {
			if ib == nil {
				continue
			}
			// For memory overhead calculation, we process all matching adapters
			// regardless of UsedByUUID status, since this is for estimation only,
			// not actual reservation.
			if ib.PciLong != "" && ib.UsbAddr == "" {
				logrus.Infof("mmioVMMOverhead: counting MMIO for PCI device <%s> (not reserving) for domain %s (UUID: %s)",
					ib.PciLong, domainName, domainUUID)
				tap := pciDevice{ioBundle: *ib}
				pciAssignments = addNoDuplicatePCI(pciAssignments, tap)
			}
		}
	}

	for _, dev := range pciAssignments {
		logrus.Infof("mmioVMMOverhead: reading MMIO size for PCI device %s %d for domain %s",
			dev.ioBundle.PciLong, dev.ioBundle.Type, domainName)
		// read the size of the PCI device aperture. Only GPU/VGA devices for now
		if dev.ioBundle.Type != types.IoOther && dev.ioBundle.Type != types.IoHDMI {
			continue
		}
		// skip bridges
		isBridge, err := dev.isBridge()
		if err != nil {
			// do not treat as fatal error
			logrus.Warnf("mmioVMMOverhead: can't read PCI device class, treating as bridge %s: %v",
				dev.ioBundle.PciLong, err)
			isBridge = true
		}

		if isBridge {
			logrus.Infof("mmioVMMOverhead: skipping PCI bridge %s\n", dev.ioBundle.PciLong)
			continue
		}

		// read all resources of the PCI device
		resources, err := dev.readResources(sysfsPciDevices)
		if err != nil {
			return 0, logError("mmioVMMOverhead: can't read PCI device resources %s: %v\n",
				dev.ioBundle.PciLong, err)
		}

		// calculate the size of the MMIO region
		for _, res := range resources {
			if res.valid() && res.isMem() {
				mmioSize += res.size()
			}
		}
	}

	// 1% of the total MMIO size in bytes
	mmioOverhead := int64(mmioSize) / 100

	logrus.Infof("mmioVMMOverhead: calculated MMIO overhead for domain %s (UUID: %s): total MMIO %d bytes, overhead %d bytes",
		domainName, domainUUID, mmioSize, mmioOverhead)

	return int64(mmioOverhead), nil
}

// each vCPU requires about 3MB of memory
func cpuVMMOverhead(maxCpus int64, vcpus int64) int64 {
	cpus := maxCpus
	if cpus == 0 {
		cpus = vcpus
	}
	return cpus * (3 << 20) // Mb in bytes
}

// memory allocated by QEMU for its own purposes.
// statistical analysis did not reveal any correlation between
// VM configuration (devices, nr of vcpus, etc) and this number
// however the size of disk space affects it. Probably some internal
// QEMU caches are allocated based on the size of the disk image.
// it requires more investigation.
func undefinedVMMOverhead() int64 {
	return 350 << 20 // Mb in bytes
}
