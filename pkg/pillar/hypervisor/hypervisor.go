// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/sirupsen/logrus"
	"os"
	"strings"
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
}

type hypervisorDesc struct {
	constructor func() Hypervisor
	dom0handle  string
}

var knownHypervisors = map[string]hypervisorDesc{
	XenHypervisorName:        {constructor: newXen, dom0handle: "/proc/xen"},
	KVMHypervisorName:        {constructor: newKvm, dom0handle: "/dev/kvm"},
	KubevirtHypervisorName:   {constructor: newKubevirt, dom0handle: "/dev/kvm"},
	ACRNHypervisorName:       {constructor: newAcrn, dom0handle: "/dev/acrn"},
	ContainerdHypervisorName: {constructor: newContainerd, dom0handle: "/run/containerd/containerd.sock"},
	NullHypervisorName:       {constructor: newNull, dom0handle: "/"},
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

// GetAvailableHypervisors returns a list of all available hypervisors plus
// the one that is enabled on the system. Note that you don't have to follow
// the advice of this function and always ask for the enabled one.
func GetAvailableHypervisors() (all []string, enabled []string) {
	all = hypervisorPriority
	for _, v := range all {
		if _, err := os.Stat(knownHypervisors[v].dom0handle); err == nil {
			// Both Kubevirt and KVM use same dom0handle.
			// Lets differentiate by eve_flavor
			if base.IsHVTypeKube() && strings.Compare(v, KVMHypervisorName) == 0 {
				continue // kubevirt image don't set kvm
			} else if !base.IsHVTypeKube() && strings.Compare(v, KubevirtHypervisorName) == 0 {
				continue // kvm image don't set kubevirt
			} else {
				enabled = append(enabled, v)
			}
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
