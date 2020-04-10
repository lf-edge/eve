// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"os"
)

// Hypervisor provides methods for manipulating domains on the host
type Hypervisor interface {
	Name() string

	CreateDomConfig(string, types.DomainConfig, []types.DiskStatus, *types.AssignableAdapters, *os.File) error

	Create(string, string, types.VmMode) (int, error)

	Start(string, int) error
	Tune(string, int, int) error
	Stop(string, int, bool) error
	Delete(string, int) error
	Info(string, int) error
	LookupByName(string, int) (int, error)

	IsDomainKnownHealthy(string) bool
	IsDeviceModelAlive(int) bool

	PCIReserve(string) error
	PCIRelease(string) error

	GetHostCPUMem() (types.HostMemory, error)
	GetDomsCPUMem() (map[string]types.DomainMetric, error)
}

type hypervisorDesc struct {
	constructor func() Hypervisor
	dom0handle  string
}

var knownHypervisors = map[string]hypervisorDesc{
	"xen":  {constructor: newXen, dom0handle: "/proc/xen"},
	"kvm":  {constructor: newKvm, dom0handle: "/dev/kvm"},
	"acrn": {constructor: newAcrn, dom0handle: "/dev/acrn"},
	"null": {constructor: newNull, dom0handle: ""},
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
	for k, v := range knownHypervisors {
		all = append(all, k)
		if _, err := os.Stat(v.dom0handle); err == nil {
			enabled = append(enabled, k)
		}
	}
	// null is always enabled for now
	enabled = append(enabled, "null")
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
