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

// A hypervisor managed domain can be in one of the following states.
// Note that this is a superset of all the states from all the hypervisors
// we support, which means that some hypervisors may only returns a subset
// of these values.

// DomState represents a state of the hypervisor domain
type DomState int

const (
	// Running in a normal fashion
	Running DomState = iota
	// Blocked and not running or runnable
	Blocked
	// Paused and can be resumed
	Paused
	// Exiting indicates that a shutdown command has been sent, but the domain isn't dying yet
	Exiting
	// Crashed indicates that the domain has hit an invalid condition while running
	Crashed
	// Dying indicates that the domain is being cleaned up, but it hasn't properly shut down or crashed
	Dying
	// Broken indicates that domain is alive, but support for it (e.g. device model) has crashed
	Broken
	// Unknown is a catch-all state for when a state of the domain can't even be retrieved from the hypervisor
	Unknown
)

// Hypervisor provides methods for manipulating domains on the host
type Hypervisor interface {
	Name() string

	CreateDomConfig(string, types.DomainConfig, []types.DiskStatus, *types.AssignableAdapters, *os.File) error

	Create(string, string, *types.DomainConfig) (int, error)

	Start(string, int) error
	Stop(string, int, bool) error
	Delete(string, int) error
	Info(string, int) (int, DomState, error)

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
	"xen":        {constructor: newXen, dom0handle: "/proc/xen"},
	"kvm":        {constructor: newKvm, dom0handle: "/dev/kvm"},
	"acrn":       {constructor: newAcrn, dom0handle: "/dev/acrn"},
	"containerd": {constructor: newContainerd, dom0handle: "/run/containerd/containerd.sock"},
	"null":       {constructor: newNull, dom0handle: "/"},
}

// this is a priority order to pick a default hypervisor if multiple are availabel (more to less likely)
var hypervisorPriority = []string{"xen", "kvm", "acrn", "containerd", "null"}

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
