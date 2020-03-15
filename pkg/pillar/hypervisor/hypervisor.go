// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"os"
)

// Hypervisor provides methods for manipulating domains on the host
type Hypervisor interface {
	Name() string

	CreateDomConfig(string, types.DomainConfig, []types.DiskStatus, *types.AssignableAdapters, *os.File) error

	Create(string, string) (int, error)

	Start(string, int) error
	Tune(string, int, int) error
	Stop(string, int, bool) error
	Delete(string, int) error
	Info(string, int) error
	LookupByName(string, int) (int, error)

	IsDeviceModelAlive(int) bool

	PCIReserve(string) error
	PCIRelease(string) error
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
