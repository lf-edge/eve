// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"os"
)

type Hypervisor interface {
	Name() string

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

func GetHypervisor(hint string) Hypervisor {
	var knownHypervisors = map[string]func() Hypervisor{
		"xen":  newXen,
		"null": newNull,
		"kvm":  newKvm,
		"acrn": newAcrn,
	}

	if knownHypervisors[hint] == nil {
		// direct hint failed, lets do dynamic discovery
		if _, err := os.Stat("/proc/xen"); os.IsNotExist(err) {
			hint = "xen"
		} else if _, err := os.Stat("/dev/kvm"); os.IsNotExist(err) {
			hint = "kvm"
		} else if _, err := os.Stat("/dev/acrn"); os.IsNotExist(err) {
			hint = "acrn"
		} else {
			hint = "null"
		}
	}

	return knownHypervisors[hint]()
}
