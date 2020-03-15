// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"os"
)

type kvmContext struct {
}

func newKvm() Hypervisor {
	return kvmContext{}
}

func (ctx kvmContext) Name() string {
	return "kvm"
}

func (ctx kvmContext) CreateDomConfig(string, types.DomainConfig, []types.DiskStatus, *types.AssignableAdapters, *os.File) error {
	return nil
}

func (ctx kvmContext) Create(domainName string, xenCfgFilename string) (int, error) {
	return 0, nil
}

func (ctx kvmContext) Start(domainName string, domainID int) error {
	return nil
}

func (ctx kvmContext) Stop(domainName string, domainID int, force bool) error {
	return nil
}

func (ctx kvmContext) Delete(domainName string, domainID int) error {
	return nil
}

func (ctx kvmContext) Info(domainName string, domainID int) error {
	return nil
}

func (ctx kvmContext) LookupByName(domainName string, domainID int) (int, error) {
	return 0, nil
}

func (ctx kvmContext) Tune(domainName string, domainID int, vifCount int) error {
	return nil
}

func (ctx kvmContext) PCIReserve(long string) error {
	return nil
}

func (ctx kvmContext) PCIRelease(long string) error {
	return nil
}

func (ctx kvmContext) IsDeviceModelAlive(domid int) bool {
	return true
}
