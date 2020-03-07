// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

type KvmContext struct {
}

func newKvm() Hypervisor {
	return KvmContext{}
}

func (ctx KvmContext) Name() string {
	return "kvm"
}

func (ctx KvmContext) Create(domainName string, xenCfgFilename string) (int, error) {
	return 0, nil
}

func (ctx KvmContext) Start(domainName string, domainID int) error {
	return nil
}

func (ctx KvmContext) Stop(domainName string, domainID int, force bool) error {
	return nil
}

func (ctx KvmContext) Delete(domainName string, domainID int) error {
	return nil
}

func (ctx KvmContext) Info(domainName string, domainID int) error {
	return nil
}

func (ctx KvmContext) LookupByName(domainName string, domainID int) (int, error) {
	return 0, nil
}

func (ctx KvmContext) Tune(domainName string, domainID int, vifCount int) error {
	return nil
}

func (ctx KvmContext) PCIReserve(long string) error {
	return nil
}

func (ctx KvmContext) PCIRelease(long string) error {
	return nil
}

func (ctx KvmContext) IsDeviceModelAlive(domid int) bool {
	return true
}
