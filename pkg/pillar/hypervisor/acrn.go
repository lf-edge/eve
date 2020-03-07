// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

type AcrnContext struct {
}

func newAcrn() Hypervisor {
	return AcrnContext{}
}

func (ctx AcrnContext) Name() string {
	return "acrn"
}

func (ctx AcrnContext) Create(domainName string, xenCfgFilename string) (int, error) {
	return 0, nil
}

func (ctx AcrnContext) Start(domainName string, domainID int) error {
	return nil
}

func (ctx AcrnContext) Stop(domainName string, domainID int, force bool) error {
	return nil
}

func (ctx AcrnContext) Delete(domainName string, domainID int) error {
	return nil
}

func (ctx AcrnContext) Info(domainName string, domainID int) error {
	return nil
}

func (ctx AcrnContext) LookupByName(domainName string, domainID int) (int, error) {
	return 0, nil
}

func (ctx AcrnContext) Tune(domainName string, domainID int, vifCount int) error {
	return nil
}

func (ctx AcrnContext) PCIReserve(long string) error {
	return nil
}

func (ctx AcrnContext) PCIRelease(long string) error {
	return nil
}

func (ctx AcrnContext) IsDeviceModelAlive(domid int) bool {
	return true
}
