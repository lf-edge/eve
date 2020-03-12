// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

type acrnContext struct {
}

func newAcrn() Hypervisor {
	return acrnContext{}
}

// Name returns the name of this hypervisor implementation
func (ctx acrnContext) Name() string {
	return "acrn"
}

// Create creates a domain in a stopped state
func (ctx acrnContext) Create(domainName string, xenCfgFilename string) (int, error) {
	return 0, nil
}

// Start starts a stopped domain
func (ctx acrnContext) Start(domainName string, domainID int) error {
	return nil
}

// Stop stops a running domain
func (ctx acrnContext) Stop(domainName string, domainID int, force bool) error {
	return nil
}

// Delete deletes a domain in any state (stopped or running)
func (ctx acrnContext) Delete(domainName string, domainID int) error {
	return nil
}

// Info outputs domain info via logging
func (ctx acrnContext) Info(domainName string, domainID int) error {
	return nil
}

// LookupByName returns domain ID for a domain with a given symbolic name
func (ctx acrnContext) LookupByName(domainName string, domainID int) (int, error) {
	return 0, nil
}

// Tune allows for additional performance tweaks on a stopped domain
func (ctx acrnContext) Tune(domainName string, domainID int, vifCount int) error {
	return nil
}

// PCIReserve takes a PCI device away from the host kernel and makes it available for Domain assignments
func (ctx acrnContext) PCIReserve(long string) error {
	return nil
}

// PCIRelease gives a PCI device back to the host kernel
func (ctx acrnContext) PCIRelease(long string) error {
	return nil
}

// IsDeviceModelAlive returns true if a process supplying device model to a domain is still running
func (ctx acrnContext) IsDeviceModelAlive(domid int) bool {
	return true
}
