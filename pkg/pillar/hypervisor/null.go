// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"

	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// NullHypervisorName is a name of null hypervisor
const NullHypervisorName = "null"

type domState struct {
	id     int
	config string
	state  types.SwState
}

type nullContext struct {
	// XXX add log?
	tempDir    string
	doms       map[string]*domState
	domCounter int
	PCI        map[string]bool
}

func (ctx nullContext) GetCapabilities() (*types.Capabilities, error) {
	return &types.Capabilities{
		HWAssistedVirtualization: false,
		IOVirtualization:         false,
		CPUPinning:               false,
		UseVHost:                 false,
	}, nil
}

// CountMemOverhead - returns the memory overhead for a domain.
// Null-implementation that returns 0 is used now for Acrn hypervisor
func (ctx nullContext) CountMemOverhead(domainName string, domainUUID uuid.UUID, domainRAMSize int64, vmmMaxMem int64,
	domainMaxCpus int64, domainVCpus int64, domainIoAdapterList []types.IoAdapter, aa *types.AssignableAdapters,
	globalConfig *types.ConfigItemValueMap) (uint64, error) {
	return 0, nil
}

func newNull() Hypervisor {
	res := nullContext{tempDir: "/tmp",
		doms:       map[string]*domState{},
		domCounter: 0,
		PCI:        map[string]bool{}}
	if dir, err := os.MkdirTemp("", "null_domains"); err == nil {
		res.tempDir = dir
	}
	return res
}

func (ctx nullContext) Name() string {
	return NullHypervisorName
}

func (ctx nullContext) Task(status *types.DomainStatus) types.Task {
	return ctx
}

func (ctx nullContext) Setup(types.DomainStatus, types.DomainConfig,
	*types.AssignableAdapters, *types.ConfigItemValueMap, *os.File) error {
	return nil
}

func (ctx nullContext) Create(domainName string, cfgFilename string, config *types.DomainConfig) (int, error) {
	// pre-flight checks
	if _, err := os.Stat(cfgFilename); domainName == "" || err != nil || config == nil {
		return 0, fmt.Errorf("Null Domain create failed to create domain with either empty name or empty config %s\n", domainName)
	}
	if _, found := ctx.doms[domainName]; found {
		return 0, fmt.Errorf("Null Domain create failed to create existing domain %s\n", domainName)
	}

	domDescriptor := ctx.tempDir + "/" + domainName
	domFile, err := os.Create(domDescriptor)
	if err != nil {
		return 0, fmt.Errorf("Null Domain create failed to create domain descriptor %v\n", err)
	}

	configContent, err := os.ReadFile(cfgFilename)
	if err != nil {
		return 0, fmt.Errorf("Null Domain create failed to read cfgFilename %s %v\n", cfgFilename, err)
	}

	if _, err := domFile.Write(configContent); err != nil {
		return 0, fmt.Errorf("Null Domain create failed to write domain descriptor %s %v\n", domDescriptor, err)
	}

	// calls to Create are serialized in the consumer: no need to worry about locking
	ctx.domCounter++
	ctx.doms[domainName] = &domState{id: ctx.domCounter, config: string(configContent), state: types.HALTED}

	return ctx.domCounter, nil
}

func (ctx nullContext) Start(domainName string) error {
	if dom, found := ctx.doms[domainName]; found && dom.state == types.HALTED {
		dom.state = types.RUNNING
		return nil
	} else {
		return fmt.Errorf("null domain %s doesn't exist or is not stopped", domainName)
	}
}

func (ctx nullContext) Stop(domainName string, force bool) error {
	if dom, found := ctx.doms[domainName]; found && dom.state == types.RUNNING {
		dom.state = types.HALTED
		return nil
	} else {
		return fmt.Errorf("null domain %s doesn't exist or is not running", domainName)
	}
}

func (ctx nullContext) Delete(domainName string) error {
	// calls to Delete are serialized in the consumer: no need to worry about locking
	os.RemoveAll(ctx.tempDir + "/" + domainName)
	delete(ctx.doms, domainName)
	return nil
}

// Cleanup is noop for null hypervisor
func (ctx nullContext) Cleanup(_ string) error {
	return nil
}

func (ctx nullContext) Info(domainName string) (int, types.SwState, error) {
	if dom, found := ctx.doms[domainName]; found {
		logrus.Infof("Null Domain %s is %v and has the following config %s\n", domainName, dom.state, dom.config)
		return dom.id, dom.state, nil
	} else {
		logrus.Errorf("Null Domain %s doesn't exist", domainName)
		return 0, types.UNKNOWN, fmt.Errorf("null domain %s doesn't exist", domainName)
	}
}

func (ctx nullContext) PCIReserve(long string) error {
	if ctx.PCI[long] {
		return fmt.Errorf("PCI %s is already reserved", long)
	} else {
		ctx.PCI[long] = true
		return nil
	}
}

func (ctx nullContext) PCIRelease(long string) error {
	if !ctx.PCI[long] {
		return fmt.Errorf("PCI %s is not reserved", long)
	} else {
		ctx.PCI[long] = false
		return nil
	}
}

func (ctx nullContext) PCISameController(id1 string, id2 string) bool {
	return types.PCISameController(id1, id2)
}

func (ctx nullContext) GetHostCPUMem(reportPhyCores bool) (types.HostMemory, error) {
	return selfDomCPUMem(reportPhyCores)
}

func (ctx nullContext) GetDomsCPUMem() (map[string]types.DomainMetric, error) {
	return nil, nil
}

func (ctx nullContext) VirtualTPMSetup(domainName string, wp *types.WatchdogParam) error {
	return fmt.Errorf("not implemented")
}

func (ctx nullContext) VirtualTPMTerminate(domainName string, wp *types.WatchdogParam) error {
	return fmt.Errorf("not implemented")
}

func (ctx nullContext) VirtualTPMTeardown(domainName string, wp *types.WatchdogParam) error {
	return fmt.Errorf("not implemented")
}
