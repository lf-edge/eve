// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"os"

	log "github.com/sirupsen/logrus"
)

type ctrdContext struct {
	doms       map[string]*domState
	domCounter int
	PCI        map[string]bool
}

func newContainerd() Hypervisor {
	if err := containerd.InitContainerdClient(); err != nil {
		log.Fatal(err)
		return nil
	}
	return ctrdContext{
		doms:       map[string]*domState{},
		domCounter: 0,
		PCI:        map[string]bool{},
	}
}

func (ctx ctrdContext) Name() string {
	return "containerd"
}

func (ctx ctrdContext) CreateDomConfig(domainName string, config types.DomainConfig, diskStatusList []types.DiskStatus, aa *types.AssignableAdapters, file *os.File) error {
	if len(diskStatusList) != 1 || diskStatusList[0].Format != zconfig.Format_CONTAINER {
		return logError("failed to create container for %s containerd only supports ECOs with a single drive in an image format for now", domainName)
	}

	spec, err := containerd.NewOciSpec(domainName)
	if err != nil {
		return logError("requesting default OCI spec for domain %s failed %v", domainName, err)
	}

	spec.UpdateFromDomain(config)
	if err := spec.UpdateFromVolume(diskStatusList[0].FileLocation); err != nil {
		return logError("failed to update OCI spec from volume %s (%v)", diskStatusList[0].FileLocation, err)
	}

	return spec.Save(file)
}

func (ctx ctrdContext) Create(domainName string, cfgFilename string, VirtualizationMode types.VmMode) (int, error) {
	spec, err := containerd.NewOciSpec(domainName)
	if err == nil {
		err = spec.CreateContainer(true)
	}

	if err == nil {
		// calls to Create are serialized in the consumer: no need to worry about locking
		ctx.domCounter++
		ctx.doms[domainName] = &domState{id: ctx.domCounter, config: cfgFilename, state: "stopped"}
		return ctx.domCounter, nil
	}
	return 0, err
}

func (ctx ctrdContext) Start(domainName string, domainID int) error {
	id, err := containerd.CtrStart(domainName)
	if err != nil {
		return err
	}
	log.Infof("container %s running with PID %d", domainName, id)
	// ctx.doms[domainName].id = id
	ctx.doms[domainName].state = "running"

	return nil
}

func (ctx ctrdContext) Stop(domainName string, domainID int, force bool) error {
	ctx.doms[domainName].state = "stopped"
	return containerd.CtrStop(domainName, force)
}

func (ctx ctrdContext) Delete(domainName string, domainID int) error {
	delete(ctx.doms, domainName)
	return containerd.CtrDelete(domainName)
}

func (ctx ctrdContext) Info(domainName string, domainID int) error {
	if dom, found := ctx.doms[domainName]; found {
		log.Infof("Container Domain %s is %s and has the following config %s\n", domainName, dom.state, dom.config)
		return nil
	} else {
		log.Errorf("Container Domain %s doesn't exist", domainName)
		return fmt.Errorf("container domain %s doesn't exist", domainName)
	}
}

func (ctx ctrdContext) LookupByName(domainName string, domainID int) (int, error) {
	if dom, found := ctx.doms[domainName]; found {
		return dom.id, nil
	} else {
		return 0, fmt.Errorf("container domain %s %d doesn't exist", domainName, domainID)
	}
}

func (ctx ctrdContext) Tune(string, int, int) error {
	return nil
}

func (ctx ctrdContext) PCIReserve(long string) error {
	if ctx.PCI[long] {
		return fmt.Errorf("PCI %s is already reserved", long)
	} else {
		ctx.PCI[long] = true
		return nil
	}
}

func (ctx ctrdContext) PCIRelease(long string) error {
	if !ctx.PCI[long] {
		return fmt.Errorf("PCI %s is not reserved", long)
	} else {
		ctx.PCI[long] = false
		return nil
	}
}

func (ctx ctrdContext) IsDomainPotentiallyShuttingDown(domainName string) bool {
	return false
}

func (ctx ctrdContext) IsDeviceModelAlive(int) bool {
	return true
}

func (ctx ctrdContext) GetHostCPUMem() (types.HostMemory, error) {
	return selfDomCPUMem()
}

func (ctx ctrdContext) GetDomsCPUMem() (map[string]types.DomainMetric, error) {
	return nil, nil
}
