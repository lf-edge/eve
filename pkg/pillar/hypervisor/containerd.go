// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

type ctrdContext struct {
	domCounter int
	PCI        map[string]bool
}

func newContainerd() Hypervisor {
	if err := containerd.InitContainerdClient(); err != nil {
		log.Fatal(err)
		return nil
	}
	return ctrdContext{
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

	if err := spec.UpdateFromVolume(diskStatusList[0].FileLocation); err != nil {
		return logError("failed to update OCI spec from volume %s (%v)", diskStatusList[0].FileLocation, err)
	}

	spec.UpdateFromDomain(config)

	return spec.Save(file)
}

func (ctx ctrdContext) Create(domainName string, cfgFilename string, VirtualizationMode types.VmMode) (int, error) {
	spec, err := containerd.NewOciSpec(domainName)
	if err != nil {
		return 0, logError("containerd create failed to initialize OCI spec %s %v", domainName, err)
	}

	specf, err := os.Open(cfgFilename)
	if err != nil {
		return 0, logError("containerd create failed to open OCI spec file %s %v", cfgFilename, err)
	}

	if err = spec.Load(specf); err == nil {
		err = spec.CreateContainer(true)
	}

	if err == nil {
		ctx.domCounter--
		log.Infof("containerd create finished creating domain %s %d", domainName, ctx.domCounter)
		return ctx.domCounter, nil
	}
	return 0, logError("containerd create failed to create domain %s %v", domainName, err)
}

func (ctx ctrdContext) Start(domainName string, domainID int) error {
	id, err := containerd.CtrStart(domainName)
	if err != nil {
		return logError("containerd failed to start domain %s %v", domainName, err)
	}
	log.Infof("containerd launched domain %s with PID %d", domainName, id)
	return nil
}

func (ctx ctrdContext) Stop(domainName string, domainID int, force bool) error {
	err := containerd.CtrStop(domainName, force)
	if err == nil {
		log.Infof("containerd stopped domain %s with PID %d (forced %v)", domainName, domainID, force)
	} else {
		log.Errorf("containerd failed to stop domain %s with PID %d (forced %v) %v", domainName, domainID, force, err)
	}
	return err
}

func (ctx ctrdContext) Delete(domainName string, domainID int) error {
	err := containerd.CtrDelete(domainName)
	if err == nil {
		log.Infof("containerd deleted domain %s with PID %d", domainName, domainID)
	} else {
		return logError("containerd failed to delete domain %s with PID %d %v", domainName, domainID, err)
	}
	return err
}

func (ctx ctrdContext) Info(domainName string, domainID int) error {
	pid, status, err := containerd.CtrInfo(domainName)
	if err == nil {
		if pid == domainID {
			log.Infof("containerd domain %s with PID %d is %s\n", domainName, domainID, status)
			return nil
		} else {
			log.Warnf("containerd domain %s with PID %d (different from expected %d) is %s",
				domainName, pid, domainID, status)
			return nil
		}
	} else {
		return logError("containerd looking up domain %s with PID %d resulted in %v", domainName, domainID, err)
	}
}

func (ctx ctrdContext) LookupByName(domainName string, domainID int) (int, error) {
	pid, status, err := containerd.CtrInfo(domainName)
	if err == nil {
		if pid == domainID {
			log.Infof("containerd domain %s with PID %d is %s\n", domainName, domainID, status)
		} else {
			log.Warnf("containerd domain %s with PID %d (different from expected %d) is %s",
				domainName, pid, domainID, status)
		}
		return pid, nil
	} else {
		return 0, logError("containerd looking up domain by name %s with PID %d resulted in %v",
			domainName, domainID, err)
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
	_, status, err := containerd.CtrInfo(domainName)
	return err == nil && status == "pausing"
}

func (ctx ctrdContext) IsDeviceModelAlive(id int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(id))
	return err == nil
}

func (ctx ctrdContext) GetHostCPUMem() (types.HostMemory, error) {
	return selfDomCPUMem()
}

func (ctx ctrdContext) GetDomsCPUMem() (map[string]types.DomainMetric, error) {
	return nil, nil
}
