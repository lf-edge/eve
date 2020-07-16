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
	"time"

	log "github.com/sirupsen/logrus"
)

type ctrdContext struct {
	domCounter int
	PCI        map[string]bool
}

func initContainerd() (*ctrdContext, error) {
	if err := containerd.InitContainerdClient(); err != nil {
		return nil, err
	}
	return &ctrdContext{
		domCounter: 0,
		PCI:        map[string]bool{},
	}, nil
}

func newContainerd() Hypervisor {
	if ret, err := initContainerd(); err != nil {
		log.Fatalf("couldn't initialize containerd (this should not happen): %v. Exiting.", err)
		return nil // it really never returns on account of above
	} else {
		return ret
	}
}

func (ctx ctrdContext) Name() string {
	return "containerd"
}

func (ctx ctrdContext) Task(status *types.DomainStatus) types.Task {
	return ctx
}

func (ctx ctrdContext) Setup(domainName string, config types.DomainConfig, diskStatusList []types.DiskStatus, aa *types.AssignableAdapters, file *os.File) error {
	spec, err := containerd.NewOciSpec(domainName)
	if err != nil {
		return logError("requesting default OCI spec for domain %s failed %v", domainName, err)
	}

	if len(diskStatusList) > 0 && diskStatusList[0].Format == zconfig.Format_CONTAINER {
		if err := spec.UpdateFromVolume(diskStatusList[0].FileLocation); err != nil {
			return logError("failed to update OCI spec from volume %s (%v)", diskStatusList[0].FileLocation, err)
		}
	}

	spec.UpdateVifList(config)
	if err := spec.CreateContainer(true); err != nil {
		return logError("Failed to create container for task %s from %v: %v", domainName, config, err)
	}

	return nil
}

func (ctx ctrdContext) Create(domainName string, cfgFilename string, config *types.DomainConfig) (int, error) {
	// if we are here we may need to get rid of the wedged, stale task just in case
	// we are ignoring error here since it is cheaper to always call this as opposed
	// to figure out if there's a wedged task (IOW, error could simply mean there was
	// nothing to kill)
	_ = containerd.CtrStopContainer(domainName, true)

	return containerd.CtrCreateTask(domainName)
}

func (ctx ctrdContext) Start(domainName string, domainID int) error {
	err := containerd.CtrStartTask(domainName)
	if err != nil {
		return err
	}

	// now lets wait for task to reach a steady state or for >10sec to elapse
	for i := 0; i < 10; i++ {
		_, status, err := containerd.CtrContainerInfo(domainName)
		if err == nil && status == "running" || status == "stopped" || status == "paused" {
			return nil
		}
		time.Sleep(time.Second)
	}

	return fmt.Errorf("task %s couldn't reach a steady state in time", domainName)
}

func (ctx ctrdContext) Stop(domainName string, domainID int, force bool) error {
	return containerd.CtrStopContainer(domainName, force)
}

func (ctx ctrdContext) Delete(domainName string, domainID int) error {
	return containerd.CtrDeleteContainer(domainName)
}

func (ctx ctrdContext) Info(domainName string, domainID int) (int, types.SwState, error) {
	effectiveDomainID, status, err := containerd.CtrContainerInfo(domainName)
	if err != nil {
		return 0, types.UNKNOWN, logError("containerd looking up domain %s with PID %d resulted in %v", domainName, domainID, err)
	}

	if effectiveDomainID != domainID {
		log.Warnf("containerd domain %s with PID %d (different from expected %d) is %s",
			domainName, effectiveDomainID, domainID, status)
	}

	stateMap := map[string]types.SwState{
		"running": types.RUNNING,
		"created": types.INSTALLED,
		"paused":  types.HALTED,
		"stopped": types.HALTED,
		"pausing": types.HALTING,
	}
	effectiveDomainState, matched := stateMap[status]
	if _, err := os.Stat("/proc/" + strconv.Itoa(effectiveDomainID)); err != nil || !matched {
		effectiveDomainState = types.UNKNOWN
	}

	return effectiveDomainID, effectiveDomainState, nil
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

func (ctx ctrdContext) GetHostCPUMem() (types.HostMemory, error) {
	return selfDomCPUMem()
}

func (ctx ctrdContext) GetDomsCPUMem() (map[string]types.DomainMetric, error) {
	res := map[string]types.DomainMetric{}
	ids, err := containerd.CtrListContainerIds()
	if err != nil {
		return nil, err
	}

	for _, id := range ids {
		var usedMem, availMem uint32
		var usedMemPerc float64
		var cpuTotal uint64

		if metric, err := containerd.CtrGetContainerMetrics(id); err == nil {
			usedMem = uint32(roundFromBytesToMbytes(metric.Memory.Usage.Usage))
			availMem = uint32(roundFromBytesToMbytes(metric.Memory.Usage.Max))
			if availMem != 0 {
				usedMemPerc = float64(100 * float32(usedMem) / float32(availMem))
			} else {
				usedMemPerc = 0
			}
			cpuTotal = metric.CPU.Usage.Total / 1000000000
		} else {
			log.Errorf("GetDomsCPUMem failed with error %v", err)
		}

		res[id] = types.DomainMetric{
			UUIDandVersion:    types.UUIDandVersion{},
			CPUTotal:          cpuTotal,
			UsedMemory:        usedMem,
			AvailableMemory:   availMem,
			UsedMemoryPercent: usedMemPerc,
		}
	}
	return res, nil
}
