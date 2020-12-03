// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type ctrdContext struct {
	domCounter int
	PCI        map[string]bool
	ctrdClient *containerd.Client
}

func initContainerd() (*ctrdContext, error) {
	ctrdClient, err := containerd.NewContainerdClient()
	if err != nil {
		return nil, err
	}
	return &ctrdContext{
		domCounter: 0,
		PCI:        map[string]bool{},
		ctrdClient: ctrdClient,
	}, nil
}

func newContainerd() Hypervisor {
	if ret, err := initContainerd(); err != nil {
		logrus.Fatalf("couldn't initialize containerd (this should not happen): %v. Exiting.", err)
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

func (ctx ctrdContext) Setup(status types.DomainStatus, config types.DomainConfig, aa *types.AssignableAdapters, file *os.File) error {
	diskStatusList := status.DiskStatusList
	domainName := status.DomainName
	spec, err := ctx.ctrdClient.NewOciSpec(domainName)
	if err != nil {
		return logError("requesting default OCI spec for domain %s failed %v", domainName, err)
	}

	if len(diskStatusList) > 0 && diskStatusList[0].Format == zconfig.Format_CONTAINER {
		if err := spec.UpdateFromVolume(diskStatusList[0].FileLocation); err != nil {
			return logError("failed to update OCI spec from volume %s (%v)", diskStatusList[0].FileLocation, err)
		}
	}

	spec.UpdateFromDomain(config)
	spec.UpdateMounts(status.DiskStatusList)
	spec.UpdateVifList(config)
	spec.Get().Mounts = append(spec.Get().Mounts, specs.Mount{
		Type:        "bind",
		Source:      "/etc/resolv.conf",
		Destination: "/etc/resolv.conf",
		Options:     []string{"rbind", "ro"}})
	spec.UpdateEnvVar(status.EnvVariables)
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
	ctrdCtx, done := ctx.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	_ = ctx.ctrdClient.CtrStopContainer(ctrdCtx, domainName, true)

	return ctx.ctrdClient.CtrCreateTask(ctrdCtx, domainName)
}

func (ctx ctrdContext) Start(domainName string, domainID int) error {
	ctrdCtx, done := ctx.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	err := ctx.ctrdClient.CtrStartTask(ctrdCtx, domainName)
	if err != nil {
		return err
	}

	// now lets wait for task to reach a steady state or for >10sec to elapse
	for i := 0; i < 10; i++ {
		_, _, status, err := ctx.ctrdClient.CtrContainerInfo(ctrdCtx, domainName)
		if err == nil && (status == "running" || status == "stopped" || status == "paused") {
			return nil
		}
		time.Sleep(time.Second)
	}

	return fmt.Errorf("task %s couldn't reach a steady state in time", domainName)
}

func (ctx ctrdContext) Stop(domainName string, domainID int, force bool) error {
	ctrdCtx, done := ctx.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	return ctx.ctrdClient.CtrStopContainer(ctrdCtx, domainName, force)
}

func (ctx ctrdContext) Delete(domainName string, domainID int) error {
	ctrdCtx, done := ctx.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	return ctx.ctrdClient.CtrDeleteContainer(ctrdCtx, domainName)
}

func (ctx ctrdContext) Annotations(domainName string, domainID int) (map[string]string, error) {
	ctrdCtx, done := ctx.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	return ctx.ctrdClient.CtrGetAnnotations(ctrdCtx, domainName)
}

func (ctx ctrdContext) Info(domainName string, domainID int) (int, types.SwState, error) {
	ctrdCtx, done := ctx.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	effectiveDomainID, exit, status, err := ctx.ctrdClient.CtrContainerInfo(ctrdCtx, domainName)
	if err != nil {
		return domainID, types.UNKNOWN, logError("containerd looking up domain %s with PID %d resulted in %v", domainName, domainID, err)
	}

	if status == "stopped" && exit != 0 {
		return domainID, types.BROKEN, logError("task broke with exit status %d", exit)
	}

	if effectiveDomainID != domainID {
		logrus.Warnf("containerd domain %s with PID %d (different from expected %d) is %s",
			domainName, effectiveDomainID, domainID, status)
	}

	stateMap := map[string]types.SwState{
		"created": types.INSTALLED,
		"running": types.RUNNING,
		"pausing": types.PAUSING,
		"paused":  types.PAUSED,
		"stopped": types.HALTED,
	}
	if effectiveDomainState, matched := stateMap[status]; !matched {
		return effectiveDomainID, types.BROKEN, fmt.Errorf("task %s happens to be in an unexpected state %s",
			domainName, status)
	} else {
		return effectiveDomainID, effectiveDomainState, nil
	}
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

const clockTicks uint64 = 100 // github.com/containerd/cgroups/ticks.go hardcoded as 100 also
const nanoSecToSec uint64 = 1000000000

func (ctx ctrdContext) GetDomsCPUMem() (map[string]types.DomainMetric, error) {
	res := map[string]types.DomainMetric{}
	ctrdCtx, done := ctx.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	ids, err := ctx.ctrdClient.CtrListTaskIds(ctrdCtx)
	if err != nil {
		return nil, err
	}

	for _, id := range ids {
		var usedMem, availMem, totalMem uint32
		var usedMemPerc float64
		var cpuTotal uint64

		if metric, err := ctx.ctrdClient.CtrGetContainerMetrics(ctrdCtx, id); err == nil {
			usedMem = uint32(roundFromBytesToMbytes(metric.Memory.Usage.Usage))
			totalMem = uint32(roundFromBytesToMbytes(metric.Memory.HierarchicalMemoryLimit))
			availMem = 0
			if totalMem > usedMem {
				availMem = totalMem - usedMem
			}
			if totalMem != 0 {
				usedMemPerc = float64(100 * float32(usedMem) / float32(totalMem))
			} else {
				usedMemPerc = 0
			}
			cpuTotal = metric.CPU.Usage.Total / nanoSecToSec / clockTicks
		} else {
			logrus.Errorf("GetDomsCPUMem failed with error %v", err)
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
