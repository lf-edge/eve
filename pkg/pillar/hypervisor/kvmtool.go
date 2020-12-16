// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"os"
	"strconv"
)

// KVM domains map 1-1 to anchor device model UNIX processes (qemu or firecracker)
// For every anchor process we maintain the following entry points in the
// /run/hypervisor/kvmtool/DOMAIN_NAME:
//    pid - contains PID of the anchor process
//   cons - symlink to /dev/pts/X that allows us to talk to the serial console of the domain
// In addition to that, we also maintain DOMAIN_NAME -> PID mapping in kvmContext, so we don't
// have to look things up in the filesystem all the time (this also allows us to filter domains
// that may be created by others)
type kvmToolContext struct {
	ctrdContext
	// for now the following is statically configured and can not be changed per domain
	dmExec string
	dmArgs []string
}

func newKvmTool() Hypervisor {
	ctrdCtx, err := initContainerd()
	if err != nil {
		logrus.Fatalf("couldn't initialize containerd (this should not happen): %v. Exiting.", err)
		return nil // it really never returns on account of above
	}
	return kvmToolContext{
		ctrdContext: *ctrdCtx,
		dmExec:      "/usr/bin/lkvm",
		dmArgs:      []string{"run"},
	}
}

func (ctx kvmToolContext) Name() string {
	return "kvmtool"
}

func (ctx kvmToolContext) Task(status *types.DomainStatus) types.Task {
	if status.VirtualizationMode == types.NOHYPER {
		return ctx.ctrdContext
	} else {
		return ctx
	}
}

const kvmToolOverHead = int64(40 * 1024 * 1024)
const sockPath = string("/run/hypervisor/kvmtool/")

func (ctx kvmToolContext) Setup(status types.DomainStatus,
	config types.DomainConfig, aa *types.AssignableAdapters, file *os.File) error {

	diskStatusList := status.DiskStatusList
	domainName := status.DomainName

	args := []string{ctx.dmExec}
	args = append(args, ctx.dmArgs...)
	args = append(args, "--name", domainName)

	args = append(args, "--mem", strconv.Itoa((config.Memory+1023)/1024))

	if config.IsContainer {
		args = append(args, "--kernel", "/hostfs/boot/kernel")
		args = append(args, "--initrd", "/boot/runx-initrd")
		args = append(args, "--params", " root=9p-kvm dhcp=1")
	}

	for _, ds := range diskStatusList {
		if ds.Devtype == "" {
			continue
		}
		if ds.Devtype == "9P" {
			args = append(args, "--9p", fmt.Sprintf("%s,hostshare", ds.FileLocation))
		}
		if ds.Devtype == "hdd" {
			args = append(args, "--disk", ds.FileLocation)
		}
	}

	for _, net := range config.VifList {
		str := fmt.Sprintf("trans=virtio,guest_mac=%s,mode=tap,tapif=%s,script=/etc/kvmtool/scripts/kvmtool-ifup,script_option=%s", net.Mac, net.Vif, net.Bridge)
		args = append(args, "--network", str)
	}

	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		logrus.Infof("Creating path %s", sockPath)
		os.MkdirAll(sockPath, 0700)
	}
	os.Setenv("HOME", sockPath)

	logrus.Infof("Launching kvmtool device model with args %q", args)

	//nolint:godox // FIXME: Not passing domain config to LKTaskPrepare for disk performance improvement,
	// revisit it later as part of resource partitioning
	if err := ctx.ctrdClient.LKTaskPrepare(domainName, "kvm-tools", nil, &status, kvmToolOverHead, args); err != nil {
		return logError("LKTaskPrepare failed for %s, (%v)", domainName, err)
	}

	return nil
}

func (ctx kvmToolContext) Start(domainName string, domainID int) error {
	logrus.Infof("starting KVM domain %s", domainName)

	if err := ctx.ctrdContext.Start(domainName, domainID); err != nil {
		logrus.Errorf("couldn't start task for domain %s: %v", domainName, err)
		return err
	}
	logrus.Infof("done launching kvmtool device model")

	return nil
}

func (ctx kvmToolContext) Stop(domainName string, domainID int, force bool) error {
	return nil
}

func (ctx kvmToolContext) Delete(domainName string, domainID int) error {
	if err := ctx.ctrdContext.Stop(domainName, domainID, true); err != nil {
		return err
	}

	return ctx.ctrdContext.Delete(domainName, domainID)
}

func (ctx kvmToolContext) Info(domainName string, domainID int) (int, types.SwState, error) {
	// first we ask for the task status
	effectiveDomainID, effectiveDomainState, err := ctx.ctrdContext.Info(domainName, domainID)
	if err != nil || effectiveDomainState != types.RUNNING {
		return effectiveDomainID, effectiveDomainState, err
	}

	return effectiveDomainID, types.RUNNING, nil
}
