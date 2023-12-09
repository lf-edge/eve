// Copyright (c) 2017-2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/sirupsen/logrus"
)

const (
	dom0Name = "Domain-0"

	//XenHypervisorName is a name of xen hypervisor
	XenHypervisorName = "xen"
)

func addNoDuplicate(list []string, add string) []string {

	for _, s := range list {
		if s == add {
			return list
		}
	}
	return append(list, add)
}

type xenContext struct {
	ctrdContext
	capabilities *types.Capabilities
}

func (ctx xenContext) GetCapabilities() (*types.Capabilities, error) {
	if ctx.capabilities != nil {
		return ctx.capabilities, nil
	}
	errorString := ""
	vtx, err := ctx.checkHWAssistedVirtualization()
	if err != nil {
		errorString = err.Error()
	}
	vtd, err := ctx.checkIOVirtualisation()
	if err != nil {
		errorString = errorString + "; " + err.Error()
	}
	if errorString != "" {
		return nil, fmt.Errorf("GetCapabilities: %s", errorString)
	}
	ctx.capabilities = &types.Capabilities{
		HWAssistedVirtualization: vtx,
		IOVirtualization:         vtd,
		CPUPinning:               false,
		UseVHost:                 false,
	}
	return ctx.capabilities, nil
}

func (ctx xenContext) checkHWAssistedVirtualization() (bool, error) {
	switch runtime.GOARCH {
	case "arm64":
		//xen requires Arm virtualization extensions to run on ARM64
		return true, nil
	case "amd64":
		ctrdSystemCtx, done := ctx.ctrdClient.CtrNewSystemServicesCtx()
		defer done()
		stdOut, stdErr, err := ctx.ctrdClient.CtrSystemExec(ctrdSystemCtx, "xen-tools",
			[]string{"xl", "dmesg"})
		if err != nil {
			errStr := fmt.Sprintf("xl dmesg failed: %s %s", stdOut, stdErr)
			logrus.Errorln(errStr)
			return false, errors.New(errStr)
		}
		return strings.Contains(stdOut, "VMX enabled") || strings.Contains(stdOut, "SVM enabled"), nil
	}
	return false, fmt.Errorf("not implemented for %s", runtime.GOARCH)
}

func (ctx xenContext) checkIOVirtualisation() (bool, error) {
	ctrdSystemCtx, done := ctx.ctrdClient.CtrNewSystemServicesCtx()
	defer done()
	stdOut, stdErr, err := ctx.ctrdClient.CtrSystemExec(ctrdSystemCtx, "xen-tools",
		[]string{"xl", "dmesg"})
	if err != nil {
		errStr := fmt.Sprintf("xl dmesg failed: %s %s", stdOut, stdErr)
		logrus.Errorln(errStr)
		return false, errors.New(errStr)
	}
	return strings.Contains(stdOut, "I/O virtualisation enabled"), nil
}

func newXen() Hypervisor {
	ctrdCtx, err := initContainerd()
	if err != nil {
		logrus.Fatalf("couldn't initialize containerd (this should not happen): %v. Exiting.", err)
		return nil // it really never returns on account of above
	}
	return xenContext{ctrdContext: *ctrdCtx}
}

func (ctx xenContext) Name() string {
	return XenHypervisorName
}

func (ctx xenContext) Task(status *types.DomainStatus) types.Task {
	if status.VirtualizationMode == types.NOHYPER {
		return ctx.ctrdContext
	}
	return ctx
}

func (ctx xenContext) Setup(status types.DomainStatus, config types.DomainConfig,
	aa *types.AssignableAdapters, globalConfig *types.ConfigItemValueMap, file *os.File) error {
	// first lets build the domain config
	if err := ctx.CreateDomConfig(status.DomainName, config, status, status.DiskStatusList, aa, file); err != nil {
		return logError("failed to build domain config: %v", err)
	}

	var spec0 containerd.OCISpec // The main container for the app instance
	for i, dcs := range status.ContainerList {
		ociConfigDir := dcs.OCIConfigDir
		logrus.Infof("XXX processing %d dir %s", i, ociConfigDir)
		spec, err := ctx.setupSpec(&status, &config, ociConfigDir)
		if err != nil {
			return logError("failed to load OCI spec for domain %s oci %d %s: %v",
				status.DomainName, i, ociConfigDir, err)
		}
		if i == 0 {
			spec0 = spec
		}
		if err = spec.AddLoader("/containers/services/xen-tools"); err != nil {
			return logError("failed to add xen hypervisor loader to domain %s oci %d %s: %v",
				status.DomainName, i, ociConfigDir, err)
		}
	}
	// XXX find better code structure
	if spec0 == nil {
		// Not a container
		var err error
		spec0, err = ctx.setupSpec(&status, &config, "")
		if err != nil {
			return logError("failed to load OCI spec for domain %s: %v",
				status.DomainName, err)
		}
		if err = spec0.AddLoader("/containers/services/xen-tools"); err != nil {
			return logError("failed to add kvm hypervisor loader to domain %s: %v",
				status.DomainName, err)
		}
	}
	// finally we can start it up
	spec0.Get().Process.Args = []string{"/etc/xen/scripts/xen-start", status.DomainName, file.Name()}
	if config.MetaDataType == types.MetaDataOpenStack {
		spec0.Get().Process.Args = append(spec0.Get().Process.Args, "smbios_product")
	}
	if err := spec0.CreateContainer(true); err != nil {
		return logError("Failed to create container for task %s from %v: %v", status.DomainName, config, err)
	}

	return nil
}

func (ctx xenContext) CreateDomConfig(domainName string, config types.DomainConfig, status types.DomainStatus, diskStatusList []types.DiskStatus,
	aa *types.AssignableAdapters, file *os.File) error {
	xenType := "pvh"
	rootDev := ""
	extra := config.ExtraArgs
	bootLoader := ""
	kernel := config.Kernel
	ramdisk := config.Ramdisk
	vifType := "vif"
	xenGlobal := ""
	uuidStr := fmt.Sprintf("appuuid=%s ", config.UUIDandVersion.UUID)

	switch config.VirtualizationMode {
	case types.PV:
		xenType = "pv"
		extra = "console=hvc0 " + uuidStr + config.ExtraArgs
		if kernel == "" {
			kernel = "/usr/lib/xen/boot/ovmf-pvh.bin"
		}
	case types.HVM:
		xenType = "hvm"
	case types.LEGACY:
		xenType = "hvm"
		vifType = "ioemu"
		xenGlobal = "hdtype = \"ahci\"\n"
	case types.FML:
		xenType = "hvm"
		vifType = "ioemu"
		xenGlobal = "hdtype = \"ahci\"\nspoof_xen = 1\npci_permissive = 1\n"
	default:
		logrus.Errorf("Internal error: Unknown virtualizationMode %d",
			config.VirtualizationMode)
	}
	numOCI := len(status.ContainerList)
	if numOCI > 1 {
		extra += fmt.Sprintf(" max_oci=%d", numOCI-1)
	}

	file.WriteString("# This file is automatically generated by domainmgr\n")
	file.WriteString(fmt.Sprintf("name = \"%s\"\n", domainName))
	file.WriteString(fmt.Sprintf("type = \"%s\"\n", xenType))
	file.WriteString(fmt.Sprintf("uuid = \"%s\"\n",
		config.UUIDandVersion.UUID))
	file.WriteString(xenGlobal)

	if kernel != "" {
		file.WriteString(fmt.Sprintf("kernel = \"%s\"\n", kernel))
	}

	if ramdisk != "" {
		file.WriteString(fmt.Sprintf("ramdisk = \"%s\"\n", ramdisk))
	}

	if bootLoader != "" {
		file.WriteString(fmt.Sprintf("bootloader = \"%s\"\n",
			bootLoader))
	}
	if config.EnableVnc {
		if config.VirtualizationMode == types.PV {
			vncParams := []string{"vnc=1", "vnclisten=0.0.0.0"}
			if config.VncDisplay != 0 {
				vncParams = append(vncParams, fmt.Sprintf("vncdisplay=%d",
					config.VncDisplay))
			}
			if config.VncPasswd != "" {
				vncParams = append(vncParams, fmt.Sprintf("vncpasswd=%s",
					config.VncPasswd))
			}
			file.WriteString(fmt.Sprintf("vfb = ['%s']\n", strings.Join(vncParams, ", ")))
		} else {
			file.WriteString(fmt.Sprintf("vnc = 1\n"))
			file.WriteString(fmt.Sprintf("vnclisten = \"0.0.0.0\"\n"))
			file.WriteString(fmt.Sprintf("usb=1\n"))
			file.WriteString(fmt.Sprintf("usbdevice=[\"tablet\"]\n"))

			if config.VncDisplay != 0 {
				file.WriteString(fmt.Sprintf("vncdisplay = %d\n",
					config.VncDisplay))
			}
			if config.VncPasswd != "" {
				file.WriteString(fmt.Sprintf("vncpasswd = \"%s\"\n",
					config.VncPasswd))
			}
		}
	} else {
		if config.GPUConfig == "" {
			file.WriteString(fmt.Sprintf("nographic = 1\nvga=\"none\"\n"))
		}
		file.WriteString(fmt.Sprintf("vnc = 0\n"))
	}

	// Go from kbytes to mbytes
	kbyte2mbyte := func(kbyte int) int {
		return (kbyte + 1023) / 1024
	}
	file.WriteString(fmt.Sprintf("memory = %d\n",
		kbyte2mbyte(config.Memory)))
	if config.MaxMem != 0 {
		file.WriteString(fmt.Sprintf("maxmem = %d\n",
			kbyte2mbyte(config.MaxMem)))
	}
	vCpus := config.VCpus
	if vCpus == 0 {
		vCpus = 1
	}
	file.WriteString(fmt.Sprintf("vcpus = %d\n", vCpus))
	maxCpus := config.MaxCpus
	if maxCpus == 0 {
		maxCpus = vCpus
	}
	file.WriteString(fmt.Sprintf("maxvcpus = %d\n", maxCpus))
	if config.CPUs != "" {
		file.WriteString(fmt.Sprintf("cpus = \"%s\"\n", config.CPUs))
	}
	if config.DeviceTree != "" {
		file.WriteString(fmt.Sprintf("device_tree = \"%s\"\n",
			config.DeviceTree))
	}
	dtString := ""
	for _, dt := range config.DtDev {
		if dtString != "" {
			dtString += ","
		}
		dtString += fmt.Sprintf("\"%s\"", dt)
	}
	if dtString != "" {
		file.WriteString(fmt.Sprintf("dtdev = [%s]\n", dtString))
	}
	// Note that qcow2 images might have partitions hence xvda1 by default
	if rootDev != "" {
		file.WriteString(fmt.Sprintf("root = \"%s\"\n", rootDev))
	}
	if extra != "" {
		file.WriteString(fmt.Sprintf("extra = \"%s\"\n", extra))
	}
	// XXX Should one be able to disable the serial console? Would need
	// knob in manifest

	var serialAssignments []string
	serialAssignments = append(serialAssignments, "pty")

	// Always prefer CDROM vdisk over disk
	file.WriteString(fmt.Sprintf("boot = \"%s\"\n", "dc"))

	var diskStrings []string
	var p9Strings []string
	diskID := 0
	for i, ds := range diskStatusList {
		switch ds.Devtype {
		case "":
			continue
		case "9P":
			tag := "share_dir"
			if diskID != 0 {
				tag += strconv.Itoa(diskID)
			}
			p9Strings = append(p9Strings,
				fmt.Sprintf("'tag=%s,security_model=none,path=%s'",
					tag, ds.FileLocation))
		default:
			access := "rw"
			if ds.ReadOnly {
				access = "ro"
			}
			oneDisk := fmt.Sprintf("'%s,%s,%s,%s'",
				ds.FileLocation, strings.ToLower(ds.Format.String()), ds.Vdev, access)
			logrus.Debugf("Processing disk %d: %s\n", i, oneDisk)
			diskStrings = append(diskStrings, oneDisk)
		}
		diskID++
	}
	if len(diskStrings) > 0 {
		file.WriteString(fmt.Sprintf("disk = [%s]\n", strings.Join(diskStrings, ",")))
	}
	if len(p9Strings) > 0 {
		file.WriteString(fmt.Sprintf("p9 = [%s]\n", strings.Join(p9Strings, ",")))
	}

	vifString := ""
	for _, net := range config.VifList {
		oneVif := fmt.Sprintf("'bridge=%s,vifname=%s,mac=%s,type=%s'",
			net.Bridge, net.Vif, net.Mac, vifType)
		if vifString == "" {
			vifString = oneVif
		} else {
			vifString = vifString + ", " + oneVif
		}
	}
	file.WriteString(fmt.Sprintf("vif = [%s]\n", vifString))

	imString := ""
	for _, im := range config.IOMem {
		if imString != "" {
			imString += ","
		}
		imString += fmt.Sprintf("\"%s\"", im)
	}
	if imString != "" {
		file.WriteString(fmt.Sprintf("iomem = [%s]\n", imString))
	}

	// Gather all PCI assignments into a single line
	// Also irqs, ioports, and serials
	// irqs and ioports are used if we are pv; serials if hvm
	var pciAssignments []pciDevice
	var irqAssignments []string
	var ioportsAssignments []string
	var usbAssignments []string

	for _, irq := range config.IRQs {
		irqString := fmt.Sprintf("%d", irq)
		irqAssignments = addNoDuplicate(irqAssignments, irqString)
	}
	for _, adapter := range config.IoAdapterList {
		logrus.Debugf("configToXenCfg processing adapter %d %s\n",
			adapter.Type, adapter.Name)
		list := aa.LookupIoBundleAny(adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if len(list) == 0 {
			logrus.Fatalf("configToXencfg IoBundle disappeared %d %s for %s\n",
				adapter.Type, adapter.Name, domainName)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				logrus.Fatalf("configToXencfg IoBundle not ours %s: %d %s for %s\n",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					domainName)
			}
			if ib.PciLong != "" {
				tap := pciDevice{pciLong: ib.PciLong, ioType: ib.Type}
				pciAssignments = addNoDuplicatePCI(pciAssignments, tap)
			}
			if ib.Irq != "" && config.VirtualizationMode == types.PV {
				logrus.Infof("Adding irq <%s>\n", ib.Irq)
				irqAssignments = addNoDuplicate(irqAssignments,
					ib.Irq)
			}
			if ib.Ioports != "" && config.VirtualizationMode == types.PV {
				logrus.Infof("Adding ioport <%s>\n", ib.Ioports)
				ioportsAssignments = addNoDuplicate(ioportsAssignments, ib.Ioports)
			}
			if ib.Serial != "" && (config.VirtualizationMode == types.HVM || config.VirtualizationMode == types.FML || config.VirtualizationMode == types.LEGACY) {
				logrus.Infof("Adding serial <%s>\n", ib.Serial)
				serialAssignments = addNoDuplicate(serialAssignments, ib.Serial)
			}
			if ib.UsbAddr != "" && (config.VirtualizationMode == types.HVM || config.VirtualizationMode == types.LEGACY || config.VirtualizationMode == types.PV) {
				logrus.Infof("Adding USB <%s>\n", ib.UsbAddr)
				usbAssignments = addNoDuplicate(usbAssignments, ib.UsbAddr)
			}
		}
	}
	if len(pciAssignments) != 0 {
		logrus.Infof("PCI assignments %v\n", pciAssignments)
		cfg := fmt.Sprintf("pci = [ ")
		for i, pa := range pciAssignments {
			if i != 0 {
				cfg = cfg + ", "
			}
			short := types.PCILongToShort(pa.pciLong)
			// USB controller are subject to legacy USB support from
			// some BIOS. Use relaxed to get past that.
			if pa.ioType == types.IoUSB {
				cfg = cfg + fmt.Sprintf("'%s,rdm_policy=relaxed'",
					short)
			} else {
				cfg = cfg + fmt.Sprintf("'%s'", short)
			}
		}
		cfg = cfg + "]"
		logrus.Debugf("Adding pci config <%s>\n", cfg)
		file.WriteString(fmt.Sprintf("%s\n", cfg))
	}
	irqString := ""
	for _, irq := range irqAssignments {
		if irqString != "" {
			irqString += ","
		}
		irqString += irq
	}
	if irqString != "" {
		file.WriteString(fmt.Sprintf("irqs = [%s]\n", irqString))
	}
	ioportString := ""
	for _, ioports := range ioportsAssignments {
		if ioportString != "" {
			ioportString += ","
		}
		ioportString += ioports
	}
	if ioportString != "" {
		file.WriteString(fmt.Sprintf("ioports = [%s]\n", ioportString))
	}
	serialString := ""
	for _, serial := range serialAssignments {
		if serialString != "" {
			serialString += ","
		}
		serialString += "'" + serial + "'"
	}
	if serialString != "" {
		file.WriteString(fmt.Sprintf("serial = [%s]\n", serialString))
	}
	if len(usbAssignments) != 0 {
		logrus.Infof("USB assignments %v\n", usbAssignments)
		cfg := fmt.Sprintf("usbctrl = ['type=auto, version=2, ports=%d']\n", 6)
		cfg += fmt.Sprintf("usbdev = [")
		for i, UsbAddr := range usbAssignments {
			if i > 0 {
				cfg = cfg + ", "
			}
			bus, addr := usbBusPort(UsbAddr)
			cfg = cfg + fmt.Sprintf("'hostbus=%s,hostaddr=%s,controller=0,port=%d'", bus, addr, i)
		}
		cfg = cfg + "]\n"
		logrus.Debugf("Adding pci config <%s>\n", cfg)
		file.WriteString(fmt.Sprintf("%s\n", cfg))
	}
	return nil
}

func (ctx xenContext) Stop(domainName string, force bool) error {
	logrus.Infof("xlShutdown %s\n", domainName)
	args := []string{
		"xl",
		"shutdown",
		domainName,
	}
	if force {
		args = append(args, "-F")
	}
	ctrdCtx, done := ctx.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	stdOut, stdErr, err := ctx.ctrdClient.CtrExec(ctrdCtx, domainName, args)
	if err != nil {
		logrus.Errorln("xl shutdown failed ", err)
		logrus.Errorln("xl shutdown output ", stdOut, stdErr)
		return fmt.Errorf("xl shutdown failed: %s %s", stdOut, stdErr)
	}
	logrus.Infof("xl shutdown done: stdout: %s, stderr: %s", stdOut, stdErr)
	return nil
}

func (ctx xenContext) Delete(domainName string) (result error) {
	// regardless of happens to everything else, we have to try and delete the task
	defer func() {
		if err := ctx.ctrdContext.Delete(domainName); err != nil {
			result = fmt.Errorf("%w; couldn't delete task %s: %v", result, domainName, err)
		}
	}()

	logrus.Infof("xlDestroy %s\n", domainName)
	ctrdSystemCtx, done := ctx.ctrdClient.CtrNewSystemServicesCtx()
	defer done()
	stdOut, stdErr, err := ctx.ctrdClient.CtrSystemExec(ctrdSystemCtx, "xen-tools",
		[]string{"xl", "destroy", domainName})
	if err != nil {
		logrus.Errorln("xl destroy failed ", err)
		logrus.Errorln("xl destroy output ", stdOut, stdErr)
		return fmt.Errorf("xl destroy failed: %s %s", stdOut, stdErr)
	}

	logrus.Infof("xl destroy done %s, stdout: %s, stderr: %s",
		domainName, stdOut, stdErr)
	return nil
}

// getTaskStateFilePath returns file where xen-start puts state of domain
// must be aligned with xen-start logic
func (ctx xenContext) getTaskStateFilePath(domainName string) string {
	return filepath.Join("/run/tasks", domainName)
}

// Cleanup removes stale files and containerd-shim
func (ctx xenContext) Cleanup(domainName string) error {
	defer func() {
		// the file should come from xen-start after subsequent start
		err := os.RemoveAll(ctx.getTaskStateFilePath(domainName))
		if err != nil {
			logrus.Errorf("cleanup tasks file %s: %v", domainName, err)
		}
	}()
	if err := ctx.ctrdContext.Cleanup(domainName); err != nil {
		return fmt.Errorf("couldn't cleanup task %s: %v", domainName, err)
	}
	return nil
}

func (ctx xenContext) Info(domainName string) (int, types.SwState, error) {
	// first we ask for the task status
	effectiveDomainID, effectiveDomainState, err := ctx.ctrdContext.Info(domainName)
	if err != nil || effectiveDomainState != types.RUNNING {
		status, err := os.ReadFile(ctx.getTaskStateFilePath(domainName))
		if err != nil {
			status = []byte("file not read")
		}
		logrus.Infof("xen.Info(%s, %d) from containerd state %s, err: %v, status: %s",
			domainName, effectiveDomainID, effectiveDomainState.String(),
			err, string(status))
		return effectiveDomainID, effectiveDomainState, err
	}

	// if task is alive, we augment task status with finer grained details from xl info
	status, err := os.ReadFile(ctx.getTaskStateFilePath(domainName))
	if err != nil {
		logrus.Errorf("couldn't read task status file: %v", err)
		status = []byte("running") // assigning default state as we weren't able to read status file
	}
	logrus.Debugf("xen.Info(%s) have %d state %s status %s",
		domainName, effectiveDomainID,
		effectiveDomainState.String(), string(status))

	stateMap := map[string]types.SwState{
		"running": types.RUNNING,
		"paused":  types.PAUSED,
		"halting": types.HALTING,
		"broken":  types.BROKEN,
	}
	effectiveDomainState, matched := stateMap[strings.TrimSpace(string(status))]
	if !matched {
		return effectiveDomainID, types.BROKEN, fmt.Errorf("info: domain %s reported to be in unexpected state %v",
			domainName, string(status))
	} else if effectiveDomainState == types.BROKEN {
		return effectiveDomainID, types.BROKEN, fmt.Errorf("info: domain %s reported to be in broken state",
			domainName)

	}

	return effectiveDomainID, effectiveDomainState, nil
}

func (ctx xenContext) PCIReserve(long string) error {
	logrus.Infof("pciAssignableAdd %s\n", long)
	ctrdSystemCtx, done := ctx.ctrdClient.CtrNewSystemServicesCtx()
	defer done()
	stdOut, stdErr, err := ctx.ctrdClient.CtrSystemExec(ctrdSystemCtx, "xen-tools",
		[]string{"xl", "pci-assignable-add", long})
	if err != nil {
		errStr := fmt.Sprintf("xl pci-assignable-add failed: %s %s", stdOut, stdErr)
		logrus.Errorln(errStr)
		return errors.New(errStr)
	}
	logrus.Infof("xl pci-assignable-add done: stdout: %s, stderr: %s",
		stdOut, stdErr)
	return nil
}

func (ctx xenContext) PCIRelease(long string) error {
	logrus.Infof("pciAssignableRemove %s\n", long)
	ctrdSystemCtx, done := ctx.ctrdClient.CtrNewSystemServicesCtx()
	defer done()
	stdOut, stdErr, err := ctx.ctrdClient.CtrSystemExec(ctrdSystemCtx, "xen-tools",
		[]string{"xl", "pci-assignable-rem", "-r", long})
	if err != nil {
		errStr := fmt.Sprintf("xl pci-assignable-rem failed: %s %s", stdOut, stdErr)
		logrus.Errorln(errStr)
		return errors.New(errStr)
	}
	logrus.Infof("xl pci-assignable-rem done: stdout: %s, stderr: %s",
		stdOut, stdErr)
	return nil
}

func (ctx xenContext) PCISameController(id1 string, id2 string) bool {
	// We can not currently do enforcement based on iommu groups for Xen,
	// since the hypervisor hides that from dom0. Thus we assume that initial
	// bringup and model creation is done using KVM. That model can then be
	// used with KVM and Xen. Note that it maybe possible to improve Xen
	// disclosure of iommu groups (at least by interrogating it) but it would
	// require patching Xen itself (which may be a useful TODO).
	logrus.Infof("can't validate that %s and %s can be assigned separately: trusting Xen to do the right thing", id1, id2)
	return false
}

func (ctx xenContext) GetHostCPUMem() (types.HostMemory, error) {
	hm := types.HostMemory{}
	ctrdSystemCtx, done := ctx.ctrdClient.CtrNewSystemServicesCtx()
	defer done()
	xlInfo, stderr, err := ctx.ctrdClient.CtrSystemExec(ctrdSystemCtx, "xen-tools",
		[]string{"xl", "info"})
	if err != nil {
		return hm, fmt.Errorf("xl info failed stdout: %s stderr: %s, err: %v",
			xlInfo, stderr, err)
	}
	// Seems like we can get empty output, or partial output, from xl info
	if xlInfo == "" {
		return hm, fmt.Errorf("xl info empty stdout, stderr: %s",
			stderr)
	}
	splitXlInfo := strings.Split(xlInfo, "\n")

	dict := make(map[string]string, len(splitXlInfo)-1)
	for _, str := range splitXlInfo {
		res := strings.SplitN(str, ":", 2)
		if len(res) == 2 {
			dict[strings.TrimSpace(res[0])] = strings.TrimSpace(res[1])
		}
	}

	if str, ok := dict["total_memory"]; ok {
		res, err := strconv.ParseUint(str, 10, 64)
		if err != nil {
			return hm, fmt.Errorf("failed parsing total_memory: %s", err)
		}
		hm.TotalMemoryMB = res
	} else {
		logrus.Warnf("Missing total_memory in %+v", dict)
	}
	if str, ok := dict["free_memory"]; ok {
		res, err := strconv.ParseUint(str, 10, 64)
		if err != nil {
			return hm, fmt.Errorf("failed parsing free_memory: %s", err)
		}
		hm.FreeMemoryMB = res
	} else {
		logrus.Warnf("Missing free_memory in %+v", dict)
	}

	// Calculate what EVE is using. This excludes any memory the hypervisor is using
	// FWIW hm.TotalMemoryMB - hm.FreeMemoryMB would include the Xen hypervisor
	vm, err := mem.VirtualMemory()
	if err != nil {
		logrus.Error(err)
	} else {
		used := vm.Total - vm.Available
		hm.UsedEveMB = roundFromBytesToMbytes(used)
	}
	if str, ok := dict["nr_cpus"]; ok {
		// Note that this is the set of physical CPUs which is different
		// than the set of CPUs assigned to dom0
		res, err := strconv.ParseUint(str, 10, 32)
		if err != nil {
			return hm, fmt.Errorf("failed parsing nr_cpus: %s", err)
		}
		hm.Ncpus = uint32(res)
	} else {
		logrus.Warnf("Missing nr_cpus in %+v", dict)
	}
	return hm, nil
}

func (ctx xenContext) GetDomsCPUMem() (map[string]types.DomainMetric, error) {
	ctrdSystemCtx, done := ctx.ctrdClient.CtrNewSystemServicesCtx()
	defer done()
	xentopInfo, _, _ := ctx.ctrdClient.CtrSystemExec(ctrdSystemCtx, "xen-tools",
		[]string{"xentop", "-b", "-d", "1", "-i", "2", "-f"})

	splitXentopInfo := strings.Split(xentopInfo, "\n")
	splitXentopInfoLength := len(splitXentopInfo)

	// Start after last instance of "NAME" in the first column
	start := -1
	for i := 0; i < splitXentopInfoLength; i++ {
		fields := strings.Fields(strings.TrimSpace(splitXentopInfo[i]))
		if len(fields) == 0 {
			// Empty line probably end
		} else if fields[0] == "NAME" {
			start = i + 1
			logrus.Tracef("start set to %d", start)
		}
	}
	if start == -1 {
		logrus.Errorf("No NAME in: %+v", splitXentopInfo)
		logrus.Errorf("Calling fallbackDomainMetric")
		return fallbackDomainMetric(), nil
	}

	length := splitXentopInfoLength - 1 - start
	if length <= 0 {
		logrus.Errorf("No domains in: %+v", splitXentopInfo)
		logrus.Errorf("Calling fallbackDomainMetric")
		return fallbackDomainMetric(), nil
	}

	finalOutput := make([][]string, length)

	for j := start; j < splitXentopInfoLength-1; j++ {
		finalOutput[j-start] = strings.Fields(strings.TrimSpace(splitXentopInfo[j]))
	}

	cpuMemoryStat := make([][]string, length)

	for i := range cpuMemoryStat {
		cpuMemoryStat[i] = make([]string, 20)
	}

	// Need to treat "no limit" as one token
	for f := 0; f < length; f++ {

		// First name and state
		counter := 0
		out := 0
		counter++
		cpuMemoryStat[f][counter] = finalOutput[f][out]
		out++
		counter++
		cpuMemoryStat[f][counter] = finalOutput[f][out]
		out++
		for ; out < len(finalOutput[f]); out++ {

			if finalOutput[f][out] == "no" {

			} else if finalOutput[f][out] == "limit" {
				counter++
				cpuMemoryStat[f][counter] = "no limit"
			} else {
				counter++
				cpuMemoryStat[f][counter] = finalOutput[f][out]
			}
		}
	}
	logrus.Tracef("ExecuteXentopCmd return %+v", cpuMemoryStat)

	// first we get all the task stats from containerd, and we update
	// the ones that have a Xen domain associated with them
	dmList, err := ctx.ctrdContext.GetDomsCPUMem()
	if len(cpuMemoryStat) != 0 {
		dmList = parseCPUMemoryStat(cpuMemoryStat, dmList)
	} else if err != nil {
		logrus.Errorf("GetDomsCPUMem failed: %v", err)
		logrus.Errorf("Calling fallbackDomainMetric")
		dmList = fallbackDomainMetric()
	}
	// Need to add all of the others CPU nanoseconds into the Domain-0 entry
	// since it represents all of the device
	// XXX what about adding memory?
	dom0, ok := dmList[dom0Name]
	if !ok {
		logrus.Errorf("No Domain-0 in CPUMemoryStat")
	} else {
		for d, dm := range dmList {
			if d == dom0Name {
				continue
			}
			dom0.CPUTotalNs += dm.CPUTotalNs
		}
		dmList[dom0Name] = dom0
	}
	return dmList, nil
}

// Returns cpuTotal, usedMemory, availableMemory, usedPercentage
func parseCPUMemoryStat(cpuMemoryStat [][]string, dmList map[string]types.DomainMetric) map[string]types.DomainMetric {
	result := dmList
	if result == nil {
		result = make(map[string]types.DomainMetric)
	}

	for _, stat := range cpuMemoryStat {
		if len(stat) <= 2 {
			continue
		}
		domainname := strings.TrimSpace(stat[1])
		if len(stat) <= 6 {
			continue
		}
		logrus.Debugf("lookupCPUMemoryStat for %s %d elem: %+v",
			domainname, len(stat), stat)
		cpuTotal, err := strconv.ParseUint(stat[3], 10, 0)
		if err != nil {
			logrus.Errorf("ParseUint(%s) failed: %s",
				stat[3], err)
			cpuTotal = 0
		}
		// This is in kbytes
		totalMemory, err := strconv.ParseUint(stat[5], 10, 0)
		if err != nil {
			logrus.Errorf("ParseUint(%s) failed: %s",
				stat[5], err)
			totalMemory = 0
		}
		totalMemory = roundFromKbytesToMbytes(totalMemory)
		usedMemoryPercent, err := strconv.ParseFloat(stat[6], 10)
		if err != nil {
			logrus.Errorf("ParseFloat(%s) failed: %s",
				stat[6], err)
			usedMemoryPercent = 0
		}
		usedMemory := (float64(totalMemory) * (usedMemoryPercent)) / 100
		availableMemory := float64(totalMemory) - usedMemory

		dm := types.DomainMetric{
			CPUTotalNs:        cpuTotal * nanoSecToSec,
			CPUScaled:         1, // Caller will scale
			AllocatedMB:       uint32(totalMemory),
			UsedMemory:        uint32(usedMemory),
			AvailableMemory:   uint32(availableMemory),
			UsedMemoryPercent: float64(usedMemoryPercent),
		}
		result[domainname] = dm
	}
	return result
}

// First approximation for a host without Xen
// XXX Assumes that all of the used memory in the host is overhead the same way dom0 is
// overhead, which is completely incorrect when running containers
func fallbackDomainMetric() map[string]types.DomainMetric {
	dmList := make(map[string]types.DomainMetric)
	vm, err := mem.VirtualMemory()
	if err != nil {
		return dmList
	}
	var usedMemoryPercent float64
	if vm.Total != 0 {
		usedMemoryPercent = float64(100 * (vm.Total - vm.Available) / vm.Total)
	}
	total := roundFromBytesToMbytes(vm.Total)
	available := roundFromBytesToMbytes(vm.Available)
	dm := types.DomainMetric{
		UsedMemory:        uint32(total - available),
		AvailableMemory:   uint32(available),
		UsedMemoryPercent: usedMemoryPercent,
	}
	// Ask for one total entry
	cpuStat, err := cpu.Times(false)
	if err != nil {
		return dmList
	}
	for _, cpu := range cpuStat {
		dm.CPUTotalNs = uint64(cpu.Total() * float64(nanoSecToSec))
		dm.CPUScaled = 1 // Caller will scale
		break
	}
	dmList[dom0Name] = dm
	return dmList
}
