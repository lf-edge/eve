// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"text/template"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"

	// "github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/sirupsen/logrus"
)

// KubevirtHypervisorName is a name of kubevirt hypervisor
const KubevirtHypervisorName = "kubevirt"
const kubevirtStateDir = "/run/hypervisor/kubevirt/"

// const sysfsPciDevices = "/sys/bus/pci/devices/"
// const sysfsVfioPciBind = "/sys/bus/pci/drivers/vfio-pci/bind"
// const sysfsPciDriversProbe = "/sys/bus/pci/drivers_probe"
// const vfioDriverPath = "/sys/bus/pci/drivers/vfio-pci"

type kubevirtContext struct {
	ctrdContext
	// for now the following is statically configured and can not be changed per domain
	devicemodel  string
	dmExec       string
	dmArgs       []string
	dmCPUArgs    []string
	dmFmlCPUArgs []string
	capabilities *types.Capabilities
}

func newKubevirt() Hypervisor {
	ctrdCtx, err := initContainerd()
	if err != nil {
		logrus.Fatalf("couldn't initialize containerd (this should not happen): %v. Exiting.", err)
		return nil // it really never returns on account of above
	}

	switch runtime.GOARCH {
	case "arm64":
		return kubevirtContext{
			ctrdContext:  *ctrdCtx,
			devicemodel:  "virt",
			dmExec:       "",
			dmArgs:       []string{},
			dmCPUArgs:    []string{},
			dmFmlCPUArgs: []string{},
		}
	case "amd64":
		return kubevirtContext{
			ctrdContext:  *ctrdCtx,
			devicemodel:  "pc-q35-3.1",
			dmExec:       "",
			dmArgs:       []string{},
			dmCPUArgs:    []string{},
			dmFmlCPUArgs: []string{},
		}
	}
	return nil
}

func (ctx kubevirtContext) GetCapabilities() (*types.Capabilities, error) {
	if ctx.capabilities != nil {
		return ctx.capabilities, nil
	}
	vtd, err := ctx.checkIOVirtualisation()
	if err != nil {
		return nil, fmt.Errorf("fail in check IOVirtualization: %v", err)
	}
	ctx.capabilities = &types.Capabilities{
		HWAssistedVirtualization: true,
		IOVirtualization:         vtd,
		CPUPinning:               true,
		UseVHost:                 false, // kubevirt does not support vhost yet
	}
	return ctx.capabilities, nil
}

func (ctx kubevirtContext) checkIOVirtualisation() (bool, error) {
	f, err := os.Open("/sys/kernel/iommu_groups")
	if err == nil {
		files, err := f.Readdirnames(0)
		if err != nil {
			return false, err
		}
		if len(files) != 0 {
			return true, nil
		}
	}
	return false, err
}

func (ctx kubevirtContext) Name() string {
	return KubevirtHypervisorName
}

func (ctx kubevirtContext) Task(status *types.DomainStatus) types.Task {
	if status.VirtualizationMode == types.NOHYPER {
		return ctx.ctrdContext
	} else {
		return ctx
	}
}

// Use eve DomainConfig and DomainStatus and generate k3s VM instance
func (ctx kubevirtContext) Setup(status types.DomainStatus, config types.DomainConfig,
	aa *types.AssignableAdapters, globalConfig *types.ConfigItemValueMap, file *os.File) error {

	return logError("PRAMOD domainmgr not supported yet for domain %s", status.DomainName)

}

func (ctx kubevirtContext) CreateDomConfig(domainName string, config types.DomainConfig, status types.DomainStatus,
	diskStatusList []types.DiskStatus, aa *types.AssignableAdapters, file *os.File) error {
	tmplCtx := struct {
		Machine string
		types.DomainConfig
		types.DomainStatus
	}{ctx.devicemodel, config, status}
	tmplCtx.DomainConfig.Memory = (config.Memory + 1023) / 1024
	tmplCtx.DomainConfig.DisplayName = domainName

	// Get a VirtualMachineInstance and populate the values from DomainConfig

	// render global device model settings
	t, _ := template.New("qemu").Parse(qemuConfTemplate)
	if err := t.Execute(file, tmplCtx); err != nil {
		return logError("can't write to config file %s (%v)", file.Name(), err)
	}

	// render disk device model settings
	diskContext := struct {
		Machine                          string
		PCIId, DiskID, SATAId, NumQueues int
		AioType                          string
		types.DiskStatus
	}{Machine: ctx.devicemodel, PCIId: 4, DiskID: 0, SATAId: 0, AioType: "io_uring", NumQueues: config.VCpus}

	t, _ = template.New("qemuDisk").
		Funcs(template.FuncMap{"Fmt": func(f zconfig.Format) string { return strings.ToLower(f.String()) }}).
		Parse(qemuDiskTemplate)
	for _, ds := range diskStatusList {
		if ds.Devtype == "" {
			continue
		}
		if ds.Devtype == "AppCustom" {
			// This is application custom data. It is forwarded to the VM
			// differently - as a download url in zedrouter
			continue
		}
		diskContext.DiskStatus = ds
		if err := t.Execute(file, diskContext); err != nil {
			return logError("can't write to config file %s (%v)", file.Name(), err)
		}
		if diskContext.Devtype == "cdrom" {
			diskContext.SATAId = diskContext.SATAId + 1
		} else {
			diskContext.PCIId = diskContext.PCIId + 1
		}
		diskContext.DiskID = diskContext.DiskID + 1
	}

	// render network device model settings
	netContext := struct {
		PCIId, NetID     int
		Driver           string
		Mac, Bridge, Vif string
	}{PCIId: diskContext.PCIId, NetID: 0}
	t, _ = template.New("qemuNet").Parse(qemuNetTemplate)
	for _, net := range config.VifList {
		netContext.Mac = net.Mac.String()
		netContext.Bridge = net.Bridge
		netContext.Vif = net.Vif
		if config.VirtualizationMode == types.LEGACY {
			netContext.Driver = "e1000"
		} else {
			netContext.Driver = "virtio-net-pci"
		}
		if err := t.Execute(file, netContext); err != nil {
			return logError("can't write to config file %s (%v)", file.Name(), err)
		}
		netContext.PCIId = netContext.PCIId + 1
		netContext.NetID = netContext.NetID + 1
	}

	// Gather all PCI assignments into a single line
	var pciAssignments []pciDevice
	// Gather all USB assignments into a single line
	var usbAssignments []string
	// Gather all serial assignments into a single line
	var serialAssignments []string

	for _, adapter := range config.IoAdapterList {
		logrus.Debugf("processing adapter %d %s\n", adapter.Type, adapter.Name)
		list := aa.LookupIoBundleAny(adapter.Name)
		// We reserved it in handleCreate so nobody could have stolen it
		if len(list) == 0 {
			logrus.Fatalf("IoBundle disappeared %d %s for %s\n",
				adapter.Type, adapter.Name, domainName)
		}
		for _, ib := range list {
			if ib == nil {
				continue
			}
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				logrus.Fatalf("IoBundle not ours %s: %d %s for %s\n",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					domainName)
			}
			if ib.PciLong != "" {
				logrus.Infof("Adding PCI device <%v>\n", ib.PciLong)
				tap := pciDevice{pciLong: ib.PciLong, ioType: ib.Type}
				pciAssignments = addNoDuplicatePCI(pciAssignments, tap)
			}
			if ib.Serial != "" {
				logrus.Infof("Adding serial <%s>\n", ib.Serial)
				serialAssignments = addNoDuplicate(serialAssignments, ib.Serial)
			}
			if ib.UsbAddr != "" {
				logrus.Infof("Adding USB host device <%s>\n", ib.UsbAddr)
				usbAssignments = addNoDuplicate(usbAssignments, ib.UsbAddr)
			}
		}
	}
	if len(pciAssignments) != 0 {
		pciPTContext := struct {
			PCIId        int
			PciShortAddr string
			Xvga         bool
			Xopregion    bool
		}{PCIId: netContext.PCIId, PciShortAddr: "", Xvga: false, Xopregion: false}

		t, _ = template.New("qemuPciPT").Parse(qemuPciPassthruTemplate)
		for _, pa := range pciAssignments {
			short := types.PCILongToShort(pa.pciLong)
			bootVgaFile := sysfsPciDevices + pa.pciLong + "/boot_vga"
			if _, err := os.Stat(bootVgaFile); err == nil {
				pciPTContext.Xvga = true
			}
			vendorFile := sysfsPciDevices + pa.pciLong + "/vendor"
			if vendor, err := os.ReadFile(vendorFile); err == nil {
				// check for Intel vendor
				if strings.TrimSpace(strings.TrimSuffix(string(vendor), "\n")) == "0x8086" {
					if pciPTContext.Xvga {
						// we set opregion for Intel vga
						// https://github.com/qemu/qemu/blob/stable-5.0/docs/igd-assign.txt#L91-L96
						pciPTContext.Xopregion = true
					}
				}
			}

			pciPTContext.PciShortAddr = short
			if err := t.Execute(file, pciPTContext); err != nil {
				return logError("can't write PCI Passthrough to config file %s (%v)", file.Name(), err)
			}
			pciPTContext.Xvga = false
			pciPTContext.Xopregion = false
			pciPTContext.PCIId = pciPTContext.PCIId + 1
		}
	}
	if len(serialAssignments) != 0 {
		serialPortContext := struct {
			SerialPortName string
			ID             int
		}{SerialPortName: "", ID: 0}

		t, _ = template.New("qemuSerial").Parse(qemuSerialTemplate)
		for id, serial := range serialAssignments {
			serialPortContext.SerialPortName = serial
			fmt.Printf("id for serial is %d\n", id)
			serialPortContext.ID = id
			if err := t.Execute(file, serialPortContext); err != nil {
				return logError("can't write serial assignment to config file %s (%v)", file.Name(), err)
			}
		}
	}
	if len(usbAssignments) != 0 {
		usbHostContext := struct {
			UsbBus     string
			UsbDevAddr string
			// Ports are dot-separated
		}{UsbBus: "", UsbDevAddr: ""}

		t, _ = template.New("qemuUsbHost").Parse(qemuUsbHostTemplate)
		for _, usbaddr := range usbAssignments {
			bus, port := usbBusPort(usbaddr)
			usbHostContext.UsbBus = bus
			usbHostContext.UsbDevAddr = port
			if err := t.Execute(file, usbHostContext); err != nil {
				return logError("can't write USB host device assignment to config file %s (%v)", file.Name(), err)
			}
		}
	}

	return nil
}

func (ctx kubevirtContext) Start(domainName string) error {
	logrus.Infof("starting KVM domain %s", domainName)
	if err := ctx.ctrdContext.Start(domainName); err != nil {
		logrus.Errorf("couldn't start task for domain %s: %v", domainName, err)
		return err
	}
	logrus.Infof("done launching qemu device model")
	if err := waitForQmp(domainName, true); err != nil {
		logrus.Errorf("Error waiting for Qmp for domain %s: %v", domainName, err)
		return err
	}
	logrus.Infof("done launching qemu device model")

	qmpFile := getQmpExecutorSocket(domainName)

	logrus.Debugf("starting qmpEventHandler")
	logrus.Infof("Creating %s at %s", "qmpEventHandler", agentlog.GetMyStack())
	go qmpEventHandler(getQmpListenerSocket(domainName), getQmpExecutorSocket(domainName))

	annotations, err := ctx.ctrdContext.Annotations(domainName)
	if err != nil {
		logrus.Warnf("Error in get annotations for domain %s: %v", domainName, err)
		return err
	}

	if vncPassword, ok := annotations[containerd.EVEOCIVNCPasswordLabel]; ok && vncPassword != "" {
		if err := execVNCPassword(qmpFile, vncPassword); err != nil {
			return logError("failed to set VNC password %v", err)
		}
	}

	if err := execContinue(qmpFile); err != nil {
		return logError("failed to start domain that is stopped %v", err)
	}

	if status, err := getQemuStatus(qmpFile); err != nil || status != "running" {
		return logError("domain status is not running but %s after cont command returned %v", status, err)
	}
	return nil
}

func (ctx kubevirtContext) Stop(domainName string, force bool) error {
	if err := execShutdown(getQmpExecutorSocket(domainName)); err != nil {
		return logError("Stop: failed to execute shutdown command %v", err)
	}
	return nil
}

func (ctx kubevirtContext) Delete(domainName string) (result error) {
	//Sending a stop signal to then domain before quitting. This is done to freeze the domain before quitting it.
	execStop(getQmpExecutorSocket(domainName))
	if err := execQuit(getQmpExecutorSocket(domainName)); err != nil {
		return logError("failed to execute quit command %v", err)
	}
	// we may want to wait a little bit here and actually kill qemu process if it gets wedged
	if err := os.RemoveAll(kubevirtStateDir + domainName); err != nil {
		return logError("failed to clean up domain state directory %s (%v)", domainName, err)
	}

	return nil
}

func (ctx kubevirtContext) Info(domainName string) (int, types.SwState, error) {
	// first we ask for the task status
	effectiveDomainID, effectiveDomainState, err := ctx.ctrdContext.Info(domainName)
	if err != nil || effectiveDomainState != types.RUNNING {
		return effectiveDomainID, effectiveDomainState, err
	}

	// if task us alive, we augment task status with finer grained details from qemu
	// lets parse the status according to https://github.com/qemu/qemu/blob/master/qapi/run-state.json#L8
	stateMap := map[string]types.SwState{
		"finish-migrate": types.PAUSED,
		"inmigrate":      types.PAUSING,
		"paused":         types.PAUSED,
		"postmigrate":    types.PAUSED,
		"prelaunch":      types.PAUSED,
		"restore-vm":     types.PAUSED,
		"running":        types.RUNNING,
		"save-vm":        types.PAUSED,
		"shutdown":       types.HALTING,
		"suspended":      types.PAUSED,
		"watchdog":       types.PAUSING,
		"colo":           types.PAUSED,
		"preconfig":      types.PAUSED,
	}
	res, err := getQemuStatus(getQmpExecutorSocket(domainName))
	if err != nil {
		return effectiveDomainID, types.BROKEN, logError("couldn't retrieve status for domain %s: %v", domainName, err)
	}

	if effectiveDomainState, matched := stateMap[res]; !matched {
		return effectiveDomainID, types.BROKEN, logError("domain %s reported to be in unexpected state %s", domainName, res)
	} else {
		return effectiveDomainID, effectiveDomainState, nil
	}
}

func (ctx kubevirtContext) Cleanup(domainName string) error {
	if err := ctx.ctrdContext.Cleanup(domainName); err != nil {
		return fmt.Errorf("couldn't cleanup task %s: %v", domainName, err)
	}
	if err := waitForQmp(domainName, false); err != nil {
		return fmt.Errorf("error waiting for Qmp absent for domain %s: %v", domainName, err)
	}

	return nil
}

// All PCI specific code is a copy from kvm.go, is there an ideal way to share the code ?
func (ctx kubevirtContext) PCIReserve(long string) error {
	logrus.Infof("PCIReserve long addr is %s", long)

	overrideFile := sysfsPciDevices + long + "/driver_override"
	driverPath := sysfsPciDevices + long + "/driver"
	unbindFile := driverPath + "/unbind"

	//Check if already bound to vfio-pci
	driverPathInfo, driverPathErr := os.Stat(driverPath)
	vfioDriverPathInfo, vfioDriverPathErr := os.Stat(vfioDriverPath)
	if driverPathErr == nil && vfioDriverPathErr == nil &&
		os.SameFile(driverPathInfo, vfioDriverPathInfo) {
		logrus.Infof("Driver for %s is already bound to vfio-pci, skipping unbind", long)
		return nil
	}

	//map vfio-pci as the driver_override for the device
	if err := os.WriteFile(overrideFile, []byte("vfio-pci"), 0644); err != nil {
		return logError("driver_override failure for PCI device %s: %v",
			long, err)
	}

	//Unbind the current driver, whatever it is, if there is one
	if _, err := os.Stat(unbindFile); err == nil {
		if err := os.WriteFile(unbindFile, []byte(long), 0644); err != nil {
			return logError("unbind failure for PCI device %s: %v",
				long, err)
		}
	}

	if err := os.WriteFile(sysfsPciDriversProbe, []byte(long), 0644); err != nil {
		return logError("drivers_probe failure for PCI device %s: %v",
			long, err)
	}

	return nil
}

func (ctx kubevirtContext) PCIRelease(long string) error {
	logrus.Infof("PCIRelease long addr is %s", long)

	overrideFile := sysfsPciDevices + long + "/driver_override"
	unbindFile := sysfsPciDevices + long + "/driver/unbind"

	//Write Empty string, to clear driver_override for the device
	if err := os.WriteFile(overrideFile, []byte("\n"), 0644); err != nil {
		logrus.Fatalf("driver_override failure for PCI device %s: %v",
			long, err)
	}

	//Unbind vfio-pci, if unbind file is present
	if _, err := os.Stat(unbindFile); err == nil {
		if err := os.WriteFile(unbindFile, []byte(long), 0644); err != nil {
			logrus.Fatalf("unbind failure for PCI device %s: %v",
				long, err)
		}
	}

	//Write PCI DDDD:BB:DD.FF to /sys/bus/pci/drivers_probe,
	//as a best-effort to bring back original driver
	if err := os.WriteFile(sysfsPciDriversProbe, []byte(long), 0644); err != nil {
		logrus.Fatalf("drivers_probe failure for PCI device %s: %v",
			long, err)
	}

	return nil
}

func (ctx kubevirtContext) PCISameController(id1 string, id2 string) bool {
	tag1, err := types.PCIGetIOMMUGroup(id1)
	if err != nil {
		return types.PCISameController(id1, id2)
	}

	tag2, err := types.PCIGetIOMMUGroup(id2)
	if err != nil {
		return types.PCISameController(id1, id2)
	}

	return tag1 == tag2
}
