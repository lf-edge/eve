// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"time"

	//	zconfig "github.com/lf-edge/eve-api/go/config"
	//	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	//	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/sirupsen/logrus"
	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//	"k8s.io/client-go/kubernetes"
	//	"k8s.io/client-go/rest"
	// "k8s.io/client-go/tools/clientcmd"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

// KubevirtHypervisorName is a name of kubevirt hypervisor
const KubevirtHypervisorName = "kubevirt"
const kubevirtStateDir = "/run/hypervisor/kubevirt/"
const eveNameSpace = "eve-kube-app"

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
	vmiList      map[string]*v1.VirtualMachineInstance
}

// Use few states  for now
var stateMap = map[string]types.SwState{
	"Paused":     types.PAUSED,
	"Running":    types.RUNNING,
	"shutdown":   types.HALTING,
	"suspended":  types.PAUSED,
	"Pending":    types.PENDING,
	"Scheduling": types.SCHEDULING,
	"Failed":     types.FAILED,
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
			ctrdContext: *ctrdCtx,
			devicemodel: "virt",
			vmiList:     make(map[string]*v1.VirtualMachineInstance),
		}
	case "amd64":
		return kubevirtContext{
			ctrdContext: *ctrdCtx,
			devicemodel: "pc-q35-3.1",
			vmiList:     make(map[string]*v1.VirtualMachineInstance),
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

	diskStatusList := status.DiskStatusList
	domainName := status.DomainName

	logrus.Infof("PRAMOD Setup called for Domain: %s", domainName)

	// Take eve domain config and convert to kube config
	if err := ctx.CreateKubeConfig(domainName, config, status, diskStatusList, aa, file); err != nil {
		return logError("failed to build kube config: %v", err)
	}

	os.MkdirAll(kubevirtStateDir+domainName, 0777)

	// return logError("PRAMOD domainmgr not supported yet for domain %s", status.DomainName)
	return nil

}

func (ctx kubevirtContext) CreateKubeConfig(domainName string, config types.DomainConfig, status types.DomainStatus,
	diskStatusList []types.DiskStatus, aa *types.AssignableAdapters, file *os.File) error {
	logrus.Infof("PRAMOD CreateKubeConfig called for Domain: %s", domainName)
	err, kubeconfig := kubeapi.GetKubeConfig()
	if err != nil {
		logrus.Errorf("couldn't get the Kube Config: %v", err)
		return err
	}

	_, err = kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return err
	}
	// Get a VirtualMachineInstance object and populate the values from DomainConfig
	vmi := v1.NewVMIReferenceFromNameWithNS(eveNameSpace, domainName)
	//vmi.ObjectMeta.UID = status.UUIDandVersion.UUID

	// Set CPUs

	cpus := v1.CPU{}
	cpus.Cores = uint32(config.VCpus)
	vmi.Spec.Domain.CPU = &cpus

	// Set memory

	mem := v1.Memory{}
	//config.Memory = (config.Memory + 1023) / 1024

	m, err := resource.ParseQuantity(convertToKubernetesFormat(config.Memory * 1024)) // To bytes from KB

	if err != nil {
		logrus.Errorf("Could not parse the memory value %v", err)
		return err
	}

	mem.Guest = &m
	vmi.Spec.Domain.Memory = &mem

	// Set Network
	intfs := make([]v1.Interface, len(config.KubeNADList)+1)
	nets := make([]v1.Network, len(config.KubeNADList)+1)
	intfs[0] = v1.Interface{
		Name:                   "default",
		InterfaceBindingMethod: v1.InterfaceBindingMethod{Bridge: &v1.InterfaceBridge{}},
	}
	nets[0] = *v1.DefaultPodNetwork()

	if len(config.KubeNADList) > 0 {
		for i, nad := range config.KubeNADList {
			intfname := "net" + strconv.Itoa(i+1)
			intfs[i+1] = v1.Interface{
				Name:                   intfname,
				MacAddress:             nad.Mac,
				InterfaceBindingMethod: v1.InterfaceBindingMethod{Bridge: &v1.InterfaceBridge{}},
			}

			nets[i+1] = v1.Network{
				Name: intfname,
				NetworkSource: v1.NetworkSource{
					Multus: &v1.MultusNetwork{
						NetworkName: nad.Name,
					},
				},
			}
		}
	}

	vmi.Spec.Networks = nets
	vmi.Spec.Domain.Devices.Interfaces = intfs

	// Set Storage

	if len(diskStatusList) > 0 {
		disks := make([]v1.Disk, len(diskStatusList))
		vols := make([]v1.Volume, len(diskStatusList))

		for i, ds := range diskStatusList {

			diskName := "disk" + strconv.Itoa(i+1)
			if ds.Devtype == "cdrom" {
				disks[i] = v1.Disk{
					Name: diskName,
					DiskDevice: v1.DiskDevice{
						CDRom: &v1.CDRomTarget{
							Bus: "sata",
						},
					},
				}
				vols[i] = v1.Volume{
					Name: diskName,
					VolumeSource: v1.VolumeSource{
						HostDisk: &v1.HostDisk{
							Path: ds.FileLocation,
							Type: "Disk",
						},
					},
				}
			} else {
				disks[i] = v1.Disk{
					Name: diskName,
					DiskDevice: v1.DiskDevice{
						Disk: &v1.DiskTarget{
							Bus: "virtio",
						},
					},
				}
				vols[i] = v1.Volume{
					Name: diskName,
					VolumeSource: v1.VolumeSource{
						PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{
							PersistentVolumeClaimVolumeSource: k8sv1.PersistentVolumeClaimVolumeSource{
								ClaimName: ds.VolumeKey,
							},
						},
					},
				}
			}

		}
		vmi.Spec.Domain.Devices.Disks = disks
		vmi.Spec.Volumes = vols
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
		return logError("PRAMOD: PCI assignments not supported yet %v", len(pciAssignments))
	}
	if len(serialAssignments) != 0 {
		return logError("PRAMOD: Serial assignments not supported yet %v", len(serialAssignments))
	}
	if len(usbAssignments) != 0 {
		return logError("PRAMOD: USB assignments not supported yet %v", len(usbAssignments))
	}

	// Now we have VirtualMachine Instance object, save it to file for debug purposes
	// and save it in context which will be use to start VM in Start() call

	ctx.vmiList[domainName] = vmi

	vmiStr := fmt.Sprintf("%+v", vmi)

	// write to config file

	file.WriteString(vmiStr)

	return nil
}

func (ctx kubevirtContext) Start(domainName string) error {
	logrus.Infof("starting Kubevirt domain %s", domainName)

	vmi := ctx.vmiList[domainName]

	err, kubeconfig := kubeapi.GetKubeConfig()
	if err != nil {
		logrus.Errorf("couldn't get the Kube Config: %v", err)
		return err
	}

	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return err
	}

	// Create the VM
	_, err = virtClient.VirtualMachineInstance(eveNameSpace).Create(context.Background(), vmi)
	if err != nil {
		fmt.Printf("Start VM failed %v\n", err)
		return err
	}

	logrus.Infof("Started Kubevirt domain %s", domainName)

	err = waitForVMI(domainName, true)

	if err != nil {
		logrus.Errorf("couldn't start VMI %v", err)
		return err
	}

	return nil

}

func (ctx kubevirtContext) Create(domainName string, cfgFilename string, config *types.DomainConfig) (int, error) {

	return len(ctx.vmiList), nil
}

// There is no such thing as stop VMI, so delete it.
func (ctx kubevirtContext) Stop(domainName string, force bool) error {
	logrus.Infof("PRAMOD Stop called for Domain: %s", domainName)
	err, kubeconfig := kubeapi.GetKubeConfig()
	if err != nil {
		logrus.Errorf("couldn't get the Kube Config: %v", err)
		return err
	}

	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return err
	}

	// Stop the VM
	err = virtClient.VirtualMachineInstance(eveNameSpace).Delete(context.Background(), domainName, &metav1.DeleteOptions{})
	if err != nil {
		fmt.Printf("Stop error %v\n", err)
		return err
	}

	return nil
}

func (ctx kubevirtContext) Delete(domainName string) (result error) {
	logrus.Infof("PRAMOD Delete called for Domain: %s", domainName)
	err, kubeconfig := kubeapi.GetKubeConfig()
	if err != nil {
		logrus.Errorf("couldn't get the Kube Config: %v", err)
		return err
	}

	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return err
	}

	// Stop the VM
	err = virtClient.VirtualMachineInstance(eveNameSpace).Delete(context.Background(), domainName, &metav1.DeleteOptions{})

	// May be already deleted during Stop action, so its not an error if does not exist
	if errors.IsNotFound(err) {
		logrus.Infof("Domain already deleted: %v", domainName)
	} else {
		fmt.Printf("Delete error %v\n", err)
		return err
	}
	// Delete the state dir
	if err := os.RemoveAll(kubevirtStateDir + domainName); err != nil {
		return logError("failed to clean up domain state directory %s (%v)", domainName, err)
	}

	return nil
}

func (ctx kubevirtContext) Info(domainName string) (int, types.SwState, error) {

	logrus.Infof("PRAMOD Info called for Domain: %s", domainName)

	res, err := getVMIStatus(domainName)

	if err != nil {
		return 0, types.BROKEN, logError("domain %s failed to get info: %v", domainName, err)
	}

	if effectiveDomainState, matched := stateMap[res]; !matched {
		return 0, types.BROKEN, logError("domain %s reported to be in unexpected state %s", domainName, res)
	} else {
		return len(ctx.vmiList), effectiveDomainState, nil
	}
}

func (ctx kubevirtContext) Cleanup(domainName string) error {
	logrus.Infof("PRAMOD Cleanup called for Domain: %s", domainName)
	if err := ctx.ctrdContext.Cleanup(domainName); err != nil {
		return fmt.Errorf("couldn't cleanup task %s: %v", domainName, err)
	}

	err := waitForVMI(domainName, false)

	if err != nil {
		return fmt.Errorf("waitforvmi failed  %s: %v", domainName, err)
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

// Kubernetes only allows size format in Ki, Mi, Gi etc. Not KiB, MiB, GiB ...
// so convert the bytes to that format
// kubevirt minimum supported memory is 1MB.
func convertToKubernetesFormat(b int) string {
	bf := float64(b)
	for _, unit := range []string{"", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"} {
		if math.Abs(bf) < 1024.0 {
			return fmt.Sprintf("%3.1f%s", bf, unit)
		}
		bf /= 1024.0
	}

	// Do we ever reach here ?
	return fmt.Sprintf("%.1fYi", bf)
}

func getVMIStatus(domainName string) (string, error) {

	err, kubeconfig := kubeapi.GetKubeConfig()
	if err != nil {
		return "", logError("couldn't get the Kube Config: %v", err)

	}

	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

	if err != nil {
		return "", logError("couldn't get the Kube client Config: %v", err)
	}

	// Get the VMI info
	vmi, err := virtClient.VirtualMachineInstance(eveNameSpace).Get(context.Background(), domainName, &metav1.GetOptions{})

	if err != nil {
		return "", logError("domain %s failed to get VMI info %s", domainName, err)
	}

	res := fmt.Sprintf("%v", vmi.Status.Phase)

	return res, nil
}
func waitForVMI(domainName string, available bool) error {
	maxDelay := time.Second * 300 // 5mins ?? lets keep it for now
	delay := time.Second
	var waited time.Duration

	for {
		logrus.Infof("waitForVMI for %s %t: waiting for %v", domainName, available, delay)
		if delay != 0 {
			time.Sleep(delay)
			waited += delay
		}

		state, err := getVMIStatus(domainName)

		if err != nil {

			if available {
				logrus.Infof("waitForVMI for %s %t done", domainName, available)
			} else {
				// Failed to get status, may be already deleted.
				logrus.Infof("waitForVMI for %s %t done", domainName, available)
				return nil
			}
		} else {
			if state == "Running" && available {
				return nil
			}
		}

		if waited > maxDelay {
			// Give up
			logrus.Warnf("waitForVMIfor %s %t: giving up", domainName, available)
			if available {
				return logError("VMI not found: error %v", err)
			}
			return logError("VMI still available")
		}
		delay = 2 * delay
		if delay > time.Minute {
			delay = time.Minute
		}
	}
}
