// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package hypervisor

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/sirupsen/logrus"
	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"

	//"k8s.io/client-go/kubernetes"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

// KubevirtHypervisorName is a name of kubevirt hypervisor
const (
	KubevirtHypervisorName = "kubevirt"
	kubevirtStateDir       = "/run/hypervisor/kubevirt/"
	eveLableKey            = "App-Domain-Name"
)

// VM instance meta data structure.
type vmiMetaData struct {
	vmi      *v1.VirtualMachineInstance // Handle to the VM instance
	pod      *k8sv1.Pod                 // Handle to the pod container
	domainId int                        // DomainId understood by domainmgr in EVE
	isPod    bool                       // switch on is Pod or is VMI
	name     string                     // Display-Name(all lower case) + first 5 bytes of domainName
	cputotal uint64                     // total CPU in NS so far
	maxmem   uint32                     // total Max memory usage in bytes so far
}

type kubevirtContext struct {
	ctrdContext
	devicemodel       string
	capabilities      *types.Capabilities
	vmiList           map[string]*vmiMetaData
	virthandlerIPAddr string
	prevDomainMetric  map[string]types.DomainMetric
	kubeConfig        *rest.Config
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

var excludedMetrics = map[string]struct{}{
	"kubevirt_vmi_cpu_affinity":                        {},
	"kubevirt_vmi_memory_actual_balloon_bytes":         {},
	"kubevirt_vmi_memory_unused_bytes":                 {},
	"kubevirt_vmi_memory_pgmajfault":                   {},
	"kubevirt_vmi_memory_pgminfault":                   {},
	"kubevirt_vmi_memory_swap_in_traffic_bytes_total":  {},
	"kubevirt_vmi_memory_swap_out_traffic_bytes_total": {},
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
			ctrdContext:      *ctrdCtx,
			devicemodel:      "virt",
			vmiList:          make(map[string]*vmiMetaData),
			prevDomainMetric: make(map[string]types.DomainMetric),
		}
	case "amd64":
		return kubevirtContext{
			ctrdContext:      *ctrdCtx,
			devicemodel:      "pc-q35-3.1",
			vmiList:          make(map[string]*vmiMetaData),
			prevDomainMetric: make(map[string]types.DomainMetric),
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

	logrus.Infof("PRAMOD Setup called for Domain: %s, vmmode %v", domainName, config.VirtualizationMode)

	if config.VirtualizationMode == types.KubeContainer {
		if err := ctx.CreatePodConfig(domainName, config, status, diskStatusList, aa, file); err != nil {
			return logError("failed to build kube pod config: %v", err)
		}
	} else {
		// Take eve domain config and convert to VMI config
		if err := ctx.CreateVMIConfig(domainName, config, status, diskStatusList, aa, file); err != nil {
			return logError("failed to build kube config: %v", err)
		}
	}

	os.MkdirAll(kubevirtStateDir+domainName, 0777)

	// return logError("PRAMOD domainmgr not supported yet for domain %s", status.DomainName)
	return nil

}

// Kubevirt VMI config spec is updated with the domain config/status of the app.
// The details and the struct of the spec can be found at:
// https://kubevirt.io/api-reference/v1.0.0/definitions.html
func (ctx kubevirtContext) CreateVMIConfig(domainName string, config types.DomainConfig, status types.DomainStatus,
	diskStatusList []types.DiskStatus, aa *types.AssignableAdapters, file *os.File) error {
	logrus.Infof("PRAMOD CreateVMIConfig called for Domain: %s", domainName)

	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	kubeconfig := ctx.kubeConfig
	kvClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return err
	}

	kubeName := base.GetAppKubeName(config.DisplayName, config.UUIDandVersion.UUID)
	// Get a VirtualMachineInstance object and populate the values from DomainConfig
	vmi := v1.NewVMIReferenceFromNameWithNS(kubeapi.EVEKubeNameSpace, kubeName)

	// Set CPUs
	cpus := v1.CPU{}
	cpus.Cores = uint32(config.VCpus)
	vmi.Spec.Domain.CPU = &cpus

	// Set memory
	mem := v1.Memory{}
	m, err := resource.ParseQuantity(convertToKubernetesFormat(config.Memory * 1024)) // To bytes from KB
	if err != nil {
		logrus.Errorf("Could not parse the memory value %v", err)
		return err
	}
	mem.Guest = &m
	vmi.Spec.Domain.Memory = &mem

	var netSelections []netattdefv1.NetworkSelectionElement
	for _, vif := range config.VifList {
		netSelections = append(netSelections, netattdefv1.NetworkSelectionElement{
			Name:       kubeapi.NetworkInstanceNAD,
			MacRequest: vif.Mac.String(),
		})
	}

	// Set Network
	// XXX for now, skip the default network interface for VMI, it seems that for some
	// type of VM its secondary interfaces will come up without IP address unless
	// we manually run dhclient on them
	intfs := make([]v1.Interface, len(netSelections))
	nads := make([]v1.Network, len(netSelections))
	/*
		intfs[0] = v1.Interface{
			Name:                   "default",
			InterfaceBindingMethod: v1.InterfaceBindingMethod{Bridge: &v1.InterfaceBridge{}},
		}
		nads[0] = *v1.DefaultPodNetwork()
	*/

	for i, netSelection := range netSelections {
		intfname := "net" + strconv.Itoa(i+1)
		intfs[i] = v1.Interface{
			Name:                   intfname,
			MacAddress:             netSelection.MacRequest,
			InterfaceBindingMethod: v1.InterfaceBindingMethod{Bridge: &v1.InterfaceBridge{}},
		}

		nads[i] = v1.Network{
			Name: intfname,
			NetworkSource: v1.NetworkSource{
				Multus: &v1.MultusNetwork{
					NetworkName: kubeapi.NetworkInstanceNAD,
				},
			},
		}
	}

	vmi.Spec.Networks = nads
	vmi.Spec.Domain.Devices.Interfaces = intfs

	// First check the diskStatusList and ignore 9P
	// Set Storage
	if len(diskStatusList) > 0 {
		disks := make([]v1.Disk, len(diskStatusList))
		vols := make([]v1.Volume, len(diskStatusList))
		ndisks := len(diskStatusList)
		for i, ds := range diskStatusList {

			diskName := "disk" + strconv.Itoa(i+1)

			// Domainmgr sets devtype 9P for container images. Though in kubevirt container image is
			// converted to PVC and will not use 9P protocol, but we still use this dev type to launch a
			// external bootable container.
			if ds.Devtype == "9P" {
				// kvm based EVE supports launching a container as VM. It generates a runtime ocispec and passes in
				// kernel and initrd along with other generated files.
				// The concept is same in kubevirt eve too. Kubevirt supports this functionality through feature
				// https://kubevirt.io/user-guide/virtual_machines/boot_from_external_source/
				// We need to have a prebuilt scratch image and pass in the path of kernel, initrd and any kernel args in the vmi spec we are generating.
				// TODO: eve build generates this scratch image. For now its hardcoded.

				// Since disks are virtio disks we assume /dev/vda is the boot disk
				kernel_args := "console=tty0 root=/dev/vda dhcp=1 rootfstype=ext4"
				scratch_image := "docker.io/lfedge/eve-external-boot-image:latest"
				kernel_path := "/kernel"
				initrd_path := "/runx-initrd"

				addKernelBootContainer(&vmi.Spec, scratch_image, kernel_args, kernel_path, initrd_path)

				// We don't set this disk to vmi spec
				ndisks = ndisks - 1

			} else if ds.Devtype == "cdrom" {
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

				pvcName, err := ds.GetPVCNameFromVolumeKey()
				if err != nil {
					return logError("Failed to fetch PVC Name from volumekey %v", ds.VolumeKey)
				}

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
								ClaimName: pvcName,
							},
						},
					},
				}
			}

		}
		vmi.Spec.Domain.Devices.Disks = disks[0:ndisks]
		vmi.Spec.Volumes = vols[0:ndisks]
	}

	// Gather all PCI assignments into a single line
	var pciAssignments []pciDevice

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
			if ib.Type == types.IoNetEth && ib.Ifname != adapter.Name {
				// if we get here, means we have a PCI device which is in the same group
				// as the ethernet passthrogh port, will have error if register to the kubevirt
				logrus.Infof("Skip PCI device %s which does not match adapter %s\n", ib.Ifname, adapter.Name)
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

		}
	}

	if len(pciAssignments) > 0 {
		// Device passthrough is a three step process in Kubevirt/Kubernetes
		// 1) First do PCI Reserve like in kvm.go (If we are here, PCI Reserve is already done)
		// 2) Register the  pciVendorSelector which is a PCI vendor ID and product ID tuple in the form vendor_id:product_id
		//    with kubevirt
		// 3) Then pass the registered names to VMI config
		err := registerWithKV(kvClient, vmi, pciAssignments)
		if err != nil {
			return logError("Failed to register with Kubevirt  %v", len(pciAssignments))
		}
	}

	vmi.Labels = make(map[string]string)
	vmi.Labels[eveLableKey] = domainName

	// Now we have VirtualMachine Instance object, save it to config file for debug purposes
	// and save it in context which will be used to start VM in Start() call
	// dispName is for vmi name/handle on kubernetes
	meta := vmiMetaData{
		vmi:      vmi,
		name:     kubeName,
		domainId: int(rand.Uint32()),
	}
	ctx.vmiList[domainName] = &meta

	vmiStr := fmt.Sprintf("%+v", vmi)

	// write to config file
	file.WriteString(vmiStr)

	return nil
}

func (ctx kubevirtContext) Start(domainName string) error {
	logrus.Infof("starting Kubevirt domain %s", domainName)

	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	kubeconfig := ctx.kubeConfig

	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return logError("start domain %s failed to get vmlist", domainName)
	}
	if vmis.isPod {
		err := StartPodContiner(kubeconfig, ctx.vmiList[domainName].pod)
		return err
	}

	vmi := vmis.vmi
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return err
	}

	// Create the VM
	i := 5
	for {
		_, err = virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).Create(context.Background(), vmi)
		// TODO: update if exists
		if err != nil {
			if strings.Contains(err.Error(), "dial tcp 127.0.0.1:6443") && i <= 0 {
				logrus.Infof("Start VM failed %v\n", err)
				return err
			}
			time.Sleep(10 * time.Second)
			logrus.Infof("Start VM failed, retry (%d) err %v", i, err)
		} else {
			break
		}
		i = i - 1
	}

	logrus.Infof("Started Kubevirt domain %s", domainName)

	err = waitForVMI(vmis.name, true)
	if err != nil {
		logrus.Errorf("couldn't start VMI %v", err)
		return err
	}

	return nil

}

// Create is no-op for kubevirt, just return the domainId we already have.
func (ctx kubevirtContext) Create(domainName string, cfgFilename string, config *types.DomainConfig) (int, error) {
	return ctx.vmiList[domainName].domainId, nil
}

// There is no such thing as stop VMI, so delete it.
func (ctx kubevirtContext) Stop(domainName string, force bool) error {
	logrus.Infof("PRAMOD Stop called for Domain: %s", domainName)
	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	kubeconfig := ctx.kubeConfig

	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return logError("domain %s failed to get vmlist", domainName)
	}
	if vmis.isPod {
		err := StopPodContainer(kubeconfig, vmis.name)
		return err
	} else {
		virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

		if err != nil {
			logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
			return err
		}

		// Stop the VM
		err = virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).Delete(context.Background(), vmis.name, &metav1.DeleteOptions{})
		if err != nil {
			fmt.Printf("Stop error %v\n", err)
			return err
		}
	}

	if _, ok := ctx.vmiList[domainName]; ok {
		delete(ctx.vmiList, domainName)
	}

	if _, ok := ctx.prevDomainMetric[domainName]; ok {
		delete(ctx.prevDomainMetric, domainName)
	}

	return nil
}

func (ctx kubevirtContext) Delete(domainName string) (result error) {
	logrus.Infof("PRAMOD Delete called for Domain: %s", domainName)
	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	kubeconfig := ctx.kubeConfig

	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return logError("delete domain %s failed to get vmlist", domainName)
	}
	if vmis.isPod {
		err := StopPodContainer(kubeconfig, vmis.name)
		return err
	} else {
		virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

		if err != nil {
			logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
			return err
		}

		// Stop the VM
		err = virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).Delete(context.Background(), vmis.name, &metav1.DeleteOptions{})

		// May be already deleted during Stop action, so its not an error if does not exist
		if errors.IsNotFound(err) {
			logrus.Infof("Domain already deleted: %v", domainName)
		} else {
			fmt.Printf("Delete error %v\n", err)
			return err
		}
	}

	// Delete the state dir
	if err := os.RemoveAll(kubevirtStateDir + domainName); err != nil {
		return logError("failed to clean up domain state directory %s (%v)", domainName, err)
	}

	if _, ok := ctx.vmiList[domainName]; ok {
		delete(ctx.vmiList, domainName)
	}

	if _, ok := ctx.prevDomainMetric[domainName]; ok {
		delete(ctx.prevDomainMetric, domainName)
	}

	return nil
}

func (ctx kubevirtContext) Info(domainName string) (int, types.SwState, error) {

	logrus.Infof("PRAMOD Info called for Domain: %s", domainName)

	var res string
	var err error
	err = getConfig(&ctx)
	if err != nil {
		return 0, types.BROKEN, err
	}
	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return 0, types.HALTED, logError("info domain %s failed to get vmlist", domainName)
	}
	if vmis.isPod {
		res, err = InfoPodContainer(ctx.kubeConfig, vmis.name)
	} else {
		res, err = getVMIStatus(vmis.name)
	}
	if err != nil {
		return 0, types.BROKEN, logError("domain %s failed to get info: %v", domainName, err)
	}

	if effectiveDomainState, matched := stateMap[res]; !matched {
		return 0, types.BROKEN, logError("domain %s reported to be in unexpected state %s", domainName, res)
	} else {
		if _, ok := ctx.vmiList[domainName]; !ok {
			return 0, types.HALTED, logError("domain %s is deleted", domainName)
		}
		return ctx.vmiList[domainName].domainId, effectiveDomainState, nil
	}
}

func (ctx kubevirtContext) Cleanup(domainName string) error {
	logrus.Infof("PRAMOD Cleanup called for Domain: %s", domainName)
	if err := ctx.ctrdContext.Cleanup(domainName); err != nil {
		return fmt.Errorf("couldn't cleanup task %s: %v", domainName, err)
	}

	var err error
	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return logError("cleanup domain %s failed to get vmlist", domainName)
	}
	if vmis.isPod {
	} else {
		err = waitForVMI(vmis.name, false)
	}
	if err != nil {
		return fmt.Errorf("waitforvmi failed  %s: %v", domainName, err)
	}

	return nil
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

func getVMIStatus(vmiName string) (string, error) {

	kubeconfig, err := kubeapi.GetKubeConfig()
	if err != nil {
		return "", logError("couldn't get the Kube Config: %v", err)
	}

	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

	if err != nil {
		return "", logError("couldn't get the Kube client Config: %v", err)
	}

	// Get the VMI info
	vmi, err := virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).Get(context.Background(), vmiName, &metav1.GetOptions{})

	if err != nil {
		return "", logError("domain %s failed to get VMI info %s", vmiName, err)
	}

	res := fmt.Sprintf("%v", vmi.Status.Phase)

	return res, nil
}

// Inspired from kvm.go
func waitForVMI(vmiName string, available bool) error {
	maxDelay := time.Second * 300 // 5mins ?? lets keep it for now
	delay := time.Second
	var waited time.Duration

	for {
		logrus.Infof("waitForVMI for %s %t: waiting for %v", vmiName, available, delay)
		if delay != 0 {
			time.Sleep(delay)
			waited += delay
		}

		state, err := getVMIStatus(vmiName)

		if err != nil {

			if available {
				logrus.Infof("waitForVMI for %s %t done, state %v, err %v", vmiName, available, state, err)
			} else {
				// Failed to get status, may be already deleted.
				logrus.Infof("waitForVMI for %s %t done, state %v, err %v", vmiName, available, state, err)
				return nil
			}
		} else {
			if state == "Running" && available {
				return nil
			}
		}

		if waited > maxDelay {
			// Give up
			logrus.Warnf("waitForVMIfor %s %t: giving up", vmiName, available)
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

func (ctx kubevirtContext) GetDomsCPUMem() (map[string]types.DomainMetric, error) {
	logrus.Debugf("GetDomsCPUMem: enter")

	res := make(map[string]types.DomainMetric, len(ctx.vmiList))
	virtIP, err := getVirtHandlerIPAddr(&ctx)
	if err != nil {
		logrus.Errorf("GetDomsCPUMem get virthandler ip error %v", err)
		return nil, err
	}

	url := "https://" + virtIP + ":8443/metrics"
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Perform the GET request
	resp, err := httpClient.Get(url)
	if err != nil {
		logrus.Errorf("GetDomsCPUMem http url %s, get error %v", url, err)
		ctx.virthandlerIPAddr = "" // next round get the IP again
		return nil, err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		logrus.Infof("GetDomsCPUMem: HTTP request failed with status code: %d", resp.StatusCode)
		ctx.virthandlerIPAddr = "" // next round get the IP again
		return nil, err
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Infof("GetDomsCPUMem: Error reading response body %v", err)
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		if (strings.HasPrefix(line, "kubevirt_vmi_cpu") ||
			strings.HasPrefix(line, "kubevirt_vmi_memory")) &&
			strings.Contains(line, kubeapi.EVEKubeNameSpace) {

			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				continue
			}

			metricStr := parts[0]
			metricValue := parts[1]

			metricStr2 := strings.SplitN(metricStr, "{", 2)
			if len(metricStr2) != 2 {
				continue
			}
			metricName := metricStr2[0]
			if _, excluded := excludedMetrics[metricName]; excluded {
				continue
			}

			vmiName := getVMIName(metricStr2[1])
			var parsedValue interface{}
			if strings.Contains(metricValue, ".") || strings.Contains(metricValue, "e+") {
				// Try parsing as float64
				value, err := strconv.ParseFloat(metricValue, 64)
				if err != nil {
					continue
				}
				parsedValue = value
			} else {
				// Try parsing as int
				value, err := strconv.Atoi(metricValue)
				if err != nil {
					continue
				}
				parsedValue = value
			}

			var domainName string
			for n, vmis := range ctx.vmiList {
				if vmis.name == vmiName {
					domainName = n
					if _, ok := res[domainName]; !ok {
						res[domainName] = types.DomainMetric{
							UUIDandVersion: types.UUIDandVersion{},
							CPUScaled:      1,
						}
					}
				}
			}
			fillMetrics(res, domainName, metricName, parsedValue)
			logrus.Debugf("GetDomsCPUMem: vmi %s, domainName %s, metric name %s, value %v", vmiName, domainName, metricName, parsedValue)
		}
	}

	for n, r := range res {
		if n == "" {
			continue
		}
		// used_bytes = available_bytes - usable_bytes
		r.UsedMemory = r.UsedMemory - r.AvailableMemory
		if r.AllocatedMB > 0 {
			per := float64(r.UsedMemory) / float64(r.AllocatedMB)
			r.UsedMemoryPercent = per
		}
		if r.UsedMemory > r.MaxUsedMemory {
			r.MaxUsedMemory = r.UsedMemory
		}
		if _, ok := ctx.prevDomainMetric[n]; !ok {
			r.MaxUsedMemory = r.UsedMemory
			ctx.prevDomainMetric[n] = r
		} else {
			if ctx.prevDomainMetric[n].MaxUsedMemory > r.UsedMemory {
				r.MaxUsedMemory = ctx.prevDomainMetric[n].MaxUsedMemory
			} else if ctx.prevDomainMetric[n].MaxUsedMemory < r.UsedMemory {
				r.MaxUsedMemory = r.UsedMemory
			}
			ctx.prevDomainMetric[n] = r
		}
		res[n] = r
	}

	hasEmptyRes := len(ctx.vmiList) - len(res)
	if hasEmptyRes > 0 {
		// check and get the kubernetes pod's metrics
		checkPodMetrics(ctx, res, hasEmptyRes)
	}
	logrus.Debugf("GetDomsCPUMem: %d VMs: %+v, podnum %d", len(ctx.vmiList), res, hasEmptyRes)
	return res, nil
}

func getVirtHandlerIPAddr(ctx *kubevirtContext) (string, error) {
	if ctx.virthandlerIPAddr != "" {
		return ctx.virthandlerIPAddr, nil
	}
	clientSet, err := kubeapi.GetClientSet()
	if err != nil {
		return "", err
	}

	pods, err := clientSet.CoreV1().Pods("kubevirt").List(context.Background(),
		metav1.ListOptions{
			LabelSelector: "kubevirt.io=virt-handler",
		})
	if err != nil {
		return "", err
	}

	var vmiPod *k8sv1.Pod
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.ObjectMeta.Name, "virt-handler-") {
			vmiPod = &pod
			break
		}
	}

	if vmiPod == nil {
		return "", fmt.Errorf("can not find virt-handler pod")
	}
	ctx.virthandlerIPAddr = vmiPod.Status.PodIP
	return ctx.virthandlerIPAddr, nil
}

func getVMIName(metricStr string) string {
	nameStr := strings.SplitN(metricStr, ",name=\"", 2)
	if len(nameStr) != 2 {
		fmt.Printf("get name failed, string %s\n", metricStr)
		return ""
	}
	nameStr2 := strings.SplitN(nameStr[1], "\",", 2)
	if len(nameStr2) != 2 {
		fmt.Printf("get name2 failed, string %s\n", metricStr)
		return ""
	}
	return nameStr2[0]
}

func fillMetrics(res map[string]types.DomainMetric, domainName, metricName string, value interface{}) {
	if _, ok := res[domainName]; !ok {
		logrus.Infof("fillMetrics, vmiName %s not in map", domainName)
		return
	}

	r := res[domainName]
	BytesInMegabyte := uint32(1024 * 1024)
	switch metricName {
	// add all the cpus to be Total, seconds should be from VM startup time
	case "kubevirt_vmi_cpu_system_usage_seconds":
	case "kubevirt_vmi_cpu_usage_seconds":
	case "kubevirt_vmi_cpu_user_usage_seconds":
		cpuNs := assignToInt64(value) * int64(time.Second)
		r.CPUTotalNs = r.CPUTotalNs + uint64(cpuNs)
	case "kubevirt_vmi_memory_usable_bytes":
		r.AvailableMemory = uint32(assignToInt64(value)) / BytesInMegabyte
	case "kubevirt_vmi_memory_domain_bytes_total":
		r.AllocatedMB = uint32(assignToInt64(value)) / BytesInMegabyte
	case "kubevirt_vmi_memory_available_bytes": // save this temp for later
		r.UsedMemory = uint32(assignToInt64(value)) / BytesInMegabyte
	//case "kubevirt_vmi_memory_resident_bytes":
	//	r.UsedMemory = uint32(assignToInt64(value)) / BytesInMegabyte
	default:
	}
	res[domainName] = r
}

func assignToInt64(parsedValue interface{}) int64 {
	var intValue int64

	// Assert the type and assign to the int64 variable
	if val, ok := parsedValue.(int); ok {
		intValue = int64(val)
	} else if val, ok := parsedValue.(float64); ok {
		intValue = int64(val)
	}

	return intValue
}

func (ctx kubevirtContext) CreatePodConfig(domainName string, config types.DomainConfig, status types.DomainStatus,
	diskStatusList []types.DiskStatus, aa *types.AssignableAdapters, file *os.File) error {

	kubeName := base.GetAppKubeName(config.DisplayName, config.UUIDandVersion.UUID)
	if config.KubeImageName == "" {
		err := fmt.Errorf("domain config kube image name empty")
		logrus.Errorf("CreateVMIConfig: %v", err)
		return err
	}
	ociName := config.KubeImageName

	var netSelections []netattdefv1.NetworkSelectionElement
	for _, vif := range config.VifList {
		netSelections = append(netSelections, netattdefv1.NetworkSelectionElement{
			Name:       kubeapi.NetworkInstanceNAD,
			MacRequest: vif.Mac.String(),
		})
	}

	// Add Direct Attach Ethernet Port
	for _, io := range config.IoAdapterList {
		if io.Type == types.IoNetEth {
			// even if ioAdapter does not exist, kubernetes will retry
			netSelections = append(netSelections, netattdefv1.NetworkSelectionElement{
				// TODO: Add method for generating NAD name of direct attach to pkg/kubeapi
				Name: "host-" + io.Name,
			})
		}
	}

	var annotations map[string]string
	if len(netSelections) > 0 {
		annotations = map[string]string{
			"k8s.v1.cni.cncf.io/networks": encodeSelections(netSelections),
		}
		logrus.Infof("CreatePodConfig: annotations %+v", annotations)
	} else {
		err := fmt.Errorf("CreatePodConfig: no network selections, exit")
		return err
	}

	vcpus := strconv.Itoa(config.VCpus*1000) + "m"
	// FixedResources.Memory is in Kbytes
	memoryLimit := strconv.Itoa(config.Memory * 1000)
	memoryRequest := strconv.Itoa(config.Memory * 1000)

	pod := &k8sv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        kubeName,
			Namespace:   kubeapi.EVEKubeNameSpace,
			Annotations: annotations,
		},
		Spec: k8sv1.PodSpec{
			Containers: []k8sv1.Container{
				{
					Name:            kubeName,
					Image:           ociName,
					ImagePullPolicy: k8sv1.PullNever,
					SecurityContext: &k8sv1.SecurityContext{
						Privileged: &[]bool{true}[0],
					},
					Resources: k8sv1.ResourceRequirements{
						Limits: k8sv1.ResourceList{
							k8sv1.ResourceCPU:    resource.MustParse(vcpus),
							k8sv1.ResourceMemory: resource.MustParse(memoryLimit),
						},
						Requests: k8sv1.ResourceList{
							k8sv1.ResourceCPU:    resource.MustParse(vcpus),
							k8sv1.ResourceMemory: resource.MustParse(memoryRequest),
						},
					},
				},
			},
			DNSConfig: &k8sv1.PodDNSConfig{
				Nameservers: []string{"8.8.8.8", "1.1.1.1"}, // XXX, temp, Add your desired DNS servers here
			},
		},
	}
	pod.Labels = make(map[string]string)
	pod.Labels[eveLableKey] = domainName
	logrus.Infof("CreatePodConfig: pod setup %+v", pod)

	// Now we have VirtualMachine Instance object, save it to config file for debug purposes
	// and save it in context which will be used to start VM in Start() call
	meta := vmiMetaData{
		pod:      pod,
		isPod:    true,
		name:     kubeName,
		domainId: int(rand.Uint32()),
	}
	ctx.vmiList[domainName] = &meta

	podStr := fmt.Sprintf("%+v", pod)

	// write to config file
	file.WriteString(podStr)

	return nil
}

func encodeSelections(selections []netattdefv1.NetworkSelectionElement) string {
	bytes, err := json.Marshal(selections)
	if err != nil {
		logrus.Errorf("encodeSelections %v", err)
		return ""
	}
	return string(bytes)
}

func StartPodContiner(kubeconfig *rest.Config, pod *k8sv1.Pod) error {

	clientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("StartPodContiner: can't get clientset %v", err)
		return err
	}

	opStr := "created"
	_, err = clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			// TODO: update
			logrus.Errorf("StartPodContiner: pod create filed: %v", err)
			return err
		} else {
			opStr = "already exists"
		}
	}

	logrus.Infof("StartPodContiner: Pod %s %s with nad %+v", pod.ObjectMeta.Name, opStr, pod.Annotations)

	err = checkForPod(kubeconfig, pod.ObjectMeta.Name)
	if err != nil {
		logrus.Errorf("StartPodContiner: check for pod status error %v", err)
		return err
	}
	logrus.Infof("StartPodContiner: Pod %s running", pod.ObjectMeta.Name)
	return nil
}

func checkForPod(kubeconfig *rest.Config, podName string) error {
	var i int
	var status string
	var err error
	for {
		i++
		logrus.Infof("checkForPod: check(%d) wait 15 sec, %v", i, podName)
		time.Sleep(15 * time.Second)

		status, err = InfoPodContainer(kubeconfig, podName)
		if err != nil {
			logrus.Infof("checkForPod: podName %s, %v", podName, err)
		} else {
			if status == "Running" {
				return nil
			} else {
				logrus.Errorf("checkForPod: get podName info status %v (not running)", status)
			}
		}
		if i > 5 {
			break
		}
	}

	return fmt.Errorf("checkForPod: timed out, statuus %s, err %v", status, err)
}

func StopPodContainer(kubeconfig *rest.Config, podName string) error {

	clientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("StopPodContainer: can't get clientset %v", err)
		return err
	}

	err = clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
	if err != nil {
		// Handle error
		logrus.Errorf("StopPodContainer: deleting pod: %v", err)
		return err
	}

	logrus.Infof("StopPodContainer: Pod %s deleted", podName)
	return nil
}

func InfoPodContainer(kubeconfig *rest.Config, podName string) (string, error) {

	podclientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return "", logError("InfoPodContainer: couldn't get the pod Config: %v", err)
	}

	pod, err := podclientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return "", logError("InfoPodContainer: couldn't get the pod: %v", err)
	}

	var res string
	// https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/
	switch pod.Status.Phase {
	case k8sv1.PodPending:
		res = "Pending"
	case k8sv1.PodRunning:
		res = "Running"
	case k8sv1.PodSucceeded:
		res = "Running"
	case k8sv1.PodFailed:
		res = "Failed"
	case k8sv1.PodUnknown:
		res = "Scheduling"
	default:
		res = "Scheduling"
	}
	logrus.Infof("InfoPodContainer: pod %s, status %s", podName, res)

	return res, nil
}

func checkPodMetrics(ctx kubevirtContext, res map[string]types.DomainMetric, emptySlot int) {

	err := getConfig(&ctx)
	if err != nil {
		return
	}
	kubeconfig := ctx.kubeConfig
	podclientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("checkPodMetrics: can not get pod client %v", err)
		return
	}

	clientset, err := metricsv.NewForConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("checkPodMetrics: can't get clientset %v", err)
		return
	}

	count := 0
	for n, vmis := range ctx.vmiList {
		if !vmis.isPod {
			continue
		}
		count++
		podName := vmis.name
		pod, err := podclientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			logrus.Errorf("checkPodMetrics: can't get pod %v", err)
			continue
		}
		memoryLimits := pod.Spec.Containers[0].Resources.Limits.Memory()

		metrics, err := clientset.MetricsV1beta1().PodMetricses(kubeapi.EVEKubeNameSpace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			logrus.Errorf("checkPodMetrics: get pod metrics error %v", err)
			continue
		}

		cpuTotalNs := metrics.Containers[0].Usage[k8sv1.ResourceCPU]
		cpuTotalNsAsFloat64 := cpuTotalNs.AsApproximateFloat64() * float64(time.Second) // get nanoseconds
		totalCpu := uint64(cpuTotalNsAsFloat64)

		//allocatedMemory := metrics.Containers[0].Usage[k8sv1.ResourceMemory]
		usedMemory := metrics.Containers[0].Usage[k8sv1.ResourceMemory]
		maxMemory := uint32(usedMemory.Value())
		if vmis.maxmem < maxMemory {
			vmis.maxmem = maxMemory
		} else {
			maxMemory = vmis.maxmem
		}

		available := uint32(memoryLimits.Value())
		if uint32(usedMemory.Value()) < available {
			available = available - uint32(usedMemory.Value())
		}
		usedMemoryPercent := calculateMemoryUsagePercent(usedMemory.Value(), memoryLimits.Value())
		BytesInMegabyte := uint32(1024 * 1024)

		realCPUTotal := vmis.cputotal + totalCpu
		vmis.cputotal = realCPUTotal
		dm := types.DomainMetric{
			CPUTotalNs:        realCPUTotal,
			CPUScaled:         1,
			AllocatedMB:       uint32(memoryLimits.Value()) / BytesInMegabyte,
			UsedMemory:        uint32(usedMemory.Value()) / BytesInMegabyte,
			MaxUsedMemory:     maxMemory / BytesInMegabyte,
			AvailableMemory:   available / BytesInMegabyte,
			UsedMemoryPercent: usedMemoryPercent,
		}
		if count <= emptySlot {
			res[n] = dm
		}
		logrus.Infof("checkPodMetrics: dm %+v, res %v", dm, res)

		ctx.vmiList[n] = vmis // update for the last seen metrics
	}
}

// Helper function to calculate the memory usage percentage
func calculateMemoryUsagePercent(usedMemory, allocatedMemory int64) float64 {
	if allocatedMemory > 0 {
		return float64(usedMemory) / float64(allocatedMemory) * 100.0
	}
	return 0.0
}

func getConfig(ctx *kubevirtContext) error {
	if ctx.kubeConfig == nil {
		kubeconfig, err := kubeapi.GetKubeConfig()
		if err != nil {
			logrus.Error("getConfig: can not get kubeconfig")
			return err
		}
		ctx.kubeConfig = kubeconfig
	}
	return nil
}

// Register the host device with Kubevirt
// Refer https://kubevirt.io/user-guide/virtual_machines/host-devices/#host-preparation-for-pci-passthrough
// Refer https://kubevirt.io/user-guide/virtual_machines/host-devices/#usb-host-passthrough
func registerWithKV(kvClient kubecli.KubevirtClient, vmi *v1.VirtualMachineInstance, pciAssignments []pciDevice) error {

	logrus.Infof("PRAMOD entered registerWithKV  pcilen %d ", len(pciAssignments))
	pcidevices := make([]v1.HostDevice, len(pciAssignments))

	// Define the KubeVirt resource's name and namespace
	kubeVirtName := "kubevirt"
	kubeVirtNamespace := "kubevirt"

	// Retrieve the KubeVirt resource
	kubeVirt, err := kvClient.KubeVirt(kubeVirtNamespace).Get(kubeVirtName, &metav1.GetOptions{})
	if err != nil {
		return logError("can't fetch the PCI device info from kubevirt %v", err)
	}

	// Get the currently registered  devices from Kubevirt
	pciHostDevs := kubeVirt.Spec.Configuration.PermittedHostDevices.PciHostDevices

	for i, pa := range pciAssignments {

		vendor, err := pa.vid()
		if err != nil {
			return logError("can't fetch the vendor id for pci device %v", err)
		}
		// Delete 0x prefix it exists, kubevirt does not like it
		if strings.HasPrefix(vendor, "0x") {
			vendor = vendor[2:]
		}
		devid, err := pa.devid()
		if err != nil {
			return logError("can't fetch the device id for pci device %v", err)
		}
		if strings.HasPrefix(devid, "0x") {
			devid = devid[2:]
		}
		pciVendorSelector := vendor + ":" + devid

		// Check if we already registered this device with kubevirt. If not register with kubevirt
		registered := isRegisteredPciHostDevice(pciVendorSelector, pciHostDevs)
		resname := "devices.kubevirt.io/hostdevice" + strconv.Itoa(i+1)
		if !registered {

			newpcidev := v1.PciHostDevice{
				ResourceName:      resname,
				PCIVendorSelector: pciVendorSelector,
			}
			logrus.Infof("Registering PCI device %s as resource %s with kubevirt", pciVendorSelector, resname)
			kubeVirt.Spec.Configuration.PermittedHostDevices.PciHostDevices = append(kubeVirt.Spec.Configuration.PermittedHostDevices.PciHostDevices, newpcidev)
			_, err = kvClient.KubeVirt(kubeVirtNamespace).Update(kubeVirt)

			if err != nil {
				return logError("can't update the PCI device info from kubevirt %v", err)
			}
		}
		// At this point we have registered the PCI device with kubevirt
		// Create HostDevice array which will be inserted into vmi Hostdevices
		// Hostdevices could be NVMe drives,USB or NICs, that is reason if just call them device.

		pcidevices[i] = v1.HostDevice{
			DeviceName: resname,
			Name:       "device" + strconv.Itoa(i+1),
		}

		vmi.Spec.Domain.Devices.HostDevices = append(vmi.Spec.Domain.Devices.HostDevices, pcidevices[i])
	}

	return nil

}

func isRegisteredPciHostDevice(pciVendorSelector string, PciHostDevices []v1.PciHostDevice) bool {

	for _, dev := range PciHostDevices {

		if dev.PCIVendorSelector == pciVendorSelector {
			return true
		}
	}

	return false
}

func addKernelBootContainer(spec *v1.VirtualMachineInstanceSpec, image, kernelArgs, kernelPath, initrdPath string) *v1.VirtualMachineInstanceSpec {
	if spec.Domain.Firmware == nil {
		spec.Domain.Firmware = &v1.Firmware{}
	}

	spec.Domain.Firmware.KernelBoot = &v1.KernelBoot{
		KernelArgs: kernelArgs,
		Container: &v1.KernelBootContainer{
			Image:           image,
			KernelPath:      kernelPath,
			InitrdPath:      initrdPath,
			ImagePullPolicy: k8sv1.PullNever,
		},
	}

	return spec
}

// PCIReserve reserves a PCI device for Kubevirt
func (ctx kubevirtContext) PCIReserve(long string) error {
	logrus.Infof("PCIReserve long addr is %s", long)

	overrideFile := filepath.Join(sysfsPciDevices, long, "driver_override")
	driverPath := filepath.Join(sysfsPciDevices, long, "driver")
	unbindFile := filepath.Join(driverPath, "unbind")

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

// PCIRelease releases the PCI device reservation
func (ctx kubevirtContext) PCIRelease(long string) error {
	logrus.Infof("PCIRelease long addr is %s", long)

	overrideFile := filepath.Join(sysfsPciDevices, long, "driver_override")
	unbindFile := filepath.Join(sysfsPciDevices, long, "driver/unbind")

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

// PCISameController checks if two PCI controllers are the same
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
