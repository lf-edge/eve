// Copyright (c) 2024 Zededa, Inc.
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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
	"k8s.io/utils/pointer"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

// KubevirtHypervisorName is a name of kubevirt hypervisor
const (
	KubevirtHypervisorName = "kubevirt"
	kubevirtStateDir       = "/run/hypervisor/kubevirt/"
	eveLabelKey            = "App-Domain-Name"
	waitForPodCheckCounter = 5  // Check 5 times
	waitForPodCheckTime    = 15 // Check every 15 seconds, don't wait for too long to cause watchdog
	tolerateSec            = 15 // Pod/VMI reschedule delay after node unreachable seconds
	unknownToHaltMinutes   = 5  // If VMI is unknown for 5 minutes, return halt state
)

// MetaDataType is a type for different Domain types
// We only support ReplicaSet for VMI and Pod for now.
type MetaDataType int

// Constants representing different resource types.
const (
	IsMetaVmi MetaDataType = iota
	IsMetaPod
	IsMetaReplicaVMI
	IsMetaReplicaPod
)

// VM instance meta data structure.
type vmiMetaData struct {
	repPod           *appsv1.ReplicaSet                   // Handle to the replicaSetof pod
	repVMI           *v1.VirtualMachineInstanceReplicaSet // Handle to the replicaSet of VMI
	domainID         int                                  // DomainID understood by domainmgr in EVE
	mtype            MetaDataType                         // switch on is ReplicaSet, Pod or is VMI
	name             string                               // Display-Name(all lower case) + first 5 bytes of domainName
	cputotal         uint64                               // total CPU in NS so far
	maxmem           uint32                               // total Max memory usage in bytes so far
	startUnknownTime time.Time                            // time when the domain returned as unknown status
}

type kubevirtContext struct {
	ctrdContext
	devicemodel       string
	capabilities      *types.Capabilities
	vmiList           map[string]*vmiMetaData
	virthandlerIPAddr string
	prevDomainMetric  map[string]types.DomainMetric
	kubeConfig        *rest.Config
	nodeNameMap       map[string]string // to pass nodeName between methods without pointer receiver
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
	"Halting":    types.HALTING,
	"Succeeded":  types.SCHEDULING,
	"Unknown":    types.UNKNOWN,
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

type kubevirtMetrics map[string]types.DomainMetric

func (metrics *kubevirtMetrics) fill(domainName, metricName string, value interface{}) {
	r, ok := (*metrics)[domainName]
	if !ok {
		// Index is not valid
		return
	}

	BytesInMegabyte := int64(1024 * 1024)
	switch metricName {
	// add all the cpus to be Total, seconds should be from VM startup time
	case "kubevirt_vmi_cpu_system_usage_seconds":
	case "kubevirt_vmi_cpu_usage_seconds":
	case "kubevirt_vmi_cpu_user_usage_seconds":
		cpuNs := assignToInt64(value) * int64(time.Second)
		r.CPUTotalNs = r.CPUTotalNs + uint64(cpuNs)
	case "kubevirt_vmi_memory_usable_bytes":
		// The amount of memory which can be reclaimed by balloon without pushing the guest system to swap,
		// corresponds to ‘Available’ in /proc/meminfo
		// https://kubevirt.io/monitoring/metrics.html#kubevirt
		r.AvailableMemory = uint32(assignToInt64(value) / BytesInMegabyte)
	case "kubevirt_vmi_memory_domain_bytes":
		// The amount of memory in bytes allocated to the domain.
		// https://kubevirt.io/monitoring/metrics.html#kubevirt
		r.AllocatedMB = uint32(assignToInt64(value) / BytesInMegabyte)
	case "kubevirt_vmi_memory_available_bytes": // save this temp for later
		// Amount of usable memory as seen by the domain.
		// https://kubevirt.io/monitoring/metrics.html#kubevirt
		r.UsedMemory = uint32(assignToInt64(value) / BytesInMegabyte)
	default:
	}
	(*metrics)[domainName] = r
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
			nodeNameMap:      make(map[string]string),
		}
	case "amd64":
		return kubevirtContext{
			ctrdContext:      *ctrdCtx,
			devicemodel:      "pc-q35-3.1",
			vmiList:          make(map[string]*vmiMetaData),
			prevDomainMetric: make(map[string]types.DomainMetric),
			nodeNameMap:      make(map[string]string),
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
	return ctx
}

// Use eve DomainConfig and DomainStatus and generate k3s VMI config or a Pod config
func (ctx kubevirtContext) Setup(status types.DomainStatus, config types.DomainConfig,
	aa *types.AssignableAdapters, globalConfig *types.ConfigItemValueMap, file *os.File) error {

	diskStatusList := status.DiskStatusList
	domainName := status.DomainName

	logrus.Debugf("Setup called for Domain: %s, vmmode %v", domainName, config.VirtualizationMode)

	if config.EnforceNetworkInterfaceOrder {
		logrus.Errorf("Enforcing user-defined network interface order is not supported "+
			"with the KubeVirt hypervisor. Ignoring EnforceNetworkInterfaceOrder flag "+
			"for app %s", config.DisplayName)
	}

	saveMyNodeUUID(&ctx, status.NodeName)

	if config.VirtualizationMode == types.NOHYPER {
		if err := ctx.CreateReplicaPodConfig(domainName, config, status, diskStatusList, aa, file); err != nil {
			return logError("failed to build kube replicaset config: %v", err)
		}
	} else {
		// Take eve domain config and convert to VMI Replicaset config
		if err := ctx.CreateReplicaVMIConfig(domainName, config, status, diskStatusList, aa, file); err != nil {
			return logError("failed to build kube config: %v", err)
		}
	}

	return os.MkdirAll(kubevirtStateDir+domainName, 0644)

}

// Kubevirt VMI ReplicaSet config spec is updated with the domain config/status of the app.
// The details and the struct of the spec can be found at:
// https://kubevirt.io/api-reference/v1.0.0/definitions.html
func (ctx kubevirtContext) CreateReplicaVMIConfig(domainName string, config types.DomainConfig, status types.DomainStatus,
	diskStatusList []types.DiskStatus, aa *types.AssignableAdapters, file *os.File) error {
	logrus.Debugf("CreateReplicaVMIConfig called for Domain: %s", domainName)

	err := getConfig(&ctx)
	if err != nil {
		return err
	}

	kvClient, err := kubecli.GetKubevirtClientFromRESTConfig(ctx.kubeConfig)
	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return err
	}

	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		return logError("Failed to get nodeName")
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
	m, err := resource.ParseQuantity(convertToKubernetesFormat(config.Memory * 1024))
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
	intfs := make([]v1.Interface, len(netSelections))
	nads := make([]v1.Network, len(netSelections))

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
				// Since disks are virtio disks we assume /dev/vda is the boot disk
				kernelArgs := "console=tty0 root=/dev/vda dhcp=1 rootfstype=ext4"
				eveRelease, err := os.ReadFile("/run/eve-release")
				if err != nil {
					return logError("Failed to fetch eve-release %v", err)
				}
				tag := strings.TrimRight(string(eveRelease), "\n")
				scratchImage := "docker.io/lfedge/eve-external-boot-image:" + tag
				kernelPath := "/kernel"
				initrdPath := "/runx-initrd"

				addKernelBootContainer(&vmi.Spec, scratchImage, kernelArgs, kernelPath, initrdPath)

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
				tap := pciDevice{ioBundle: *ib}
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

	// Set the affinity to this node the VMI is preferred to run on
	affinity := setKubeAffinity(nodeName)

	// Set tolerations to handle node conditions
	tolerations := setKubeToleration(int64(tolerateSec))

	vmi.Spec.Affinity = affinity
	vmi.Spec.Tolerations = tolerations
	vmi.Labels = make(map[string]string)
	vmi.Labels[eveLabelKey] = domainName

	// Create a VirtualMachineInstanceReplicaSet
	replicaSet := &v1.VirtualMachineInstanceReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kubeName,
			Namespace: kubeapi.EVEKubeNameSpace,
		},
		Spec: v1.VirtualMachineInstanceReplicaSetSpec{
			Replicas: pointer.Int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					eveLabelKey: domainName,
				},
			},
			Template: &v1.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						eveLabelKey: domainName,
					},
				},
				Spec: vmi.Spec,
			},
		},
	}

	logrus.Infof("CreateReplicaVMIConfig: VirtualMachineInstanceReplicaSet: %+v", replicaSet)

	// Now we have VirtualMachine Instance object, save it to config file for debug purposes
	// and save it in context which will be used to start VM in Start() call
	// dispName is for vmi name/handle on kubernetes
	meta := vmiMetaData{
		repVMI:   replicaSet,
		name:     kubeName,
		mtype:    IsMetaReplicaVMI,
		domainID: int(rand.Uint32()),
	}
	ctx.vmiList[domainName] = &meta

	repvmiStr := fmt.Sprintf("%+v", replicaSet)

	// write to config file
	file.WriteString(repvmiStr)

	return nil
}

func (ctx kubevirtContext) Start(domainName string) error {
	logrus.Debugf("Starting Kubevirt domain %s", domainName)

	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		return logError("Failed to get nodeName")
	}

	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	kubeconfig := ctx.kubeConfig

	logrus.Infof("Starting Kubevirt domain %s, devicename nodename %d", domainName, len(ctx.nodeNameMap))
	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return logError("start domain %s failed to get vmlist", domainName)
	}

	// Start the Pod ReplicaSet
	if vmis.mtype == IsMetaReplicaPod {
		err := StartReplicaPodContiner(ctx, vmis)
		return err
	} else if vmis.mtype != IsMetaReplicaVMI {
		return logError("Start domain %s wrong type", domainName)
	}

	// Start the VMI ReplicaSet
	repvmi := vmis.repVMI
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return err
	}

	// Create the VMI ReplicaSet
	i := 5
	for {
		_, err = virtClient.ReplicaSet(kubeapi.EVEKubeNameSpace).Create(repvmi)
		if err != nil {
			if errors.IsAlreadyExists(err) {
				// VMI could have been already started, for example failover from other node.
				// Its not an error, just proceed.
				logrus.Warnf("VMI replicaset %v already exists", repvmi)
				break
			}
			if strings.Contains(err.Error(), "dial tcp 127.0.0.1:6443") && i <= 0 {
				logrus.Errorf("Start VMI replicaset failed %v\n", err)
				return err
			}
			time.Sleep(10 * time.Second)
			logrus.Errorf("Start VMI replicaset failed, retry (%d) err %v", i, err)
		} else {
			break
		}
		i = i - 1
	}
	logrus.Infof("Started Kubevirt domain replicaset %s, VMI replicaset %s", domainName, vmis.name)

	err = waitForVMI(vmis, nodeName, true)
	if err != nil {
		logrus.Errorf("couldn't start VMI %v", err)
		return err
	}

	return nil
}

// Create is no-op for kubevirt, just return the domainID we already have.
func (ctx kubevirtContext) Create(domainName string, cfgFilename string, config *types.DomainConfig) (int, error) {
	return ctx.vmiList[domainName].domainID, nil
}

// There is no such thing as stop VMI, so delete it.
func (ctx kubevirtContext) Stop(domainName string, force bool) error {
	logrus.Debugf("Stop called for Domain: %s", domainName)
	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	kubeconfig := ctx.kubeConfig

	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return logError("domain %s failed to get vmlist", domainName)
	}
	if vmis.mtype == IsMetaReplicaPod {
		err = StopReplicaPodContainer(kubeconfig, vmis.name)
	} else if vmis.mtype == IsMetaReplicaVMI {
		err = StopReplicaVMI(kubeconfig, vmis.name)
	} else {
		return logError("Stop domain %s wrong type", domainName)
	}

	if err != nil {
		return err
	}

	delete(ctx.vmiList, domainName)

	delete(ctx.prevDomainMetric, domainName)

	return nil
}

func (ctx kubevirtContext) Delete(domainName string) (result error) {
	logrus.Debugf("Delete called for Domain: %s", domainName)
	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	kubeconfig := ctx.kubeConfig

	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return logError("delete domain %s failed to get vmlist", domainName)
	}
	if vmis.mtype == IsMetaReplicaPod {
		err = StopReplicaPodContainer(kubeconfig, vmis.name)
	} else if vmis.mtype == IsMetaReplicaVMI {
		err = StopReplicaVMI(kubeconfig, vmis.name)
	} else {
		return logError("delete domain %s wrong type", domainName)
	}

	if err != nil {
		return err
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

// StopReplicaVMI stops the VMI ReplicaSet
func StopReplicaVMI(kubeconfig *rest.Config, repVmiName string) error {
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return err
	}

	// Stop the VMI ReplicaSet
	err = virtClient.ReplicaSet(kubeapi.EVEKubeNameSpace).Delete(repVmiName, &metav1.DeleteOptions{})
	if errors.IsNotFound(err) {
		logrus.Infof("Stop VMI Replicaset, Domain already deleted: %v", repVmiName)
	} else {
		logrus.Errorf("Stop VMI Replicaset error %v\n", err)
		return err
	}

	return nil
}

func (ctx kubevirtContext) Info(domainName string) (int, types.SwState, error) {

	logrus.Debugf("Info called for Domain: %s", domainName)
	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		return 0, types.BROKEN, logError("Failed to get nodeName")
	}

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
	if vmis.mtype == IsMetaReplicaPod {
		res, err = InfoReplicaSetContainer(ctx, vmis)
	} else {
		res, err = getVMIStatus(vmis, nodeName)
	}
	if err != nil {
		return 0, types.BROKEN, logError("domain %s failed to get info: %v", domainName, err)
	}

	if effectiveDomainState, matched := stateMap[res]; !matched {
		// Received undefined state in our map, return UNKNOWN instead
		retStatus, err := checkAndReturnStatus(vmis, true)
		logrus.Infof("domain %s reported to be in unexpected state %s", domainName, res)
		effectiveDomainState = types.HALTING
		if retStatus == "Unknown" {
			effectiveDomainState = types.UNKNOWN
		}
		return ctx.vmiList[domainName].domainID, effectiveDomainState, err
	} else {
		if _, ok := ctx.vmiList[domainName]; !ok { // domain is deleted
			return 0, types.HALTED, logError("domain %s is deleted", domainName)
		}
		return ctx.vmiList[domainName].domainID, effectiveDomainState, err
	}
}

func (ctx kubevirtContext) Cleanup(domainName string) error {
	logrus.Debugf("Cleanup called for Domain: %s", domainName)
	if err := ctx.ctrdContext.Cleanup(domainName); err != nil {
		return fmt.Errorf("couldn't cleanup task %s: %v", domainName, err)
	}
	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		return logError("Cleanup: Failed to get nodeName")
	}

	var err error
	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return logError("cleanup domain %s failed to get vmlist", domainName)
	}
	if vmis.mtype == IsMetaReplicaPod {
		_, err = InfoReplicaSetContainer(ctx, vmis)
		if err == nil {
			err = ctx.Delete(domainName)
		}
	} else if vmis.mtype == IsMetaReplicaVMI {
		err = waitForVMI(vmis, nodeName, false)
	} else {
		err = logError("cleanup domain %s wrong type", domainName)
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

func getVMIStatus(vmis *vmiMetaData, nodeName string) (string, error) {

	repVmiName := vmis.name
	kubeconfig, err := kubeapi.GetKubeConfig()
	if err != nil {
		return "", logError("couldn't get the Kube Config: %v", err)
	}

	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)

	if err != nil {
		return "", logError("couldn't get the Kube client Config: %v", err)
	}

	// List VMIs with a label selector that matches the replicaset name
	vmiList, err := virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).List(context.Background(), &metav1.ListOptions{})
	if err != nil {
		retStatus, err2 := checkAndReturnStatus(vmis, true)
		logError("getVMIStatus: domain %s failed to get VMI info %s, return %s", repVmiName, err, retStatus)
		return retStatus, err2
	}
	if len(vmiList.Items) == 0 {
		retStatus, err2 := checkAndReturnStatus(vmis, true)
		logError("getVMIStatus: No VMI found with the given replicaset name %s, return %s", repVmiName, retStatus)
		return retStatus, err2
	}

	// Use the first VMI in the list
	var nonLocalStatus string
	var targetVMI *v1.VirtualMachineInstance
	for _, vmi := range vmiList.Items {
		if vmi.Status.NodeName == nodeName {
			if vmi.GenerateName == repVmiName {
				targetVMI = &vmi
				break
			}
		} else {
			if vmi.GenerateName == repVmiName {
				nonLocalStatus = fmt.Sprintf("%v", vmi.Status.Phase)
			}
		}
	}
	if targetVMI == nil {
		if nonLocalStatus != "" {
			_, _ = checkAndReturnStatus(vmis, false) // reset the unknown timestamp
			return nonLocalStatus, nil
		}
		retStatus, err2 := checkAndReturnStatus(vmis, true)
		logError("getVMIStatus: No VMI %s found with the given nodeName %s, return %s", repVmiName, nodeName, retStatus)
		return retStatus, err2
	}
	res := fmt.Sprintf("%v", targetVMI.Status.Phase)
	_, _ = checkAndReturnStatus(vmis, false) // reset the unknown timestamp
	return res, nil
}

// Inspired from kvm.go
func waitForVMI(vmis *vmiMetaData, nodeName string, available bool) error {
	vmiName := vmis.name
	maxDelay := time.Minute * 5 // 5mins ?? lets keep it for now
	delay := time.Second
	var waited time.Duration

	for {
		logrus.Infof("waitForVMI for %s %t: waiting for %v", vmiName, available, delay)
		if delay != 0 {
			time.Sleep(delay)
			waited += delay
		}

		state, err := getVMIStatus(vmis, nodeName)
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

	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		return nil, nil
	}
	res := make(kubevirtMetrics, len(ctx.vmiList))
	virtIP, err := getVirtHandlerIPAddr(&ctx, nodeName)
	if err != nil {
		logrus.Debugf("GetDomsCPUMem get virthandler ip error %v", err)
		return nil, err
	}

	url := "https://" + virtIP + ":8443/metrics"
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
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

	// It seems the virt-handler metrics only container the VMIs running on this node
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
				if strings.HasPrefix(vmiName, vmis.name) { // handle the VMI ReplicaSet
					domainName = n
					if _, ok := res[domainName]; !ok {
						res[domainName] = types.DomainMetric{
							UUIDandVersion: types.UUIDandVersion{},
							CPUScaled:      1,
						}
					}
				}
			}
			res.fill(domainName, metricName, parsedValue)
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
	checkReplicaPodMetrics(ctx, res, hasEmptyRes)

	logrus.Debugf("GetDomsCPUMem: %d VMs: %+v, podnum %d", len(ctx.vmiList), res, hasEmptyRes)
	return res, nil
}

func getVirtHandlerIPAddr(ctx *kubevirtContext, nodeName string) (string, error) {
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
		if nodeName != pod.Spec.NodeName {
			continue
		}
		if strings.HasPrefix(pod.ObjectMeta.Name, "virt-handler-") {
			vmiPod = &pod
			break
		}
	}

	if vmiPod == nil {
		return "", fmt.Errorf("getVirtHandlerIPAddr: can not find virt-handler pod")
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

func (ctx kubevirtContext) CreateReplicaPodConfig(domainName string, config types.DomainConfig, status types.DomainStatus,
	diskStatusList []types.DiskStatus, aa *types.AssignableAdapters, file *os.File) error {

	kubeName := base.GetAppKubeName(config.DisplayName, config.UUIDandVersion.UUID)
	if config.KubeImageName == "" {
		err := fmt.Errorf("domain config kube image name empty")
		logrus.Errorf("CreateReplicaPodConfig: %v", err)
		return err
	}
	ociName := config.KubeImageName

	logrus.Infof("CreateReplicaPodConfig: domainName %s, kubeName %s, nodeName %d", domainName, kubeName, len(ctx.nodeNameMap))
	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		return logError("Failed to get nodeName")
	}

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
			nadName := "host-" + io.Name
			// even if ioAdapter does not exist, kubernetes will retry
			netSelections = append(netSelections, netattdefv1.NetworkSelectionElement{
				Name: nadName,
			})

			// Check if the NAD is created in the cluster, return error if not
			err := kubeapi.CheckEtherPassThroughNAD(nadName)
			if err != nil {
				logrus.Errorf("CreateReplicaPodConfig: check ether NAD failed, %v", err)
				return err
			}
		}
	}

	var annotations map[string]string
	if len(netSelections) > 0 {
		annotations = map[string]string{
			"k8s.v1.cni.cncf.io/networks": encodeSelections(netSelections),
		}
		logrus.Infof("CreateReplicaPodConfig: annotations %+v", annotations)
	} else {
		err := fmt.Errorf("CreateReplicaPodConfig: no network selections, exit")
		return err
	}

	//vcpus := strconv.Itoa(config.VCpus*1000) + "m"
	// FixedResources.Memory is in Kbytes
	//memoryLimit := "100Mi" // convertToKubernetesFormat(config.Memory * 1000)
	//memoryRequest := memoryLimit

	var replicaNum int32
	replicaNum = 1
	repNum := &replicaNum
	replicaSet := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kubeName,
			Namespace: kubeapi.EVEKubeNameSpace,
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: repNum,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": kubeName,
				},
			},
			Template: k8sv1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": kubeName,
					},
					Annotations: annotations,
				},
				Spec: k8sv1.PodSpec{
					Tolerations: setKubeToleration(int64(tolerateSec)),
					Affinity:    setKubeAffinity(nodeName),
					Containers: []k8sv1.Container{
						{
							Name:            kubeName,
							Image:           ociName,
							ImagePullPolicy: k8sv1.PullNever,
							SecurityContext: &k8sv1.SecurityContext{
								Privileged: &[]bool{true}[0],
							},
						},
					},
					RestartPolicy: k8sv1.RestartPolicyAlways,
					DNSConfig: &k8sv1.PodDNSConfig{
						Nameservers: []string{"8.8.8.8", "1.1.1.1"}, // XXX, temp, Add your desired DNS servers here
					},
				},
			},
		},
	}
	logrus.Infof("CreateReplicaPodConfig: replicaset %+v", replicaSet)

	// Add pod non-image volume disks
	if len(diskStatusList) > 1 {
		logrus.Infof("CreateReplicaPodConfig: diskStatusList:%v", diskStatusList)

		var volumes []k8sv1.Volume
		var mounts []k8sv1.VolumeMount
		var devs []k8sv1.VolumeDevice

		for _, ds := range diskStatusList[1:] {
			if ds.Devtype == "9P" { // skip 9P volume type
				continue
			}

			voldispName := strings.ToLower("vol-" + ds.FileLocation)

			if ds.MountDir == "" {
				devs = append(devs, k8sv1.VolumeDevice{
					Name:       voldispName,
					DevicePath: "/dev/" + ds.Vdev,
				})
			} else {
				mounts = append(mounts, k8sv1.VolumeMount{
					Name:      voldispName,
					MountPath: ds.MountDir,
					ReadOnly:  ds.ReadOnly,
				})
			}

			vol := k8sv1.Volume{
				Name: voldispName,
				VolumeSource: k8sv1.VolumeSource{
					PersistentVolumeClaim: &k8sv1.PersistentVolumeClaimVolumeSource{
						ClaimName: strings.ToLower(ds.FileLocation),
					},
				},
			}
			volumes = append(volumes, vol)
			logrus.Infof("CreateReplicaPodConfig: mounts %+v, volumes %+v, devices %+v", mounts, volumes, devs)
		}
		replicaSet.Spec.Template.Spec.Containers[0].VolumeMounts = mounts
		replicaSet.Spec.Template.Spec.Containers[0].VolumeDevices = devs
		replicaSet.Spec.Template.Spec.Volumes = volumes
	}
	logrus.Infof("CreateReplicaPodConfig: replicaset setup %+v", replicaSet)

	// Now we have VirtualMachine Instance object, save it to config file for debug purposes
	// and save it in context which will be used to start VM in Start() call
	meta := vmiMetaData{
		repPod:   replicaSet,
		mtype:    IsMetaReplicaPod,
		name:     kubeName,
		domainID: int(rand.Uint32()),
	}
	ctx.vmiList[domainName] = &meta

	repStr := fmt.Sprintf("%+v", replicaSet)

	// write to config file
	file.WriteString(repStr)

	return nil
}

func setKubeAffinity(nodeName string) *k8sv1.Affinity {
	affinity := &k8sv1.Affinity{
		NodeAffinity: &k8sv1.NodeAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []k8sv1.PreferredSchedulingTerm{
				{
					Preference: k8sv1.NodeSelectorTerm{
						MatchExpressions: []k8sv1.NodeSelectorRequirement{
							{
								Key:      "kubernetes.io/hostname",
								Operator: "In",
								Values:   []string{nodeName},
							},
						},
					},
					Weight: 100,
				},
			},
		},
	}
	return affinity
}

func setKubeToleration(timeOutSec int64) []k8sv1.Toleration {
	tolerations := []k8sv1.Toleration{
		{
			Key:               "node.kubernetes.io/unreachable",
			Operator:          k8sv1.TolerationOpExists,
			Effect:            k8sv1.TaintEffectNoExecute,
			TolerationSeconds: pointer.Int64Ptr(timeOutSec),
		},
		{
			Key:               "node.kubernetes.io/not-ready",
			Operator:          k8sv1.TolerationOpExists,
			Effect:            k8sv1.TaintEffectNoExecute,
			TolerationSeconds: pointer.Int64Ptr(timeOutSec),
		},
	}
	return tolerations
}

// StartReplicaPodContiner starts the ReplicaSet pod
func StartReplicaPodContiner(ctx kubevirtContext, vmis *vmiMetaData) error {
	rep := vmis.repPod
	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(ctx.kubeConfig)
	if err != nil {
		logrus.Errorf("StartReplicaPodContiner: can't get clientset %v", err)
		return err
	}

	opStr := "created"
	result, err := clientset.AppsV1().ReplicaSets(kubeapi.EVEKubeNameSpace).Create(context.TODO(), rep, metav1.CreateOptions{})
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			logrus.Errorf("StartReplicaPodContiner: replicaset create failed: %v", err)
			return err
		} else {
			opStr = "already exists"
		}
	}

	logrus.Infof("StartReplicaPodContiner: Rep %s %s, result %v", rep.ObjectMeta.Name, opStr, result)

	err = checkForReplicaPod(ctx, vmis)
	if err != nil {
		logrus.Errorf("StartReplicaPodContiner: check for pod status error %v", err)
		return err
	}
	logrus.Infof("StartReplicaPodContiner: Pod %s running", rep.ObjectMeta.Name)
	return nil
}

func checkForReplicaPod(ctx kubevirtContext, vmis *vmiMetaData) error {
	repName := vmis.repPod.ObjectMeta.Name
	var i int
	var status string
	var err error
	for {
		i++
		logrus.Infof("checkForReplicaPod: check(%d) wait 15 sec, %v", i, repName)
		time.Sleep(15 * time.Second)

		status, err = InfoReplicaSetContainer(ctx, vmis)
		if err != nil {
			logrus.Infof("checkForReplicaPod: repName %s, %v", repName, err)
		} else {
			if status == "Running" {
				logrus.Infof("checkForReplicaPod: (%d) status %s, good", i, status)
				return nil
			} else {
				logrus.Errorf("checkForReplicaPod(%d): get podName info status %v (not running)", i, status)
			}
		}
		if i > waitForPodCheckCounter {
			break
		}
	}

	return fmt.Errorf("checkForReplicaPod: timed out, statuus %s, err %v", status, err)
}

// InfoReplicaSetContainer gets the status of the ReplicaSet pod
func InfoReplicaSetContainer(ctx kubevirtContext, vmis *vmiMetaData) (string, error) {

	repName := vmis.repPod.ObjectMeta.Name
	err := getConfig(&ctx)
	if err != nil {
		return "", err
	}
	podclientset, err := kubernetes.NewForConfig(ctx.kubeConfig)
	if err != nil {
		return "", logError("InfoReplicaSetContainer: couldn't get the pod Config: %v", err)
	}

	pods, err := podclientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", repName),
	})
	if err != nil || len(pods.Items) == 0 {
		// we either can not talk to the kubernetes api-server or it can not find our pod
		retStatus, err2 := checkAndReturnStatus(vmis, true)
		logError("InfoReplicaSetContainer: couldn't get the pods: %v, return %s", err, retStatus)
		return retStatus, err2
	}

	for _, pod := range pods.Items {

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
		logrus.Infof("InfoReplicaSetContainer: rep %s, pod nodeName %v, status %s", pod.ObjectMeta.Name, pod.Spec.NodeName, res)
		if pod.Status.Phase != k8sv1.PodRunning {
			continue
		}

		_, _ = checkAndReturnStatus(vmis, false) // reset the unknown timestamp
		return res, nil
	}

	return "", logError("InfoReplicaSetContainer: pod not ready")
}

func checkReplicaPodMetrics(ctx kubevirtContext, res map[string]types.DomainMetric, emptySlot int) {

	err := getConfig(&ctx)
	if err != nil {
		return
	}
	kubeconfig := ctx.kubeConfig
	podclientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("checkReplicaPodMetrics: can not get pod client %v", err)
		return
	}

	clientset, err := metricsv.NewForConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("checkReplicaPodMetrics: can't get clientset %v", err)
		return
	}

	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		logrus.Errorf("checkReplicaPodMetrics: can't get node name") // XXX may remove
		return
	}

	count := 0
	for n, vmis := range ctx.vmiList {
		if vmis.mtype != IsMetaReplicaPod {
			continue
		}
		count++
		repName := vmis.name
		pods, err := podclientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("app=%s", repName),
		})
		if err != nil {
			logrus.Errorf("checkReplicaPodMetrics: can't get pod %v", err)
			continue
		}

		for _, pod := range pods.Items {
			dm := getPodMetrics(clientset, pod, vmis, nodeName, res)
			if dm != nil {
				if count <= emptySlot {
					res[n] = *dm
				}
				logrus.Infof("checkReplicaPodMetrics: dm %+v, res %v", dm, res)

				ctx.vmiList[n] = vmis // update for the last seen metrics
			}
		}
	}

	logrus.Infof("checkReplicaPodMetrics: done with vmiList")
}

func getPodMetrics(clientset *metricsv.Clientset, pod k8sv1.Pod, vmis *vmiMetaData,
	nodeName string, res map[string]types.DomainMetric) *types.DomainMetric {
	if pod.Status.Phase != k8sv1.PodRunning {
		return nil
	}
	if nodeName != pod.Spec.NodeName { // cluster, pod from other nodes
		return nil
	}
	podName := pod.ObjectMeta.Name
	memoryLimits := pod.Spec.Containers[0].Resources.Limits.Memory()

	metrics, err := clientset.MetricsV1beta1().PodMetricses(kubeapi.EVEKubeNameSpace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		logrus.Errorf("getPodMetrics: get pod metrics error %v", err)
		return nil
	}

	cpuTotalNs := metrics.Containers[0].Usage[k8sv1.ResourceCPU]
	cpuTotalNsAsFloat64 := cpuTotalNs.AsApproximateFloat64() * float64(time.Second) // get nanoseconds
	totalCPU := uint64(cpuTotalNsAsFloat64)

	//allocatedMemory := metrics.Containers[0].Usage[k8sv1.ResourceMemory]
	usedMemory := metrics.Containers[0].Usage[k8sv1.ResourceMemory]
	maxMemory := uint32(usedMemory.Value())
	if vmis != nil {
		if vmis.maxmem < maxMemory {
			vmis.maxmem = maxMemory
		} else {
			maxMemory = vmis.maxmem
		}
	}

	available := uint32(memoryLimits.Value())
	if uint32(usedMemory.Value()) < available {
		available = available - uint32(usedMemory.Value())
	}
	usedMemoryPercent := calculateMemoryUsagePercent(usedMemory.Value(), memoryLimits.Value())
	BytesInMegabyte := uint32(1024 * 1024)

	var realCPUTotal uint64
	if vmis != nil {
		realCPUTotal = vmis.cputotal + totalCPU
		vmis.cputotal = realCPUTotal
	}
	dm := &types.DomainMetric{
		CPUTotalNs:        realCPUTotal,
		CPUScaled:         1,
		AllocatedMB:       uint32(memoryLimits.Value()) / BytesInMegabyte,
		UsedMemory:        uint32(usedMemory.Value()) / BytesInMegabyte,
		MaxUsedMemory:     maxMemory / BytesInMegabyte,
		AvailableMemory:   available / BytesInMegabyte,
		UsedMemoryPercent: usedMemoryPercent,
		NodeName:          pod.Spec.NodeName,
	}
	logrus.Infof("getPodMetrics: dm %+v, res %v", dm, res)
	return dm
}

// StopReplicaPodContainer stops the ReplicaSet pod
func StopReplicaPodContainer(kubeconfig *rest.Config, repName string) error {

	clientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("StopReplicaPodContainer: can't get clientset %v", err)
		return err
	}

	err = clientset.AppsV1().ReplicaSets(kubeapi.EVEKubeNameSpace).Delete(context.TODO(), repName, metav1.DeleteOptions{})
	if err != nil {
		// Handle error
		logrus.Errorf("StopReplicaPodContainer: deleting pod: %v", err)
		return err
	}

	logrus.Infof("StopReplicaPodContainer: Pod %s deleted", repName)
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

// InfoPodContainer : Get the pod information
func InfoPodContainer(ctx kubevirtContext, podName string) (string, error) {
	err := getConfig(&ctx)
	if err != nil {
		return "", err
	}
	podclientset, err := kubernetes.NewForConfig(ctx.kubeConfig)
	if err != nil {
		return "", logError("InfoPodContainer: couldn't get the pod Config: %v", err)
	}

	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		return "", logError("Failed to get nodeName")
	}

	pod, err := podclientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return "", logError("InfoPodContainer: couldn't get the pod: %v", err)
	}

	if nodeName != pod.Spec.NodeName {
		logrus.Infof("InfoPodContainer: pod %s, nodeName %v differ w/ hostname", podName, pod.Spec.NodeName)
		return "", nil
	} else {
		logrus.Infof("InfoPodContainer: pod %s, nodeName %v, matches the hostname uuid", podName, pod.Spec.NodeName)
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
	logrus.Infof("InfoPodContainer: pod %s, nodeName %v, status %s", podName, pod.Spec.NodeName, res)

	return res, nil
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

	logrus.Debugf("Entered registerWithKV  pcilen %d ", len(pciAssignments))
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
		vendor = strings.TrimPrefix(vendor, "0x")
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
		// Lets make sure resname is unique by appending vendor and devid
		// NOTE we cannot use pciVendorSelector directly since ":" is not accepted in kubernetes resource name standard
		resname := "devices.kubevirt.io/hostdevice-" + vendor + devid
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
	return PCIReserveGeneric(long)
}

// PCIRelease releases the PCI device reservation
func (ctx kubevirtContext) PCIRelease(long string) error {
	return PCIReleaseGeneric(long)
}

// PCISameController checks if two PCI controllers are the same
func (ctx kubevirtContext) PCISameController(id1 string, id2 string) bool {
	return PCISameControllerGeneric(id1, id2)
}

func (ctx kubevirtContext) VirtualTPMSetup(domainName string, wp *types.WatchdogParam) error {
	return fmt.Errorf("not implemented")
}

func (ctx kubevirtContext) VirtualTPMTerminate(domainName string, wp *types.WatchdogParam) error {
	return fmt.Errorf("not implemented")
}

func (ctx kubevirtContext) VirtualTPMTeardown(domainName string, wp *types.WatchdogParam) error {
	return fmt.Errorf("not implemented")
}

func (ctx kubevirtContext) OemWindowsLicenseKeySetup(wlk *types.OemWindowsLicenseKeyInfo) error {
	return fmt.Errorf("not implemented")
}

// save the node-name to context map for later retrieval
func saveMyNodeUUID(ctx *kubevirtContext, nodeName string) {
	if len(ctx.nodeNameMap) == 0 {
		ctx.nodeNameMap["nodename"] = nodeName
	}
}

// checkAndReturnStatus
// when pass-in gotUnknown is true, we failed to get the kubernetes pod, return 'Unknown' for
// the status, and if the status exceeds 5 minutes, return 'Halting' with error
// when pass-in !goUnknown, we reset the unknown timestamp
// see detail description in the 'zedkube.md' section 'Handle Domain Apps Status in domainmgr'
func checkAndReturnStatus(vmis *vmiMetaData, gotUnknown bool) (string, error) {
	if gotUnknown {
		if vmis.startUnknownTime.IsZero() { // first time, set the unknown timestamp
			vmis.startUnknownTime = time.Now()
			return "Unknown", nil
		} else {
			if time.Since(vmis.startUnknownTime) > unknownToHaltMinutes*time.Minute {
				return "Halting", fmt.Errorf("Unknown status for more than 5 minute")
			} else {
				return "Unknown", nil
			}
		}
	} else {
		// we got the pod status, reset the unknown timestamp
		vmis.startUnknownTime = time.Time{}
	}
	return "", nil
}
