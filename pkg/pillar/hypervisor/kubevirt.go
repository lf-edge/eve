// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	"github.com/lf-edge/eve/pkg/pillar/types"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netattdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sapitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
	"k8s.io/utils/pointer"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

// KubevirtHypervisorName is a name of the imaginary EVE 'k' hypervisor
const (
	KubevirtHypervisorName = "k"
	kubevirtStateDir       = "/run/hypervisor/kubevirt/"
	eveLabelKey            = "App-Domain-Name"
	waitForPodCheckCounter = 5  // Check 5 times
	waitForPodCheckTime    = 15 // Check every 15 seconds, don't wait for too long to cause watchdog
	tolerateSec            = 15 // Pod/VMI reschedule delay after node unreachable seconds
	unknownToHaltMinutes   = 30 // If VMI is unknown for 30 minutes, return halt state
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
	// sriovVFs lists the (PF ifname, VF index) of every SR-IOV VF this VMI
	// was wired with via attachSRIOVInterfaces.  Used on Stop/Delete/Cleanup
	// to clear the per-VF admin MAC on the PF — sriov-cni's DEL path doesn't
	// reliably clear it when the VF is pre-bound to vfio-pci, so EVE owns
	// the cleanup.
	sriovVFs []sriovVFRef
}

// sriovVFRef identifies a single VF on a Physical Function for cleanup
// purposes.  PfIface is the PF kernel netdev name (e.g. "eth2"), Index is
// the VF index within that PF.  Together they uniquely identify a slot in
// the PF's VF table that netlink.LinkSetVfHardwareAddr addresses.
type sriovVFRef struct {
	PfIface string
	Index   uint8
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
	// kubevirt_vmi_cpu_usage_seconds_total is the combined total (system+user); use it alone to avoid double-counting
	case "kubevirt_vmi_cpu_usage_seconds_total":
		if v, ok := value.(float64); ok {
			r.CPUTotalNs += uint64(v * float64(time.Second))
		}
	case "kubevirt_vmi_cpu_system_usage_seconds_total":
	case "kubevirt_vmi_cpu_user_usage_seconds_total":
	case "kubevirt_vmi_memory_usable_bytes":
		// The amount of memory which can be reclaimed by balloon without pushing the guest system to swap,
		// corresponds to ‘Available’ in /proc/meminfo
		// https://kubevirt.io/monitoring/metrics.html#kubevirt
		r.AvailableMemory = uint32(assignToInt64(value) / BytesInMegabyte)
	case "kubevirt_vmi_memory_domain_bytes":
		// The amount of memory in bytes allocated to the domain.
		// https://kubevirt.io/monitoring/metrics.html#kubevirt
		r.AllocatedMB = uint32(assignToInt64(value) / BytesInMegabyte)
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

// uuidPrefixOfDomainName returns the "uuid." prefix from a domainName of the
// form "uuid.version.appnum". Returns "" when the input is malformed.
func uuidPrefixOfDomainName(domainName string) string {
	dotIdx := strings.Index(domainName, ".")
	if dotIdx <= 0 {
		return ""
	}
	return domainName[:dotIdx+1]
}

// evictStaleVMIByUUIDPrefix removes any entry from vmiList whose key shares
// the UUID prefix of newDomainName but is a different key. Used when creating
// a new VMIRS / Pod replicaset for an app whose domainName has changed
// (typically a purge changed PurgeCounter, which also changed Version), so
// that the in-memory map keeps a single entry per app UUID.
func (ctx kubevirtContext) evictStaleVMIByUUIDPrefix(newDomainName string) {
	uuidPrefix := uuidPrefixOfDomainName(newDomainName)
	if uuidPrefix == "" {
		return
	}
	for k := range ctx.vmiList {
		if k != newDomainName && strings.HasPrefix(k, uuidPrefix) {
			logrus.Warnf("evictStaleVMIByUUIDPrefix: removing stale entry %s for new %s",
				k, newDomainName)
			delete(ctx.vmiList, k)
			delete(ctx.prevDomainMetric, k)
		}
	}
}

// lookupVMIByUUIDPrefix scans vmiList for an entry whose key shares the UUID
// prefix of domainName. Used as a fallback when Stop/Delete/Cleanup is called
// with a domainName that does not match the current vmiList key — e.g. the
// caller still has the old DomainConfig version in hand. Returns the meta and
// the actual key under which it was found.
func (ctx kubevirtContext) lookupVMIByUUIDPrefix(domainName string) (*vmiMetaData, string) {
	uuidPrefix := uuidPrefixOfDomainName(domainName)
	if uuidPrefix == "" {
		return nil, ""
	}
	for k, v := range ctx.vmiList {
		if strings.HasPrefix(k, uuidPrefix) {
			return v, k
		}
	}
	return nil, ""
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
	kubeName := base.GetAppKubeNameWithPurge(config.DisplayName, config.UUIDandVersion.UUID, config.PurgeCounter)
	// Get a VirtualMachineInstance object and populate the values from DomainConfig
	vmi := v1.NewVMIReferenceFromNameWithNS(kubeapi.EVEKubeNameSpace, kubeName)

	// Set CPUs
	cpus := v1.CPU{}
	cpus.Cores = uint32(config.VCpus)

	// CPU Pinning (HV=k / KubeVirt):
	// DedicatedCPUPlacement instructs the KubeVirt CPU Manager integration
	// to pin every vCPU to a unique physical CPU thread.
	// Cluster prerequisites:
	//   - KubeVirt featureGate "CPUManager" must be enabled in the KubeVirt CR
	//   - Node kubelet must run with --cpu-manager-policy=static
	//   - VMI pod must reach Kubernetes Guaranteed QoS (cpu requests == limits)
	if config.VmConfig.CPUsPinned {
		cpus.DedicatedCPUPlacement = true
	}

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

	// Guaranteed QoS: Kubernetes static CPU Manager requires that CPU
	// Requests == Limits. Without this, the VMI pod is in Burstable QoS and
	// the CPU Manager will not honour dedicated (pinned) CPU placement.
	// Memory must also be included in Requests/Limits to satisfy the
	// KubeVirt admission webhook requirement.
	if config.VmConfig.CPUsPinned {
		cpuQuantity := resource.MustParse(strconv.Itoa(config.VCpus))
		vmi.Spec.Domain.Resources.Requests = k8sv1.ResourceList{
			k8sv1.ResourceCPU:    cpuQuantity,
			k8sv1.ResourceMemory: m,
		}
		vmi.Spec.Domain.Resources.Limits = k8sv1.ResourceList{
			k8sv1.ResourceCPU:    cpuQuantity,
			k8sv1.ResourceMemory: m,
		}
	}

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

	// Set video device for better VNC resolution.
	// Note: Requires VideoConfig feature gate enabled in KubeVirt cluster configuration for kubevirt.io v1.6.0
	vmi.Spec.Domain.Devices.Video = &v1.VideoDevice{
		Type: "virtio",
	}

	// Disable app log collection if user asked for it
	if config.DisableLogs {
		vmi.Spec.Domain.Devices.LogSerialConsole = ptrBool(false)
	}

	// Set Firmware UUID from app UUID so the guest always sees a stable SMBIOS UUID.
	// This is required for Firewall kind of apps that needs a stable UUID to work with during failover and keep licenses valid.
	vmi.Spec.Domain.Firmware = &v1.Firmware{
		UUID: k8sapitypes.UID(config.UUIDandVersion.UUID.String()),
	}

	// If FML type, set the firmware bootloader to EFI
	if config.VirtualizationMode == types.FML {
		if runtime.GOARCH == "amd64" {
			addEFIBootLoader(&vmi.Spec)
		} else {
			return logError("FML app not supported on architecture %v", runtime.GOARCH)
		}
	}

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
				// The concept is same in kubevirt too. Kubevirt supports this functionality through feature
				// https://kubevirt.io/user-guide/virtual_machines/boot_from_external_source/
				// Since disks are virtio disks we assume /dev/vda is the boot disk
				// Include both tty0 (video) and ttyS0 (serial) consoles so that logs are captured
				// by kubevirt's guest-console-log container
				kernelArgs := "console=tty0 console=ttyS0 root=/dev/vda dhcp=1 rootfstype=ext4"
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
		logrus.Debugf("processing adapter type=%d name=%s\n", adapter.Type, adapter.Name)
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
			// IoNetEth: skip sibling PCI functions in the same assignment group
			// whose ifname doesn't match the requested adapter name.  Registering
			// them separately with KubeVirt would cause an allocation error.
			if ib.Type == types.IoNetEth && ib.Ifname != adapter.Name {
				logrus.Infof("CreateReplicaVMIConfig: skip sibling PCI device %s "+
					"(not the requested adapter %s)\n", ib.Ifname, adapter.Name)
				continue
			}
			// IoNetEthPF is the SR-IOV Physical Function.  It must remain in the host
			// (keepInHost=true, never in vfio-pci).  Only the derived VFs
			// (IoNetEthVF) should be passed through to the VM.
			if ib.Type == types.IoNetEthPF {
				logrus.Warnf("CreateReplicaVMIConfig: skipping SR-IOV PF %s for adapter %s — "+
					"assign VFs (e.g. %svf0) to the VM instead",
					ib.Ifname, adapter.Name, ib.Ifname)
				continue
			}
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				logrus.Fatalf("IoBundle not ours %s: %d %s for %s\n",
					ib.UsedByUUID, adapter.Type, adapter.Name,
					domainName)
			}
			if ib.PciLong != "" {
				if ib.Type.IsNetEthVF() {
					logrus.Infof("CreateReplicaVMIConfig: adding SR-IOV VF <%s> "+
						"(index %d, VLAN %d, MAC %s, PF %s)\n",
						ib.PciLong, ib.VfParams.Index, ib.VfParams.VlanID,
						ib.MacAddr, ib.VfParams.PFIface)
				} else {
					logrus.Infof("CreateReplicaVMIConfig: adding PCI device <%s> type %d\n",
						ib.PciLong, ib.Type)
				}
				tap := pciDevice{ioBundle: *ib}
				pciAssignments = addNoDuplicatePCI(pciAssignments, tap)
			}
		}
	}

	// Split assignments into two buckets:
	//   - SR-IOV VFs go through Multus + sriov-cni so KubeVirt selects a specific
	//     VF per VMI by BDF (resource pool counts) and we can set a per-VM MAC
	//     via Interface.MacAddress.  This is the canonical KubeVirt SR-IOV path.
	//   - Other PCI devices (GPUs, NVMe, USB controllers, plain NICs) keep the
	//     HostDevices path: register vendor:device once, attach by resource name.
	var hostDevAssignments []pciDevice
	var vfAssignments []pciDevice
	for _, pa := range pciAssignments {
		if pa.ioBundle.Type.IsNetEthVF() {
			vfAssignments = append(vfAssignments, pa)
		} else {
			hostDevAssignments = append(hostDevAssignments, pa)
		}
	}

	if len(hostDevAssignments) > 0 {
		// PCI passthrough for KubeVirt is a three-step process:
		//   1. PCIReserve (vfio-pci bind) — already done in domainmgr handleCreate.
		//   2. Register the vendor:device tuple in the KubeVirt CR PermittedHostDevices
		//      so the KubeVirt device plugin exposes it as a Kubernetes resource.
		//   3. Reference the resource name in the VMI HostDevices list.
		if err := registerWithKV(kvClient, vmi, hostDevAssignments); err != nil {
			return logError("Failed to register PCI devices with KubeVirt (%d device(s)): %v",
				len(hostDevAssignments), err)
		}
	}

	var sriovVFs []sriovVFRef
	if len(vfAssignments) > 0 {
		refs, err := attachSRIOVInterfaces(ctx.kubeConfig, vmi, vfAssignments, config.UUIDandVersion.UUID)
		if err != nil {
			return logError("Failed to attach SR-IOV VFs to VMI (%d VF(s)): %v",
				len(vfAssignments), err)
		}
		sriovVFs = refs
	}

	// Set the affinity to this node the VMI is preferred to run on
	affinity := setKubeAffinity(nodeName, config.AffinityType)

	// Set tolerations to handle node conditions
	tolerations := setKubeToleration(int64(tolerateSec))

	vmi.Spec.Affinity = affinity
	vmi.Spec.Tolerations = tolerations

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
					Annotations: map[string]string{
						kubeapi.DeschedulerEvictAnnotation: "true",
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
		sriovVFs: sriovVFs,
	}
	ctx.evictStaleVMIByUUIDPrefix(domainName)
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

	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		return logError("start domain %s failed to get vmlist", domainName)
	}
	logrus.Infof("Starting Kubevirt domain %s, devicename nodename %d nodeName:%s vmis:%v", domainName, len(ctx.nodeNameMap), nodeName, vmis)

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

	// Create the VMI ReplicaSet, retrying on transient kube API server errors.
	const maxRetries = 5
	for retries := maxRetries; ; retries-- {
		_, err = virtClient.ReplicaSet(kubeapi.EVEKubeNameSpace).Create(context.Background(), repvmi, metav1.CreateOptions{})
		if err == nil {
			break
		}
		if errors.IsAlreadyExists(err) {
			// VMI could have been already started, for example failover from other node.
			logrus.Warnf("VMI replicaset %v already exists", repvmi)
			break
		}
		if retries <= 0 {
			logrus.Errorf("Start VMI replicaset failed, no retries left: %v", err)
			return err
		}
		logrus.Errorf("Start VMI replicaset failed, retrying (%d left): %v", retries-1, err)
		time.Sleep(10 * time.Second)
	}
	logrus.Infof("Started Kubevirt domain replicaset %s, VMI replicaset %s", domainName, vmis.name)

	// Start() returns as soon as VMIRS is created; cluster drives VMI scheduling.
	return nil
}

// Create is no-op for kubevirt, just return the domainID we already have.
func (ctx kubevirtContext) Create(domainName string, cfgFilename string, config *types.DomainConfig) (int, error) {
	return ctx.vmiList[domainName].domainID, nil
}

// replicaVmiScheduledOnMe is the VMI replicaset implementation of scheduledOnMe()
func (ctx kubevirtContext) replicaVmiScheduledOnMe(vmirsName string) (scheduledOnMe bool, scheduledOnNone bool, err error) {
	err = getConfig(&ctx)
	if err != nil {
		return false, false, err
	}
	kubeconfig := ctx.kubeConfig

	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		return false, false, fmt.Errorf("Failed to get nodeName")
	}

	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(kubeconfig)
	if err != nil {
		logrus.Errorf("couldn't get the kubernetes client API config: %v", err)
		return false, false, err
	}

	vmirs, err := virtClient.ReplicaSet(kubeapi.EVEKubeNameSpace).Get(context.Background(), vmirsName, metav1.GetOptions{})
	if err != nil {
		return false, false, err
	}
	appDomainNameSelector := vmirs.Status.LabelSelector

	vmis, err := virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{
		LabelSelector: appDomainNameSelector,
	})
	if err != nil {
		return false, false, err
	}
	if len(vmis.Items) > 0 {
		// Have a vmi, use it for status
		// If there are multiple copies, one should be terminating
		// Skip it and find the copy scheduling or running and see if it matches node name
		for _, vmi := range vmis.Items {
			if vmi.ObjectMeta.DeletionTimestamp != nil {
				// copy is terminating
				// could be a leftover from a vmi currently failing over
				continue
			}
			if vmi.Status.NodeName == "" {
				// Not scheduled yet, move on
				continue
			}
			return (vmi.Status.NodeName == nodeName), false, nil
		}
		// Intentional fallback to looking at a virt-launcher pod
		// One or both VMI objects may be either terminating or not scheduled to any node.
	}

	// No VMI, look for a Virt-launcher pod instead, it will start earlier
	podclientset, err := kubernetes.NewForConfig(ctx.kubeConfig)
	if err != nil {
		return false, false, fmt.Errorf("no kube config")
	}
	vlPods, err := podclientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "kubevirt.io=virt-launcher," + appDomainNameSelector,
	})
	if len(vlPods.Items) == 0 {
		return false, false, nil
	}
	for _, vlPod := range vlPods.Items {
		if vlPod.ObjectMeta.DeletionTimestamp != nil {
			// copy is terminating
			// could be a leftover from a vmi currently failing over
			continue
		}
		if vlPod.Status.Phase == "Pending" {
			return false, true, nil
		}
		if vlPod.Spec.NodeName == "" {
			// Not scheduled yet, move on
			continue
		}
		return (vlPod.Spec.NodeName == nodeName), true, nil
	}
	// No VMI or virt-launcher pod (which isn't terminating)
	return false, false, fmt.Errorf("Unhandled scheduling state")
}

// replicaPodScheduledOnMe is the ReplicaSet Pod implementation of scheduledOnMe()
func (ctx kubevirtContext) replicaPodScheduledOnMe(rsName string) (onMe bool, scheduledOnNone bool, err error) {
	err = getConfig(&ctx)
	if err != nil {
		return false, false, err
	}

	nodeName, ok := ctx.nodeNameMap["nodename"]
	if !ok {
		return false, false, fmt.Errorf("Failed to get nodeName")
	}

	podclientset, err := kubernetes.NewForConfig(ctx.kubeConfig)
	if err != nil {
		return false, false, fmt.Errorf("no kube config")
	}

	pods, err := podclientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", rsName),
	})
	if err != nil {
		return false, false, err
	}
	if len(pods.Items) < 1 {
		return false, false, nil
	}

	for _, pod := range pods.Items {
		if pod.ObjectMeta.DeletionTimestamp != nil {
			// this is terminating, check for another.
			continue
		}
		if pod.Status.Phase == "Pending" {
			return false, true, nil
		}
		if pod.Spec.NodeName == "" {
			continue
		}
		return (pod.Spec.NodeName == nodeName), false, nil
	}
	return false, true, fmt.Errorf("Unhandled scheduling state")
}

// scheduledOnMe compares local node name to the node name kubernetes reports running/scheduling on
// this is used in cluster environments to determine if action should be taken on an app only if the app
// is running on the local node. The functions/actions should call this to check it the app has
// recently failed over to another node, if so then take no action (defer to the new node's pillar).
func (ctx kubevirtContext) scheduledOnMe(mtype MetaDataType, objectName string) (onMe bool, scheduledOnNone bool, err error) {
	if mtype == IsMetaReplicaPod {
		return ctx.replicaPodScheduledOnMe(objectName)
	} else if mtype == IsMetaReplicaVMI {
		return ctx.replicaVmiScheduledOnMe(objectName)
	} else {
		return false, false, logError("domain %s wrong type %d", objectName, mtype)
	}
}

// clearSRIOVAdminMACs zeroes the per-VF admin MAC for every VF this VMI was
// wired with.  Called on VM teardown so the next VM that lands on the same
// VF doesn't inherit the previous tenant's admin MAC.
//
// Best-effort: a per-VF failure is logged and skipped.  Leaving an old MAC
// in place is bad but not catastrophic (the next attach will reprogram it);
// returning an error here would block the VMI delete and produce a worse
// failure mode for the operator (stuck delete loop).
func (ctx kubevirtContext) clearSRIOVAdminMACs(vmis *vmiMetaData) {
	for _, ref := range vmis.sriovVFs {
		if err := sriov.ClearVFAdminMAC(ref.PfIface, ref.Index); err != nil {
			logrus.Warnf("clearSRIOVAdminMACs: PF %s VF %d: %v",
				ref.PfIface, ref.Index, err)
			continue
		}
		logrus.Infof("clearSRIOVAdminMACs: cleared admin MAC on PF %s VF %d",
			ref.PfIface, ref.Index)
	}
}

// There is no such thing as stop VMI, so delete it.
func (ctx kubevirtContext) Stop(domainName string, force bool) error {
	logrus.Debugf("Stop called for Domain: %s", domainName)
	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	kubeconfig := ctx.kubeConfig

	keyToDelete := domainName
	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		if stale, oldKey := ctx.lookupVMIByUUIDPrefix(domainName); stale != nil {
			logrus.Warnf("Stop: domainName %s not in vmiList; using stale entry under %s",
				domainName, oldKey)
			vmis = stale
			keyToDelete = oldKey
		} else {
			return logError("domain %s failed to get vmlist", domainName)
		}
	}

	onMe, _, err := ctx.scheduledOnMe(vmis.mtype, vmis.name)
	if err != nil {
		return err
	}
	if !onMe {
		return nil
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

	ctx.clearSRIOVAdminMACs(vmis)

	delete(ctx.vmiList, keyToDelete)

	delete(ctx.prevDomainMetric, keyToDelete)

	return nil
}

func (ctx kubevirtContext) Delete(domainName string) (result error) {
	logrus.Warnf("Delete called for Domain: %s", domainName)
	err := getConfig(&ctx)
	if err != nil {
		return err
	}
	kubeconfig := ctx.kubeConfig

	keyToDelete := domainName
	vmis, ok := ctx.vmiList[domainName]
	if !ok {
		if stale, oldKey := ctx.lookupVMIByUUIDPrefix(domainName); stale != nil {
			logrus.Warnf("Delete: domainName %s not in vmiList; using stale entry under %s",
				domainName, oldKey)
			vmis = stale
			keyToDelete = oldKey
		} else {
			return logError("delete domain %s failed to get vmlist", domainName)
		}
	}

	onMe, scheduledOnNone, err := ctx.scheduledOnMe(vmis.mtype, vmis.name)
	if !onMe && !scheduledOnNone {
		// Not scheduled on me, but is scheduled elsewhere.
		return nil
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

	ctx.clearSRIOVAdminMACs(vmis)

	// Delete the state dir
	if err := os.RemoveAll(kubevirtStateDir + domainName); err != nil {
		return logError("failed to clean up domain state directory %s (%v)", domainName, err)
	}

	if _, ok := ctx.vmiList[keyToDelete]; ok {
		delete(ctx.vmiList, keyToDelete)
	}

	if _, ok := ctx.prevDomainMetric[keyToDelete]; ok {
		delete(ctx.prevDomainMetric, keyToDelete)
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

	logrus.Infof("Attempt to stop VMI:%s vmirs deleted", repVmiName)
	// Stop the VMI ReplicaSet

	err = virtClient.ReplicaSet(kubeapi.EVEKubeNameSpace).Delete(context.Background(), repVmiName, metav1.DeleteOptions{})
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
		if stale, oldKey := ctx.lookupVMIByUUIDPrefix(domainName); stale != nil {
			logrus.Warnf("Info: domainName %s not in vmiList; using stale entry under %s",
				domainName, oldKey)
			vmis = stale
		} else {
			return 0, types.HALTED, logError("info domain %s failed to get vmlist", domainName)
		}
	}

	onMe, _, err := ctx.scheduledOnMe(vmis.mtype, vmis.name)
	if err != nil {
		if isK3sUnreachable(err) {
			return 0, types.UNKNOWN, nil
		}
		return 0, types.BROKEN, logError("Failed to determine scheduled node: %s", err)
	}
	if !onMe {
		return 0, types.UNKNOWN, nil
	}

	if vmis.mtype == IsMetaReplicaPod {
		res, err = InfoReplicaSetContainer(ctx, vmis)
	} else {
		res, err = getVMIStatus(vmis, nodeName)
	}
	if err != nil {
		if isK3sUnreachable(err) {
			return 0, types.UNKNOWN, nil
		}
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
		return vmis.domainID, effectiveDomainState, err
	} else {
		return vmis.domainID, effectiveDomainState, err
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
		if stale, oldKey := ctx.lookupVMIByUUIDPrefix(domainName); stale != nil {
			logrus.Warnf("Cleanup: domainName %s not in vmiList; using stale entry under %s",
				domainName, oldKey)
			vmis = stale
		} else {
			return logError("cleanup domain %s failed to get vmlist", domainName)
		}
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
	vmiList, err := virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{})
	if err != nil {

		if isK3sUnreachable(err) {
			// This means we are unable to talk to kubernetes.
			// May be API server crashed or network cable got pulled ??
			return "Unknown", err
		}
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
		logrus.Infof("getVMIStatus: repVmi:%s nodeName:%s vmiList vmi.ObjectMeta.Name:%s vmi.Status.NodeName:%s vmi.ObjectMeta.DeletionTimestamp:%v vmi.Status.Phase:%s",
			repVmiName, nodeName, vmi.ObjectMeta.Name, vmi.Status.NodeName, vmi.ObjectMeta.DeletionTimestamp, vmi.Status.Phase)
		if vmi.Status.NodeName == nodeName {
			if vmi.GenerateName == repVmiName {
				targetVMI = &vmi
				logrus.Infof("getVMIStatus: repVmi:%s nodeName:%s picked vmi", repVmiName, nodeName)
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
			logrus.Infof("getVMIStatus: repVmi:%s nodeName:%s nonLocalStatus:%s", repVmiName, nodeName, nonLocalStatus)
			return nonLocalStatus, nil
		}
		retStatus, err2 := checkAndReturnStatus(vmis, true)
		logError("getVMIStatus: No VMI %s found with the given nodeName %s, return %s", repVmiName, nodeName, retStatus)
		return retStatus, err2
	}
	res := fmt.Sprintf("%v", targetVMI.Status.Phase)
	logrus.Infof("getVMIStatus: repVmi:%s nodeName:%s targetVMI.ObjectMeta.Name:%s targetVMI.Status.NodeName:%s targetVMI.ObjectMeta.DeletionTimestamp:%v targetVMI.Status.Phase:%s res:%s",
		repVmiName, nodeName, targetVMI.ObjectMeta.Name, targetVMI.Status.NodeName, targetVMI.ObjectMeta.DeletionTimestamp, targetVMI.Status.Phase, res)
	_, _ = checkAndReturnStatus(vmis, false) // reset the unknown timestamp
	return res, nil
}

// Inspired from kvm.go
func waitForVMI(vmis *vmiMetaData, nodeName string, available bool) error {
	vmiName := vmis.name
	maxDelay := time.Minute * 15
	if !available {
		// available=false is "wait for the VMI to be GONE", called from
		// Cleanup at the tail of doInactivate. In kubevirt cluster mode the
		// VMIRS lifecycle is owned by Kubernetes; once we (or the cluster)
		// delete the VMIRS, GC of residual child VMIs runs asynchronously
		// and we do not need to confirm it inline. The original 15-minute
		// cap stalls handleDelete end-to-end — DomainStatus stays
		// published, zedmanager never reaches unpublishAppNetworkConfig,
		// zedrouter never frees portmap/MAC/UuidToNum allocations, and
		// follow-on apps with overlapping portmaps fail to come up.
		maxDelay = time.Minute
	}
	delay := time.Second
	var waited time.Duration

	for {
		logrus.Infof("waitForVMI for %s on %s %t: waiting for %v", vmiName, nodeName, available, delay)
		if delay != 0 {
			time.Sleep(delay)
			waited += delay
		}

		state, err := getVMIStatus(vmis, nodeName)
		if err != nil {

			if available {
				logrus.Infof("waitForVMI for %s on %s %t done, state %v, err %v", vmiName, nodeName, available, state, err)
			} else {
				// Failed to get status, may be already deleted.
				logrus.Infof("waitForVMI for %s on %s %t done, state %v, err %v", vmiName, nodeName, available, state, err)
				return nil
			}
		} else {
			if state == "Running" && available {
				logrus.Infof("waitForVMI %s %s %t found state==Running", vmiName, nodeName, available)
				return nil
			}
		}

		if waited > maxDelay {
			// Give up, also log the state at the time of give up.
			logrus.Warnf("waitForVMI for %s on %s %t: giving up at state:%s", vmiName, nodeName, available, state)
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
		logrus.Debugf("GetDomsCPUMem: get virthandler ip error %v", err)
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

	// domainAvailMB temporarily tracks kubevirt_vmi_memory_available_bytes per domain
	// so we can compute UsedMemory = available_bytes - usable_bytes after all metrics are parsed.
	domainAvailMB := make(map[string]uint32)

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
			if metricName == "kubevirt_vmi_memory_available_bytes" && domainName != "" {
				const bytesInMegabyte = int64(1024 * 1024)
				domainAvailMB[domainName] = uint32(assignToInt64(parsedValue) / bytesInMegabyte)
			}
			res.fill(domainName, metricName, parsedValue)
			logrus.Debugf("GetDomsCPUMem: vmi %s, domainName %s, metric name %s, value %v", vmiName, domainName, metricName, parsedValue)
		}
	}

	for n, r := range res {
		if n == "" {
			continue
		}
		// used_bytes = available_bytes - usable_bytes; guard uint32 underflow when guest agent data is stale/absent
		if domainAvailMB[n] > r.AvailableMemory {
			r.UsedMemory = domainAvailMB[n] - r.AvailableMemory
		} else {
			r.UsedMemory = 0
		}
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

	kubeName := base.GetAppKubeNameWithPurge(config.DisplayName, config.UUIDandVersion.UUID, config.PurgeCounter)
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
					Affinity:    setKubeAffinity(nodeName, config.AffinityType),
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
	ctx.evictStaleVMIByUUIDPrefix(domainName)
	ctx.vmiList[domainName] = &meta

	repStr := fmt.Sprintf("%+v", replicaSet)

	// write to config file
	file.WriteString(repStr)

	return nil
}

func setKubeAffinity(nodeName string, affinityType types.Affinity) *k8sv1.Affinity {
	matchExpressions := []k8sv1.NodeSelectorRequirement{
		{
			Key:      "kubernetes.io/hostname",
			Operator: "In",
			Values:   []string{nodeName},
		},
	}

	k8sAffinity := &k8sv1.Affinity{
		NodeAffinity: &k8sv1.NodeAffinity{},
	}
	switch affinityType {
	case types.PreferredDuringScheduling:
		k8sAffinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution = []k8sv1.PreferredSchedulingTerm{
			{
				Preference: k8sv1.NodeSelectorTerm{
					MatchExpressions: matchExpressions,
				},
				Weight: 100,
			},
		}
	case types.RequiredDuringScheduling:
		k8sAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = &k8sv1.NodeSelector{
			NodeSelectorTerms: []k8sv1.NodeSelectorTerm{
				{
					MatchExpressions: matchExpressions,
				},
			},
		}
	}
	return k8sAffinity
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

// registerWithKV registers PCI host-devices with KubeVirt and adds them as
// HostDevices in the VMI spec.
//
// SR-IOV VFs are NOT routed through this path — they go through
// attachSRIOVInterfaces (Multus + sriov-cni).  This function only handles
// non-VF passthrough (GPUs, NVMe, USB controllers, plain NICs).
//
// Flow:
//  1. For each PCI assignment look up its vendor:device tuple.
//  2. If the tuple is not yet in KubeVirt's PermittedHostDevices CR, add it and
//     update the CR.  This triggers the KubeVirt device plugin to expose the
//     resource to kubelet.
//  3. Reference the resource name in the VMI HostDevices list.
//
// References:
//
//	https://kubevirt.io/user-guide/virtual_machines/host-devices/#host-preparation-for-pci-passthrough
func registerWithKV(kvClient kubecli.KubevirtClient, vmi *v1.VirtualMachineInstance,
	pciAssignments []pciDevice) error {

	logrus.Debugf("registerWithKV: %d PCI assignment(s)", len(pciAssignments))
	pcidevices := make([]v1.HostDevice, len(pciAssignments))

	const (
		kubeVirtName      = "kubevirt"
		kubeVirtNamespace = "kubevirt"
	)

	// Retrieve the KubeVirt CR so we can inspect / update PermittedHostDevices.
	kubeVirt, err := kvClient.KubeVirt(kubeVirtNamespace).Get(context.Background(), kubeVirtName, metav1.GetOptions{})
	if err != nil {
		return logError("registerWithKV: can't fetch KubeVirt CR: %v", err)
	}

	pciHostDevs := kubeVirt.Spec.Configuration.PermittedHostDevices.PciHostDevices

	for i, pa := range pciAssignments {
		vendor, err := pa.vid()
		if err != nil {
			return logError("registerWithKV: can't read vendor ID for %s: %v", pa.ioBundle.PciLong, err)
		}
		// KubeVirt rejects the "0x" prefix in vendor/device IDs.
		vendor = strings.TrimPrefix(vendor, "0x")

		devid, err := pa.devid()
		if err != nil {
			return logError("registerWithKV: can't read device ID for %s: %v", pa.ioBundle.PciLong, err)
		}
		devid = strings.TrimPrefix(devid, "0x")

		pciVendorSelector := vendor + ":" + devid

		// Resource names must not contain ":" (Kubernetes naming rules), so we
		// concatenate vendor and device ID directly.
		resname := "devices.kubevirt.io/hostdevice-" + vendor + devid

		if !isRegisteredPciHostDevice(pciVendorSelector, pciHostDevs) {
			newpcidev := v1.PciHostDevice{
				ResourceName:      resname,
				PCIVendorSelector: pciVendorSelector,
			}
			logrus.Infof("registerWithKV: registering PCI device "+
				"(BDF %s, vendor:device %s) as resource %s",
				pa.ioBundle.PciLong, pciVendorSelector, resname)

			kubeVirt.Spec.Configuration.PermittedHostDevices.PciHostDevices =
				append(kubeVirt.Spec.Configuration.PermittedHostDevices.PciHostDevices, newpcidev)
			_, err = kvClient.KubeVirt(kubeVirtNamespace).Update(context.Background(), kubeVirt, metav1.UpdateOptions{})
			if err != nil {
				return logError("registerWithKV: can't update KubeVirt CR: %v", err)
			}
		} else {
			logrus.Debugf("registerWithKV: resource %s already registered for vendor:device %s",
				resname, pciVendorSelector)
		}

		// At this point the device is registered.  Add it to the VMI HostDevices list.
		// HostDevices cover NVMe drives, GPUs, USB, etc. — we call them
		// "device<N>" generically.
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

func addEFIBootLoader(spec *v1.VirtualMachineInstanceSpec) {
	if spec.Domain.Firmware == nil {
		spec.Domain.Firmware = &v1.Firmware{}
	}
	// Refer https://pkg.go.dev/kubevirt.io/api/core/v1#EFI
	spec.Domain.Firmware.Bootloader = &v1.Bootloader{
		EFI: &v1.EFI{
			SecureBoot: ptrBool(false), // For this we need SMM CPU feature enabled
			Persistent: ptrBool(false),
		},
	}
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

// check if the error is due to k3s unreachable or any other timeouts.
func isK3sUnreachable(err error) bool {

	// k3s API server timeout or any other timeouts or if etcd service or any other service is not available.
	if errors.IsServerTimeout(err) || errors.IsTimeout(err) || errors.IsServiceUnavailable(err) {
		return true
	}
	return false
}

func ptrBool(b bool) *bool {
	return &b
}

// ============================================================================
// SR-IOV via Multus + sriov-cni
// ----------------------------------------------------------------------------
// Each SR-IOV Virtual Function is attached to the VMI as a KubeVirt SR-IOV
// network interface backed by a Multus NetworkAttachmentDefinition.  This lets
// us:
//   - Pick a specific VF (by BDF) via the sriov-network-device-plugin's resource
//     pool — eliminates the "fungible pool" problem that affects raw PCI
//     HostDevices when multiple VFs share the same vendor:device tuple.
//   - Set a per-VM MAC address using vmi.Spec.Domain.Devices.Interfaces[].MacAddress.
//     KubeVirt -> libvirt -> sriov-cni honors this on the guest side regardless
//     of what the PF admin-MAC was programmed to.
//   - Re-bind a VF on the destination node automatically during failover, as
//     long as the destination has free VFs in the same pool.
//
// Cluster prerequisites (installed by pkg/kube/cluster-init.sh on SR-IOV nodes):
//   - Multus CNI (already present for the eve-bridge primary network).
//   - sriov-cni                : /opt/cni/bin/sriov on every node.
//   - sriov-network-device-plugin : advertises eve.network/<pf>_vfs as a
//     Kubernetes extended resource, tracked by BDF.
//
// Resource naming: one pool per Virtual Function (pfName + VF index).  Each
// pool's selector pins exactly one BDF, so kubelet allocates the specific VF
// EVE intended for the VM — eliminating the "random VF from the pool" failure
// mode that occurs with a per-PF pool where any free BDF is fungible.
// ============================================================================

// sriovResourceName returns the Kubernetes extended-resource name advertised by
// the sriov-network-device-plugin for ONE specific VF.  Must match the
// resourceName/resourcePrefix in the device plugin ConfigMap.
//
// Per-VF naming (eth2_vf0, eth2_vf1, ...) is the lever EVE uses to pin a
// specific BDF to a specific VMI: the per-VF pool's pciAddresses selector
// constrains the device plugin to advertise that one BDF under this name,
// so a VMI requesting eve.network/eth2_vf3 can only ever receive BDF
// virtfn3 of eth2 — no pool-level scheduling lottery.
func sriovResourceName(pfName string, vfIdx uint8) string {
	return fmt.Sprintf("eve.network/%s_vf%d", pfName, vfIdx)
}

// sriovNADName returns the NetworkAttachmentDefinition name for ONE specific
// VF.  Per-VF NADs (not per-PF) so distinct Multus annotations exist for
// every VF the VMI uses; KubeVirt translates each Interface->Network pairing
// into a separate pod-networks annotation entry, and Multus invokes sriov-cni
// once per entry.  VLAN, when configured, lives in the NAD's CNI config.
func sriovNADName(pfName string, vfIdx uint8, vlanID uint32) string {
	if vlanID == 0 {
		return fmt.Sprintf("sriov-%s-vf%d", pfName, vfIdx)
	}
	return fmt.Sprintf("sriov-%s-vf%d-vlan%d", pfName, vfIdx, vlanID)
}

// ensureSRIOVNAD creates (or refreshes) the NetworkAttachmentDefinition that
// binds Multus calls to sriov-cni for ONE specific VF.  Idempotent: existing
// NADs are updated only when the embedded CNI config has drifted (e.g. VLAN
// change).
//
// The annotation k8s.v1.cni.cncf.io/resourceName tells Multus to ask the
// sriov-network-device-plugin for THIS VF's pool when wiring the pod; the
// plugin injects PCIDEVICE_<pool> (containing that single BDF) into the pod
// env, and sriov-cni reads it to bind that exact VF.
func ensureSRIOVNAD(kubeConfig *rest.Config, pfName string, vfIdx uint8, vlanID uint32) error {
	nadClient, err := netattdefclient.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("ensureSRIOVNAD: can't create NAD clientset: %v", err)
	}

	nadName := sriovNADName(pfName, vfIdx, vlanID)
	resourceName := sriovResourceName(pfName, vfIdx)
	cniConfig := fmt.Sprintf(
		`{"cniVersion":"0.3.1","name":%q,"type":"sriov"}`,
		nadName)
	if vlanID > 0 {
		cniConfig = fmt.Sprintf(
			`{"cniVersion":"0.3.1","name":%q,"type":"sriov","vlan":%d}`,
			nadName, vlanID)
	}
	desired := &netattdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nadName,
			Namespace: kubeapi.EVEKubeNameSpace,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/resourceName": resourceName,
			},
		},
		Spec: netattdefv1.NetworkAttachmentDefinitionSpec{Config: cniConfig},
	}

	nads := nadClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(kubeapi.EVEKubeNameSpace)

	existing, err := nads.Get(context.Background(), nadName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		if _, err := nads.Create(context.Background(), desired, metav1.CreateOptions{}); err != nil && !errors.IsAlreadyExists(err) {
			return fmt.Errorf("ensureSRIOVNAD: can't create NAD %s: %v", nadName, err)
		}
		logrus.Infof("ensureSRIOVNAD: created NAD %s -> resource %s (vlan %d)",
			nadName, resourceName, vlanID)
		return nil
	}
	if err != nil {
		return fmt.Errorf("ensureSRIOVNAD: can't get NAD %s: %v", nadName, err)
	}

	if existing.Spec.Config == cniConfig &&
		existing.Annotations["k8s.v1.cni.cncf.io/resourceName"] == resourceName {
		return nil
	}

	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Annotations["k8s.v1.cni.cncf.io/resourceName"] = resourceName
	existing.Spec.Config = cniConfig
	if _, err := nads.Update(context.Background(), existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("ensureSRIOVNAD: can't update NAD %s: %v", nadName, err)
	}
	logrus.Infof("ensureSRIOVNAD: updated NAD %s -> resource %s (vlan %d)",
		nadName, resourceName, vlanID)
	return nil
}

// attachSRIOVInterfaces wires every SR-IOV VF in vfs into the VMI as a KubeVirt
// SR-IOV interface backed by a Multus NetworkAttachmentDefinition.
//
// Per-VF MAC: we set Interface.MacAddress from the IoBundle's MacAddr.  This is
// the user-configured MAC (possibly via the EVE app config); the in-VM driver
// observes this exact MAC regardless of what the PF admin-MAC was programmed
// to, fixing the "all VMs see the same MAC" symptom of the HostDevice path.
//
// Per-VF BDF selection: the resource pool counts in the device plugin guarantee
// that two VMIs requesting the same pool get different VFs.  No nodeSelector
// stamping is needed because the scheduler will only place the VMI on a node
// where the resource pool has free capacity.
func attachSRIOVInterfaces(kubeConfig *rest.Config, vmi *v1.VirtualMachineInstance, vfs []pciDevice, appUUID uuid.UUID) ([]sriovVFRef, error) {
	// VF refs accumulated for the caller to remember on the vmiMetaData; on
	// Stop/Delete/Cleanup we use these to zero the per-VF admin MAC.
	vfRefs := make([]sriovVFRef, 0, len(vfs))

	for i, pa := range vfs {
		pfName := pa.ioBundle.VfParams.PFIface
		if pfName == "" {
			// domainmgr.checkAndFillIoBundle populates VfParams.PFIface at
			// parse time, but the VF may not have existed in sysfs yet (e.g.
			// sriov_numvfs not written when the phyAdapter list was first
			// processed).  Recover from sysfs now — the VF must exist by the
			// time we're attaching it to a VMI.
			derived, err := sriov.GetPFIfaceFromVFBDF(pa.ioBundle.PciLong)
			if err != nil {
				return nil, fmt.Errorf("attachSRIOVInterfaces: VF %s has empty PFIface "+
					"and sysfs lookup failed: %w", pa.ioBundle.PciLong, err)
			}
			logrus.Warnf("attachSRIOVInterfaces: VF %s arrived without PFIface; "+
				"recovered PFIface=%s from sysfs", pa.ioBundle.PciLong, derived)
			pfName = derived
		}
		// Resolve VF index authoritatively from Phylabel — VfParams.Index is
		// 0 for every statically-declared VF until checkAndFillIoBundle has
		// run, which can produce per-VM NADs all pointing at "<pf>-vf0" and
		// resource requests all targeting "<pf>_vf0".  Phylabel ("eth2vf5")
		// is set by the device model and stable.
		vfIdx, pfFromLabel, err := sriov.ParseVfIfaceName(pa.ioBundle.Phylabel)
		if err != nil {
			return nil, fmt.Errorf("attachSRIOVInterfaces: can't parse VF index "+
				"from Phylabel %q: %w", pa.ioBundle.Phylabel, err)
		}
		// Re-confirm PF name from the Phylabel parse as a final safety net.
		// Sysfs already filled pfName above; only override if sysfs gave us
		// the empty string (extremely unusual).
		if pfName == "" {
			pfName = pfFromLabel
		}
		vlanID := uint32(pa.ioBundle.VfParams.VlanID)

		// Per-VF NAD + per-VF resource pool.  Each VF has its own pool of size
		// 1 with a pciAddresses selector pinning that exact BDF, so kubelet's
		// allocation is deterministic — VM asks for eve.network/<pf>_vf<i> and
		// receives BDF virtfn<i> of <pf>, never anything else.
		if err := ensureSRIOVNAD(kubeConfig, pfName, vfIdx, vlanID); err != nil {
			return nil, err
		}

		// Remember this (PF, VF index) for the caller to stash on vmiMetaData;
		// we'll iterate it in Stop/Delete/Cleanup to clear admin MAC.
		vfRefs = append(vfRefs, sriovVFRef{
			PfIface: pfName,
			Index:   vfIdx,
		})

		// Backstop: ensure this VF is bound to vfio-pci before we hand the VMI
		// off to KubeVirt.  setupVf binds at boot, but in the field we've seen
		// VFs end up driverless when a per-VF createVfIoBundle error short-
		// circuited the bind loop on an earlier code path, or when iavf
		// re-grabbed the VF after an autoprobe race.  BindVFToVfioPCI is
		// idempotent (no-ops when already vfio-pci), so this is cheap on the
		// happy path and self-healing on the bad one.  Non-fatal here: if the
		// bind fails, kubelet will refuse to schedule the VMI and the user will
		// see the resource shortage in events — better diagnostic than a
		// silently-half-attached VM.
		if err := sriov.BindVFToVfioPCI(pa.ioBundle.PciLong); err != nil {
			logrus.Warnf("attachSRIOVInterfaces: backstop bind VF %s to vfio-pci: %v",
				pa.ioBundle.PciLong, err)
		}

		// KubeVirt SR-IOV interfaces must reference a Multus network of the
		// same Name.  Use a stable, non-conflicting interface name per VF.
		ifName := fmt.Sprintf("sriov%d", i+1)
		nadName := sriovNADName(pfName, vfIdx, vlanID)

		iface := v1.Interface{
			Name: ifName,
			InterfaceBindingMethod: v1.InterfaceBindingMethod{
				SRIOV: &v1.InterfaceSRIOV{},
			},
		}
		// MAC selection priority:
		//   1. User-configured MacAddr from the IoBundle, if it's not just
		//      a stale copy of the parent PF's hardware MAC.  Some EVE
		//      config paths set every VF IoBundle's MacAddr to the PF MAC
		//      when per-VF user config is absent — that would make every
		//      VM see the same MAC (the original bug this path fixes).
		//   2. A deterministic locally-administered MAC generated from
		//      (appUUID, vfBDF) using the same SHA-256 + OUI 02:16:3E
		//      scheme that zedrouter uses for switch-network VIFs (see
		//      pkg/pillar/cmd/zedrouter/ipam.go:generateAppMac).  Stable
		//      across reboots, unique per (app, VF), and recognizable as
		//      EVE-generated.
		mac, source := resolveVFMac(pa, appUUID)
		if mac != "" {
			iface.MacAddress = mac
		}
		logrus.Infof("attachSRIOVInterfaces: VF %s MAC %s (source=%s)",
			pa.ioBundle.PciLong, mac, source)

		vmi.Spec.Domain.Devices.Interfaces = append(
			vmi.Spec.Domain.Devices.Interfaces, iface)

		vmi.Spec.Networks = append(vmi.Spec.Networks, v1.Network{
			Name: ifName,
			NetworkSource: v1.NetworkSource{
				Multus: &v1.MultusNetwork{
					NetworkName: kubeapi.EVEKubeNameSpace + "/" + nadName,
				},
			},
		})

		logrus.Infof("attachSRIOVInterfaces: VMI iface %s -> NAD %s "+
			"(VF %s, PF %s, VF-index %d, VLAN %d, MAC %q)",
			ifName, nadName, pa.ioBundle.PciLong, pfName,
			pa.ioBundle.VfParams.Index, vlanID, pa.ioBundle.MacAddr)
	}
	return vfRefs, nil
}

// derivePFMacFromVFSysfs returns the hardware MAC of the Physical Function
// that owns the given Virtual Function PCI BDF, formatted lowercase
// "xx:xx:xx:xx:xx:xx" as the kernel exposes it.
//
// Used by attachSRIOVInterfaces to detect IoBundle MacAddr fields that have
// been (incorrectly) populated with the PF's hardware MAC — a pattern that
// shows up when the EVE device model lacks per-VF MAC config and would cause
// every VM sharing the pool to see the same MAC.
//
// Path: /sys/bus/pci/devices/<vf-bdf>/physfn/net/<ifname>/address
func derivePFMacFromVFSysfs(vfBDF string) (string, error) {
	netDir := filepath.Join("/sys/bus/pci/devices", vfBDF, "physfn", "net")
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return "", fmt.Errorf("readdir %s: %w", netDir, err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("no netdev under %s", netDir)
	}
	addrFile := filepath.Join(netDir, entries[0].Name(), "address")
	raw, err := os.ReadFile(addrFile)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", addrFile, err)
	}
	return strings.ToLower(strings.TrimSpace(string(raw))), nil
}

// resolveVFMac picks the MAC address to assign to a VF VMI interface.
// Returns the chosen MAC string (in canonical "xx:xx:xx:xx:xx:xx" form) and a
// short source label for logging ("config" or "generated").
//
// Priority:
//  1. pa.ioBundle.MacAddr, when it's set and not a stale copy of the parent
//     PF's hardware MAC.
//  2. A deterministic locally-administered MAC generated from (appUUID, vfBDF).
//
// Returns "" only if generation itself fails — never silently leaves a VMI
// without a stable identity.
func resolveVFMac(pa pciDevice, appUUID uuid.UUID) (string, string) {
	cfgMac := strings.TrimSpace(pa.ioBundle.MacAddr)
	if cfgMac != "" {
		pfMac, err := derivePFMacFromVFSysfs(pa.ioBundle.PciLong)
		if err != nil {
			logrus.Warnf("can't trust cfgMac → fall through to generated")
		}
		if pfMac == "" || !strings.EqualFold(cfgMac, pfMac) {
			if hw, err := net.ParseMAC(cfgMac); err == nil {
				return hw.String(), "config"
			}
			// fall through to generated
			return strings.ToLower(cfgMac), "config"
		}
		// cfgMac is the PF MAC — bogus per-VF value, fall through to generation.
	}
	return generateVFMac(appUUID, pa.ioBundle.PciLong).String(), "generated"
}

// generateVFMac returns a stable, locally-administered MAC for a VF assigned to
// a given app instance.
//
// Uses the same scheme zedrouter applies to VIFs on switch network instances
// (pkg/pillar/cmd/zedrouter/ipam.go:generateAppMac):
//
//   - SHA-256 hash over (appUUID || vfBDF) — both inputs are stable and
//     unique, so the same VF assigned to the same app always yields the same
//     MAC across reboots and across cluster failovers.
//   - OUI 02:16:3E (locally-administered, unicast).  This OUI is reserved for
//     XenSource originally and is what EVE has used for VIF MAC generation
//     for years; reusing it keeps EVE-generated MACs visually consistent
//     and easy to recognize in tcpdump / arp tables.
//
// The resulting MAC is essentially guaranteed unique across (app, VF) pairs in
// the enterprise — collision probability with 24 random bits and 1000 VFs is
// well under 0.01 percent.
func generateVFMac(appUUID uuid.UUID, vfBDF string) net.HardwareAddr {
	h := sha256.New()
	h.Write(appUUID[:])
	h.Write([]byte(vfBDF))
	hash := h.Sum(nil)
	return net.HardwareAddr{0x02, 0x16, 0x3e, hash[0], hash[1], hash[2]}
}
