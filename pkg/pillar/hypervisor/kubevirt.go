// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"bufio"
	"context"
	"crypto/tls"
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

// VM instance meta data structure.
type vmiMetaData struct {
	vmi      *v1.VirtualMachineInstance // Handle to the VM instance
	domainId int                        // DomainId understood by domainmgr in EVE
}

type kubevirtContext struct {
	ctrdContext
	devicemodel       string
	capabilities      *types.Capabilities
	vmiList           map[string]*vmiMetaData
	virthandlerIPAddr string
	prevDomainMetric  map[string]types.DomainMetric
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

	logrus.Infof("PRAMOD Setup called for Domain: %s", domainName)

	// Take eve domain config and convert to VMI config
	if err := ctx.CreateVMIConfig(domainName, config, status, diskStatusList, aa, file); err != nil {
		return logError("failed to build kube config: %v", err)
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

	// Now we have VirtualMachine Instance object, save it to config file for debug purposes
	// and save it in context which will be used to start VM in Start() call
	meta := vmiMetaData{
		vmi:      vmi,
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

	vmi := ctx.vmiList[domainName].vmi

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

// Create is no-op for kubevirt, just return the domainId we already have.
func (ctx kubevirtContext) Create(domainName string, cfgFilename string, config *types.DomainConfig) (int, error) {
	return ctx.vmiList[domainName].domainId, nil
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

	res, err := getVMIStatus(domainName)

	if err != nil {
		return 0, types.BROKEN, logError("domain %s failed to get info: %v", domainName, err)
	}

	if effectiveDomainState, matched := stateMap[res]; !matched {
		return 0, types.BROKEN, logError("domain %s reported to be in unexpected state %s", domainName, res)
	} else {
		return ctx.vmiList[domainName].domainId, effectiveDomainState, nil
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

// Inspired from kvm.go
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

func (ctx kubevirtContext) GetDomsCPUMem() (map[string]types.DomainMetric, error) {
	logrus.Infof("GetDomsCPUMem: enter")

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
			strings.Contains(line, eveNameSpace) {

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

			if _, ok := res[vmiName]; !ok {
				res[vmiName] = types.DomainMetric{
					UUIDandVersion: types.UUIDandVersion{},
					CPUScaled:      1,
				}
			}
			fillMetrics(res, vmiName, metricName, parsedValue)
			logrus.Infof("GetDomsCPUMem: vmi %s, metric name %s, value %v", vmiName, metricName, parsedValue)
		}
	}

	for n, r := range res {
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
	logrus.Infof("GetDomsCPUMem: %d VMs: %+v", len(ctx.vmiList), res)
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
	logrus.Infof("getVirtHandlerIPAddr: %s", ctx.virthandlerIPAddr)
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

func fillMetrics(res map[string]types.DomainMetric, vmiName, metricName string, value interface{}) {
	if _, ok := res[vmiName]; !ok {
		logrus.Infof("fillMetrics, vmiName %s not in map", vmiName)
		return
	}

	r := res[vmiName]
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
	res[vmiName] = r
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
