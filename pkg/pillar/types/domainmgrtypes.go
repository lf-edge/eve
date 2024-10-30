// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/kube/cnirpc"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/utils/cloudconfig"
)

// DomainConfig contains information DomainManager needs to boot and halt domains
// If the the version (in UUIDandVersion) changes then the domain needs to
// halted and booted?? NO, because an ACL change from ZedControl would bump
// the version. Who determines which changes require halt+reboot?
// Do we need an explicit interlock with ZedManager when a reboot
// is needed? For instance, ZedManager could remove the DomainConfig, what for
// DomainStatus to be deleted, then re-create the DomainConfig.
type DomainConfig struct {
	UUIDandVersion UUIDandVersion
	DisplayName    string // Use as name for domU? DisplayName+version?
	Activate       bool   // Actually start the domU as opposed to prepare
	AppNum         int    // From networking; makes the name unique
	VmConfig
	DisableLogs    bool
	GPUConfig      string
	DiskConfigList []DiskConfig
	VifList        []VifConfig
	IoAdapterList  []IoAdapter
	// KubeImageName: is the container image reference we pass to domainmgr to launch a native container
	// in kubevirt eve
	KubeImageName string
	// if this node is the DNiD of the App
	IsDNidNode bool

	// XXX: to be deprecated, use CipherBlockStatus instead
	CloudInitUserData *string `json:"pubsub-large-CloudInitUserData"` // base64-encoded

	// CipherBlockStatus, for encrypted cloud-init data
	CipherBlockStatus

	// MetaDataType for select type of metadata service for app
	MetaDataType MetaDataType

	// Service flag indicates that we want to start app instance
	// with options defined in org.mobyproject.config label of image provided by linuxkit
	Service bool

	// All changes to the cloud-init config are tracked using this version field -
	// once the version is changed cloud-init tool restarts in a guest.
	// See getCloudInitVersion() and createCloudInitISO() for details.
	CloudInitVersion uint32
}

// MetaDataType of metadata service for app
// must match the values in the proto definition
type MetaDataType uint8

// types of metadata service for app if CloudInitUserData provided
const (
	MetaDataDrive MetaDataType = iota + 0 // Default
	MetaDataNone
	MetaDataOpenStack
	MetaDataDriveMultipart // Process multipart MIME for application
)

// String returns the string name
func (metaDataType MetaDataType) String() string {
	switch metaDataType {
	case MetaDataDrive:
		return "MetaDataDrive"
	case MetaDataNone:
		return "MetaDataNone"
	case MetaDataOpenStack:
		return "MetaDataOpenStack"
	case MetaDataDriveMultipart:
		return "MetaDataDriveMultipart"
	default:
		return fmt.Sprintf("Unknown MetaDataType %d", metaDataType)
	}
}

// The whole domain is considered as a container-based if the first disk
// has the 'CONTAINER' format.
func (config DomainConfig) IsOCIContainer() bool {
	if len(config.DiskConfigList) > 0 &&
		config.DiskConfigList[0].Format == zconfig.Format_CONTAINER {
		return true
	}
	return false
}

// GetTaskName assigns a unique name to the task representing this domain
// FIXME: given config.UUIDandVersion.Version part not sure config.AppNum is needed for uniqueness
func (config DomainConfig) GetTaskName() string {
	return config.UUIDandVersion.UUID.String() + "." +
		config.UUIDandVersion.Version + "." +
		strconv.Itoa(config.AppNum)
}

// DomainnameToUUID does the reverse of GetTaskName
func DomainnameToUUID(name string) (uuid.UUID, string, int, error) {
	// FIXME: we can likely drop this altogether
	if name == "Domain-0" {
		return uuid.UUID{}, "", 0, nil
	}

	res := strings.Split(name, ".")
	if len(res) != 3 {
		return uuid.UUID{}, "", 0, fmt.Errorf("Unknown domainname format %s",
			name)
	}
	id, err := uuid.FromString(res[0])
	if err != nil {
		return uuid.UUID{}, "", 0, fmt.Errorf("Bad UUID %s: %w",
			res[0], err)
	}
	appNum, err := strconv.Atoi(res[2])
	if err != nil {
		return uuid.UUID{}, "", 0, fmt.Errorf("Bad appNum %s: %w",
			res[2], err)
	}
	return id, res[1], appNum, nil
}

// Key returns domain UUID string
func (config DomainConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
}

// VirtualizationModeOrDefault sets the default to PV
func (config DomainConfig) VirtualizationModeOrDefault() VmMode {
	switch config.VirtualizationMode {
	case PV, HVM, FML, NOHYPER, LEGACY:
		return config.VirtualizationMode
	default:
		return PV
	}
}

// GetPVCNameFromVolumeKey gets the pvcName from volume key
func (status DiskStatus) GetPVCNameFromVolumeKey() (string, error) {
	volumeIDAndGeneration := status.VolumeKey
	generation := strings.Split(volumeIDAndGeneration, "#")
	volUUID, err := uuid.FromString(generation[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse volUUID: %w", err)
	}

	generationCounter, err := strconv.ParseInt(generation[1], 10, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse GenerationCounter: %w", err)
	}

	pvcName := fmt.Sprintf("%s-pvc-%d", volUUID, generationCounter)

	return pvcName, nil
}

// LogCreate :
func (config DomainConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DomainConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activate-bool", config.Activate).
		AddField("enable-vnc-bool", config.EnableVnc).
		AddField("enable-vnc-shim-vm-bool", config.EnableVncShimVM).
		Noticef("domain config create")
}

// LogModify :
func (config DomainConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DomainConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())

	oldConfig, ok := old.(DomainConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DomainConfig type")
	}
	if oldConfig.Activate != config.Activate ||
		oldConfig.EnableVnc != config.EnableVnc ||
		oldConfig.EnableVncShimVM != config.EnableVncShimVM {

		logObject.CloneAndAddField("activate-bool", config.Activate).
			AddField("enable-vnc-bool", config.EnableVnc).
			AddField("enable-vnc-shim-vm-bool", config.EnableVncShimVM).
			AddField("old-activate-bool", oldConfig.Activate).
			AddField("old-enable-vnc-bool", oldConfig.EnableVnc).
			AddField("old-enable-vnc-shim-vm-bool", oldConfig.EnableVncShimVM).
			Noticef("domain config modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Noticef("domain config modify other change")
	}
}

// LogDelete :
func (config DomainConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DomainConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	logObject.CloneAndAddField("activate-bool", config.Activate).
		AddField("enable-vnc-bool", config.EnableVnc).
		AddField("enable-vnc-shim-vm-bool", config.EnableVncShimVM).
		Noticef("domain config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config DomainConfig) LogKey() string {
	return string(base.DomainConfigLogType) + "-" + config.Key()
}

// VmConfig, Some of these items can be overridden by matching Targets in
// StorageConfigList. For example, a Target of "kernel" means to set/override
// the Kernel attribute below.
//
// Keep in mind that the fields in this structure are considered
// so-called "fixed resources", which means that the virtual machine
// must be restarted before changes to the field will take effect.
type VmConfig struct {
	Kernel     string // default ""
	Ramdisk    string // default ""
	Memory     int    // in kbytes; Rounded up to Mbytes for xen
	MaxMem     int    // in kbytes; Default equal to 'Memory', so no ballooning for xen
	VCpus      int    // default 1
	MaxCpus    int    // default VCpus
	RootDev    string // default "/dev/xvda1"
	ExtraArgs  string // added to bootargs
	BootLoader string // default ""
	// For CPU pinning
	CPUs string // default "", list of "1,2"
	// Needed for device passthru
	DeviceTree string // default ""; sets device_tree
	// Example: device_tree="guest-gpio.dtb"
	DtDev []string // default nil; sets dtdev
	// Example, DtDev=["/smb/gpio@f7020000","/smb/gpio@f8013000"]
	IRQs []int // default nil; sets irqs
	// Example, IRQs=[88,86]
	IOMem []string // default nil; sets iomem
	// Example, IOMem=["0xf7020,1","0xf8013,1"]
	VirtualizationMode VmMode
	EnableVnc          bool
	VncDisplay         uint32
	VncPasswd          string
	CPUsPinned         bool
	VMMMaxMem          int // in kbytes
	EnableVncShimVM    bool
}

// VmMode is the type for the virtualization mode
type VmMode uint8

const (
	PV VmMode = iota + 0 // Default
	HVM
	Filler
	FML
	NOHYPER
	LEGACY
)

// Task represents any runnable entity on EVE
type Task interface {
	Setup(DomainStatus, DomainConfig, *AssignableAdapters,
		*ConfigItemValueMap, *os.File) error
	VirtualTPMSetup(domainName, agentName string, ps *pubsub.PubSub, warnTime, errTime time.Duration) error
	VirtualTPMTerminate(domainName string) error
	VirtualTPMTeardown(domainName string) error
	Create(string, string, *DomainConfig) (int, error)
	Start(string) error
	Stop(string, bool) error
	Delete(string) error
	Info(string) (int, SwState, error)
	Cleanup(string) error
}

type DomainStatus struct {
	UUIDandVersion UUIDandVersion
	DisplayName    string
	State          SwState // BOOTING and above?
	Activated      bool    // XXX remove??
	AppNum         int     // From networking; makes the name unique
	PendingAdd     bool
	PendingModify  bool
	PendingDelete  bool
	DomainName     string // Name of Xen domain
	DomainId       int
	BootTime       time.Time
	DiskStatusList []DiskStatus
	VifList        []VifInfo
	IoAdapterList  []IoAdapter
	DisableLogs    bool
	TriedCount     int
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
	ConfigFailed   bool
	BootFailed     bool
	AdaptersFailed bool
	OCIConfigDir   string                     // folder holding an OCI Image config for this domain (empty string means no config)
	EnvVariables   map[string]string          // List of environment variables to be set in container
	WritableFiles  []cloudconfig.WritableFile // List of files from CloudInit scripts to be created in container
	VmConfig                                  // From DomainConfig
	Service        bool
	// VirtualTPM is a flag to signal the hypervisor implementation
	// that vTPM is available for the domain.
	VirtualTPM bool
	// FmlCustomResolution is the custom resolution for FML mode,
	// xxx: this should be moved to VmConfig
	FmlCustomResolution string
	// if this node is the DNiD of the App
	IsDNidNode bool
	// the device name is used for kube node name
	// Need to pass in from domainmgr to hypervisor context commands
	NodeName string
}

func (status DomainStatus) Key() string {
	return status.UUIDandVersion.UUID.String()
}

func (status DomainStatus) Pending() bool {
	return status.PendingAdd || status.PendingModify || status.PendingDelete
}

// VifInfoByVif looks up based on the name aka Vif
func (status DomainStatus) VifInfoByVif(vif string) *VifInfo {
	for i := range status.VifList {
		net := &status.VifList[i]
		if net.Vif == vif {
			return net
		}
	}
	return nil
}

// LogCreate :
func (status DomainStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DomainStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("activated-bool", status.Activated).
		Noticef("domain status create")
}

// LogModify :
func (status DomainStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DomainStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())

	oldStatus, ok := old.(DomainStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DomainStatus type")
	}
	if oldStatus.State != status.State ||
		oldStatus.Activated != status.Activated {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("activated-bool", status.Activated).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-activated-bool", oldStatus.Activated).
			Noticef("domain status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("domain status modify other change")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("activated-bool", status.Activated).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Noticef("domain status modify")
	}
}

// LogDelete :
func (status DomainStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DomainStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("activated-bool", status.Activated).
		Noticef("domain status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status DomainStatus) LogKey() string {
	return string(base.DomainStatusLogType) + "-" + status.Key()
}

// VlanInfo : applicable only for VIFs inside switch network instances.
type VlanInfo struct {
	Start   uint32
	End     uint32
	IsTrunk bool
}

// VifConfig configure vif
type VifConfig struct {
	Bridge string
	Vif    string
	Mac    net.HardwareAddr
	MTU    uint16
	// PodVif is only valid in the Kubernetes mode.
	PodVif PodVIF
}

// PodVIF : configuration parameters for VIF connecting Kubernetes pod with the host.
type PodVIF struct {
	GuestIfName string
	IPAM        cnirpc.PodIPAMConfig
}

// VifInfo store info about vif
type VifInfo struct {
	VifConfig
	VifUsed string // Has -emu in name in Status if appropriate
}

// DomainManager will pass these to the xen xl config file
// The vdev is automatically assigned as xvd[x], where X is a, b, c etc,
// based on the order in the DiskList
// Note that vdev in general can be hd[x], xvd[x], sd[x] but here we only
// use xvd
type DiskConfig struct {
	VolumeKey    string
	FileLocation string // Location of the volume
	ReadOnly     bool
	Format       zconfig.Format
	MountDir     string
	DisplayName  string
	WWN          string
	Target       zconfig.Target
	CustomMeta   string
}

type DiskStatus struct {
	VolumeKey    string
	ReadOnly     bool
	FileLocation string // From DiskConfig
	Format       zconfig.Format
	MountDir     string
	DisplayName  string
	Devtype      string // XXX used internally by hypervisor; deprecate?
	Vdev         string // Allocated
	WWN          string
	CustomMeta   string
}

// DomainMetric carries CPU and memory usage. UUID=devUUID for the dom0/host metrics overhead
type DomainMetric struct {
	UUIDandVersion    UUIDandVersion
	CPUTotalNs        uint64 // Nanoseconds since Domain boot scaled by #CPUs
	CPUScaled         uint32 // The scale factor which was applied
	AllocatedMB       uint32
	UsedMemory        uint32 // in MB
	MaxUsedMemory     uint32 // in MB
	AvailableMemory   uint32 // in MB
	UsedMemoryPercent float64
	LastHeard         time.Time
	Activated         bool
	NodeName          string // the name of the kubernetes node on which the app is currently running
}

// Key returns the key for pubsub
func (metric DomainMetric) Key() string {
	return metric.UUIDandVersion.UUID.String()
}

// LogCreate :
func (metric DomainMetric) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DomainMetricLogType, "",
		metric.UUIDandVersion.UUID, metric.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Domain metric create")
}

// LogModify :
func (metric DomainMetric) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DomainMetricLogType, "",
		metric.UUIDandVersion.UUID, metric.LogKey())

	oldMetric, ok := old.(DomainMetric)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DomainMetric type")
	}
	// XXX remove? XXX huge?
	logObject.CloneAndAddField("diff", cmp.Diff(oldMetric, metric)).
		Metricf("Domain metric modify")
}

// LogDelete :
func (metric DomainMetric) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DomainMetricLogType, "",
		metric.UUIDandVersion.UUID, metric.LogKey())
	logObject.Metricf("Domain metric delete")

	base.DeleteLogObject(logBase, metric.LogKey())
}

// LogKey :
func (metric DomainMetric) LogKey() string {
	return string(base.DomainMetricLogType) + "-" + metric.Key()
}

// HostMemory reports global stats. Published under "global" key
// Note that Ncpus is the set of physical CPUs which is different
// than the set of CPUs assigned to dom0
type HostMemory struct {
	TotalMemoryMB uint64
	FreeMemoryMB  uint64
	UsedEveMB     uint64
	KmemUsedEveMB uint64
	Ncpus         uint32
}

// Key returns the key for pubsub
func (hm HostMemory) Key() string {
	return "global"
}

// LogCreate :
func (hm HostMemory) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.HostMemoryLogType, "",
		nilUUID, hm.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Host memory create")
}

// LogModify :
func (hm HostMemory) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.HostMemoryLogType, "",
		nilUUID, hm.LogKey())

	oldHm, ok := old.(HostMemory)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of HostMemory type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldHm, hm)).
		Metricf("Host memory modify")
}

// LogDelete :
func (hm HostMemory) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.HostMemoryLogType, "",
		nilUUID, hm.LogKey())
	logObject.Metricf("Host memory delete")

	base.DeleteLogObject(logBase, hm.LogKey())
}

// LogKey :
func (hm HostMemory) LogKey() string {
	return string(base.HostMemoryLogType) + "-" + hm.Key()
}

// Capabilities represents device information
type Capabilities struct {
	HWAssistedVirtualization bool // VMX/SVM for amd64 or Arm virtualization extensions for arm64
	IOVirtualization         bool // I/O Virtualization support
	CPUPinning               bool // CPU Pinning support
	UseVHost                 bool // vHost support
}
