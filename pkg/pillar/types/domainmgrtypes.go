// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"os"
	"time"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// The information DomainManager needs to boot and halt domains
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
	DiskConfigList []DiskConfig
	VifList        []VifInfo
	IoAdapterList  []IoAdapter

	// XXX: to be deprecated, use CipherBlockStatus instead
	CloudInitUserData *string // base64-encoded
	// Container related info
	IsContainer bool // Is this Domain for a Container?

	// CipherBlockStatus, for encrypted cloud-init data
	CipherBlockStatus
}

func (config DomainConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
}

// VirtualizationModeOrDefault sets the default to PV
func (config DomainConfig) VirtualizationModeOrDefault() VmMode {
	switch config.VirtualizationMode {
	case PV, HVM, FML, NOHYPER:
		return config.VirtualizationMode
	default:
		return PV
	}
}

// LogCreate :
func (config DomainConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DomainConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activate", config.Activate).
		AddField("enable-vnc", config.EnableVnc).
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
		oldConfig.EnableVnc != config.EnableVnc {

		logObject.CloneAndAddField("activate", config.Activate).
			AddField("enable-vnc", config.EnableVnc).
			AddField("old-activate", oldConfig.Activate).
			AddField("old-enable-vnc", oldConfig.EnableVnc).
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
	logObject.CloneAndAddField("activate", config.Activate).
		AddField("enable-vnc", config.EnableVnc).
		Noticef("domain config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config DomainConfig) LogKey() string {
	return string(base.DomainConfigLogType) + "-" + config.Key()
}

// Some of these items can be overridden by matching Targets in
// StorageConfigList. For example, a Target of "kernel" means to set/override
// the Kernel attribute below.
type VmConfig struct {
	Kernel     string // default ""
	Ramdisk    string // default ""
	Memory     int    // in kbytes; Rounded up to Mbytes for xen
	MaxMem     int    // Default not set i.e. no ballooning
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
}

type VmMode uint8

const (
	PV VmMode = iota + 0 // Default
	HVM
	Filler
	FML
	NOHYPER
)

// Task represents any runnable entity on EVE
type Task interface {
	Setup(DomainStatus, DomainConfig, *AssignableAdapters, *os.File) error
	Create(string, string, *DomainConfig) (int, error)
	Start(string, int) error
	Stop(string, int, bool) error
	Delete(string, int) error
	Info(string, int) (int, SwState, error)
}

type DomainStatus struct {
	UUIDandVersion     UUIDandVersion
	DisplayName        string
	State              SwState // BOOTING and above?
	Activated          bool    // XXX remove??
	AppNum             int     // From networking; makes the name unique
	PendingAdd         bool
	PendingModify      bool
	PendingDelete      bool
	DomainName         string // Name of Xen domain
	DomainId           int
	BootTime           time.Time
	DiskStatusList     []DiskStatus
	VifList            []VifInfo
	IoAdapterList      []IoAdapter
	VirtualizationMode VmMode
	EnableVnc          bool
	VncDisplay         uint32
	VncPasswd          string
	TriedCount         int
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
	BootFailed     bool
	AdaptersFailed bool
	IsContainer    bool              // Is this Domain for a Container?
	EnvVariables   map[string]string // List of environment variables to be set in container
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
		AddField("activated", status.Activated).
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
			AddField("activated", status.Activated).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-activated", oldStatus.Activated).
			Noticef("domain status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("domain status modify other change")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("activated", status.Activated).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Errorf("domain status modify")
	}
}

// LogDelete :
func (status DomainStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DomainStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("activated", status.Activated).
		Noticef("domain status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status DomainStatus) LogKey() string {
	return string(base.DomainStatusLogType) + "-" + status.Key()
}

type VifInfo struct {
	Bridge  string
	Vif     string
	VifUsed string // Has -emu in name in Status if appropriate
	Mac     string
}

// DomainManager will pass these to the xen xl config file
// The vdev is automatically assigned as xvd[x], where X is a, b, c etc,
// based on the order in the DiskList
// Note that vdev in general can be hd[x], xvd[x], sd[x] but here we only
// use xvd
type DiskConfig struct {
	FileLocation string // Location of the volume
	ReadOnly     bool
	Format       zconfig.Format
	MountDir     string
	DisplayName  string
}

type DiskStatus struct {
	ReadOnly     bool
	FileLocation string // From DiskConfig
	Format       zconfig.Format
	MountDir     string
	DisplayName  string
	Devtype      string // XXX used internally by hypervisor; deprecate?
	Vdev         string // Allocated
}

// DomainMetric carries CPU and memory usage. UUID=devUUID for the dom0/host metrics overhead
type DomainMetric struct {
	UUIDandVersion    UUIDandVersion
	CPUTotal          uint64 // Seconds since Domain boot
	UsedMemory        uint32
	AvailableMemory   uint32
	UsedMemoryPercent float64
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
