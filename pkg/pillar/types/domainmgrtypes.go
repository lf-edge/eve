// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
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

func (config DomainConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// VirtualizationModeOrDefault sets the default to PV
func (config DomainConfig) VirtualizationModeOrDefault() VmMode {
	switch config.VirtualizationMode {
	case PV, HVM, FML:
		return config.VirtualizationMode
	default:
		return PV
	}
}

// LogCreate :
func (config DomainConfig) LogCreate() {
	logObject := base.NewLogObject(base.DomainConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activate", config.Activate).
		AddField("enable-vnc", config.EnableVnc).
		Infof("domain config create")
}

// LogModify :
func (config DomainConfig) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.DomainConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())

	oldConfig, ok := old.(DomainConfig)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of DomainConfig type")
	}
	if oldConfig.Activate != config.Activate ||
		oldConfig.EnableVnc != config.EnableVnc {

		logObject.CloneAndAddField("activate", config.Activate).
			AddField("enable-vnc", config.EnableVnc).
			AddField("old-activate", oldConfig.Activate).
			AddField("old-enable-vnc", oldConfig.EnableVnc).
			Infof("domain config modify")
	}

}

// LogDelete :
func (config DomainConfig) LogDelete() {
	logObject := base.EnsureLogObject(base.DomainConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	logObject.CloneAndAddField("activate", config.Activate).
		AddField("enable-vnc", config.EnableVnc).
		Infof("domain config delete")

	base.DeleteLogObject(config.LogKey())
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
)

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

func (status DomainStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

func (status DomainStatus) CheckPendingAdd() bool {
	return status.PendingAdd
}

func (status DomainStatus) CheckPendingModify() bool {
	return status.PendingModify
}

func (status DomainStatus) CheckPendingDelete() bool {
	return status.PendingDelete
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
func (status DomainStatus) LogCreate() {
	logObject := base.NewLogObject(base.DomainStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("activated", status.Activated).
		Infof("domain status create")
}

// LogModify :
func (status DomainStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.DomainStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())

	oldStatus, ok := old.(DomainStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of DomainStatus type")
	}
	if oldStatus.State != status.State ||
		oldStatus.Activated != status.Activated {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("activated", status.Activated).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-activated", oldStatus.Activated).
			Infof("domain status modify")
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
func (status DomainStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.DomainStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("activated", status.Activated).
		Infof("domain status delete")

	base.DeleteLogObject(status.LogKey())
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
	ImageID      uuid.UUID // UUID of the image
	FileLocation string    // Where to find the volume
	ReadOnly     bool
	Format       zconfig.Format
}

type DiskStatus struct {
	ImageID      uuid.UUID // UUID of immutable image
	ReadOnly     bool
	FileLocation string // From DiskConfig
	Format       zconfig.Format
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

// HostMemory reports global stats. Published under "global" key
// Note that Ncpus is the set of physical CPUs which is different
// than the set of CPUs assigned to dom0
type HostMemory struct {
	TotalMemoryMB uint64
	FreeMemoryMB  uint64
	Ncpus         uint32
}
