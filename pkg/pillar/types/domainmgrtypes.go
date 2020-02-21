// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
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

	// XXX: to be deprecated, use CipherBlock instead
	CloudInitUserData *string // base64-encoded
	// Container related info
	IsContainer bool // Is this Domain for a Container?

	// CipherBlock, for encrypted cloud-init data
	CipherBlock
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
	LastErr            string // Xen error
	LastErrTime        time.Time
	BootFailed         bool
	AdaptersFailed     bool
	IsContainer        bool              // Is this Domain for a Container?
	PodUUID            string            // Pod UUID outputted by rkt
	EnvVariables       map[string]string // List of environment variables to be set in container
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
	ImageID     uuid.UUID // UUID of the image
	ImageSha256 string    // sha256 of immutable image
	ReadOnly    bool
	Preserve    bool // If set a rw disk will be preserved across
	// boots (acivate/inactivate)
	Maxsizebytes uint64 // Resize filesystem to this size if set
	Format       zconfig.Format
	Devtype      string // Default ""; could be e.g. "cdrom"
}

type DiskStatus struct {
	ImageID            uuid.UUID // UUID of immutable image
	ImageSha256        string    // sha256 of immutable image
	ReadOnly           bool
	Preserve           bool
	FileLocation       string // Local location of Image
	Maxsizebytes       uint64 // Resize filesystem to this size if set
	Format             zconfig.Format
	Devtype            string // From config
	Vdev               string // Allocated
	ActiveFileLocation string // Allocated; private copy if RW; FileLocation if RO
}

// Track the active image files in rwImgDirname
// The ImageSha256 is used when an app instance has multiple virtual disks.
// We do not have an imageID in the pathnames for the RW images hence we can't report
// an imageID on startup.
type ImageStatus struct {
	AppInstUUID  uuid.UUID // UUID of App Instance using the image.
	ImageSha256  string    // ImageSha256 of original image
	Filename     string    // Basename; used as key
	FileLocation string    // Local location of Image
	RefCount     uint
	LastUse      time.Time // When RefCount dropped to zero
	Size         uint64
}

func (status ImageStatus) Key() string {
	return status.Filename
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
