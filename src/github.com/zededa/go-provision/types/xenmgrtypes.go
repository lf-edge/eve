// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

// The information XenManager needs to boot and halt domains
// If the the version (in UUIDandVersion) changes then the domain needs to
// halted and booted?? NO, because an ACL change from ZedControl would bump
// the version. Who determines which changes require halt+reboot?
// Do we need an explicit interlock with ZedManager when a reboot
// is needed? For instance, ZedManager could remove the DomainConfig, what for
// DomainStatus to be deleted, then re-create the DomainConfig.
type DomainConfig struct {
	UUIDandVersion  UUIDandVersion
	DisplayName     string	// Use as name for domU? DisplayName+version?
	Activate	bool	// Actually start the domU as opposed to prepare
	AppNum		int	// From networking; makes the name unique
	FixedResources
	DiskConfigList	[]DiskConfig
	VifList		[]VifInfo
}

type FixedResources struct {
	Kernel		string	// default ""
	Ramdisk		string	// default ""
	Memory		int	// in kbytes; XXX round up to Mbytes for xen?
	MaxMem		int	// Default not set i.e. no balooning
	VCpus		int	// default 1
	// XXX Add CPU pinning
	ExtraArgs	string	// added to bootargs
}

type DomainStatus struct {
	UUIDandVersion  UUIDandVersion
	DisplayName	string
	Activated	bool
	AppNum		int
	PendingAdd	bool
	PendingModify	bool
	PendingDelete	bool
	DomainName	string	// Name of Xen domain
	DomainId	int
	DiskStatusList	[]DiskStatus
}

type VifInfo struct {
	Bridge		string
	Vif		string
	Mac		string
}

// XenManager will pass these to the xen xl config file
// The vdev is automatically assigned as xvd[x], where X is a, b, c etc,
// based on the order in the DiskList
// Note that vdev in general can be hd[x], xvd[x], sd[x] but here we only
// use xvd
type DiskConfig struct {
	ImageSha256	string	// sha256 of immutable image
	ReadOnly	bool
	Preserve	bool	// If set a rw disk will be preserved across
				// boots (acivate/inactivate)
	Format		string	// Default "raw"; could be raw, qcow, qcow2, vhd
	Devtype		string	// Default ""; could be e.g. "cdrom"
}

type DiskStatus struct {
	ImageSha256	string	// sha256 of immutable image
	ReadOnly	bool
	Preserve	bool
	FileLocation	string	// Local location of Image
	Format		string	// From config
	Devtype		string	// From config
	Vdev		string	// Allocated
	Target		string	// Allocated; private copy if RW; FileLocation if RO
}
