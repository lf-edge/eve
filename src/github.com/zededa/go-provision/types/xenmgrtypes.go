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
	AppNum		int	// From networking; makes the name unique
	Kernel		string	// XXX default /boot/vmlinuz??
	Ramdisk		string	// default none
	Memory		int	// in kbytes; XXX round up to Mbytes for xen
	MaxMem		int	// Default not set i.e. no balooning
	VCpus		int	// default 1
	DiskConfigList	[]DiskConfig
	VifList		[]VifInfo
	ExtraArgs	string	// added to bootargs
}

type DomainStatus struct {
	UUIDandVersion  UUIDandVersion
	DisplayName	string	// Use as name for domU? DisplayName+version?
	PendingAdd	bool
	PendingModify	bool
	PendingDelete	bool
	DiskStatusList	[]DiskStatus
}

// XXX Move to networking pieces? Separate out networking from types.go
type VifInfo struct {
	Bridge		string
	Vif		string
	Mac		string
}

// XenManager will pass these to the xen xl config file
// The vdev is automatically assigned as xvd[x], where X is a, b, c etc,
// based on the order in the DiskList
// XXX alternatively we make could the vdev be the index to a map
// Note that vdev in general can be hd[x], xvd[x], sd[x] but here we only
// use xvd
type DiskConfig struct {
	ImageSha256	string	// sha256 of immutable image
	ReadOnly	bool
	// XXX /dev/loop3,raw,xvda,rw,backendtype=phy
	// XXX   format=raw, vdev=hda, access=rw, target=/dev/vg/guest-volume
	// ro as losetup --show -f -r /root/xxx-test.img
	// auto-allocates
	Format		string	// Default "raw"; could be raw, qcow, qcow2, vhd	Devtype		string	// Default ""; could be e.g. "cdrom"   
	// XXX Vdev	string	// See above
	// XXX Target	string	// See above
}

// XXX do we need a DiskStatus with the allocated Target and Vdev?
// XXX what about temporary name when a copy? filename in /var/run/xenmgr/img/
// XXX do we want a "preserve" option to reuse rw image across boots? Means using /var/tmp/ path.
type DiskStatus struct {
	ImageSha256	string	// sha256 of immutable image
	ReadOnly	bool
	FileLocation	string	// Same as image of RO, otherwise private copy
	Vdev		string	// Allocated
	Target		string	// Allocated
}
