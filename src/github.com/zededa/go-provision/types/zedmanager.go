// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
// XXX	"github.com/satori/go.uuid"
//	"net"
//	"time"
)

// This is what we assume will come from the ZedControl for each
// application instance. Note that we can have different versions
// configured for the same UUID, hence the key is the UUIDandVersion
type AppInstanceConfig struct {
	UUIDandVersion      UUIDandVersion
	DisplayName         string
	IsZedmanager        bool // XXX needed?
	StorageInfoList	    []StorageInfo
	// XXX EID per overlay network? Allocation?
	OverlayNetworkList  []OverlayNetwork
	UnderlayNetworkList []UnderlayNetwork
}

// Indexed by UUIDandVersion as above
type AppInstanceStatus struct {
	UUIDandVersion UUIDandVersion
	DisplayName    string
}

type StorageInfo struct {
	DownloadURL	string	// XXX is there a specific type?
	DigestAlg	string	// XXX is there a specific type?
	Digest		string
	MaxSize		uint	// Unit? kbytes?
	// XXX do we put SignatureInfo here? Or in the manifest?
}

// XXX once downloaded as immutable? Or once copied and loopback mounted?
type LocalStorageInfo struct {
	StorageInfo
	// XXX Used in status - move to separate LocalDiskInfo type?
	Pathname	string
	// loopbackname?
}

type SignatureInfo struct {
	IntermediateCertPem	[]byte
	SignerCertPem		[]byte
}

// The information XenManager needs to boot and halt domains
// If the the version (in UUIDandVersion) changes then the domain needs to
// halted and booted?? NO, because an ACL change from ZedControl would bump
// the version.
// Do we need an explicit interlock with ZedManager when a reboot
// is needed? For instance, ZedManager could remove the DomainConfig, what for
// DomainStatus to be deleted, then re-create the DomainConfig.
type DomainConfig struct {
	UUIDandVersion  UUIDandVersion
	DisplayName     string	// Use as name for domU? DisplayName+version?
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
	DisplayName     string	// Use as name for domU? DisplayName+version?
	PendingAdd     bool
	PendingModify  bool
	PendingDelete  bool
	DiskStatusList	[]DiskStatus
}

// XXX Move to networking pieces? Separate out from types.go
type VifInfo struct {
	Bridge		string
	Vif		string
	Mac		string
}

// XenManager will create loop deices for these, and use the resulting /dev/lo
// as the target
// The vdev is assigned as xvd[x], where X is a, b, c etc, based on the order
// in the DiskList
// XXX alternatively we make could the vdev be the index to a map
// Note that vdev can be hd[x], xvd[x], sd[x]
type DiskConfig struct {
	ImageSha	string	// sha256 of immutable image
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
type DiskStatus struct {
	ImageSha	string	// sha256 of immutable image
	ReadOnly	bool
	Vdev		string	// Allocated
	Target		string	// Allocated
}
