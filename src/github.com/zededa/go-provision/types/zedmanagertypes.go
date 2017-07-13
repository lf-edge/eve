// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"github.com/satori/go.uuid"
)

// UUID plus version
type UUIDandVersion struct {
	UUID    uuid.UUID
	Version string
}

// This is what we assume will come from the ZedControl for each
// application instance. Note that we can have different versions
// configured for the same UUID, hence the key is the UUIDandVersion
type AppInstanceConfig struct {
	UUIDandVersion      UUIDandVersion
	DisplayName         string
	FixedResources			// CPU etc
	StorageConfigList    []StorageConfig
	// Assume StorageConfig should be installed when present in list
	Activate     	    bool
	// The allocation polcies (incl prefix) are common across all IIDs for now
	EIDAllocation
	OverlayNetworkList  []OverlayNetworkConfig
	UnderlayNetworkList []UnderlayNetworkConfig
}

// Indexed by UUIDandVersion as above
type AppInstanceStatus struct {
	UUIDandVersion	UUIDandVersion
	DisplayName	string
	Activated	bool
	PendingAdd	bool
	PendingModify	bool
	PendingDelete	bool
	StorageStatusList    []StorageStatus
	// XXX common min across all StorageStatus?
	// State		SwState
	// XXX gather errors including from xl?
	// Error		string	// Download or verify error
}

type StorageConfig struct {
	DownloadURL	string	// XXX is there a specific type?
	MaxSize		uint	// XXX in kbytes
	// XXX do we put SignatureInfo here? Or in the manifest? Or both?
	// XXX this vs. ImageSha256?
	// DigestAlg	string	// XXX is there a specific type for sha256 etc?
	// Digest	string
	ImageSha256	string	// sha256 of immutable image
	ReadOnly	bool
	Preserve	bool	// If set a rw disk will be preserved across
				// boots (acivate/inactivate)
	Format		string	// Default "raw"; could be raw, qcow, qcow2, vhd
	Devtype		string	// Default ""; could be e.g. "cdrom"
}

type StorageStatus struct {
	DownloadURL	string	// XXX is there a specific type?
	ImageSha256	string	// sha256 of immutable image
	State		SwState	// DOWNLOADED etc
	Error		string	// Download or verify error
}

type SignatureInfo struct {
	IntermediateCertPem	[]byte
	SignerCertPem		[]byte
}
