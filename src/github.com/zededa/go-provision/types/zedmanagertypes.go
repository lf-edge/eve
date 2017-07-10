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
	IsZedmanager        bool // XXX needed?
	StorageInfoList	    []StorageInfo
	// Assume it should be installed when present.
	Activate     	    bool
	// XXX EID per overlay network? Allocation?
	OverlayNetworkList  []OverlayNetwork
	UnderlayNetworkList []UnderlayNetwork
}

// Indexed by UUIDandVersion as above
type AppInstanceStatus struct {
	UUIDandVersion	UUIDandVersion
	DisplayName	string
	Activated	bool
	PendingAdd	bool
	PendingModify	bool
	PendingDelete	bool
	// XXX StorageStatus with downloading etc. Per unit or calculate min
	// across all StorageStatus?
}

type StorageInfo struct {
	DownloadURL	string	// XXX is there a specific type?
	DigestAlg	string	// XXX is there a specific type for sha256 etc?
	Digest		string
	MaxSize		uint	// Unit? kbytes?
	// XXX do we put SignatureInfo here? Or in the manifest? Or both?
}

// XXX once downloaded as immutable? Or once copied and loopback mounted?
// XXX download will always be to /var/tmp/zedmanager/downloads/<sha256>
type LocalStorageInfo struct {
	StorageInfo
	// XXX Used in status - move to separate LocalDiskInfo type?
	Pathname	string
}

type SignatureInfo struct {
	IntermediateCertPem	[]byte
	SignerCertPem		[]byte
}
