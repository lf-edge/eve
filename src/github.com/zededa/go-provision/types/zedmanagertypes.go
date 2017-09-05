// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"github.com/satori/go.uuid"
	"time"
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
	UUIDandVersion    UUIDandVersion
	DisplayName       string
	FixedResources    // CPU etc
	StorageConfigList []StorageConfig
	// Assume StorageConfig should be installed when present in list
	Activate            bool
	OverlayNetworkList  []EIDOverlayConfig
	UnderlayNetworkList []UnderlayNetworkConfig
}

// Indexed by UUIDandVersion as above
type AppInstanceStatus struct {
	UUIDandVersion    UUIDandVersion
	DisplayName       string
	Activated         bool
	PendingAdd        bool // XXX delete. Assumes hook in common diff code
	PendingModify     bool // XXX delete
	PendingDelete     bool // XXX delete
	StorageStatusList []StorageStatus
	EIDList           []EIDStatusDetails
	// Mininum state across all steps and all StorageStatus.
	// INITIAL implies error.
	State SwState
	// All error strngs across all steps and all StorageStatus
	Error     string
	ErrorTime time.Time
}

type EIDOverlayConfig struct {
	EIDConfigDetails
	ACLs          []ACE
	NameToEidList []NameToEid // Used to populate DNS for the overlay
}

type StorageConfig struct {
	DownloadURL string // XXX is there a more specific type?
	MaxSize     uint   // In kbytes
	// XXX Add SignatureInfo for the sha256. Verifier should check.
	SignatureInfo SignatureInfo
	ImageSha256   string // sha256 of immutable image
	ReadOnly      bool
	Preserve      bool // If set a rw disk will be preserved across
	// boots (acivate/inactivate)
	Format  string // Default "raw"; could be raw, qcow, qcow2, vhd
	Devtype string // Default ""; could be e.g. "cdrom"
}

type StorageStatus struct {
	DownloadURL      string  // XXX is there a more specific type?
	ImageSha256      string  // sha256 of immutable image
	State            SwState // DOWNLOADED etc
	HasDownloaderRef bool    // Reference against downloader to clean up
	HasVerifierRef   bool    // Reference against verifier to clean up
	Error            string  // Download or verify error
	ErrorTime        time.Time
}

// The Intermediate can be a byte sequence of PEM certs
type SignatureInfo struct {
	IntermediateCertsPem []byte
	SignerCertPem        []byte
	Signature            []byte
}
