// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"github.com/satori/go.uuid"
	"log"
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

func (config AppInstanceConfig) VerifyFilename(fileName string) bool {
	uuid := config.UUIDandVersion.UUID
	ret := uuid.String()+".json" == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, uuid.String())
	}
	return ret
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

func (status AppInstanceStatus) VerifyFilename(fileName string) bool {
	uuid := status.UUIDandVersion.UUID
	ret := uuid.String()+".json" == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, uuid.String())
	}
	return ret
}

func (status AppInstanceStatus) CheckPendingAdd() bool {
	return status.PendingAdd
}

func (status AppInstanceStatus) CheckPendingModify() bool {
	return status.PendingModify
}

func (status AppInstanceStatus) CheckPendingDelete() bool {
	return status.PendingDelete
}

type EIDOverlayConfig struct {
	EIDConfigDetails
	ACLs          []ACE
	NameToEidList []NameToEid // Used to populate DNS for the overlay
}

type StorageConfig struct {
	DownloadURL	string	// XXX is there a more specific type?
	MaxSize		uint	// In kbytes
	Bucket		string	// S3 Bucket Name
	Operation	string	// Operation Type (Download/Upload/Delete etc.)
	TransportMethod	string	// Download method S3/HTTP/SFTP etc.
	// XXX Add SignatureInfo for the sha256. Verifier should check.
	CertificateChain	[]string//name of intermediate certificates
	ImageSignature		[]byte	//signature of image
	SignatureKey		string	//certificate containing public key 

	ImageSha256	string	// sha256 of immutable image
	ReadOnly	bool
	Preserve	bool	// If set a rw disk will be preserved across
				// boots (acivate/inactivate)
	Format		string	// Default "raw"; could be raw, qcow, qcow2, vhd
	Devtype		string	// Default ""; could be e.g. "cdrom"
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
