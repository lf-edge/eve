// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"github.com/satori/go.uuid"
	"log"
	"time"
)

type UrlCloudCfg struct {
	ConfigUrl  string
	MetricsUrl string
	StatusUrl  string
	LogUrl     string
}

// top level config container
type DeviceConfigResponse struct {
	Config EdgeDevConfig
}

type EdgeDevConfig struct {
	Id                 UUIDandVersion
	DevConfigSha256    string
	DevConfigSignature string
	Apps               []AppInstanceConfig
	Networks           []UnderlayNetworkConfig
}

// UUID plus version
type UUIDandVersion struct {
	UUID    uuid.UUID
	Version string
}

// This is what we assume will come from the ZedControl for each
// application instance. Note that we can have different versions
// configured for the same UUID, hence the key is the UUIDandVersion
// We assume the elements in StorageConfig should be installed, but activation
// (advertize the EID in lisp and boot the guest) is driven by the Activate
// attribute.
type AppInstanceConfig struct {
	UUIDandVersion      UUIDandVersion
	DisplayName         string
	ConfigSha256        string
	ConfigSignature     string
	FixedResources      VmConfig // CPU etc
	StorageConfigList   []StorageConfig
	Activate            bool
	OverlayNetworkList  []EIDOverlayConfig
	UnderlayNetworkList []UnderlayNetworkConfig
	IoAdapterList       []IoAdapter
}

type IoAdapter struct {
	Type IoType
	Name string // Short hand name such as "com"
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
	UUIDandVersion     UUIDandVersion
	DisplayName        string
	Activated          bool
	ActivateInprogress bool // Needed for cleanup after failure
	StorageStatusList  []StorageStatus
	EIDList            []EIDStatusDetails
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
	return false
}

func (status AppInstanceStatus) CheckPendingModify() bool {
	return false
}

func (status AppInstanceStatus) CheckPendingDelete() bool {
	return false
}

type EIDOverlayConfig struct {
	EIDConfigDetails
	ACLs          []ACE
	NameToEidList []NameToEid // Used to populate DNS for the overlay
	LispServers   []LispServerInfo
}

// If the Target is "" or "disk", then this becomes a vdisk for the domU
// Other possible targets are:
// - "kernel"
// - "ramdisk"
// - "device_tree"
type StorageConfig struct {
	DownloadURL      string
	Size             uint64   // In bytes
	TransportMethod  string   // Download method S3/HTTP/SFTP etc.
	CertificateChain []string //name of intermediate certificates
	ImageSignature   []byte   //signature of image
	SignatureKey     string   //certificate containing public key
	ApiKey           string
	Password         string
	Dpath            string

	ImageSha256 string // sha256 of immutable image
	ReadOnly    bool
	Preserve    bool // If set a rw disk will be preserved across
	// boots (acivate/inactivate)
	Format  string // Default "raw"; could be raw, qcow, qcow2, vhd
	Devtype string // Default ""; could be e.g. "cdrom"
	Target  string // Default "" is interpreted as "disk"

	// XXX FinalObjDir shouldn't be setable from the cloud. Local to
	// device.
	FinalObjDir string // installation dir, may differ from verified
}

func RoundupToKB(b uint64) uint64 {
	return (b + 1023) / 1024
}

type StorageStatus struct {
	DownloadURL        string
	ImageSha256        string  // sha256 of immutable image
	Target             string  // Default "" is interpreted as "disk"
	State              SwState // DOWNLOADED etc
	HasDownloaderRef   bool    // Reference against downloader to clean up
	HasVerifierRef     bool    // Reference against verifier to clean up
	ActiveFileLocation string  // Location of filestystem
	Error              string  // Download or verify error
	ErrorTime          time.Time
}

// The Intermediate can be a byte sequence of PEM certs
type SignatureInfo struct {
	IntermediateCertsPem []byte
	SignerCertPem        []byte
	Signature            []byte
}
