// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
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
	UUIDandVersion  UUIDandVersion
	DisplayName     string
	ConfigSha256    string
	ConfigSignature string

	// Error
	//	If this is set, do not process further.. Just set the status to error
	//	so the cloud gets it.
	Errors              []string
	FixedResources      VmConfig // CPU etc
	StorageConfigList   []StorageConfig
	Activate            bool
	OverlayNetworkList  []EIDOverlayConfig
	UnderlayNetworkList []UnderlayNetworkConfig
	IoAdapterList       []IoAdapter
	RestartCmd          AppInstanceOpsCmd
	PurgeCmd            AppInstanceOpsCmd
	CloudInitUserData   string // base64-encoded
	RemoteConsole       bool
}

type AppInstanceOpsCmd struct {
	Counter   uint32
	ApplyTime string // XXX not currently used
}

// IoAdapter specifies that a group of ports should be assigned
type IoAdapter struct {
	Type IoType
	Name string // Short hand name such as "COM1" or "eth1-2"
}

func (config AppInstanceConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
}

func (config AppInstanceConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// Indexed by UUIDandVersion as above
type AppInstanceStatus struct {
	UUIDandVersion     UUIDandVersion
	DisplayName        string
	DomainName         string // Once booted
	Activated          bool
	ActivateInprogress bool     // Needed for cleanup after failure
	FixedResources     VmConfig // CPU etc
	StorageStatusList  []StorageStatus
	EIDList            []EIDStatusDetails
	OverlayNetworks    []OverlayNetworkStatus
	UnderlayNetworks   []UnderlayNetworkStatus
	// Copies of config to determine diffs
	OverlayNetworkList  []EIDOverlayConfig
	UnderlayNetworkList []UnderlayNetworkConfig
	BootTime            time.Time
	IoAdapterList       []IoAdapter
	RestartCmd          AppInstanceOpsCmd
	PurgeCmd            AppInstanceOpsCmd
	RestartInprogress   Inprogress
	PurgeInprogress     Inprogress
	ImageID             uuid.UUID // UUID of the image

	// Container related state
	IsContainer      bool
	ContainerImageID string

	// Mininum state across all steps and all StorageStatus.
	// Error* set implies error.
	State          SwState
	MissingNetwork bool // If some Network UUID not found
	// All error strings across all steps and all StorageStatus
	ErrorSource string
	Error       string
	ErrorTime   time.Time
}

// Track more complicated workflows
type Inprogress uint8

const (
	NONE     Inprogress = iota
	DOWNLOAD            // Download and verify new images
	BRING_DOWN
	BRING_UP
)

func (status AppInstanceStatus) Key() string {
	return status.UUIDandVersion.UUID.String()
}

func (status AppInstanceStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
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

// GetAppInterfaceList is a helper function to get all the vifnames
func (status AppInstanceStatus) GetAppInterfaceList() []string {

	var viflist []string
	for _, ulStatus := range status.UnderlayNetworks {
		if ulStatus.Vif != "" {
			viflist = append(viflist, ulStatus.Vif)
		}
	}
	for _, olStatus := range status.OverlayNetworks {
		if olStatus.Vif != "" {
			viflist = append(viflist, olStatus.Vif)
		}
	}
	return viflist
}

// SetError - Clears error state of Status
func (statusPtr *AppInstanceStatus) SetError( //revive:disable-line
	errStr string, source string,
	errTime time.Time) {
	statusPtr.Error = errStr
	statusPtr.ErrorSource = source
	statusPtr.ErrorTime = errTime
}

// ClearError - Clears error state of Status
func (statusPtr *AppInstanceStatus) ClearError() { //revive:disable-line
	statusPtr.Error = ""
	statusPtr.ErrorSource = ""
	statusPtr.ErrorTime = time.Time{}
}

type EIDOverlayConfig struct {
	Name string // From proto message
	EIDConfigDetails
	ACLs       []ACE
	AppMacAddr net.HardwareAddr // If set use it for vif
	AppIPAddr  net.IP           // EIDv4 or EIDv6
	Network    uuid.UUID

	// Error
	//	If there is a parsing error and this uLNetwork config cannot be
	//	processed, set the error here. This allows the error to be propagated
	//  back to zedcloud
	//	If this is non-empty ( != ""), the network Config should not be
	// 	processed further. It Should just	be flagged to be in error state
	//  back to the cloud.
	Error string
}

// If the Target is "" or "disk", then this becomes a vdisk for the domU
// Other possible targets are:
// - "kernel"
// - "ramdisk"
// - "device_tree"
type StorageConfig struct {
	// DatastoreID - UUID of the DataStore
	DatastoreID uuid.UUID
	// ImageID - UUID of the image
	ImageID          uuid.UUID
	Name             string   // XXX Do depend on URL for clobber avoidance?
	NameIsURL        bool     // If not we form URL based on datastore info
	Size             uint64   // In bytes
	CertificateChain []string //name of intermediate certificates
	ImageSignature   []byte   //signature of image
	SignatureKey     string   //certificate containing public key

	ImageSha256 string // sha256 of immutable image
	ReadOnly    bool
	Preserve    bool // If set a rw disk will be preserved across
	// boots (acivate/inactivate)
	Maxsizebytes uint64 // Resize filesystem to this size if set
	Format       string // Default "raw"; could be raw, qcow, qcow2, vhd
	Devtype      string // Default ""; could be e.g. "cdrom"
	Target       string // Default "" is interpreted as "disk"
}

func RoundupToKB(b uint64) uint64 {
	return (b + 1023) / 1024
}

type StorageStatus struct {
	DatastoreID uuid.UUID
	// ImageID - UUID of the image
	ImageID            uuid.UUID
	Name               string
	ImageSha256        string   // sha256 of immutable image
	NameIsURL          bool     // If not we form URL based on datastore info
	Size               uint64   // In bytes
	CertificateChain   []string //name of intermediate certificates
	ImageSignature     []byte   //signature of image
	SignatureKey       string   //certificate containing public key
	ReadOnly           bool
	Preserve           bool
	Maxsizebytes       uint64 // Resize filesystem to this size if set
	Format             string
	Devtype            string
	Target             string  // Default "" is interpreted as "disk"
	State              SwState // DOWNLOADED etc
	Progress           uint    // In percent i.e., 0-100
	HasDownloaderRef   bool    // Reference against downloader to clean up
	HasVerifierRef     bool    // Reference against verifier to clean up
	IsContainer        bool    // Is the image a Container??
	ContainerImageID   string  // Container Image ID if IsContainer=true
	Vdev               string  // Allocated
	ActiveFileLocation string  // Location of filestystem
	FinalObjDir        string  // Installation dir; may differ from verified
	Error              string  // Download or verify error
	ErrorSource        string
	ErrorTime          time.Time
}

// UpdateFromStorageConfig sets up StorageStatus based on StorageConfig struct
func (ssPtr *StorageStatus) UpdateFromStorageConfig(sc StorageConfig) {
	ssPtr.DatastoreID = sc.DatastoreID
	ssPtr.Name = sc.Name
	ssPtr.NameIsURL = sc.NameIsURL
	ssPtr.ImageSha256 = sc.ImageSha256
	ssPtr.Size = sc.Size
	ssPtr.CertificateChain = sc.CertificateChain
	ssPtr.ImageSignature = sc.ImageSignature
	ssPtr.SignatureKey = sc.SignatureKey
	ssPtr.ReadOnly = sc.ReadOnly
	ssPtr.Preserve = sc.Preserve
	ssPtr.Format = sc.Format
	ssPtr.Maxsizebytes = sc.Maxsizebytes
	ssPtr.Devtype = sc.Devtype
	ssPtr.Target = sc.Target
	if ssPtr.Format == "container" {
		ssPtr.IsContainer = true
	}
	return
}

// IsCerts checks certificate requirement/availability for a storage object
func (ssPtr *StorageStatus) IsCertsAvailable(safename string) (bool, error) {
	if !ssPtr.needsCerts() {
		log.Debugf("%s, Certs are not required\n", safename)
		return false, nil
	}
	cidx, err := ssPtr.getCertCount(safename)
	return cidx != 0, err
}

// GetCertStatus gets the CertObject Status for the storage object
// True, when there is no Certs or, the certificates are ready
// False, Certificates are not ready or, there are some errors
func (ssPtr *StorageStatus) GetCertStatus(safename string,
	certObjStatusPtr *CertObjStatus) (bool, string, string, time.Time) {
	if ret, errStr, errSrc, errTime := ssPtr.checkCertsStatusForObject(safename,
		certObjStatusPtr); !ret {
		log.Infof("%s, Certs are still not ready\n", safename)
		return ret, errStr, errSrc, errTime
	}
	if ret, errStr, errSrc, errTime := ssPtr.checkCertsForObject(); !ret {
		log.Infof("%s, Certs are still not installed\n", safename)
		return ret, errStr, errSrc, errTime
	}
	return true, "", "", time.Time{}
}

// needsCerts whether certificates are required for the Storage Object
func (ssPtr *StorageStatus) needsCerts() bool {
	if len(ssPtr.ImageSignature) == 0 {
		return false
	}
	return true
}

// getCertCount returns the number of certificates for the Storage Object
// called with valid ImageSignature only
func (ssPtr *StorageStatus) getCertCount(safename string) (int, error) {
	cidx := 0
	if ssPtr.SignatureKey == "" {
		errStr := fmt.Sprintf("%s, Invalid Root CertURL\n", safename)
		log.Errorf(errStr)
		return cidx, errors.New(errStr)
	}
	cidx++
	if len(ssPtr.CertificateChain) != 0 {
		for _, certURL := range ssPtr.CertificateChain {
			if certURL == "" {
				errStr := fmt.Sprintf("%s, Invalid Intermediate CertURL\n", safename)
				log.Errorf(errStr)
				return 0, errors.New(errStr)
			}
			cidx++
		}
	}
	return cidx, nil
}

// checkCertsStatusForObject checks certificates for installation status
func (ssPtr *StorageStatus) checkCertsStatusForObject(safename string,
	certObjStatusPtr *CertObjStatus) (bool, string, string, time.Time) {

	// certificates are still not ready, for processing
	if certObjStatusPtr == nil {
		return false, "", "", time.Time{}
	}

	if ssPtr.SignatureKey != "" {
		for _, certObj := range certObjStatusPtr.StorageStatusList {
			if certObj.Name == ssPtr.SignatureKey {
				if certObj.Error != "" {
					return false, certObj.Error, certObj.ErrorSource, certObj.ErrorTime
				}
				if certObj.State != DELIVERED {
					return false, "", "", time.Time{}
			}
		}
	}
	return true, "", "", time.Time{}
}

// checkCertsForObject checks availability of Certs in Disk
func (ssPtr *StorageStatus) checkCertsForObject() (bool, string, string, time.Time) {

	if ssPtr.SignatureKey != "" {
		safename := UrlToSafename(ssPtr.SignatureKey, "")
		filename := CertificateDirname + "/" + SafenameToFilename(safename)
		if _, err := os.Stat(filename); err != nil {
			log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
			return false, "", "", time.Time{}
		}
		// XXX check for valid or non-zero length?
	}

	for _, certURL := range ssPtr.CertificateChain {
		safename := UrlToSafename(certURL, "")
		filename := CertificateDirname + "/" + SafenameToFilename(safename)
		if _, err := os.Stat(filename); err != nil {
			log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
			return false, "", "", time.Time{}
		}
		// XXX check for valid or non-zero length?
	}
	return true, "", "", time.Time{}
}

// SetErrorInfo sets the errorInfo for the Storage Object
func (ssPtr *StorageStatus) SetErrorInfo(errorStr string, errSrc string,
	errTime time.Time) {
	ssPtr.Error = errorStr
	ssPtr.ErrorTime = errTime
	ssPtr.ErrorSource = errSrc
}

// ClearErrorInfo clears errorInfo for the Storage Object
func (ssPtr *StorageStatus) ClearErrorInfo() {
	ssPtr.Error = ""
	ssPtr.ErrorSource = ""
	ssPtr.ErrorTime = time.Time{}
}

// The Intermediate can be a byte sequence of PEM certs
type SignatureInfo struct {
	IntermediateCertsPem []byte
	SignerCertPem        []byte
	Signature            []byte
}
