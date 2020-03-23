// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
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
	// XXX: to be deprecated, use CipherBlockStatus instead
	CloudInitUserData *string // base64-encoded
	RemoteConsole     bool

	// CipherBlockStatus, for encrypted cloud-init data
	CipherBlockStatus
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

	// Container related state
	IsContainer bool

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
		if ulStatus.VifUsed != "" {
			viflist = append(viflist, ulStatus.VifUsed)
		}
	}
	for _, olStatus := range status.OverlayNetworks {
		if olStatus.VifUsed != "" {
			viflist = append(viflist, olStatus.VifUsed)
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

// MaybeUpdateAppIPAddr - Check if the AI status has the underlay network with this Mac Address
func (status *AppInstanceStatus) MaybeUpdateAppIPAddr(macAddr, ipAddr string) bool {
	for idx, ulStatus := range status.UnderlayNetworks {
		if ulStatus.VifInfo.Mac == macAddr {
			status.UnderlayNetworks[idx].AllocatedIPAddr = ipAddr
			return true
		}
	}
	return false
}

type EIDOverlayConfig struct {
	Name string // From proto message
	EIDConfigDetails
	ACLs       []ACE
	AppMacAddr net.HardwareAddr // If set use it for vif
	AppIPAddr  net.IP           // EIDv4 or EIDv6
	Network    uuid.UUID
	IntfOrder  int32 // XXX need to get from API

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
	// ImageID - UUID of the image
	ImageID          uuid.UUID
	DatastoreID      uuid.UUID
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
	Maxsizebytes uint64         // Resize filesystem to this size if set
	Format       zconfig.Format // Default "raw"; could be raw, qcow, qcow2, vhd
	Devtype      string         // Default ""; could be e.g. "cdrom"
	Target       string         // Default "" is interpreted as "disk"
}

func RoundupToKB(b uint64) uint64 {
	return (b + 1023) / 1024
}

// ErrorInfo errorInfo holder structure
type ErrorInfo struct {
	Error       string
	ErrorSource string
	ErrorTime   time.Time
}

type StorageStatus struct {
	// ImageID - UUID of the image
	ImageID            uuid.UUID
	DatastoreID        uuid.UUID
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
	Format             zconfig.Format
	Devtype            string
	Target             string  // Default "" is interpreted as "disk"
	State              SwState // DOWNLOADED etc
	Progress           uint    // In percent i.e., 0-100
	HasDownloaderRef   bool    // Reference against downloader to clean up
	HasVerifierRef     bool    // Reference against verifier to clean up
	IsContainer        bool    // Is the image a Container??
	Vdev               string  // Allocated
	ActiveFileLocation string  // Location of filestystem
	FinalObjDir        string  // Installation dir; may differ from verified
	ErrorInfo
}

// UpdateFromStorageConfig sets up StorageStatus based on StorageConfig struct
func (ss *StorageStatus) UpdateFromStorageConfig(sc StorageConfig) {
	ss.DatastoreID = sc.DatastoreID
	ss.Name = sc.Name
	ss.NameIsURL = sc.NameIsURL
	ss.ImageID = sc.ImageID
	ss.ImageSha256 = sc.ImageSha256
	ss.Size = sc.Size
	ss.CertificateChain = sc.CertificateChain
	ss.ImageSignature = sc.ImageSignature
	ss.SignatureKey = sc.SignatureKey
	ss.ReadOnly = sc.ReadOnly
	ss.Preserve = sc.Preserve
	ss.Format = sc.Format
	ss.Maxsizebytes = sc.Maxsizebytes
	ss.Devtype = sc.Devtype
	ss.Target = sc.Target
	if ss.Format == zconfig.Format_CONTAINER {
		ss.IsContainer = true
	}
	return
}

// GetErrorInfo sets the errorInfo for the Storage Object
func (ss StorageStatus) GetErrorInfo() ErrorInfo {
	errInfo := ErrorInfo{
		Error:       ss.Error,
		ErrorSource: ss.ErrorSource,
		ErrorTime:   ss.ErrorTime,
	}
	return errInfo
}

// SetErrorInfo sets the errorInfo for the Storage Object
func (ss *StorageStatus) SetErrorInfo(errInfo ErrorInfo) {
	ss.Error = errInfo.Error
	ss.ErrorTime = errInfo.ErrorTime
	ss.ErrorSource = errInfo.ErrorSource
}

// ClearErrorInfo clears errorInfo for the Storage Object
func (ss *StorageStatus) ClearErrorInfo() {
	ss.Error = ""
	ss.ErrorSource = ""
	ss.ErrorTime = time.Time{}
}

// IsCertsAvailable checks certificate requirement/availability for a storage object
func (ss StorageStatus) IsCertsAvailable(displaystr string) (bool, error) {
	if !ss.needsCerts() {
		log.Debugf("%s, Certs are not required\n", displaystr)
		return false, nil
	}
	cidx, err := ss.getCertCount(displaystr)
	return cidx != 0, err
}

// HandleCertStatus gets the CertObject Status for the storage object
// True, when there is no Certs or, the certificates are ready
// False, Certificates are not ready or, there are some errors
func (ss StorageStatus) HandleCertStatus(displaystr string,
	certObjStatus CertObjStatus) (bool, ErrorInfo) {
	if ret, errInfo := ss.checkCertsStatusForObject(certObjStatus); !ret {
		log.Infof("%s, Certs are still not ready\n", displaystr)
		return ret, errInfo
	}
	if ret := ss.checkCertsForObject(); !ret {
		log.Infof("%s, Certs are still not installed\n", displaystr)
		return ret, ErrorInfo{}
	}
	return true, ErrorInfo{}
}

// needsCerts whether certificates are required for the Storage Object
func (ss StorageStatus) needsCerts() bool {
	if len(ss.ImageSignature) == 0 {
		return false
	}
	return true
}

// getCertCount returns the number of certificates for the Storage Object
// called with valid ImageSignature only
func (ss StorageStatus) getCertCount(displaystr string) (int, error) {
	cidx := 0
	if ss.SignatureKey == "" {
		errStr := fmt.Sprintf("%s, Invalid Root CertURL\n", displaystr)
		log.Errorf(errStr)
		return cidx, errors.New(errStr)
	}
	cidx++
	if len(ss.CertificateChain) != 0 {
		for _, certURL := range ss.CertificateChain {
			if certURL == "" {
				errStr := fmt.Sprintf("%s, Invalid Intermediate CertURL\n", displaystr)
				log.Errorf(errStr)
				return 0, errors.New(errStr)
			}
			cidx++
		}
	}
	return cidx, nil
}

// checkCertsStatusForObject checks certificates for installation status
func (ss StorageStatus) checkCertsStatusForObject(certObjStatus CertObjStatus) (bool, ErrorInfo) {

	if ss.SignatureKey != "" {
		found, installed, errInfo := certObjStatus.getCertStatus(ss.SignatureKey)
		if !found || !installed {
			return false, errInfo
		}
	}

	for _, certURL := range ss.CertificateChain {
		found, installed, errInfo := certObjStatus.getCertStatus(certURL)
		if !found || !installed {
			return false, errInfo
		}
	}
	return true, ErrorInfo{}
}

// checkCertsForObject checks availability of Certs in Disk
func (ss StorageStatus) checkCertsForObject() bool {

	if ss.SignatureKey != "" {
		safename := UrlToSafename(ss.SignatureKey, "")
		filename := CertificateDirname + "/" + SafenameToFilename(safename)
		// XXX result is just the sha? Or "serverCert.<sha>?
		if _, err := os.Stat(filename); err != nil {
			log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
			return false
		}
		// XXX check for valid or non-zero length?
	}

	for _, certURL := range ss.CertificateChain {
		safename := UrlToSafename(certURL, "")
		filename := CertificateDirname + "/" + SafenameToFilename(safename)
		// XXX result is just the sha? Or "serverCert.<sha>?
		if _, err := os.Stat(filename); err != nil {
			log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
			return false
		}
		// XXX check for valid or non-zero length?
	}
	return true
}

// The Intermediate can be a byte sequence of PEM certs
type SignatureInfo struct {
	IntermediateCertsPem []byte
	SignerCertPem        []byte
	Signature            []byte
}

// AppAndImageToHash is used to retain <app,image> to sha maps across reboots.
// Key for OCI images which can be specified with a tag and we need to be
// able to latch the sha and choose when to update/refresh from the tag.
type AppAndImageToHash struct {
	AppUUID uuid.UUID
	ImageID uuid.UUID
	Hash    string
}

// Key is used for pubsub
func (aih AppAndImageToHash) Key() string {
	return fmt.Sprintf("%s.%s", aih.AppUUID.String(), aih.ImageID.String())
}
