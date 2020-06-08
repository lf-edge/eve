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
	"github.com/lf-edge/eve/pkg/pillar/base"
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

// LogCreate :
func (config AppInstanceConfig) LogCreate() {
	logObject := base.NewLogObject(base.AppInstanceConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activate", config.Activate).
		AddField("remote-console", config.RemoteConsole).
		Infof("App instance config create")
}

// LogModify :
func (config AppInstanceConfig) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.AppInstanceConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())

	oldConfig, ok := old.(AppInstanceConfig)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of AppInstanceConfig type")
	}
	if oldConfig.Activate != config.Activate ||
		oldConfig.RemoteConsole != config.RemoteConsole {

		logObject.CloneAndAddField("activate", config.Activate).
			AddField("remote-console", config.RemoteConsole).
			AddField("old-activate", oldConfig.Activate).
			AddField("old-remote-console", oldConfig.RemoteConsole).
			Infof("App instance config modify")
	}

}

// LogDelete :
func (config AppInstanceConfig) LogDelete() {
	logObject := base.EnsureLogObject(base.AppInstanceConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	logObject.CloneAndAddField("activate", config.Activate).
		AddField("remote-console", config.RemoteConsole).
		Infof("App instance config delete")

	base.DeleteLogObject(config.LogKey())
}

// LogKey :
func (config AppInstanceConfig) LogKey() string {
	return string(base.AppInstanceConfigLogType) + "-" + config.Key()
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
	// ErrorAndTimeWithSource provides SetError, SetErrrorWithSource, etc
	ErrorAndTimeWithSource
}

// LogCreate :
func (status AppInstanceStatus) LogCreate() {
	logObject := base.NewLogObject(base.AppInstanceStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("restart-in-progress", status.RestartInprogress).
		AddField("purge-in-progress", status.PurgeInprogress).
		Infof("App instance status create")
}

// LogModify :
func (status AppInstanceStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.AppInstanceStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())

	oldStatus, ok := old.(AppInstanceStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of AppInstanceStatus type")
	}
	if oldStatus.State != status.State ||
		oldStatus.RestartInprogress != status.RestartInprogress ||
		oldStatus.PurgeInprogress != status.PurgeInprogress {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("restart-in-progress", status.RestartInprogress).
			AddField("purge-in-progress", status.PurgeInprogress).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-restart-in-progress", oldStatus.RestartInprogress).
			AddField("old-purge-in-progress", oldStatus.PurgeInprogress).
			Infof("App instance status modify")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime()
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("restart-in-progress", status.RestartInprogress).
			AddField("purge-in-progress", status.PurgeInprogress).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Errorf("App instance status modify")
	}
}

// LogDelete :
func (status AppInstanceStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.AppInstanceStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("restart-in-progress", status.RestartInprogress).
		AddField("purge-in-progress", status.PurgeInprogress).
		Infof("App instance status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status AppInstanceStatus) LogKey() string {
	return string(base.AppInstanceStatusLogType) + "-" + status.Key()
}

// Track more complicated workflows
type Inprogress uint8

// NotInprogress and other values for Inprogress
const (
	NotInprogress   Inprogress = iota
	RecreateVolumes            // Download and verify new images if need be
	BringDown
	BringUp
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
	PurgeCounter     uint32
	Name             string   // XXX Do depend on URL for clobber avoidance?
	NameIsURL        bool     // If not we form URL based on datastore info
	MaxDownSize      uint64   // Maximum download size (In bytes)
	CertificateChain []string //name of intermediate certificates
	ImageSignature   []byte   //signature of image
	SignatureKey     string   //certificate containing public key

	ImageSha256 string // sha256 of immutable image
	ReadOnly    bool
	Preserve    bool // If set a rw disk will be preserved across
	// boots (acivate/inactivate)
	MaxVolSize uint64         // Resize filesystem to this size if set (In bytes)
	Format     zconfig.Format // Default "raw"; could be raw, qcow, qcow2, vhd
	Devtype    string         // Default ""; could be e.g. "cdrom"
	Target     string         // Default "" is interpreted as "disk"
}

func RoundupToKB(b uint64) uint64 {
	return (b + 1023) / 1024
}

type StorageStatus struct {
	// ImageID - UUID of the image
	ImageID            uuid.UUID
	DatastoreID        uuid.UUID
	PurgeCounter       uint32
	Name               string
	ImageSha256        string   // sha256 of immutable image
	NameIsURL          bool     // If not we form URL based on datastore info
	MaxDownSize        uint64   // Maximum download size (In bytes)
	CertificateChain   []string //name of intermediate certificates
	ImageSignature     []byte   //signature of image
	SignatureKey       string   //certificate containing public key
	ReadOnly           bool
	Preserve           bool
	MaxVolSize         uint64 // Resize filesystem to this size if set (In bytes)
	Format             zconfig.Format
	Devtype            string
	Target             string  // Default "" is interpreted as "disk"
	State              SwState // DOWNLOADED etc
	Progress           uint    // In percent i.e., 0-100
	HasVolumemgrRef    bool    // Reference against volumemgr to clean up
	HasResolverRef     bool    // Reference against resolver for resolving tags
	IsContainer        bool    // Is the image a Container??
	Vdev               string  // Allocated
	ActiveFileLocation string  // Location of filestystem
	FinalObjDir        string  // Installation dir; may differ from verified
	// ErrorAndTimeWithSource provides SetError, SetErrrorWithSource, etc
	ErrorAndTimeWithSource
}

// ResolveKey will return the key of resolver config/status
func (ss *StorageStatus) ResolveKey() string {
	return fmt.Sprintf("%s+%s+%v", ss.DatastoreID.String(), ss.Name, ss.PurgeCounter)
}

// UpdateFromStorageConfig sets up StorageStatus based on StorageConfig struct
func (ss *StorageStatus) UpdateFromStorageConfig(sc StorageConfig) {
	ss.ImageID = sc.ImageID
	ss.DatastoreID = sc.DatastoreID
	ss.PurgeCounter = sc.PurgeCounter
	ss.Name = sc.Name
	ss.ImageSha256 = sc.ImageSha256
	ss.NameIsURL = sc.NameIsURL
	ss.MaxDownSize = sc.MaxDownSize
	ss.CertificateChain = sc.CertificateChain
	ss.ImageSignature = sc.ImageSignature
	ss.SignatureKey = sc.SignatureKey
	ss.ReadOnly = sc.ReadOnly
	ss.Preserve = sc.Preserve
	ss.MaxVolSize = sc.MaxVolSize
	ss.Format = sc.Format
	ss.Devtype = sc.Devtype
	ss.Target = sc.Target
	ss.State = 0
	ss.Progress = 0
	ss.HasVolumemgrRef = false
	ss.HasResolverRef = false
	if ss.Format == zconfig.Format_CONTAINER {
		ss.IsContainer = true
	}
	ss.Vdev = ""
	ss.ActiveFileLocation = ""
	ss.FinalObjDir = ""
	ss.ErrorAndTimeWithSource = ErrorAndTimeWithSource{}
	return
}

// IsCertsAvailable checks certificate requirement/availability for a Volume object
func (vs OldVolumeStatus) IsCertsAvailable(displaystr string) (bool, error) {
	if !vs.needsCerts() {
		log.Debugf("%s, Certs are not required\n", displaystr)
		return false, nil
	}
	cidx, err := vs.getCertCount(displaystr)
	return cidx != 0, err
}

// HandleCertStatus gets the CertObject Status for the volume object
// True, when there is no Certs or, the certificates are ready
// False, Certificates are not ready or, there are some errors
func (vs OldVolumeStatus) HandleCertStatus(displaystr string,
	certObjStatus CertObjStatus) (bool, ErrorAndTime) {
	if ret, errInfo := vs.checkCertsStatusForObject(certObjStatus); !ret {
		log.Infof("%s, Certs are still not ready\n", displaystr)
		return ret, errInfo
	}
	if ret := vs.checkCertsForObject(); !ret {
		log.Infof("%s, Certs are still not installed\n", displaystr)
		return ret, ErrorAndTime{}
	}
	return true, ErrorAndTime{}
}

// needsCerts whether certificates are required for the Volume object
func (vs OldVolumeStatus) needsCerts() bool {
	if vs.DownloadOrigin == nil {
		return false
	}
	if len(vs.DownloadOrigin.ImageSignature) == 0 {
		return false
	}
	return true
}

// getCertCount returns the number of certificates for the Volume Object
// called with valid ImageSignature only
func (vs OldVolumeStatus) getCertCount(displaystr string) (int, error) {
	cidx := 0
	if vs.DownloadOrigin == nil {
		return 0, nil
	}
	dos := vs.DownloadOrigin
	if dos.SignatureKey == "" {
		errStr := fmt.Sprintf("%s, Invalid Root CertURL\n", displaystr)
		log.Errorf(errStr)
		return cidx, errors.New(errStr)
	}
	cidx++
	if len(dos.CertificateChain) != 0 {
		for _, certURL := range dos.CertificateChain {
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
func (vs OldVolumeStatus) checkCertsStatusForObject(certObjStatus CertObjStatus) (bool, ErrorAndTime) {

	dos := vs.DownloadOrigin
	if dos == nil {
		return true, ErrorAndTime{}
	}
	if dos.SignatureKey != "" {
		found, installed, errInfo := certObjStatus.getCertStatus(dos.SignatureKey)
		if !found || !installed {
			return false, errInfo
		}
	}

	for _, certURL := range dos.CertificateChain {
		found, installed, errorAndTime := certObjStatus.getCertStatus(certURL)
		if !found || !installed {
			return false, errorAndTime
		}
	}
	return true, ErrorAndTime{}
}

// checkCertsForObject checks availability of Certs in Disk
func (vs OldVolumeStatus) checkCertsForObject() bool {

	dos := vs.DownloadOrigin
	if dos == nil {
		return true
	}
	if dos.SignatureKey != "" {
		safename := UrlToSafename(dos.SignatureKey, "")
		filename := CertificateDirname + "/" + SafenameToFilename(safename)
		// XXX result is just the sha? Or "serverCert.<sha>?
		if _, err := os.Stat(filename); err != nil {
			log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
			return false
		}
		// XXX check for valid or non-zero length?
	}

	for _, certURL := range dos.CertificateChain {
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
	AppUUID      uuid.UUID
	ImageID      uuid.UUID
	Hash         string
	PurgeCounter uint32
}

// Key is used for pubsub
func (aih AppAndImageToHash) Key() string {
	if aih.PurgeCounter == 0 {
		return fmt.Sprintf("%s.%s", aih.AppUUID.String(), aih.ImageID.String())
	} else {
		return fmt.Sprintf("%s.%s.%d", aih.AppUUID.String(), aih.ImageID.String(), aih.PurgeCounter)
	}
}
