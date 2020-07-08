// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"net"
	"time"

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
	VolumeRefConfigList []VolumeRefConfig
	Activate            bool
	OverlayNetworkList  []EIDOverlayConfig
	UnderlayNetworkList []UnderlayNetworkConfig
	IoAdapterList       []IoAdapter
	RestartCmd          AppInstanceOpsCmd
	PurgeCmd            AppInstanceOpsCmd
	// XXX: to be deprecated, use CipherBlockStatus instead
	CloudInitUserData *string // base64-encoded
	RemoteConsole     bool
	// Collect Stats IP Address, assume port is the default docker API for http: 2375
	CollectStatsIPAddr net.IP

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
	UUIDandVersion      UUIDandVersion
	DisplayName         string
	DomainName          string // Once booted
	Activated           bool
	ActivateInprogress  bool     // Needed for cleanup after failure
	FixedResources      VmConfig // CPU etc
	VolumeRefStatusList []VolumeRefStatus
	EIDList             []EIDStatusDetails
	OverlayNetworks     []OverlayNetworkStatus
	UnderlayNetworks    []UnderlayNetworkStatus
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

func RoundupToKB(b uint64) uint64 {
	return (b + 1023) / 1024
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
