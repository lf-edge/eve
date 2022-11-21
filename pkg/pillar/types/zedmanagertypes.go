// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"net"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	uuid "github.com/satori/go.uuid"
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
// (advertise the EID in lisp and boot the guest) is driven by the Activate
// attribute.
type AppInstanceConfig struct {
	UUIDandVersion UUIDandVersion
	DisplayName    string

	// Error
	//	If this is set, do not process further.. Just set the status to error
	//	so the cloud gets it.
	Errors              []string
	FixedResources      VmConfig // CPU etc
	VolumeRefConfigList []VolumeRefConfig
	Activate            bool //EffectiveActivate in AppInstanceStatus must be used for the actual activation
	UnderlayNetworkList []UnderlayNetworkConfig
	IoAdapterList       []IoAdapter
	RestartCmd          AppInstanceOpsCmd
	PurgeCmd            AppInstanceOpsCmd
	LocalRestartCmd     AppInstanceOpsCmd
	LocalPurgeCmd       AppInstanceOpsCmd
	HasLocalServer      bool // Set if localServerAddr matches
	// XXX: to be deprecated, use CipherBlockStatus instead
	CloudInitUserData *string `json:"pubsub-large-CloudInitUserData"`
	RemoteConsole     bool
	// Collect Stats IP Address, assume port is the default docker API for http: 2375
	CollectStatsIPAddr net.IP

	// CipherBlockStatus, for encrypted cloud-init data
	CipherBlockStatus

	MetaDataType MetaDataType

	ProfileList []string

	Delay time.Duration

	// Service flag indicates that we want to start app instance
	// with options defined in org.mobyproject.config label of image provided by linuxkit
	Service bool

	// All changes to the cloud-init config are tracked using this version field -
	// once the version is changed cloud-init tool restarts in a guest.
	CloudInitVersion uint32
}

type AppInstanceOpsCmd struct {
	Counter   uint32
	ApplyTime string // XXX not currently used
}

// IoAdapter specifies that a group of ports should be assigned
type IoAdapter struct {
	Type  IoType
	Name  string      // Short hand name such as "COM1" or "eth1-2"
	EthVf sriov.EthVF // Applies only to the VF IoType
}

// LogCreate :
func (config AppInstanceConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppInstanceConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activate", config.Activate).
		AddField("remote-console", config.RemoteConsole).
		Noticef("App instance config create")
}

// LogModify :
func (config AppInstanceConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppInstanceConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())

	oldConfig, ok := old.(AppInstanceConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppInstanceConfig type")
	}
	if oldConfig.Activate != config.Activate ||
		oldConfig.RemoteConsole != config.RemoteConsole {

		logObject.CloneAndAddField("activate", config.Activate).
			AddField("remote-console", config.RemoteConsole).
			AddField("old-activate", oldConfig.Activate).
			AddField("old-remote-console", oldConfig.RemoteConsole).
			Noticef("App instance config modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Noticef("App instance config modify other change")
	}
}

// LogDelete :
func (config AppInstanceConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppInstanceConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	logObject.CloneAndAddField("activate", config.Activate).
		AddField("remote-console", config.RemoteConsole).
		Noticef("App instance config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config AppInstanceConfig) LogKey() string {
	return string(base.AppInstanceConfigLogType) + "-" + config.Key()
}

func (config AppInstanceConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
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
	UnderlayNetworks    []UnderlayNetworkStatus
	BootTime            time.Time
	IoAdapterList       []IoAdapter // Report what was actually used
	RestartInprogress   Inprogress
	RestartStartedAt    time.Time
	PurgeInprogress     Inprogress
	PurgeStartedAt      time.Time

	// Minimum state across all steps and all StorageStatus.
	// Error* set implies error.
	State          SwState
	MissingNetwork bool // If some Network UUID not found
	MissingMemory  bool // Waiting for memory

	// All error strings across all steps and all StorageStatus
	// ErrorAndTimeWithSource provides SetError, SetErrrorWithSource, etc
	ErrorAndTimeWithSource
	// Effective time, when the application should start
	StartTime time.Time
}

// AppCount is uint8 and it should be sufficient for the number of apps we can support
type AppCount uint8

// AppInstanceSummary captures the running state of all apps
type AppInstanceSummary struct {
	UUIDandVersion UUIDandVersion
	TotalStarting  AppCount // Total number of apps starting/booting
	TotalRunning   AppCount // Total number of apps in running state
	TotalStopping  AppCount // Total number of apps in halting state
	TotalError     AppCount // Total number of apps in error state
}

// LogCreate :
func (status AppInstanceStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppInstanceStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("restart-in-progress", status.RestartInprogress).
		AddField("purge-in-progress", status.PurgeInprogress).
		Noticef("App instance status create")
}

// LogModify :
func (status AppInstanceStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppInstanceStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())

	oldStatus, ok := old.(AppInstanceStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppInstanceStatus type")
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
			Noticef("App instance status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("App instance status modify other change")
	}

	if status.HasError() {
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("restart-in-progress", status.RestartInprogress).
			AddField("purge-in-progress", status.PurgeInprogress).
			AddField("error", status.Error).
			AddField("error-time", status.ErrorTime).
			Noticef("App instance status modify")
	}
}

// LogDelete :
func (status AppInstanceStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppInstanceStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("restart-in-progress", status.RestartInprogress).
		AddField("purge-in-progress", status.PurgeInprogress).
		Noticef("App instance status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status AppInstanceStatus) LogKey() string {
	return string(base.AppInstanceStatusLogType) + "-" + status.Key()
}

// Track more complicated workflows
type Inprogress uint8

// NotInprogress and other values for Inprogress
const (
	NotInprogress     Inprogress = iota
	DownloadAndVerify            // Download and verify new images if need be
	BringDown
	RecreateVolumes
	BringUp
)

func (status AppInstanceStatus) Key() string {
	return status.UUIDandVersion.UUID.String()
}

// Key provides a unique key
func (status AppInstanceSummary) Key() string {
	return status.UUIDandVersion.UUID.String()
}

// GetAppInterfaceList is a helper function to get all the vifnames
func (status AppInstanceStatus) GetAppInterfaceList() []string {

	var viflist []string
	for _, ulStatus := range status.UnderlayNetworks {
		if ulStatus.VifUsed != "" {
			viflist = append(viflist, ulStatus.VifUsed)
		}
	}
	return viflist
}

func RoundupToKB(b uint64) uint64 {
	return (b + 1023) / 1024
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

// LogCreate :
func (aih AppAndImageToHash) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppAndImageToHashLogType, "",
		aih.AppUUID, aih.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("purge-counter-int64", aih.PurgeCounter).
		AddField("image-id", aih.ImageID.String()).
		AddField("hash", aih.Hash).
		Noticef("App and image to hash create")
}

// LogModify :
func (aih AppAndImageToHash) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppAndImageToHashLogType, "",
		aih.AppUUID, aih.LogKey())

	oldAih, ok := old.(AppAndImageToHash)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppAndImageToHash type")
	}
	if oldAih.Hash != aih.Hash ||
		oldAih.PurgeCounter != aih.PurgeCounter {

		logObject.CloneAndAddField("purge-counter-int64", aih.PurgeCounter).
			AddField("image-id", aih.ImageID.String()).
			AddField("hash", aih.Hash).
			AddField("purge-counter-int64", aih.PurgeCounter).
			AddField("old-hash", oldAih.Hash).
			AddField("old-purge-counter-int64", oldAih.PurgeCounter).
			Noticef("App and image to hash modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldAih, aih)).
			Noticef("App and image to hash modify other change")
	}
}

// LogDelete :
func (aih AppAndImageToHash) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppAndImageToHashLogType, "",
		aih.AppUUID, aih.LogKey())
	logObject.CloneAndAddField("purge-counter-int64", aih.PurgeCounter).
		AddField("image-id", aih.ImageID.String()).
		AddField("hash", aih.Hash).
		Noticef("App and image to hash delete")

	base.DeleteLogObject(logBase, aih.LogKey())
}

// LogKey :
func (aih AppAndImageToHash) LogKey() string {
	return string(base.AppAndImageToHashLogType) + "-" + aih.Key()
}
