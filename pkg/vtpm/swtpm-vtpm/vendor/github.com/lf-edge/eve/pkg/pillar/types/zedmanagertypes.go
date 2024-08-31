// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	uuid "github.com/satori/go.uuid"
)

// UUID plus version
type UUIDandVersion struct {
	UUID    uuid.UUID
	Version string
}

// SnapshotType type of the snapshot creation trigger
// Must match the definition in appconfig.proto
type SnapshotType int32

const (
	// SnapshotTypeUnspecified is the default value, and should not be used in practice
	SnapshotTypeUnspecified SnapshotType = 0
	// SnapshotTypeAppUpdate is used when the snapshot is created as a result of an app update
	SnapshotTypeAppUpdate SnapshotType = 1
)

func (s SnapshotType) String() string {
	switch s {
	case SnapshotTypeUnspecified:
		return "SnapshotTypeUnspecified"
	case SnapshotTypeAppUpdate:
		return "SnapshotTypeAppUpdate"
	default:
		return fmt.Sprintf("Unknown SnapshotType %d", s)
	}
}

// ConvertToInfoSnapshotType converts from SnapshotType to info.SnapshotType
func (s SnapshotType) ConvertToInfoSnapshotType() info.SnapshotType {
	switch s {
	case SnapshotTypeAppUpdate:
		return info.SnapshotType_SNAPSHOT_TYPE_APP_UPDATE
	default:
		return info.SnapshotType_SNAPSHOT_TYPE_UNSPECIFIED
	}
}

// SnapshotDesc a description of a snapshot instance
type SnapshotDesc struct {
	SnapshotID   string       // UUID of the snapshot
	SnapshotType SnapshotType // Type of the snapshot creation trigger
}

// SnapshotInstanceStatus status of a snapshot instance. Used as a zedmanager-level representation of a snapshot
type SnapshotInstanceStatus struct {
	// Snapshot contains the snapshot description
	Snapshot SnapshotDesc `mandatory:"true"`
	// Reported indicates if the snapshot has been reported to the controller
	Reported bool
	// TimeTriggered is the time when the snapshot was triggered. At the moment, it is used to check if the snapshot has
	// already been triggered. Later it can be used to order the snapshots for example in the case of choosing the
	// snapshot to be deleted.
	TimeTriggered time.Time
	// TimeCreated is the time when the snapshot was created. It's reported by FS-specific snapshot creation code.
	TimeCreated time.Time
	// AppInstanceID is the UUID of the app instance the snapshot belongs to
	AppInstanceID uuid.UUID `mandatory:"true"`
	// ConfigVersion is the version of the app instance config at the moment of the snapshot creation
	// It is reported to the controller, so it can use the proper config to roll back the app instance
	ConfigVersion UUIDandVersion `mandatory:"true"`
	// Error indicates if snapshot deletion or a rollback to the snapshot failed
	Error ErrorDescription
}

// SnapshotConfig configuration of the snapshot handling for the app instance
type SnapshotConfig struct {
	ActiveSnapshot string            // UUID of the active snapshot used by the app instance
	MaxSnapshots   uint32            // Number of snapshots that may be created for the app instance
	RollbackCmd    AppInstanceOpsCmd // Command to roll back the app instance to the active snapshot
	Snapshots      []SnapshotDesc    // List of snapshots known to the controller at the moment
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
	DisableLogs         bool
	VolumeRefConfigList []VolumeRefConfig
	Activate            bool //EffectiveActivate in AppInstanceStatus must be used for the actual activation
	AppNetAdapterList   []AppNetAdapterConfig
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

	// Contains the configuration of the snapshot handling for the app instance.
	// Meanwhile, the list of actual snapshots is stored in the AppInstanceStatus.
	Snapshot SnapshotConfig

	// allow AppInstance to discover other AppInstances attached to its network instances
	AllowToDiscover bool
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

// SnapshottingStatus contains the snapshot information for the app instance.
type SnapshottingStatus struct {
	// MaxSnapshots indicates the maximum number of snapshots to be kept for the app instance.
	MaxSnapshots uint32
	// RequestedSnapshots contains the list of snapshots to be taken for the app instance.
	RequestedSnapshots []SnapshotInstanceStatus
	// AvailableSnapshots contains the list of snapshots available for the app instance.
	AvailableSnapshots []SnapshotInstanceStatus
	// SnapshotsToBeDeleted contains the list of snapshots to be deleted for the app instance.
	SnapshotsToBeDeleted []SnapshotDesc
	// PreparedVolumesSnapshotConfigs contains the list of snapshots to be triggered for the app instance.
	PreparedVolumesSnapshotConfigs []VolumesSnapshotConfig
	// SnapshotOnUpgrade indicates whether a snapshot should be taken during the app instance update.
	SnapshotOnUpgrade bool
	// HasRollbackRequest indicates whether there are any rollback requests for the app instance.
	// Set to true when a rollback is requested by controller, set to false when the rollback is triggered.
	HasRollbackRequest bool
	// ActiveSnapshot contains the id of the snapshot to be used for the rollback.
	ActiveSnapshot string
	// RollbackInProgress indicates whether a rollback is in progress for the app instance.
	// Set to true when a rollback is triggered, set to false when the rollback is completed.
	RollbackInProgress bool
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
	AppNetAdapters      []AppNetAdapterStatus
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
	// Snapshot related information
	SnapStatus SnapshottingStatus
	// Estimated memory overhead for VM, counted in MB
	MemOverhead uint64
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
	for _, adapterStatus := range status.AppNetAdapters {
		if adapterStatus.VifUsed != "" {
			viflist = append(viflist, adapterStatus.VifUsed)
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

// GetSnapshotDir returns the snapshot directory for the given snapshot ID
func GetSnapshotDir(snapshotID string) string {
	return filepath.Join(SnapshotsDirname, snapshotID)
}

// GetVolumesSnapshotStatusFile returns the volumes snapshot status file for the given snapshot ID and volume ID
func GetVolumesSnapshotStatusFile(snapshotID string) string {
	return filepath.Join(GetSnapshotDir(snapshotID), SnapshotVolumesSnapshotStatusFilename)
}

// GetSnapshotInstanceStatusFile returns the instance status file for the given snapshot ID
func GetSnapshotInstanceStatusFile(snapshotID string) string {
	return filepath.Join(GetSnapshotDir(snapshotID), SnapshotInstanceStatusFilename)
}

// GetSnapshotAppInstanceConfigFile returns the app instance config file for the given snapshot ID
func GetSnapshotAppInstanceConfigFile(snapshotID string) string {
	return filepath.Join(GetSnapshotDir(snapshotID), SnapshotAppInstanceConfigFilename)
}
