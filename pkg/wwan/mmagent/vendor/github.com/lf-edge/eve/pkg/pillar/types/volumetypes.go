// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
)

// VolumeConfig specifies the needed information for volumes
type VolumeConfig struct {
	VolumeID                uuid.UUID
	ContentID               uuid.UUID
	VolumeContentOriginType zconfig.VolumeContentOriginType
	MaxVolSize              uint64
	ReadOnly                bool
	GenerationCounter       int64
	LocalGenerationCounter  int64
	Encrypted               bool
	DisplayName             string
	HasNoAppReferences      bool
	Target                  zconfig.Target
	CustomMeta              string
	// This is a replicated volume
	IsReplicated bool
	// This volume is container image for native container.
	// We will find out from NOHYPER flag in appinstanceconfig
	IsNativeContainer bool
}

// Key is volume UUID which will be unique
func (config VolumeConfig) Key() string {
	return fmt.Sprintf("%s#%d", config.VolumeID.String(),
		config.GenerationCounter+config.LocalGenerationCounter)
}

// LogCreate :
func (config VolumeConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.VolumeConfigLogType, config.DisplayName,
		config.VolumeID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("content-id", config.ContentID).
		AddField("max-vol-size-int64", config.MaxVolSize).
		AddField("generation-counter-int64", config.GenerationCounter).
		AddField("local-generation-counter-int64", config.LocalGenerationCounter).
		Noticef("Volume config create")
}

// LogModify :
func (config VolumeConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.VolumeConfigLogType, config.DisplayName,
		config.VolumeID, config.LogKey())

	oldConfig, ok := old.(VolumeConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of VolumeConfig type")
	}
	if oldConfig.ContentID != config.ContentID ||
		oldConfig.MaxVolSize != config.MaxVolSize {

		logObject.CloneAndAddField("content-id", config.ContentID).
			AddField("max-vol-size-int64", config.MaxVolSize).
			AddField("old-content-id", oldConfig.ContentID).
			AddField("old-max-vol-size-int64", oldConfig.MaxVolSize).
			Noticef("Volume config modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Noticef("Volume config modify other change")
	}
}

// LogDelete :
func (config VolumeConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.VolumeConfigLogType, config.DisplayName,
		config.VolumeID, config.LogKey())
	logObject.CloneAndAddField("content-id", config.ContentID).
		AddField("max-vol-size-int64", config.MaxVolSize).
		AddField("generation-counter-int64", config.GenerationCounter).
		AddField("local-generation-counter-int64", config.LocalGenerationCounter).
		Noticef("Volume config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config VolumeConfig) LogKey() string {
	return string(base.VolumeConfigLogType) + "-" + config.Key()
}

// volumeSubState is type for defining additional statuses for VolumeStatus
type volumeSubState uint8

// Enum of volumeSubState variants
const (
	VolumeSubStateInitial volumeSubState = iota
	VolumeSubStatePreparing
	VolumeSubStatePrepareDone
	VolumeSubStateCreated
	VolumeSubStateDeleting
)

// VolumeStatus is response from volumemgr about status of volumes
type VolumeStatus struct {
	VolumeID                uuid.UUID
	ContentID               uuid.UUID
	VolumeContentOriginType zconfig.VolumeContentOriginType
	MaxVolSize              uint64
	ReadOnly                bool
	GenerationCounter       int64
	LocalGenerationCounter  int64
	Encrypted               bool
	DisplayName             string
	State                   SwState
	SubState                volumeSubState
	RefCount                uint
	LastRefCountChangeTime  time.Time
	Progress                uint   // In percent i.e., 0-100
	TotalSize               int64  // expected size as reported by the downloader, if any
	CurrentSize             int64  // current total downloaded size as reported by the downloader
	FileLocation            string // Location of filestystem
	CreateTime              time.Time
	ContentFormat           zconfig.Format
	LastUse                 time.Time
	PreReboot               bool // Was volume last use prior to device reboot?
	ReferenceName           string
	WWN                     string
	Target                  zconfig.Target
	CustomMeta              string

	// Is this a replicated volume
	IsReplicated bool
	// Is this volume actually a container image for native container deployment
	// We find that info from NOHYPER flag set in appinstance.
	IsNativeContainer bool

	ErrorAndTimeWithSource
}

// Key is volume UUID which will be unique
func (status VolumeStatus) Key() string {
	return fmt.Sprintf("%s#%d", status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)
}

// IsContainer will return true if content tree attached
// to the volume is of container type
func (status VolumeStatus) IsContainer() bool {
	return status.ContentFormat == zconfig.Format_CONTAINER
}

// PathName returns the path of the volume
func (status VolumeStatus) PathName() string {
	baseDir := VolumeClearDirName
	if status.Encrypted {
		baseDir = VolumeEncryptedDirName
	}
	return fmt.Sprintf("%s/%s#%d.%s", baseDir, status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter,
		strings.ToLower(status.ContentFormat.String()))
}

// GetPVCName : returns the volume name for kubernetes(longhorn)
// Kubernetes does not allow special characters like '#' in the object names.
// so we need to generate a PVC name.
func (status VolumeStatus) GetPVCName() string {
	return fmt.Sprintf("%s-pvc-%d", status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)

}

// LogCreate :
func (status VolumeStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.VolumeStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("content-id", status.ContentID).
		AddField("max-vol-size-int64", status.MaxVolSize).
		AddField("state", status.State.String()).
		AddField("progress-int64", status.Progress).
		AddField("refcount-int64", status.RefCount).
		AddField("filelocation", status.FileLocation).
		Noticef("Volume status create")
}

// LogModify :
func (status VolumeStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.VolumeStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())

	oldStatus, ok := old.(VolumeStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of VolumeStatus type")
	}
	if oldStatus.ContentID != status.ContentID ||
		oldStatus.MaxVolSize != status.MaxVolSize ||
		oldStatus.State != status.State ||
		oldStatus.Progress != status.Progress ||
		oldStatus.RefCount != status.RefCount ||
		oldStatus.FileLocation != status.FileLocation {

		logObject.CloneAndAddField("content-id", status.ContentID).
			AddField("max-vol-size-int64", status.MaxVolSize).
			AddField("state", status.State.String()).
			AddField("progress-int64", status.Progress).
			AddField("refcount-int64", status.RefCount).
			AddField("filelocation", status.FileLocation).
			AddField("old-content-id", oldStatus.ContentID).
			AddField("old-max-vol-size-int64", oldStatus.MaxVolSize).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-progress-int64", oldStatus.Progress).
			AddField("old-refcount-int64", oldStatus.RefCount).
			AddField("old-filelocation", oldStatus.FileLocation).
			Noticef("Volume status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("Volume status modify other change")
	}
}

// LogDelete :
func (status VolumeStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.VolumeStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())
	logObject.CloneAndAddField("content-id", status.ContentID).
		AddField("max-vol-size-int64", status.MaxVolSize).
		AddField("state", status.State.String()).
		AddField("progress-int64", status.Progress).
		AddField("refcount-int64", status.RefCount).
		AddField("filelocation", status.FileLocation).
		Noticef("Volume status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status VolumeStatus) LogKey() string {
	return string(base.VolumeStatusLogType) + "-" + status.Key()
}

// VolumesSnapshotAction is the action to perform on the snapshot
type VolumesSnapshotAction uint8

const (
	// VolumesSnapshotUnspecifiedAction is the default value
	VolumesSnapshotUnspecifiedAction VolumesSnapshotAction = iota
	// VolumesSnapshotCreate is used to create a snapshot
	VolumesSnapshotCreate
	// VolumesSnapshotRollback is used to roll back to a snapshot
	VolumesSnapshotRollback
	// VolumesSnapshotDelete is used to delete a snapshot
	VolumesSnapshotDelete
)

func (action VolumesSnapshotAction) String() string {
	switch action {
	case VolumesSnapshotCreate:
		return "Create"
	case VolumesSnapshotRollback:
		return "Rollback"
	case VolumesSnapshotDelete:
		return "Delete"
	default:
		return "Unspecified"
	}
}

// VolumesSnapshotConfig is used to send snapshot requests from zedmanager to volumemgr
type VolumesSnapshotConfig struct {
	// SnapshotID is the ID of the snapshot
	SnapshotID string
	// Action is the action to perform on the snapshot
	Action VolumesSnapshotAction
	// VolumeIDs is a list of volumes to snapshot
	VolumeIDs []uuid.UUID
	// AppUUID used as a backlink to the app
	AppUUID uuid.UUID
}

// Key returns unique key for the snapshot
func (config VolumesSnapshotConfig) Key() string {
	return config.SnapshotID
}

// VolumesSnapshotStatus is used to send snapshot status from volumemgr to zedmanager
type VolumesSnapshotStatus struct {
	// SnapshotID is the ID of the snapshot, critical field
	SnapshotID string `mandatory:"true"`
	// Metadata is a map of volumeID to metadata, depending on the volume type. Critical field.
	VolumeSnapshotMeta map[string]interface{} `mandatory:"true"`
	// TimeCreated is the time the snapshot was created, reported by FS-specific code
	TimeCreated time.Time
	// AppUUID used as a backlink to the app, critical field
	AppUUID uuid.UUID `mandatory:"true"`
	// RefCount is the number of times the snapshot is used. Necessary to trigger the handleModify handler
	RefCount int
	// ResultOfAction is the type of action that was performed on the snapshot that resulted in this status
	ResultOfAction VolumesSnapshotAction
	// ErrorAndTimeWithSource provides SetErrorNow() and ClearError()
	ErrorAndTimeWithSource
}

// Key returns unique key for the snapshot
func (status VolumesSnapshotStatus) Key() string {
	return status.SnapshotID
}

// VolumeRefConfig : Used for communication from zedagent to volumemgr, contains info from AppInstanceConfig
type VolumeRefConfig struct {
	// this part shows the link between the volume and the app
	VolumeID               uuid.UUID
	GenerationCounter      int64
	LocalGenerationCounter int64
	AppUUID                uuid.UUID

	// this information comes from AppInstanceConfig and remains constant
	MountDir string

	// this part is for communication between zedmanager and volumemgr (set by zedmanager)
	VerifyOnly bool // controls whether the volumemgr should only download and verify the volume (true) or also create it (false)
}

// Key : VolumeRefConfig unique key (used to uniquely identify the current struct, mostly for pubsub) - the same as for the corresponding VolumeRefStatus
func (config VolumeRefConfig) Key() string {
	return fmt.Sprintf("%s#%d#%s", config.VolumeID.String(),
		config.GenerationCounter+config.LocalGenerationCounter, config.AppUUID.String())
}

// VolumeKey : Unique key of volume referenced in VolumeRefConfig (used to uniquely identify the volume, attached to the app instance)
func (config VolumeRefConfig) VolumeKey() string {
	return fmt.Sprintf("%s#%d", config.VolumeID.String(),
		config.GenerationCounter+config.LocalGenerationCounter)
}

// LogCreate :
func (config VolumeRefConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.VolumeRefConfigLogType, "",
		config.VolumeID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("generation-counter-int64", config.GenerationCounter).
		AddField("local-generation-counter-int64", config.LocalGenerationCounter).
		Noticef("Volume ref config create")
}

// LogModify :
func (config VolumeRefConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.VolumeRefConfigLogType, "",
		config.VolumeID, config.LogKey())

	oldConfig, ok := old.(VolumeRefConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of VolumeRefConfig type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
		Noticef("Volume ref config modify other change")
}

// LogDelete :
func (config VolumeRefConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.VolumeRefConfigLogType, "",
		config.VolumeID, config.LogKey())
	logObject.Noticef("Volume ref config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config VolumeRefConfig) LogKey() string {
	return string(base.VolumeRefConfigLogType) + "-" + config.Key()
}

// VolumeRefStatus : Reference to a Volume specified separately in the API
// If a volume is purged (re-created from scratch) it will either have a new
// UUID or a new generationCount
type VolumeRefStatus struct {
	VolumeID               uuid.UUID
	GenerationCounter      int64
	LocalGenerationCounter int64
	AppUUID                uuid.UUID
	State                  SwState
	ActiveFileLocation     string
	ContentFormat          zconfig.Format
	ReadOnly               bool
	DisplayName            string
	MaxVolSize             uint64
	PendingAdd             bool // Flag to identify whether volume ref config published or not
	WWN                    string
	VerifyOnly             bool
	Target                 zconfig.Target
	CustomMeta             string
	ReferenceName          string

	ErrorAndTimeWithSource
}

// Key : VolumeRefStatus unique key (used to uniquely identify the current struct, mostly for pubsub) - the same as for the corresponding VolumeRefConfig
func (status VolumeRefStatus) Key() string {
	return fmt.Sprintf("%s#%d#%s", status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter, status.AppUUID.String())
}

// VolumeKey : Unique key of volume referenced in VolumeRefStatus (used to uniquely identify the volume, attached to the app instance)
func (status VolumeRefStatus) VolumeKey() string {
	return fmt.Sprintf("%s#%d", status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)
}

// IsContainer will return true if content tree attached
// to the volume ref is of container type
func (status VolumeRefStatus) IsContainer() bool {
	return status.ContentFormat == zconfig.Format_CONTAINER
}

// LogCreate :
func (status VolumeRefStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.VolumeRefStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("generation-counter-int64", status.GenerationCounter).
		AddField("local-generation-counter-int64", status.LocalGenerationCounter).
		AddField("state", status.State.String()).
		AddField("filelocation", status.ActiveFileLocation).
		AddField("content-format", status.ContentFormat).
		AddField("read-only-bool", status.ReadOnly).
		AddField("displayname", status.DisplayName).
		AddField("max-vol-size-int64", status.MaxVolSize).
		AddField("pending-add-bool", status.PendingAdd).
		Noticef("Volume ref status create")
}

// LogModify :
func (status VolumeRefStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.VolumeRefStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())

	oldStatus, ok := old.(VolumeRefStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of VolumeRefStatus type")
	}
	if oldStatus.State != status.State ||
		oldStatus.ActiveFileLocation != status.ActiveFileLocation ||
		oldStatus.ContentFormat != status.ContentFormat ||
		oldStatus.ReadOnly != status.ReadOnly ||
		oldStatus.DisplayName != status.DisplayName ||
		oldStatus.MaxVolSize != status.MaxVolSize ||
		oldStatus.PendingAdd != status.PendingAdd {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("filelocation", status.ActiveFileLocation).
			AddField("content-format", status.ContentFormat).
			AddField("read-only-bool", status.ReadOnly).
			AddField("displayname", status.DisplayName).
			AddField("max-vol-size-int64", status.MaxVolSize).
			AddField("pending-add-bool", status.PendingAdd).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-filelocation", oldStatus.ActiveFileLocation).
			AddField("content-format", oldStatus.ContentFormat).
			AddField("read-only-bool", oldStatus.ReadOnly).
			AddField("displayname", oldStatus.DisplayName).
			AddField("old-max-vol-size-int64", oldStatus.MaxVolSize).
			AddField("Pending-add-bool", oldStatus.PendingAdd).
			Noticef("Volume ref status modify")
	}
}

// LogDelete :
func (status VolumeRefStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.VolumeRefStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())
	logObject.CloneAndAddField("generation-counter-int64", status.GenerationCounter).
		AddField("local-generation-counter-int64", status.LocalGenerationCounter).
		AddField("state", status.State.String()).
		AddField("filelocation", status.ActiveFileLocation).
		AddField("content-format", status.ContentFormat).
		AddField("read-only-bool", status.ReadOnly).
		AddField("displayname", status.DisplayName).
		AddField("max-vol-size-int64", status.MaxVolSize).
		AddField("pending-add-bool", status.PendingAdd).
		Noticef("Volume ref status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status VolumeRefStatus) LogKey() string {
	return string(base.VolumeRefStatusLogType) + "-" + status.Key()
}

// VolumeCreatePending is temporary store for volumes that are creating
// After successful creating operation we should delete this object
type VolumeCreatePending struct {
	VolumeID               uuid.UUID
	GenerationCounter      int64
	LocalGenerationCounter int64
	ContentFormat          zconfig.Format
	Encrypted              bool
}

// Key : VolumeCreatePending unique key
func (status VolumeCreatePending) Key() string {
	return fmt.Sprintf("%s#%d", status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)
}

// LogKey :
func (status VolumeCreatePending) LogKey() string {
	return string(base.VolumeCreatePendingLogType) + "-" + status.Key()
}

// PathName returns the path of the volume
func (status VolumeCreatePending) PathName() string {
	baseDir := VolumeClearDirName
	if status.Encrypted {
		baseDir = VolumeEncryptedDirName
	}
	return fmt.Sprintf("%s/%s#%d.%s", baseDir, status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter,
		strings.ToLower(status.ContentFormat.String()))
}

// IsContainer will return true if content tree attached
// to the volume is of container type
func (status VolumeCreatePending) IsContainer() bool {
	return status.ContentFormat == zconfig.Format_CONTAINER
}

// VolumeCreatePendingFromVolumeStatus returns VolumeCreatePending for provided VolumeStatus
func VolumeCreatePendingFromVolumeStatus(status VolumeStatus) VolumeCreatePending {
	return VolumeCreatePending{
		VolumeID:               status.VolumeID,
		GenerationCounter:      status.GenerationCounter,
		LocalGenerationCounter: status.LocalGenerationCounter,
		ContentFormat:          status.ContentFormat,
		Encrypted:              status.Encrypted,
	}
}

// LogCreate :
func (status VolumeCreatePending) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.VolumeCreatePendingLogType, "",
		status.VolumeID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("generation-counter-int64", status.GenerationCounter).
		AddField("local-generation-counter-int64", status.LocalGenerationCounter).
		AddField("content-format", status.ContentFormat).
		AddField("encrypted", status.Encrypted).
		Noticef("Volume create pending create")
}

// LogModify :
func (status VolumeCreatePending) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.VolumeCreatePendingLogType, "",
		status.VolumeID, status.LogKey())

	oldStatus, ok := old.(VolumeCreatePending)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of VolumeCreatePending type")
	}
	if oldStatus.GenerationCounter != status.GenerationCounter ||
		oldStatus.LocalGenerationCounter != status.LocalGenerationCounter ||
		oldStatus.ContentFormat != status.ContentFormat ||
		oldStatus.Encrypted != status.Encrypted {

		logObject.CloneAndAddField("generation-counter-int64", status.GenerationCounter).
			AddField("local-generation-counter-int64", status.LocalGenerationCounter).
			AddField("content-format", status.ContentFormat).
			AddField("encrypted", status.Encrypted).
			AddField("old-generation-counter-int64", oldStatus.GenerationCounter).
			AddField("old-local-generation-counter-int64", oldStatus.LocalGenerationCounter).
			AddField("old-content-format", oldStatus.ContentFormat).
			AddField("old-encrypted", oldStatus.Encrypted).
			Noticef("Volume create pending modify")
	}
}

// LogDelete :
func (status VolumeCreatePending) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.VolumeCreatePendingLogType, "",
		status.VolumeID, status.LogKey())
	logObject.CloneAndAddField("generation-counter-int64", status.GenerationCounter).
		AddField("local-generation-counter-int64", status.LocalGenerationCounter).
		AddField("content-format", status.ContentFormat).
		AddField("encrypted", status.Encrypted).
		Noticef("Volume create pending delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// VolumeMgrStatus :
type VolumeMgrStatus struct {
	Name           string
	Initialized    bool
	RemainingSpace uint64 // In bytes. Takes into account "reserved" for dom0
}

// Key :
func (status VolumeMgrStatus) Key() string {
	return status.Name
}

// LogCreate :
func (status VolumeMgrStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.VolumeMgrStatusLogType, status.Name,
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Zedagent status create")
}

// LogModify :
func (status VolumeMgrStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.VolumeMgrStatusLogType, status.Name,
		nilUUID, status.LogKey())

	oldStatus, ok := old.(VolumeMgrStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of VolumeMgrStatus type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Zedagent status modify")
}

// LogDelete :
func (status VolumeMgrStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.VolumeMgrStatusLogType, status.Name,
		nilUUID, status.LogKey())
	logObject.Noticef("Zedagent status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status VolumeMgrStatus) LogKey() string {
	return string(base.VolumeMgrStatusLogType) + "-" + status.Key()
}
