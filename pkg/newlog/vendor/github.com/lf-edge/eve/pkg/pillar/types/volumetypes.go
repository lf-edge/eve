// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
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
	RefCount                uint
	GenerationCounter       int64
	LocalGenerationCounter  int64
	Encrypted               bool
	DisplayName             string
	HasNoAppReferences      bool
	Target                  zconfig.Target
	CustomMeta              string
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
		AddField("refcount-int64", config.RefCount).
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
		oldConfig.MaxVolSize != config.MaxVolSize ||
		oldConfig.RefCount != config.RefCount {

		logObject.CloneAndAddField("content-id", config.ContentID).
			AddField("max-vol-size-int64", config.MaxVolSize).
			AddField("refcount-int64", config.RefCount).
			AddField("old-content-id", oldConfig.ContentID).
			AddField("old-max-vol-size-int64", oldConfig.MaxVolSize).
			AddField("old-refcount-int64", oldConfig.RefCount).
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
		AddField("refcount-int64", config.RefCount).
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
	if status.ContentFormat == zconfig.Format_CONTAINER {
		return true
	}
	return false
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

// VolumeRefConfig : Reference to a Volume specified separately in the API
// If a volume is purged (re-created from scratch) it will either have a new
// UUID or a new generationCount
type VolumeRefConfig struct {
	VolumeID               uuid.UUID
	GenerationCounter      int64
	LocalGenerationCounter int64
	RefCount               uint
	MountDir               string
	VerifyOnly             bool
}

// Key : VolumeRefConfig unique key
func (config VolumeRefConfig) Key() string {
	return fmt.Sprintf("%s#%d", config.VolumeID.String(),
		config.GenerationCounter+config.LocalGenerationCounter)
}

// VolumeKey : Unique key of volume referenced in VolumeRefConfig
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
	logObject.CloneAndAddField("refcount-int64", config.RefCount).
		AddField("generation-counter-int64", config.GenerationCounter).
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
	if oldConfig.RefCount != config.RefCount {
		logObject.CloneAndAddField("refcount-int64", config.RefCount).
			AddField("old-refcount-int64", oldConfig.RefCount).
			Noticef("Volume ref config modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Noticef("Volume ref config modify other change")
	}
}

// LogDelete :
func (config VolumeRefConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.VolumeRefConfigLogType, "",
		config.VolumeID, config.LogKey())
	logObject.CloneAndAddField("refcount-int64", config.RefCount).
		Noticef("Volume ref config delete")

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
	RefCount               uint
	State                  SwState
	ActiveFileLocation     string
	ContentFormat          zconfig.Format
	ReadOnly               bool
	DisplayName            string
	MaxVolSize             uint64
	MountDir               string
	PendingAdd             bool // Flag to identify whether volume ref config published or not
	WWN                    string
	VerifyOnly             bool
	Target                 zconfig.Target
	CustomMeta             string

	ErrorAndTimeWithSource
}

// Key : VolumeRefStatus unique key
func (status VolumeRefStatus) Key() string {
	return fmt.Sprintf("%s#%d", status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)
}

// VolumeKey : Unique key of volume referenced in VolumeRefStatus
func (status VolumeRefStatus) VolumeKey() string {
	return fmt.Sprintf("%s#%d", status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)
}

// IsContainer will return true if content tree attached
// to the volume ref is of container type
func (status VolumeRefStatus) IsContainer() bool {
	if status.ContentFormat == zconfig.Format_CONTAINER {
		return true
	}
	return false
}

// LogCreate :
func (status VolumeRefStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.VolumeRefStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("refcount-int64", status.RefCount).
		AddField("generation-counter-int64", status.GenerationCounter).
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
	if oldStatus.RefCount != status.RefCount ||
		oldStatus.State != status.State ||
		oldStatus.ActiveFileLocation != status.ActiveFileLocation ||
		oldStatus.ContentFormat != status.ContentFormat ||
		oldStatus.ReadOnly != status.ReadOnly ||
		oldStatus.DisplayName != status.DisplayName ||
		oldStatus.MaxVolSize != status.MaxVolSize ||
		oldStatus.PendingAdd != status.PendingAdd {

		logObject.CloneAndAddField("refcount-int64", status.RefCount).
			AddField("state", status.State.String()).
			AddField("filelocation", status.ActiveFileLocation).
			AddField("content-format", status.ContentFormat).
			AddField("read-only-bool", status.ReadOnly).
			AddField("displayname", status.DisplayName).
			AddField("max-vol-size-int64", status.MaxVolSize).
			AddField("pending-add-bool", status.PendingAdd).
			AddField("refcount-int64", oldStatus.RefCount).
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
	logObject.CloneAndAddField("refcount-int64", status.RefCount).
		AddField("generation-counter-int64", status.GenerationCounter).
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
