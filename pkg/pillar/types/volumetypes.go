// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
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
	DisplayName             string
}

// Key is volume UUID which will be unique
func (config VolumeConfig) Key() string {
	return fmt.Sprintf("%s#%d", config.VolumeID.String(), config.GenerationCounter)
}

// LogCreate :
func (config VolumeConfig) LogCreate() {
	logObject := base.NewLogObject(base.VolumeConfigLogType, config.DisplayName,
		config.VolumeID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("content-id", config.ContentID).
		Infof("Volume config create")
}

// LogModify :
func (config VolumeConfig) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.VolumeConfigLogType, config.DisplayName,
		config.VolumeID, config.LogKey())

	oldConfig, ok := old.(VolumeConfig)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of VolumeConfig type")
	}
	if oldConfig.ContentID != config.ContentID ||
		oldConfig.MaxVolSize != config.MaxVolSize ||
		oldConfig.RefCount != config.RefCount ||
		oldConfig.GenerationCounter != config.GenerationCounter {

		logObject.CloneAndAddField("content-id", config.ContentID).
			AddField("max-vol-size-int64", config.MaxVolSize).
			AddField("refcount-int64", config.RefCount).
			AddField("generation-counter-int64", config.GenerationCounter).
			AddField("old-content-id", oldConfig.ContentID).
			AddField("old-max-vol-size-int64", oldConfig.MaxVolSize).
			AddField("old-refcount-int64", oldConfig.RefCount).
			AddField("old-generation-counter-int64", oldConfig.GenerationCounter).
			Infof("Volume config modify")
	}
}

// LogDelete :
func (config VolumeConfig) LogDelete() {
	logObject := base.EnsureLogObject(base.VolumeConfigLogType, config.DisplayName,
		config.VolumeID, config.LogKey())
	logObject.CloneAndAddField("content-id", config.ContentID).
		Infof("Volume config delete")

	base.DeleteLogObject(config.LogKey())
}

// LogKey :
func (config VolumeConfig) LogKey() string {
	return string(base.VolumeConfigLogType) + "-" + config.Key()
}

// VolumeStatus is response from volumemgr about status of volumes
type VolumeStatus struct {
	VolumeID                uuid.UUID
	ContentID               uuid.UUID
	VolumeContentOriginType zconfig.VolumeContentOriginType
	MaxVolSize              uint64
	ReadOnly                bool
	GenerationCounter       int64
	DisplayName             string
	State                   SwState
	RefCount                uint
	Progress                uint   // In percent i.e., 0-100
	FileLocation            string // Location of filestystem
	VolumeCreated           bool   // Done aka Activated
	ContentFormat           zconfig.Format
	LastUse                 time.Time
	PreReboot               bool // Was volume last use prior to device reboot?

	ErrorAndTimeWithSource
}

// Key is volume UUID which will be unique
func (status VolumeStatus) Key() string {
	return fmt.Sprintf("%s#%d", status.VolumeID.String(), status.GenerationCounter)
}

// IsContainer will return true if content tree attached
// to the volume is of container type
func (status VolumeStatus) IsContainer() bool {
	if status.ContentFormat == zconfig.Format_CONTAINER {
		return true
	}
	return false
}

// LogCreate :
func (status VolumeStatus) LogCreate() {
	logObject := base.NewLogObject(base.VolumeStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("content-id", status.ContentID).
		AddField("max-vol-size-int64", status.MaxVolSize).
		AddField("state", status.State).
		AddField("progress-int64", status.Progress).
		AddField("refcount-int64", status.RefCount).
		AddField("filelocation", status.FileLocation).
		Infof("Volume status create")
}

// LogModify :
func (status VolumeStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.VolumeStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())

	oldStatus, ok := old.(VolumeStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of VolumeStatus type")
	}
	if oldStatus.ContentID != status.ContentID ||
		oldStatus.MaxVolSize != status.MaxVolSize ||
		oldStatus.State != status.State ||
		oldStatus.Progress != status.Progress ||
		oldStatus.RefCount != status.RefCount ||
		oldStatus.FileLocation != status.FileLocation {

		logObject.CloneAndAddField("content-id", status.ContentID).
			AddField("max-vol-size-int64", status.MaxVolSize).
			AddField("state", status.State).
			AddField("progress-int64", status.Progress).
			AddField("refcount-int64", status.RefCount).
			AddField("filelocation", status.FileLocation).
			AddField("old-content-id", oldStatus.ContentID).
			AddField("old-max-vol-size-int64", oldStatus.MaxVolSize).
			AddField("old-state", oldStatus.State).
			AddField("old-progress-int64", oldStatus.Progress).
			AddField("old-refcount-int64", oldStatus.RefCount).
			AddField("old-filelocation", oldStatus.FileLocation).
			Infof("Volume status modify")
	}
}

// LogDelete :
func (status VolumeStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.VolumeStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())
	logObject.CloneAndAddField("content-id", status.ContentID).
		AddField("max-vol-size-int64", status.MaxVolSize).
		Infof("Volume status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status VolumeStatus) LogKey() string {
	return string(base.VolumeStatusLogType) + "-" + status.Key()
}
