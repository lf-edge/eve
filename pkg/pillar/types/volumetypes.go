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
	GenerationCounter       int64
	DisplayName             string
}

// Key is volume UUID which will be unique
func (config VolumeConfig) Key() string {
	return fmt.Sprintf("%s.%d", config.VolumeID.String(), config.GenerationCounter)
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
		oldConfig.GenerationCounter != config.GenerationCounter {

		logObject.CloneAndAddField("content-id", config.ContentID).
			AddField("maxVolSize", config.MaxVolSize).
			AddField("generationCounter", config.GenerationCounter).
			AddField("old-content-id", oldConfig.ContentID).
			AddField("old-maxVolSize", oldConfig.MaxVolSize).
			AddField("old-generationCounter", oldConfig.GenerationCounter).
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
	FileLocation            string // Location of filestystem
	VolumeCreated           bool   // Done aka Activated
	ContentFormat           zconfig.Format
	LastUse                 time.Time
	PreReboot               bool // Was volume last use prior to device reboot?

	ErrorAndTimeWithSource
}

// Key is volume UUID which will be unique
func (status VolumeStatus) Key() string {
	return fmt.Sprintf("%s.%d", status.VolumeID.String(), status.GenerationCounter)
}

// IsContainer will return true if content tree attached
// to the volume is of container type
func (status VolumeStatus) IsContainer() bool {
	if status.ContentFormat == zconfig.Format_CONTAINER {
		return true
	}
	return false
}

/*
// LogCreate :
func (status ContentTreeStatus) LogCreate() {
	logObject := base.NewLogObject(base.ContentTreeStatusLogType, status.DisplayName,
		status.ContentID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("contentSha256", status.ContentSha256).
		AddField("maxDownloadSize", status.MaxDownloadSize).
		AddField("state", status.State).
		AddField("progress", status.Progress).
		AddField("fileLocation", status.FileLocation).
		Infof("Content tree status create")
}

// LogModify :
func (status ContentTreeStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.ContentTreeStatusLogType, status.DisplayName,
		status.ContentID, status.LogKey())

	oldStatus, ok := old.(ContentTreeStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of ContentTreeStatus type")
	}
	if oldStatus.ContentSha256 != status.ContentSha256 ||
		oldStatus.MaxDownloadSize != status.MaxDownloadSize ||
		oldStatus.State != status.State ||
		oldStatus.Progress != status.Progress ||
		oldStatus.FileLocation != status.FileLocation {

		logObject.CloneAndAddField("contentSha256", status.ContentSha256).
			AddField("maxDownloadSize", status.MaxDownloadSize).
			AddField("state", status.State).
			AddField("progress", status.Progress).
			AddField("fileLocation", status.FileLocation).
			AddField("old-contentSha256", oldStatus.ContentSha256).
			AddField("old-maxDownloadSize", oldStatus.MaxDownloadSize).
			AddField("old-state", oldStatus.State).
			AddField("old-progress", oldStatus.Progress).
			AddField("old-fileLocation", oldStatus.FileLocation).
			Infof("ContentTree status modify")
	}
}

// LogDelete :
func (status ContentTreeStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.ContentTreeStatusLogType, status.DisplayName,
		status.ContentID, status.LogKey())
	logObject.CloneAndAddField("contentSha256", status.ContentSha256).
		AddField("maxDownloadSize", status.MaxDownloadSize).
		Infof("ContentTree status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status ContentTreeStatus) LogKey() string {
	return string(base.ContentTreeStatusLogType) + "-" + status.Key()
}
*/
