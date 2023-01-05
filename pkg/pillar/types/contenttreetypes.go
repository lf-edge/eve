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

// ContentTreeConfig specifies the needed information for content tree
// which might need to be downloaded and verified
type ContentTreeConfig struct {
	ContentID         uuid.UUID
	DatastoreIDList   []uuid.UUID
	RelativeURL       string
	Format            zconfig.Format // this is the format of the content tree itself, not necessarily of the datastore
	ContentSha256     string
	MaxDownloadSize   uint64
	GenerationCounter int64
	DisplayName       string
	CustomMeta        string
}

// Key is content info UUID which will be unique
func (config ContentTreeConfig) Key() string {
	return config.ContentID.String()
}

// LogCreate :
func (config ContentTreeConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ContentTreeConfigLogType, config.DisplayName,
		config.ContentID, config.LogKey())
	if logObject == nil {
		return
	}
	uuids := strings.Join(UuidsToStrings(config.DatastoreIDList), ",")
	logObject.CloneAndAddField("datastore-ids", uuids).
		AddField("relative-URL", config.RelativeURL).
		AddField("format", config.Format).
		AddField("content-sha256", config.ContentSha256).
		AddField("max-download-size-int64", config.MaxDownloadSize).
		Noticef("Content tree config create")
}

// LogModify :
func (config ContentTreeConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ContentTreeConfigLogType, config.DisplayName,
		config.ContentID, config.LogKey())

	oldConfig, ok := old.(ContentTreeConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ContentTreeConfig type")
	}
	uuids := strings.Join(UuidsToStrings(config.DatastoreIDList), ",")
	oldUuids := strings.Join(UuidsToStrings(oldConfig.DatastoreIDList), ",")

	if uuids != oldUuids ||
		oldConfig.RelativeURL != config.RelativeURL ||
		oldConfig.Format != config.Format ||
		oldConfig.ContentSha256 != config.ContentSha256 ||
		oldConfig.MaxDownloadSize != config.MaxDownloadSize {

		logObject.CloneAndAddField("datastore-ids", uuids).
			AddField("relative-URL", config.RelativeURL).
			AddField("format", config.Format).
			AddField("content-sha256", config.ContentSha256).
			AddField("max-download-size-int64", config.MaxDownloadSize).
			AddField("old-datastore-ids", oldUuids).
			AddField("old-relative-URL", oldConfig.RelativeURL).
			AddField("old-format", oldConfig.Format).
			AddField("old-content-sha256", oldConfig.ContentSha256).
			AddField("old-max-download-size-int64", oldConfig.MaxDownloadSize).
			Noticef("Content tree config modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Noticef("Content tree config modify other change")
	}
}

// LogDelete :
func (config ContentTreeConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ContentTreeConfigLogType, config.DisplayName,
		config.ContentID, config.LogKey())
	uuids := strings.Join(UuidsToStrings(config.DatastoreIDList), ",")
	logObject.CloneAndAddField("datastore-ids", uuids).
		AddField("relative-URL", config.RelativeURL).
		AddField("format", config.Format).
		AddField("content-sha256", config.ContentSha256).
		AddField("max-download-size-int64", config.MaxDownloadSize).
		Noticef("Content tree config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config ContentTreeConfig) LogKey() string {
	return string(base.ContentTreeConfigLogType) + "-" + config.Key()
}

// ContentTreeStatus is response from volumemgr about status of content tree
type ContentTreeStatus struct {
	ContentID             uuid.UUID
	DatastoreIDList       []uuid.UUID
	DatastoreTypesList    []string
	AllDatastoresResolved bool
	IsOCIRegistry         bool
	RelativeURL           string
	Format                zconfig.Format
	ContentSha256         string
	MaxDownloadSize       uint64
	GenerationCounter     int64
	DisplayName           string
	HasResolverRef        bool
	State                 SwState
	// XXX RefCount not needed?
	// RefCount                uint
	// LastRefCountChangeTime  time.Time
	CreateTime   time.Time // When LOADED
	TotalSize    int64     // expected size as reported by the downloader, if any
	CurrentSize  int64     // current total downloaded size as reported by the downloader
	Progress     uint      // In percent i.e., 0-100
	FileLocation string    // Location of filestystem
	NameIsURL    bool
	// Blobs the sha256 hashes of the blobs that are in this tree, the first of which always is the root
	Blobs []string

	ErrorAndTimeWithSource
}

// Key is content info UUID which will be unique
func (status ContentTreeStatus) Key() string {
	return status.ContentID.String()
}

// ResolveKey will return the key of resolver config/status
func (status ContentTreeStatus) ResolveKey() string {
	uuids := strings.Join(UuidsToStrings(status.DatastoreIDList), ",")
	return fmt.Sprintf("%s+%s+%v", uuids,
		status.RelativeURL, status.GenerationCounter)
}

// IsContainer will return true if content tree is of container type
func (status ContentTreeStatus) IsContainer() bool {
	if status.Format == zconfig.Format_CONTAINER {
		return true
	}
	return false
}

// ReferenceID get the image reference ID
func (status ContentTreeStatus) ReferenceID() string {
	return fmt.Sprintf("%s-%s", status.ContentID.String(), status.RelativeURL)
}

// UpdateFromContentTreeConfig sets up ContentTreeStatus based on ContentTreeConfig struct
// Be aware: don't expect all fields are updated from the config
func (status *ContentTreeStatus) UpdateFromContentTreeConfig(config ContentTreeConfig) {
	status.ContentID = config.ContentID
	status.DatastoreIDList = config.DatastoreIDList
	status.RelativeURL = config.RelativeURL
	status.Format = config.Format
	status.ContentSha256 = config.ContentSha256
	status.MaxDownloadSize = config.MaxDownloadSize
	status.GenerationCounter = config.GenerationCounter
	status.DisplayName = config.DisplayName
}

// LogCreate :
func (status ContentTreeStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ContentTreeStatusLogType, status.DisplayName,
		status.ContentID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("content-sha256", status.ContentSha256).
		AddField("max-download-size-int64", status.MaxDownloadSize).
		AddField("state", status.State.String()).
		AddField("progress", status.Progress).
		AddField("filelocation", status.FileLocation).
		Noticef("Content tree status create")
}

// LogModify :
func (status ContentTreeStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ContentTreeStatusLogType, status.DisplayName,
		status.ContentID, status.LogKey())

	oldStatus, ok := old.(ContentTreeStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ContentTreeStatus type")
	}
	if oldStatus.ContentSha256 != status.ContentSha256 ||
		oldStatus.MaxDownloadSize != status.MaxDownloadSize ||
		oldStatus.State != status.State ||
		oldStatus.Progress != status.Progress ||
		oldStatus.FileLocation != status.FileLocation {

		logObject.CloneAndAddField("content-sha256", status.ContentSha256).
			AddField("max-download-size-int64", status.MaxDownloadSize).
			AddField("state", status.State.String()).
			AddField("progress", status.Progress).
			AddField("filelocation", status.FileLocation).
			AddField("old-content-sha256", oldStatus.ContentSha256).
			AddField("old-max-download-size-int64", oldStatus.MaxDownloadSize).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-progress", oldStatus.Progress).
			AddField("old-filelocation", oldStatus.FileLocation).
			Noticef("Content tree status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("Content tree status modify other change")
	}
}

// LogDelete :
func (status ContentTreeStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ContentTreeStatusLogType, status.DisplayName,
		status.ContentID, status.LogKey())
	logObject.CloneAndAddField("content-sha256", status.ContentSha256).
		AddField("max-download-size-int64", status.MaxDownloadSize).
		AddField("state", status.State.String()).
		AddField("progress", status.Progress).
		AddField("filelocation", status.FileLocation).
		Noticef("Content tree status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status ContentTreeStatus) LogKey() string {
	return string(base.ContentTreeStatusLogType) + "-" + status.Key()
}
