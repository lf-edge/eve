// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
)

// The key/index to this is the ImageSha256 which is allocated by the controller or resolver.
type DownloaderConfig struct {
	ImageSha256     string
	DatastoreIDList []uuid.UUID
	Name            string
	Target          string // file path where to download the file
	NameIsURL       bool   // If not we form URL based on datastore info
	Size            uint64 // In bytes
	FinalObjDir     string // final Object Store
	RefCount        uint
}

func (config DownloaderConfig) Key() string {
	return config.ImageSha256
}

// LogCreate :
func (config DownloaderConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DownloaderConfigLogType, config.Name,
		nilUUID, config.LogKey())
	if logObject == nil {
		return
	}
	uuids := strings.Join(UuidsToStrings(config.DatastoreIDList), ",")
	logObject.CloneAndAddField("target", config.Target).
		AddField("datastore-ids", uuids).
		AddField("refcount-int64", config.RefCount).
		AddField("size-int64", config.Size).
		Noticef("Download config create")
}

// LogModify :
func (config DownloaderConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DownloaderConfigLogType, config.Name,
		nilUUID, config.LogKey())

	oldConfig, ok := old.(DownloaderConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DownloaderConfig type")
	}
	uuids := strings.Join(UuidsToStrings(config.DatastoreIDList), ",")
	oldUuids := strings.Join(UuidsToStrings(oldConfig.DatastoreIDList), ",")

	if oldConfig.Target != config.Target ||
		oldUuids != uuids ||
		oldConfig.RefCount != config.RefCount ||
		oldConfig.Size != config.Size {

		logObject.CloneAndAddField("target", config.Target).
			AddField("datastore-ids", uuids).
			AddField("refcount-int64", config.RefCount).
			AddField("size-int64", config.Size).
			AddField("old-target", oldConfig.Target).
			AddField("old-datastore-ids", oldUuids).
			AddField("old-refcount-int64", oldConfig.RefCount).
			AddField("old-size-int64", oldConfig.Size).
			Noticef("Download config modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Noticef("Download config modify other change")
	}
}

// LogDelete :
func (config DownloaderConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DownloaderConfigLogType, config.Name,
		nilUUID, config.LogKey())
	uuids := strings.Join(UuidsToStrings(config.DatastoreIDList), ",")
	logObject.CloneAndAddField("target", config.Target).
		AddField("datastore-ids", uuids).
		AddField("refcount-int64", config.RefCount).
		AddField("size-int64", config.Size).
		Noticef("Download config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config DownloaderConfig) LogKey() string {
	return string(base.DownloaderConfigLogType) + "-" + config.Key()
}

// The key/index to this is the ImageSha256 which comes from DownloaderConfig.
type DownloaderStatus struct {
	ImageSha256     string
	DatastoreIDList []uuid.UUID
	Target          string // file path where we download the file
	Name            string
	PendingAdd      bool
	PendingModify   bool
	PendingDelete   bool
	RefCount        uint      // Zero means not downloaded
	LastUse         time.Time // When RefCount dropped to zero
	Expired         bool      // Handshake to client
	NameIsURL       bool      // If not we form URL based on datastore info
	State           SwState   // DOWNLOADED etc
	ReservedSpace   uint64    // Contribution to global ReservedSpace
	Size            uint64    // Once DOWNLOADED; in bytes
	TotalSize       int64     // expected size as reported by the downloader, if any
	CurrentSize     int64     // current total downloaded size as reported by the downloader
	Progress        uint      // In percent i.e., 0-100, given by CurrentSize/ExpectedSize
	ModTime         time.Time
	ContentType     string // content-type header, if provided
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
	RetryCount int
	// We save the original error when we do a retry
	OrigError string
}

func (status DownloaderStatus) Key() string {
	return status.ImageSha256
}

func (status DownloaderStatus) Pending() bool {
	return status.PendingAdd || status.PendingModify || status.PendingDelete
}

// ClearPendingStatus : Clear Pending Status for DownloaderStatus
func (status *DownloaderStatus) ClearPendingStatus() {
	if status.PendingAdd {
		status.PendingAdd = false
	}
	if status.PendingModify {
		status.PendingModify = false
	}
}

// HandleDownloadFail : Do Failure specific tasks
func (status *DownloaderStatus) HandleDownloadFail(errStr string, retryTime time.Duration, cancelled bool) {
	errDescription := ErrorDescription{
		Error: errStr,
	}
	if !cancelled && retryTime != 0 {
		severity := GetErrorSeverity(status.RetryCount, time.Duration(status.RetryCount)*retryTime)
		errDescription.ErrorSeverity = severity
		errDescription.ErrorRetryCondition = fmt.Sprintf("Will retry in %s; have retried %d times", retryTime, status.RetryCount)
	}
	status.SetErrorDescription(errDescription)
	status.ClearPendingStatus()
}

// LogCreate :
func (status DownloaderStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DownloaderStatusLogType, status.Name,
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("refcount-int64", status.RefCount).
		AddField("size-int64", status.Size).
		Noticef("Download status create")
}

// LogModify :
func (status DownloaderStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DownloaderStatusLogType, status.Name,
		nilUUID, status.LogKey())

	oldStatus, ok := old.(DownloaderStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DownloaderStatus type")
	}
	if oldStatus.State != status.State ||
		oldStatus.RefCount != status.RefCount ||
		oldStatus.Size != status.Size {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("refcount-int64", status.RefCount).
			AddField("size-int64", status.Size).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-refcount-int64", oldStatus.RefCount).
			AddField("old-size-int64", oldStatus.Size).
			Noticef("Download status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("Download status modify other change")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Noticef("Download status modify")
	}
}

// LogDelete :
func (status DownloaderStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DownloaderStatusLogType, status.Name,
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("refcount-int64", status.RefCount).
		AddField("size-int64", status.Size).
		Noticef("Download status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status DownloaderStatus) LogKey() string {
	return string(base.DownloaderStatusLogType) + "-" + status.Key()
}

// DatastoreContext : datastore detail
type DatastoreContext struct {
	DownloadURL     string
	TransportMethod string // Download Method S3/HTTP/SFTP etc.
	Dpath           string
	APIKey          string
	Password        string
	Region          string
}
