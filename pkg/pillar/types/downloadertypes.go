// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"time"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// The key/index to this is the ImageSha256 which is allocated by the controller or resolver.
type DownloaderConfig struct {
	ImageSha256      string
	ImageID          uuid.UUID // Used for logging
	DatastoreID      uuid.UUID
	Name             string
	Target           string // file path where to download the file
	NameIsURL        bool   // If not we form URL based on datastore info
	IsContainer      bool
	AllowNonFreePort bool
	Size             uint64 // In bytes
	FinalObjDir      string // final Object Store
	RefCount         uint
}

func (config DownloaderConfig) Key() string {
	return config.ImageSha256
}

func (config DownloaderConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// Cert Object may contain multiple objects

type CertConfig struct {
	ServerCert DownloaderConfig
	CertChain  []DownloaderConfig
}

// The key/index to this is the ImageSha256 which comes from DownloaderConfig.
type DownloaderStatus struct {
	ImageSha256      string
	ImageID          uuid.UUID // Used for logging
	DatastoreID      uuid.UUID
	Target           string // file path where we download the file
	Name             string
	ObjType          string
	IsContainer      bool
	PendingAdd       bool
	PendingModify    bool
	PendingDelete    bool
	RefCount         uint      // Zero means not downloaded
	LastUse          time.Time // When RefCount dropped to zero
	Expired          bool      // Handshake to client
	NameIsURL        bool      // If not we form URL based on datastore info
	AllowNonFreePort bool
	State            SwState // DOWNLOADED etc
	ReservedSpace    uint64  // Contribution to global ReservedSpace
	Size             uint64  // Once DOWNLOADED; in bytes
	Progress         uint    // In percent i.e., 0-100
	ModTime          time.Time
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
	RetryCount int
}

func (status DownloaderStatus) Key() string {
	return status.ImageSha256
}

func (status DownloaderStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

func (status DownloaderStatus) CheckPendingAdd() bool {
	return status.PendingAdd
}

func (status DownloaderStatus) CheckPendingModify() bool {
	return status.PendingModify
}

func (status DownloaderStatus) CheckPendingDelete() bool {
	return status.PendingDelete
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
func (status *DownloaderStatus) HandleDownloadFail(errStr string) {
	status.SetErrorNow(errStr)
	status.ClearPendingStatus()
}

type GlobalDownloadConfig struct {
	MaxSpace uint64 // Number of kbytes allowed in types.DownloadDirname
}

// These are all in kbytes
type GlobalDownloadStatus struct {
	UsedSpace      uint64 // Number of kbytes used in types.DownloadDirname
	ReservedSpace  uint64 // Reserved for ongoing downloads
	RemainingSpace uint64 // MaxSpace - UsedSpace - ReservedSpace
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

// AllowNonFreePort looks at GlobalConfig to determine which policy
// to apply for the download of the object.
func AllowNonFreePort(gc ConfigItemValueMap, objType string) bool {

	switch objType {
	case AppImgObj:
		return gc.GlobalValueTriState(AllowNonFreeAppImages) == TS_ENABLED
	case BaseOsObj:
		return gc.GlobalValueTriState(AllowNonFreeBaseImages) == TS_ENABLED
	case CertObj:
		return (gc.GlobalValueTriState(AllowNonFreeBaseImages) == TS_ENABLED) ||
			(gc.GlobalValueTriState(AllowNonFreeAppImages) == TS_ENABLED)
	default:
		log.Fatalf("AllowNonFreePort: Unknown ObjType %s\n",
			objType)
		return false
	}
}

// ResolveConfig key/index to this is the combination of
// DatastoreID which is allocated by the controller, name
// and the sequence counter.
// It will resolve the tag in name to sha256
type ResolveConfig struct {
	DatastoreID      uuid.UUID
	Name             string
	AllowNonFreePort bool
	Counter          uint32
}

// Key : DatastoreID, name and sequence counter are used
// to differentiate different config
func (config ResolveConfig) Key() string {
	return fmt.Sprintf("%s+%s+%v", config.DatastoreID.String(), config.Name, config.Counter)
}

// VerifyFilename will verify the key name
func (config ResolveConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// ResolveStatus key/index to this is the combination of
// DatastoreID, name and the sequence counter which comes
// from the ResolveConfig
type ResolveStatus struct {
	DatastoreID uuid.UUID
	Name        string
	ImageSha256 string
	Counter     uint32
	RetryCount  int
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// Key : DatastoreID, name and sequence counter are used
// to differentiate different config
func (status ResolveStatus) Key() string {
	return fmt.Sprintf("%s+%s+%v", status.DatastoreID.String(), status.Name, status.Counter)
}

// VerifyFilename will verify the key name
func (status ResolveStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}
