// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"time"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// The key/index to this is the ImageID which is allocated by the controller.
type DownloaderConfig struct {
	ImageID          uuid.UUID
	DatastoreID      uuid.UUID
	Name             string
	NameIsURL        bool // If not we form URL based on datastore info
	IsContainer      bool
	AllowNonFreePort bool
	Size             uint64 // In bytes
	FinalObjDir      string // final Object Store
	RefCount         uint
	ImageSha256      string
}

func (config DownloaderConfig) Key() string {
	return fmt.Sprintf("%s.%s", config.ImageID.String(), config.ImageSha256)
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

// The key/index to this is the ImageID which comes from DownloaderConfig.
type DownloaderStatus struct {
	ImageID          uuid.UUID
	DatastoreID      uuid.UUID
	Name             string
	ObjType          string
	FileLocation     string // Filename where downloaded; replace with file info
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
	LastErr          string // Download error
	LastErrTime      time.Time
	RetryCount       int
	ImageSha256      string
}

func (status DownloaderStatus) Key() string {
	return fmt.Sprintf("%s.%s", status.ImageID.String(), status.ImageSha256)
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

// SetErrorInfo : Set Error Information for DownloaderStatus
func (status *DownloaderStatus) SetErrorInfo(errStr string) {
	status.LastErr = errStr
	status.LastErrTime = time.Now()
}

// ClearErrorInfo : Clear Error Information for DownloaderStatus
func (status *DownloaderStatus) ClearErrorInfo() {
	status.LastErr = ""
	status.LastErrTime = time.Time{}
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
	status.SetErrorInfo(errStr)
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

// The key/index to this is the ImageID which is allocated by the controller.
type AppImgResolveConfig struct {
	ImageID     uuid.UUID
	DatastoreID uuid.UUID
	Name        string
	NameIsURL   bool // If not we form URL based on datastore info
	IsContainer bool
}

func (config AppImgResolveConfig) Key() string {
	return fmt.Sprintf("%s", config.ImageID.String())
}

func (config AppImgResolveConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// The key/index to this is the ImageID which comes from AppImgResolveConfig.
type AppImgResolveStatus struct {
	ImageID     uuid.UUID
	DatastoreID uuid.UUID
	Name        string
	IsContainer bool
	NameIsURL   bool // If not we form URL based on datastore info
	ImageSha256 string
}

func (status AppImgResolveStatus) Key() string {
	return fmt.Sprintf("%s", status.ImageID.String())
}

func (status AppImgResolveStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}
