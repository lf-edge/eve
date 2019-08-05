// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"time"
)

// The key/index to this is the Safename which is allocated by ZedManager.
// That is the filename in which we store the corresponding json files.
type DownloaderConfig struct {
	DatastoreId      uuid.UUID
	Safename         string
	Name             string
	NameIsURL        bool // If not we form URL based on datastore info
	UseFreeMgmtPorts bool
	Size             uint64 // In bytes
	ImageSha256      string // sha256 of immutable image
	FinalObjDir      string // final Object Store
	RefCount         uint
}

func (config DownloaderConfig) Key() string {
	return config.Safename
}

func (config DownloaderConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained Safename: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// Cert Object may contain multiple objects

type CertConfig struct {
	ServerCert DownloaderConfig
	CertChain  []DownloaderConfig
}

// The key/index to this is the Safename which comes from DownloaderConfig.
// That is the filename in which we store the corresponding json files.
type DownloaderStatus struct {
	DatastoreId      uuid.UUID
	Safename         string
	Name             string
	ObjType          string
	PendingAdd       bool
	PendingModify    bool
	PendingDelete    bool
	RefCount         uint      // Zero means not downloaded
	LastUse          time.Time // When RefCount dropped to zero
	Expired          bool      // Handshake to client
	NameIsURL        bool      // If not we form URL based on datastore info
	UseFreeMgmtPorts bool
	ImageSha256      string  // sha256 of immutable image
	State            SwState // DOWNLOADED etc
	ReservedSpace    uint64  // Contribution to global ReservedSpace
	Size             uint64  // Once DOWNLOADED; in bytes
	Progress         uint    // In percent i.e., 0-100
	ModTime          time.Time
	LastErr          string // Download error
	LastErrTime      time.Time
	RetryCount       int
}

func (status DownloaderStatus) Key() string {
	return status.Safename
}

func (status DownloaderStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained Safename: %s vs. %s\n",
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

type GlobalDownloadConfig struct {
	MaxSpace uint64 // Number of kbytes allowed in /var/tmp/zedmanager/downloads
}

// These are all in kbytes
type GlobalDownloadStatus struct {
	UsedSpace      uint64 // Number of kbytes used in /var/tmp/zedmanager/downloads
	ReservedSpace  uint64 // Reserved for ongoing downloads
	RemainingSpace uint64 // MaxSpace - UsedSpace - ReservedSpace
}

// datastore configuration context
type DatastoreContext struct {
	DownloadURL     string
	TransportMethod string // Download Method S3/HTTP/SFTP etc.
	Dpath           string
	ApiKey          string
	Password        string
	Region          string
	FinalObjDir     string
}
