// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	log "github.com/sirupsen/logrus"
	"time"
)

// The key/index to this is the Safename which is allocated by ZedManager.
// That is the filename in which we store the corresponding json files.
type DownloaderConfig struct {
	Safename        string
	DownloadURL     string
	UseFreeUplinks  bool
	TransportMethod string // Download Method S3/HTTP/SFTP etc.
	Dpath           string
	ApiKey          string
	Password        string
	Region          string
	Size            uint64 // In bytes
	ImageSha256     string // sha256 of immutable image
	FinalObjDir     string // final Object Store
	RefCount        uint   // Zero means can delete file/cancel download
}

func (config DownloaderConfig) Key() string {
	return config.Safename
}

func (config DownloaderConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
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
	Safename       string
	ObjType        string
	PendingAdd     bool
	PendingModify  bool
	PendingDelete  bool
	RefCount       uint // Zero means not downloaded
	DownloadURL    string
	UseFreeUplinks bool
	ImageSha256    string  // sha256 of immutable image
	State          SwState // DOWNLOADED etc
	ReservedSpace  uint    // Contribution to global ReservedSpace
	Size           uint64  // Once DOWNLOADED; in bytes
	ModTime        time.Time
	LastErr        string // Download error
	LastErrTime    time.Time
	RetryCount     int
}

func (status DownloaderStatus) Key() string {
	return status.Safename
}

func (status DownloaderStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
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
	MaxSpace uint // Number of kbytes allowed in /var/tmp/zedmanager/downloads
}

// These are all in kbytes
type GlobalDownloadStatus struct {
	UsedSpace      uint // Number of kbytes used in /var/tmp/zedmanager/downloads
	ReservedSpace  uint // Reserved for ongoing downloads
	RemainingSpace uint // MaxSpace - UsedSpace - ReservedSpace
}
