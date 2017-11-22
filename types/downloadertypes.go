// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"log"
	"time"
)

// The key/index to this is the Safename which is allocated by ZedManager.
// That is the filename in which we store the corresponding json files.
type DownloaderConfig struct {
	Safename        string
	DownloadURL     string
	TransportMethod string // Download Method S3/HTTP/SFTP etc.
	Dpath           string
	ApiKey          string
	Password        string
	MaxSize         uint   // In kbytes
	ImageSha256     string // sha256 of immutable image
	DownloadObjDir  string // Download Object Store
	VerifiedObjDir  string // Final Object Store
	RefCount        uint   // Zero means can delete file/cancel download
}

func (config DownloaderConfig) VerifyFilename(fileName string) bool {
	name := config.Safename
	ret := name+".json" == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
			fileName, name)
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
	PendingAdd     bool
	PendingModify  bool
	PendingDelete  bool
	RefCount       uint    // Zero means not downloaded
	DownloadURL    string
	ImageSha256    string  // sha256 of immutable image
	DownloadObjDir string  // Download Object store
	VerifiedObjDir string  // Target Object Store
	State          SwState // DOWNLOADED etc
	ReservedSpace  uint    // Contribution to global ReservedSpace
	Size           uint    // Once DOWNLOADED; less than MaxSize
	ModTime        time.Time
	LastErr        string // Download error
	LastErrTime    time.Time
	RetryCount     int
}

func (status DownloaderStatus) VerifyFilename(fileName string) bool {
	name := status.Safename
	ret := name+".json" == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
			fileName, name)
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

type GlobalDownloadConfig struct {
	MaxSpace uint // Number of kbytes allowed in /var/tmp/zedmanager/downloads
}

type GlobalDownloadStatus struct {
	UsedSpace      uint // Number of kbytes used in /var/tmp/zedmanager/downloads
	ReservedSpace  uint // Reserved for ongoing downloads
	RemainingSpace uint // MaxSpace - UsedSpace - ReservedSpace
}
