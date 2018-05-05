// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Types which feed in and out of the verifier

package types

import (
	"log"
	"time"
)

// XXX more than images; rename type and clean up comments
// XXX make clean that Cert/Key are names of them and not PEM content

// Types for verifying the images.
// For now we just verify the sha checksum.
// For defense-in-depth we assume that the ZedManager with the help of
// dom0 has moved the image file to a read-only directory before asking
// for the file to be verified.

// The key/index to this is the Safename which is allocated by ZedManager.
// That is the filename in which we store the corresponding json files.
type VerifyImageConfig struct {
	Safename         string   // Also refers to the dirname in pending dir
	DownloadURL      string   // For logging output
	ImageSha256      string   // sha256 of immutable image
	RefCount         uint     // Zero means can delete file
	CertificateChain []string //name of intermediate certificates
	ImageSignature   []byte   //signature of image
	SignatureKey     string   //certificate containing public key
}

func (config VerifyImageConfig) VerifyFilename(fileName string) bool {
	name := config.Safename
	ret := name+".json" == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
			fileName, name)
	}
	return ret
}

// The key/index to this is the Safename which comes from VerifyImageConfig.
// That is the filename in which we store the corresponding json files.
type VerifyImageStatus struct {
	Safename      string
	ObjType       string
	PendingAdd    bool
	PendingModify bool
	PendingDelete bool
	ImageSha256   string  // sha256 of immutable image
	State         SwState // DELIVERED, or INITIAL if failed
	LastErr       string  // Verification error
	LastErrTime   time.Time
	Size          int64
	RefCount      uint // Zero means deleted
}

func (status VerifyImageStatus) VerifyFilename(fileName string) bool {
	name := status.Safename
	ret := name+".json" == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained Safename: %s vs. %s\n",
			fileName, name)
	}
	return ret
}

func (status VerifyImageStatus) CheckPendingAdd() bool {
	return status.PendingAdd
}

func (status VerifyImageStatus) CheckPendingModify() bool {
	return status.PendingModify
}

func (status VerifyImageStatus) CheckPendingDelete() bool {
	return status.PendingDelete
}
