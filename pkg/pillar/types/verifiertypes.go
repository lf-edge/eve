// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types which feed in and out of the verifier

package types

import (
	"time"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
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
	Safename         string // Also refers to the dirname in pending dir
	Name             string // For logging output
	ImageSha256      string // sha256 of immutable image
	RefCount         uint
	CertificateChain []string  //name of intermediate certificates
	ImageSignature   []byte    //signature of image
	SignatureKey     string    //certificate containing public key
	IsContainer      bool      // Is this Domain for a Container?
	ContainerImageID string    // Container Image ID
	ImageID          uuid.UUID // UUID of the image
}

func (config VerifyImageConfig) Key() string {
	return config.Safename
}

func (config VerifyImageConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained Safename: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// The key/index to this is the Safename which comes from VerifyImageConfig.
// That is the filename in which we store the corresponding json files.
type VerifyImageStatus struct {
	Safename         string
	ObjType          string
	PendingAdd       bool
	PendingModify    bool
	PendingDelete    bool
	IsContainer      bool    // Is this Domain for a Container?
	ContainerImageID string  // Container Image ID if IsContainer=true
	ImageSha256      string  // sha256 of immutable image
	State            SwState // DELIVERED; LastErr* set if failed
	LastErr          string  // Verification error
	LastErrTime      time.Time
	Size             int64
	RefCount         uint
	LastUse          time.Time // When RefCount dropped to zero
	Expired          bool      // Handshake to client
	ImageID          uuid.UUID // UUID of the image
}

func (status VerifyImageStatus) Key() string {
	return status.Safename
}

func (status VerifyImageStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained Safename: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// ImageDownloadDirNames - Returns pendingDirname, verifierDirname, verifiedDirname
// for the image.
func (status VerifyImageStatus) ImageDownloadDirNames() (string, string, string) {
	downloadDirname := DownloadDirname + "/" + status.ObjType

	var pendingDirname, verifierDirname, verifiedDirname string
	if status.IsContainer {
		pendingDirname = downloadDirname + "/pending/" + status.ImageID.String()
		verifierDirname = downloadDirname + "/verifier/" + status.ImageID.String()
		verifiedDirname = downloadDirname + "/verified/" + status.ImageID.String()
	} else {
		// Else..VMs
		pendingDirname = downloadDirname + "/pending/" + status.ImageSha256
		verifierDirname = downloadDirname + "/verifier/" + status.ImageSha256
		verifiedDirname = downloadDirname + "/verified/" + status.ImageSha256
	}
	return pendingDirname, verifierDirname, verifiedDirname
}

// ImageDownloadFilenames - Returns pendingFilename, verifierFilename, verifiedFilename
// for the image
func (status VerifyImageStatus) ImageDownloadFilenames() (string, string, string) {
	var pendingFilename, verifierFilename, verifiedFilename string

	pendingDirname, verifierDirname, verifiedDirname :=
		status.ImageDownloadDirNames()
	pendingFilename = pendingDirname + "/" + status.Safename
	verifierFilename = verifierDirname + "/" + status.Safename
	// TODO:
	// most of the filename and safename for containers and VMs have been
	// unified, so we need fewer "if IsContainer" but this one still needs to
	// exist. It should be cleaned up.
	if status.IsContainer {
		verifiedFilename = verifiedDirname + "/" + status.Safename
	} else {
		filename := SafenameToFilename(status.Safename)
		verifiedFilename = verifiedDirname + "/" + filename
	}
	return pendingFilename, verifierFilename, verifiedFilename
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

func (status VerifyImageStatus) Pending() bool {
	return status.PendingAdd || status.PendingModify || status.PendingDelete
}
