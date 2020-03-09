// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types which feed in and out of the verifier

package types

import (
	"fmt"
	"path"
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

// VerifyImageConfig captures the verifications which have been requested.
// The key/index to this is the ImageID which is allocated by the controller.
// The ImageSha256 may not be known when the VerifyImageConfig is created
type VerifyImageConfig struct {
	ImageID uuid.UUID // UUID of the image
	VerifyConfig
	IsContainer bool // Is this image for a Container?
	RefCount    uint
}

// VerifyConfig is shared between VerifyImageConfig and PersistImageConfig
type VerifyConfig struct {
	ImageSha256      string // sha256 of immutable image
	Name             string
	CertificateChain []string //name of intermediate certificates
	ImageSignature   []byte   //signature of image
	SignatureKey     string   //certificate containing public key
}

// Key returns the pubsub Key
func (config VerifyImageConfig) Key() string {
	return fmt.Sprintf("%s.%s", config.ImageID.String(), config.VerifyConfig.ImageSha256)
}

func (config VerifyImageConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// PersistImageConfig captures the images which already exists in /persist
// e.g., from before a reboot. Normally these become requested with a
// VerifyImageConfig, or are garbage collected.
// The key is the ImageSha256. The existence of a VerifyImageConfig means
// the client does not want to to be garbage collected. See handshake using
// the Expired boolean in PersistImageStatus
type PersistImageConfig struct {
	VerifyConfig
	RefCount uint
}

// Key returns the pubsub Key
func (config PersistImageConfig) Key() string {
	return config.ImageSha256
}

// VerifyImageStatus captures the verifications which have been requested.
// The key/index to this is the ImageID if known otherwise the ImageSha256
// The sha can come from the verified filename
type VerifyImageStatus struct {
	ImageID uuid.UUID // UUID of the image if known
	VerifyStatus
	PendingAdd    bool
	PendingModify bool
	PendingDelete bool
	IsContainer   bool    // Is this image for a Container?
	State         SwState // DELIVERED; LastErr* set if failed
	LastErr       string  // Verification error
	LastErrTime   time.Time
	RefCount      uint
}

// The VerifyStatus is shared between VerifyImageStatus and PersistImageStatus
type VerifyStatus struct {
	ImageSha256  string // sha256 of immutable image
	Name         string
	ObjType      string
	FileLocation string // Current location; should be info about file
	Size         int64
}

// Key returns the pubsub Key
func (status VerifyImageStatus) Key() string {
	return fmt.Sprintf("%s.%s", status.ImageID.String(), status.VerifyStatus.ImageSha256)
}

func (status VerifyImageStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained key: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// PersistImageStatus captures the images which already exists in /persist
// The key/index to this is the ImageSha256
// The sha comes from the verified filename
type PersistImageStatus struct {
	VerifyStatus
	RefCount uint
	LastUse  time.Time // When RefCount dropped to zero
	Expired  bool      // Handshake to client to ask for permission to delete
}

// Key returns the pubsub Key
func (status PersistImageStatus) Key() string {
	return status.ImageSha256
}

// ImageDownloadDirNames - Returns pendingDirname, verifierDirname, verifiedDirname
// for the image.
func (status VerifyImageStatus) ImageDownloadDirNames() (string, string, string) {
	downloadDirname := DownloadDirname + "/" + status.ObjType

	var pendingDirname, verifierDirname, verifiedDirname string
	pendingDirname = downloadDirname + "/pending/" + status.ImageID.String()
	verifierDirname = downloadDirname + "/verifier/" + status.ImageID.String()
	verifiedDirname = downloadDirname + "/verified/" + status.ImageSha256
	return pendingDirname, verifierDirname, verifiedDirname
}

// ImageDownloadFilenames - Returns pendingFilename, verifierFilename, verifiedFilename
// for the image
func (status VerifyImageStatus) ImageDownloadFilenames() (string, string, string) {
	var pendingFilename, verifierFilename, verifiedFilename string

	pendingDirname, verifierDirname, verifiedDirname :=
		status.ImageDownloadDirNames()
	// Handle names which are paths
	filename := path.Base(status.Name)
	pendingFilename = pendingDirname + "/" + filename
	verifierFilename = verifierDirname + "/" + filename
	verifiedFilename = verifiedDirname + "/" + filename
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

// ImageDownloadDirName - Returns verifiedDirname
// for the image.
func (status PersistImageStatus) ImageDownloadDirName() string {
	downloadDirname := DownloadDirname + "/" + status.ObjType
	return downloadDirname + "/verified/" + status.ImageSha256
}
