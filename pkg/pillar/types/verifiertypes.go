// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types which feed in and out of the verifier

package types

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
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
// The key/index to this is the ImageSha256 which is allocated by the controller or resolver.
type VerifyImageConfig struct {
	ImageSha256      string // sha256 of immutable image
	Name             string
	CertificateChain []string  //name of intermediate certificates
	ImageSignature   []byte    //signature of image
	SignatureKey     string    //certificate containing public key
	FileLocation     string    // Current location; should be info about file
	Size             int64     //FileLocation size
	ImageID          uuid.UUID // Used for logging
	IsContainer      bool      // Is this image for a Container?
	RefCount         uint
}

// Key returns the pubsub Key
func (config VerifyImageConfig) Key() string {
	return config.ImageSha256
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

// LogCreate :
func (config VerifyImageConfig) LogCreate() {
	logObject := base.NewLogObject(base.VerifyImageConfigLogType, config.Name,
		config.ImageID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("refcount-int64", config.RefCount).
		Infof("VerifyImage config create")
}

// LogModify :
func (config VerifyImageConfig) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.VerifyImageConfigLogType, config.Name,
		config.ImageID, config.LogKey())

	oldConfig, ok := old.(VerifyImageConfig)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of VerifyImageConfig type")
	}
	if oldConfig.RefCount != config.RefCount {

		logObject.CloneAndAddField("refcount-int64", config.RefCount).
			AddField("old-refcount-int64", oldConfig.RefCount).
			Infof("VerifyImage config modify")
	}
}

// LogDelete :
func (config VerifyImageConfig) LogDelete() {
	logObject := base.EnsureLogObject(base.VerifyImageConfigLogType, config.Name,
		config.ImageID, config.LogKey())
	logObject.CloneAndAddField("refcount-int64", config.RefCount).
		Infof("VerifyImage config delete")

	base.DeleteLogObject(config.LogKey())
}

// LogKey :
func (config VerifyImageConfig) LogKey() string {
	return string(base.VerifyImageConfigLogType) + "-" + config.Key()
}

// VerifyImageStatus captures the verifications which have been requested.
// The key/index to this is the ImageSha256
type VerifyImageStatus struct {
	VerifyStatus
	ImageID       uuid.UUID // Used for logging
	PendingAdd    bool
	PendingModify bool
	PendingDelete bool
	IsContainer   bool    // Is this image for a Container?
	State         SwState // DELIVERED; LastErr* set if failed
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
	RefCount uint
}

// The VerifyStatus is shared between VerifyImageStatus and PersistImageStatus
type VerifyStatus struct {
	ImageSha256  string // sha256 of immutable image
	Name         string
	ObjType      string
	FileLocation string // Current location; should be info about file
	Size         int64  // XXX used?
}

// Key returns the pubsub Key
func (status VerifyImageStatus) Key() string {
	return status.ImageSha256
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

// LogCreate :
func (status VerifyImageStatus) LogCreate() {
	logObject := base.NewLogObject(base.VerifyImageStatusLogType, status.Name,
		status.ImageID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("refcount-int64", status.RefCount).
		AddField("size-int64", status.Size).
		Infof("VerifyImage status create")
}

// LogModify :
func (status VerifyImageStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.VerifyImageStatusLogType, status.Name,
		status.ImageID, status.LogKey())

	oldStatus, ok := old.(VerifyImageStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of VerifyImageStatus type")
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
			Infof("VerifyImage status modify")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Errorf("VerifyImage status modify")
	}
}

// LogDelete :
func (status VerifyImageStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.VerifyImageStatusLogType, status.Name,
		status.ImageID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("refcount-int64", status.RefCount).
		AddField("size-int64", status.Size).
		Infof("VerifyImage status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status VerifyImageStatus) LogKey() string {
	return string(base.VerifyImageStatusLogType) + "-" + status.Key()
}

// PersistImageStatus captures the images which already exists in /persist
// The key/index to this is the ImageSha256
// The sha comes from the verified filename
type PersistImageStatus struct {
	VerifyStatus
	RefCount uint
}

// Key returns the pubsub Key
func (status PersistImageStatus) Key() string {
	return status.ImageSha256
}

// LogCreate :
func (status PersistImageStatus) LogCreate() {
	logObject := base.NewLogObject(base.PersistImageStatusLogType, status.Name,
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("refcount-int64", status.RefCount).
		AddField("size-int64", status.Size).
		Infof("PersistImage status create")
}

// LogModify :
func (status PersistImageStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.PersistImageStatusLogType, status.Name,
		nilUUID, status.LogKey())

	oldStatus, ok := old.(PersistImageStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of PersistImageStatus type")
	}
	if oldStatus.RefCount != status.RefCount ||
		oldStatus.Size != status.Size {

		logObject.CloneAndAddField("refcount-int64", status.RefCount).
			AddField("size-int64", status.Size).
			AddField("old-refcount-int64", oldStatus.RefCount).
			AddField("old-size-int64", oldStatus.Size).
			Infof("PersistImage status modify")
	}
}

// LogDelete :
func (status PersistImageStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.PersistImageStatusLogType, status.Name,
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("refcount-int64", status.RefCount).
		AddField("size-int64", status.Size).
		Infof("PersistImage status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status PersistImageStatus) LogKey() string {
	return string(base.PersistImageStatusLogType) + "-" + status.Key()
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
