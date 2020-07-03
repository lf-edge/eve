// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types which feed in and out of the verifier

package types

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
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
	CertificateChain []string //name of intermediate certificates
	ImageSignature   []byte   //signature of image
	SignatureKey     string   //certificate containing public key
	FileLocation     string   // Current location; should be info about file
	Size             int64    //FileLocation size
	RefCount         uint
	Expired          bool // Used in delete handshake
}

// Key returns the pubsub Key
func (config VerifyImageConfig) Key() string {
	return config.ImageSha256
}

// LogCreate :
func (config VerifyImageConfig) LogCreate() {
	logObject := base.NewLogObject(base.VerifyImageConfigLogType, config.Name,
		nilUUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("refcount-int64", config.RefCount).
		AddField("expired-bool", config.Expired).
		Infof("VerifyImage config create")
}

// LogModify :
func (config VerifyImageConfig) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.VerifyImageConfigLogType, config.Name,
		nilUUID, config.LogKey())

	oldConfig, ok := old.(VerifyImageConfig)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of VerifyImageConfig type")
	}
	if oldConfig.RefCount != config.RefCount ||
		oldConfig.Expired != config.Expired {

		logObject.CloneAndAddField("refcount-int64", config.RefCount).
			AddField("expired-bool", config.Expired).
			AddField("old-refcount-int64", oldConfig.RefCount).
			AddField("old-expired-bool", oldConfig.Expired).
			Infof("VerifyImage config modify")
	}
}

// LogDelete :
func (config VerifyImageConfig) LogDelete() {
	logObject := base.EnsureLogObject(base.VerifyImageConfigLogType, config.Name,
		nilUUID, config.LogKey())
	logObject.CloneAndAddField("refcount-int64", config.RefCount).
		AddField("expired-bool", config.Expired).
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
	ImageSha256   string // sha256 of immutable image
	Name          string
	ObjType       string
	FileLocation  string // Current location
	Size          int64
	PendingAdd    bool
	PendingModify bool
	PendingDelete bool
	State         SwState // DELIVERED; LastErr* set if failed
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
	RefCount uint
	Expired  bool // Used in delete handshake
}

// Key returns the pubsub Key
func (status VerifyImageStatus) Key() string {
	return status.ImageSha256
}

// LogCreate :
func (status VerifyImageStatus) LogCreate() {
	logObject := base.NewLogObject(base.VerifyImageStatusLogType, status.Name,
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("refcount-int64", status.RefCount).
		AddField("expired-bool", status.Expired).
		AddField("size-int64", status.Size).
		AddField("objtype", status.ObjType).
		AddField("filelocation", status.FileLocation).
		Infof("VerifyImage status create")
}

// LogModify :
func (status VerifyImageStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.VerifyImageStatusLogType, status.Name,
		nilUUID, status.LogKey())

	oldStatus, ok := old.(VerifyImageStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of VerifyImageStatus type")
	}
	if oldStatus.State != status.State ||
		oldStatus.RefCount != status.RefCount ||
		oldStatus.Expired != status.Expired ||
		oldStatus.Size != status.Size ||
		oldStatus.FileLocation != status.FileLocation {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("refcount-int64", status.RefCount).
			AddField("expired-bool", status.Expired).
			AddField("size-int64", status.Size).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-refcount-int64", oldStatus.RefCount).
			AddField("old-expired-bool", oldStatus.Expired).
			AddField("old-size-int64", oldStatus.Size).
			AddField("objtype", status.ObjType).
			AddField("filelocation", status.FileLocation).
			AddField("old-filelocation", oldStatus.FileLocation).
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
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("refcount-int64", status.RefCount).
		AddField("expired-bool", status.Expired).
		AddField("size-int64", status.Size).
		AddField("objtype", status.ObjType).
		AddField("filelocation", status.FileLocation).
		Infof("VerifyImage status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status VerifyImageStatus) LogKey() string {
	return string(base.VerifyImageStatusLogType) + "-" + status.Key()
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
