// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

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

// LogCreate :
func (config ResolveConfig) LogCreate() {
	logObject := base.NewLogObject(base.ResolveConfigLogType, config.Name,
		config.DatastoreID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.Infof("Resolve config create")
}

// LogModify :
func (config ResolveConfig) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.ResolveConfigLogType, config.Name,
		config.DatastoreID, config.LogKey())

	// Why would it change?
	logObject.Infof("Resolve config modify")
}

// LogDelete :
func (config ResolveConfig) LogDelete() {
	logObject := base.EnsureLogObject(base.ResolveConfigLogType, config.Name,
		config.DatastoreID, config.LogKey())
	logObject.Infof("Resolve config delete")

	base.DeleteLogObject(config.LogKey())
}

// LogKey :
func (config ResolveConfig) LogKey() string {
	return string(base.ResolveConfigLogType) + "-" + config.Key()
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

// LogCreate :
func (status ResolveStatus) LogCreate() {
	logObject := base.NewLogObject(base.ResolveStatusLogType, status.Name,
		status.DatastoreID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("image-sha256", status.ImageSha256).
		AddField("retry-count-int64", status.RetryCount).
		Infof("Resolve status create")
}

// LogModify :
func (status ResolveStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.ResolveStatusLogType, status.Name,
		status.DatastoreID, status.LogKey())

	oldStatus, ok := old.(ResolveStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of ResolveStatus type")
	}
	if oldStatus.ImageSha256 != status.ImageSha256 ||
		oldStatus.RetryCount != status.RetryCount {

		logObject.CloneAndAddField("image-sha256", status.ImageSha256).
			AddField("retry-count-int64", status.RetryCount).
			AddField("old-image-sha256", oldStatus.ImageSha256).
			AddField("old-retry-count-int64", oldStatus.RetryCount).
			Infof("Resolve status modify")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("image-sha256", status.ImageSha256).
			AddField("retry-count-int64", status.RetryCount).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Errorf("Resolve status modify")
	}
}

// LogDelete :
func (status ResolveStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.ResolveStatusLogType, status.Name,
		status.DatastoreID, status.LogKey())
	logObject.CloneAndAddField("image-sha256", status.ImageSha256).
		AddField("retry-count-int64", status.RetryCount).
		Infof("Resolve status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status ResolveStatus) LogKey() string {
	return string(base.ResolveStatusLogType) + "-" + status.Key()
}
