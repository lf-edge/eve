// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
)

// ResolveConfig key/index to this is the combination of
// DatastoreID which is allocated by the controller, name
// and the sequence counter.
// It will resolve the tag in name to sha256
type ResolveConfig struct {
	DatastoreID uuid.UUID
	Name        string
	Counter     uint32
}

// Key : DatastoreID, name and sequence counter are used
// to differentiate different config
func (config ResolveConfig) Key() string {
	return fmt.Sprintf("%s+%s+%v", config.DatastoreID.String(), config.Name, config.Counter)
}

// LogCreate :
func (config ResolveConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ResolveConfigLogType, config.Name,
		config.DatastoreID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Resolve config create")
}

// LogModify :
func (config ResolveConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ResolveConfigLogType, config.Name,
		config.DatastoreID, config.LogKey())

	oldConfig, ok := old.(ResolveConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ResolveConfig type")
	}
	// Why would it change?
	logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
		Noticef("Resolve config modify other change")
}

// LogDelete :
func (config ResolveConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ResolveConfigLogType, config.Name,
		config.DatastoreID, config.LogKey())
	logObject.Noticef("Resolve config delete")

	base.DeleteLogObject(logBase, config.LogKey())
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
	// We save the original error when we do a retry
	OrigError string
}

// Key : DatastoreID, name and sequence counter are used
// to differentiate different config
func (status ResolveStatus) Key() string {
	return fmt.Sprintf("%s+%s+%v", status.DatastoreID.String(), status.Name, status.Counter)
}

// LogCreate :
func (status ResolveStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ResolveStatusLogType, status.Name,
		status.DatastoreID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("image-sha256", status.ImageSha256).
		AddField("retry-count-int64", status.RetryCount).
		Noticef("Resolve status create")
}

// LogModify :
func (status ResolveStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ResolveStatusLogType, status.Name,
		status.DatastoreID, status.LogKey())

	oldStatus, ok := old.(ResolveStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ResolveStatus type")
	}
	if oldStatus.ImageSha256 != status.ImageSha256 ||
		oldStatus.RetryCount != status.RetryCount {

		logObject.CloneAndAddField("image-sha256", status.ImageSha256).
			AddField("retry-count-int64", status.RetryCount).
			AddField("old-image-sha256", oldStatus.ImageSha256).
			AddField("old-retry-count-int64", oldStatus.RetryCount).
			Noticef("Resolve status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("Resolve status modify other change")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("image-sha256", status.ImageSha256).
			AddField("retry-count-int64", status.RetryCount).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Noticef("Resolve status modify")
	}
}

// LogDelete :
func (status ResolveStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ResolveStatusLogType, status.Name,
		status.DatastoreID, status.LogKey())
	logObject.CloneAndAddField("image-sha256", status.ImageSha256).
		AddField("retry-count-int64", status.RetryCount).
		Noticef("Resolve status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status ResolveStatus) LogKey() string {
	return string(base.ResolveStatusLogType) + "-" + status.Key()
}
