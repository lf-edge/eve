// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// ZbootConfig contains information fed from zedagent to baseosmgr.
// Only used to indicate that the testing of the image/partition is complete.
type ZbootConfig struct {
	PartitionLabel string
	TestComplete   bool
}

// Key returns the key used in pubsub for ZbootConfig
func (config ZbootConfig) Key() string {
	return config.PartitionLabel
}

// LogCreate :
func (config ZbootConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ZbootConfigLogType, "",
		nilUUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("test-complete-bool", config.TestComplete).
		Noticef("Zboot config create")
}

// LogModify :
func (config ZbootConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ZbootConfigLogType, "",
		nilUUID, config.LogKey())

	oldConfig, ok := old.(ZbootConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ZbootConfig type")
	}
	if oldConfig.TestComplete != config.TestComplete {

		logObject.CloneAndAddField("test-complete-bool", config.TestComplete).
			AddField("old-test-complete-bool", oldConfig.TestComplete).
			Noticef("Zboot config modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Noticef("Zboot config modify other change")
	}
}

// LogDelete :
func (config ZbootConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ZbootConfigLogType, "",
		nilUUID, config.LogKey())
	logObject.CloneAndAddField("test-complete-bool", config.TestComplete).
		Noticef("Zboot config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey : XXX note that this only the IMGx, while Status includes ShortVersion for logs
func (config ZbootConfig) LogKey() string {
	return string(base.ZbootConfigLogType) + "-" + config.PartitionLabel
}

type ZbootStatus struct {
	PartitionLabel   string
	PartitionDevname string
	PartitionState   string
	ShortVersion     string
	LongVersion      string
	CurrentPartition bool
	TestComplete     bool
}

func (status ZbootStatus) Key() string {
	return status.PartitionLabel
}

// LogCreate :
func (status ZbootStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ZbootStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("partition-state", status.PartitionState).
		AddField("current-partition-bool", status.CurrentPartition).
		AddField("test-complete-bool", status.TestComplete).
		Noticef("Zboot status create")
}

// LogModify :
func (status ZbootStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ZbootStatusLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(ZbootStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ZbootStatus type")
	}
	if oldStatus.PartitionState != status.PartitionState ||
		oldStatus.CurrentPartition != status.CurrentPartition ||
		oldStatus.TestComplete != status.TestComplete {

		logObject.CloneAndAddField("partition-state", status.PartitionState).
			AddField("old-partition-state", oldStatus.PartitionState).
			AddField("current-partition-bool", status.CurrentPartition).
			AddField("old-current-partition-bool", oldStatus.CurrentPartition).
			AddField("test-complete-bool", status.TestComplete).
			AddField("old-test-complete-bool", oldStatus.TestComplete).
			Noticef("Zboot status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("Zboot status modify other change")
	}
}

// LogDelete :
func (status ZbootStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ZbootStatusLogType, "",
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("partition-state", status.PartitionState).
		AddField("current-partition-bool", status.CurrentPartition).
		AddField("test-complete-bool", status.TestComplete).
		Noticef("Zboot status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey : XXX note that this includes the ShortVersion, while Status only the PartitionLabel
func (status ZbootStatus) LogKey() string {
	return string(base.ZbootStatusLogType) + "-" + status.PartitionLabel + "-" + status.ShortVersion
}
