// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	log "github.com/sirupsen/logrus"
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
func (config ZbootConfig) LogCreate() {
	logObject := base.NewLogObject(base.ZbootConfigLogType, "",
		nilUUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("test-complete-bool", config.TestComplete).
		Infof("Zboot config create")
}

// LogModify :
func (config ZbootConfig) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.ZbootConfigLogType, "",
		nilUUID, config.LogKey())

	oldConfig, ok := old.(ZbootConfig)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of ZbootConfig type")
	}
	if oldConfig.TestComplete != config.TestComplete {

		logObject.CloneAndAddField("test-complete-bool", config.TestComplete).
			AddField("old-test-complete-bool", oldConfig.TestComplete).
			Infof("Zboot config modify")
	}

}

// LogDelete :
func (config ZbootConfig) LogDelete() {
	logObject := base.EnsureLogObject(base.ZbootConfigLogType, "",
		nilUUID, config.LogKey())
	logObject.CloneAndAddField("test-complete-bool", config.TestComplete).
		Infof("Zboot config delete")

	base.DeleteLogObject(config.LogKey())
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
func (status ZbootStatus) LogCreate() {
	logObject := base.NewLogObject(base.ZbootStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("partition-state", status.PartitionState).
		AddField("current-partition-bool", status.CurrentPartition).
		AddField("test-complete-bool", status.TestComplete).
		Infof("Zboot status create")
}

// LogModify :
func (status ZbootStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.ZbootStatusLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(ZbootStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of ZbootStatus type")
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
			Infof("Zboot status modify")
	}
}

// LogDelete :
func (status ZbootStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.ZbootStatusLogType, "",
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("partition-state", status.PartitionState).
		AddField("current-partition-bool", status.CurrentPartition).
		AddField("test-complete-bool", status.TestComplete).
		Infof("Zboot status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey : XXX note that this includes the ShortVersion, while Status only the PartitionLabel
func (status ZbootStatus) LogKey() string {
	return string(base.ZbootStatusLogType) + "-" + status.PartitionLabel + "-" + status.ShortVersion
}
