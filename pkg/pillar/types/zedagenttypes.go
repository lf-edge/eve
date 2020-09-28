// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/satori/go.uuid"
)

// This is what we assume will come from the ZedControl for base OS.
// Note that we can have different versions  configured for the
// same UUID, hence the key is the UUIDandVersion  We assume the
// elements in ContentTreeConfig should be installed, but activation
// is driven by the Activate attribute.

type BaseOsConfig struct {
	UUIDandVersion        UUIDandVersion
	BaseOsVersion         string // From GetShortVersion
	ContentTreeConfigList []ContentTreeConfig
	RetryCount            int32
	Activate              bool
}

func (config BaseOsConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
}

// LogCreate :
func (config BaseOsConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.BaseOsConfigLogType, config.BaseOsVersion,
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activate", config.Activate).
		Noticef("BaseOs config create")
}

// LogModify :
func (config BaseOsConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.BaseOsConfigLogType, config.BaseOsVersion,
		config.UUIDandVersion.UUID, config.LogKey())

	oldConfig, ok := old.(BaseOsConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of BaseOsConfig type")
	}
	if oldConfig.Activate != config.Activate {

		logObject.CloneAndAddField("activate", config.Activate).
			AddField("old-activate", oldConfig.Activate).
			Noticef("BaseOs config modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Noticef("BaseOs config modify other change")
	}

}

// LogDelete :
func (config BaseOsConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.BaseOsConfigLogType, config.BaseOsVersion,
		config.UUIDandVersion.UUID, config.LogKey())
	logObject.CloneAndAddField("activate", config.Activate).
		Noticef("BaseOs config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config BaseOsConfig) LogKey() string {
	return string(base.BaseOsConfigLogType) + "-" + config.BaseOsVersion
}

// Indexed by UUIDandVersion as above
type BaseOsStatus struct {
	UUIDandVersion        UUIDandVersion
	BaseOsVersion         string
	Activated             bool
	Reboot                bool
	TooEarly              bool // Failed since previous was inprogress/test
	ContentTreeStatusList []ContentTreeStatus
	PartitionLabel        string
	PartitionDevice       string // From zboot
	PartitionState        string // From zboot
	// Mininum state across all steps/StorageStatus.
	// Error* set implies error.
	State SwState
	// error strings across all steps/StorageStatus
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

func (status BaseOsStatus) Key() string {
	return status.UUIDandVersion.UUID.String()
}

// LogCreate :
func (status BaseOsStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.BaseOsStatusLogType, status.BaseOsVersion,
		status.UUIDandVersion.UUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		Noticef("BaseOs status create")
}

// LogModify :
func (status BaseOsStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.BaseOsStatusLogType, status.BaseOsVersion,
		status.UUIDandVersion.UUID, status.LogKey())

	oldStatus, ok := old.(BaseOsStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of BaseOsStatus type")
	}
	if oldStatus.State != status.State {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("old-state", oldStatus.State.String()).
			Noticef("BaseOs status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("BaseOs status modify other change")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Errorf("BaseOs status modify")
	}
}

// LogDelete :
func (status BaseOsStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.BaseOsStatusLogType, status.BaseOsVersion,
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		Noticef("BaseOs status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status BaseOsStatus) LogKey() string {
	return string(base.BaseOsStatusLogType) + "-" + status.BaseOsVersion
}

// return value holder
type RetStatus struct {
	Changed   bool
	MinState  SwState
	AllErrors string
	ErrorTime time.Time
}

// Mirrors proto definition for ConfigItem
// The value can be bool, float, uint, or string
type ConfigItem struct {
	Key   string
	Value interface{}
}

// Mirrors proto definition for MetricItem
// The value can be bool, float, uint, or string
type MetricItem struct {
	Key   string
	Type  MetricItemType
	Value interface{}
}

type MetricItemType uint8

const (
	MetricItemOther   MetricItemType = iota // E.g., a string like an ESSID
	MetricItemGauge                         // Goes up and down over time
	MetricItemCounter                       // Monotonically increasing (until reboot)
	MetricItemState                         // Toggles on and off; count transitions
)

type DatastoreConfig struct {
	UUID     uuid.UUID
	DsType   string
	Fqdn     string
	ApiKey   string // XXX: to be deprecated, use CipherBlockStatus instead
	Password string // XXX: to be deprecated, use CipherBlockStatus instead
	Dpath    string // depending on DsType, it could be bucket or path
	Region   string

	// CipherBlockStatus, for encrypted credentials
	CipherBlockStatus
}

// Key is the key in pubsub
func (config DatastoreConfig) Key() string {
	return config.UUID.String()
}

// LogCreate :
func (config DatastoreConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DatastoreConfigLogType, "",
		config.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Datastore config create")
}

// LogModify :
func (config DatastoreConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DatastoreConfigLogType, "",
		config.UUID, config.LogKey())

	oldConfig, ok := old.(DatastoreConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DatastoreConfig type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
		Noticef("Datastore config modify")
}

// LogDelete :
func (config DatastoreConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DatastoreConfigLogType, "",
		config.UUID, config.LogKey())
	logObject.Noticef("Datastore config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config DatastoreConfig) LogKey() string {
	return string(base.DatastoreConfigLogType) + "-" + config.Key()
}

// NodeAgentStatus :
type NodeAgentStatus struct {
	Name              string
	CurPart           string
	UpdateInprogress  bool
	RemainingTestTime time.Duration
	DeviceReboot      bool
	RebootReason      string    // From last reboot
	RebootStack       string    // From last reboot
	RebootTime        time.Time // From last reboot
	RestartCounter    uint32
	RebootImage       string
}

// Key :
func (status NodeAgentStatus) Key() string {
	return status.Name
}

// LogCreate :
func (status NodeAgentStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NodeAgentStatusLogType, status.Name,
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Nodeagent status create")
}

// LogModify :
func (status NodeAgentStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NodeAgentStatusLogType, status.Name,
		nilUUID, status.LogKey())

	oldStatus, ok := old.(NodeAgentStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NodeAgentStatus type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Nodeagent status modify")
}

// LogDelete :
func (status NodeAgentStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NodeAgentStatusLogType, status.Name,
		nilUUID, status.LogKey())
	logObject.Noticef("Nodeagent status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status NodeAgentStatus) LogKey() string {
	return string(base.NodeAgentStatusLogType) + "-" + status.Key()
}

// ConfigGetStatus : Config Get Status from Controller
type ConfigGetStatus uint8

// ConfigGetSuccess : Config get is successful
const (
	ConfigGetSuccess ConfigGetStatus = iota + 1
	ConfigGetFail
	ConfigGetTemporaryFail
	ConfigGetReadSaved
)

// ZedAgentStatus :
type ZedAgentStatus struct {
	Name            string
	ConfigGetStatus ConfigGetStatus
	RebootCmd       bool
	RebootReason    string // Current reason to reboot
}

// Key :
func (status ZedAgentStatus) Key() string {
	return status.Name
}

// LogCreate :
func (status ZedAgentStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ZedAgentStatusLogType, status.Name,
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Zedagent status create")
}

// LogModify :
func (status ZedAgentStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ZedAgentStatusLogType, status.Name,
		nilUUID, status.LogKey())

	oldStatus, ok := old.(ZedAgentStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ZedAgentStatus type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Zedagent status modify")
}

// LogDelete :
func (status ZedAgentStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ZedAgentStatusLogType, status.Name,
		nilUUID, status.LogKey())
	logObject.Noticef("Zedagent status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status ZedAgentStatus) LogKey() string {
	return string(base.ZedAgentStatusLogType) + "-" + status.Key()
}

// DeviceOpsCmd - copy of zconfig.DeviceOpsCmd
type DeviceOpsCmd struct {
	Counter      uint32
	DesiredState bool
	OpsTime      string
}
