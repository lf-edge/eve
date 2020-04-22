// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"time"

	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

type OsVerParams struct {
	OSVerKey   string
	OSVerValue string
}

// This is what we assume will come from the ZedControl for base OS.
// Note that we can have different versions  configured for the
// same UUID, hence the key is the UUIDandVersion  We assume the
// elements in StorageConfig should be installed, but activation
// is driven by the Activate attribute.

type BaseOsConfig struct {
	UUIDandVersion    UUIDandVersion
	BaseOsVersion     string // From GetShortVersion
	ConfigSha256      string
	ConfigSignature   string
	OsParams          []OsVerParams // From GetLongVersion
	StorageConfigList []StorageConfig
	RetryCount        int32
	Activate          bool
}

func (config BaseOsConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
}

func (config BaseOsConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// Indexed by UUIDandVersion as above
type BaseOsStatus struct {
	UUIDandVersion    UUIDandVersion
	BaseOsVersion     string
	ConfigSha256      string
	Activated         bool
	Reboot            bool
	TooEarly          bool // Failed since previous was inprogress/test
	OsParams          []OsVerParams
	StorageStatusList []StorageStatus
	PartitionLabel    string
	PartitionDevice   string // From zboot
	PartitionState    string // From zboot

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

func (status BaseOsStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

func (status BaseOsStatus) CheckPendingAdd() bool {
	return false
}

func (status BaseOsStatus) CheckPendingModify() bool {
	return false
}

func (status BaseOsStatus) CheckPendingDelete() bool {
	return false
}

// captures the certificate config currently embeded
// in Storage config from various objects
// the UUIDandVersion/Config Sha are just
// copied from the holder object configuration
// for indexing
// XXX shouldn't it be keyed by safename
type CertObjConfig struct {
	UUIDandVersion    UUIDandVersion
	ConfigSha256      string
	StorageConfigList []StorageConfig
}

func (config CertObjConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
}

func (config CertObjConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// Indexed by UUIDandVersion as above
// XXX shouldn't it be keyed by safename
type CertObjStatus struct {
	UUIDandVersion    UUIDandVersion
	ConfigSha256      string
	StorageStatusList []StorageStatus
	// Mininum state across all steps/ StorageStatus.
	// Error* set implies error.
	State SwState
	// error strings across all steps/StorageStatus
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

func (status CertObjStatus) Key() string {
	return status.UUIDandVersion.UUID.String()
}

func (status CertObjStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

func (status CertObjStatus) CheckPendingAdd() bool {
	return false
}

func (status CertObjStatus) CheckPendingModify() bool {
	return false
}

func (status CertObjStatus) CheckPendingDelete() bool {
	return false
}

// getCertObjStatus finds a certificate, and returns the status
// returns three values,
//  - whether the cert object status is found
//  - whether the cert object is installed
//  - any error information
func (status CertObjStatus) getCertStatus(certURL string) (bool, bool, ErrorAndTime) {
	for _, certObj := range status.StorageStatusList {
		if certObj.Name == certURL {
			installed := true
			if certObj.HasError() || certObj.State != INSTALLED {
				installed = false
			}
			// An Error in StorageStatus can be from
			// DownloaderStatus with changing timestamp
			// from re-trying the download. Carry that to caller.
			return true, installed, ErrorAndTime{
				Error:     certObj.Error,
				ErrorTime: certObj.ErrorTime,
			}
		}
	}
	return false, false, ErrorAndTime{
		Error:     fmt.Sprintf("Invalid Certificate %s, not found", certURL),
		ErrorTime: time.Now(),
	}
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

// DeviceOpsCmd - copy of zconfig.DeviceOpsCmd
type DeviceOpsCmd struct {
	Counter      uint32
	DesiredState bool
	OpsTime      string
}
