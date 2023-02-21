// Copyright (c) 2017-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// IPAddrNotAvail is returned when there is no (suitable) IP address
// assigned to a given interface.
type IPAddrNotAvail struct {
	IfName string
}

// Error message.
func (e *IPAddrNotAvail) Error() string {
	return fmt.Sprintf("interface %s: no suitable IP address available", e.IfName)
}

// DNSNotAvail is returned when there is no DNS server configured
// for a given interface.
type DNSNotAvail struct {
	IfName string
}

// Error message.
func (e *DNSNotAvail) Error() string {
	return fmt.Sprintf("interface %s: no DNS server available", e.IfName)
}

// Indexed by UUID
type AppNetworkConfig struct {
	UUIDandVersion      UUIDandVersion
	DisplayName         string
	Activate            bool
	GetStatsIPAddr      net.IP
	UnderlayNetworkList []UnderlayNetworkConfig
	CloudInitUserData   *string `json:"pubsub-large-CloudInitUserData"`
	CipherBlockStatus   CipherBlockStatus
	MetaDataType        MetaDataType
}

func (config AppNetworkConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
}

// LogCreate :
func (config AppNetworkConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppNetworkConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activate", config.Activate).
		Noticef("App network config create")
}

// LogModify :
func (config AppNetworkConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppNetworkConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())

	oldConfig, ok := old.(AppNetworkConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppNetworkConfig type")
	}
	if oldConfig.Activate != config.Activate {

		logObject.CloneAndAddField("activate", config.Activate).
			AddField("old-activate", oldConfig.Activate).
			Noticef("App network config modify")
	} else {
		// Log at Function level
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Functionf("App network config modify other change")
	}
}

// LogDelete :
func (config AppNetworkConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppNetworkConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	logObject.CloneAndAddField("activate", config.Activate).
		Noticef("App network config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config AppNetworkConfig) LogKey() string {
	return string(base.AppNetworkConfigLogType) + "-" + config.Key()
}

func (config *AppNetworkConfig) getUnderlayConfig(
	network uuid.UUID) *UnderlayNetworkConfig {
	for i := range config.UnderlayNetworkList {
		ulConfig := &config.UnderlayNetworkList[i]
		if ulConfig.Network == network {
			return ulConfig
		}
	}
	return nil
}

func (config *AppNetworkConfig) IsNetworkUsed(network uuid.UUID) bool {
	ulConfig := config.getUnderlayConfig(network)
	if ulConfig != nil {
		return true
	}
	// Network UUID matching neither UL nor OL network
	return false
}

func (status AppNetworkStatus) Pending() bool {
	return status.PendingAdd || status.PendingModify || status.PendingDelete
}

// AwaitingNetwork - Is the app waiting for network?
func (status AppNetworkStatus) AwaitingNetwork() bool {
	return status.AwaitNetworkInstance
}

// GetULStatusForNI returns UnderlayNetworkStatus for every application VIF
// connected to the given network instance (there can be multiple interfaces connected
// to the same network instance).
func (status AppNetworkStatus) GetULStatusForNI(netUUID uuid.UUID) []*UnderlayNetworkStatus {
	var uls []*UnderlayNetworkStatus
	for i := range status.UnderlayNetworkList {
		ul := &status.UnderlayNetworkList[i]
		if ul.Network == netUUID {
			uls = append(uls, ul)
		}
	}
	return uls
}

// Indexed by UUID
type AppNetworkStatus struct {
	UUIDandVersion UUIDandVersion
	AppNum         int
	Activated      bool
	PendingAdd     bool
	PendingModify  bool
	PendingDelete  bool
	DisplayName    string
	// Copy from the AppNetworkConfig; used to delete when config is gone.
	GetStatsIPAddr       net.IP
	UnderlayNetworkList  []UnderlayNetworkStatus
	AwaitNetworkInstance bool // If any Missing flag is set in the networks
	// Any errors from provisioning the network
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

func (status AppNetworkStatus) Key() string {
	return status.UUIDandVersion.UUID.String()
}

// LogCreate :
func (status AppNetworkStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppNetworkStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activated", status.Activated).
		Noticef("App network status create")
}

// LogModify :
func (status AppNetworkStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppNetworkStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())

	oldStatus, ok := old.(AppNetworkStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppNetworkStatus type")
	}
	if oldStatus.Activated != status.Activated {

		logObject.CloneAndAddField("activated", status.Activated).
			AddField("old-activated", oldStatus.Activated).
			Noticef("App network status modify")
	} else {
		// Log at Function level
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Functionf("App network status modify other change")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("activated", status.Activated).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Noticef("App network status modify")
	}
}

// LogDelete :
func (status AppNetworkStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppNetworkStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.CloneAndAddField("activated", status.Activated).
		Noticef("App network status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status AppNetworkStatus) LogKey() string {
	return string(base.AppNetworkStatusLogType) + "-" + status.Key()
}

// AppContainerMetrics - App Container Metrics
type AppContainerMetrics struct {
	UUIDandVersion UUIDandVersion // App UUID
	// Stats Collection time for uploading stats to cloud
	CollectTime time.Time
	StatsList   []AppContainerStats
}

// AppContainerStats - for App Container Stats
type AppContainerStats struct {
	ContainerName string // unique under an App
	Status        string // uptime, pause, stop status
	Pids          uint32 // number of PIDs within the container
	// CPU stats
	Uptime         int64  // unix.nano, time since container starts
	CPUTotal       uint64 // container CPU since starts in nanosec
	SystemCPUTotal uint64 // total system, user, idle in nanosec
	// Memory stats
	UsedMem      uint32 // in MBytes
	AllocatedMem uint32 // in MBytes
	// Network stats
	TxBytes uint64 // in Bytes
	RxBytes uint64 // in Bytes
	// Disk stats
	ReadBytes  uint64 // in MBytes
	WriteBytes uint64 // in MBytes
}

// Key - key for AppContainerMetrics
func (acMetric AppContainerMetrics) Key() string {
	return acMetric.UUIDandVersion.UUID.String()
}

// LogCreate :
func (acMetric AppContainerMetrics) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppContainerMetricsLogType, "",
		acMetric.UUIDandVersion.UUID, acMetric.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("App container metric create")
}

// LogModify :
func (acMetric AppContainerMetrics) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppContainerMetricsLogType, "",
		acMetric.UUIDandVersion.UUID, acMetric.LogKey())

	oldAcMetric, ok := old.(AppContainerMetrics)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppContainerMetrics type")
	}
	// XXX remove? XXX huge?
	logObject.CloneAndAddField("diff", cmp.Diff(oldAcMetric, acMetric)).
		Metricf("App container metric modify")
}

// LogDelete :
func (acMetric AppContainerMetrics) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppContainerMetricsLogType, "",
		acMetric.UUIDandVersion.UUID, acMetric.LogKey())
	logObject.Metricf("App container metric delete")

	base.DeleteLogObject(logBase, acMetric.LogKey())
}

// LogKey :
func (acMetric AppContainerMetrics) LogKey() string {
	return string(base.AppContainerMetricsLogType) + "-" + acMetric.Key()
}

// IntfStatusMap - Used to return per-interface test results (success and failures)
//
//	ifName is used as the key
type IntfStatusMap struct {
	// StatusMap -> Key: ifname, Value: TestResults
	StatusMap map[string]TestResults
}

// RecordSuccess records a success for the ifName
func (intfMap *IntfStatusMap) RecordSuccess(ifName string) {
	tr, ok := intfMap.StatusMap[ifName]
	if !ok {
		tr = TestResults{}
	}
	tr.RecordSuccess()
	intfMap.StatusMap[ifName] = tr
}

// RecordFailure records a failure for the ifName
func (intfMap *IntfStatusMap) RecordFailure(ifName string, errStr string) {
	tr, ok := intfMap.StatusMap[ifName]
	if !ok {
		tr = TestResults{}
	}
	tr.RecordFailure(errStr)
	intfMap.StatusMap[ifName] = tr
}

// SetOrUpdateFromMap - Set all the entries from the given per-interface map
// Entries which are not in the source are not modified
func (intfMap *IntfStatusMap) SetOrUpdateFromMap(
	source IntfStatusMap) {
	for intf, src := range source.StatusMap {
		tr, ok := intfMap.StatusMap[intf]
		if !ok {
			tr = TestResults{}
		}
		tr.Update(src)
		intfMap.StatusMap[intf] = tr
	}
}

// NewIntfStatusMap - Create a new instance of IntfStatusMap
func NewIntfStatusMap() *IntfStatusMap {
	intfStatusMap := IntfStatusMap{}
	intfStatusMap.StatusMap = make(map[string]TestResults)
	return &intfStatusMap
}

// DevicePortConfigList is an array in timestamp aka priority order;
// first one is the most desired config to use
// It includes test results hence is misnamed - should have a separate status
// This is only published under the key "global"
type DevicePortConfigList struct {
	CurrentIndex   int
	PortConfigList []DevicePortConfig
}

// MostlyEqual - Equal if everything else other than timestamps is equal.
func (config DevicePortConfigList) MostlyEqual(config2 DevicePortConfigList) bool {

	if len(config.PortConfigList) != len(config2.PortConfigList) {
		return false
	}
	if config.CurrentIndex != config2.CurrentIndex {
		return false
	}
	for i, c1 := range config.PortConfigList {
		c2 := config2.PortConfigList[i]

		if !c1.MostlyEqual(&c2) || c1.State != c2.State {
			return false
		}
	}
	return true
}

// PubKey is used for pubsub
func (config DevicePortConfigList) PubKey() string {
	return "global"
}

// LogCreate :
func (config DevicePortConfigList) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DevicePortConfigListLogType, "",
		nilUUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("current-index-int64", config.CurrentIndex).
		AddField("num-portconfig-int64", len(config.PortConfigList)).
		Noticef("DevicePortConfigList create")
}

// LogModify :
func (config DevicePortConfigList) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DevicePortConfigListLogType, "",
		nilUUID, config.LogKey())

	oldConfig, ok := old.(DevicePortConfigList)
	if !ok {
		logObject.Clone().Errorf("LogModify: Old object interface passed is not of DevicePortConfigList type")
		return
	}
	if oldConfig.CurrentIndex != config.CurrentIndex ||
		len(oldConfig.PortConfigList) != len(config.PortConfigList) {

		logObject.CloneAndAddField("current-index-int64", config.CurrentIndex).
			AddField("num-portconfig-int64", len(config.PortConfigList)).
			AddField("old-current-index-int64", oldConfig.CurrentIndex).
			AddField("old-num-portconfig-int64", len(oldConfig.PortConfigList)).
			Noticef("DevicePortConfigList modify")
	} else {
		// Log at Trace level - most likely just a timestamp change
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Tracef("DevicePortConfigList modify other change")
	}

}

// LogDelete :
func (config DevicePortConfigList) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DevicePortConfigListLogType, "",
		nilUUID, config.LogKey())
	logObject.CloneAndAddField("current-index-int64", config.CurrentIndex).
		AddField("num-portconfig-int64", len(config.PortConfigList)).
		Noticef("DevicePortConfigList delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config DevicePortConfigList) LogKey() string {
	return string(base.DevicePortConfigListLogType) + "-" + config.PubKey()
}

// DPCState tracks the progression a DPC verification.
type DPCState uint8

const (
	// DPCStateNone : undefined state.
	DPCStateNone DPCState = iota
	// DPCStateFail : DPC verification failed.
	DPCStateFail
	// DPCStateFailWithIPAndDNS : failed to reach controller but has IP/DNS.
	DPCStateFailWithIPAndDNS
	// DPCStateSuccess : DPC verification succeeded.
	DPCStateSuccess
	// DPCStateIPDNSWait : waiting for interface IP address(es) and/or DNS server(s).
	DPCStateIPDNSWait
	// DPCStatePCIWait : waiting for some interface to come from pciback.
	DPCStatePCIWait
	// DPCStateIntfWait : waiting for some interface to appear in the network stack.
	DPCStateIntfWait
	// DPCStateRemoteWait : DPC verification failed because controller is down
	// or has old certificate.
	DPCStateRemoteWait
	// DPCStateAsyncWait : waiting for some config operations to finalize which are
	// running asynchronously in the background.
	DPCStateAsyncWait
)

// String returns the string name
func (status DPCState) String() string {
	switch status {
	case DPCStateNone:
		return ""
	case DPCStateFail:
		return "DPC_FAIL"
	case DPCStateFailWithIPAndDNS:
		return "DPC_FAIL_WITH_IPANDDNS"
	case DPCStateSuccess:
		return "DPC_SUCCESS"
	case DPCStateIPDNSWait:
		return "DPC_IPDNS_WAIT"
	case DPCStatePCIWait:
		return "DPC_PCI_WAIT"
	case DPCStateIntfWait:
		return "DPC_INTF_WAIT"
	case DPCStateRemoteWait:
		return "DPC_REMOTE_WAIT"
	case DPCStateAsyncWait:
		return "DPC_ASYNC_WAIT"
	default:
		return fmt.Sprintf("Unknown status %d", status)
	}
}

// DevicePortConfig is a misnomer in that it includes the total test results
// plus the test results for a given port. The complete status with
// IP addresses lives in DeviceNetworkStatus
type DevicePortConfig struct {
	Version      DevicePortConfigVersion
	Key          string
	TimePriority time.Time // All zero's is fallback lowest priority
	State        DPCState
	ShaFile      string // File in which to write ShaValue once DevicePortConfigList published
	ShaValue     []byte
	TestResults
	LastIPAndDNS time.Time // Time when we got some IP addresses and DNS

	Ports []NetworkPortConfig
}

// PubKey is used for pubsub. Key string plus TimePriority
func (config DevicePortConfig) PubKey() string {
	return config.Key + "@" + config.TimePriority.UTC().Format(time.RFC3339Nano)
}

// LogCreate :
func (config DevicePortConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DevicePortConfigLogType, "",
		nilUUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("ports-int64", len(config.Ports)).
		AddField("last-failed", config.LastFailed).
		AddField("last-succeeded", config.LastSucceeded).
		AddField("last-error", config.LastError).
		AddField("state", config.State.String()).
		Noticef("DevicePortConfig create")
	for _, p := range config.Ports {
		// XXX different logobject for a particular port?
		logObject.CloneAndAddField("ifname", p.IfName).
			AddField("last-error", p.LastError).
			AddField("last-succeeded", p.LastSucceeded).
			AddField("last-failed", p.LastFailed).
			Noticef("DevicePortConfig port create")
	}
}

// LogModify :
func (config DevicePortConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DevicePortConfigLogType, "",
		nilUUID, config.LogKey())

	oldConfig, ok := old.(DevicePortConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DevicePortConfig type")
	}
	if len(oldConfig.Ports) != len(config.Ports) ||
		oldConfig.LastFailed != config.LastFailed ||
		oldConfig.LastSucceeded != config.LastSucceeded ||
		oldConfig.LastError != config.LastError ||
		oldConfig.State != config.State {

		logData := logObject.CloneAndAddField("ports-int64", len(config.Ports)).
			AddField("last-failed", config.LastFailed).
			AddField("last-succeeded", config.LastSucceeded).
			AddField("last-error", config.LastError).
			AddField("state", config.State.String()).
			AddField("old-ports-int64", len(oldConfig.Ports)).
			AddField("old-last-failed", oldConfig.LastFailed).
			AddField("old-last-succeeded", oldConfig.LastSucceeded).
			AddField("old-last-error", oldConfig.LastError).
			AddField("old-state", oldConfig.State.String())
		if len(oldConfig.Ports) == len(config.Ports) &&
			config.LastFailed == oldConfig.LastFailed &&
			config.LastError == oldConfig.LastError &&
			oldConfig.State == config.State &&
			config.LastSucceeded.After(oldConfig.LastFailed) &&
			oldConfig.LastSucceeded.After(oldConfig.LastFailed) {
			// if we have success again, reduce log level
			logData.Function("DevicePortConfig port modify")
		} else {
			logData.Notice("DevicePortConfig port modify")
		}
	}
	// XXX which fields to compare/log?
	for i, p := range config.Ports {
		if len(oldConfig.Ports) <= i {
			continue
		}
		op := oldConfig.Ports[i]
		// XXX different logobject for a particular port?
		if p.HasError() != op.HasError() ||
			p.LastFailed != op.LastFailed ||
			p.LastSucceeded != op.LastSucceeded ||
			p.LastError != op.LastError {
			logData := logObject.CloneAndAddField("ifname", p.IfName).
				AddField("last-error", p.LastError).
				AddField("last-succeeded", p.LastSucceeded).
				AddField("last-failed", p.LastFailed).
				AddField("old-last-error", op.LastError).
				AddField("old-last-succeeded", op.LastSucceeded).
				AddField("old-last-failed", op.LastFailed)
			if p.HasError() == op.HasError() &&
				p.LastFailed == op.LastFailed &&
				p.LastError == op.LastError &&
				p.LastSucceeded.After(op.LastFailed) &&
				op.LastSucceeded.After(op.LastFailed) {
				// if we have success again, reduce log level
				logData.Function("DevicePortConfig port modify")
			} else {
				logData.Notice("DevicePortConfig port modify")
			}
		}
	}
}

// LogDelete :
func (config DevicePortConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DevicePortConfigLogType, "",
		nilUUID, config.LogKey())
	logObject.CloneAndAddField("ports-int64", len(config.Ports)).
		AddField("last-failed", config.LastFailed).
		AddField("last-succeeded", config.LastSucceeded).
		AddField("last-error", config.LastError).
		AddField("state", config.State.String()).
		Noticef("DevicePortConfig delete")
	for _, p := range config.Ports {
		// XXX different logobject for a particular port?
		logObject.CloneAndAddField("ifname", p.IfName).
			AddField("last-error", p.LastError).
			AddField("last-succeeded", p.LastSucceeded).
			AddField("last-failed", p.LastFailed).
			Noticef("DevicePortConfig port delete")
	}

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config DevicePortConfig) LogKey() string {
	return string(base.DevicePortConfigLogType) + "-" + config.PubKey()
}

// LookupPortByIfName returns port configuration for the given interface.
func (config *DevicePortConfig) LookupPortByIfName(ifName string) *NetworkPortConfig {
	if config != nil {
		for _, port := range config.Ports {
			if port.IfName == ifName {
				return &port
			}
		}
	}
	return nil
}

// LookupPortByLogicallabel returns port configuration referenced by the logical label.
func (config *DevicePortConfig) LookupPortByLogicallabel(
	label string) *NetworkPortConfig {
	for _, port := range config.Ports {
		if port.Logicallabel == label {
			return &port
		}
	}
	return nil
}

// TestResults is used to record when some test Failed or Succeeded.
// All zeros timestamps means it was never tested.
type TestResults struct {
	LastFailed    time.Time
	LastSucceeded time.Time
	LastError     string // Set when LastFailed is updated
}

// RecordSuccess records a success
// Keeps the LastFailed in place as history
func (trPtr *TestResults) RecordSuccess() {
	trPtr.LastSucceeded = time.Now()
	trPtr.LastError = ""
}

// RecordFailure records a failure
// Keeps the LastSucceeded in place as history
func (trPtr *TestResults) RecordFailure(errStr string) {
	if errStr == "" {
		logrus.Fatal("Missing error string")
	}
	trPtr.LastFailed = time.Now()
	trPtr.LastError = errStr
}

// HasError returns true if there is an error
// Returns false if it was never tested i.e., both timestamps zero
func (trPtr *TestResults) HasError() bool {
	return trPtr.LastFailed.After(trPtr.LastSucceeded)
}

// Update uses the src to add info to the results
// If src has newer information for the 'other' part we update that as well.
func (trPtr *TestResults) Update(src TestResults) {
	if src.HasError() {
		trPtr.LastFailed = src.LastFailed
		trPtr.LastError = src.LastError
		if src.LastSucceeded.After(trPtr.LastSucceeded) {
			trPtr.LastSucceeded = src.LastSucceeded
		}
	} else {
		trPtr.LastSucceeded = src.LastSucceeded
		trPtr.LastError = ""
		if src.LastFailed.After(trPtr.LastFailed) {
			trPtr.LastFailed = src.LastFailed
		}
	}
}

// Clear test results.
func (trPtr *TestResults) Clear() {
	trPtr.LastFailed = time.Time{}
	trPtr.LastSucceeded = time.Time{}
	trPtr.LastError = ""
}

type DevicePortConfigVersion uint32

// GetPortByIfName - DevicePortConfig method to get config pointer
func (config *DevicePortConfig) GetPortByIfName(
	ifname string) *NetworkPortConfig {
	for indx := range config.Ports {
		portPtr := &config.Ports[indx]
		if ifname == portPtr.IfName {
			return portPtr
		}
	}
	return nil
}

// RecordPortSuccess - Record for given ifname in PortConfig
func (config *DevicePortConfig) RecordPortSuccess(ifname string) {
	portPtr := config.GetPortByIfName(ifname)
	if portPtr != nil {
		portPtr.RecordSuccess()
	}
}

// RecordPortFailure - Record for given ifname in PortConfig
func (config *DevicePortConfig) RecordPortFailure(ifname string, errStr string) {
	portPtr := config.GetPortByIfName(ifname)
	if portPtr != nil {
		portPtr.RecordFailure(errStr)
	}
}

// When new fields and/or new semantics are added to DevicePortConfig a new
// version value is added here.
const (
	DPCInitial DevicePortConfigVersion = iota
	DPCIsMgmt                          // Require IsMgmt to be set for management ports
)

// DoSanitize -
func (config *DevicePortConfig) DoSanitize(log *base.LogObject,
	sanitizeTimePriority bool, sanitizeKey bool, key string,
	sanitizeName, sanitizeL3Port bool) {

	if sanitizeTimePriority {
		zeroTime := time.Time{}
		if config.TimePriority == zeroTime {
			// A json override file should really contain a
			// timepriority field so we can determine whether
			// it or the information received from the controller
			// is more current.
			// If we can stat the file we use 1980, otherwise
			// we use 1970; using the modify time of the file
			// is too unpredictable.
			_, err1 := os.Stat(fmt.Sprintf("%s/DevicePortConfig/%s.json",
				TmpDirname, key))
			_, err2 := os.Stat(fmt.Sprintf("%s/DevicePortConfig/%s.json",
				IdentityDirname, key))
			if err1 == nil || err2 == nil {
				config.TimePriority = time.Date(1980,
					time.January, 1, 0, 0, 0, 0, time.UTC)
			} else {
				config.TimePriority = time.Date(1970,
					time.January, 1, 0, 0, 0, 0, time.UTC)
			}
			log.Warnf("DoSanitize: Forcing TimePriority for %s to %v",
				key, config.TimePriority)
		}
	}
	if sanitizeKey {
		if config.Key == "" {
			config.Key = key
			log.Noticef("DoSanitize: Forcing Key for %s TS %v\n",
				key, config.TimePriority)
		}
	}
	if sanitizeName {
		// In case Phylabel isn't set we make it match IfName. Ditto for Logicallabel
		// XXX still needed?
		for i := range config.Ports {
			port := &config.Ports[i]
			if port.Phylabel == "" {
				port.Phylabel = port.IfName
				log.Functionf("XXX DoSanitize: Forcing Phylabel for %s ifname %s\n",
					key, port.IfName)
			}
			if port.Logicallabel == "" {
				port.Logicallabel = port.IfName
				log.Functionf("XXX DoSanitize: Forcing Logicallabel for %s ifname %s\n",
					key, port.IfName)
			}
		}
	}
	if sanitizeL3Port {
		// IsL3Port flag was introduced to NetworkPortConfig in 7.3.0
		// It is used to differentiate between L3 ports (with IP/DNS config)
		// and intermediate L2-only ports (bond slaves, VLAN parents, etc.).
		// Before 7.3.0, EVE didn't support L2-only adapters and all uplink ports
		// were L3 endpoints.
		// However, even with VLANs and bonds there has to be at least one L3
		// port (L2 adapters are only intermediates with L3 endpoint(s) at the top).
		// This means that to support upgrade from older EVE versions,
		// we can simply check if there is at least one L3 port, and if not, it means
		// that we are dealing with an older persisted/override DPC, where all
		// ports should be marked as L3.
		var hasL3Port bool
		for _, port := range config.Ports {
			hasL3Port = hasL3Port || port.IsL3Port
		}
		if !hasL3Port {
			for i := range config.Ports {
				config.Ports[i].IsL3Port = true
			}
		}
	}
}

// CountMgmtPorts returns the number of management ports
// Exclude any broken ones with Dhcp = DT_NONE
func (config *DevicePortConfig) CountMgmtPorts() int {

	count := 0
	for _, port := range config.Ports {
		if port.IsMgmt && port.Dhcp != DT_NONE {
			count++
		}
	}
	return count
}

// MostlyEqual compares two DevicePortConfig but skips things that are
// more of status such as the timestamps and the TestResults
// XXX Compare Version or not?
// We compare the Ports in array order.
func (config *DevicePortConfig) MostlyEqual(config2 *DevicePortConfig) bool {

	if config.Key != config2.Key {
		return false
	}
	if len(config.Ports) != len(config2.Ports) {
		return false
	}
	for i, p1 := range config.Ports {
		p2 := config2.Ports[i]
		if p1.IfName != p2.IfName ||
			p1.Phylabel != p2.Phylabel ||
			p1.Logicallabel != p2.Logicallabel ||
			p1.Alias != p2.Alias ||
			p1.IsMgmt != p2.IsMgmt ||
			p1.Cost != p2.Cost {
			return false
		}
		if !reflect.DeepEqual(p1.DhcpConfig, p2.DhcpConfig) ||
			!reflect.DeepEqual(p1.ProxyConfig, p2.ProxyConfig) ||
			!reflect.DeepEqual(p1.WirelessCfg, p2.WirelessCfg) {
			return false
		}
	}
	return true
}

// IsDPCTestable - Return false if recent failure (less than "minTimeSinceFailure")
// Also returns false if it isn't usable
func (config DevicePortConfig) IsDPCTestable(minTimeSinceFailure time.Duration) bool {
	if !config.IsDPCUsable() {
		return false
	}
	if config.LastFailed.IsZero() {
		return true
	}
	if config.LastSucceeded.After(config.LastFailed) {
		return true
	}
	return time.Since(config.LastFailed) >= minTimeSinceFailure
}

// IsDPCUntested - returns true if this is something we might want to test now.
// Checks if it is Usable since there is no point in testing unusable things.
func (config DevicePortConfig) IsDPCUntested() bool {
	if config.LastFailed.IsZero() && config.LastSucceeded.IsZero() &&
		config.IsDPCUsable() {
		return true
	}
	return false
}

// IsDPCUsable - checks whether something is invalid; no management IP
// addresses means it isn't usable hence we return false if none.
func (config DevicePortConfig) IsDPCUsable() bool {
	mgmtCount := config.CountMgmtPorts()
	return mgmtCount > 0
}

// WasDPCWorking - Check if the last results for the DPC was Success
func (config DevicePortConfig) WasDPCWorking() bool {

	if config.LastSucceeded.IsZero() {
		return false
	}
	if config.LastSucceeded.After(config.LastFailed) {
		return true
	}
	return false
}

// UpdatePortStatusFromIntfStatusMap - Set TestResults for ports in DevicePortConfig to
// those from intfStatusMap. If a port is not found in intfStatusMap, it means
// the port was not tested, so we retain the original TestResults for the port.
func (config *DevicePortConfig) UpdatePortStatusFromIntfStatusMap(
	intfStatusMap IntfStatusMap) {
	for indx := range config.Ports {
		portPtr := &config.Ports[indx]
		tr, ok := intfStatusMap.StatusMap[portPtr.IfName]
		if ok {
			portPtr.TestResults.Update(tr)
		}
		// Else - Port not tested hence no change
	}
}

type NetworkProxyType uint8

// Values if these definitions should match the values
// given to the types in zapi.ProxyProto
const (
	NPT_HTTP NetworkProxyType = iota
	NPT_HTTPS
	NPT_SOCKS
	NPT_FTP
	NPT_NOPROXY
	NPT_LAST = 255
)

// WifiKeySchemeType - types of key management
type WifiKeySchemeType uint8

// Key Scheme type
const (
	KeySchemeNone WifiKeySchemeType = iota // enum for key scheme
	KeySchemeWpaPsk
	KeySchemeWpaEap
	KeySchemeOther
)

// WirelessType - types of wireless media
type WirelessType uint8

// enum wireless type
const (
	WirelessTypeNone WirelessType = iota // enum for wireless type
	WirelessTypeCellular
	WirelessTypeWifi
)

type ProxyEntry struct {
	Type   NetworkProxyType `json:"type"`
	Server string           `json:"server"`
	Port   uint32           `json:"port"`
}

type ProxyConfig struct {
	Proxies    []ProxyEntry
	Exceptions string
	Pacfile    string
	// If Enable is set we use WPAD. If the URL is not set we try
	// the various DNS suffixes until we can download a wpad.dat file
	NetworkProxyEnable bool   // Enable WPAD
	NetworkProxyURL    string // Complete URL i.e., with /wpad.dat
	WpadURL            string // The URL determined from DNS
	// List of certs which will be added to TLS trust
	ProxyCertPEM [][]byte `json:"pubsub-large-ProxyCertPEM"`
}

type DhcpConfig struct {
	Dhcp       DhcpType // If DT_STATIC use below; if DT_NONE do nothing
	AddrSubnet string   // In CIDR e.g., 192.168.1.44/24
	Gateway    net.IP
	DomainName string
	NtpServer  net.IP
	DnsServers []net.IP    // If not set we use Gateway as DNS server
	Type       NetworkType // IPv4 or IPv6 or Dual stack
}

// WifiConfig - Wifi structure
type WifiConfig struct {
	SSID      string            // wifi SSID
	KeyScheme WifiKeySchemeType // such as WPA-PSK, WPA-EAP

	// XXX: to be deprecated, use CipherBlockStatus instead
	Identity string // identity or username for WPA-EAP

	// XXX: to be deprecated, use CipherBlockStatus instead
	Password string // string of pass phrase or password hash
	Priority int32

	// CipherBlockStatus, for encrypted credentials
	CipherBlockStatus
}

// CellConfig - Cellular part of the configure
type CellConfig struct {
	APN          string // LTE APN
	ProbeAddr    string
	DisableProbe bool
	// Enable to get location info from the GNSS receiver of the LTE modem.
	LocationTracking bool
}

// WirelessConfig - wireless structure
type WirelessConfig struct {
	WType    WirelessType // Wireless Type
	Cellular []CellConfig // LTE APN
	Wifi     []WifiConfig // Wifi Config params
}

// WirelessStatus : state information for a single wireless device
type WirelessStatus struct {
	WType    WirelessType
	Cellular WwanNetworkStatus
	// TODO: Wifi status
}

const (
	// PortCostMin is the lowest cost
	PortCostMin = uint8(0)
	// PortCostMax is the highest cost
	PortCostMax = uint8(255)
)

// L2LinkType - supported types of an L2 link
type L2LinkType uint8

const (
	// L2LinkTypeNone : not an L2 link (used for physical network adapters).
	L2LinkTypeNone L2LinkType = iota
	// L2LinkTypeVLAN : VLAN sub-interface
	L2LinkTypeVLAN
	// L2LinkTypeBond : Bond interface
	L2LinkTypeBond
)

// L2LinkConfig - contains either VLAN or Bond interface configuration,
// depending on the L2Type.
type L2LinkConfig struct {
	L2Type L2LinkType
	VLAN   VLANConfig
	Bond   BondConfig
}

// VLANConfig - VLAN sub-interface configuration.
type VLANConfig struct {
	// Logical name of the parent port.
	ParentPort string
	// VLAN ID.
	ID uint16
}

// BondMode specifies the policy indicating how bonding slaves are used
// during network transmissions.
type BondMode uint8

const (
	// BondModeUnspecified : default is Round-Robin
	BondModeUnspecified BondMode = iota
	// BondModeBalanceRR : Round-Robin
	BondModeBalanceRR
	// BondModeActiveBackup : Active/Backup
	BondModeActiveBackup
	// BondModeBalanceXOR : select slave for a packet using a hash function
	BondModeBalanceXOR
	// BondModeBroadcast : send every packet on all slaves
	BondModeBroadcast
	// BondMode802Dot3AD : IEEE 802.3ad Dynamic link aggregation
	BondMode802Dot3AD
	// BondModeBalanceTLB : Adaptive transmit load balancing
	BondModeBalanceTLB
	// BondModeBalanceALB : Adaptive load balancing
	BondModeBalanceALB
)

// LacpRate specifies the rate in which EVE will ask LACP link partners
// to transmit LACPDU packets in 802.3ad mode.
type LacpRate uint8

const (
	// LacpRateUnspecified : default is Slow.
	LacpRateUnspecified LacpRate = iota
	// LacpRateSlow : Request partner to transmit LACPDUs every 30 seconds.
	LacpRateSlow
	// LacpRateFast : Request partner to transmit LACPDUs every 1 second.
	LacpRateFast
)

// BondConfig - Bond (LAG) interface configuration.
type BondConfig struct {
	// Logical names of PhysicalIO network adapters aggregated by this bond.
	AggregatedPorts []string

	// Bonding policy.
	Mode BondMode

	// LACPDU packets transmission rate.
	// Applicable for BondMode802Dot3AD only.
	LacpRate LacpRate

	// Link monitoring is either disabled or one of the monitors
	// is enabled, never both at the same time.
	MIIMonitor BondMIIMonitor
	ARPMonitor BondArpMonitor
}

// BondMIIMonitor : MII link monitoring parameters (see devmodel.proto for description).
type BondMIIMonitor struct {
	Enabled   bool
	Interval  uint32
	UpDelay   uint32
	DownDelay uint32
}

// BondArpMonitor : ARP-based link monitoring parameters (see devmodel.proto for description).
type BondArpMonitor struct {
	Enabled   bool
	Interval  uint32
	IPTargets []net.IP
}

// NetworkPortConfig has the configuration and some status like TestResults
// for one IfName.
// XXX odd to have ParseErrors and/or TestResults here but we don't have
// a corresponding Status struct.
// Note that if fields are added the MostlyEqual function needs to be updated.
type NetworkPortConfig struct {
	IfName       string
	Phylabel     string // Physical name set by controller/model
	Logicallabel string // SystemAdapter's name which is logical label in phyio
	Alias        string // From SystemAdapter's alias
	// NetworkUUID - UUID of the Network Object configured for the port.
	NetworkUUID uuid.UUID
	IsMgmt      bool  // Used to talk to controller
	IsL3Port    bool  // True if port is applicable to operate on the network layer
	Cost        uint8 // Zero is free
	DhcpConfig
	ProxyConfig
	L2LinkConfig
	WirelessCfg WirelessConfig
	// TestResults - Errors from parsing plus success/failure from testing
	TestResults
}

type NetworkPortStatus struct {
	IfName         string
	Phylabel       string // Physical name set by controller/model
	Logicallabel   string
	Alias          string // From SystemAdapter's alias
	IsMgmt         bool   // Used to talk to controller
	IsL3Port       bool   // True if port is applicable to operate on the network layer
	Cost           uint8
	Dhcp           DhcpType
	Type           NetworkType // IPv4 or IPv6 or Dual stack
	Subnet         net.IPNet
	NtpServer      net.IP // This comes from network instance configuration
	DomainName     string
	DNSServers     []net.IP // If not set we use Gateway as DNS server
	NtpServers     []net.IP // This comes from DHCP done on uplink port
	AddrInfoList   []AddrInfo
	Up             bool
	MacAddr        string
	DefaultRouters []net.IP
	WirelessCfg    WirelessConfig
	WirelessStatus WirelessStatus
	ProxyConfig
	L2LinkConfig
	// TestResults provides recording of failure and success
	TestResults
}

// HasIPAndDNS - Check if the given port has a valid unicast IP along with DNS & Gateway.
func (port NetworkPortStatus) HasIPAndDNS() bool {
	foundUnicast := false

	for _, addr := range port.AddrInfoList {
		if !addr.Addr.IsLinkLocalUnicast() {
			foundUnicast = true
		}
	}

	if foundUnicast && len(port.DefaultRouters) > 0 && len(port.DNSServers) > 0 {
		return true
	}

	return false
}

type AddrInfo struct {
	Addr             net.IP
	Geo              ipinfo.IPInfo
	LastGeoTimestamp time.Time
}

// DeviceNetworkStatus is published to microservices which needs to know about ports and IP addresses
// It is published under the key "global" only
type DeviceNetworkStatus struct {
	DPCKey       string                  // For logs/testing
	Version      DevicePortConfigVersion // From DevicePortConfig
	Testing      bool                    // Ignore since it is not yet verified
	State        DPCState                // Details about testing state
	CurrentIndex int                     // For logs
	RadioSilence RadioSilence            // The actual state of the radio-silence mode
	Ports        []NetworkPortStatus
}

// Key is used for pubsub
func (status DeviceNetworkStatus) Key() string {
	return "global"
}

// LogCreate :
func (status DeviceNetworkStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DeviceNetworkStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("testing-bool", status.Testing).
		AddField("ports-int64", len(status.Ports)).
		AddField("state", status.State.String()).
		AddField("current-index-int64", status.CurrentIndex).
		Noticef("DeviceNetworkStatus create")
	for _, p := range status.Ports {
		// XXX different logobject for a particular port?
		logObject.CloneAndAddField("ifname", p.IfName).
			AddField("last-error", p.LastError).
			AddField("last-succeeded", p.LastSucceeded).
			AddField("last-failed", p.LastFailed).
			Noticef("DeviceNetworkStatus port create")
	}
}

// LogModify :
func (status DeviceNetworkStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DeviceNetworkStatusLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(DeviceNetworkStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DeviceNetworkStatus type")
	}
	if oldStatus.Testing != status.Testing ||
		oldStatus.State != status.State ||
		oldStatus.CurrentIndex != status.CurrentIndex ||
		len(oldStatus.Ports) != len(status.Ports) {

		logData := logObject.CloneAndAddField("testing-bool", status.Testing).
			AddField("ports-int64", len(status.Ports)).
			AddField("state", status.State.String()).
			AddField("current-index-int64", status.CurrentIndex).
			AddField("old-testing-bool", oldStatus.Testing).
			AddField("old-ports-int64", len(oldStatus.Ports)).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-current-index-int64", oldStatus.CurrentIndex)

		if oldStatus.State == status.State && oldStatus.CurrentIndex == status.CurrentIndex &&
			len(oldStatus.Ports) == len(status.Ports) {
			// if only testing state changed, reduce log level
			logData.Function("DeviceNetworkStatus modify")
		} else {
			logData.Notice("DeviceNetworkStatus modify")
		}
	}
	// XXX which fields to compare/log?
	for i, p := range status.Ports {
		if len(oldStatus.Ports) <= i {
			continue
		}
		op := oldStatus.Ports[i]
		// XXX different logobject for a particular port?
		if p.HasError() != op.HasError() ||
			p.LastFailed != op.LastFailed ||
			p.LastSucceeded != op.LastSucceeded ||
			p.LastError != op.LastError {
			logData := logObject.CloneAndAddField("ifname", p.IfName).
				AddField("last-error", p.LastError).
				AddField("last-succeeded", p.LastSucceeded).
				AddField("last-failed", p.LastFailed).
				AddField("old-last-error", op.LastError).
				AddField("old-last-succeeded", op.LastSucceeded).
				AddField("old-last-failed", op.LastFailed)
			if p.HasError() == op.HasError() &&
				p.LastFailed == op.LastFailed &&
				p.LastError == op.LastError &&
				p.LastSucceeded.After(op.LastFailed) &&
				op.LastSucceeded.After(op.LastFailed) {
				// if we have success again, reduce log level
				logData.Function("DeviceNetworkStatus port modify")
			} else {
				logData.Notice("DeviceNetworkStatus port modify")
			}
		}
	}
}

// LogDelete :
func (status DeviceNetworkStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DeviceNetworkStatusLogType, "",
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("testing-bool", status.Testing).
		AddField("ports-int64", len(status.Ports)).
		AddField("state", status.State.String()).
		Noticef("DeviceNetworkStatus instance status delete")
	for _, p := range status.Ports {
		// XXX different logobject for a particular port?
		logObject.CloneAndAddField("ifname", p.IfName).
			AddField("last-error", p.LastError).
			AddField("last-succeeded", p.LastSucceeded).
			AddField("last-failed", p.LastFailed).
			Noticef("DeviceNetworkStatus port delete")
	}

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status DeviceNetworkStatus) LogKey() string {
	return string(base.DeviceNetworkStatusLogType) + "-" + status.Key()
}

// MostlyEqual compares two DeviceNetworkStatus but skips things the test status/results aspects, including State and Testing.
// We compare the Ports in array order.
func (status DeviceNetworkStatus) MostlyEqual(status2 DeviceNetworkStatus) bool {

	if len(status.Ports) != len(status2.Ports) {
		return false
	}
	for i, p1 := range status.Ports {
		p2 := status2.Ports[i]
		if p1.IfName != p2.IfName ||
			p1.Phylabel != p2.Phylabel ||
			p1.Logicallabel != p2.Logicallabel ||
			p1.Alias != p2.Alias ||
			p1.IsMgmt != p2.IsMgmt ||
			p1.Cost != p2.Cost {
			return false
		}
		if p1.Dhcp != p2.Dhcp ||
			!EqualSubnet(p1.Subnet, p2.Subnet) ||
			!p1.NtpServer.Equal(p2.NtpServer) ||
			p1.DomainName != p2.DomainName {
			return false
		}
		if len(p1.DNSServers) != len(p2.DNSServers) {
			return false
		}
		for i := range p1.DNSServers {
			if !p1.DNSServers[i].Equal(p2.DNSServers[i]) {
				return false
			}
		}
		if len(p1.AddrInfoList) != len(p2.AddrInfoList) {
			return false
		}
		for i := range p1.AddrInfoList {
			if !p1.AddrInfoList[i].Addr.Equal(p2.AddrInfoList[i].Addr) {
				return false
			}
		}
		if p1.Up != p2.Up ||
			p1.MacAddr != p2.MacAddr {
			return false
		}
		if len(p1.DefaultRouters) != len(p2.DefaultRouters) {
			return false
		}
		for i := range p1.DefaultRouters {
			if !p1.DefaultRouters[i].Equal(p2.DefaultRouters[i]) {
				return false
			}
		}

		if !reflect.DeepEqual(p1.ProxyConfig, p2.ProxyConfig) ||
			!reflect.DeepEqual(p1.WirelessStatus, p2.WirelessStatus) {
			return false
		}
	}
	if !reflect.DeepEqual(status.RadioSilence, status2.RadioSilence) {
		return false
	}
	return true
}

// MostlyEqualStatus compares two DeviceNetworkStatus but skips things that are
// unimportant like just an increase in the success timestamp, but detects
// when a port changes to/from a failure.
func (status *DeviceNetworkStatus) MostlyEqualStatus(status2 DeviceNetworkStatus) bool {

	if !status.MostlyEqual(status2) {
		return false
	}
	if status.State != status2.State || status.Testing != status2.Testing ||
		status.CurrentIndex != status2.CurrentIndex {
		return false
	}
	if len(status.Ports) != len(status2.Ports) {
		return false
	}
	for i, p1 := range status.Ports {
		p2 := status2.Ports[i]
		// Did we change to/from failure?
		if p1.HasError() != p2.HasError() {
			return false
		}
	}
	return true
}

// EqualSubnet compares two subnets; silently assumes contiguous masks
func EqualSubnet(subnet1, subnet2 net.IPNet) bool {
	if !subnet1.IP.Equal(subnet2.IP) {
		return false
	}
	len1, _ := subnet1.Mask.Size()
	len2, _ := subnet2.Mask.Size()
	return len1 == len2
}

// GetPortByIfName - Get Port Status for port with given Ifname
func (status *DeviceNetworkStatus) GetPortByIfName(
	ifname string) *NetworkPortStatus {
	for i := range status.Ports {
		if status.Ports[i].IfName == ifname {
			return &status.Ports[i]
		}
	}
	return nil
}

// GetPortsByLogicallabel - Get Port Status for all ports matching the given label.
func (status *DeviceNetworkStatus) GetPortsByLogicallabel(
	label string) (ports []*NetworkPortStatus) {
	// Check for shared labels first.
	switch label {
	case UplinkLabel:
		for i := range status.Ports {
			if status.Version >= DPCIsMgmt && !status.Ports[i].IsMgmt {
				continue
			}
			ports = append(ports, &status.Ports[i])
		}
		return ports
	case FreeUplinkLabel:
		for i := range status.Ports {
			if status.Version >= DPCIsMgmt && !status.Ports[i].IsMgmt {
				continue
			}
			if status.Ports[i].Cost > 0 {
				continue
			}
			ports = append(ports, &status.Ports[i])
		}
		return ports
	}
	// Label is referencing single port.
	for i := range status.Ports {
		if status.Ports[i].Logicallabel == label {
			ports = append(ports, &status.Ports[i])
			return ports
		}
	}
	return nil
}

// HasErrors - DeviceNetworkStatus has errors on any of it's ports?
func (status DeviceNetworkStatus) HasErrors() bool {
	for _, port := range status.Ports {
		if port.HasError() {
			return true
		}
	}
	return false
}

// GetPortAddrInfo returns address info for a given interface and its IP address.
func (status DeviceNetworkStatus) GetPortAddrInfo(ifname string, addr net.IP) *AddrInfo {
	portStatus := status.GetPortByIfName(ifname)
	if portStatus == nil {
		return nil
	}
	for i := range portStatus.AddrInfoList {
		if portStatus.AddrInfoList[i].Addr.Equal(addr) {
			return &portStatus.AddrInfoList[i]
		}
	}
	return nil
}

func rotate(arr []string, amount int) []string {
	if len(arr) == 0 {
		return []string{}
	}
	amount = amount % len(arr)
	return append(append([]string{}, arr[amount:]...), arr[:amount]...)
}

// GetMgmtPortsSortedCost returns all management ports sorted by port cost
// rotation causes rotation/round-robin within each cost
func GetMgmtPortsSortedCost(globalStatus DeviceNetworkStatus, rotation int) []string {
	return getPortsSortedCostImpl(globalStatus, rotation,
		PortCostMax, true, false)
}

// GetAllPortsSortedCost returns all ports (management and app shared) sorted by port cost.
// Rotation causes rotation/round-robin within each cost.
func GetAllPortsSortedCost(globalStatus DeviceNetworkStatus, rotation int) []string {
	return getPortsSortedCostImpl(globalStatus, rotation,
		PortCostMax, false, false)
}

// GetMgmtPortsSortedCostWithoutFailed returns all management ports sorted by
// port cost ignoring ports with failures.
// rotation causes rotation/round-robin within each cost
func GetMgmtPortsSortedCostWithoutFailed(globalStatus DeviceNetworkStatus, rotation int) []string {
	return getPortsSortedCostImpl(globalStatus, rotation,
		PortCostMax, true, true)
}

// getPortsSortedCostImpl returns all ports sorted by port cost
// up to and including the maxCost
func getPortsSortedCostImpl(globalStatus DeviceNetworkStatus, rotation int, maxCost uint8,
	mgmtOnly, dropFailed bool) []string {
	ifnameList := []string{}
	costList := getPortCostListImpl(globalStatus, maxCost)
	for _, cost := range costList {
		ifnameList = append(ifnameList,
			getPortsImpl(globalStatus, rotation, true, cost, mgmtOnly, dropFailed)...)
	}
	return ifnameList
}

// GetMgmtPortsAny returns all management ports
func GetMgmtPortsAny(globalStatus DeviceNetworkStatus, rotation int) []string {
	return getPortsImpl(globalStatus, rotation, false, 0, true, false)
}

// GetMgmtPortsByCost returns all management ports with a given port cost
func GetMgmtPortsByCost(globalStatus DeviceNetworkStatus, cost uint8) []string {
	return getPortsImpl(globalStatus, 0, true, cost, true, false)
}

// Returns the IfNames.
func getPortsImpl(globalStatus DeviceNetworkStatus, rotation int,
	matchCost bool, cost uint8, mgmtOnly, dropFailed bool) []string {

	var ifnameList []string
	for _, us := range globalStatus.Ports {
		if matchCost && us.Cost != cost {
			continue
		}
		if mgmtOnly && globalStatus.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		if dropFailed && us.HasError() {
			continue
		}
		ifnameList = append(ifnameList, us.IfName)
	}
	return rotate(ifnameList, rotation)
}

// GetPortCostList returns the sorted list of port costs
// with cost zero entries first.
func GetPortCostList(globalStatus DeviceNetworkStatus) []uint8 {

	return getPortCostListImpl(globalStatus, PortCostMax)
}

// getPortCostListImpl returns the sorted port costs up to and including the max
func getPortCostListImpl(globalStatus DeviceNetworkStatus, maxCost uint8) []uint8 {
	var costList []uint8
	for _, us := range globalStatus.Ports {
		costList = append(costList, us.Cost)
	}
	if len(costList) == 0 {
		return []uint8{}
	}
	// Need sort -u so separately we remove the duplicates
	sort.Slice(costList,
		func(i, j int) bool { return costList[i] < costList[j] })
	unique := make([]uint8, 0, len(costList))
	i := 0
	unique = append(unique, costList[0])
	for _, cost := range costList {
		if cost != unique[i] && cost <= maxCost {
			unique = append(unique, cost)
			i++
		}
	}
	return unique
}

// CountLocalAddrAnyNoLinkLocal returns the number of local IP addresses for
// all the management ports (for all port costs) excluding link-local addresses
func CountLocalAddrAnyNoLinkLocal(globalStatus DeviceNetworkStatus) int {

	// Count the number of addresses which apply
	addrs, _ := getLocalAddrListImpl(globalStatus, "", PortCostMax,
		false, 0)
	return len(addrs)
}

// CountLocalAddrAnyNoLinkLocalIf return number of local IP addresses for
// the interface excluding link-local addresses
func CountLocalAddrAnyNoLinkLocalIf(globalStatus DeviceNetworkStatus,
	ifname string) (int, error) {

	if ifname == "" {
		return 0, fmt.Errorf("ifname not specified")
	}
	// Count the number of addresses which apply
	addrs, err := getLocalAddrListImpl(globalStatus, ifname,
		PortCostMax, false, 0)
	return len(addrs), err
}

// CountLocalAddrNoLinkLocalWithCost is like CountLocalAddrAnyNoLinkLocal but
// in addition allows the caller to specify the cost between
// PortCostMin (0) and PortCostMax(255).
// If 0 is specified it only considers cost 0 ports.
// if 255 is specified it considers all the ports.
func CountLocalAddrNoLinkLocalWithCost(globalStatus DeviceNetworkStatus,
	maxCost uint8) int {

	// Count the number of addresses which apply
	addrs, _ := getLocalAddrListImpl(globalStatus, "", maxCost,
		false, 0)
	return len(addrs)
}

// CountLocalIPv4AddrAnyNoLinkLocal is like CountLocalAddrAnyNoLinkLocal but
// only IPv4 addresses are counted
func CountLocalIPv4AddrAnyNoLinkLocal(globalStatus DeviceNetworkStatus) int {

	// Count the number of addresses which apply
	addrs, _ := getLocalAddrListImpl(globalStatus, "", PortCostMax,
		false, 4)
	return len(addrs)
}

// CountDNSServers returns the number of DNS servers; for ifname if set
func CountDNSServers(globalStatus DeviceNetworkStatus, ifname string) int {

	count := 0
	for _, us := range globalStatus.Ports {
		if us.IfName != ifname && ifname != "" {
			continue
		}
		count += len(us.DNSServers)
	}
	return count
}

// GetDNSServers returns all, or the ones on one interface if ifname is set
func GetDNSServers(globalStatus DeviceNetworkStatus, ifname string) []net.IP {

	var servers []net.IP
	for _, us := range globalStatus.Ports {
		if !us.IsMgmt && ifname == "" {
			continue
		}
		if ifname != "" && ifname != us.IfName {
			continue
		}
		for _, server := range us.DNSServers {
			servers = append(servers, server)
		}
	}
	return servers
}

// GetNTPServers returns all, or the ones on one interface if ifname is set
func GetNTPServers(globalStatus DeviceNetworkStatus, ifname string) []net.IP {

	var servers []net.IP
	for _, us := range globalStatus.Ports {
		if ifname != "" && ifname != us.IfName {
			continue
		}
		servers = append(servers, us.NtpServers...)
		// Add statically configured NTP server as well, but avoid duplicates.
		if us.NtpServer != nil {
			var found bool
			for _, server := range servers {
				if server.Equal(us.NtpServer) {
					found = true
					break
				}
			}
			if !found {
				servers = append(servers, us.NtpServer)
			}
		}
	}
	return servers
}

// CountLocalIPv4AddrAnyNoLinkLocalIf is like CountLocalAddrAnyNoLinkLocalIf but
// only IPv4 addresses are counted
func CountLocalIPv4AddrAnyNoLinkLocalIf(globalStatus DeviceNetworkStatus,
	ifname string) (int, error) {

	if ifname == "" {
		return 0, fmt.Errorf("ifname not specified")
	}
	// Count the number of addresses which apply
	addrs, err := getLocalAddrListImpl(globalStatus, ifname,
		PortCostMax, false, 4)
	return len(addrs), err
}

// GetLocalAddrAnyNoLinkLocal is used to pick one address from:
// - ifname if set.
// - otherwise from all of the management ports
// Excludes link-local addresses.
// The addresses are sorted in cost order thus as the caller starts with
// pickNum zero and increases it will use the ports in cost order.
func GetLocalAddrAnyNoLinkLocal(globalStatus DeviceNetworkStatus, pickNum int,
	ifname string) (net.IP, error) {

	includeLinkLocal := false
	return getLocalAddrImpl(globalStatus, pickNum, ifname,
		PortCostMax, includeLinkLocal, 0)
}

// GetLocalAddrNoLinkLocalWithCost is like GetLocalAddrNoLinkLocal but
// in addition allows the caller to specify the cost between
// PortCostMin (0) and PortCostMax(255).
// If 0 is specified it only considers local addresses on cost zero ports;
// if 255 is specified it considers all the local addresses.
func GetLocalAddrNoLinkLocalWithCost(globalStatus DeviceNetworkStatus, pickNum int,
	ifname string, maxCost uint8) (net.IP, error) {

	includeLinkLocal := false
	return getLocalAddrImpl(globalStatus, pickNum, ifname,
		maxCost, includeLinkLocal, 0)
}

// getLocalAddrImpl returns an IP address based on interfaces sorted in
// cost order. If ifname is set, the addresses are from that
// interface. Otherwise from all management interfaces up to and including maxCost.
// af can be set to 0 (any), 4, IPv4), or 6 (IPv6) to select the family.
func getLocalAddrImpl(globalStatus DeviceNetworkStatus, pickNum int,
	ifname string, maxCost uint8, includeLinkLocal bool,
	af uint) (net.IP, error) {

	addrs, err := getLocalAddrListImpl(globalStatus, ifname,
		maxCost, includeLinkLocal, af)
	if err != nil {
		return net.IP{}, err
	}
	numAddrs := len(addrs)
	if numAddrs == 0 {
		return net.IP{}, fmt.Errorf("no addresses")
	}
	pickNum = pickNum % numAddrs
	return addrs[pickNum], nil
}

// getLocalAddrListImpl returns a list IP addresses based on interfaces sorted
// in cost order. If ifname is set, the addresses are from that
// interface. Otherwise from all management interfaces up to and including maxCost
// af can be set to 0 (any), 4, IPv4), or 6 (IPv6) to select a subset.
func getLocalAddrListImpl(globalStatus DeviceNetworkStatus,
	ifname string, maxCost uint8, includeLinkLocal bool,
	af uint) ([]net.IP, error) {

	var ifnameList []string
	var ignoreErrors bool
	if ifname == "" {
		// Get interfaces in cost order
		ifnameList = getPortsSortedCostImpl(globalStatus, 0,
			maxCost, true, false)
		// If we are looking across all interfaces, then We ignore errors
		// since we get them if there are no addresses on a ports
		ignoreErrors = true
	} else {
		us := GetPort(globalStatus, ifname)
		if us == nil {
			return []net.IP{}, fmt.Errorf("Unknown interface %s",
				ifname)
		}
		if us.Cost > maxCost {
			return []net.IP{}, fmt.Errorf("Interface %s cost %d exceeds maxCost %d",
				ifname, us.Cost, maxCost)
		}
		ifnameList = []string{ifname}
	}
	addrs := []net.IP{}
	for _, ifname := range ifnameList {
		ifaddrs, err := getLocalAddrIf(globalStatus, ifname,
			includeLinkLocal, af)
		if !ignoreErrors && err != nil {
			return addrs, err
		}
		addrs = append(addrs, ifaddrs...)
	}
	return addrs, nil
}

// Return the list of ifnames in DNC which exist in the kernel
func GetExistingInterfaceList(log *base.LogObject, globalStatus DeviceNetworkStatus) []string {

	var ifs []string
	for _, us := range globalStatus.Ports {

		link, _ := netlink.LinkByName(us.IfName)
		if link == nil {
			log.Warnf("GetExistingInterfaceList: if %s not found\n",
				us.IfName)
			continue
		}
		ifs = append(ifs, us.IfName)
	}
	return ifs
}

// Check if an interface name is a port owned by nim
func IsPort(globalStatus DeviceNetworkStatus, ifname string) bool {
	for _, us := range globalStatus.Ports {
		if us.IfName != ifname {
			continue
		}
		return true
	}
	return false
}

// IsL3Port checks if an interface name belongs to a port with SystemAdapter attached.
func IsL3Port(globalStatus DeviceNetworkStatus, ifname string) bool {
	for _, us := range globalStatus.Ports {
		if us.IfName != ifname {
			continue
		}
		return us.IsL3Port
	}
	return false
}

// Check if a physical label or ifname is a management port
func IsMgmtPort(globalStatus DeviceNetworkStatus, ifname string) bool {
	for _, us := range globalStatus.Ports {
		if us.IfName != ifname {
			continue
		}
		if globalStatus.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		return true
	}
	return false
}

// GetPortCost returns the port cost
// Returns 0 if the ifname does not exist.
func GetPortCost(globalStatus DeviceNetworkStatus, ifname string) uint8 {
	for _, us := range globalStatus.Ports {
		if us.IfName != ifname {
			continue
		}
		return us.Cost
	}
	return 0
}

func GetPort(globalStatus DeviceNetworkStatus, ifname string) *NetworkPortStatus {
	for _, us := range globalStatus.Ports {
		if us.IfName != ifname {
			continue
		}
		if globalStatus.Version < DPCIsMgmt {
			us.IsMgmt = true
		}
		return &us
	}
	return nil
}

// Given an address tell me its IfName
func GetMgmtPortFromAddr(globalStatus DeviceNetworkStatus, addr net.IP) string {
	for _, us := range globalStatus.Ports {
		if globalStatus.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		for _, i := range us.AddrInfoList {
			if i.Addr.Equal(addr) {
				return us.IfName
			}
		}
	}
	return ""
}

// GetLocalAddrList returns all IP addresses on the ifName except
// the link local addresses.
func GetLocalAddrList(globalStatus DeviceNetworkStatus,
	ifname string) ([]net.IP, error) {

	if ifname == "" {
		return []net.IP{}, fmt.Errorf("ifname not specified")
	}
	return getLocalAddrIf(globalStatus, ifname, false, 0)
}

// getLocalAddrIf returns all of the IP addresses for the ifname.
// includeLinkLocal and af can be used to exclude addresses.
func getLocalAddrIf(globalStatus DeviceNetworkStatus, ifname string,
	includeLinkLocal bool, af uint) ([]net.IP, error) {

	var addrs []net.IP
	for _, us := range globalStatus.Ports {
		if us.IfName != ifname {
			continue
		}
		for _, i := range us.AddrInfoList {
			if !includeLinkLocal && i.Addr.IsLinkLocalUnicast() {
				continue
			}
			if i.Addr == nil {
				continue
			}
			switch af {
			case 0:
				// Accept any
			case 4:
				if i.Addr.To4() == nil {
					continue
				}
			case 6:
				if i.Addr.To4() != nil {
					continue
				}
			}
			addrs = append(addrs, i.Addr)
		}
	}
	if len(addrs) != 0 {
		return addrs, nil
	} else {
		return []net.IP{}, &IPAddrNotAvail{IfName: ifname}
	}
}

// ReportLogicallabels returns a list of Logicallabels we will report in info and metrics
func ReportLogicallabels(deviceNetworkStatus DeviceNetworkStatus) []string {

	var names []string
	for _, port := range deviceNetworkStatus.Ports {
		names = append(names, port.Logicallabel)
	}
	return names
}

// UpdatePortStatusFromIntfStatusMap - Set TestResults for ports in DeviceNetworkStatus to
// those from intfStatusMap. If a port is not found in intfStatusMap, it means
// the port was not tested, so we retain the original TestResults for the port.
func (status *DeviceNetworkStatus) UpdatePortStatusFromIntfStatusMap(
	intfStatusMap IntfStatusMap) {
	for indx := range status.Ports {
		portPtr := &status.Ports[indx]
		tr, ok := intfStatusMap.StatusMap[portPtr.IfName]
		if ok {
			portPtr.TestResults.Update(tr)
		}
		// Else - Port not tested hence no change
	}
}

// LogicallabelToIfName looks up a port Logical label to find an existing IfName
// If not found, return the logicallabel argument string
func LogicallabelToIfName(deviceNetworkStatus *DeviceNetworkStatus,
	logicallabel string) string {

	for _, p := range deviceNetworkStatus.Ports {
		if p.Logicallabel == logicallabel {
			return p.IfName
		}
	}
	return logicallabel
}

// IsAnyPortInPciBack
//
//	Checks if any of the Ports are part of IO bundles which are in PCIback.
//	If true, it also returns the ifName ( NOT bundle name )
//	Also returns whether it is currently used by an application by
//	returning a UUID. If the UUID is zero it is in PCIback but available.
//	Use filterUnassigned to filter out unassigned ports.
func (config *DevicePortConfig) IsAnyPortInPciBack(
	log *base.LogObject, aa *AssignableAdapters, filterUnassigned bool) (bool, string, uuid.UUID) {
	if aa == nil {
		log.Functionf("IsAnyPortInPciBack: nil aa")
		return false, "", uuid.UUID{}
	}
	log.Functionf("IsAnyPortInPciBack: aa init %t, %d bundles, %d ports",
		aa.Initialized, len(aa.IoBundleList), len(config.Ports))
	for _, port := range config.Ports {
		ioBundle := aa.LookupIoBundleIfName(port.IfName)
		if ioBundle == nil {
			// It is not guaranteed that all Ports are part of Assignable Adapters
			// If not found, the adapter is not capable of being assigned at
			// PCI level. So it cannot be in PCI back.
			log.Functionf("IsAnyPortInPciBack: ifname %s not found",
				port.IfName)
			continue
		}
		if ioBundle.IsPCIBack && (!filterUnassigned || ioBundle.UsedByUUID != nilUUID) {
			return true, port.IfName, ioBundle.UsedByUUID
		}
	}
	return false, "", uuid.UUID{}
}

type MapServerType uint8

const (
	MST_INVALID MapServerType = iota
	MST_MAPSERVER
	MST_SUPPORT_SERVER
	MST_LAST = 255
)

type DhcpType uint8

const (
	DT_NOOP       DhcpType = iota
	DT_STATIC              // Device static config
	DT_NONE                // App passthrough e.g., to a bridge
	DT_Deprecated          // XXX to match .proto value
	DT_CLIENT              // Device client on external port
)

type UnderlayNetworkConfig struct {
	Name       string           // From proto message
	AppMacAddr net.HardwareAddr // If set use it for vif
	AppIPAddr  net.IP           // If set use DHCP to assign to app
	IntfOrder  int32            // XXX need to get from API

	// XXX Shouldn't we use ErrorAndTime here
	// Error
	//	If there is a parsing error and this uLNetwork config cannot be
	//	processed, set the error here. This allows the error to be propagated
	//  back to zedcloud
	//	If this is non-empty ( != ""), the UL network Config should not be
	// 	processed further. It Should just	be flagged to be in error state
	//  back to the cloud.
	Error        string
	Network      uuid.UUID // Points to a NetworkInstance.
	ACLs         []ACE
	AccessVlanID uint32
	IfIdx        uint32 // If we have multiple interfaces on that network, we will increase the index
}

type UnderlayNetworkStatus struct {
	UnderlayNetworkConfig
	ACLs int // drop ACLs field from UnderlayNetworkConfig
	VifInfo
	BridgeMac         net.HardwareAddr
	BridgeIPAddr      net.IP   // The address for DNS/DHCP service in zedrouter
	AllocatedIPv4Addr string   // Assigned to domU
	AllocatedIPv6List []string // IPv6 addresses assigned to domU
	IPv4Assigned      bool     // Set to true once DHCP has assigned it to domU
	IPAddrMisMatch    bool
	HostName          string
	ACLDependList     []ACLDepend
}

// ACLDepend is used to track an external interface/port and optional IP addresses
// on that interface which are encoded in the rules. Does not include the vif(s)
// for the AppNetworkStatus itself.
type ACLDepend struct {
	Ifname string
	IPAddr net.IP
}

// ULNetworkACLs - Underlay Network ACLRules
// moved out from UnderlayNetowrkStatus, and now ACLRules are kept in zedrouterContext 2D-map NLaclMap
type ULNetworkACLs struct {
	ACLRules IPTablesRuleList
}

type NetworkType uint8

const (
	NT_NOOP NetworkType = 0
	NT_IPV4             = 4
	NT_IPV6             = 6

	// EVE has been running with Dual stack DHCP behavior with both IPv4 & IPv6 specific networks.
	// There can be users who are currently benefitting from this behavior.
	// It makes sense to introduce two new types IPv4_ONLY & IPv6_ONLY and allow
	// the same family selection from UI for the use cases where only one of the IP families
	// is required on management/app-shared adapters.

	// NtIpv4Only : IPv4 addresses only
	NtIpv4Only = 5
	// NtIpv6Only : IPv6 addresses only
	NtIpv6Only = 7
	// NtDualStack : Run with dual stack
	NtDualStack = 8
)

// Extracted from the protobuf NetworkConfig. Used by parseSystemAdapter
// XXX replace by inline once we have device model
type NetworkXObjectConfig struct {
	UUID            uuid.UUID
	Type            NetworkType
	Dhcp            DhcpType // If DT_STATIC or DT_CLIENT use below
	Subnet          net.IPNet
	Gateway         net.IP
	DomainName      string
	NtpServer       net.IP
	DnsServers      []net.IP // If not set we use Gateway as DNS server
	DhcpRange       IpRange
	DnsNameToIPList []DnsNameToIP // Used for DNS and ACL ipset
	Proxy           *ProxyConfig
	WirelessCfg     WirelessConfig
	// Any errors from the parser
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

type IpRange struct {
	Start net.IP
	End   net.IP
}

// Contains used to evaluate whether an IP address
// is within the range
func (ipRange IpRange) Contains(ipAddr net.IP) bool {
	if bytes.Compare(ipAddr, ipRange.Start) >= 0 &&
		bytes.Compare(ipAddr, ipRange.End) <= 0 {
		return true
	}
	return false
}

// Size returns addresses count inside IpRange
func (ipRange IpRange) Size() uint32 {
	//TBD:XXX, IPv6 handling
	ip1v4 := ipRange.Start.To4()
	ip2v4 := ipRange.End.To4()
	if ip1v4 == nil || ip2v4 == nil {
		return 0
	}
	ip1Int := binary.BigEndian.Uint32(ip1v4)
	ip2Int := binary.BigEndian.Uint32(ip2v4)
	if ip1Int > ip2Int {
		return ip1Int - ip2Int
	}
	return ip2Int - ip1Int
}

func (config NetworkXObjectConfig) Key() string {
	return config.UUID.String()
}

// LogCreate :
func (config NetworkXObjectConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkXObjectConfigLogType, "",
		config.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("NetworkXObject config create")
}

// LogModify :
func (config NetworkXObjectConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkXObjectConfigLogType, "",
		config.UUID, config.LogKey())

	oldConfig, ok := old.(NetworkXObjectConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkXObjectConfig type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
		Noticef("NetworkXObject config modify")
}

// LogDelete :
func (config NetworkXObjectConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkXObjectConfigLogType, "",
		config.UUID, config.LogKey())
	logObject.Noticef("NetworkXObject config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config NetworkXObjectConfig) LogKey() string {
	return string(base.NetworkXObjectConfigLogType) + "-" + config.Key()
}

// AssignedAddrs :
type AssignedAddrs struct {
	IPv4Addr  net.IP
	IPv6Addrs []net.IP
}

type NetworkInstanceInfo struct {
	BridgeNum     int
	BridgeName    string // bn<N>
	BridgeIPAddr  net.IP
	BridgeMac     string
	BridgeIfindex int

	// interface names for the Logicallabel
	IfNameList []string // Recorded at time of activate

	// Collection of address assignments; from MAC address to IP address
	IPAssignments map[string]AssignedAddrs

	// Union of all ipsets fed to dnsmasq for the linux bridge
	BridgeIPSets []string

	// Set of vifs on this bridge
	Vifs []VifNameMac

	// Vif metric map. This should have a union of currently existing
	// vifs and previously deleted vifs.
	// XXX When a vif is removed from bridge (app instance delete case),
	// device might start reporting smaller statistic values. To avoid this
	// from happening, we keep a list of all vifs that were ever connected
	// to this bridge and their statistics.
	// We add statistics from all vifs while reporting to cloud.
	VifMetricMap map[string]NetworkMetric

	// Maintain a map of all access vlan ids to their counts, used by apps
	// connected to this network instance.
	VlanMap map[uint32]uint32
	// Counts the number of trunk ports attached to this network instance
	NumTrunkPorts uint32

	// IP address on which the meta-data server listens
	MetaDataServerIP net.IP
}

func (instanceInfo *NetworkInstanceInfo) IsVifInBridge(
	vifName string) bool {
	for _, vif := range instanceInfo.Vifs {
		if vif.Name == vifName {
			return true
		}
	}
	return false
}

func (instanceInfo *NetworkInstanceInfo) RemoveVif(log *base.LogObject,
	vifName string) {
	log.Functionf("RemoveVif(%s, %s)", instanceInfo.BridgeName, vifName)

	found := false
	var vifs []VifNameMac
	for _, vif := range instanceInfo.Vifs {
		if vif.Name != vifName {
			vifs = append(vifs, vif)
		} else {
			found = true
		}
	}
	if !found {
		log.Errorf("RemoveVif(%x, %x) not found",
			instanceInfo.BridgeName, vifName)
	}
	instanceInfo.Vifs = vifs
}

func (instanceInfo *NetworkInstanceInfo) AddVif(log *base.LogObject,
	vifName string, appMac string, appID uuid.UUID) {

	log.Functionf("AddVif(%s, %s, %s, %s)",
		instanceInfo.BridgeName, vifName, appMac, appID.String())
	// XXX Should we just overwrite it? There is a lookup function
	//	anyways if the caller wants "check and add" semantics
	if instanceInfo.IsVifInBridge(vifName) {
		log.Errorf("AddVif(%s, %s) exists",
			instanceInfo.BridgeName, vifName)
		return
	}
	info := VifNameMac{
		Name:    vifName,
		MacAddr: appMac,
		AppID:   appID,
	}
	instanceInfo.Vifs = append(instanceInfo.Vifs, info)
}

type NetworkInstanceMetrics struct {
	UUIDandVersion UUIDandVersion
	DisplayName    string
	Type           NetworkInstanceType
	NetworkMetrics NetworkMetrics
	ProbeMetrics   ProbeMetrics
	VlanMetrics    VlanMetrics
}

// VlanMetrics :
type VlanMetrics struct {
	NumTrunkPorts uint32
	VlanCounts    map[uint32]uint32
}

// ProbeMetrics - NI probe metrics
type ProbeMetrics struct {
	SelectedUplinkIntf string             // the uplink interface that probing picked
	RemoteEndpoints    []string           // remote IP/URL addresses used for probing
	LocalPingIntvl     uint32             // local ping interval in seconds
	RemotePingIntvl    uint32             // remote probing interval in seconds
	UplinkCount        uint32             // number of possible uplink interfaces
	IntfProbeStats     []ProbeIntfMetrics // per dom0 intf uplink probing metrics
}

// ProbeIntfMetrics - per dom0 network uplink interface probing
type ProbeIntfMetrics struct {
	IntfName        string   // dom0 uplink interface name
	NexthopIPs      []net.IP // interface local next-hop address(es) used for probing
	NexthopUP       bool     // Is local next-hop in UP status
	RemoteUP        bool     // Is remote endpoint in UP status
	NexthopUPCnt    uint32   // local ping UP count
	NexthopDownCnt  uint32   // local ping DOWN count
	RemoteUPCnt     uint32   // remote probe UP count
	RemoteDownCnt   uint32   // remote probe DOWN count
	LatencyToRemote uint32   // probe latency to remote in msec
}

func (metrics NetworkInstanceMetrics) Key() string {
	return metrics.UUIDandVersion.UUID.String()
}

// LogCreate :
func (metrics NetworkInstanceMetrics) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkInstanceMetricsLogType, "",
		metrics.UUIDandVersion.UUID, metrics.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Network instance metrics create")
}

// LogModify :
func (metrics NetworkInstanceMetrics) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceMetricsLogType, "",
		metrics.UUIDandVersion.UUID, metrics.LogKey())

	oldMetrics, ok := old.(NetworkInstanceMetrics)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkInstanceMetrics type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldMetrics, metrics)).
		Metricf("Network instance metrics modify")
}

// LogDelete :
func (metrics NetworkInstanceMetrics) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceMetricsLogType, "",
		metrics.UUIDandVersion.UUID, metrics.LogKey())
	logObject.Metricf("Network instance metrics delete")

	base.DeleteLogObject(logBase, metrics.LogKey())
}

// LogKey :
func (metrics NetworkInstanceMetrics) LogKey() string {
	return string(base.NetworkInstanceMetricsLogType) + "-" + metrics.Key()
}

// Network metrics for overlay and underlay
// Matches networkMetrics protobuf message
type NetworkMetrics struct {
	MetricList     []NetworkMetric
	TotalRuleCount uint64
}

// Key is used for pubsub
func (nms NetworkMetrics) Key() string {
	return "global"
}

// LogCreate :
func (nms NetworkMetrics) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkMetricsLogType, "",
		nilUUID, nms.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Network metrics create")
}

// LogModify :
func (nms NetworkMetrics) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkMetricsLogType, "",
		nilUUID, nms.LogKey())

	oldNms, ok := old.(NetworkMetrics)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkMetrics type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldNms, nms)).
		Metricf("Network metrics modify")
}

// LogDelete :
func (nms NetworkMetrics) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkMetricsLogType, "",
		nilUUID, nms.LogKey())
	logObject.Metricf("Network metrics delete")

	base.DeleteLogObject(logBase, nms.LogKey())
}

// LogKey :
func (nms NetworkMetrics) LogKey() string {
	return string(base.NetworkMetricsLogType) + "-" + nms.Key()
}

func (nms *NetworkMetrics) LookupNetworkMetrics(ifName string) (NetworkMetric, bool) {
	for _, metric := range nms.MetricList {
		if ifName == metric.IfName {
			return metric, true
		}
	}
	return NetworkMetric{}, false
}

type NetworkMetric struct {
	IfName              string
	TxBytes             uint64
	RxBytes             uint64
	TxDrops             uint64
	RxDrops             uint64
	TxPkts              uint64
	RxPkts              uint64
	TxErrors            uint64
	RxErrors            uint64
	TxAclDrops          uint64 // For implicit deny/drop at end
	RxAclDrops          uint64 // For implicit deny/drop at end
	TxAclRateLimitDrops uint64 // For all rate limited rules
	RxAclRateLimitDrops uint64 // For all rate limited rules
}

type NetworkInstanceType int32

// These values should be same as the ones defined in zconfig.ZNetworkInstType
const (
	NetworkInstanceTypeFirst       NetworkInstanceType = 0
	NetworkInstanceTypeSwitch      NetworkInstanceType = 1
	NetworkInstanceTypeLocal       NetworkInstanceType = 2
	NetworkInstanceTypeCloud       NetworkInstanceType = 3
	NetworkInstanceTypeHoneyPot    NetworkInstanceType = 5
	NetworkInstanceTypeTransparent NetworkInstanceType = 6
	NetworkInstanceTypeLast        NetworkInstanceType = 255
)

type AddressType int32

// The values here should be same as the ones defined in zconfig.AddressType
const (
	AddressTypeNone       AddressType = 0 // For switch networks
	AddressTypeIPV4       AddressType = 1
	AddressTypeIPV6       AddressType = 2
	AddressTypeCryptoIPV4 AddressType = 3
	AddressTypeCryptoIPV6 AddressType = 4
	AddressTypeLast       AddressType = 255
)

// NetworkInstanceConfig
//
//	Config Object for NetworkInstance
//	Extracted from the protobuf NetworkInstanceConfig
type NetworkInstanceConfig struct {
	UUIDandVersion
	DisplayName string

	Type NetworkInstanceType

	// Activate - Activate the config.
	Activate bool

	// Logicallabel - name specified in the Device Config.
	// Can be a specific logicallabel for an interface, or a tag like "uplink"
	Logicallabel string

	// IP configuration for the Application
	IpType          AddressType
	Subnet          net.IPNet
	Gateway         net.IP
	DomainName      string
	NtpServer       net.IP
	DnsServers      []net.IP // If not set we use Gateway as DNS server
	DhcpRange       IpRange
	DnsNameToIPList []DnsNameToIP // Used for DNS and ACL ipset

	// For other network services - Proxy / StrongSwan etc..
	OpaqueConfig string

	// Any errors from the parser
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

func (config *NetworkInstanceConfig) Key() string {
	return config.UUID.String()
}

// LogCreate :
func (config NetworkInstanceConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkInstanceConfigLogType, "",
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Network instance config create")
}

// LogModify :
func (config NetworkInstanceConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceConfigLogType, "",
		config.UUIDandVersion.UUID, config.LogKey())

	oldConfig, ok := old.(NetworkInstanceConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkInstanceConfig type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
		Noticef("Network instance config modify")
}

// LogDelete :
func (config NetworkInstanceConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceConfigLogType, "",
		config.UUIDandVersion.UUID, config.LogKey())
	logObject.Noticef("Network instance config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config NetworkInstanceConfig) LogKey() string {
	return string(base.NetworkInstanceConfigLogType) + "-" + config.Key()
}

func (config *NetworkInstanceConfig) IsIPv6() bool {
	switch config.IpType {
	case AddressTypeIPV6:
		return true
	case AddressTypeCryptoIPV6:
		return true
	}
	return false
}

// WithUplinkProbing returns true if the network instance is eligible for uplink
// probing (see pkg/pillar/uplinkprober).
// Uplink probing is performed only for L3 networks with non-empty "shared" uplink
// label, matching a subset of uplink ports.
// Even if a network instance is eligible for probing as determined by this method,
// the actual process of connectivity probing may still be inactive if there are
// no uplink ports available that match the label.
func (config *NetworkInstanceConfig) WithUplinkProbing() bool {
	switch config.Type {
	case NetworkInstanceTypeLocal:
		return IsSharedPortLabel(config.Logicallabel)
	default:
		return false
	}
}

const (
	// UplinkLabel references all management interfaces.
	UplinkLabel = "uplink"
	// FreeUplinkLabel references all management interfaces with 0 cost.
	FreeUplinkLabel = "freeuplink"
)

// IsSharedPortLabel : returns true if the logical label references multiple
// ports.
// Currently used labels are:
//   - "uplink": any management interface
//   - "freeuplink": any management interface with 0 cost
func IsSharedPortLabel(label string) bool {
	switch label {
	case UplinkLabel:
		return true
	case FreeUplinkLabel:
		return true
	}
	return false
}

type ChangeInProgressType int32

const (
	ChangeInProgressTypeNone   ChangeInProgressType = 0
	ChangeInProgressTypeCreate ChangeInProgressType = 1
	ChangeInProgressTypeModify ChangeInProgressType = 2
	ChangeInProgressTypeDelete ChangeInProgressType = 3
	ChangeInProgressTypeLast   ChangeInProgressType = 255
)

// NetworkInstanceStatus
//
//	Config Object for NetworkInstance
//	Extracted from the protobuf NetworkInstanceConfig
type NetworkInstanceStatus struct {
	NetworkInstanceConfig
	// Make sure the Activate from the config isn't exposed as a boolean
	Activate uint64

	ChangeInProgress ChangeInProgressType

	// Activated
	//	Keeps track of current state of object - if it has been activated
	Activated bool

	Server4Running bool // Did we start the server?

	NetworkInstanceInfo

	SelectedUplinkIntf string // Decided by local/remote probing
	ProgUplinkIntf     string // Currently programmed uplink interface for app traffic
}

// LogCreate :
func (status NetworkInstanceStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkInstanceStatusLogType, "",
		status.UUIDandVersion.UUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Network instance status create")
}

// LogModify :
func (status NetworkInstanceStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceStatusLogType, "",
		status.UUIDandVersion.UUID, status.LogKey())

	oldStatus, ok := old.(NetworkInstanceStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkInstanceStatus type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Network instance status modify")
}

// LogDelete :
func (status NetworkInstanceStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceStatusLogType, "",
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.Noticef("Network instance status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status NetworkInstanceStatus) LogKey() string {
	return string(base.NetworkInstanceStatusLogType) + "-" + status.Key()
}

type VifNameMac struct {
	Name    string
	MacAddr string
	AppID   uuid.UUID
}

// AppNetworkACLArgs : args for converting ACL to iptables rules
type AppNetworkACLArgs struct {
	IsMgmt     bool
	IPVer      int
	BridgeName string
	VifName    string
	BridgeIP   net.IP
	AppIP      string
	UpLinks    []string // List of ifnames
	NIType     NetworkInstanceType
	// This is the same AppNum that comes from AppNetworkStatus
	AppNum int32
}

// IPTablesRule : iptables rule detail
type IPTablesRule struct {
	IPVer            int      // 4 or, 6
	Table            string   // filter/nat/raw/mangle...
	Chain            string   // FORWARDING/INPUT/PREROUTING...
	Prefix           []string // constructed using ACLArgs
	Rule             []string // rule match
	Action           []string // rule action
	RuleID           int32    // Unique rule ID
	RuleName         string
	ActionChainName  string
	IsUserConfigured bool // Does this rule come from user configuration/manifest?
	IsMarkingRule    bool // Rule does marking of packet for flow tracking.
	IsPortMapRule    bool // Is this a port map rule?
	IsLimitDropRule  bool // Is this a policer limit drop rule?
	IsDefaultDrop    bool // Is this a default drop rule that forwards to dummy?
	AnyPhysdev       bool // Apply rule irrespective of the input/output physical device.
}

// IPTablesRuleList : list of iptables rules
type IPTablesRuleList []IPTablesRule

/*
 * Tx/Rx of bridge is equal to the total of Tx/Rx on all member
 * virtual interfaces excluding the bridge itself.
 *
 * Drops/Errors/AclDrops of bridge is equal to total of Drops/Errors/AclDrops
 * on all member virtual interface including the bridge.
 */
func (status *NetworkInstanceStatus) UpdateNetworkMetrics(log *base.LogObject,
	nms *NetworkMetrics) (brNetMetric *NetworkMetric) {

	brNetMetric = &NetworkMetric{IfName: status.BridgeName}
	status.VifMetricMap = make(map[string]NetworkMetric) // clear previous metrics
	for _, vif := range status.Vifs {
		metric, found := nms.LookupNetworkMetrics(vif.Name)
		if !found {
			log.Tracef("No metrics found for interface %s",
				vif.Name)
			continue
		}
		status.VifMetricMap[vif.Name] = metric
	}
	for _, metric := range status.VifMetricMap {
		brNetMetric.TxBytes += metric.TxBytes
		brNetMetric.RxBytes += metric.RxBytes
		brNetMetric.TxPkts += metric.TxPkts
		brNetMetric.RxPkts += metric.RxPkts
		brNetMetric.TxErrors += metric.TxErrors
		brNetMetric.RxErrors += metric.RxErrors
		brNetMetric.TxDrops += metric.TxDrops
		brNetMetric.RxDrops += metric.RxDrops
		brNetMetric.TxAclDrops += metric.TxAclDrops
		brNetMetric.RxAclDrops += metric.RxAclDrops
		brNetMetric.TxAclRateLimitDrops += metric.TxAclRateLimitDrops
		brNetMetric.RxAclRateLimitDrops += metric.RxAclRateLimitDrops
	}
	return brNetMetric
}

/*
 * Tx/Rx of bridge is equal to the total of Tx/Rx on all member
 * virtual interfaces excluding the bridge itself.
 *
 * Drops/Errors/AclDrops of bridge is equal to total of Drops/Errors/AclDrops
 * on all member virtual interface including the bridge.
 */
func (status *NetworkInstanceStatus) UpdateBridgeMetrics(log *base.LogObject,
	nms *NetworkMetrics, netMetric *NetworkMetric) {
	// Get bridge metrics
	bridgeMetric, found := nms.LookupNetworkMetrics(status.BridgeName)
	if !found {
		log.Tracef("No metrics found for Bridge %s",
			status.BridgeName)
	} else {
		netMetric.TxErrors += bridgeMetric.TxErrors
		netMetric.RxErrors += bridgeMetric.RxErrors
		netMetric.TxDrops += bridgeMetric.TxDrops
		netMetric.RxDrops += bridgeMetric.RxDrops
		netMetric.TxAclDrops += bridgeMetric.TxAclDrops
		netMetric.RxAclDrops += bridgeMetric.RxAclDrops
		netMetric.TxAclRateLimitDrops += bridgeMetric.TxAclRateLimitDrops
		netMetric.RxAclRateLimitDrops += bridgeMetric.RxAclRateLimitDrops
	}
}

// Returns true if found
func (status *NetworkInstanceStatus) IsIpAssigned(ip net.IP) bool {
	for _, assignments := range status.IPAssignments {
		if ip.Equal(assignments.IPv4Addr) {
			return true
		}
		for _, nip := range assignments.IPv6Addrs {
			if ip.Equal(nip) {
				return true
			}
		}
	}
	return false
}

// IsUsingIfName checks if ifname is used
func (status *NetworkInstanceStatus) IsUsingIfName(ifname string) bool {
	for _, ifname2 := range status.IfNameList {
		if ifname2 == ifname {
			return true
		}
	}
	return false
}

// ACEDirection :
// Rule direction
type ACEDirection uint8

const (
	// AceDirBoth : Rule applies in both directions
	AceDirBoth ACEDirection = iota
	// AceDirIngress : Rules applies in Ingress direction (from internet to app)
	AceDirIngress ACEDirection = 1
	// AceDirEgress : Rules applies in Egress direction (from app to internet)
	AceDirEgress ACEDirection = 2
)

// Similar support as in draft-ietf-netmod-acl-model
type ACE struct {
	Matches []ACEMatch
	Actions []ACEAction
	Name    string
	RuleID  int32
	Dir     ACEDirection
}

// The Type can be "ip" or "host" (aka domain name), "eidset", "protocol",
// "fport", or "lport" for now. The ip and host matches the remote IP/hostname.
// The host matching is suffix-matching thus zededa.net matches *.zededa.net.
// XXX Need "interface"... e.g. "uplink" or "eth1"? Implicit in network used?
// For now the matches are bidirectional.
// XXX Add directionality? Different rate limits in different directions?
// Value is always a string.
// There is an implicit reject rule at the end.
// The "eidset" type is special for the overlay. Matches all the IPs which
// are part of the DnsNameToIPList.
type ACEMatch struct {
	Type  string
	Value string
}

type ACEAction struct {
	Drop bool // Otherwise accept

	Limit      bool   // Is limiter enabled?
	LimitRate  int    // Packets per unit
	LimitUnit  string // "s", "m", "h", for second, minute, hour
	LimitBurst int    // Packets

	PortMap    bool // Is port mapping part of action?
	TargetPort int  // Internal port
}

// IPTuple :
type IPTuple struct {
	Src     net.IP // local App IP address
	Dst     net.IP // remote IP address
	SrcPort int32  // local App IP Port
	DstPort int32  // remote IP Port
	Proto   int32
}

// FlowScope :
type FlowScope struct {
	AppUUID        uuid.UUID
	NetAdapterName string // logical name for VIF (set by controller in NetworkAdapter.Name)
	BrIfName       string
	NetUUID        uuid.UUID
	Sequence       string // used internally for limit and pkt size per app/bn
}

// Key identifies flow.
func (fs FlowScope) Key() string {
	// Use adapter name instead of NI UUID because application can be connected to the same
	// network instance with multiple interfaces.
	key := fs.AppUUID.String() + "-" + fs.NetAdapterName
	if fs.Sequence != "" {
		key += "-" + fs.Sequence
	}
	return key
}

// ACLActionType - action
type ACLActionType uint8

// ACLAction Enum
const (
	ACLActionNone ACLActionType = iota
	ACLActionAccept
	ACLActionDrop
)

// FlowRec :
type FlowRec struct {
	Flow      IPTuple
	Inbound   bool
	ACLID     int32
	Action    ACLActionType
	StartTime int64
	StopTime  int64
	TxBytes   int64
	TxPkts    int64
	RxBytes   int64
	RxPkts    int64
}

// DNSReq :
type DNSReq struct {
	HostName    string
	Addrs       []net.IP
	RequestTime int64
	ACLNum      int32
}

// IPFlow :
type IPFlow struct {
	Scope   FlowScope
	Flows   []FlowRec
	DNSReqs []DNSReq
}

// Key :
func (flows IPFlow) Key() string {
	return flows.Scope.Key()
}

// LogCreate : we treat IPFlow as Metrics for logging
func (flows IPFlow) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.IPFlowLogType, "",
		nilUUID, flows.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("IP flow create")
}

// LogModify :
func (flows IPFlow) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.IPFlowLogType, "",
		nilUUID, flows.LogKey())

	oldFlows, ok := old.(IPFlow)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of IPFlow type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldFlows, flows)).
		Metricf("IP flow modify")
}

// LogDelete :
func (flows IPFlow) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.IPFlowLogType, "",
		nilUUID, flows.LogKey())
	logObject.Metricf("IP flow delete")

	base.DeleteLogObject(logBase, flows.LogKey())
}

// LogKey :
func (flows IPFlow) LogKey() string {
	return string(base.IPFlowLogType) + "-" + flows.Key()
}

// OnboardingStatus - UUID, etc. advertised by client process
type OnboardingStatus struct {
	DeviceUUID    uuid.UUID
	HardwareModel string // From controller
}

// Key returns the key for pubsub
func (status OnboardingStatus) Key() string {
	return "global"
}

// LogCreate :
func (status OnboardingStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.OnboardingStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Onboarding status create")
}

// LogModify :
func (status OnboardingStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.OnboardingStatusLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(OnboardingStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of OnboardingStatus type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Onboarding status modify")
}

// LogDelete :
func (status OnboardingStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.OnboardingStatusLogType, "",
		nilUUID, status.LogKey())
	logObject.Noticef("Onboarding status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status OnboardingStatus) LogKey() string {
	return string(base.OnboardingStatusLogType) + "-" + status.Key()
}

// AppInstMetaDataType - types of app meta data
type AppInstMetaDataType uint8

// enum app metadata type
const (
	AppInstMetaDataTypeNone AppInstMetaDataType = iota // enum for app inst metadata type
	AppInstMetaDataTypeKubeConfig
	AppInstMetaDataCustomStatus
)

// AppInstMetaData : App Instance Metadata
type AppInstMetaData struct {
	AppInstUUID uuid.UUID
	Data        []byte
	Type        AppInstMetaDataType
}

// Key : App Instance Metadata unique key
func (data AppInstMetaData) Key() string {
	return data.AppInstUUID.String() + "-" + string(data.Type)
}

// AddToIP :
func AddToIP(ip net.IP, addition int) net.IP {
	if addr := ip.To4(); addr != nil {
		val := uint32(addr[0])<<24 + uint32(addr[1])<<16 +
			uint32(addr[2])<<8 + uint32(addr[3])
		val += uint32(addition)
		byte0 := byte((val >> 24) & 0xFF)
		byte1 := byte((val >> 16) & 0xFF)
		byte2 := byte((val >> 8) & 0xFF)
		byte3 := byte(val & 0xFF)
		return net.IPv4(byte0, byte1, byte2, byte3)
	}
	//TBD:XXX, IPv6 handling
	return net.IP{}
}

// GetIPAddrCountOnSubnet IP address count on subnet
func GetIPAddrCountOnSubnet(subnet net.IPNet) int {
	prefixLen, _ := subnet.Mask.Size()
	if prefixLen != 0 {
		if subnet.IP.To4() != nil {
			return 0x01 << (32 - prefixLen)
		}
		if subnet.IP.To16() != nil {
			return 0x01 << (128 - prefixLen)
		}
	}
	return 0
}

// GetIPNetwork  :
// returns the first IP Address of the subnet(Network Address)
func GetIPNetwork(subnet net.IPNet) net.IP {
	return subnet.IP.Mask(subnet.Mask)
}

// GetIPBroadcast :
// returns the last IP Address of the subnet(Broadcast Address)
func GetIPBroadcast(subnet net.IPNet) net.IP {
	if network := GetIPNetwork(subnet); network != nil {
		if addrCount := GetIPAddrCountOnSubnet(subnet); addrCount != 0 {
			return AddToIP(network, addrCount-1)
		}
	}
	return net.IP{}
}

// At the MinSubnetSize there is room for one app instance (.0 being reserved,
// .3 broadcast, .1 is the bridgeIPAddr, and .2 is usable).
const (
	MinSubnetSize   = 4  // minimum Subnet Size
	LargeSubnetSize = 16 // for determining default Dhcp Range
)

// WwanConfig is published by nim and consumed by the wwan service.
type WwanConfig struct {
	RadioSilence bool                `json:"radio-silence"`
	Networks     []WwanNetworkConfig `json:"networks"`
}

// Equal compares two instances of WwanConfig for equality.
func (wc WwanConfig) Equal(wc2 WwanConfig) bool {
	if wc.RadioSilence != wc2.RadioSilence {
		return false
	}
	if len(wc.Networks) != len(wc2.Networks) {
		return false
	}
	for _, m1 := range wc.Networks {
		var found bool
		for _, m2 := range wc2.Networks {
			if m1.Equal(m2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// WwanNetworkConfig contains configuration for a single cellular network.
type WwanNetworkConfig struct {
	// Logical label in PhysicalIO.
	LogicalLabel string        `json:"logical-label"`
	PhysAddrs    WwanPhysAddrs `json:"physical-addrs"`
	// XXX Multiple APNs are not yet supported.
	Apns []string `json:"apns"`
	// Proxies configured for the cellular network.
	Proxies []ProxyEntry `json:"proxies"`
	// Probe used to detect broken connection.
	Probe WwanProbe `json:"probe"`
	// Some LTE modems have GNSS receiver integrated and can be used
	// for device location tracking.
	// Enable this option to have location info periodically obtained
	// from this modem and published into /run/wwan/location.json by the wwan
	// microservice. This is further distributed to the controller and
	// to applications by zedagent.
	LocationTracking bool `json:"location-tracking"`
}

// WwanProbe : cellular connectivity verification probe.
type WwanProbe struct {
	Disable bool `json:"disable"`
	// IP/FQDN address to periodically probe to determine connection status.
	Address string `json:"address"`
}

// Equal compares two instances of WwanNetworkConfig for equality.
func (wnc WwanNetworkConfig) Equal(wnc2 WwanNetworkConfig) bool {
	if wnc.LogicalLabel != wnc2.LogicalLabel ||
		wnc.PhysAddrs.PCI != wnc2.PhysAddrs.PCI ||
		wnc.PhysAddrs.USB != wnc2.PhysAddrs.USB ||
		wnc.PhysAddrs.Interface != wnc2.PhysAddrs.Interface {
		return false
	}
	if wnc.Probe.Address != wnc2.Probe.Address ||
		wnc.Probe.Disable != wnc2.Probe.Disable {
		return false
	}
	if len(wnc.Proxies) != len(wnc2.Proxies) {
		return false
	}
	for i := range wnc.Proxies {
		if wnc.Proxies[i] != wnc2.Proxies[i] {
			return false
		}
	}
	if wnc.LocationTracking != wnc2.LocationTracking {
		return false
	}
	if len(wnc.Apns) != len(wnc2.Apns) {
		return false
	}
	for _, apn1 := range wnc.Apns {
		var found bool
		for _, apn2 := range wnc2.Apns {
			if apn1 == apn2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// WwanPhysAddrs is a physical address of a cellular modem.
// Not all fields have to be defined. Empty WwanPhysAddrs will match the first modem found in sysfs.
// With multiple LTE modems the USB address is the most unambiguous and reliable.
type WwanPhysAddrs struct {
	// Interface name.
	// For example: wwan0
	Interface string `json:"interface"`
	// USB address in the format "<BUS>:[<PORT>]", with nested ports separated by dots.
	// For example: 1:2.3
	USB string `json:"usb"`
	// PCI address in the long format.
	// For example: 0000:00:15.0
	PCI string `json:"pci"`
}

// WwanStatus is published by the wwan service and consumed by nim.
type WwanStatus struct {
	Networks []WwanNetworkStatus `json:"networks"`
	// MD5 checksum of the corresponding WwanConfig (as config.json).
	ConfigChecksum string `json:"config-checksum,omitempty"`
}

// LookupNetworkStatus returns status corresponding to the given cellular network.
func (ws WwanStatus) LookupNetworkStatus(logicalLabel string) (WwanNetworkStatus, bool) {
	for _, status := range ws.Networks {
		if logicalLabel == status.LogicalLabel {
			return status, true
		}
	}
	return WwanNetworkStatus{}, false
}

// DoSanitize fills in logical names for cellular modules and SIM cards.
func (ws WwanStatus) DoSanitize() {
	uniqueModel := func(model string) bool {
		var counter int
		for i := range ws.Networks {
			if ws.Networks[i].Module.Model == model {
				counter++
			}
		}
		return counter == 1
	}
	for i := range ws.Networks {
		network := &ws.Networks[i]
		if network.Module.Name == "" {
			if network.Module.IMEI != "" {
				network.Module.Name = network.Module.IMEI
			} else if uniqueModel(network.Module.Model) {
				network.Module.Name = network.Module.Model
			} else {
				network.Module.Name = network.PhysAddrs.USB
			}
		}
		for j := range network.SimCards {
			simCard := &network.SimCards[j]
			if simCard.Name == "" {
				if simCard.ICCID != "" {
					simCard.Name = simCard.ICCID
				} else {
					simCard.Name = fmt.Sprintf("%s - SIM%d", network.Module.Name, j)
				}
			}
		}
	}
}

// WwanNetworkStatus contains status information for a single cellular network.
type WwanNetworkStatus struct {
	// Logical label of the cellular modem in PhysicalIO.
	// Can be empty if this device is not configured by the controller
	// (and hence logical label does not exist).
	LogicalLabel string         `json:"logical-label"`
	PhysAddrs    WwanPhysAddrs  `json:"physical-addrs"`
	Module       WwanCellModule `json:"cellular-module"`
	SimCards     []WwanSimCard  `json:"sim-cards"`
	ConfigError  string         `json:"config-error"`
	ProbeError   string         `json:"probe-error"`
	Providers    []WwanProvider `json:"providers"`
}

// WwanCellModule contains cellular module specs.
type WwanCellModule struct {
	Name            string       `json:"name,omitempty"`
	IMEI            string       `json:"imei"`
	Model           string       `json:"model"`
	Revision        string       `json:"revision"`
	ControlProtocol WwanCtrlProt `json:"control-protocol"`
	OpMode          WwanOpMode   `json:"operating-mode"`
}

// WwanSimCard contains SIM card information.
type WwanSimCard struct {
	Name   string `json:"name,omitempty"`
	ICCID  string `json:"iccid"`
	IMSI   string `json:"imsi"`
	Status string `json:"status"`
}

// WwanProvider contains information about a cellular connectivity provider.
type WwanProvider struct {
	PLMN           string `json:"plmn"`
	Description    string `json:"description"`
	CurrentServing bool   `json:"current-serving"`
	Roaming        bool   `json:"roaming"`
}

// WwanOpMode : wwan operating mode
type WwanOpMode string

const (
	// WwanOpModeUnspecified : operating mode is not specified
	WwanOpModeUnspecified WwanOpMode = ""
	// WwanOpModeOnline : modem is online but not connected
	WwanOpModeOnline WwanOpMode = "online"
	// WwanOpModeConnected : modem is online and connected
	WwanOpModeConnected WwanOpMode = "online-and-connected"
	// WwanOpModeRadioOff : modem has disabled radio transmission
	WwanOpModeRadioOff WwanOpMode = "radio-off"
	// WwanOpModeOffline : modem is offline
	WwanOpModeOffline WwanOpMode = "offline"
	// WwanOpModeUnrecognized : unrecongized operating mode
	WwanOpModeUnrecognized WwanOpMode = "unrecognized"
)

// WwanCtrlProt : wwan control protocol
type WwanCtrlProt string

const (
	// WwanCtrlProtUnspecified : control protocol is not specified
	WwanCtrlProtUnspecified WwanCtrlProt = ""
	// WwanCtrlProtQMI : modem is controlled using the QMI protocol
	WwanCtrlProtQMI WwanCtrlProt = "qmi"
	// WwanCtrlProtMBIM : modem is controlled using the MBIM protocol
	WwanCtrlProtMBIM WwanCtrlProt = "mbim"
)

// WwanMetrics is published by the wwan service.
type WwanMetrics struct {
	Networks []WwanNetworkMetrics `json:"networks"`
}

// LookupNetworkMetrics returns metrics corresponding to the given cellular network.
func (wm WwanMetrics) LookupNetworkMetrics(logicalLabel string) (WwanNetworkMetrics, bool) {
	for _, metrics := range wm.Networks {
		if logicalLabel == metrics.LogicalLabel {
			return metrics, true
		}
	}
	return WwanNetworkMetrics{}, false
}

// Key is used for pubsub
func (wm WwanMetrics) Key() string {
	return "global"
}

// LogCreate :
func (wm WwanMetrics) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.WwanMetricsLogType, "",
		nilUUID, wm.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Wwan metrics create")
}

// LogModify :
func (wm WwanMetrics) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.WwanMetricsLogType, "",
		nilUUID, wm.LogKey())

	oldWm, ok := old.(WwanMetrics)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object passed is not of WwanMetrics type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldWm, wm)).
		Metricf("Wwan metrics modify")
}

// LogDelete :
func (wm WwanMetrics) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.WwanMetricsLogType, "",
		nilUUID, wm.LogKey())
	logObject.Metricf("Wwan metrics delete")

	base.DeleteLogObject(logBase, wm.LogKey())
}

// LogKey :
func (wm WwanMetrics) LogKey() string {
	return string(base.WwanMetricsLogType) + "-" + wm.Key()
}

// WwanNetworkMetrics contains metrics for a single cellular network.
type WwanNetworkMetrics struct {
	// Logical label of the cellular modem in PhysicalIO.
	// Can be empty if this device is not configured by the controller
	// (and hence logical label does not exist).
	LogicalLabel string          `json:"logical-label"`
	PhysAddrs    WwanPhysAddrs   `json:"physical-addrs"`
	PacketStats  WwanPacketStats `json:"packet-stats"`
	SignalInfo   WwanSignalInfo  `json:"signal-info"`
}

// WwanPacketStats contains packet statistics recorded by a cellular modem.
type WwanPacketStats struct {
	RxBytes   uint64 `json:"rx-bytes"`
	RxPackets uint64 `json:"rx-packets"`
	RxDrops   uint64 `json:"rx-drops"`
	TxBytes   uint64 `json:"tx-bytes"`
	TxPackets uint64 `json:"tx-packets"`
	TxDrops   uint64 `json:"tx-drops"`
}

// WwanSignalInfo contains cellular signal strength information.
// The maximum value of int32 (0x7FFFFFFF) represents unspecified/unavailable metric.
type WwanSignalInfo struct {
	// Received signal strength indicator (RSSI) measured in dBm (decibel-milliwatts).
	RSSI int32 `json:"rssi"`
	// Reference Signal Received Quality (RSRQ) measured in dB (decibels).
	RSRQ int32 `json:"rsrq"`
	// Reference Signal Receive Power (RSRP) measured in dBm (decibel-milliwatts).
	RSRP int32 `json:"rsrp"`
	// Signal-to-Noise Ratio (SNR) measured in dB (decibels).
	SNR int32 `json:"snr"`
}

// WwanLocationInfo contains device location information obtained from a GNSS
// receiver integrated into an LTE modem.
type WwanLocationInfo struct {
	// Logical label of the device used to obtain this location information.
	LogicalLabel string `json:"logical-label"`
	// Latitude in the Decimal degrees (DD) notation.
	// Valid values are in the range <-90, 90>. Anything outside of this range
	// should be treated as an unavailable value.
	// Note that wwan microservice uses -32768 specifically when latitude is not known.
	Latitude float64 `json:"latitude"`
	// Longitude in the Decimal degrees (DD) notation.
	// Valid values are in the range <-180, 180>. Anything outside of this range
	// should be treated as an unavailable value.
	// Note that wwan microservice uses -32768 specifically when longitude is not known.
	Longitude float64 `json:"longitude"`
	// Altitude w.r.t. mean sea level in meters.
	// Negative value of -32768 is returned when altitude is not known.
	Altitude float64 `json:"altitude"`
	// Circular horizontal position uncertainty in meters.
	// Negative values are not valid and represent unavailable uncertainty.
	// Note that wwan microservice uses -32768 specifically when horizontal
	// uncertainty is not known.
	HorizontalUncertainty float32 `json:"horizontal-uncertainty"`
	// Reliability of the provided information for latitude and longitude.
	HorizontalReliability LocReliability `json:"horizontal-reliability"`
	// Vertical position uncertainty in meters.
	// Negative values are not valid and represent unavailable uncertainty.
	// Note that wwan microservice uses -32768 specifically when vertical
	// uncertainty is not known.
	VerticalUncertainty float32 `json:"vertical-uncertainty"`
	// Reliability of the provided information for altitude.
	VerticalReliability LocReliability `json:"vertical-reliability"`
	// Unix timestamp in milliseconds.
	// Zero value represents unavailable UTC timestamp.
	UTCTimestamp uint64 `json:"utc-timestamp"`
}

// Key is used for pubsub
func (wli WwanLocationInfo) Key() string {
	return "global"
}

// LogCreate :
func (wli WwanLocationInfo) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.WwanLocationInfoLogType, "",
		nilUUID, wli.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Wwan location info create")
}

// LogModify :
func (wli WwanLocationInfo) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.WwanLocationInfoLogType, "",
		nilUUID, wli.LogKey())

	oldWli, ok := old.(WwanLocationInfo)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object passed is not of WwanLocationInfo type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldWli, wli)).
		Metricf("Wwan location info modify")
}

// LogDelete :
func (wli WwanLocationInfo) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.WwanLocationInfoLogType, "",
		nilUUID, wli.LogKey())
	logObject.Metricf("Wwan location info delete")
	base.DeleteLogObject(logBase, wli.LogKey())
}

// LogKey :
func (wli WwanLocationInfo) LogKey() string {
	return string(base.WwanLocationInfoLogType) + "-" + wli.Key()
}

// LocReliability : reliability of location information.
type LocReliability string

const (
	// LocReliabilityUnspecified : reliability is not specified
	LocReliabilityUnspecified LocReliability = "not-set"
	// LocReliabilityVeryLow : very low reliability
	LocReliabilityVeryLow LocReliability = "very-low"
	// LocReliabilityLow : low reliability
	LocReliabilityLow LocReliability = "low"
	// LocReliabilityMedium : medium reliability
	LocReliabilityMedium LocReliability = "medium"
	// LocReliabilityHigh : high reliability
	LocReliabilityHigh LocReliability = "high"
)

// AppBlobsAvailable provides a list of AppCustom blobs which has been provided
// from the cloud
type AppBlobsAvailable struct {
	CustomMeta  string
	DownloadURL string
}

// AppInfo provides various information to the application
type AppInfo struct {
	AppBlobs []AppBlobsAvailable
}
