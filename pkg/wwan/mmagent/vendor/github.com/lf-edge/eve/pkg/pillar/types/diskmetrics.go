/*
 * Copyright (c) 2020. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package types

import (
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// ReportDiskPaths Report disk usage for these paths
var ReportDiskPaths = []string{
	"/",
	IdentityDirname,
	PersistDir,
}

// ReportDirPaths  Report directory usage for these paths
var ReportDirPaths = []string{
	PersistDir + "/downloads", // XXX old to be removed
	PersistDir + "/img",       // XXX old to be removed
	PersistDir + "/containerd",
	PersistDir + "/tmp",
	PersistDir + "/log",
	PersistDir + "/newlog",
	PersistDir + "/config",
	PersistDir + "/status",
	PersistDir + "/certs",
	PersistDir + "/checkpoint",
}

// AppPersistPaths  Application-related files live here
// XXX do we need to exclude the ContentTrees used for eve image update?
// If so how do we tell them apart
var AppPersistPaths = []string{
	VolumeEncryptedDirName,
	VolumeClearDirName,
	SealedDirName + "/downloader",
	SealedDirName + "/verifier",
}

// DiskMetric holds metrics data per disk
type DiskMetric struct {
	DiskPath   string
	ReadBytes  uint64 // Value in Bytes. Number read Bytes.
	WriteBytes uint64 // Value in Bytes. Number written Bytes.
	ReadCount  uint64 // Number of read operations.
	WriteCount uint64 // Number of write operations.
	TotalBytes uint64 // Value in Bytes. Total number of allotted Bytes for the disk.
	UsedBytes  uint64 // Value in Bytes. Total number of used Bytes by the disk.
	FreeBytes  uint64 // Value in Bytes. Total number of free Bytes for the disk.
	IsDir      bool   // Will be true if DiskPath is a mountPath, will false if it's a disk.
}

// Key returns the pubsub Key.
func (status DiskMetric) Key() string {
	return PathToKey(status.DiskPath)
}

// LogCreate :
func (status DiskMetric) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DiskMetricType, status.DiskPath, nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("diskpath", status.DiskPath).
		AddField("readbytes-int64", status.ReadBytes).
		AddField("writebytes-int64", status.WriteBytes).
		AddField("readcount-int64", status.ReadCount).
		AddField("writecount-int64", status.WriteCount).
		AddField("totalbytes-int64", status.TotalBytes).
		AddField("userbytes-int64", status.UsedBytes).
		AddField("freebytes-int64", status.FreeBytes).
		AddField("isdor", status.IsDir).
		Metricf("DiskMetric status create")
}

// LogModify :
func (status DiskMetric) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DiskMetricType, status.DiskPath, nilUUID, status.LogKey())

	if _, ok := old.(DiskMetric); !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DiskMetric type")
	}
	logObject.CloneAndAddField("diskpath", status.DiskPath).
		AddField("old-readbytes-int64", status.ReadBytes).
		AddField("old-writebytes-int64", status.WriteBytes).
		AddField("old-readcount-int64", status.ReadCount).
		AddField("old-writecount-int64", status.WriteCount).
		AddField("totalbytes-int64", status.TotalBytes).
		AddField("old-userbytes-int64", status.UsedBytes).
		AddField("old-freebytes-int64", status.FreeBytes).
		AddField("isdor", status.IsDir).
		Metricf("DiskMetric status modify")
}

// LogDelete :
func (status DiskMetric) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DiskMetricType, status.DiskPath, nilUUID, status.LogKey())
	logObject.CloneAndAddField("diskpath", status.DiskPath).
		AddField("totalbytes-int64", status.TotalBytes).
		AddField("userbytes-int64", status.UsedBytes).
		AddField("freebytes-int64", status.FreeBytes).
		AddField("isdor", status.IsDir).
		Metricf("DiskMetric status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status DiskMetric) LogKey() string {
	return string(base.DiskMetricType) + "-" + status.Key()
}

// AppDiskMetric hold metrics data per appInstance volume
type AppDiskMetric struct {
	DiskPath         string
	ProvisionedBytes uint64 // Value in Bytes. Total number of allotted Bytes for the disk.
	UsedBytes        uint64 // Value in Bytes. Total number of used Bytes by the disk.
	DiskType         string
	Dirty            bool
}

// Key returns the pubsub Key.
func (status AppDiskMetric) Key() string {
	return PathToKey(status.DiskPath)
}

// LogCreate :
func (status AppDiskMetric) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppDiskMetricType, status.DiskPath, nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("diskpath", status.DiskPath).
		AddField("userbytes-int64", status.UsedBytes).
		AddField("provisionedbytes-int64", status.ProvisionedBytes).
		AddField("disktype", status.DiskType).
		AddField("dirty", status.Dirty).
		Metricf("AppDiskMetric status create")
}

// LogModify :
func (status AppDiskMetric) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppDiskMetricType, status.DiskPath, nilUUID, status.LogKey())

	if _, ok := old.(AppDiskMetric); !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppDiskMetric type")
	}
	logObject.CloneAndAddField("diskpath", status.DiskPath).
		AddField("old-userbytes-int64", status.UsedBytes).
		AddField("provisionedbytes-int64", status.ProvisionedBytes).
		AddField("disktype", status.DiskType).
		AddField("dirty", status.Dirty).
		Metricf("AppDiskMetric status modify")
}

// LogDelete :
func (status AppDiskMetric) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppDiskMetricType, status.DiskPath, nilUUID, status.LogKey())
	logObject.CloneAndAddField("diskpath", status.DiskPath).
		AddField("provisionedbytes-int64", status.ProvisionedBytes).
		AddField("disktype", status.DiskType).
		AddField("dirty", status.Dirty).
		Metricf("AppDiskMetric status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status AppDiskMetric) LogKey() string {
	return string(base.AppDiskMetricType) + "-" + status.Key()
}

// PathToKey converts /path/to/dir to path-to-dir.
func PathToKey(path string) string {
	path = strings.TrimPrefix(path, "/")
	key := strings.ReplaceAll(path, "/", "-")
	return key
}

// ImgInfo matches the json output of qemu-img info
type ImgInfo struct {
	VirtualSize uint64 `json:"virtual-size"`
	Filename    string `json:"filename"`
	ClusterSize uint64 `json:"cluster-size"`
	Format      string `json:"format"`
	ActualSize  uint64 `json:"actual-size"`
	DirtyFlag   bool   `json:"dirty-flag"`
}

// UsageStat stores usage information about directory
type UsageStat struct {
	Total uint64
	Used  uint64
	Free  uint64
}
