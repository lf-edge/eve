// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	uuid "github.com/satori/go.uuid"
)

const (
	// ZVolDevicePrefix controlled by mdev
	ZVolDevicePrefix = "/dev/zvol"

	// ZFSSnapshotter is containerd snapshotter for zfs
	ZFSSnapshotter = "zfs"

	// ZFSBinary is the zfs binary
	ZFSBinary = "zfs"

	// ZPoolBinary is the zpool binary
	ZPoolBinary = "zpool"
)

// ZVolName returns name of zvol for volume
func (status VolumeStatus) ZVolName() string {
	pool := VolumeClearZFSDataset
	if status.Encrypted {
		pool = VolumeEncryptedZFSDataset
	}
	return fmt.Sprintf("%s/%s.%d", pool, status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)
}

// ZVolName returns name of zvol for volume
func (status VolumeCreatePending) ZVolName() string {
	pool := VolumeClearZFSDataset
	if status.Encrypted {
		pool = VolumeEncryptedZFSDataset
	}
	return fmt.Sprintf("%s/%s.%d", pool, status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)
}

// UseZVolDisk returns true if we should use zvol for the provided VolumeStatus and PersistType
func (status VolumeStatus) UseZVolDisk(persistType PersistType) bool {
	if status.IsContainer() {
		return false
	}
	if status.ContentFormat == zconfig.Format_ISO {
		return false
	}
	return persistType == PersistZFS
}

// ZVolStatus specifies the needed information for zfs volume
type ZVolStatus struct {
	Dataset string
	Device  string
}

// Key is Dataset with '/' replaced by '_'
func (status ZVolStatus) Key() string {
	return strings.ReplaceAll(status.Dataset, "/", "_")
}

// PoolStatus type value from ZFS
type PoolStatus uint32

// PoolStatus value.
//
// The following correspond to faults as defined in enum zfs_error in the
// libzfs.h header file. But we add +1 to their values to that we can
// have a Unspecified=0 value to follow our conventions. Basically that the
// definitions should follow that in the (fault.fs.zfs.*) event namespace.
const (
	PoolStatusUnspecified       PoolStatus = iota // Unspecified
	PoolStatusCorruptCache                        // PoolStatusCorruptCache - corrupt /kernel/drv/zpool.cache
	PoolStatusMissingDevR                         // missing device with replicas
	PoolStatusMissingDevNr                        // missing device with no replicas
	PoolStatusCorruptLabelR                       // bad device label with replicas
	PoolStatusCorruptLabelNr                      // bad device label with no replicas
	PoolStatusBadGUIDSum                          // sum of device guids didn't match
	PoolStatusCorruptPool                         // pool metadata is corrupted
	PoolStatusCorruptData                         // data errors in user (meta)data
	PoolStatusFailingDev                          // device experiencing errors
	PoolStatusVersionNewer                        // newer on-disk version
	PoolStatusHostidMismatch                      // last accessed by another system
	PoolStatusHosidActive                         // currently active on another system
	PoolStatusHostidRequired                      // multihost=on and hostid=0
	PoolStatusIoFailureWait                       // failed I/O, failmode 'wait'
	PoolStatusIoFailureContinue                   // failed I/O, failmode 'continue'
	PoolStatusIOFailureMMP                        // ailed MMP, failmode not 'panic'
	PoolStatusBadLog                              // cannot read log chain(s)
	PoolStatusErrata                              // informational errata available
	PoolStatusUnsupFeatRead                       // If the pool has unsupported features but cannot be opened at all, its status is ZPOOL_STATUS_UNSUP_FEAT_READ.
	PoolStatusUnsupFeatWrite                      // If the pool has unsupported features but can still be opened in read-only mode, its status is ZPOOL_STATUS_UNSUP_FEAT_WRITE
	PoolStatusFaultedDevR                         // faulted device with replicas
	PoolStatusFaultedDevNr                        // faulted device with no replicas
	PoolStatusVersionOlder                        // older legacy on-disk version
	PoolStatusFeatDisabled                        // supported features are disabled
	PoolStatusResilvering                         // device being resilvered
	PoolStatusOfflineDev                          // device offline
	PoolStatusRemovedDev                          // removed device
	PoolStatusRebuilding                          // device being rebuilt
	PoolStatusRebuildScrub                        // recommend scrubbing the pool
	PoolStatusNonNativeAshift                     // (e.g. 512e dev with ashift of 9)
	PoolStatusCompatibilityErr                    // bad 'compatibility' property
	PoolStatusIncompatibleFeat                    // feature set outside compatibility
	PoolStatusOk                                  // the indicates a healthy pool.
)

// VDevAux - vdev aux states
type VDevAux uint64

// VDevAux - vdev aux states. When a vdev is in the CANT_OPEN state, the aux field
// of the vdev stats structure uses these constants to distinguish why.
//
// But we add +1 to their values to that we can have a Unspecified=0 value
// to follow our conventions. Basically that the
// definitions should follow that in the vdev_aux enum in sys/fs/zfs.h.
const (
	VDevAuxUnspecified     VDevAux = iota // Unspecified
	VDevAuxStatusOk                       // no error (normal state)
	VDevAuxOpenFailed                     // ldi_open_*() or vn_open() failed
	VDevAuxCorruptData                    // bad label or disk contents
	VDevAuxNoReplicas                     // insufficient number of replicas
	VDevAuxBadGUIDSum                     // vdev guid sum doesn't match
	VDevAuxTooSmall                       // vdev size is too small
	VDevAuxBadLabel                       // the label is OK but invalid
	VDevAuxVersionNewer                   // on-disk version is too new
	VDevAuxVersionOlder                   // on-disk version is too old
	VDevAuxUnsupFeat                      // unsupported features
	VDevAuxSpared                         // hot spare used in another pool
	VDevAuxErrExceeded                    // too many errors
	VDevAuxIOFailure                      // experienced I/O failure
	VDevAuxBadLog                         // cannot read log chain(s)
	VDevAuxExternal                       // external diagnosis
	VDevAuxSplitPool                      // vdev was split off into another pool
	VdevAuxBadAshift                      // vdev ashift is invalid
	VdevAuxExternalPersist                // persistent forced fault
	VdevAuxActive                         // vdev active on a different host
	VdevAuxChildrenOffline                // all children are offline
	VdevAuxAshiftTooBig                   // vdev's min block size is too large
)

// StorageRaidType indicates storage raid type
type StorageRaidType int32

// StorageRaidType enum should be in sync with info api
const (
	StorageRaidTypeUnspecified StorageRaidType = 0
	StorageRaidTypeRAID0       StorageRaidType = 1 // RAID-0
	StorageRaidTypeRAID1       StorageRaidType = 2 // Mirror
	StorageRaidTypeRAID5       StorageRaidType = 3 // raidz1 (RAID-5)
	StorageRaidTypeRAID6       StorageRaidType = 4 // raidz2 (RAID-6)
	StorageRaidTypeRAID7       StorageRaidType = 5 // raidz3 (RAID-7)
	StorageRaidTypeNoRAID      StorageRaidType = 6 // without RAID
)

// StorageStatus indicates current status of storage
type StorageStatus int32

// StorageStatus enum should be in sync with info api
const (
	StorageStatusUnspecified StorageStatus = 0
	StorageStatusOnline      StorageStatus = 1 // The device or virtual device is in normal working order.
	StorageStatusDegraded    StorageStatus = 2 // The virtual device has experienced a failure but can still function.
	StorageStatusFaulted     StorageStatus = 3 // The device or virtual device is completely inaccessible.
	StorageStatusOffline     StorageStatus = 4 // The device has been explicitly taken offline by the administrator.
	StorageStatusUnavail     StorageStatus = 5 // The device or virtual device cannot be opened. In some cases, pools with UNAVAIL devices appear in DEGRADED mode.
	StorageStatusRemoved     StorageStatus = 6 // The device was physically removed while the system was running.
	StorageStatusSuspended   StorageStatus = 7 // A pool that is waiting for device connectivity to be restored.
)

// ZFSPoolStatus stores collected information about zpool
type ZFSPoolStatus struct {
	PoolName         string
	ZfsVersion       string
	CurrentRaid      StorageRaidType
	CompressionRatio float64
	ZpoolSize        uint64
	CountZvols       uint32
	StorageState     StorageStatus
	Disks            []*StorageDiskState
	CollectorErrors  string
	Children         []*StorageChildren
	PoolStatusMsg    PoolStatus // pool status value from ZFS
	PoolStatusMsgStr string     // pool status value from ZFS in string format
}

// Key for pubsub
func (s ZFSPoolStatus) Key() string {
	return s.PoolName
}

// DiskDescription stores disk information
type DiskDescription struct {
	Name        string // bus-related name, for example: /dev/sdc
	LogicalName string // logical name, for example: disk3
	Serial      string // serial number of disk
}

// ZIOType - IO types in ZFS.
// These values are used to access the data in the
// arrays (Ops/Bytes) with statistics coming from libzfs.
// ZIOTypeMax value determines the number of ZIOType in this enum.
// (Should always be the last in this enum)
const (
	ZIOTypeNull = iota
	ZIOTypeRead
	ZIOTypeWrite
	ZIOTypeFree
	ZIOTypeClaim
	ZIOTypeIoctl
	ZIOTypeMax // ZIOTypeMax value determines the number of ZIOType in this enum. (Should always be the last in this enum)
)

// ZFSVDevMetrics metrics for VDev from ZFS and /proc/diskstats
type ZFSVDevMetrics struct {
	Alloc          uint64             // space allocated (in byte)
	Space          uint64             // total capacity (in byte)
	DSpace         uint64             // deflated capacity (in byte)
	RSize          uint64             // replaceable dev size (in byte)
	ESize          uint64             // expandable dev size (in byte)
	ReadErrors     uint64             // read errors
	WriteErrors    uint64             // write errors
	ChecksumErrors uint64             // checksum errors
	Ops            [ZIOTypeMax]uint64 // operation count
	Bytes          [ZIOTypeMax]uint64 // bytes read/written
	IOsInProgress  uint64             // IOsInProgress is number of I/Os currently in progress.
	ReadTicks      uint64             // ReadTicks is the total number of milliseconds spent by all reads.
	WriteTicks     uint64             // WriteTicks is the total number of milliseconds spent by all writes.
	IOsTotalTicks  uint64             // IOsTotalTicks is the number of milliseconds spent doing I/Os.
	// WeightedIOTicks is the weighted number of milliseconds spent doing I/Os.
	// This can also be used to estimate average queue wait time for requests.
	WeightedIOTicks uint64
}

// StorageDiskState represent state of disk
type StorageDiskState struct {
	DiskName    *DiskDescription
	Status      StorageStatus
	AuxState    VDevAux
	AuxStateStr string // AuxState in string format
}

// StorageChildren stores children of zfs pool
type StorageChildren struct {
	DisplayName string
	CurrentRaid StorageRaidType
	// GUID - a unique value for the binding.
	// Since the DisplayName may not be unique. This may be important
	// for accurate matching with other information.
	// Actual case only for RAID or Mirror.
	GUID     uint64
	Disks    []*StorageDiskState
	Children []*StorageChildren
}

// StorageZVolMetrics stores metrics for zvol (/dev/zd*)
type StorageZVolMetrics struct {
	VolumeID uuid.UUID       // From VolumeStatus.VolumeID. Ex: c546e61f-ffd9-406e-9074-8b19b417510d
	Metrics  *ZFSVDevMetrics // Metrics for zdev from /proc/diskstats
}

// StorageDiskMetrics represent metrics of disk
type StorageDiskMetrics struct {
	DiskName *DiskDescription
	Metrics  *ZFSVDevMetrics // metrics for disk from ZFS and /proc/diskstats
}

// StorageChildrenMetrics stores metrics for children of zfs pool
type StorageChildrenMetrics struct {
	DisplayName string
	// GUID - a unique value for the binding.
	// Since the DisplayName may not be unique.
	GUID uint64
	// Metrics from ZFS. Displays the sum of metrics from all disks it consists of.
	Metrics  *ZFSVDevMetrics
	Disks    []*StorageDiskMetrics
	Children []*StorageChildrenMetrics
}

// ZFSPoolMetrics - stores metrics for the pool including all child devices
type ZFSPoolMetrics struct {
	PoolName        string
	CollectionTime  time.Time                 // Time when the metrics was collected
	Metrics         *ZFSVDevMetrics           // Metrics and error counters for zfs pool
	ChildrenDataset []*StorageChildrenMetrics // Children metrics for datasets (RAID or Mirror)
	Disks           []*StorageDiskMetrics     // Metrics for disks that are not included in the RAID or mirror
	ZVols           []*StorageZVolMetrics     // Metrics for zvols from /proc/diskstats
}

// Key for pubsub ZFSPoolMetrics
func (s ZFSPoolMetrics) Key() string {
	return s.PoolName
}
