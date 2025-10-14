// Package zfs implements basic manipulation of ZFS pools and data sets.
// Use libzfs C library instead CLI zfs tools, with goal
// to let using and manipulating OpenZFS form with in go project.
//
// TODO: Adding to the pool. (Add the given vdevs to the pool)
// TODO: Scan for pools.
package zfs

/*
#cgo CFLAGS: -I /usr/include/libzfs -I /usr/include/libspl -DHAVE_IOCTL_IN_SYS_IOCTL_H -D_GNU_SOURCE
#cgo LDFLAGS: -lzfs -lzpool -lnvpair

#include <stdlib.h>
#include <libzfs.h>
#include "common.h"
#include "zpool.h"
#include "zfs.h"
*/
import "C"

import (
	"errors"
	"sync"
)

// VDevType type of device in the pool
type VDevType string

func init() {
	C.go_libzfs_init()
	return
}

// Types of Virtual Devices
const (
	VDevTypeRoot      VDevType = "root"      // VDevTypeRoot root device in ZFS pool
	VDevTypeMirror             = "mirror"    // VDevTypeMirror mirror device in ZFS pool
	VDevTypeReplacing          = "replacing" // VDevTypeReplacing replacing
	VDevTypeRaidz              = "raidz"     // VDevTypeRaidz RAIDZ device
	VDevTypeDisk               = "disk"      // VDevTypeDisk device is disk
	VDevTypeFile               = "file"      // VDevTypeFile device is file
	VDevTypeMissing            = "missing"   // VDevTypeMissing missing device
	VDevTypeHole               = "hole"      // VDevTypeHole hole
	VDevTypeSpare              = "spare"     // VDevTypeSpare spare device
	VDevTypeLog                = "log"       // VDevTypeLog ZIL device
	VDevTypeL2cache            = "l2cache"   // VDevTypeL2cache cache device (disk)
)

// Prop type to enumerate all different properties suppoerted by ZFS
type Prop int

// PoolStatus type representing status of the pool
type PoolStatus int

// PoolState type representing pool state
type PoolState uint64

// VDevState - vdev states tye
type VDevState uint64

// VDevAux - vdev aux states
type VDevAux uint64

// Property ZFS pool or dataset property value
type Property struct {
	Value  string
	Source string
}

var Global struct {
	Mtx sync.Mutex
}

// Pool status
const (
	/*
	 * The following correspond to faults as defined in the (fault.fs.zfs.*)
	 * event namespace.  Each is associated with a corresponding message ID.
	 */
	PoolStatusCorruptCache      PoolStatus = iota /* corrupt /kernel/drv/zpool.cache */
	PoolStatusMissingDevR                         /* missing device with replicas */
	PoolStatusMissingDevNr                        /* missing device with no replicas */
	PoolStatusCorruptLabelR                       /* bad device label with replicas */
	PoolStatusCorruptLabelNr                      /* bad device label with no replicas */
	PoolStatusBadGUIDSum                          /* sum of device guids didn't match */
	PoolStatusCorruptPool                         /* pool metadata is corrupted */
	PoolStatusCorruptData                         /* data errors in user (meta)data */
	PoolStatusFailingDev                          /* device experiencing errors */
	PoolStatusVersionNewer                        /* newer on-disk version */
	PoolStatusHostidMismatch                      /* last accessed by another system */
	PoolStatusHosidActive                         /* currently active on another system */
	PoolStatusHostidRequired                      /* multihost=on and hostid=0 */
	PoolStatusIoFailureWait                       /* failed I/O, failmode 'wait' */
	PoolStatusIoFailureContinue                   /* failed I/O, failmode 'continue' */
	PoolStatusIOFailureMap                        /* ailed MMP, failmode not 'panic' */
	PoolStatusBadLog                              /* cannot read log chain(s) */
	PoolStatusErrata                              /* informational errata available */

	/*
	 * If the pool has unsupported features but can still be opened in
	 * read-only mode, its status is ZPOOL_STATUS_UNSUP_FEAT_WRITE. If the
	 * pool has unsupported features but cannot be opened at all, its
	 * status is ZPOOL_STATUS_UNSUP_FEAT_READ.
	 */
	PoolStatusUnsupFeatRead  /* unsupported features for read */
	PoolStatusUnsupFeatWrite /* unsupported features for write */

	/*
	 * These faults have no corresponding message ID.  At the time we are
	 * checking the status, the original reason for the FMA fault (I/O or
	 * checksum errors) has been lost.
	 */
	PoolStatusFaultedDevR  /* faulted device with replicas */
	PoolStatusFaultedDevNr /* faulted device with no replicas */

	/*
	 * The following are not faults per se, but still an error possibly
	 * requiring administrative attention.  There is no corresponding
	 * message ID.
	 */
	PoolStatusVersionOlder /* older legacy on-disk version */
	PoolStatusFeatDisabled /* supported features are disabled */
	PoolStatusResilvering  /* device being resilvered */
	PoolStatusOfflineDev   /* device online */
	PoolStatusRemovedDev   /* removed device */

	/*
	 * Finally, the following indicates a healthy pool.
	 */
	PoolStatusOk
)

// Possible ZFS pool states
const (
	PoolStateActive            PoolState = iota /* In active use		*/
	PoolStateExported                           /* Explicitly exported		*/
	PoolStateDestroyed                          /* Explicitly destroyed		*/
	PoolStateSpare                              /* Reserved for hot spare use	*/
	PoolStateL2cache                            /* Level 2 ARC device		*/
	PoolStateUninitialized                      /* Internal spa_t state		*/
	PoolStateUnavail                            /* Internal libzfs state	*/
	PoolStatePotentiallyActive                  /* Internal libzfs state	*/
)

// Pool properties. Enumerates available ZFS pool properties. Use it to access
// pool properties either to read or set soecific property.
const (
	PoolPropCont Prop = iota - 2
	PoolPropInval
	PoolPropName
	PoolPropSize
	PoolPropCapacity
	PoolPropAltroot
	PoolPropHealth
	PoolPropGUID
	PoolPropVersion
	PoolPropBootfs
	PoolPropDelegation
	PoolPropAutoreplace
	PoolPropCachefile
	PoolPropFailuremode
	PoolPropListsnaps
	PoolPropAutoexpand
	PoolPropDedupditto
	PoolPropDedupratio
	PoolPropFree
	PoolPropAllocated
	PoolPropReadonly
	PoolPropAshift
	PoolPropComment
	PoolPropExpandsz
	PoolPropFreeing
	PoolPropFragmentaion
	PoolPropLeaked
	PoolPropMaxBlockSize
	PoolPropTName
	PoolPropMaxDNodeSize
	PoolPropMultiHost
	PoolPropCheckpoint
	PoolPropLoadGUID
	PoolPropAutotrim
	PoolPropCompatibility
	PoolPropBcloneUsed
	PoolPropBcloneSaved
	PoolPropBcloneRatio
	PoolPropDedupTableSize
	PoolPropDedupTableQuota
	PoolPropDedupcached
	PoolPropLastScrubbedTxg
	PoolNumProps
)

/*
 * Dataset properties are identified by these constants and must be added to
 * the end of this list to ensure that external consumers are not affected
 * by the change. If you make any changes to this list, be sure to update
 * the property table in module/zcommon/zfs_prop.c.
 */
const (
	DatasetPropCont Prop = iota - 2
	DatasetPropBad
	DatasetPropType
	DatasetPropCreation
	DatasetPropUsed
	DatasetPropAvailable
	DatasetPropReferenced
	DatasetPropCompressratio
	DatasetPropMounted
	DatasetPropOrigin
	DatasetPropQuota
	DatasetPropReservation
	DatasetPropVolsize
	DatasetPropVolblocksize
	DatasetPropRecordsize
	DatasetPropMountpoint
	DatasetPropSharenfs
	DatasetPropChecksum
	DatasetPropCompression
	DatasetPropAtime
	DatasetPropDevices
	DatasetPropExec
	DatasetPropSetuid
	DatasetPropReadonly
	DatasetPropZoned
	DatasetPropSnapdir
	DatasetPropPrivate /* not exposed to user, temporary */
	DatasetPropAclinherit
	DatasetPropCreateTXG /* not exposed to the user */
	DatasetPropName      /* not exposed to the user */
	DatasetPropCanmount
	DatasetPropIscsioptions /* not exposed to the user */
	DatasetPropXattr
	DatasetPropNumclones /* not exposed to the user */
	DatasetPropCopies
	DatasetPropVersion
	DatasetPropUtf8only
	DatasetPropNormalize
	DatasetPropCase
	DatasetPropVscan
	DatasetPropNbmand
	DatasetPropSharesmb
	DatasetPropRefquota
	DatasetPropRefreservation
	DatasetPropGUID
	DatasetPropPrimarycache
	DatasetPropSecondarycache
	DatasetPropUsedsnap
	DatasetPropUsedds
	DatasetPropUsedchild
	DatasetPropUsedrefreserv
	DatasetPropUseraccounting /* not exposed to the user */
	DatasetPropStmfShareinfo  /* not exposed to the user */
	DatasetPropDeferDestroy
	DatasetPropUserrefs
	DatasetPropLogbias
	DatasetPropUnique   /* not exposed to the user */
	DatasetPropObjsetid /* not exposed to the user */
	DatasetPropDedup
	DatasetPropMlslabel
	DatasetPropSync
	DatasetPropDnodeSize
	DatasetPropRefratio
	DatasetPropWritten
	DatasetPropClones
	DatasetPropLogicalused
	DatasetPropLogicalreferenced
	DatasetPropInconsistent /* not exposed to the user */
	DatasetPropVolmode
	DatasetPropFilesystemLimit
	DatasetPropSnapshotLimit
	DatasetPropFilesystemCount
	DatasetPropSnapshotCount
	DatasetPropSnapdev
	DatasetPropAcltype
	DatasetPropSelinuxContext
	DatasetPropSelinuxFsContext
	DatasetPropSelinuxDefContext
	DatasetPropSelinuxRootContext
	DatasetPropRelatime
	DatasetPropRedundantMetadata
	DatasetPropOverlay
	DatasetPropPrevSnap
	DatasetPropReceiveResumeToken
	DatasetPropEncryption
	DatasetPropKeyLocation
	DatasetPropKeyFormat
	DatasetPropPBKDF2Salt
	DatasetPropPBKDF2Iters
	DatasetPropEncryptionRoot
	DatasetPropKeyGUID
	DatasetPropKeyStatus
	DatasetPropRemapTXG /* not exposed to the user */
	DatasetPropSpecialSmallBlocks
	DatasetPropIVSetGuid /* not exposed to the user */
	DatasetPropRedacted
	DatasetPropRedactSnaps
	DatasetPropSnapshotsChanged
	DatasetNumProps
)

// LastError get last underlying libzfs error description if any
func LastError() (err error) {
	return errors.New(C.GoString(C.libzfs_last_error_str()))
}

// ClearLastError force clear of any last error set by undeliying libzfs
func ClearLastError() (err error) {
	err = LastError()
	C.libzfs_clear_last_error()
	return
}

func booleanT(b bool) (r C.boolean_t) {
	if b {
		return 1
	}
	return 0
}

// ZFS errors
const (
	ESuccess              = 0               /* no error -- success */
	ENomem                = 2000 + iota - 1 /* out of memory */
	EBadprop                                /* invalid property value */
	EPropreadonly                           /* cannot set readonly property */
	EProptype                               /* property does not apply to dataset type */
	EPropnoninherit                         /* property is not inheritable */
	EPropspace                              /* bad quota or reservation */
	EBadtype                                /* dataset is not of appropriate type */
	EBusy                                   /* pool or dataset is busy */
	EExists                                 /* pool or dataset already exists */
	ENoent                                  /* no such pool or dataset */
	EBadstream                              /* bad backup stream */
	EDsreadonly                             /* dataset is readonly */
	EVoltoobig                              /* volume is too large for 32-bit system */
	EInvalidname                            /* invalid dataset name */
	EBadrestore                             /* unable to restore to destination */
	EBadbackup                              /* backup failed */
	EBadtarget                              /* bad attach/detach/replace target */
	ENodevice                               /* no such device in pool */
	EBaddev                                 /* invalid device to add */
	ENoreplicas                             /* no valid replicas */
	EResilvering                            /* currently resilvering */
	EBadversion                             /* unsupported version */
	EPoolunavail                            /* pool is currently unavailable */
	EDevoverflow                            /* too many devices in one vdev */
	EBadpath                                /* must be an absolute path */
	ECrosstarget                            /* rename or clone across pool or dataset */
	EZoned                                  /* used improperly in local zone */
	EMountfailed                            /* failed to mount dataset */
	EUmountfailed                           /* failed to unmount dataset */
	EUnsharenfsfailed                       /* unshare(1M) failed */
	ESharenfsfailed                         /* share(1M) failed */
	EPerm                                   /* permission denied */
	ENospc                                  /* out of space */
	EFault                                  /* bad address */
	EIo                                     /* I/O error */
	EIntr                                   /* signal received */
	EIsspare                                /* device is a hot spare */
	EInvalconfig                            /* invalid vdev configuration */
	ERecursive                              /* recursive dependency */
	ENohistory                              /* no history object */
	EPoolprops                              /* couldn't retrieve pool props */
	EPoolNotsup                             /* ops not supported for this type of pool */
	EPoolInvalarg                           /* invalid argument for this pool operation */
	ENametoolong                            /* dataset name is too long */
	EOpenfailed                             /* open of device failed */
	ENocap                                  /* couldn't get capacity */
	ELabelfailed                            /* write of label failed */
	EBadwho                                 /* invalid permission who */
	EBadperm                                /* invalid permission */
	EBadpermset                             /* invalid permission set name */
	ENodelegation                           /* delegated administration is disabled */
	EUnsharesmbfailed                       /* failed to unshare over smb */
	ESharesmbfailed                         /* failed to share over smb */
	EBadcache                               /* bad cache file */
	EIsl2CACHE                              /* device is for the level 2 ARC */
	EVdevnotsup                             /* unsupported vdev type */
	ENotsup                                 /* ops not supported on this dataset */
	EActiveSpare                            /* pool has active shared spare devices */
	EUnplayedLogs                           /* log device has unplayed logs */
	EReftagRele                             /* snapshot release: tag not found */
	EReftagHold                             /* snapshot hold: tag already exists */
	ETagtoolong                             /* snapshot hold/rele: tag too long */
	EPipefailed                             /* pipe create failed */
	EThreadcreatefailed                     /* thread create failed */
	EPostsplitOnline                        /* onlining a disk after splitting it */
	EScrubbing                              /* currently scrubbing */
	ENoScrub                                /* no active scrub */
	EDiff                                   /* general failure of zfs diff */
	EDiffdata                               /* bad zfs diff data */
	EPoolreadonly                           /* pool is in read-only mode */
	EScrubpaused                            /* scrub currently paused */
	EActivepool                             /* pool is imported on a different system */
	ECryptofailed                           /* failed to setup encryption */
	ENopending                              /* cannot cancel, no operation is pending */
	ECheckpointExists                       /* checkpoint exists */
	EDiscardingCheckpoint                   /* currently discarding a checkpoint */
	ENoCheckpoint                           /* pool has no checkpoint */
	EDevrmInProgress                        /* a device is currently being removed */
	EVdevTooBig                             /* a device is too big to be used */
	EIocNotsupported                        /* operation not supported by zfs module */
	EToomany                                /* argument list too long */
	EInitializing                           /* currently initializing */
	ENoInitialize                           /* no active initialize */
	EWrongParent                            /* invalid parent dataset (e.g ZVOL) */
	ETrimming                               /* currently trimming */
	ENoTrim                                 /* no active trim */
	ETrimNotsup                             /* device does not support trim */
	ENoResilverDefer                        /* pool doesn't support resilver_defer */
	EExportInProgress                       /* currently exporting the pool */
	ERebuilding                             /* resilvering (sequential reconstrution) */
	EVdevNotSup                             /* ops not supported for this type of vdev */
	ENotUserNamespace                       /* a file is not a user namespace */
	ECksum                                  /* insufficient replicas */
	EResumeExists                           /* resume on existing dataset without force */
	EShareFailed                            /* filesystem share failed */
	EUnknown
)

// vdev states are ordered from least to most healthy.
// A vdev that's VDevStateCantOpen or below is considered unusable.
const (
	VDevStateUnknown  VDevState = iota // Uninitialized vdev
	VDevStateClosed                    // Not currently open
	VDevStateOffline                   // Not allowed to open
	VDevStateRemoved                   // Explicitly removed from system
	VDevStateCantOpen                  // Tried to open, but failed
	VDevStateFaulted                   // External request to fault device
	VDevStateDegraded                  // Replicated vdev with unhealthy kids
	VDevStateHealthy                   // Presumed good
)

// vdev aux states.  When a vdev is in the VDevStateCantOpen state, the aux field
// of the vdev stats structure uses these constants to distinguish why.
const (
	VDevAuxNone         VDevAux = iota // no error
	VDevAuxOpenFailed                  // ldi_open_*() or vn_open() failed
	VDevAuxCorruptData                 // bad label or disk contents
	VDevAuxNoReplicas                  // insufficient number of replicas
	VDevAuxBadGUIDSum                  // vdev guid sum doesn't match
	VDevAuxTooSmall                    // vdev size is too small
	VDevAuxBadLabel                    // the label is OK but invalid
	VDevAuxVersionNewer                // on-disk version is too new
	VDevAuxVersionOlder                // on-disk version is too old
	VDevAuxUnsupFeat                   // unsupported features
	VDevAuxSpared                      // hot spare used in another pool
	VDevAuxErrExceeded                 // too many errors
	VDevAuxIOFailure                   // experienced I/O failure
	VDevAuxBadLog                      // cannot read log chain(s)
	VDevAuxExternal                    // external diagnosis
	VDevAuxSplitPool                   // vdev was split off into another pool
)

// status strings used by the zfs CLI when reporting zpool status.
// These make it easier for users of this library to report status.
const (
	MsgPoolStatusMissingDevR       = `One or more devices could not be opened.  Sufficient replicas exist for the pool to continue functioning in a degraded state.`
	MsgPoolStatusMissingDevNr      = `One or more devices could not be opened.  There are insufficient replicas for the pool to continue functioning.`
	MsgPoolStatusCorruptLabelR     = `One or more devices could not be used because the label is missing or invalid. Sufficient replicas exist for the pool to continue functioning in a degraded state.`
	MsgPoolStatusCorruptLabelNr    = `One or more devices could not be used because the label is missing or invalid. There are insufficient replicas for the pool to continue functioning.`
	MsgPoolStatusCorruptPool       = `The pool metadata is corrupted and the pool cannot be opened.`
	MsgPoolStatusCorruptData       = `One or more devices has experienced an error resulting in data corruption. Applications may be affected.`
	MsgPoolStatusFailingDev        = `One or more devices has experienced an unrecoverable error. An attempt was made to correct the error.  Applications are unaffected.`
	MsgPoolStatusOfflineDev        = `One or more devices has been taken offline by the administrator. Sufficient replicas exist for the pool to continue functioning in a degraded state.`
	MsgPoolStatusRemovedDev        = `One or more devices has been removed by the administrator. Sufficient replicas exist for the pool to continue functioning in a degraded state.`
	MsgPoolStatusResilvering       = `One or more devices is currently being resilvered. The pool will continue to function, possibly in a degraded state.`
	MsgPoolStatusRebuilding        = MsgPoolStatusResilvering
	MsgPoolStatusVersionNewer      = `The pool has been upgraded to a newer, incompatible on-disk version. The pool cannot be accessed on this system.`
	MsgPoolStatusVersionOlder      = `The pool is formatted using a legacy on-disk format.  The pool can still be used, but some features are unavailable.`
	MsgPoolStatusFeatDisabled      = `Some supported and requested features are not enabled on the pool. The pool can still be used, but some features are unavailable.`
	MsgPoolStatusUnsupFeatRead     = `The pool cannot be accessed on this system because it uses feature(s) not supported on this system.`
	MsgPoolStatusUnsupFeatWrite    = `The pool can only be accessed in read-only mode on this system. It cannot be accessed in read-write mode because it uses feature(s) not supported on this system.`
	MsgPoolStatusFaultedDevR       = `One or more devices are faulted in response to persistent errors. Sufficient replicas exist for the pool to continue functioning in a degraded state.`
	MsgPoolStatusFaultedDevNr      = `One or more devices are faulted in response to persistent errors. There are insufficient replicas for the pool to continue functioning.`
	MsgPoolStatusHostidMismatch    = `Mismatch between pool hostid and system hostid on imported pool. This pool was previously imported into a system with a different hostid, and then was verbatim imported into this system.`
	MsgPoolStatusHosidActive       = `The pool is currently imported by another system.`
	MsgPoolStatusHostidRequired    = `The pool has the multihost property on.  It cannot be safely imported when the system hostid is not set.`
	MsgPoolStatusIoFailureWait     = `One or more devices are faulted in response to IO failures.`
	MsgPoolStatusIoFailureContinue = MsgPoolStatusIoFailureWait
	MsgPoolStatusIOFailureMap      = `The pool is suspended because multihost writes failed or were delayed; another system could import the pool undetected.`
	MsgPoolStatusBadLog            = `An intent log record could not be read. Waiting for administrator intervention to fix the faulted pool.`
	MsgPoolStatusErrata            = `Errate detected.`
)

// action strings
const (
	ActionPoolStatusMissingDevR       = `Attach the missing device and online it using 'zpool online'.`
	ActionPoolStatusMissingDevNr      = `Attach the missing device and online it using 'zpool online'.`
	ActionPoolStatusCorruptLabelR     = `Replace the device using 'zpool replace'.`
	ActionPoolStatusCorruptLabelNr    = ``
	ActionPoolStatusCorruptPool       = ``
	ActionPoolStatusCorruptData       = `Restore the file in question if possible.  Otherwise restore the entire pool from backup.`
	ActionPoolStatusFailingDev        = `Determine if the device needs to be replaced, and clear the errors using 'zpool clear' or replace the device with 'zpool replace'.`
	ActionPoolStatusOfflineDev        = `Online the device using 'zpool online' or replace the device with 'zpool replace'.`
	ActionPoolStatusRemovedDev        = `Online the device using zpool online' or replace the device with 'zpool replace'.`
	ActionPoolStatusResilvering       = `Wait for the resilver to complete.`
	ActionPoolStatusRebuilding        = ActionPoolStatusResilvering
	ActionPoolStatusVersionNewer      = `Access the pool from a system running more recent software, or restore the pool from backup.`
	ActionPoolStatusVersionOlder      = `Upgrade the pool using 'zpool upgrade'.  Once this is done, the pool will no longer be accessible on software that does not support feature flags.`
	ActionPoolStatusFeatDisabled      = `Enable all features using 'zpool upgrade'. Once this is done, the pool may no longer be accessible by software that does not support the features. See zpool-features(7) for details.`
	ActionPoolStatusUnsupFeatRead     = `Access the pool from a system that supports the required feature(s), or restore the pool from backup.`
	ActionPoolStatusUnsupFeatWrite    = `The pool cannot be accessed in read-write mode. Import the pool with "-o readonly=on", access the pool from a system that supports the required feature(s), or restore the pool from backup.`
	ActionPoolStatusFaultedDevR       = `Replace the faulted device, or use 'zpool clear' to mark the device repaired.`
	ActionPoolStatusFaultedDevNr      = `Destroy and re-create the pool from a backup source.  Manually marking the device repaired using 'zpool clear' may allow some data to be recovered.`
	ActionPoolStatusHostidMismatch    = `Export this pool on all systems on which it is imported. Then import it to correct the mismatch.`
	ActionPoolStatusHosidActive       = ``
	ActionPoolStatusHostidRequired    = ``
	ActionPoolStatusIoFailureWait     = `Make sure the affected devices are connected, then run 'zpool clear'.`
	ActionPoolStatusIoFailureContinue = ActionPoolStatusIoFailureWait
	ActionPoolStatusIOFailureMap      = `Make sure the pool's devices are connected, then reboot your system and import the pool.`
	ActionPoolStatusBadLog            = `Either restore the affected device(s) and run 'zpool online', or ignore the intent log records by running 'zpool clear'.`
	ActionPoolStatusErrata            = ``
)

// GetStatusMessages get the status and action message for a given PoolStatus.
// If none is available, return "" for each.
func GetStatusMessages(status PoolStatus) (msg, action string) {
	switch status {
	case PoolStatusCorruptCache:
		// no msg or status for this, but leaving blank as a sign for later
	case PoolStatusMissingDevNr:
		msg = MsgPoolStatusMissingDevNr
		action = ActionPoolStatusMissingDevNr
	case PoolStatusCorruptLabelR:
		msg = MsgPoolStatusCorruptLabelR
		action = ActionPoolStatusCorruptLabelR
	case PoolStatusCorruptLabelNr:
		msg = MsgPoolStatusCorruptLabelNr
		action = ActionPoolStatusCorruptLabelNr
	case PoolStatusBadGUIDSum:
		// no msg or status for this, but leaving blank as a sign for later
	case PoolStatusCorruptPool:
		msg = MsgPoolStatusCorruptPool
		action = ActionPoolStatusCorruptPool
	case PoolStatusCorruptData:
		msg = MsgPoolStatusCorruptData
		action = ActionPoolStatusCorruptData
	case PoolStatusFailingDev:
		msg = MsgPoolStatusFailingDev
		action = ActionPoolStatusFailingDev
	case PoolStatusVersionNewer:
		msg = MsgPoolStatusVersionNewer
		action = ActionPoolStatusVersionNewer
	case PoolStatusHostidMismatch:
		msg = MsgPoolStatusHostidMismatch
		action = ActionPoolStatusHostidMismatch
	case PoolStatusHosidActive:
		msg = MsgPoolStatusHosidActive
		action = ActionPoolStatusHosidActive
	case PoolStatusHostidRequired:
		msg = MsgPoolStatusHostidRequired
		action = ActionPoolStatusHostidRequired
	case PoolStatusIoFailureWait:
		msg = MsgPoolStatusIoFailureWait
		action = ActionPoolStatusIoFailureWait
	case PoolStatusIoFailureContinue:
		msg = MsgPoolStatusIoFailureContinue
		action = ActionPoolStatusIoFailureContinue
	case PoolStatusIOFailureMap:
		msg = MsgPoolStatusIOFailureMap
		action = ActionPoolStatusIOFailureMap
	case PoolStatusBadLog:
		msg = MsgPoolStatusBadLog
		action = ActionPoolStatusBadLog
	case PoolStatusErrata:
		msg = MsgPoolStatusErrata
		action = ActionPoolStatusErrata
	case PoolStatusUnsupFeatRead:
		msg = MsgPoolStatusUnsupFeatRead
		action = ActionPoolStatusUnsupFeatRead
	case PoolStatusUnsupFeatWrite:
		msg = MsgPoolStatusUnsupFeatWrite
		action = ActionPoolStatusUnsupFeatWrite
	case PoolStatusFaultedDevR:
		msg = MsgPoolStatusFaultedDevR
		action = ActionPoolStatusFaultedDevR
	case PoolStatusFaultedDevNr:
		msg = MsgPoolStatusFaultedDevNr
		action = ActionPoolStatusFaultedDevNr
	case PoolStatusVersionOlder:
		msg = MsgPoolStatusVersionOlder
		action = ActionPoolStatusVersionOlder
	case PoolStatusFeatDisabled:
		msg = MsgPoolStatusFeatDisabled
		action = ActionPoolStatusFeatDisabled
	case PoolStatusResilvering:
		msg = MsgPoolStatusResilvering
		action = ActionPoolStatusResilvering
	case PoolStatusOfflineDev:
		msg = MsgPoolStatusOfflineDev
		action = ActionPoolStatusOfflineDev
	case PoolStatusRemovedDev:
		msg = MsgPoolStatusRemovedDev
		action = ActionPoolStatusRemovedDev
	case PoolStatusOk:
		msg = ""
		action = ""
	}
	return msg, action
}
