// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// VolumeKeyFromParts creates the key for OldVolumeConfig and OldVolumeStatus. It is:
// BlobSha256+AppInstID if the sha is set (common case for volumes based on downloaded blobs), otherwise
// AppInstID:VolumeID if AppInstID is set (for blank and cloudinit volumes), otherwise
// VolumeID if this is a blank, named volume (which can be shared between apps)
// In addition, if purgeCounter is non-zero, there is a "." <purgeCounter>
// at the end for all the cases.
func VolumeKeyFromParts(blobSha256 string, appInstID uuid.UUID,
	volumeID uuid.UUID, purgeCounter uint32) string {

	purgeString := ""
	if purgeCounter != 0 {
		purgeString = fmt.Sprintf(".%d", purgeCounter)
	}
	var res string
	if blobSha256 != "" {
		res = fmt.Sprintf("%s+%s", blobSha256, appInstID)
	} else if appInstID != nilUUID {
		res = fmt.Sprintf("%s:%s", appInstID, volumeID)
	} else {
		res = volumeID.String()
	}
	return res + purgeString
}

// VolumeKeyToParts parses a key of the above form
// Returns (blobSha256, appInstID, volumeID, purgeCounter)
func VolumeKeyToParts(key string) (string, uuid.UUID, uuid.UUID, uint32, error) {
	var purgeCounter uint32
	p := strings.LastIndex(key, ".")
	if p != -1 {
		count, err := strconv.ParseUint(key[p+1:], 10, 32)
		if err != nil {
			log.Error(err)
			return "", nilUUID, nilUUID, purgeCounter, err
		}
		purgeCounter = uint32(count)
		key = key[0:p]
	}
	p = strings.Index(key, "+")
	if p != -1 {
		sha := key[0:p]
		ua, err := uuid.FromString(key[p+1:])
		if err != nil {
			log.Error(err)
			return "", nilUUID, nilUUID, purgeCounter, err
		}
		return sha, ua, nilUUID, purgeCounter, nil
	}
	p = strings.Index(key, ":")
	if p != -1 {
		ua, err := uuid.FromString(key[0:p])
		if err != nil {
			log.Error(err)
			return "", nilUUID, nilUUID, purgeCounter, err
		}
		uv, err := uuid.FromString(key[p+1:])
		if err != nil {
			log.Error(err)
			return "", nilUUID, nilUUID, purgeCounter, err
		}
		return "", ua, uv, purgeCounter, nil
	}
	uv, err := uuid.FromString(key)
	if err != nil {
		log.Error(err)
		return "", nilUUID, nilUUID, purgeCounter, err
	}
	return "", nilUUID, uv, purgeCounter, nil
}

// OldVolumeConfig is a request to volumemgr to have a volume available
// for a particular application instance.
type OldVolumeConfig struct {
	BlobSha256   string
	AppInstID    uuid.UUID
	VolumeID     uuid.UUID
	PurgeCounter uint32

	DisplayName string // User-friendly name for logging

	// Information about the source/origin of the volume
	Origin         OriginType
	DownloadOrigin *DownloadOriginConfig

	// Information about the result
	MaxVolSize uint64 // Create or resize to this size
	ReadOnly   bool
	Format     zconfig.Format // Default "raw"; could be raw, qcow, qcow2, vhd
	// XXX add "directory" to format?  enum?

	// XXX if this is not needed in Status it is not needed in Config
	Target string // Default "" is interpreted as "disk"

	// XXX RefCount? free handshake? Will this ever be different than 1?
	RefCount uint
}

// Key is for pubsub; unique per object.
func (config OldVolumeConfig) Key() string {
	return VolumeKeyFromParts(config.BlobSha256, config.AppInstID,
		config.VolumeID, config.PurgeCounter)
}

// LogCreate :
func (config OldVolumeConfig) LogCreate() {
	logObject := base.NewLogObject(base.OldVolumeConfigLogType, config.DisplayName,
		config.VolumeID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("origin", config.Origin).
		AddField("max-vol-size-int64", config.MaxVolSize).
		Infof("Volume config create")
}

// LogModify :
func (config OldVolumeConfig) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.OldVolumeConfigLogType, config.DisplayName,
		config.VolumeID, config.LogKey())

	oldConfig, ok := old.(OldVolumeConfig)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of OldVolumeConfig type")
	}
	// why would we get modified?
	if oldConfig.Origin != config.Origin ||
		oldConfig.MaxVolSize != config.MaxVolSize {

		logObject.CloneAndAddField("origin", config.Origin).
			AddField("max-vol-size-int64", config.MaxVolSize).
			AddField("old-origin", oldConfig.Origin).
			AddField("old-max-vol-size-int64", oldConfig.MaxVolSize).
			Infof("Volume config modify")
	}
}

// LogDelete :
func (config OldVolumeConfig) LogDelete() {
	logObject := base.EnsureLogObject(base.OldVolumeConfigLogType, config.DisplayName,
		config.VolumeID, config.LogKey())
	logObject.CloneAndAddField("origin", config.Origin).
		AddField("max-vol-size-int64", config.MaxVolSize).
		Infof("Volume config delete")

	base.DeleteLogObject(config.LogKey())
}

// LogKey :
func (config OldVolumeConfig) LogKey() string {
	return string(base.OldVolumeConfigLogType) + "-" + config.Key()
}

// OriginType - types of origin
type OriginType uint8

// OriginTypeNone etc are the values for OriginType
const (
	OriginTypeNone      OriginType = iota
	OriginTypeBlank                // Create empty target
	OriginTypeDownload             // From DownloadOriginConfig
	OriginTypeCloudInit            // From cloud-init
)

// DownloadOriginConfig specifies the needed information for something
// which might need to be downloaded.
type DownloadOriginConfig struct {
	// ImageID - UUID of the image
	ImageID          uuid.UUID
	DatastoreID      uuid.UUID
	Name             string // XXX Do depend on URL for clobber avoidance?
	NameIsURL        bool   // If not we form URL based on datastore info
	ImageSha256      string
	IsContainer      bool
	AllowNonFreePort bool
	MaxDownSize      uint64 // Upper limit of download size

	// XXX used?
	FinalObjDir string // final Object Store

	CertificateChain []string //name of intermediate certificates
	ImageSignature   []byte   //signature of image
	SignatureKey     string   //certificate containing public key
}

// OldVolumeStatus is a response from volumemgr to have a volume available
// for a particular application instance. Its key the same as for OldVolumeConfig
type OldVolumeStatus struct {
	BlobSha256   string
	AppInstID    uuid.UUID
	VolumeID     uuid.UUID
	PurgeCounter uint32

	DisplayName string // User-friendly name for logging
	ObjType     string

	PendingAdd    bool
	PendingModify bool
	PendingDelete bool

	VolumeCreated bool // Done aka Activated

	// Information about the source/origin of the volume
	Origin         OriginType
	DownloadOrigin *DownloadOriginStatus

	MaxVolSize uint64 // Create or resize to this size
	ReadOnly   bool

	WaitingForCerts bool

	State       SwState // DOWNLOADED etc
	TotalSize   int64   // expected size as reported by the downloader, if any
	CurrentSize int64   // current total downloaded size as reported by the downloader
	Progress    uint    // In percent i.e., 0-100
	// ErrorAndTimeWithSource provides SetError, SetErrrorWithSource, etc
	ErrorAndTimeWithSource

	FileLocation string // Current location; should be info about file

	// Blobs the sha256 hashes of the blobs that are in this tree, the first of which always is the root
	Blobs []string

	Format zconfig.Format // Default "raw"; could be raw, qcow, qcow2, vhd

	RefCount  uint
	LastUse   time.Time // When RefCount dropped to zero
	PreReboot bool      // Was volume last use prior to device reboot?
}

// Key is for pubsub; unique per object.
func (status OldVolumeStatus) Key() string {
	return VolumeKeyFromParts(status.BlobSha256, status.AppInstID,
		status.VolumeID, status.PurgeCounter)
}

// Pending returns if any of the pending flags are set
func (status OldVolumeStatus) Pending() bool {
	return status.PendingAdd || status.PendingModify || status.PendingDelete
}

// LogCreate :
func (status OldVolumeStatus) LogCreate() {
	logObject := base.NewLogObject(base.OldVolumeStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("volume-created", status.VolumeCreated).
		Infof("Volume status create")
}

// LogModify :
func (status OldVolumeStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.OldVolumeStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())

	oldStatus, ok := old.(OldVolumeStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of OldVolumeStatus type")
	}
	if oldStatus.State != status.State ||
		oldStatus.VolumeCreated != status.VolumeCreated {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("volume-created", status.VolumeCreated).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-volume-created", oldStatus.VolumeCreated).
			Infof("Volume status modify")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime()
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("volume-created", status.VolumeCreated).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Errorf("Volume status modify")
	}
}

// LogDelete :
func (status OldVolumeStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.OldVolumeStatusLogType, status.DisplayName,
		status.VolumeID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("volume-created", status.VolumeCreated).
		Infof("Volume status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status OldVolumeStatus) LogKey() string {
	return string(base.OldVolumeStatusLogType) + "-" + status.Key()
}

// DownloadOriginStatus is status when the OriginType is download
type DownloadOriginStatus struct {
	DownloadOriginConfig

	HasDownloaderRef bool // Reference against downloader to clean up
	HasVerifierRef   bool // Reference against verifier to clean up
	HasPersistRef    bool // Reference against PersistImage to clean up (maintained by volumeMgr)
}
