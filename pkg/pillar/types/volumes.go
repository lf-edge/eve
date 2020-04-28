// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// VolumeKeyFromParts creates the key for VolumeConfig and VolumeStatus. It is:
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

// VolumeConfig is a request to volumemgr to have a volume available
// for a particular application instance.
type VolumeConfig struct {
	BlobSha256   string
	AppInstID    uuid.UUID
	VolumeID     uuid.UUID
	PurgeCounter uint32

	DisplayName string // User-friendly name for logging

	// Information about the source/origin of the volume
	Origin         OriginType
	DownloadOrigin *DownloadOriginConfig

	// Information about the result
	TargetSizeBytes uint64 // Create or resize to this size
	ReadOnly        bool
	// XXX Preserve    bool // If set a rw disk will be preserved across
	// boots (acivate/inactivate)
	// XXX Preserve is only interpreted by domainmgr?? Need new on reboot?
	// XXX drop/ignore Preserve?
	Format zconfig.Format // Default "raw"; could be raw, qcow, qcow2, vhd
	// XXX add "directory" to format?  enum?

	// XXX if these are not needed in Status they are not needed in Config
	Devtype string // Default ""; could be e.g. "cdrom"
	Target  string // Default "" is interpreted as "disk"

	// XXX RefCount? free handshake? Will this ever be different than 1?
	RefCount uint
}

// Key is for pubsub; unique per object.
func (config VolumeConfig) Key() string {
	return VolumeKeyFromParts(config.BlobSha256, config.AppInstID,
		config.VolumeID, config.PurgeCounter)
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
	MaxSizeBytes     uint64 // Upper limit

	// XXX used?
	FinalObjDir string // final Object Store

	CertificateChain []string //name of intermediate certificates
	ImageSignature   []byte   //signature of image
	SignatureKey     string   //certificate containing public key
}

// VolumeStatus is a response from volumemgr to have a volume available
// for a particular application instance. Its key the same as for VolumeConfig
type VolumeStatus struct {
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

	TargetSizeBytes uint64 // Create or resize to this size
	ReadOnly        bool

	WaitingForCerts bool

	State    SwState // DOWNLOADED etc
	Progress uint    // In percent i.e., 0-100
	// ErrorAndTimeWithSource provides SetError, SetErrrorWithSource, etc
	ErrorAndTimeWithSource

	FileLocation string // Current location; should be info about file

	Format zconfig.Format // Default "raw"; could be raw, qcow, qcow2, vhd

	RefCount  uint
	LastUse   time.Time // When RefCount dropped to zero
	PreReboot bool      // Was volume last use prior to device reboot?

	ReservedSpace uint64 // Contribution to global ReservedSpace
	Size          uint64 // Once DOWNLOADED; in bytes

	RetryCount int
}

// Key is for pubsub; unique per object.
func (status VolumeStatus) Key() string {
	return VolumeKeyFromParts(status.BlobSha256, status.AppInstID,
		status.VolumeID, status.PurgeCounter)
}

// Pending returns if any of the pending flags are set
func (status VolumeStatus) Pending() bool {
	return status.PendingAdd || status.PendingModify || status.PendingDelete
}

// DownloadOriginStatus is status when the OriginType is download
type DownloadOriginStatus struct {
	DownloadOriginConfig

	HasDownloaderRef bool // Reference against downloader to clean up
	HasVerifierRef   bool // Reference against verifier to clean up
}
