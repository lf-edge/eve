// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	uuid "github.com/satori/go.uuid"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// PatchEnvelopeURLPath is route used for patch envelopes
// it is used in URL composing of patch envelopes
const PatchEnvelopeURLPath = "/eve/v1/patch/"

// PatchEnvelopes is a structure representing
// Patch Envelopes exposed to App instances via metadata server
// for more info check docs/PATCH-ENVELOPES.md
// Must be created by calling NewPatchEnvelopes()
//
// Internally, PatchEnvelopes structure stores envelopes which
// come from EdgeDevConfig parsed by zedagent. This envelopes contains
// both inline binary artifacts which are ready to be downloaded by app instances
// and volume references, which are handled by volumemgr.
// So PatchEnvelopes struct has completedVolumes and contentTreeStatus to store
// information of all volumes and contentTree handled by volumemgr to link them with
// patch envelope volume references. ContentTreeStatus is used to retrieve SHA of underlying
// file.
// App instances are accessing PatchEnvelopes via metadata server handlers, which is calling
// PatchEnvelopes.Get() method to get list of available PatchEnvelopeInfo
// to certain App Instance which are stored in currentState.
// PatchEnvelopes also hasupdateStateNotificationCh channel
// to receive notification about the need of updating specified PatchEnvelopes.
// updateStateNotificationCh has length of 1, so update queue will never pile up.
// When updating state, we iterate through all envelopes, and remove envelopes which
// are marked in envelopesToDelete boolean map (set).
// NewPatchEnvelopes() starts goroutine processStateUpdate() which reads from the channel and updates
// currentState to desired one. In addition, this goroutine publishes status for every PatchEnvelope
// via pubsub. Note that PatchEnvelopes does not create PubSub, rather used one provided to NewPatchEnvelopes()
// So it does not have a agentName, but could easily be split into one if needed
// This way handlers can do work of determining which patch envelopes actually need change (if any)
// and send back in go routine rest of the update including slow work.
// Note that this channels are only accessible from the outside by calling a function which returns
// write-only channel, meaning that updateStateNotificationCh should not be
// read from anywhere except processStateUpdate() so that there could not be any deadlock.
type PatchEnvelopes struct {
	sync.RWMutex

	updateStateNotificationCh chan struct{}

	envelopesToDelete *generics.LockedMap[uuid.UUID, bool]

	currentState      *generics.LockedMap[uuid.UUID, types.PatchEnvelopeInfo]
	envelopes         *generics.LockedMap[uuid.UUID, types.PatchEnvelopeInfo]
	completedVolumes  *generics.LockedMap[uuid.UUID, types.VolumeStatus]
	contentTreeStatus *generics.LockedMap[uuid.UUID, types.ContentTreeStatus]

	pubSub                *pubsub.PubSub
	log                   *base.LogObject
	pubPatchEnvelopeState pubsub.Publication

	msrv *Msrv
}

// UpdateStateNotificationCh return update channel to send notifications to update currentState
func (pes *PatchEnvelopes) UpdateStateNotificationCh() chan<- struct{} {
	return pes.updateStateNotificationCh
}

// NewPatchEnvelopes returns PatchEnvelopes structure and starts goroutine
// to process notifications from channel. Note that we create buffered channel
// to avoid unbounded processing time in writing to channel
func NewPatchEnvelopes(msrv *Msrv) *PatchEnvelopes {
	pe := &PatchEnvelopes{

		updateStateNotificationCh: make(chan struct{}, 1),

		envelopesToDelete: generics.NewLockedMap[uuid.UUID, bool](),

		currentState:      generics.NewLockedMap[uuid.UUID, types.PatchEnvelopeInfo](),
		envelopes:         generics.NewLockedMap[uuid.UUID, types.PatchEnvelopeInfo](),
		completedVolumes:  generics.NewLockedMap[uuid.UUID, types.VolumeStatus](),
		contentTreeStatus: generics.NewLockedMap[uuid.UUID, types.ContentTreeStatus](),

		log:    msrv.Log,
		pubSub: msrv.PubSub,
		msrv:   msrv,
	}

	var err error
	pe.pubPatchEnvelopeState, err = pe.pubSub.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.PatchEnvelopeInfo{},
	})
	if err != nil {
		return nil
	}

	go pe.processStateUpdate()

	return pe
}

func (pes *PatchEnvelopes) processStateUpdate() {
	for {
		select {
		case <-pes.updateStateNotificationCh:
			pes.updateState()
		}
	}
}

func (pes *PatchEnvelopes) updateState() {
	pes.Lock()
	defer pes.Unlock()

	keys := pes.envelopesToDelete.Keys()
	for _, k := range keys {
		if toDelete, _ := pes.envelopesToDelete.Load(k); toDelete {
			if peInfo, ok := pes.currentState.Load(k); ok {
				pes.unpublishPatchEnvelopeInfo(&peInfo)
			}
			pes.currentState.Delete(k)
			pes.envelopesToDelete.Store(k, false)
		}
	}

	keys = pes.envelopes.Keys()
	for _, peUUID := range keys {
		if pe, ok := pes.envelopes.Load(peUUID); ok {
			peState := types.PatchEnvelopeStateActive
			for _, volRef := range pe.VolumeRefs {
				if blob, blobState := pes.blobFromVolumeRef(volRef); blob != nil {
					if blobState < peState {
						peState = blobState
					}
					if idx := types.CompletedBinaryBlobIdxByName(pe.BinaryBlobs, blob.FileName); idx != -1 {
						pe.BinaryBlobs[idx] = *blob
					} else {
						pe.BinaryBlobs = append(pe.BinaryBlobs, *blob)
					}
				}
			}
			// Check also the cipher blobs
			for _, cipher := range pe.CipherBlobs {
				if cipher.Volume == nil {
					continue
				}
				if blob, blobState := pes.blobFromVolumeRef(*cipher.Volume); blob != nil {
					if blobState < peState {
						peState = blobState
					}
					if idx := types.CompletedBinaryBlobIdxByName(pe.BinaryBlobs, blob.FileName); idx != -1 {
						pe.BinaryBlobs[idx] = *blob
					} else {
						pe.BinaryBlobs = append(pe.BinaryBlobs, *blob)
					}
				}
			}

			// If controller forces us to store patch envelope and don't expose it
			// to appInstance we keep it that way
			if pe.State == types.PatchEnvelopeStateReady && peState == types.PatchEnvelopeStateActive {
				peState = types.PatchEnvelopeStateReady
			}

			if len(pe.Errors) > 0 {
				peState = types.PatchEnvelopeStateError
				pes.log.Errorf("Errors: %v", pe.Errors)
			}

			pe.State = peState
			pes.currentState.Store(peUUID, pe)
			pes.publishPatchEnvelopeInfo(&pe)
		} else {
			pes.log.Errorf("No entry in envelopes for %v to fetch", peUUID)
		}
	}
}

func (pes *PatchEnvelopes) publishPatchEnvelopeInfo(peInfo *types.PatchEnvelopeInfo) {
	if peInfo == nil {
		pes.log.Errorf("publishPatchEnvelopeInfo: nil peInfo")
	}
	key := peInfo.Key()
	pub := pes.pubPatchEnvelopeState
	err := pub.Publish(key, *peInfo)
	if err != nil {
		pes.log.Errorf("publishPatchEnvelopeInfo failed: %v", err)
	}
}

func (pes *PatchEnvelopes) unpublishPatchEnvelopeInfo(peInfo *types.PatchEnvelopeInfo) {
	if peInfo == nil {
		pes.log.Errorf("unpublishPatchEnvelopeInfo: nil peInfo")
		return
	}
	key := peInfo.Key()
	pub := pes.pubPatchEnvelopeState
	if exists, _ := pub.Get(key); exists == nil {
		pes.log.Errorf("unpublishPatchEnvelopeInfo: key %s not found", key)
		return
	}
	if err := pub.Unpublish(key); err != nil {
		pes.log.Errorf("unpublishPatchEnvelopeInfo failed: %v", err)
	}
}

// Get returns list of Patch Envelopes available for this app instance
func (pes *PatchEnvelopes) Get(appUUID string) types.PatchEnvelopeInfoList {
	var res []types.PatchEnvelopeInfo
	pes.currentState.Range(func(patchEnvelopeUUID uuid.UUID, envelope types.PatchEnvelopeInfo) bool {
		// We don't want to expose patch envelopes which are not activated to app instance
		if envelope.State != types.PatchEnvelopeStateActive {
			return true
		}
		for _, allowedUUID := range envelope.AllowedApps {
			if allowedUUID == appUUID {
				res = append(res, envelope)
				break
			}
		}
		return true
	})

	return types.PatchEnvelopeInfoList{
		Envelopes: res,
	}
}

func (pes *PatchEnvelopes) blobFromVolumeRef(vr types.BinaryBlobVolumeRef) (*types.BinaryBlobCompleted, types.PatchEnvelopeState) {
	volUUID, err := uuid.FromString(vr.ImageID)
	if err != nil {
		pes.log.Errorf("Failed to compose volUUID from string %v", err)
		return nil, types.PatchEnvelopeStateError
	}
	state := types.PatchEnvelopeStateRecieved
	if vs, hasVs := pes.completedVolumes.Load(volUUID); hasVs {
		state = types.PatchEnvelopeStateDownloading
		result := &types.BinaryBlobCompleted{
			FileName:         vr.FileName,
			FileMetadata:     vr.FileMetadata,
			ArtifactMetadata: vr.ArtifactMetadata,
			URL:              vs.FileLocation,
			Size:             vs.TotalSize,
		}

		if ct, hasCt := pes.contentTreeStatus.Load(vs.ContentID); hasCt {
			state = types.PatchEnvelopeStateActive
			result.FileSha = ct.ContentSha256
		}

		return result, state
	}

	return nil, state
}

// UpdateVolumeStatus adds or removes VolumeStatus from PatchEnvelopes structure
func (pes *PatchEnvelopes) UpdateVolumeStatus(vs types.VolumeStatus, deleteVolume bool) {
	if deleteVolume {
		pes.completedVolumes.Delete(vs.VolumeID)
	} else {
		if vs.State < types.CREATED_VOLUME {
			return
		}
		pes.completedVolumes.Store(vs.VolumeID, vs)
	}
}

// UpdateEnvelopes sets pes.envelopes and marks envelopes that are not
// present in new peInfo as ones to be deleted and updates the rest of them
// all of the updates will happen after notification to updateStateNotificationCh
// will be sent
func (pes *PatchEnvelopes) UpdateEnvelopes(peInfo []types.PatchEnvelopeInfo) {
	pes.RLock()
	defer pes.RUnlock()

	before := pes.envelopes.Keys()

	envelopes := generics.NewLockedMap[uuid.UUID, types.PatchEnvelopeInfo]()

	for _, pe := range peInfo {
		peUUID, err := uuid.FromString(pe.PatchID)
		if err != nil {
			pes.log.Errorf("Failed to Update Envelopes :%v", err)
		}
		pes.checkAndExpandCipherBlobs(&pe)
		envelopes.Store(peUUID, pe)
	}

	toDelete, _ := generics.DiffSets(before, envelopes.Keys())
	for _, deleteUUID := range toDelete {
		pes.envelopesToDelete.Store(deleteUUID, true)
	}

	pes.envelopes = envelopes
}

func (pes *PatchEnvelopes) checkAndExpandCipherBlobs(pe *types.PatchEnvelopeInfo) {

	for i := range pe.BinaryBlobs {
		blob := &pe.BinaryBlobs[i]
		if !blob.EncArtifactMeta.IsCipher {
			continue
		}
		aMeta := pes.GetArtifactMetaData(blob.EncArtifactMeta)
		if aMeta == "" {
			pes.log.Errorf("checkAndExpandCipherBlobs: Failed to get artifact metadata for %v", blob.FileName)
			continue
		}
		blob.ArtifactMetadata = aMeta
		pes.log.Functionf("checkAndExpandCipherBlobs: got binaryBlobs (%d)", i)
	}

	for i := range pe.VolumeRefs {
		volRef := &pe.VolumeRefs[i]
		if !volRef.EncArtifactMeta.IsCipher {
			continue
		}
		aMeta := pes.GetArtifactMetaData(volRef.EncArtifactMeta)
		if aMeta == "" {
			pes.log.Errorf("checkAndExpandCipherBlobs: Failed to get artifact metadata for %v", volRef.FileName)
			continue
		}
		volRef.ArtifactMetadata = aMeta
		pes.log.Functionf("checkAndExpandCipherBlobs: got binary volumeref (%d)", i)
	}

	// Either the inline blob or the volume ref is encrypted, the artifactMetadata attached
	// may or may not be encrypted
	for i := range pe.CipherBlobs {
		cBlob := &pe.CipherBlobs[i]
		if cBlob.EncArtifactMeta.IsCipher {
			aMeta := pes.GetArtifactMetaData(cBlob.EncArtifactMeta)
			if aMeta == "" {
				pes.log.Errorf("checkAndExpandCipherBlobs: Failed to get artifact metadata for cipher blob")
				continue
			}
			cBlob.ArtifactMetaData = aMeta
		}
		_, err := pes.msrv.PopulateBinaryBlobFromCipher(cBlob, false)
		if err != nil {
			pes.log.Errorf("checkAndExpandCipherBlobs: Failed to populate binary blob from cipher blob")
		}
	}
}

// GetArtifactMetaData returns artifact metadata for the given cipher block status
func (pes *PatchEnvelopes) GetArtifactMetaData(c types.CipherBlockStatus) string {
	status, decBlock, err := cipher.GetCipherCredentials(&pes.msrv.decryptCipherContext, c)
	if pes.msrv.pubCipherBlockStatus != nil {
		_ = pes.msrv.pubCipherBlockStatus.Publish(status.Key(), status)
		if err != nil {
			return ""
		}
	}
	if decBlock.User == evecommon.EncryptionBlockUser_ENCRYPTION_BLOCK_USER_BINARY_ARTIFACT_METADATA {
		return decBlock.EncryptedData
	}
	return ""
}

// PopulateBinaryBlobFromCipher populates BinaryBlobCompleted or BinaryBlobVolumeRef
func (msrv *Msrv) PopulateBinaryBlobFromCipher(cBlob *types.BinaryCipherBlob, download bool) (string, error) {
	if cBlob == nil {
		return "", fmt.Errorf("cBlob is nil")
	}
	EncBinaryArtifact, err := loadCipherBlockStatusFromFile(cBlob.EncURL)
	if err != nil {
		return "", fmt.Errorf("failed to load cipher block status from file: %v", err)
	}
	status, clearBytes, err := cipher.GetCipherMarshalledData(&msrv.decryptCipherContext, EncBinaryArtifact)
	if msrv.pubCipherBlockStatus != nil {
		_ = msrv.pubCipherBlockStatus.Publish(status.Key(), status)
		if err != nil {
			return "", err
		}
	}

	switch cBlob.EncType {
	case types.BlobEncrytedTypeInline:
		var inline zconfig.InlineOpaqueBase64Data
		err = cipher.UnmarshalCipherData(&msrv.decryptCipherContext, clearBytes, &inline)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal BinaryBlobCompleted: %v", err)
		}
		data := inline.GetBase64Data()
		if download {
			return data, nil
		}
		shaBytes := sha256.Sum256([]byte(data))
		inlineBlob := &types.BinaryBlobCompleted{
			FileName:     inline.GetFileNameToUse(),
			FileSha:      hex.EncodeToString(shaBytes[:]),
			FileMetadata: inline.GetBase64MetaData(),
			URL:          "", //data, // this URL now is not used for download, but for decrypted data saved
			Size:         int64(len(data)),
		}
		cBlob.Inline = inlineBlob
		msrv.Log.Functionf("PopulateBinaryBlobFromCipher: inlineBlob %v", inlineBlob)
	case types.BlobEncrytedTypeVolume:
		var volume zconfig.ExternalOpaqueBinaryBlob
		err = cipher.UnmarshalCipherData(&msrv.decryptCipherContext, clearBytes, &volume)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal BinaryBlobCompleted: %v", err)
		}
		volumeBlob := &types.BinaryBlobVolumeRef{
			ImageName:    volume.GetImageName(),
			FileName:     volume.GetFileNameToUse(),
			FileMetadata: volume.GetBlobMetaData(),
			ImageID:      volume.GetImageId(),
		}
		cBlob.Volume = volumeBlob
		msrv.Log.Functionf("PopulateBinaryBlobFromCipher: volumeBlob %v", volumeBlob)
	default:
		return "", fmt.Errorf("unknown encryption type: %v", cBlob.EncType)
	}
	return "", nil
}

// loadCipherBlockStatusFromFile loads CipherBlockStatus from EncURL file path,
// and Gob decodes it into CipherBlockStatus structure
func loadCipherBlockStatusFromFile(encURL string) (types.CipherBlockStatus, error) {
	var status types.CipherBlockStatus
	file, err := os.Open(encURL)
	if err != nil {
		return status, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&status); err != nil {
		return status, fmt.Errorf("failed to decode CipherBlockStatus: %v", err)
	}

	return status, nil
}

// UpdateContentTree adds or removes ContentTreeStatus from PatchEnvelopes structure
// marks PatchEnvelopes which will require update. Update will happen explicitly
// after sending notification to updateStateNotificationCh
func (pes *PatchEnvelopes) UpdateContentTree(ct types.ContentTreeStatus, deleteCt bool) {
	if deleteCt {
		pes.contentTreeStatus.Delete(ct.ContentID)
	} else {
		pes.contentTreeStatus.Store(ct.ContentID, ct)
	}
}

// EnvelopesInUsage returns list of currently patch envelopes currently attached to
// app instances
func (pes *PatchEnvelopes) EnvelopesInUsage() []string {
	var result []string
	pes.envelopes.Range(func(_ uuid.UUID, peInfo types.PatchEnvelopeInfo) bool {
		peUsages := types.PatchEnvelopeUsageFromInfo(peInfo)
		for _, usage := range peUsages {
			result = append(result, usage.Key())
		}
		return true
	})
	return result
}

// PeInfoToDisplay is used together with patchEnvelopesJSONFOrAppInstance to marshal
// marshal PatchEnvelopeInfoList in a format, which is suitable for app instance.
// Also,  PatchEnvelopeInfo contains fields that we don't want to expose to app instance (like AllowedApps)
// We cannot use json:"-" structure tag to omit AllowedApps from json marshaling since we use PatchEnvelopeInfo between
// zedagent and zedrouter to communicate new PatchEnvelopes from EdgeDevConfig. This communication is done via pubSub,
// which uses json marshaling to communicate structures between processes. And using json:"-" will make AllowedApps "magically"
// disappear on zedrouter
type PeInfoToDisplay struct {
	PatchID     string
	Version     string
	BinaryBlobs []types.BinaryBlobCompleted
	VolumeRefs  []types.BinaryBlobVolumeRef
}

// patchEnvelopesJSONForAppInstance returns json representation
// of Patch Envelopes list which are shown to app instances
func patchEnvelopesJSONForAppInstance(pe types.PatchEnvelopeInfoList) ([]byte, error) {
	toDisplay := make([]PeInfoToDisplay, len(pe.Envelopes))

	for i, envelope := range pe.Envelopes {
		// Create copies of the slices
		binaryBlobs := make([]types.BinaryBlobCompleted, len(envelope.BinaryBlobs))
		copy(binaryBlobs, envelope.BinaryBlobs)

		for j := range binaryBlobs {
			url := fmt.Sprintf("http://%s%sdownload/%s/%s", MetaDataServerIP, PatchEnvelopeURLPath, envelope.PatchID, binaryBlobs[j].FileName)
			binaryBlobs[j].URL = url
			binaryBlobs[j].EncArtifactMeta = types.CipherBlockStatus{}
		}

		// Create copies of the cipher blobs
		for _, cipher := range envelope.CipherBlobs {
			if cipher.EncType == types.BlobEncrytedTypeInline && cipher.Inline != nil {
				inline := *cipher.Inline
				url := fmt.Sprintf("http://%s%sdownload/%s/%s", MetaDataServerIP, PatchEnvelopeURLPath, envelope.PatchID, inline.FileName)
				inline.URL = url
				inline.EncArtifactMeta = types.CipherBlockStatus{}
				binaryBlobs = append(binaryBlobs, inline)
			}
		}

		// Set binaryBlobs to nil if empty
		if len(binaryBlobs) == 0 {
			binaryBlobs = nil
		}

		// Create copies of the volumeRefs
		volumeRefs := make([]types.BinaryBlobVolumeRef, len(envelope.VolumeRefs))
		copy(volumeRefs, envelope.VolumeRefs)

		for j := range volumeRefs {
			volRef := &volumeRefs[j]
			volRef.EncArtifactMeta = types.CipherBlockStatus{}
		}

		// Create copies of the cipher blobs for volume blobs
		for _, cipher := range envelope.CipherBlobs {
			if cipher.EncType == types.BlobEncrytedTypeVolume && cipher.Volume != nil {
				volume := *cipher.Volume
				volume.EncArtifactMeta = types.CipherBlockStatus{}
				volumeRefs = append(volumeRefs, volume)
			}
		}

		// Set volumeRefs to nil if empty
		if len(volumeRefs) == 0 {
			volumeRefs = nil
		}

		toDisplay[i] = PeInfoToDisplay{
			PatchID:     envelope.PatchID,
			Version:     envelope.Version,
			BinaryBlobs: binaryBlobs,
			VolumeRefs:  volumeRefs,
		}
	}

	return json.Marshal(toDisplay)
}
