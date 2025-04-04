// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"

	"crypto/sha256"

	zconfig "github.com/lf-edge/eve-api/go/config"
	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/persistcache"
	"github.com/lf-edge/eve/pkg/pillar/types"

	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

func parsePatchEnvelopes(ctx *getconfigContext, config *zconfig.EdgeDevConfig) {
	parsePatchEnvelopesImpl(ctx, config, types.PersistCachePatchEnvelopes)
}

func parsePatchEnvelopesImpl(ctx *getconfigContext, config *zconfig.EdgeDevConfig,
	persistCacheFilepath string) {
	log.Tracef("Parsing patchEnvelope from configuration")

	// Store list of binary blobs which were created before
	pc, err := persistcache.New(persistCacheFilepath)
	if err != nil {
		log.Errorf("Failed to load persistCache %v", err)
		return
	}
	blobsBefore := pc.Objects()

	var blobsAfter []string
	patchEnvelopes := config.GetPatchEnvelopes()
	result := types.PatchEnvelopeInfoList{}
	for _, pe := range patchEnvelopes {
		peInfo := types.PatchEnvelopeInfo{
			AllowedApps: pe.GetAppInstIdsAllowed(),
			PatchID:     pe.GetUuid(),
			Name:        pe.GetDisplayName(),
			Version:     pe.GetVersion(),
			State:       evePatchEnvelopeActionToState(pe.GetAction()),
		}
		for _, a := range pe.GetArtifacts() {
			err := addBinaryBlobToPatchEnvelope(ctx, &peInfo, a, persistCacheFilepath)
			if err != nil {
				msg := fmt.Sprintf("Failed to compose binary blob for patch envelope %v", err)
				peInfo.Errors = append(peInfo.Errors, msg)
				log.Error(msg)
				return
			}
		}

		result.Envelopes = append(result.Envelopes, peInfo)

		for _, inlineBlob := range peInfo.BinaryBlobs {
			blobsAfter = append(blobsAfter, inlineBlob.FileName)
		}

		for _, cipherBlob := range peInfo.CipherBlobs {
			blobsAfter = append(blobsAfter, cipherBlob.EncFileName)
		}
	}

	publishPatchEnvelopes(ctx, result)

	// Provide zedrouter with newest version for description.json and then delete files
	blobsToDelete, _ := generics.DiffSets(blobsBefore, blobsAfter)
	for _, blob := range blobsToDelete {
		pc.Delete(blob)
	}
}

func publishPatchEnvelopes(ctx *getconfigContext, patchEnvelopes types.PatchEnvelopeInfoList) {
	key := patchEnvelopes.Key()
	pub := ctx.pubPatchEnvelopeInfo

	pub.Publish(key, patchEnvelopes)

	log.Tracef("publishPatchEnvelopes(%s) done\n", key)
}

func addBinaryBlobToPatchEnvelope(ctx *getconfigContext, pe *types.PatchEnvelopeInfo, artifact *zconfig.EveBinaryArtifact, persistCacheFilepath string) error {

	switch blob := artifact.GetBinaryBlob().(type) {
	case *zconfig.EveBinaryArtifact_VolumeRef:
		binaryArtifact := blob.VolumeRef
		if binaryArtifact == nil {
			return fmt.Errorf("ExternalOpaqueBinaryBlob is empty, type indicates it should be present")
		}
		volumeRef, err := getBinaryBlobVolumeRef(binaryArtifact)
		if err != nil {
			return err
		}
		volumeRef.ArtifactMetadata = artifact.GetArtifactMetaData()
		volumeRef.EncArtifactMeta, err = getEncArtifactMetadata(ctx, artifact)
		if err != nil {
			return err
		}
		pe.VolumeRefs = append(pe.VolumeRefs, *volumeRef)
		return nil
	case *zconfig.EveBinaryArtifact_Inline:
		inlineArtifact := blob.Inline
		if inlineArtifact == nil {
			return fmt.Errorf("InlineOpaqueBase64data is empty, type indicates it should be present")
		}
		binaryBlob, err := cacheInlineBase64Artifact(inlineArtifact, persistCacheFilepath)
		if err != nil {
			return err
		}
		binaryBlob.ArtifactMetadata = artifact.GetArtifactMetaData()
		binaryBlob.EncArtifactMeta, err = getEncArtifactMetadata(ctx, artifact)
		if err != nil {
			return err
		}
		pe.BinaryBlobs = append(pe.BinaryBlobs, *binaryBlob)

		return nil
	case *zconfig.EveBinaryArtifact_EncryptedInline:
		encInline := blob.EncryptedInline
		if encInline == nil {
			return fmt.Errorf("EncryptedInlineOpaqueBase64data is empty, type indicates it should be present")
		}
		encBlob, err := getEncryptedCipherBlock(ctx, artifact, types.BlobEncrytedTypeInline, encInline, persistCacheFilepath)
		if err != nil {
			return err
		}
		pe.CipherBlobs = append(pe.CipherBlobs, *encBlob)
		return nil
	case *zconfig.EveBinaryArtifact_EncryptedVolumeref:
		encVolumeRef := blob.EncryptedVolumeref
		if encVolumeRef == nil {
			return fmt.Errorf("EncryptedVolumeref is empty, type indicates it should be present")
		}
		encBlob, err := getEncryptedCipherBlock(ctx, artifact, types.BlobEncrytedTypeVolume, encVolumeRef, persistCacheFilepath)
		if err != nil {
			return err
		}
		pe.CipherBlobs = append(pe.CipherBlobs, *encBlob)
		return nil
	default:
	}

	return errors.New("Unknown EveBinaryArtifact format")
}

func getEncArtifactMetadata(ctx *getconfigContext,
	artifact *zconfig.EveBinaryArtifact) (types.CipherBlockStatus, error) {
	data := artifact.GetMetadataCipherData()
	if data == nil {
		return types.CipherBlockStatus{}, nil
	}
	if len(data.CipherData) < 16 {
		log.Errorf("Failed to get metadata cipher data, cipherData is nil or less than 16 bytes")
		return parseCipherBlock(ctx, "None", nil)
	}

	key := fmt.Sprintf("artifactMeta-%s", hex.EncodeToString(data.CipherData[:16]))
	return parseCipherBlock(ctx, key, data)
}

// getEncryptedCipherBlock extracts artifact metadata, either encrypted or not,
// it stores the cypher block data in the EncBinaryArtifact, this data can be
// either encrypted inline blob or encrypted volume reference
// returns path to it to be served by HTTP server
func getEncryptedCipherBlock(ctx *getconfigContext,
	artifact *zconfig.EveBinaryArtifact,
	enctype types.BlobEncrytedType,
	blob interface{},
	persistCacheFilepath string) (*types.BinaryCipherBlob, error) {
	var cipherData *zcommon.CipherBlock
	var typeStr string
	encArtifactMeta, err := getEncArtifactMetadata(ctx, artifact)
	if err != nil {
		return nil, err
	}
	cipherBlob := types.BinaryCipherBlob{
		EncType:          enctype,
		ArtifactMetaData: artifact.GetArtifactMetaData(),
		EncArtifactMeta:  encArtifactMeta,
	}
	switch enctype {
	case types.BlobEncrytedTypeInline:
		inline, ok := blob.(*zconfig.EncryptedInlineOpaqueBase64Data)
		if !ok || inline == nil {
			return nil, fmt.Errorf("invalid type for EncryptedInline")
		}
		cipherData = inline.GetCipherData()
		typeStr = "encInline"
	case types.BlobEncrytedTypeVolume:
		volume, ok := blob.(*zconfig.EncryptedExternalOpaqueBinaryBlob)
		if !ok || volume == nil {
			return nil, fmt.Errorf("invalid type for EncryptedVolumeref")
		}
		cipherData = volume.GetCipherData()
		typeStr = "encVolume"
	}
	if cipherData == nil || len(cipherData.CipherData) < 16 {
		return nil, fmt.Errorf("BlobEncrytedType %v has incorrect cipher data", enctype)
	}
	// the key is used for cipher block and also the file name for the URL saved
	// we save the cipher block data to the cache file, and read it back in msrv side to decrypt,
	// to avoid publishing the cipher block data which can be too big in size
	key := fmt.Sprintf("%s-%s", typeStr, hex.EncodeToString(cipherData.CipherData[:16]))
	EncBinaryArtifact, err := parseCipherBlock(ctx, key, cipherData)
	if err != nil {
		return nil, err
	}
	url, err := saveCipherBlockStatusToFile(EncBinaryArtifact, key, persistCacheFilepath)
	if err != nil {
		return nil, err
	}
	cipherBlob.EncURL = url
	cipherBlob.EncFileName = key
	return &cipherBlob, nil
}

func saveCipherBlockStatusToFile(status types.CipherBlockStatus, fileName, persistCacheFilepath string) (string, error) {
	pc, err := persistcache.New(persistCacheFilepath)
	if err != nil {
		return "", err
	}

	// Encode the CipherBlockStatus to []byte using gob
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(status); err != nil {
		return "", fmt.Errorf("failed to gob encode CipherBlockStatus: %v", err)
	}
	encodedData := buf.Bytes()

	// Write the encoded data to a file using pc.Put()
	url, err := pc.Put(fileName, encodedData)
	if err != nil {
		return "", err
	}

	return url, nil
}

// cacheInlineBinaryArtifact stores inline artifact as file and
// returns path to it to be served by HTTP server
func cacheInlineBase64Artifact(artifact *zconfig.InlineOpaqueBase64Data, persistCacheFilepath string) (*types.BinaryBlobCompleted, error) {
	pc, err := persistcache.New(persistCacheFilepath)

	if err != nil {
		return nil, err
	}

	metadata := artifact.GetBase64MetaData()
	data := artifact.GetBase64Data()

	// We want write inline data to a file to serve it from http server
	url, err := pc.Put(artifact.GetFileNameToUse(), []byte(data))
	if err != nil {
		return nil, err
	}

	shaBytes := sha256.Sum256([]byte(data))
	return &types.BinaryBlobCompleted{
		FileName:     artifact.GetFileNameToUse(),
		FileSha:      hex.EncodeToString(shaBytes[:]),
		FileMetadata: metadata,
		URL:          url,
		Size:         int64(len(data)),
	}, nil
}

func getBinaryBlobVolumeRef(artifact *zconfig.ExternalOpaqueBinaryBlob) (*types.BinaryBlobVolumeRef, error) {
	// Since Volumes will be handled by volumemgr we can only provide
	// reference for now. It will be updated once download is completed
	// down the processing pipeline
	return &types.BinaryBlobVolumeRef{
		ImageName:    artifact.GetImageName(),
		FileName:     artifact.GetFileNameToUse(),
		FileMetadata: artifact.GetBlobMetaData(),
		ImageID:      artifact.GetImageId(),
	}, nil
}

func evePatchEnvelopeActionToState(action zconfig.EVE_PATCH_ENVELOPE_ACTION) types.PatchEnvelopeState {
	switch action {
	case zconfig.EVE_PATCH_ENVELOPE_ACTION_STORE:
		return types.PatchEnvelopeStateReady
	case zconfig.EVE_PATCH_ENVELOPE_ACTION_ACTIVATE:
		return types.PatchEnvelopeStateActive
	}
	return types.PatchEnvelopeStateError
}
