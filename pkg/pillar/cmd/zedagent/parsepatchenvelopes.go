// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"encoding/hex"
	"errors"
	"fmt"

	"crypto/sha256"

	zconfig "github.com/lf-edge/eve-api/go/config"
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
			err := addBinaryBlobToPatchEnvelope(&peInfo, a, persistCacheFilepath)
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

func addBinaryBlobToPatchEnvelope(pe *types.PatchEnvelopeInfo, artifact *zconfig.EveBinaryArtifact, persistCacheFilepath string) error {
	format := artifact.GetFormat()

	switch format {
	case zconfig.EVE_OPAQUE_OBJECT_CATEGORY_BINARYBLOB:
		binaryArtifact := artifact.GetVolumeRef()
		if binaryArtifact == nil {
			return fmt.Errorf("ExternalOpaqueBinaryBlob is empty, type indicates it should be present")
		}
		volumeRef, err := getBinaryBlobVolumeRef(binaryArtifact)
		if err != nil {
			return err
		}
		volumeRef.ArtifactMetadata = artifact.GetArtifactMetaData()
		pe.VolumeRefs = append(pe.VolumeRefs, *volumeRef)
		return nil
	case zconfig.EVE_OPAQUE_OBJECT_CATEGORY_SECRET:
	case zconfig.EVE_OPAQUE_OBJECT_CATEGORY_BASE64:
		inlineArtifact := artifact.GetInline()
		if inlineArtifact == nil {
			return fmt.Errorf("InlineOpaqueBase64data is empty, type indicates it should be present")
		}
		binaryBlob, err := cacheInlineBase64Artifact(inlineArtifact, persistCacheFilepath)
		if err != nil {
			return err
		}
		binaryBlob.ArtifactMetadata = artifact.GetArtifactMetaData()
		pe.BinaryBlobs = append(pe.BinaryBlobs, *binaryBlob)
		return nil
	}

	return errors.New("Unknown EveBinaryArtifact format")
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
