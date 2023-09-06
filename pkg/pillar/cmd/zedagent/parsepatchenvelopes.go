// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"encoding/hex"
	"fmt"

	"crypto/sha256"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/persistcache"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const PERSIST_CACHE_FILEPATH = "/persist/cache/"

func parsePatchEnvelopes(ctx *getconfigContext, config *zconfig.EdgeDevConfig) {
	parsePatchEnvelopesImpl(ctx, config, PERSIST_CACHE_FILEPATH)
}

func parsePatchEnvelopesImpl(ctx *getconfigContext, config *zconfig.EdgeDevConfig,
	persistCacheFilepath string) {
	log.Tracef("Parsing patchEnvelope from configuration")

	patchEnvelopes := config.GetPatchEnvelopes()
	result := types.NewPatchEnvelopes()
	for _, pe := range patchEnvelopes {
		peName := getPatchEnvelopeName(pe)
		peBlobs, err := composeBinaryBlob(pe, persistCacheFilepath)
		if err != nil {
			log.Errorf("Failed to compose binary blob for patch envelope %v", err)
			return
		}
		peInfo := types.PatchEnvelopeInfo{
			PatchId:     peName,
			BinaryBlobs: peBlobs,
		}

		result.Add(peInfo, pe.GetAppInstIdsAllowed())
	}

	publishPatchEnvelopes(ctx, *result)
}

func publishPatchEnvelopes(ctx *getconfigContext, patchEnvelopes types.PatchEnvelopes) {
	key := patchEnvelopes.Key()
	pub := ctx.pubPatchEnvelopeInfo

	pub.Publish(key, patchEnvelopes)

	log.Tracef("publishPatchEnvelopes(%s) done\n", key)
}

func composeBinaryBlob(patch *zconfig.EvePatchEnvelope, persistCacheFilepath string) ([]types.BinaryBlob, error) {
	var result []types.BinaryBlob
	for _, a := range patch.GetArtifacts() {
		binaryBlob, err := processEveBinaryArtifact(a, persistCacheFilepath)
		if err != nil {
			return nil, err
		}
		result = append(result, *binaryBlob)
	}
	return result, nil
}

func getPatchEnvelopeName(patch *zconfig.EvePatchEnvelope) string {
	if displayName := patch.GetDisplayName(); displayName != "" {
		return displayName
	}
	return patch.GetUuid()
}

// processEveBinaryArtifact returns filepath which can be served
// by HTTP server. In case of query parameter it'll cache it first
func processEveBinaryArtifact(artifact *zconfig.EveBinaryArtifact, persistCacheFilepath string) (*types.BinaryBlob, error) {
	format := artifact.GetFormat()

	switch format {
	case zconfig.EVE_OPAQUE_OBJECT_CATEGORY_BINARYBLOB:
		binaryArtifact := artifact.GetVolumeRef()
		if binaryArtifact == nil {
			return nil, fmt.Errorf("ExternalOpaqueBinaryBlob is empty, type indicates it should be present")
		}
		return getBinaryBlobFilepath(binaryArtifact)
	case zconfig.EVE_OPAQUE_OBJECT_CATEGORY_SECRET:
	case zconfig.EVE_OPAQUE_OBJECT_CATEGORY_BASE64:
		inlineArtifact := artifact.GetInline()
		if inlineArtifact == nil {
			return nil, fmt.Errorf("InlineOpaqueBase64data is empty, type indicates it should be present")
		}
		return cacheInlineBase64Artifact(inlineArtifact, persistCacheFilepath)
	}

	return fmt.Errorf("Unknown EveBinaryArtifact format")
}

// cacheInlineBinaryArtifact stores inline artifact as file and
// returns path to it to be served by HTTP server
func cacheInlineBase64Artifact(artifact *zconfig.InlineOpaqueBase64Data, persistCacheFilepath string) (*types.BinaryBlob, error) {
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
	return &types.BinaryBlob{
		FileName:     artifact.GetFileNameToUse(),
		FileSha:      hex.EncodeToString(shaBytes[:]),
		FileMetadata: metadata,
		Url:          url,
	}, nil
}

func getBinaryBlobFilepath(artifact *zconfig.ExternalOpaqueBinaryBlob) (*types.BinaryBlob, error) {
	// TODO: implement handling BinaryBlob patch envelopes
	return &types.BinaryBlob{}, nil
}
