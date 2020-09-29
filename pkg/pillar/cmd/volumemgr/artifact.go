package volumemgr

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	ctrcontent "github.com/containerd/containerd/content"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/lf-edge/edge-containers/pkg/registry"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/opencontainers/go-digest"
)

// getManifestsForBareBlob either retrieve the manifests for an existing
// image name that wraps the blob, or create one
func getManifestsForBareBlob(ctx *volumemgrContext, image, rootHash string, size int64) ([]*types.BlobStatus, error) {
	// at least one decriptor must match ours
	log.Infof("getManifestsForBareBlob(%s, %s, %d)", image, rootHash, size)
	rootHashFull := fmt.Sprintf("%s:%s", "sha256", rootHash)
	artifact := &registry.Artifact{
		Root: &registry.Disk{
			Source: &registry.HashSource{
				Hash: rootHashFull,
				Size: size,
				Name: "root",
			},
		},
	}

	manifest, err := ctx.casClient.GetImageHash(image)
	// if we do not have that image, just create a manifest
	if err != nil {
		return createManifestsForBareBlob(artifact)
	}

	// we had a manifest hash, so check for the existence of the blob
	// note that the manifest is in the "sha256:<hash>" format, while
	// lookupBlobStatuses expects just "<hash>", so we need to trim it
	blobStatuses := lookupBlobStatuses(ctx, strings.Replace(manifest, "sha256:", "", 1))

	// not found? just create
	if len(blobStatuses) == 0 {
		return createManifestsForBareBlob(artifact)
	}

	// found a manifest. check the content and make sure it references our content.
	_, desc, err := resolveManifestChildren(ctx, blobStatuses[0])
	if err != nil {
		// we could not read that blob, so create a new one
		return createManifestsForBareBlob(artifact)
	}

	//Adding config blob to blobStatuses list
	configBlobStatus := lookupBlobStatus(ctx,
		strings.Replace(desc[0].Digest.String(), "sha256:", "", 1))
	if configBlobStatus != nil {
		blobStatuses = append(blobStatuses, configBlobStatus)
	}

	for _, d := range desc {
		// we found it, so it is good
		if d.Digest.String() == rootHashFull {
			return blobStatuses, nil
		}
	}

	// if we made it this far, we found an image that matches, and a blobstatus
	// for that image, and a manifest, but no link from that manifest to us,
	// so we need to create a new manifest.
	return createManifestsForBareBlob(artifact)
}

// createManifestsForBareBlob create a manifest and config for a bare blob so
// it can be used in OCI stores like containerd
func createManifestsForBareBlob(artifact *registry.Artifact) ([]*types.BlobStatus, error) {
	blobStatuses := []*types.BlobStatus{}
	manifest, provider, err := artifact.Manifest(registry.FormatArtifacts, registry.ConfigOpts{})
	if err != nil {
		return nil, fmt.Errorf("getManifestsForBareBlob: Could not get manifest or provider for artifact: %s", err.Error())
	}
	// now we have the manifest, which should point just to the root,
	// so use it and the generated config
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("getManifestsForBlob: Exception while converting manifest to json: %s",
			err.Error())
	}
	blobStatuses = append(blobStatuses, &types.BlobStatus{
		Content:   manifestBytes,
		State:     types.VERIFIED,
		MediaType: string(v1types.OCIManifestSchema1),
		Sha256:    digest.FromBytes(manifestBytes).Encoded(),
	})

	configReaderAt, err := provider.ReaderAt(context.Background(), manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("getManifestsForBlob: Exception while getting config ReaderAt: %s",
			err.Error())
	}
	configReader := ctrcontent.NewReader(configReaderAt)
	configBytes, err := ioutil.ReadAll(configReader)
	if err != nil {
		return nil, fmt.Errorf("getManifestsForBlob: Exception while reading config bytes: %s",
			err.Error())
	}
	// and the config file which was in the manifest
	blobStatuses = append(blobStatuses, &types.BlobStatus{
		Content:   configBytes,
		State:     types.VERIFIED,
		MediaType: string(v1types.OCIConfigJSON),
		Sha256:    manifest.Config.Digest.Encoded(),
	})
	return blobStatuses, nil
}
