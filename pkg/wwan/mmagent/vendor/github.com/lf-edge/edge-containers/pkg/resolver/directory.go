package resolver

/*
 Provides an oras target backed by a local filesystem directory.

 The format in the directory is the OCI spec for an image layout,
 at https://github.com/opencontainers/image-spec/blob/master/image-layout.md

 The image reference name is stored in the root index.json, with the image name stored
 as the annotation for image name, i.e. org.opencontainers.image.ref.name

 The spec for annotations is available https://github.com/opencontainers/image-spec/blob/master/annotations.md
*/

import (
	"context"
	"fmt"
	"os"

	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
)

// Directory resolver that reads and writes an OCI image layout in a directory.
type Directory struct {
	store *oci.Store
	ctx   context.Context
}

// NewDirectory create a Directory resolver over dir, creating it if needed.
func NewDirectory(ctx context.Context, dir string) (context.Context, *Directory, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return ctx, nil, fmt.Errorf("could not create directory %s: %v", dir, err)
	}
	store, err := oci.NewWithContext(ctx, dir)
	if err != nil {
		return ctx, nil, fmt.Errorf("could not open image layout at %s: %v", dir, err)
	}
	return ctx, &Directory{store: store, ctx: ctx}, nil
}

// Target returns the image layout, which serves every reference it holds.
func (d *Directory) Target(_ context.Context, _ string) (oras.Target, error) {
	return d.store, nil
}

func (d *Directory) Finalize(_ context.Context) error {
	return nil
}

func (d *Directory) Context() context.Context {
	return d.ctx
}
