package store

import (
	"context"
	"fmt"

	"github.com/containerd/containerd/content"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// MultiReader store to read content from multiple
type MultiReader struct {
	stores []content.Provider
}

// AddStore add a store to read from
func (m *MultiReader) AddStore(store ...content.Provider) {
	m.stores = append(m.stores, store...)
}

// ReaderAt get a reader
func (m MultiReader) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	for _, store := range m.stores {
		r, err := store.ReaderAt(ctx, desc)
		if r != nil && err == nil {
			return r, nil
		}
	}
	// we did not find any
	return nil, fmt.Errorf("not found")
}
