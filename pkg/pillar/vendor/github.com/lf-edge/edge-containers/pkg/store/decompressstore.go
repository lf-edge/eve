package store

import (
	"context"
	"strings"

	ctrcontent "github.com/containerd/containerd/content"
	"github.com/deislabs/oras/pkg/content"
)

const (
	// DefaultBlocksize default size of each slice of bytes read in each write through.
	// Simply uses the same size as io.Copy()
	DefaultBlocksize = content.DefaultBlocksize
)

// DecompressWriter store to decompress content and extract from tar, if needed
type DecompressStore struct {
	ingester  ctrcontent.Ingester
	blocksize int
}

func NewDecompressStore(ingester ctrcontent.Ingester, blocksize int) DecompressStore {
	return DecompressStore{ingester, blocksize}
}

// Writer get a writer
func (d DecompressStore) Writer(ctx context.Context, opts ...ctrcontent.WriterOpt) (ctrcontent.Writer, error) {
	// the logic is straightforward:
	// - if there is a desc in the opts, and the mediatype is tar or tar+gzip, then pass the correct decompress writer
	// - else, pass the regular writer
	var (
		writer ctrcontent.Writer
		err    error
	)
	writer, err = d.ingester.Writer(ctx, opts...)
	if err != nil {
		return nil, err
	}

	// we have to reprocess the opts to find the desc
	var wOpts ctrcontent.WriterOpts
	for _, opt := range opts {
		if err := opt(&wOpts); err != nil {
			return nil, err
		}
	}
	desc := wOpts.Desc
	// determine if we pass it blocksize, only if positive
	writerOpts := []content.WriterOpt{}
	if d.blocksize > 0 {
		writerOpts = append(writerOpts, content.WithBlocksize(d.blocksize))
	}
	// figure out which writer we need
	hasGzip, hasTar := checkCompression(desc.MediaType)
	if hasTar {
		writer = content.NewUntarWriter(writer, writerOpts...)
	}
	if hasGzip {
		writer = content.NewGunzipWriter(writer, writerOpts...)
	}
	return writer, nil
}

// checkCompression check if the mediatype uses gzip compression or tar
func checkCompression(mediaType string) (gzip, tar bool) {
	mt := mediaType
	gzipSuffix := "+gzip"
	if strings.HasSuffix(mt, gzipSuffix) {
		mt = mt[:len(mt)-len(gzipSuffix)]
		gzip = true
	}
	if strings.HasSuffix(mt, ".tar") {
		tar = true
	}
	return
}
