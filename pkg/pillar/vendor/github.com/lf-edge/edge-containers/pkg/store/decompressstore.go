package store

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"strings"

	"github.com/containerd/containerd/content"
	log "github.com/sirupsen/logrus"
)

const (
	// Blocksize size of each slice of bytes read in each write through. Technically not a "block" size, but just like it.
	Blocksize = 10240
)

// DecompressWriter store to decompress content and extract from tar, if needed
type DecompressStore struct {
	ingester content.Ingester
}

func NewDecompressStore(ingester content.Ingester) DecompressStore {
	return DecompressStore{ingester}
}

// Writer get a writer
func (d DecompressStore) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	// the logic is straightforward:
	// - if there is a desc in the opts, and the mediatype is tar or tar+gzip, then pass the correct decompress writer
	// - else, pass the regular writer
	var (
		writer content.Writer
		err    error
	)
	writer, err = d.ingester.Writer(ctx, opts...)
	if err != nil {
		return nil, err
	}

	// we have to reprocess the opts to find the desc
	var wOpts content.WriterOpts
	for _, opt := range opts {
		if err := opt(&wOpts); err != nil {
			return nil, err
		}
	}
	desc := wOpts.Desc
	// figure out which writer we need
	hasGzip, hasTar := checkCompression(desc.MediaType)
	if hasTar {
		writer = NewUntarWriter(writer)
	}
	if hasGzip {
		writer = NewGunzipWriter(writer)
	}
	return writer, nil
}

// untarWriter wrap a writer with an untar, so that the stream is untarred
func NewUntarWriter(writer content.Writer) content.Writer {
	return NewPassthroughWriter(writer, func(pw *PassthroughWriter) {
		tr := tar.NewReader(pw.Reader)
		for {
			_, err := tr.Next()
			if err == io.EOF {
				break // End of archive
			}
			if err != nil {
				log.Errorf("UntarWriter header read error: %v\n", err)
				continue
			}
			// write out the untarred data
			for {
				b := make([]byte, Blocksize, Blocksize)
				n, err := tr.Read(b)
				if err != nil && err != io.EOF {
					log.Errorf("UntarWriter file data read error: %v\n", err)
					continue
				}
				l := n
				if n > len(b) {
					l = len(b)
				}
				if err := pw.UnderlyingWrite(b[:l]); err != nil {
					log.Errorf("UntarWriter: error writing to underlying writer: %v", err)
					break
				}
				if err == io.EOF {
					break
				}
			}
		}
		pw.Done <- true
	})
}

// gunzipWriter wrap a writer with a gunzip, so that the stream is gunzipped
func NewGunzipWriter(writer content.Writer) content.Writer {
	return NewPassthroughWriter(writer, func(pw *PassthroughWriter) {
		gr, err := gzip.NewReader(pw.Reader)
		if err != nil {
			log.Errorf("error creating gzip reader: %v", err)
			return
		}
		// write out the uncompressed data
		for {
			b := make([]byte, Blocksize, Blocksize)
			n, err := gr.Read(b)
			if err != nil && err != io.EOF {
				log.Errorf("GunzipWriter data read error: %v\n", err)
				continue
			}
			l := n
			if n > len(b) {
				l = len(b)
			}
			if err := pw.UnderlyingWrite(b[:l]); err != nil {
				log.Errorf("GunzipWriter: error writing to underlying writer: %v", err)
				break
			}
			if err == io.EOF {
				break
			}
		}
		gr.Close()
		pw.Done <- true
	})
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
