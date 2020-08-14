package store

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/containerd/containerd/content"
	"github.com/opencontainers/go-digest"
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
		writer, err = NewGunzipWriter(writer)
		if err != nil {
			log.Errorf("unable to get gunzip writer: %v", err)
			return nil, fmt.Errorf("unable to get gunzip writer: %v", err)
		}
	}
	return writer, nil
}

// UntarWriter takes an input stream and untars it
type UntarWriter struct {
	writer             content.Writer
	pipew              *io.PipeWriter
	piper              *io.PipeReader
	tr                 *tar.Reader
	digester           digest.Digester
	size               int64
	underlyingDigester digest.Digester
	underlyingSize     int64
	done               chan bool
}

// untarWriter wrap a writer with an untar, so that the stream is untarred
func NewUntarWriter(writer content.Writer) content.Writer {
	r, w := io.Pipe()
	uw := &UntarWriter{
		writer:             writer,
		pipew:              w,
		piper:              r,
		digester:           digest.Canonical.Digester(),
		underlyingDigester: digest.Canonical.Digester(),
		done:               make(chan bool, 1),
	}
	go func(uw *UntarWriter) {
		tr := tar.NewReader(uw.piper)
		writer := uw.writer
		uw.tr = tr
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
				if _, err := writer.Write(b[:l]); err != nil {
					log.Errorf("UntarWriter error writing to underlying writer: %v", err)
					break
				}
				uw.underlyingSize += int64(l)
				uw.underlyingDigester.Hash().Write(b[:l])
				if err == io.EOF {
					break
				}
			}
		}
		uw.piper.Close()
		uw.done <- true
	}(uw)
	return uw
}

func (u *UntarWriter) Write(p []byte) (n int, err error) {
	n, err = u.pipew.Write(p)
	u.digester.Hash().Write(p[:n])
	u.size += int64(n)
	return
}

func (u *UntarWriter) Close() error {
	u.pipew.Close()
	u.writer.Close()
	return nil
}

// Digest may return empty digest or panics until committed.
func (u *UntarWriter) Digest() digest.Digest {
	return u.digester.Digest()
}

// Commit commits the blob (but no roll-back is guaranteed on an error).
// size and expected can be zero-value when unknown.
// Commit always closes the writer, even on error.
// ErrAlreadyExists aborts the writer.
func (u *UntarWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	u.pipew.Close()
	_ = <-u.done
	return u.writer.Commit(ctx, u.underlyingSize, u.underlyingDigester.Digest(), opts...)
}

// Status returns the current state of write
func (u *UntarWriter) Status() (content.Status, error) {
	return u.writer.Status()
}

// Truncate updates the size of the target blob
func (u *UntarWriter) Truncate(size int64) error {
	return u.writer.Truncate(size)
}

// GunzipWriter takes an input stream and decompresses it
type GunzipWriter struct {
	writer             content.Writer
	pipew              *io.PipeWriter
	piper              *io.PipeReader
	gr                 *gzip.Reader
	digester           digest.Digester
	size               int64
	underlyingDigester digest.Digester
	underlyingSize     int64
	done               chan bool
}

// gunzipWriter wrap a writer with a gunzip, so that the stream is gunzipped
func NewGunzipWriter(writer content.Writer) (content.Writer, error) {
	r, w := io.Pipe()
	gw := &GunzipWriter{
		writer: writer,
		pipew:  w, piper: r,
		digester:           digest.Canonical.Digester(),
		underlyingDigester: digest.Canonical.Digester(),
		done:               make(chan bool, 1),
	}
	go func(gw *GunzipWriter) {
		gr, err := gzip.NewReader(gw.piper)
		if err != nil {
			log.Errorf("error creating gzip reader: %v", err)
			return
		}
		gw.gr = gr
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
			if _, err := gw.writer.Write(b[:l]); err != nil {
				log.Errorf("GunzipWriter: error writing to underlying writer: %v", err)
				break
			}
			gw.underlyingSize += int64(l)
			gw.underlyingDigester.Hash().Write(b[:l])
			if err == io.EOF {
				break
			}
		}
		gw.gr.Close()
		gw.piper.Close()
		gw.done <- true
	}(gw)
	return gw, nil
}

func (g *GunzipWriter) Write(p []byte) (n int, err error) {
	n, err = g.pipew.Write(p)
	g.digester.Hash().Write(p[:n])
	g.size += int64(n)
	return
}

func (g *GunzipWriter) Close() error {
	g.pipew.Close()
	g.writer.Close()
	return nil
}

// Digest may return empty digest or panics until committed.
func (g *GunzipWriter) Digest() digest.Digest {
	return g.digester.Digest()
}

// Commit commits the blob (but no roll-back is guaranteed on an error).
// size and expected can be zero-value when unknown.
// Commit always closes the writer, even on error.
// ErrAlreadyExists aborts the writer.
func (g *GunzipWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	g.pipew.Close()
	_ = <-g.done
	return g.writer.Commit(ctx, g.underlyingSize, g.underlyingDigester.Digest(), opts...)
}

// Status returns the current state of write
func (g *GunzipWriter) Status() (content.Status, error) {
	return g.writer.Status()
}

// Truncate updates the size of the target blob
func (g *GunzipWriter) Truncate(size int64) error {
	return g.writer.Truncate(size)
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
