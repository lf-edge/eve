// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package gsutil

import (
	"compress/gzip"
	"io"
	"os"
	"path"
	"path/filepath"
	"sync/atomic"

	"google.golang.org/api/iterator"

	"github.com/lf-edge/eve-libs/zedUpload/types"
)

// Resp structure for response
type Resp struct {
	Name string
	List []string //list of images at given path
}

// CustomReader contains the details of Chunks being downloaded
type CustomReader struct {
	fp        *os.File
	upSize    types.UpdateStats
	name      string
	prgNotify types.StatsNotifChan
}

// Read with updates notification
func (r *CustomReader) Read(p []byte) (int, error) {
	n, err := r.fp.Read(p)
	if err != nil {
		return n, err
	}
	atomic.AddInt64(&r.upSize.Asize, int64(n))
	types.SendStats(r.prgNotify, r.upSize)
	return n, err
}

// ReadAt with updates notification
func (r *CustomReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.fp.ReadAt(p, off)
	if err != nil {
		return n, err
	}
	// Got the length have read( or means has uploaded), and you can construct your message
	atomic.AddInt64(&r.upSize.Asize, int64(n))

	types.SendStats(r.prgNotify, r.upSize)

	return n, err
}

// Seek implementation
func (r *CustomReader) Seek(offset int64, whence int) (int64, error) {
	return r.fp.Seek(offset, whence)
}

// CustomWriter with notification on updates
type CustomWriter struct {
	fp        *os.File
	upSize    types.UpdateStats
	name      string
	prgNotify types.StatsNotifChan
}

// Write with notification on updates
func (r *CustomWriter) Write(p []byte) (int, error) {
	n, err := r.fp.Write(p)
	if err != nil {
		return n, err
	}
	atomic.AddInt64(&r.upSize.Asize, int64(n))

	types.SendStats(r.prgNotify, r.upSize)

	return n, err
}

// WriteAt with notification on updates
func (r *CustomWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := r.fp.WriteAt(p, off)
	if err != nil {
		return n, err
	}
	// Got the length have written( or means has uploaded), and you can construct your message
	atomic.AddInt64(&r.upSize.Asize, int64(n))

	types.SendStats(r.prgNotify, r.upSize)

	return n, err
}

// Seek implementation
func (r *CustomWriter) Seek(offset int64, whence int) (int64, error) {
	return r.fp.Seek(offset, whence)
}

// UploadFile to Google Storage
func (s *GSctx) UploadFile(fname, bname, bkey string, compression bool, prgNotify types.StatsNotifChan) (string, error) {
	location := ""

	// if bucket doesn't exist, create one
	ok, _ := s.IsBucketAvailable(bname)
	if !ok {
		err := s.CreateBucket(bname)
		if err != nil {
			return location, err
		}
	}

	file, err := os.Open(fname)
	if err != nil {
		return location, err
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return location, err
	}

	creader := &CustomReader{
		fp:        file,
		upSize:    types.UpdateStats{Size: fileInfo.Size()},
		name:      bkey,
		prgNotify: prgNotify,
	}

	reader, writer := io.Pipe()
	if compression {
		// Note required, but you could zip the file prior to uploading it
		// using io.Pipe read/writer to stream gzip'ed file contents.
		go func() {
			gw := gzip.NewWriter(writer)
			_, err := io.Copy(gw, creader)

			file.Close()
			gw.Close()
			_ = writer.CloseWithError(err) //it always returns nil
		}()
	} else {
		go func() {
			_, err := io.Copy(writer, creader)

			file.Close()
			_ = writer.CloseWithError(err) //it always returns nil
		}()
	}

	obj := s.gsClient.Bucket(bname).Object(bkey)

	w := obj.NewWriter(s.ctx)

	defer w.Close()

	_, err = io.Copy(w, reader)
	if err != nil {
		return location, err
	}

	location = path.Join("https://storage.cloud.google.com", bname, bkey)

	return location, nil
}

// DownloadFile from Google Storage
func (s *GSctx) DownloadFile(fname, bname, bkey string,
	bsize int64, prgNotify types.StatsNotifChan) error {

	if err := os.MkdirAll(filepath.Dir(fname), 0775); err != nil {
		return err
	}

	// Setup the local file
	fd, err := os.Create(fname)
	if err != nil {
		return err
	}

	cWriter := &CustomWriter{
		fp:        fd,
		upSize:    types.UpdateStats{Size: bsize},
		name:      bkey,
		prgNotify: prgNotify,
	}

	defer fd.Close()

	obj := s.gsClient.Bucket(bname).Object(bkey)

	r, err := obj.NewReader(s.ctx)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = io.Copy(cWriter, r)
	if err != nil {
		return err
	}
	return nil
}

// ListImages in Google Storage
func (s *GSctx) ListImages(bname string, prgNotify types.StatsNotifChan) ([]string, error) {
	var img []string

	stats := types.UpdateStats{}
	objs := s.gsClient.Bucket(bname).Objects(s.ctx, nil)
	for {
		o, err := objs.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return img, err
		}
		if o == nil {
			return img, nil
		}
		img = append(img, o.Name)
		types.SendStats(prgNotify, stats)
	}
	return img, nil
}

// GetObjectMetaData located in Google Storage
func (s *GSctx) GetObjectMetaData(bname, bkey string) (int64, string, error) {
	bsize, err := s.GetObjectSize(bname, bkey)
	if err != nil {
		return 0, "", err
	}
	md5, err := s.GetObjectMD5(bname, bkey)
	if err != nil {
		return 0, "", err
	}
	return bsize, md5, nil
}
