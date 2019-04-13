// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package awsutil

import (
	"compress/gzip"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"io"
	"os"
	"path"
	"path/filepath"
	"sync/atomic"
)

// stats update
type UpdateStats struct {
	Name  string   // always the remote key
	Size  int64    // complete size to upload/download
	Asize int64    // current size uploaded/downloaded
	List  []string //list of images at given path
}

type NotifChan chan UpdateStats

type CustomReader struct {
	fp        *os.File
	upSize    UpdateStats
	prgNotify NotifChan
}

func (r *CustomReader) Read(p []byte) (int, error) {
	n, err := r.fp.Read(p)
	if err != nil {
		return n, err
	}
	atomic.AddInt64(&r.upSize.Asize, int64(n))
	if r.prgNotify != nil {
		select {
		case r.prgNotify <- r.upSize:
		default: //ignore we cannot write
		}
	}
	return n, err
}
func (r *CustomReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.fp.ReadAt(p, off)
	if err != nil {
		return n, err
	}
	// Got the length have read( or means has uploaded), and you can construct your message
	atomic.AddInt64(&r.upSize.Asize, int64(n))

	if r.prgNotify != nil {
		select {
		case r.prgNotify <- r.upSize:
		default: //ignore we cannot write
		}
	}

	return n, err
}
func (r *CustomReader) Seek(offset int64, whence int) (int64, error) {
	return r.fp.Seek(offset, whence)
}

type CustomWriter struct {
	fp        *os.File
	upSize    UpdateStats
	prgNotify NotifChan
}

func (r *CustomWriter) Write(p []byte) (int, error) {
	return r.fp.Write(p)
}
func (r *CustomWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := r.fp.WriteAt(p, off)
	if err != nil {
		return n, err
	}
	// Got the length have read( or means has uploaded), and you can construct your message
	atomic.AddInt64(&r.upSize.Asize, int64(n))

	if r.prgNotify != nil {
		select {
		case r.prgNotify <- r.upSize:
		default: //ignore we cannot write
		}
	}

	return n, err
}

func (r *CustomWriter) Seek(offset int64, whence int) (int64, error) {
	return r.fp.Seek(offset, whence)
}

func (s *S3ctx) UploadFile(fname, bname, bkey string, compression bool, prgNotify NotifChan) (string, error) {
	location := ""

	// if bucket doesn't exits, create one
	ok := s.WaitUntilBucketExists(bname)
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
		upSize:    UpdateStats{Size: fileInfo.Size(), Name: bkey},
		prgNotify: prgNotify,
	}

	reader, writer := io.Pipe()
	if err != nil {
		return location, err
	}
	if compression {
		// Note required, but you could zip the file prior to uploading it
		// using io.Pipe read/writer to stream gzip'ed file contents.
		go func() {
			gw := gzip.NewWriter(writer)
			io.Copy(gw, creader)

			file.Close()
			gw.Close()
			writer.Close()
		}()
	} else {
		go func() {
			io.Copy(writer, creader)
			file.Close()
			writer.Close()
		}()
	}

	result, err := s.up.Upload(&s3manager.UploadInput{
		Body: reader, Bucket: aws.String(bname),
		Key: aws.String(bkey)})
	if err != nil {
		return location, err
	}
	return result.Location, nil
}

func (s *S3ctx) DownloadFile(fname, bname, bkey string, prgNotify NotifChan) error {
	if err := os.MkdirAll(filepath.Dir(fname), 0775); err != nil {
		return err
	}

	err, bsize := s.GetObjectSize(bname, bkey)
	if err != nil {
		return err
	}

	// Setup the local file
	fd, err := os.Create(fname)
	if err != nil {
		return err
	}

	cWriter := &CustomWriter{
		fp:        fd,
		upSize:    UpdateStats{Size: bsize, Name: bkey},
		prgNotify: prgNotify,
	}

	defer fd.Close()
	_, err = s.dn.Download(cWriter, &s3.GetObjectInput{Bucket: aws.String(bname),
		Key: aws.String(bkey)})
	if err != nil {
		return err
	}
	return nil
}

func (s *S3ctx) ListImages(bname string, prgNotify NotifChan) ([]string, error) {
	var img []string
	input := &s3.ListObjectsInput{
		Bucket: aws.String(bname),
	}

	result, err := s.ss3.ListObjects(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				return img, aerr
			default:
				return img, aerr
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			return img, aerr
		}
	}

	for _, list := range result.Contents {
		img = append(img, *list.Key)
	}
	stats := UpdateStats{}
	stats.List = img
	if prgNotify != nil {
		select {
		case prgNotify <- stats:
		default: //ignore we cannot write
		}
	}
	return img, nil
}

func (s *S3ctx) GetObjectMetaData(bname, bkey string) (int64, string, error) {
	err, bsize := s.GetObjectSize(bname, bkey)
	if err != nil {
		return 0, "", err
	}
	err, md5 := s.GetObjectMD5(bname, bkey)
	if err != nil {
		return 0, "", err
	}
	return bsize, md5, nil
}

func (s *S3ctx) UploadDir(localPath, bname, bkey string, compression bool, prgNotify NotifChan) error {
	walker := make(fileWalk)
	go func() {
		// Gather the files to upload by walking the path recursively.
		if err := filepath.Walk(localPath, walker.Walk); err != nil {
		}
		close(walker)
	}()

	// For each file found walking upload it to S3.
	for path := range walker {
		rel, err := filepath.Rel(localPath, path)
		if err != nil {
		}
		s.UploadFile(rel, bname, bkey, compression, prgNotify)
	}

	return nil
}

type fileWalk chan string

func (f fileWalk) Walk(path string, info os.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if !info.IsDir() {
		f <- path
	}
	return nil
}

func (s *S3ctx) DownloadDir(localpath, bname, prefix string, prgNotify NotifChan) error {
	d := downloader{s, bname, localpath, prgNotify}

	client := s3.New(nil)
	err := client.ListObjectsPages(&s3.ListObjectsInput{Bucket: aws.String(bname), Prefix: aws.String(prefix)}, d.eachPage)

	return err
}

type downloader struct {
	*S3ctx
	bucket, dir string
	prgNotify   NotifChan
}

func (d *downloader) eachPage(page *s3.ListObjectsOutput, more bool) bool {
	for _, obj := range page.Contents {
		d.DownloadFile(path.Join(d.dir, *obj.Key), d.bucket, *obj.Key, d.prgNotify)
	}

	return true
}
