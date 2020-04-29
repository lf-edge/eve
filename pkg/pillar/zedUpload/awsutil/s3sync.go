// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package awsutil

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
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

func (s *S3ctx) DownloadFile(fname, bname, bkey string,
	bsize int64, prgNotify NotifChan) error {

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

// UploadPart is used to upload the given chunk of data into the Multipart file
func (s *S3ctx) UploadPart(bname, bkey string, chunk []byte, partNumber int64, uploadID string) (string, string, error) {
	// initializing Multipart request before uploading parts
	if uploadID == "" {
		fileType := http.DetectContentType(chunk)
		input := &s3.CreateMultipartUploadInput{
			Bucket:      aws.String(bname),
			Key:         aws.String(bkey),
			ContentType: aws.String(fileType),
		}
		multiPartUplladCreateResponse, err := s.ss3.CreateMultipartUpload(input)
		if err != nil {
			return "", "", err
		}
		uploadID = *multiPartUplladCreateResponse.UploadId
	}
	partInput := &s3.UploadPartInput{
		Body:          bytes.NewReader(chunk),
		Bucket:        &bname,
		Key:           &bkey,
		PartNumber:    aws.Int64(partNumber),
		UploadId:      &uploadID,
		ContentLength: aws.Int64(int64(len(chunk))),
	}
	uploadResult, err := s.ss3.UploadPart(partInput)
	return *uploadResult.ETag, uploadID, err
}

// CompleteUploadedParts is used to complete the multiple upladed parts
func (s *S3ctx) CompleteUploadedParts(bname, bkey, uploadID string, parts []string) error {
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   &bname,
		Key:      &bkey,
		UploadId: &uploadID,
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: getUploadedParts(parts),
		},
	}
	_, err := s.ss3.CompleteMultipartUpload(completeInput)
	if err != nil {
		return err
	}
	return nil
}

// GetSignedURL is used to generate the URI which can be used to access the resource until the URI expries
func (s *S3ctx) GetSignedURL(bname, bkey string, duration time.Duration) (string, error) {
	_, err := s.ss3.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(bname),
		Key:    aws.String(bkey)})
	if err != nil {
		return "", err
	}
	req, _ := s.ss3.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(bname),
		Key:    aws.String(bkey)})

	// Presign a request with specified duration.
	signedURL, err := req.Presign(duration)

	return signedURL, err
}

func getUploadedParts(parts []string) []*s3.CompletedPart {
	var completedParts []*s3.CompletedPart
	for i := 0; i < len(parts); i++ {
		part := s3.CompletedPart{
			ETag:       &parts[i],
			PartNumber: aws.Int64(int64(i + 1))}
		completedParts = append(completedParts, &part)
	}
	return completedParts
}
