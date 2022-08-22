// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package awsutil

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/lf-edge/eve/libs/zedUpload/types"
)

// CustomReader contains the details of Chunks being downloaded
type CustomReader struct {
	fp        *os.File
	name      string
	upSize    types.UpdateStats
	prgNotify types.StatsNotifChan
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

type writerOptions struct {
	fp            *os.File
	upSize        types.UpdateStats
	name          string
	prgNotify     types.StatsNotifChan
	donePartsLock sync.Mutex
	err           error
}

type CustomWriter struct {
	writerGlobalOptions *writerOptions
	writtenBytes        int64
	offset              int64
	partInd             int64
}

func (r *CustomWriter) Write(p []byte) (int, error) {
	return r.writerGlobalOptions.fp.Write(p)
}

func (r *CustomWriter) WriteAt(p []byte, off int64) (int, error) {
	//adjust offset from begin of the part
	off += r.offset
	n, err := r.writerGlobalOptions.fp.WriteAt(p, off)
	if err != nil {
		return n, err
	}
	r.writtenBytes += int64(n)
	r.writerGlobalOptions.donePartsLock.Lock()
	r.writerGlobalOptions.upSize.DoneParts.SetPartSize(r.partInd, r.writtenBytes)
	r.writerGlobalOptions.donePartsLock.Unlock()
	// Got the length have read (or means has uploaded), and you can construct your message
	atomic.AddInt64(&r.writerGlobalOptions.upSize.Asize, int64(n))

	if r.writerGlobalOptions.prgNotify != nil {
		select {
		case r.writerGlobalOptions.prgNotify <- r.writerGlobalOptions.upSize:
		default: //ignore we cannot write
		}
	}

	return n, err
}

func (r *CustomWriter) Seek(offset int64, whence int) (int64, error) {
	return r.writerGlobalOptions.fp.Seek(offset, whence)
}

func (s *S3ctx) UploadFile(fname, bname, bkey string, compression bool, prgNotify types.StatsNotifChan) (string, error) {
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

	result, err := s.up.UploadWithContext(s.ctx, &s3manager.UploadInput{
		Body: reader, Bucket: aws.String(bname),
		Key: aws.String(bkey)})
	if err != nil {
		return location, err
	}
	return result.Location, nil
}

// partS3 stores information about part of file in S3 datastore
type partS3 struct {
	cWriter     *CustomWriter
	bname, bkey string
	start, size int64 // offset in the file and size of range
}

func (s *S3ctx) downloadPart(ch chan *partS3, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		p, ok := <-ch
		if !ok {
			break
		}
		if p.cWriter.writerGlobalOptions.err != nil {
			continue
		}
		//download range of bytes from file
		byteRange := fmt.Sprintf("bytes=%d-%d", p.start, p.start+p.size-1)
		_, err := s.dn.DownloadWithContext(s.ctx, p.cWriter, &s3.GetObjectInput{Bucket: aws.String(p.bname),
			Key:   aws.String(p.bkey),
			Range: aws.String(byteRange)})
		if err != nil {
			p.cWriter.writerGlobalOptions.err = err
		}
	}
}

//getNeededParts returns description of parts of file to download
//it skips parts from doneParts slice which are fully downloaded
func getNeededParts(cWriterOptions *writerOptions, bname, bkey string, doneParts types.DownloadedParts, size int64) []*partS3 {
	partsCount := int64(math.Ceil(float64(size) / float64(S3PartSize)))
	var needed []*partS3
	for i := int64(0); i < partsCount; i++ {
		currentPartSize := int64(0)
		for _, val := range doneParts.Parts {
			if val.Ind == i {
				currentPartSize = val.Size
				break
			}
		}
		part := &partS3{
			cWriter: &CustomWriter{
				writerGlobalOptions: cWriterOptions,
				partInd:             i,
				offset:              S3PartSize*i + currentPartSize,
				writtenBytes:        currentPartSize,
			},
			bname: bname,
			bkey:  bkey,
			start: S3PartSize*i + currentPartSize,
			size:  S3PartSize - currentPartSize,
		}
		if i == partsCount-1 {
			part.size = size - (partsCount-1)*S3PartSize - currentPartSize
		}
		if part.size > 0 {
			needed = append(needed, part)
		}
	}
	return needed
}

func (s *S3ctx) DownloadFile(fname, bname, bkey string,
	objMaxSize int64, doneParts types.DownloadedParts, prgNotify types.StatsNotifChan) (types.DownloadedParts, error) {

	var fd *os.File
	var wg sync.WaitGroup

	err, bsize := s.GetObjectSize(bname, bkey)
	if err != nil {
		return doneParts, err
	}

	if objMaxSize != 0 && bsize > objMaxSize {
		return types.DownloadedParts{PartSize: S3PartSize},
			fmt.Errorf("configured image size (%d) is less than size of file (%d)", objMaxSize, bsize)
	}

	if err := os.MkdirAll(filepath.Dir(fname), 0775); err != nil {
		return doneParts, err
	}

	if _, err := os.Stat(fname); err != nil && os.IsNotExist(err) {
		//if file not exists clean doneParts
		doneParts = types.DownloadedParts{
			PartSize: S3PartSize,
		}
	}

	if len(doneParts.Parts) > 0 {
		fd, err = os.OpenFile(fname, os.O_RDWR, 0666)
		if err != nil {
			return doneParts, err
		}
	} else {
		// Create the local file
		fd, err = os.Create(fname)
		if err != nil {
			return doneParts, err
		}
	}
	defer fd.Close()

	asize := int64(0)
	for _, p := range doneParts.Parts {
		asize += p.Size
	}

	cWriterOpts := &writerOptions{
		fp:        fd,
		upSize:    types.UpdateStats{Size: bsize, Asize: asize, DoneParts: doneParts},
		name:      bkey,
		prgNotify: prgNotify,
	}

	ch := make(chan *partS3, S3Concurrency)
	neededPart := getNeededParts(cWriterOpts, bname, bkey, doneParts, bsize)
	//create goroutines to download parts in parallel
	for c := 0; c < S3Concurrency; c++ {
		wg.Add(1)
		go s.downloadPart(ch, &wg)
	}
	for _, el := range neededPart {
		if cWriterOpts.err != nil {
			break
		}
		ch <- el
	}
	close(ch)
	wg.Wait()

	return cWriterOpts.upSize.DoneParts, cWriterOpts.err
}

// DownloadFileByChunks downloads the file from s3 chunk by chunk and passes it to the caller
func (s *S3ctx) DownloadFileByChunks(fname, bname, bkey string) (io.ReadCloser, int64, error) {
	err, bsize := s.GetObjectSize(bname, bkey)
	if err != nil {
		return nil, 0, err
	}
	fmt.Println("size,", bsize)
	req, err := s.ss3.GetObjectWithContext(s.ctx, &s3.GetObjectInput{Bucket: aws.String(bname),
		Key: aws.String(bkey)})
	if err != nil {
		return nil, 0, err
	}
	return req.Body, bsize, nil
}

func (s *S3ctx) ListImages(bname string, prgNotify types.StatsNotifChan) ([]string, error) {
	var img []string
	input := &s3.ListObjectsInput{
		Bucket: aws.String(bname),
	}

	result, err := s.ss3.ListObjectsWithContext(s.ctx, input)
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
	stats := types.UpdateStats{}
	types.SendStats(prgNotify, stats)
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
	if err != nil {
		return "", "", err
	}
	return *uploadResult.ETag, uploadID, err
}

// CompleteUploadedParts is used to complete the multiple uploaded parts
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
