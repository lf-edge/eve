// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package awsutil

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/aws/smithy-go"
	"github.com/lf-edge/eve-libs/zedUpload/types"
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
	maxPartSize         int64
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
	// it is quite unexpected but nice to check
	if r.writtenBytes > r.maxPartSize {
		// invalidating part
		r.writerGlobalOptions.upSize.DoneParts.SetPartSize(r.partInd, 0)
		r.writerGlobalOptions.donePartsLock.Unlock()
		return 0, fmt.Errorf("written (%d) more than expected (%d)", r.writtenBytes, r.maxPartSize)
	}
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

	// Check if the bucket exists; if not, create it.
	_, err := s.client.HeadBucket(s.ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bname),
	})
	if err != nil {
		// We got an error from HeadBucket; inspect it
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "NoSuchBucket", "NotFound":
				// Bucket doesn't exist — go ahead and create it
				s.log.Printf("Creating bucket in %s region\n", s.client.Options().Region)
				if err := s.CreateBucket(bname); err != nil {
					return location, err
				}

			case "PermanentRedirect", "BadRequest":
				// The bucket exists, but in a different region (or wrong endpoint).
				// Treat that as "it exists" and move on.
				s.log.Printf("Bucket %q exists in another region; continuing\n", bname)

			default:
				// Some other error (permissions, networking, etc.)
				return location, fmt.Errorf("unable to verify bucket %q: %w", bname, err)
			}
		} else {
			// Not an AWS API error?
			return location, fmt.Errorf("unexpected error checking bucket %q: %w", bname, err)
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
	go func() {
		var w io.WriteCloser = writer
		if compression {
			w = gzip.NewWriter(writer)
		}
		_, err := io.Copy(w, creader)
		w.Close()
		writer.CloseWithError(err)
	}()

	result, err := s.uploader.Upload(s.ctx, &s3.PutObjectInput{
		Bucket: aws.String(bname),
		Key:    aws.String(bkey),
		Body:   reader,
	})
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
	for p := range ch {
		if p.cWriter.writerGlobalOptions.err != nil {
			continue
		}
		rangeHeader := fmt.Sprintf("bytes=%d-%d", p.start, p.start+p.size-1)
		resp, err := s.client.GetObject(s.ctx, &s3.GetObjectInput{
			Bucket: aws.String(p.bname),
			Key:    aws.String(p.bkey),
			Range:  aws.String(rangeHeader),
		})
		if err != nil {
			p.cWriter.writerGlobalOptions.err = err
			continue
		}
		defer resp.Body.Close()

		buf := make([]byte, 32*1024)
		offset := int64(0)

		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				_, writeErr := p.cWriter.WriteAt(buf[:n], offset)
				if writeErr != nil {
					p.cWriter.writerGlobalOptions.err = writeErr
					break
				}
				offset += int64(n)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				p.cWriter.writerGlobalOptions.err = readErr
				break
			}
		}
	}
}

// getNeededParts returns description of parts of file to download
// it skips parts from doneParts slice which are fully downloaded
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
				maxPartSize:         S3PartSize,
			},
			bname: bname,
			bkey:  bkey,
			start: S3PartSize*i + currentPartSize,
			size:  S3PartSize - currentPartSize,
		}
		if i == partsCount-1 {
			part.size = size - (partsCount-1)*S3PartSize - currentPartSize
			// adjust maxPartSize for last part to the remaining size
			part.cWriter.maxPartSize = size - (partsCount-1)*S3PartSize
		}
		if part.size > 0 {
			needed = append(needed, part)
		}
	}
	return needed
}

func (s *S3ctx) DownloadFile(fname, bname, bkey string,
	objMaxSize int64, doneParts types.DownloadedParts, prgNotify types.StatsNotifChan) (types.DownloadedParts, error) {

	bsize, err := s.GetObjectSize(bname, bkey)
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

	// if PartSize differ from saved clean doneParts
	// we may hit this in case of S3PartSize change or from different type of datastore
	if doneParts.PartSize != S3PartSize {
		doneParts = types.DownloadedParts{PartSize: S3PartSize}
	}
	fd, err := os.OpenFile(fname, os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		return doneParts, err
	}
	defer fd.Close()

	// compute already downloaded
	var asize int64
	for _, p := range doneParts.Parts {
		asize += p.Size
	}
	opts := &writerOptions{
		fp:        fd,
		upSize:    types.UpdateStats{Size: bsize, Asize: asize, DoneParts: doneParts},
		name:      bkey,
		prgNotify: prgNotify,
	}
	ch := make(chan *partS3, S3Concurrency)
	parts := getNeededParts(opts, bname, bkey, doneParts, bsize)
	// spawn workers
	var wg sync.WaitGroup
	for i := 0; i < S3Concurrency; i++ {
		wg.Add(1)
		go s.downloadPart(ch, &wg)
	}
	for _, p := range parts {
		ch <- p
	}
	close(ch)
	wg.Wait()
	return opts.upSize.DoneParts, opts.err
}

// DownloadFileByChunks downloads the file from s3 chunk by chunk and passes it to the caller
func (s *S3ctx) DownloadFileByChunks(fname, bname, bkey string) (io.ReadCloser, int64, error) {
	bsize, err := s.GetObjectSize(bname, bkey)
	if err != nil {
		return nil, 0, err
	}

	resp, err := s.client.GetObject(s.ctx, &s3.GetObjectInput{
		Bucket: aws.String(bname), Key: aws.String(bkey),
	})
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, bsize, nil
}

func (s *S3ctx) ListImages(bname string, prgNotify types.StatsNotifChan) ([]string, error) {
	var imgs []string
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bname),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(s.ctx)
		if err != nil {
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchBucket" {
				return imgs, apiErr
			}
			return imgs, err
		}
		for _, obj := range page.Contents {
			imgs = append(imgs, aws.ToString(obj.Key))
		}
	}
	types.SendStats(prgNotify, types.UpdateStats{})
	return imgs, nil
}

func (s *S3ctx) GetObjectMetaData(bname, bkey string) (int64, string, error) {
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

// UploadPart is used to upload the given chunk of data into the Multipart file
func (s *S3ctx) UploadPart(bname, bkey string, chunk []byte, partNumber int64, uploadID string) (string, string, error) {
	// initializing Multipart request before uploading parts
	if uploadID == "" {
		ct := http.DetectContentType(chunk)
		out, err := s.client.CreateMultipartUpload(s.ctx, &s3.CreateMultipartUploadInput{
			Bucket:      aws.String(bname),
			Key:         aws.String(bkey),
			ContentType: aws.String(ct),
		})
		if err != nil {
			return "", "", err
		}
		uploadID = aws.ToString(out.UploadId)
	}
	res, err := s.client.UploadPart(s.ctx, &s3.UploadPartInput{
		Bucket:        aws.String(bname),
		Key:           aws.String(bkey),
		PartNumber:    aws.Int32(int32(partNumber)),
		UploadId:      aws.String(uploadID),
		Body:          bytes.NewReader(chunk),
		ContentLength: aws.Int64(int64(len(chunk))),
	})
	if err != nil {
		return "", "", err
	}
	return aws.ToString(res.ETag), uploadID, nil
}

// CompleteUploadedParts is used to complete the multiple uploaded parts
func (s *S3ctx) CompleteUploadedParts(bname, bkey, uploadID string, parts []string) error {
	completed := make([]s3types.CompletedPart, len(parts))
	for i, etag := range parts {
		completed[i] = s3types.CompletedPart{
			ETag:       aws.String(etag),
			PartNumber: aws.Int32(int32(i + 1)),
		}
	}
	_, err := s.client.CompleteMultipartUpload(s.ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bname),
		Key:      aws.String(bkey),
		UploadId: aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{
			Parts: completed,
		},
	})
	return err
}

// GetSignedURL is used to generate the URI which can be used to access the resource until the URI expries
func (s *S3ctx) GetSignedURL(bname, bkey string, duration time.Duration) (string, error) {
	// ensure object exists
	if _, err := s.client.HeadObject(s.ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bname), Key: aws.String(bkey),
	}); err != nil {
		return "", err
	}
	presigned, err := s.presigner.PresignGetObject(s.ctx, &s3.GetObjectInput{
		Bucket: aws.String(bname), Key: aws.String(bkey),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = duration
	})
	if err != nil {
		return "", err
	}
	return presigned.URL, nil
}
