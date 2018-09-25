package awsutil

import (
	"compress/gzip"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"sync/atomic"
)

// stats update
type UpdateStats struct {
	Name  string // always the remote key
	Size  int64  // complete size to upload/download
	Asize int64  // current size uploaded/downloaded
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
		log.Printf("Failed to open file %s/%v", fname, err)
		return location, err
	}

	fileInfo, err := file.Stat()
	if err != nil {
		log.Println("ERROR:", err)
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
		log.Printf("Failed to upload object %s/%v", bname, err)
		return location, err
	}

	log.Printf("Successfully uploaded to %v", result.Location)
	return result.Location, nil
}

func (s *S3ctx) DownloadFile(fname, bname, bkey string, prgNotify NotifChan) error {
	if err := os.MkdirAll(filepath.Dir(fname), 0775); err != nil {
		log.Printf("failed to create dir %s, %v", fname, err)
		return err
	}

	err, bsize := s.GetObjectSize(bname, bkey)
	if err != nil {
		return err
	}

	// Setup the local file
	fd, err := os.Create(fname)
	if err != nil {
		log.Printf("failed to create filer %s, %v", fname, err)
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
		log.Printf("Failed to download object %s/%v", bname, err)
		return err
	}
	log.Printf("Successfully downloaded to %v", bkey)
	return nil
}

func (s *S3ctx) UploadDir(localPath, bname, bkey string, compression bool, prgNotify NotifChan) error {
	walker := make(fileWalk)
	go func() {
		// Gather the files to upload by walking the path recursively.
		if err := filepath.Walk(localPath, walker.Walk); err != nil {
			log.Printf("Walk failed: %v", err)
		}
		close(walker)
	}()

	// For each file found walking upload it to S3.
	for path := range walker {
		rel, err := filepath.Rel(localPath, path)
		if err != nil {
			log.Printf("Unable to get relative path:%s, %s", path, err)
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
