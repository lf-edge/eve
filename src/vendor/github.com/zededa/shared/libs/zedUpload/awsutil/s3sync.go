package aws

import (
	"compress/gzip"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"io"
	"os"
	"path"
	"path/filepath"
	"log"
)

func (s *S3ctx) UploadFile(fname, bname, bkey string, compression bool) (string, error) {
	location := ""
	file, err := os.Open(fname)
	if err != nil {
		log.Printf("Failed to open file %s/%v", fname, err)
		return location, err
	}

	reader, writer := io.Pipe()
	if compression {
		// Note required, but you could zip the file prior to uploading it
		// using io.Pipe read/writer to stream gzip'ed file contents.
		go func() {
			gw := gzip.NewWriter(writer)
			io.Copy(gw, file)

			file.Close()
			gw.Close()
			writer.Close()
		}()
	} else {
		go func() {
			io.Copy(writer, file)
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

func (s *S3ctx) DownloadFile(fname, bname, bkey string) error {
	if err := os.MkdirAll(filepath.Dir(fname), 0775); err != nil {
		log.Printf("failed to create dir %s, %v", fname, err)
		return err
	}

	// Setup the local file
	fd, err := os.Create(fname)
	if err != nil {
		log.Printf("failed to create filer %s, %v", fname, err)
		return err
	}
	defer fd.Close()
	_, err = s.dn.Download(fd, &s3.GetObjectInput{Bucket: aws.String(bname),
		Key: aws.String(bkey)})
	if err != nil {
		log.Printf("Failed to download object %s/%v", bname, err)
		return err
	}
	log.Printf("Successfully downloaded to %v", bkey)
	return nil
}

func (s *S3ctx) UploadDir(localPath, bname, bkey string, compression bool) error {
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
		s.UploadFile(rel, bname, bkey, compression)
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

func (s *S3ctx) DownloadDir(localpath, bname, prefix string) error {
	d := downloader{s, bname, localpath}

	client := s3.New(nil)
	err := client.ListObjectsPages(&s3.ListObjectsInput{Bucket: aws.String(bname), Prefix: aws.String(prefix)}, d.eachPage)

	return err
}

type downloader struct {
	*S3ctx
	bucket, dir string
}

func (d *downloader) eachPage(page *s3.ListObjectsOutput, more bool) bool {
	for _, obj := range page.Contents {
		d.DownloadFile(path.Join(d.dir, *obj.Key), d.bucket, *obj.Key)
	}

	return true
}
