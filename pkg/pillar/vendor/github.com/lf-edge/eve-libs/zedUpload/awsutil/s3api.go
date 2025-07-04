// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package awsutil

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/lf-edge/eve-libs/zedUpload/types"
	"github.com/sirupsen/logrus"
)

const (
	// S3Concurrency parallels parts download/upload limit
	S3Concurrency = 5
	// S3PartSize size of part to download/upload
	S3PartSize = 5 * 1024 * 1024
	// S3PartLeaveError leaves parts to manual resolve errors on uploads
	S3PartLeaveError = true
)

type S3ctx struct {
	client     *s3.Client
	uploader   *manager.Uploader
	downloader *manager.Downloader
	presigner  *s3.PresignClient
	ctx        context.Context
	log        types.Logger
}

// NewAwsCtx initializes AWS S3 context using SDK v2
func NewAwsCtx(id, secret, region string, useIPv6 bool, hctx *http.Client) (*S3ctx, error) {
	ctx := context.Background()
	logger := logrus.New()
	logger.SetLevel(logrus.TraceLevel)

	// Enable dual-stack (IPv4 + IPv6) endpoint if IPv6 is in use.
	dualStackState := aws.DualStackEndpointStateUnset
	if useIPv6 {
		dualStackState = aws.DualStackEndpointStateEnabled
	}
	// Load config with static credentials
	cfg, err := awsConfig.LoadDefaultConfig(ctx,
		awsConfig.WithRegion(region),
		awsConfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(id, secret, ""),
		),
		awsConfig.WithUseDualStackEndpoint(dualStackState),
	)
	if err != nil {
		return nil, err
	}

	// Override HTTP client if provided
	if hctx != nil {
		cfg.HTTPClient = hctx
	}

	client := s3.NewFromConfig(cfg)
	// Presigner for generating pre-signed URLs
	presigner := s3.NewPresignClient(client)

	// Uploader
	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		u.PartSize = S3PartSize
		u.LeavePartsOnError = S3PartLeaveError
		u.Concurrency = S3Concurrency
		u.BufferProvider = manager.NewBufferedReadSeekerWriteToPool(32 * 1024)
	})

	// Downloader
	downloader := manager.NewDownloader(client, func(d *manager.Downloader) {
		d.PartSize = S3PartSize
		d.Concurrency = S3Concurrency
		d.BufferProvider = manager.NewPooledBufferedWriterReadFromProvider(32 * 1024)
	})

	return &S3ctx{
		client:     client,
		uploader:   uploader,
		downloader: downloader,
		presigner:  presigner,
		ctx:        ctx,
		log:        logger,
	}, nil
}

// WithContext sets a custom context (e.g., for cancellation)
func (s *S3ctx) WithContext(ctx context.Context) *S3ctx {
	s.ctx = ctx
	return s
}

// WithLogger attaches a logger
func (s *S3ctx) WithLogger(logger types.Logger) *S3ctx {
	s.log = logger
	return s
}

// CreateBucket creates a new S3 bucket
func (s *S3ctx) CreateBucket(bname string) error {
	input := &s3.CreateBucketInput{
		Bucket: aws.String(bname),
	}
	if s.client.Options().Region != "us-east-1" {
		input.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			// use the generated constant, not a free-form string
			LocationConstraint: s3types.BucketLocationConstraintMeCentral1,
		}
	}
	_, err := s.client.CreateBucket(s.ctx, input)
	if err != nil {
		s.log.Errorf("Failed to create bucket %q: %v", bname, err)
		return err
	}
	return nil
}

// IsBucketAvailable checks if a bucket exists in the account
func (s *S3ctx) IsBucketAvailable(bname string) (bool, error) {
	output, err := s.client.ListBuckets(s.ctx, &s3.ListBucketsInput{})
	if err != nil {
		s.log.Printf("Failed to list buckets: %v", err)
		return false, err
	}
	for _, b := range output.Buckets {
		if aws.ToString(b.Name) == bname {
			return true, nil
		}
	}
	return false, nil
}

// WaitUntilBucketExists waits until the bucket exists or times out
func (s *S3ctx) WaitUntilBucketExists(bname string) bool {
	waiter := s3.NewBucketExistsWaiter(s.client)

	maxWait := 100 * time.Second
	err := waiter.Wait(
		s.ctx,
		&s3.HeadBucketInput{Bucket: aws.String(bname)},
		maxWait,
		func(o *s3.BucketExistsWaiterOptions) {
			// cap the delay between retries to 5s
			o.MaxDelay = 5 * time.Second
		},
	)
	if err != nil {
		s.log.Printf("Error waiting for bucket %q to exist: %v", bname, err)
		return false
	}
	return true
}

// DeleteBucket deletes an S3 bucket
func (s *S3ctx) DeleteBucket(bname string) error {
	_, err := s.client.DeleteBucket(s.ctx, &s3.DeleteBucketInput{Bucket: aws.String(bname)})
	return err
}

// GetObjectURL generates a pre-signed GET URL valid for 1 minute
func (s *S3ctx) GetObjectURL(bname, bkey string) (string, error) {
	resp, err := s.presigner.PresignGetObject(
		s.ctx,
		&s3.GetObjectInput{
			Bucket: aws.String(bname),
			Key:    aws.String(bkey),
		},
		// set a 1-minute expiration
		s3.WithPresignExpires(1*time.Minute),
	)
	if err != nil {
		return "", err
	}
	return resp.URL, nil
}

// DeleteObject removes an object from a bucket
func (s *S3ctx) DeleteObject(bname, bkey string) error {
	_, err := s.client.DeleteObject(s.ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bname),
		Key:    aws.String(bkey),
	})
	return err
}

// GetObjectSize retrieves the size (ContentLength) of an object
func (s *S3ctx) GetObjectSize(bname, bkey string) (int64, error) {
	resp, err := s.client.HeadObject(s.ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bname),
		Key:    aws.String(bkey),
	})
	if err != nil {
		return 0, err
	}
	return *resp.ContentLength, nil
}

// GetObjectMD5 retrieves the ETag (often MD5) of an object
func (s *S3ctx) GetObjectMD5(bname, bkey string) (string, error) {
	resp, err := s.client.HeadObject(s.ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bname),
		Key:    aws.String(bkey),
	})
	if err != nil {
		return "", err
	}
	etag := aws.ToString(resp.ETag)
	return strings.Trim(etag, `"`), nil
}
