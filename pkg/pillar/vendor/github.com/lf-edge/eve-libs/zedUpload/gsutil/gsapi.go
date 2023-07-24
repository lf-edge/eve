// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package gsutil

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

//GSctx context for google cloud storage communication
type GSctx struct {
	gsClient  *storage.Client
	projectID string
	ctx       context.Context
}

//NewGsCtx creates GSctx for provided options
//it uses data from apiKeyJSONContent to decode service account credentials
//setting of requestWriteAccess adds write scope to token in case of provided hctx
func NewGsCtx(ctx context.Context, projectID, apiKeyJSONContent string, hctx *http.Client, requestWriteAccess bool) (*GSctx, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var options []option.ClientOption

	data, err := base64.StdEncoding.DecodeString(apiKeyJSONContent)
	if err != nil {
		data = []byte(apiKeyJSONContent)
	}

	if hctx != nil {
		// we use different flow for provided http client
		// because of WithHTTPClient overrides other options
		// and removes authentication, so we use oauth2 transport
		scope := "https://www.googleapis.com/auth/devstorage.read_only"
		if requestWriteAccess {
			scope = "https://www.googleapis.com/auth/devstorage.read_write"
		}
		JWTCfg, err := google.JWTConfigFromJSON(data, scope)
		if err != nil {
			return nil, fmt.Errorf("JWTConfigFromJSON error: %v", err)
		}
		transport := &oauth2.Transport{
			Source: JWTCfg.TokenSource(ctx),
			Base:   hctx.Transport,
		}
		options = []option.ClientOption{option.WithHTTPClient(&http.Client{Transport: transport})}
	} else {
		options = append(options, option.WithCredentialsJSON(data))
	}
	client, err := storage.NewClient(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("NewClient error: %v", err)
	}
	gsCtx := GSctx{
		gsClient:  client,
		projectID: projectID,
		ctx:       ctx,
	}
	return &gsCtx, nil
}

//CreateBucket creates bucket with the given name
func (s *GSctx) CreateBucket(bname string) error {
	err := s.gsClient.Bucket(bname).Create(s.ctx, s.projectID, nil)
	if err != nil {
		log.Printf("Failed to create bucket %s in project %s/%v", bname, s.projectID, err)
		return err
	}

	return nil
}

//IsBucketAvailable checks if the bucket with the given name available
func (s *GSctx) IsBucketAvailable(bname string) (bool, error) {
	for {
		bi, err := s.gsClient.Buckets(s.ctx, s.projectID).Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("Failed to list buckets %s in project %s/%s", bname, s.projectID, err.Error())
			return false, err
		}
		if bi == nil {
			break
		}
		if bi.Name == bname {
			return true, nil
		}
	}

	return false, nil
}

//DeleteBucket removes the bucket
func (s *GSctx) DeleteBucket(bname string) error {
	return s.gsClient.Bucket(bname).Delete(s.ctx)
}

//DeleteObject removes the object from bucket
func (s *GSctx) DeleteObject(bname, bkey string) error {
	return s.gsClient.Bucket(bname).Object(bkey).Delete(s.ctx)
}

//GetObjectSize returns the size of object in bytes
func (s *GSctx) GetObjectSize(bname, bkey string) (int64, error) {
	attrs, err := s.gsClient.Bucket(bname).Object(bkey).Attrs(s.ctx)
	if err != nil {
		return 0, err
	}
	return attrs.Size, nil
}

//GetObjectMD5 returns hex string of MD5 hash of object
func (s *GSctx) GetObjectMD5(bname, bkey string) (string, error) {
	attrs, err := s.gsClient.Bucket(bname).Object(bkey).Attrs(s.ctx)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(attrs.MD5), nil
}
