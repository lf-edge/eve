package aws

import (
	"fmt"
	"net/http"
)

func S3UploadFile(hctx *http.Client, region, key, secret, bucket, object, objloc string, compression bool) (string, error) {
	var location string
	var err error
	sc := NewAwsCtx(key, secret, region, hctx)
	if sc == nil {
		return location, fmt.Errorf("unable to create S3 context")
	}
	//IsBucketAvailable fails for list buckets and tries
	// to create a duplicate bucket
	//_, ok := sc.IsBucketAvailable(bucket)

	// Wait Until Bucket is checks if bucket is available
	// else waits for 5*20 and finally returns false
	ok := sc.WaitUntilBucketExists(bucket)

	if !ok {
		err = sc.CreateBucket(bucket)
		if err != nil {
			return location, err
		}

	}

	location, err = sc.UploadFile(objloc, bucket, object, compression)
	if err != nil {
		return location, err
	}

	return location, err
}

func S3DownloadFile(hctx *http.Client, region, key, secret, bucket, object, objloc string) error {
	sc := NewAwsCtx(key, secret, region, hctx)
	if sc == nil {
		return fmt.Errorf("unable to create S3 context")
	}

	/* --- No need for this check, becausing listing of bucket requires
	      --- different permission, that object level permission
	   	err, ok := sc.IsBucketAvailable(bucket)
	   	if !ok {
	   		return err
	   	}
	*/
	err := sc.DownloadFile(objloc, bucket, object)
	if err != nil {
		return err
	}

	return nil
}
