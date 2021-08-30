// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package azure

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-pipeline-go/pipeline"
	"github.com/Azure/azure-storage-blob-go/azblob"
)

const (
	// SingleMB contains chunk size
	SingleMB       int64 = 1024 * 1024
	blobURLPattern       = "https://%s.blob.core.windows.net/%s"
	maxRetries           = 20
	parallelism          = 128
)

// UpdateStats contains the information for the progress of an update
type UpdateStats struct {
	Size          int64    // complete size to upload/download
	Asize         int64    // current size uploaded/downloaded
	List          []string //list of images at given path
	Error         error
	BodyLength    int   // Body legth in http response
	ContentLength int64 // Content length in http response
}

// NotifChan is the uploading/downloading progress notification channel
type NotifChan chan UpdateStats

// newHTTPClientFactory creates a HTTPClientPolicyFactory object that sends HTTP requests using a provided http.Client
func newHTTPClientFactory(pipelineHTTPClient *http.Client) pipeline.Factory {
	return pipeline.FactoryFunc(func(next pipeline.Policy, po *pipeline.PolicyOptions) pipeline.PolicyFunc {
		return func(ctx context.Context, request pipeline.Request) (pipeline.Response, error) {
			r, err := pipelineHTTPClient.Do(request.WithContext(ctx))
			if err != nil {
				err = pipeline.NewError(err, "HTTP request failed")
			}
			return pipeline.NewHTTPResponse(r), err
		}
	})
}

func newPipeline(accountName, accountKey string, httpClient *http.Client) (pipeline.Pipeline, error) {
	var sender pipeline.Factory
	if httpClient != nil {
		sender = newHTTPClientFactory(httpClient)
	}
	credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return nil, fmt.Errorf("Invalid credentials with error: " + err.Error())
	}
	p := azblob.NewPipeline(credential, azblob.PipelineOptions{HTTPSender: sender})
	return p, nil
}

func ListAzureBlob(accountName, accountKey, containerName string, httpClient *http.Client) ([]string, error) {
	var imgList []string
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := url.Parse(fmt.Sprintf(blobURLPattern, accountName, containerName))
	if err != nil {
		return nil, fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}
	containerURL := azblob.NewContainerURL(*URL, p)

	ctx := context.Background()
	for marker := (azblob.Marker{}); marker.NotDone(); {
		// Get a result segment starting with the blob indicated by the current Marker.
		listBlob, err := containerURL.ListBlobsFlatSegment(ctx, marker, azblob.ListBlobsSegmentOptions{})
		if err != nil {
			return nil, fmt.Errorf("error listing blobs for container %s: %v", containerName, err)
		}

		// ListBlobs returns the start of the next segment; you MUST use this to get
		// the next segment (after processing the current result segment).
		marker = listBlob.NextMarker

		// Process the blobs returned in this result segment (if the segment is empty, the loop body won't execute)
		for _, blobInfo := range listBlob.Segment.BlobItems {
			imgList = append(imgList, blobInfo.Name)
		}
	}
	return imgList, nil
}

func DeleteAzureBlob(accountName, accountKey, containerName, remoteFile string, httpClient *http.Client) error {
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := url.Parse(fmt.Sprintf(blobURLPattern, accountName, containerName))
	if err != nil {
		return fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}
	containerURL := azblob.NewContainerURL(*URL, p)
	blobURL := containerURL.NewBlockBlobURL(remoteFile)
	ctx := context.Background()
	_, err = blobURL.Delete(ctx, azblob.DeleteSnapshotsOptionInclude, azblob.BlobAccessConditions{})
	return err
}

func DownloadAzureBlob(accountName, accountKey, containerName, remoteFile, localFile string,
	objSize int64, httpClient *http.Client, prgNotify NotifChan) error {

	stats := UpdateStats{}
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := url.Parse(fmt.Sprintf(blobURLPattern, accountName, containerName))
	if err != nil {
		return fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}

	// Create a ContainerURL object that wraps the container URL and a request
	// pipeline to make requests.
	containerURL := azblob.NewContainerURL(*URL, p)
	blobURL := containerURL.NewBlockBlobURL(remoteFile)
	ctx := context.Background()

	tempLocalFile := localFile
	index := strings.LastIndex(tempLocalFile, "/")
	dir_err := os.MkdirAll(tempLocalFile[:index+1], 0755)
	if dir_err != nil {
		return dir_err
	}

	file, err := os.Create(localFile)
	if err != nil {
		return err
	}
	defer file.Close()

	stats.Size = objSize
	var progressReceiver pipeline.ProgressReceiver
	if prgNotify != nil {
		progressReceiver = func(bytesTransferred int64) {
			stats.Asize = bytesTransferred
			select {
			case prgNotify <- stats:
			default: //ignore we cannot write
			}
		}
	}
	// we could just return the error that comes from this function, but in the case of
	// a nil error, we want to be sure we sent the total
	if err := azblob.DownloadBlobToFile(ctx, blobURL.BlobURL, 0, 0, file, azblob.DownloadFromBlobOptions{
		BlockSize:                  SingleMB,
		Parallelism:                uint16(parallelism),
		RetryReaderOptionsPerBlock: azblob.RetryReaderOptions{MaxRetryRequests: maxRetries},
		Progress:                   progressReceiver,
	}); err != nil {
		return err
	}
	// ensure we send the total; it is theoretically possible that it downloaded without error
	// but the progress receiver did not get invoked at the end
	if stats.Asize < stats.Size {
		progressReceiver(stats.Size)
	}
	return nil
}

// DownloadAzureBlobByChunks will process the blob download by chunks, i.e., chunks will be
// responded back on as and hwen they recieve
func DownloadAzureBlobByChunks(accountName, accountKey, containerName, remoteFile, localFile string, httpClient *http.Client) (io.ReadCloser, int64, error) {
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := url.Parse(fmt.Sprintf(blobURLPattern, accountName, containerName))
	if err != nil {
		return nil, 0, fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}

	// Create a ContainerURL object that wraps the container URL and a request
	// pipeline to make requests.
	containerURL := azblob.NewContainerURL(*URL, p)
	blobURL := containerURL.NewBlockBlobURL(remoteFile)
	ctx := context.Background()
	downloadResponse, err := blobURL.Download(ctx, 0, azblob.CountToEnd, azblob.BlobAccessConditions{}, false, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("could not start download: %v", err)
	}

	readCloser := downloadResponse.Body(azblob.RetryReaderOptions{MaxRetryRequests: maxRetries})

	properties, err := blobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("could not get properties for blob: %v", err)
	}
	return readCloser, int64(properties.ContentLength()), nil
}

func UploadAzureBlob(accountName, accountKey, containerName, remoteFile, localFile string, httpClient *http.Client) (string, error) {
	var (
		ctx = context.Background()
	)
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return "", fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := url.Parse(fmt.Sprintf(blobURLPattern, accountName, containerName))
	if err != nil {
		return "", fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}

	// Create a ContainerURL object that wraps the container URL and a request
	// pipeline to make requests.
	containerURL := azblob.NewContainerURL(*URL, p)

	// create the blob, but we can handle if the container already exists
	if _, err := containerURL.Create(ctx, nil, azblob.PublicAccessNone); err != nil {
		// we can handle if it already exists
		var (
			storageError azblob.StorageError
			ok           bool
		)
		if storageError, ok = err.(azblob.StorageError); !ok {
			return "", fmt.Errorf("error creating container %s: %v", containerName, err)
		}
		sct := storageError.ServiceCode()
		if sct != azblob.ServiceCodeContainerAlreadyExists {
			return "", fmt.Errorf("error creating container %s: %v", containerName, err)
		}
		// it was an existing container, which is fine
	}

	blob := containerURL.NewBlockBlobURL(remoteFile)

	file, err := os.Open(localFile)
	if err != nil {
		return "", fmt.Errorf("unable to open local file %s: %v", localFile, err)
	}
	defer file.Close()

	if _, err := azblob.UploadFileToBlockBlob(ctx, file, blob, azblob.UploadToBlockBlobOptions{}); err != nil {
		return "", fmt.Errorf("failed to upload file: %v", err)
	}
	return blob.String(), nil
}

func GetAzureBlobMetaData(accountName, accountKey, containerName, remoteFile string, httpClient *http.Client) (int64, string, error) {
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return 0, "", fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := url.Parse(fmt.Sprintf(blobURLPattern, accountName, containerName))
	if err != nil {
		return 0, "", fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}

	// Create a ContainerURL object that wraps the container URL and a request
	// pipeline to make requests.
	containerURL := azblob.NewContainerURL(*URL, p)
	blobURL := containerURL.NewBlockBlobURL(remoteFile)
	ctx := context.Background()
	properties, err := blobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return 0, "", fmt.Errorf("could not get properties for blob: %v", err)
	}
	stringHex := hex.EncodeToString(properties.ContentMD5())
	return properties.ContentLength(), stringHex, nil
}

// GenerateBlobSasURI is used to generate the URI which can be used to access the blob until the the URI expries
func GenerateBlobSasURI(accountName, accountKey, containerName, remoteFile string, httpClient *http.Client, duration time.Duration) (string, error) {
	credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return "", fmt.Errorf("Invalid credentials with error: " + err.Error())
	}

	// Set the desired SAS signature values and sign them with the shared key credentials to get the SAS query parameters.
	sasQueryParams, err := azblob.BlobSASSignatureValues{
		Protocol:      azblob.SASProtocolHTTPS, // Users MUST use HTTPS (not HTTP)
		ExpiryTime:    time.Now().UTC().Add(duration),
		StartTime:     time.Now(),
		ContainerName: containerName,
		BlobName:      remoteFile,
		Permissions:   azblob.BlobSASPermissions{Read: true}.String(),
	}.NewSASQueryParameters(credential)
	if err != nil {
		return "", fmt.Errorf("could not generated SAS URI: %v", err)
	}

	// Create the URL of the resource you wish to access and append the SAS query parameters.
	// Since this is a blob SAS, the URL is to the Azure storage blob.
	qp := sasQueryParams.Encode()

	sasURI := fmt.Sprintf("%s/%s?%s", blobURLPattern, remoteFile, qp)

	return sasURI, nil
}

// UploadPartByChunk upload an individual chunk given an io.ReadSeeker and partID
func UploadPartByChunk(accountName, accountKey, containerName, remoteFile, partID string, httpClient *http.Client, chunk io.ReadSeeker) error {
	var (
		ctx = context.Background()
	)
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := url.Parse(fmt.Sprintf(blobURLPattern, accountName, containerName))
	if err != nil {
		return fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}

	// Create a ContainerURL object that wraps the container URL and a request
	// pipeline to make requests.
	containerURL := azblob.NewContainerURL(*URL, p)

	// create the blob, but we can handle if the container already exists
	if _, err := containerURL.Create(ctx, nil, azblob.PublicAccessNone); err != nil {
		// we can handle if it already exists
		var (
			storageError azblob.StorageError
			ok           bool
		)
		if storageError, ok = err.(azblob.StorageError); !ok {
			return fmt.Errorf("error creating container %s: %v", containerName, err)
		}
		sct := storageError.ServiceCode()
		if sct != azblob.ServiceCodeContainerAlreadyExists {
			return fmt.Errorf("error creating container %s: %v", containerName, err)
		}
		// it was an existing container, which is fine
	}

	blob := containerURL.NewBlockBlobURL(remoteFile)

	if _, err := blob.StageBlock(ctx, partID, chunk, azblob.LeaseAccessConditions{}, nil, azblob.ClientProvidedKeyOptions{}); err != nil {
		return fmt.Errorf("failed to upload chunk %s: %v", partID, err)
	}
	return nil
}

// UploadBlockListToBlob used to complete the list of parts which are already uploaded in block blob
func UploadBlockListToBlob(accountName, accountKey, containerName, remoteFile string, httpClient *http.Client, blocks []string) error {
	var (
		ctx = context.Background()
	)
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := url.Parse(fmt.Sprintf(blobURLPattern, accountName, containerName))
	if err != nil {
		return fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}

	// Create a ContainerURL object that wraps the container URL and a request
	// pipeline to make requests.
	containerURL := azblob.NewContainerURL(*URL, p)

	// create the blob, but we can handle if the container already exists
	if _, err := containerURL.Create(ctx, nil, azblob.PublicAccessNone); err != nil {
		// we can handle if it already exists
		var (
			storageError azblob.StorageError
			ok           bool
		)
		if storageError, ok = err.(azblob.StorageError); !ok {
			return fmt.Errorf("error creating container %s: %v", containerName, err)
		}
		sct := storageError.ServiceCode()
		if sct != azblob.ServiceCodeContainerAlreadyExists {
			return fmt.Errorf("error creating container %s: %v", containerName, err)
		}
		// it was an existing container, which is fine
	}

	blob := containerURL.NewBlockBlobURL(remoteFile)

	if _, err := blob.CommitBlockList(ctx, blocks, azblob.BlobHTTPHeaders{}, azblob.Metadata{}, azblob.BlobAccessConditions{}, azblob.DefaultAccessTier, nil, azblob.ClientProvidedKeyOptions{}); err != nil {
		return fmt.Errorf("failed to commit block list: %v", err)
	}
	return nil
}
