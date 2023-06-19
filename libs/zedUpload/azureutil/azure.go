// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package azure

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-pipeline-go/pipeline"
	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/lf-edge/eve/libs/zedUpload/types"
)

const (
	// SingleMB contains chunk size
	SingleMB       int64 = 1024 * 1024
	blobURLPattern       = "https://%s.blob.core.windows.net"
	maxRetries           = 20
	parallelism          = 16
)

type sectionWriter struct {
	count    int64
	offset   int64
	position int64
	part     *types.PartDefinition
	writerAt io.WriterAt
}

func newSectionWriter(c io.WriterAt, off int64, count int64, part *types.PartDefinition) *sectionWriter {
	return &sectionWriter{
		count:    count,
		offset:   off,
		writerAt: c,
		part:     part,
	}
}

// Write implementation for sectionWriter
func (c *sectionWriter) Write(p []byte) (int, error) {
	remaining := c.count - c.position

	if remaining <= 0 {
		return 0, fmt.Errorf("end of section reached: %v", *c.part)
	}

	slice := p

	if int64(len(slice)) > remaining {
		slice = slice[:remaining]
	}

	n, err := c.writerAt.WriteAt(slice, c.offset+c.position)
	c.position += int64(n)
	if err != nil {
		return n, err
	}

	if len(p) > n {
		return n, fmt.Errorf("not enough space for %d bytes: %d", p, n)
	}

	c.part.Size = c.part.Size + int64(n)

	return n, nil
}

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
	p := azblob.NewPipeline(credential, azblob.PipelineOptions{
		HTTPSender: sender,
		RequestLog: azblob.RequestLogOptions{
			LogWarningIfTryOverThreshold: -1,
			SyslogDisabled:               true,
		}})
	return p, nil
}

func getURL(accountURL, accountName, pathPart, queryPart string) (*url.URL, error) {
	if accountURL == "" {
		accountURL = fmt.Sprintf(blobURLPattern, accountName)
	}
	accountURL = strings.TrimSuffix(accountURL, "/")
	if pathPart != "" {
		accountURL = fmt.Sprintf("%s/%s", accountURL, pathPart)
	}
	if queryPart != "" {
		accountURL = fmt.Sprintf("%s?%s", accountURL, queryPart)
	}
	URL, err := url.Parse(accountURL)
	if err != nil {
		return nil, err
	}

	return URL, nil
}

func ListAzureBlob(accountURL, accountName, accountKey, containerName string, httpClient *http.Client) ([]string, error) {
	var imgList []string
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := getURL(accountURL, accountName, containerName, "")
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

func DeleteAzureBlob(accountURL, accountName, accountKey, containerName, remoteFile string, httpClient *http.Client) error {
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := getURL(accountURL, accountName, containerName, "")
	if err != nil {
		return fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}
	containerURL := azblob.NewContainerURL(*URL, p)
	blobURL := containerURL.NewBlockBlobURL(remoteFile)
	ctx := context.Background()
	_, err = blobURL.Delete(ctx, azblob.DeleteSnapshotsOptionInclude, azblob.BlobAccessConditions{})
	return err
}

func DownloadAzureBlob(accountURL, accountName, accountKey, containerName, remoteFile, localFile string,
	objMaxSize int64, httpClient *http.Client, doneParts types.DownloadedParts, prgNotify types.StatsNotifChan) (types.DownloadedParts, error) {

	var file *os.File
	stats := &types.UpdateStats{DoneParts: doneParts}
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return stats.DoneParts, fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := getURL(accountURL, accountName, containerName, "")
	if err != nil {
		return stats.DoneParts, fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}

	// Create a ContainerURL object that wraps the container URL and a request
	// pipeline to make requests.
	containerURL := azblob.NewContainerURL(*URL, p)
	blobURL := containerURL.NewBlockBlobURL(remoteFile)
	ctx := context.Background()
	properties, err := blobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return stats.DoneParts, fmt.Errorf("could not get properties for blob: %v", err)
	}
	objSize := properties.ContentLength()

	if objMaxSize != 0 && objSize > objMaxSize {
		return types.DownloadedParts{PartSize: SingleMB},
			fmt.Errorf("configured image size (%d) is less than size of file (%d)", objMaxSize, objSize)
	}

	tempLocalFile := localFile
	index := strings.LastIndex(tempLocalFile, "/")
	dir_err := os.MkdirAll(tempLocalFile[:index+1], 0755)
	if dir_err != nil {
		return stats.DoneParts, dir_err
	}

	if _, err := os.Stat(localFile); err != nil && os.IsNotExist(err) {
		//if file not exists clean doneParts
		stats.DoneParts = types.DownloadedParts{
			PartSize: SingleMB,
		}
	}

	if len(doneParts.Parts) > 0 {
		file, err = os.OpenFile(localFile, os.O_RDWR, 0666)
		if err != nil {
			return stats.DoneParts, err
		}
	} else {
		// Create the local file
		file, err = os.Create(localFile)
		if err != nil {
			return stats.DoneParts, err
		}
		stats.DoneParts.PartSize = SingleMB
	}
	defer file.Close()

	stats.Size = objSize
	var progressReceiver pipeline.ProgressReceiver
	if prgNotify != nil {
		progressReceiver = func(bytesTransferred int64) {
			stats.Asize = bytesTransferred
			select {
			case prgNotify <- *stats:
			default: //ignore we cannot write
			}
		}
	}
	// calculate downloaded size based on parts
	progress := int64(0)
	for _, p := range stats.DoneParts.Parts {
		progress += p.Size
	}
	progressLock := &sync.Mutex{}

	// use pool of buffers to re-use them if needed without re-allocation
	// The way that azure download azblob.DoBatchTransfer below works,
	// we are downloading `SingleMB` chunks, with a parallelism of `parallelism`.
	// Above, that is set to 16.
	// So we are downloading 16 1MB chunks at a time.
	// We then write those to the correct offset in a file.
	// This is a highly efficient way to download them.
	// However, each call of `io.Copy()` will create a new buffer on start, and
	// remove it on completion.
	// With a parallelism of 16, we will need at least 16 buffers. As file sizes get large,
	// and we require more and more 1MB chunks, there will be more and more buffer created and destroyed.
	// A 1TB file has 1024*1024 1MB chunks, and therefore 1024*1024 buffer create and destroy.
	// This can cause significant overhead.
	//
	// To alleviate this burden, we create a sync.Pool, which creates a reusable pool of buffers.
	// With 16 parallelism, it will create 16 buffers, and then reuse them, reducing the burden.
	var bufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32*1024)
			return &buf
		},
	}

	err = azblob.DoBatchTransfer(ctx, azblob.BatchTransferOptions{
		OperationName: "DownloadAzureBlob",
		TransferSize:  objSize,
		ChunkSize:     SingleMB,
		Parallelism:   parallelism,
		Operation: func(chunkStart int64, count int64, ctx context.Context) error {
			offset := int64(0)
			partNum := int64(0)
			if chunkStart > 0 {
				//calculate part number based on offset (chunkStart) in file
				partNum = int64(math.Floor(float64(chunkStart) / float64(SingleMB)))
			}
			var part *types.PartDefinition
			progressLock.Lock()
			for _, el := range stats.DoneParts.Parts {
				if el.Ind == partNum {
					offset = el.Size
					part = el
					break
				}
			}
			if count-offset == 0 {
				progressLock.Unlock()
				// nothing to download
				return nil
			}
			if part == nil {
				// if no part found, append new
				part = &types.PartDefinition{Ind: partNum}
				stats.DoneParts.Parts = append(stats.DoneParts.Parts, part)
			}
			progressLock.Unlock()
			dr, err := blobURL.Download(ctx, chunkStart+offset, count-offset, azblob.BlobAccessConditions{}, false, azblob.ClientProvidedKeyOptions{})
			if err != nil {
				return err
			}
			body := dr.Body(azblob.RetryReaderOptions{MaxRetryRequests: maxRetries})
			rangeProgress := int64(0)
			body = pipeline.NewResponseBodyProgress(
				body,
				func(bytesTransferred int64) {
					diff := bytesTransferred - rangeProgress
					rangeProgress = bytesTransferred
					progressLock.Lock()
					progress += diff
					progressReceiver(progress)
					progressLock.Unlock()
				})
			// we get buffer from the pool to not allocate
			// new buffer per every chunk inside io.copyBuffer
			// and to not rely on garbage collecting of them
			bp := *bufPool.Get().(*[]byte)
			_, err = io.CopyBuffer(newSectionWriter(file, chunkStart+offset, count-offset, part), body, bp)
			bufPool.Put(&bp)
			if err != nil {
				_ = body.Close()
				return err
			}
			return body.Close()
		},
	})
	if err != nil {
		return stats.DoneParts, err
	}
	// ensure we send the total; it is theoretically possible that it downloaded without error
	// but the progress receiver did not get invoked at the end
	if stats.Asize < stats.Size {
		progressReceiver(stats.Size)
	}
	return stats.DoneParts, nil
}

// DownloadAzureBlobByChunks will process the blob download by chunks, i.e., chunks will be
// responded back on as and when they receive
func DownloadAzureBlobByChunks(accountURL, accountName, accountKey, containerName, remoteFile, localFile string, httpClient *http.Client) (io.ReadCloser, int64, error) {
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := getURL(accountURL, accountName, containerName, "")
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

func UploadAzureBlob(accountURL, accountName, accountKey, containerName, remoteFile, localFile string, httpClient *http.Client) (string, error) {
	var (
		ctx = context.Background()
	)
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return "", fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := getURL(accountURL, accountName, containerName, "")
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

func GetAzureBlobMetaData(accountURL, accountName, accountKey, containerName, remoteFile string, httpClient *http.Client) (int64, string, error) {
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return 0, "", fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := getURL(accountURL, accountName, containerName, "")
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
func GenerateBlobSasURI(accountURL, accountName, accountKey, containerName, remoteFile string, httpClient *http.Client, duration time.Duration) (string, error) {
	credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return "", fmt.Errorf("Invalid credentials with error: " + err.Error())
	}

	// Checking whether blob exists or not before generating SAS URI
	_, _, err = GetAzureBlobMetaData(accountURL, accountName, accountKey, containerName, remoteFile, httpClient)
	if err != nil {
		return "", err
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

	URL, err := getURL(accountURL, accountName, fmt.Sprintf("%s/%s", containerName, remoteFile), qp)
	if err != nil {
		return "", fmt.Errorf("invalid URL for container name %s: %v", containerName, err)
	}

	return URL.String(), nil
}

// UploadPartByChunk upload an individual chunk given an io.ReadSeeker and partID
func UploadPartByChunk(accountURL, accountName, accountKey, containerName, remoteFile, partID string, httpClient *http.Client, chunk io.ReadSeeker) error {
	var (
		ctx = context.Background()
	)
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := getURL(accountURL, accountName, containerName, "")
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
func UploadBlockListToBlob(accountURL, accountName, accountKey, containerName, remoteFile string, httpClient *http.Client, blocks []string) error {
	var (
		ctx = context.Background()
	)
	p, err := newPipeline(accountName, accountKey, httpClient)
	if err != nil {
		return fmt.Errorf("unable to create pipeline: %v", err)
	}

	URL, err := getURL(accountURL, accountName, containerName, "")
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
