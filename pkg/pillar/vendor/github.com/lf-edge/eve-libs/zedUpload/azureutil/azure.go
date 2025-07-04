// Copyright(c) 2025 Zededa, Inc.
// All rights reserved.

package azure

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
	"github.com/lf-edge/eve-libs/zedUpload/types"
)

const (
	// SingleMB contains chunk size
	SingleMB    int64 = 4 * 1024 * 1024
	parallelism       = 16
)

// buffer pool for streaming IO (32KB buffers)
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

type readSeekCloser struct {
	io.ReadSeeker
}

func (r readSeekCloser) Close() error {
	return nil
}

// sectionWriter wraps an *os.File to implement io.Writer by using WriteAt and advancing an offset
type sectionWriter struct {
	f   *os.File
	off int64
}

func (w *sectionWriter) Write(p []byte) (int, error) {
	n, err := w.f.WriteAt(p, w.off)
	if err != nil {
		return n, err
	}
	w.off += int64(n)
	return n, nil
}

// pool of writerAtOffset to avoid per-chunk allocations
var writerPool = sync.Pool{
	New: func() interface{} {
		return &sectionWriter{}
	},
}

// pool of sectionWriter to avoid per-chunk allocations
var sectionWriterPool = sync.Pool{
	New: func() interface{} {
		return &sectionWriter{}
	},
}

// newSectionWriter retrieves a pooled sectionWriter set to write at f starting at off
func newSectionWriter(f *os.File, off int64) *sectionWriter {
	w := sectionWriterPool.Get().(*sectionWriter)
	w.f = f
	w.off = off
	return w
}

// Adapter that turns *http.Client into a policy.Transporter:
type httpClientTransporter struct {
	client *http.Client
}

func (t *httpClientTransporter) Do(req *http.Request) (*http.Response, error) {
	return t.client.Do(req)
}

// clientOptionsFromHTTP wraps your *http.Client into azcore.ClientOptions.
func clientOptionsFromHTTP(httpClient *http.Client) azcore.ClientOptions {
	return azcore.ClientOptions{
		Transport: &httpClientTransporter{client: httpClient},
	}
}

// getContainerClient creates and returns an Azure Blob Storage container client.
// getContainerClient creates a Container client with your custom httpClient.
func getContainerClient(
	accountURL, accountName, accountKey, containerName string,
	httpClient *http.Client,
) (*container.Client, error) {
	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}
	svcURL := strings.TrimSuffix(accountURL, "/")
	svcClient, err := service.NewClientWithSharedKeyCredential(
		svcURL,
		cred,
		&service.ClientOptions{
			ClientOptions: clientOptionsFromHTTP(httpClient),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create service client: %w", err)
	}
	return svcClient.NewContainerClient(containerName), nil
}

// getContainerAndBlockBlobClients now also takes httpClient
func getContainerAndBlockBlobClients(
	accountURL, accountName, accountKey, containerName, blobName string,
	httpClient *http.Client,
) (*container.Client, *blockblob.Client, error) {
	containerClient, err := getContainerClient(
		accountURL, accountName, accountKey, containerName, httpClient,
	)
	if err != nil {
		return nil, nil, err
	}
	blobClient := containerClient.NewBlockBlobClient(blobName)
	return containerClient, blobClient, nil
}

// ListAzureBlob lists all blobs in a container. Uses Azure's paginated listing with marker.
// Returns a slice of blob names ([]string).
func ListAzureBlob(
	accountURL, accountName, accountKey, containerName string,
	httpClient *http.Client,
) ([]string, error) {
	var imgList []string

	containerClient, err := getContainerClient(
		accountURL, accountName, accountKey, containerName, httpClient,
	)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := containerClient.NewListBlobsFlatPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list blobs: %v", err)
		}
		for _, blob := range page.Segment.BlobItems {
			imgList = append(imgList, *blob.Name)
		}
	}

	return imgList, nil
}

// DeleteAzureBlob deletes a blob from Azure Storage. Deletes snapshots too (DeleteSnapshotsOptionInclude).
func DeleteAzureBlob(
	accountURL, accountName, accountKey, containerName, remoteFile string,
	httpClient *http.Client,
) error {
	_, blobClient, err := getContainerAndBlockBlobClients(
		accountURL, accountName, accountKey, containerName, remoteFile, httpClient,
	)
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	// Set deletion options: include snapshots
	deleteSnapshots := azblob.DeleteSnapshotsOptionTypeInclude

	// Perform the delete
	ctx := context.Background()
	_, err = blobClient.Delete(ctx, &azblob.DeleteBlobOptions{
		DeleteSnapshots: &deleteSnapshots,
	})
	if err != nil {
		return fmt.Errorf("failed to delete blob: %v", err)
	}

	return nil
}

// DownloadAzureBlob is a parallel, resumable, chunked download with progress.
// Steps:
//  1. Open/create local file.
//  2. Reuse existing downloaded parts (doneParts) if resuming.
//  3. Uses DoBatchTransfer:
//     a. Splits download into SingleMB (1 MB) chunks.
//     b. Downloads 16 parts in parallel (parallelism).
//     c. Uses buffer pool (sync.Pool) to reuse memory.
//     d. Tracks progress and sends updates via prgNotify.
//     e. Resumable, efficient for large files. Ensures chunks are written to correct
//     offsets using sectionWriter.
func DownloadAzureBlob(
	accountURL, accountName, accountKey, containerName, blobName, localFile string,
	objMaxSize int64,
	httpClient *http.Client,
	doneParts types.DownloadedParts,
	prgNotify types.StatsNotifChan,
) (types.DownloadedParts, error) {

	stats := &types.UpdateStats{DoneParts: doneParts}

	_, blobClient, err := getContainerAndBlockBlobClients(
		accountURL, accountName, accountKey, containerName, blobName, httpClient,
	)
	if err != nil {
		return stats.DoneParts, fmt.Errorf("Error: %v", err)
	}

	ctx := context.Background()
	properties, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return stats.DoneParts, fmt.Errorf("could not get blob properties: %v", err)
	}
	objSize := *properties.ContentLength

	if objMaxSize > 0 && objSize > objMaxSize {
		return stats.DoneParts, fmt.Errorf("blob too large (%d bytes), max allowed is %d", objSize, objMaxSize)
	}
	stats.Size = objSize

	// Prepare file
	if err := os.MkdirAll(filepath.Dir(localFile), 0755); err != nil {
		return stats.DoneParts, err
	}

	f, err := os.OpenFile(localFile, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return stats.DoneParts, fmt.Errorf("cannot open file: %v", err)
	}
	defer f.Close()

	totalChunks := int((objSize + SingleMB - 1) / SingleMB)
	progress := int64(0)
	errCh := make(chan error, totalChunks)
	mu := &sync.Mutex{}
	var wg sync.WaitGroup

	// Process chunks in batches of parallelism
	for i := 0; i < totalChunks; i += parallelism {
		endChunk := i + parallelism
		if endChunk > totalChunks {
			endChunk = totalChunks
		}

		for chunkIndex := i; chunkIndex < endChunk; chunkIndex++ {
			start := int64(chunkIndex) * SingleMB
			end := start + SingleMB - 1
			if end >= objSize {
				end = objSize - 1
			}
			wg.Add(1)

			go func(start, end int64, partNum int) {
				defer wg.Done()
				resp, err := blobClient.DownloadStream(ctx, &blob.DownloadStreamOptions{
					Range: azblob.HTTPRange{Offset: start, Count: end - start + 1},
				})
				if err != nil {
					errCh <- fmt.Errorf("chunk %d failed: %v", partNum, err)
					return
				}
				defer resp.Body.Close()

				// get a sectionWriter and buffer
				w := newSectionWriter(f, start)
				bufptr := bufPool.Get().(*[]byte)
				buf := *bufptr
				if _, err := io.CopyBuffer(w, resp.Body, buf); err != nil {
					errCh <- fmt.Errorf("chunk %d copy error: %v", partNum, err)
					return
				}
				// recycle writer
				writerPool.Put(w)
				bufPool.Put(bufptr)

				mu.Lock()
				stats.DoneParts.Parts = append(stats.DoneParts.Parts, &types.PartDefinition{
					Ind:  int64(partNum),
					Size: end - start + 1,
				})
				progress += end - start + 1
				if prgNotify != nil {
					stats.Asize = progress
					select {
					case prgNotify <- *stats:
					default:
					}
				}
				mu.Unlock()
			}(start, end, chunkIndex)
		}

		wg.Wait() // Wait for this batch to finish before continuing
	}

	close(errCh)
	for err := range errCh {
		if err != nil {
			return stats.DoneParts, err
		}
	}

	return stats.DoneParts, nil
}

// DownloadAzureBlobByChunks will process the blob download by chunks, i.e., chunks will be
// responded back on as and when they receive
func DownloadAzureBlobByChunks(
	accountURL, accountName, accountKey, containerName, remoteFile, localFile string,
	httpClient *http.Client,
) (io.ReadCloser, int64, error) {
	// Get clients using helper
	_, blobClient, err := getContainerAndBlockBlobClients(
		accountURL, accountName, accountKey, containerName, remoteFile, httpClient)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get clients: %v", err)
	}

	ctx := context.Background()

	// Fetch blob properties to get the content length
	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("could not get blob properties: %v", err)
	}
	size := *props.ContentLength

	// Stream download (entire blob)
	resp, err := blobClient.DownloadStream(ctx, &blob.DownloadStreamOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("could not start download: %v", err)
	}

	return resp.Body, size, nil
}

// UploadAzureBlob uploads a local file to Azure Blob Storage using the new SDK and block blobs.
func UploadAzureBlob(
	accountURL, accountName, accountKey, containerName, remoteFile, localFile string,
	httpClient *http.Client,
) (string, error) {
	ctx := context.Background()

	// Get clients using helper
	containerClient, blobClient, err := getContainerAndBlockBlobClients(
		accountURL, accountName, accountKey, containerName, remoteFile, httpClient)
	if err != nil {
		return "", fmt.Errorf("failed to get clients: %v", err)
	}

	// Try to create the container (ignore if it already exists)
	_, err = containerClient.Create(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) {
			if respErr.ErrorCode != "ContainerAlreadyExists" {
				return "", fmt.Errorf("failed to create container: %v", err)
			}
		} else {
			return "", fmt.Errorf("failed to create container: %v", err)
		}
	}

	// Open the local file
	file, err := os.Open(localFile)
	if err != nil {
		return "", fmt.Errorf("unable to open local file %s: %v", localFile, err)
	}
	defer file.Close()

	// Upload the file stream to the blob
	_, err = blobClient.UploadStream(ctx, file, &blockblob.UploadStreamOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to upload file to blob: %v", err)
	}

	return blobClient.URL(), nil
}

// GetAzureBlobMetaData gets content length and content MD5 (as hex string).
// Useful for verifying file integrity.
func GetAzureBlobMetaData(
	accountURL, accountName, accountKey, containerName, remoteFile string,
	httpClient *http.Client,
) (int64, string, error) {
	ctx := context.Background()

	// Get the blob client using helper
	_, blobClient, err := getContainerAndBlockBlobClients(
		accountURL, accountName, accountKey, containerName, remoteFile, httpClient)
	if err != nil {
		return 0, "", fmt.Errorf("failed to get blob client: %v", err)
	}

	// Get blob properties
	resp, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return 0, "", fmt.Errorf("could not get blob properties: %v", err)
	}

	// Content length and ContentMD5 may be nil
	length := int64(0)
	if resp.ContentLength != nil {
		length = *resp.ContentLength
	}

	var md5Hex string
	if resp.ContentMD5 != nil {
		md5Hex = hex.EncodeToString(resp.ContentMD5)
	}

	return length, md5Hex, nil
}

// GenerateBlobSasURI is used to generate the URI which can be used to access the blob until the the URI expries
func GenerateBlobSasURI(
	accountURL, accountName, accountKey, containerName, remoteFile string,
	httpClient *http.Client,
	duration time.Duration,
) (string, error) {
	// Create credential
	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return "", fmt.Errorf("invalid credentials: %v", err)
	}

	// Check if the blob exists
	_, _, err = GetAzureBlobMetaData(
		accountURL, accountName, accountKey, containerName, remoteFile, httpClient)
	if err != nil {
		return "", fmt.Errorf("blob does not exist or error fetching metadata: %v", err)
	}

	// Build SAS query parameters
	sasValues := sas.BlobSignatureValues{
		Version:       sas.Version, // latest version constant
		Protocol:      sas.ProtocolHTTPS,
		StartTime:     time.Now().UTC(),
		ExpiryTime:    time.Now().UTC().Add(duration),
		ContainerName: containerName,
		BlobName:      remoteFile,
		Permissions:   (&sas.BlobPermissions{Read: true}).String(),
	}

	sasQueryParams, err := sasValues.SignWithSharedKey(cred)
	if err != nil {
		return "", fmt.Errorf("could not generate SAS token: %v", err)
	}

	// Construct final URL
	blobURL := fmt.Sprintf("%s/%s/%s?%s", strings.TrimSuffix(accountURL, "/"), containerName, remoteFile, sasQueryParams.Encode())
	return blobURL, nil
}

// UploadPartByChunk upload an individual chunk given an io.ReadSeeker and partID
func UploadPartByChunk(
	accountURL, accountName, accountKey, containerName, remoteFile, partID string,
	httpClient *http.Client,
	chunk io.ReadSeeker,
) error {
	ctx := context.Background()

	// Get container and blob clients
	containerClient, blobClient, err := getContainerAndBlockBlobClients(
		accountURL, accountName, accountKey, containerName, remoteFile, httpClient)
	if err != nil {
		return fmt.Errorf("failed to get blob client: %v", err)
	}

	// Attempt to create the container (ignore if already exists)
	_, err = containerClient.Create(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.ErrorCode != "ContainerAlreadyExists" {
			return fmt.Errorf("failed to create container %s: %v", containerName, err)
		} else if !errors.As(err, &respErr) {
			return fmt.Errorf("unexpected error creating container %s: %v", containerName, err)
		}
	}

	// Stage the block (upload the chunk)
	_, err = blobClient.StageBlock(ctx, partID, readSeekCloser{chunk}, nil)
	if err != nil {
		return fmt.Errorf("failed to upload chunk %s: %v", partID, err)
	}

	return nil
}

// UploadBlockListToBlob used to complete the list of parts which are already uploaded in block blob
func UploadBlockListToBlob(
	accountURL, accountName, accountKey, containerName, remoteFile string,
	httpClient *http.Client,
	blocks []string,
) error {
	ctx := context.Background()

	// Get container and blob clients
	containerClient, blobClient, err := getContainerAndBlockBlobClients(accountURL, accountName, accountKey, containerName, remoteFile, httpClient)
	if err != nil {
		return fmt.Errorf("failed to get blob client: %v", err)
	}

	// Try to create the container (ignore if already exists)
	_, err = containerClient.Create(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.ErrorCode != "ContainerAlreadyExists" {
			return fmt.Errorf("failed to create container %s: %v", containerName, err)
		} else if !errors.As(err, &respErr) {
			return fmt.Errorf("unexpected error creating container %s: %v", containerName, err)
		}
	}

	// Build list of block IDs (Base64 encoded strings)
	_, err = blobClient.CommitBlockList(ctx, blocks, nil)
	if err != nil {
		return fmt.Errorf("failed to commit block list: %v", err)
	}

	return nil
}
