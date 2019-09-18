// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package azure

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/storage"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	// SingleMB contains chunk size
	SingleMB int64 = 1024 * 1024
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

func NewClient(accountName, accountKey string, httpClient *http.Client) (storage.Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	client, err := storage.NewBasicClient(accountName, accountKey)
	if err != nil {
		return client, err
	}
	client.HTTPClient = httpClient
	return client, nil
}

func ListAzureBlob(accountName, accountKey, containerName string, httpClient *http.Client) ([]string, error) {
	var imgList []string
	c, err := NewClient(accountName, accountKey, httpClient)
	if err != nil {
		return imgList, err
	}
	blobClient := c.GetBlobService()
	container := blobClient.GetContainerReference(containerName)
	containerExists, _ := container.Exists()
	if !containerExists {
		return imgList, fmt.Errorf("Container doesn't exist")
	}
	blobList, err := container.ListBlobs(storage.ListBlobsParameters{})
	if err != nil {
		return imgList, err
	}
	for _, images := range blobList.Blobs {
		imgList = append(imgList, images.Name)
	}
	return imgList, nil
}

func DeleteAzureBlob(accountName, accountKey, containerName, remoteFile string, httpClient *http.Client) error {
	c, err := NewClient(accountName, accountKey, httpClient)
	if err != nil {
		return err
	}
	blobClient := c.GetBlobService()
	container := blobClient.GetContainerReference(containerName)
	containerExists, _ := container.Exists()
	if !containerExists {
		return fmt.Errorf("Container doesn't exist")
	}
	blob := container.GetBlobReference(remoteFile)
	er := blob.Delete(nil)
	if er != nil {
		return er
	}
	return nil
}

func DownloadAzureBlob(accountName, accountKey, containerName, remoteFile, localFile string, httpClient *http.Client, prgNotify NotifChan) error {
	stats := UpdateStats{}
	c, err := NewClient(accountName, accountKey, httpClient)
	if err != nil {
		return err
	}
	blobClient := c.GetBlobService()
	container := blobClient.GetContainerReference(containerName)
	containerExists, _ := container.Exists()
	if !containerExists {
		return fmt.Errorf("Container doesn't exist")
	}
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
	blob := container.GetBlobReference(remoteFile)
	getErr := blob.GetProperties(nil)
	if getErr != nil {
		return getErr
	}
	readCloser, err := blob.Get(nil)
	if err != nil {
		return err
	}
	defer readCloser.Close()
	chunkSize := SingleMB
	var written, copiedSize int64
	var copyErr error
	stats.Size = int64(blob.Properties.ContentLength)
	for {
		if written, copyErr = io.CopyN(file, readCloser, chunkSize); copyErr != nil && copyErr != io.EOF {
			return copyErr
		}
		copiedSize += written
		if written != chunkSize {
			break
		}
		stats.Asize = copiedSize
		if prgNotify != nil {
			select {
			case prgNotify <- stats:
			default: //ignore we cannot write
			}
		}
	}
	return nil
}

// PutBlockBlob uploads given stream into a block blob by splitting
// data stream into chunks and uploading as blocks. Commits the block
// list at the end. This is a helper method built on top of PutBlock
// and PutBlockList methods with sequential block ID counting logic.
func putBlockBlob(b *storage.Blob, blob io.Reader) error {
        chunkSize := storage.MaxBlobBlockSize

        chunk := make([]byte, chunkSize)
        n, err := blob.Read(chunk)
        if err != nil && err != io.EOF {
                return err
        }

        blockList := []storage.Block{}

        for blockNum := 0; ; blockNum++ {
                id := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("1d", blockNum)))
                data := chunk[:n]
                err = b.PutBlock(id, data, nil)
                if err != nil {
                        return err
                }

                blockList = append(blockList, storage.Block{id, storage.BlockStatusLatest})

                // Read next block
                n, err = blob.Read(chunk)
                if err != nil && err != io.EOF {
                        return err
                }
                if err == io.EOF {
                        break
                }
	}
	return b.PutBlockList(blockList, nil)
}

func UploadAzureBlob(accountName, accountKey, containerName, remoteFile, localFile string, httpClient *http.Client) error {
	c, err := NewClient(accountName, accountKey, httpClient)
	if err != nil {
		return err
	}
	blobClient := c.GetBlobService()
	container := blobClient.GetContainerReference(containerName)
	containerExists, _ := container.Exists()
	if !containerExists {
		fmt.Printf("Container is creating")
		err := container.Create(nil)
		if err != nil {
			fmt.Printf("Error %v", err)
			return err
		}
	}
	file, _ := os.Open(localFile)
	defer file.Close()
	blob := container.GetBlobReference(remoteFile)
	putBlockErr := putBlockBlob(blob, file)
	if putBlockErr != nil {
		return putBlockErr
	}
	return nil
}

func GetAzureBlobMetaData(accountName, accountKey, containerName, remoteFile string, httpClient *http.Client) (int64, string, error) {
	c, err := NewClient(accountName, accountKey, httpClient)
	if err != nil {
		return 0, "", err
	}
	blobClient := c.GetBlobService()
	container := blobClient.GetContainerReference(containerName)
	containerExists, _ := container.Exists()
	if !containerExists {
		return 0, "", fmt.Errorf("Container doesn't exist")
	}
	blob := container.GetBlobReference(remoteFile)
	er := blob.GetProperties(nil)
	if er != nil {
		return 0, "", er
	}
	decodedString, err := base64.StdEncoding.DecodeString(blob.Properties.ContentMD5)
	if err != nil {
		return 0, "", err
	}
	stringHex := hex.EncodeToString(decodedString)
	return blob.Properties.ContentLength, stringHex, nil
}
