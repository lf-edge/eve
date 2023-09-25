// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/lf-edge/eve-libs/zedUpload/types"
)

var (
	SyncUnsupport = errors.New("Unsupported function")
	SyncerRetry   = errors.New("Retry - syncer full")
)

type DronaRequest struct {
	sync.RWMutex

	// Optional, you can direct request for perticular server
	syncEp    DronaEndPoint
	operation SyncOpType

	// If cancelContext is set it can be used to cancel some operations
	cancelContext context.Context
	cancelFunc    context.CancelFunc

	// Object that needs to be downloaded
	name      string
	localName string

	// Location to where to download
	objloc string

	// need size acknowledgement
	ackback bool

	// request is processed, this is just update
	processed bool

	// if size exceed this don't download
	sizelimit int64

	// Filled by Drona, actual size
	asize      int64
	objectSize int64

	// Filled by Drona, images list
	imgList []string

	// Filled by Drona, download metadata
	contentType string

	// Filled by Drona, uploaded blob content length
	contentLength int64

	// Filled by Drona, uploaded blob MD5sum
	remoteFileMD5 string

	// Status of Download, we convert here to string because this
	// field is going to be json marshalled
	status string

	// result to be sent out
	result chan *DronaRequest

	startTime, endTime time.Time

	// Image Sha256
	ImageSha256 string

	// used by Multipart upload
	Adata  []byte
	PartID int64
	SasURI string

	// used by azure and s3 while Multipart Upload
	Blocks []string
	// generated SasURI TTL
	Duration time.Duration
	// generated while creating multipart file
	UploadID string
	// generated after uploading the part to the multipart file
	EtagID string
	// chunkInfoChan used for communication of chunk details
	chunkInfoChan chan ChunkData

	//downloaded parts indexes
	doneParts types.DownloadedParts

	logger types.Logger
}

// Return object local name
func (req *DronaRequest) GetLocalName() string {
	req.Lock()
	defer req.Unlock()
	if req.localName != "" {
		return req.localName
	}
	return req.name
}

// Return object error status string
func (req *DronaRequest) GetDnStatus() error {
	req.Lock()
	defer req.Unlock()
	return fmt.Errorf("Syncer Download Status of image name: %s, location: %s - error %s",
		req.name, req.objloc, req.status)
}

func (req *DronaRequest) GetUpStatus() (string, error) {
	req.Lock()
	defer req.Unlock()
	return req.objloc, fmt.Errorf("Syncer Upload Status of image name: %s, location: %s "+
		" - error %s", req.name, req.objloc, req.status)
}

// Return is it update
func (req *DronaRequest) IsDnUpdate() bool {
	req.Lock()
	defer req.Unlock()
	return !req.processed
}

func (req *DronaRequest) setProcessed() {
	req.Lock()
	defer req.Unlock()
	req.processed = true
}

// Return object actual synced down size
func (req *DronaRequest) GetAsize() int64 {
	req.Lock()
	defer req.Unlock()
	return req.asize
}

// Return object actual synced down size
func (req *DronaRequest) GetOsize() int64 {
	req.Lock()
	defer req.Unlock()
	return req.objectSize
}

// Progress return download progress
// returns asize (bytes), osize (bytes), progress (percent out of 100)
func (req *DronaRequest) Progress() (int64, int64, uint) {
	req.Lock()
	defer req.Unlock()
	asize := req.asize
	osize := req.objectSize
	progress := uint(0)
	if osize != 0 {
		percent := 100 * asize / osize
		progress = uint(percent)
	}
	return asize, osize, progress
}

func (req *DronaRequest) GetImageList() []string {
	req.Lock()
	defer req.Unlock()
	return req.imgList
}

func (req *DronaRequest) GetContentLength() int64 {
	req.Lock()
	defer req.Unlock()
	return req.contentLength
}

func (req *DronaRequest) GetRemoteFileMD5() string {
	req.Lock()
	defer req.Unlock()
	return req.remoteFileMD5
}

// GetContentType return the content type if available. If not, return
// an empty string.
func (req *DronaRequest) GetContentType() string {
	req.Lock()
	defer req.Unlock()
	return req.contentType
}

// Update the actual size
func (req *DronaRequest) updateAsize(size int64) {
	req.Lock()
	defer req.Unlock()
	req.asize = size
}

// Update the object size
func (req *DronaRequest) updateOsize(size int64) {
	req.Lock()
	defer req.Unlock()
	req.objectSize = size
}

// GetChunkDetails Return the chunk details
func (req *DronaRequest) GetChunkDetails() (int64, []byte, bool) {
	req.Lock()
	defer req.Unlock()
	chunkDetails := <-req.chunkInfoChan
	return chunkDetails.Size, chunkDetails.Chunk, chunkDetails.EOF
}

// Return the if the object was downloaded with error
func (req *DronaRequest) IsError() bool {
	req.Lock()
	defer req.Unlock()
	return req.status != ""
}

// Return the status
func (req *DronaRequest) GetStatus() string {
	req.Lock()
	defer req.Unlock()
	return req.status
}

// GetSha256 returns an image sha256
func (req *DronaRequest) GetSha256() string {
	req.Lock()
	defer req.Unlock()
	return req.ImageSha256
}

type SyncMetaFile struct {
	Operation SyncOpType

	// Object that needs to be downloaded
	Name string

	// Filled by Syncer, actual size
	Asize int64

	// Status of Download, we convert here to string because this
	// field is going to be json marshalled
	Status string

	EndTime   string
	StartTime string
}

// helper function to write the metafile for the transcation that is
// defined by this request
func (req *DronaRequest) WriteMetaFile(metaloc string) error {
	var internalerr error
	if metaloc != "" {
		f, err := os.OpenFile(metaloc, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Printf("file create failed %s - %v", metaloc, err)
			internalerr = err
		} else {
			defer f.Close()

			wreq := &SyncMetaFile{
				Operation: req.operation,
				Name:      req.name,
				Asize:     req.asize,
				Status:    req.status,
				EndTime:   req.endTime.Format(time.RFC3339),
				StartTime: req.startTime.Format(time.RFC3339)}

			b, err := json.MarshalIndent(wreq, "", "    ")
			if err != nil {
				internalerr = err
				log.Printf("metadata %s write failed %v", req.name, err)
				b = []byte(fmt.Sprintf("Error on marshaling data into bytes %v - %v\n", req, err))
			}
			if _, err := f.Write(b); err != nil {
				internalerr = err
				log.Printf("error writing file %s, %v", metaloc, err)
			}
		}
	} else {
		internalerr = fmt.Errorf("No metafile for req %s", req.name)
	}

	return internalerr
}

func ReadMetaFile(metaloc string) (error, *DronaRequest) {
	if metaloc == "" {
		return fmt.Errorf("file path empty"), nil
	}
	sbody, serr := os.ReadFile(metaloc)
	if serr != nil {
		return serr, nil
	}

	rreq := &SyncMetaFile{}
	if err := json.Unmarshal(sbody, rreq); err != nil {
		return err, nil
	}

	dnResp := DronaRequest{operation: rreq.Operation,
		name:   rreq.Name,
		asize:  rreq.Asize,
		status: rreq.Status}

	return nil, &dnResp
}

func (req *DronaRequest) Post() error {
	return req.postOnChannel()
}

func (req *DronaRequest) postOnChannel() error {
	ctx := req.syncEp.getContext()

	select {
	case ctx.reqChan <- req:
		req.startTime = time.Now()
		return nil
	default:
		return SyncerRetry
	}
}

// Cancel checks if WithCancel was used.
func (req *DronaRequest) Cancel() error {
	if req.cancelFunc != nil {
		req.cancelFunc()
	}
	return nil
}

// WithCancel can be used to setup cancellation
// Caller should call req.Cancel when done even on success
func (req *DronaRequest) WithCancel(ctx context.Context) *DronaRequest {

	cancelContext, cancel := context.WithCancel(ctx)
	req.cancelContext = cancelContext
	req.cancelFunc = cancel
	return req
}

// WithDoneParts can be used to set already downloaded parts indexes
func (req *DronaRequest) WithDoneParts(doneParts types.DownloadedParts) *DronaRequest {

	req.doneParts = doneParts
	return req
}

// GetDoneParts returns already downloaded parts indexes
func (req *DronaRequest) GetDoneParts() types.DownloadedParts {
	return req.doneParts
}

// WithLogger sets logger
func (req *DronaRequest) WithLogger(logger types.Logger) *DronaRequest {
	req.logger = logger
	return req
}
