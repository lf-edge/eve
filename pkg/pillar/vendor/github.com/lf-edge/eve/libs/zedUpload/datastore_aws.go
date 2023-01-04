// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/libs/nettrace"
	zedAWS "github.com/lf-edge/eve/libs/zedUpload/awsutil"
	"github.com/lf-edge/eve/libs/zedUpload/types"
)

// Action : execute selected action targeting AWS datastore.
func (ep *AwsTransportMethod) Action(req *DronaRequest) error {
	var err error
	var size int
	var list []string
	var contentLength int64
	var remoteFileMD5 string

	switch req.operation {
	case SyncOpUpload:
		err, size = ep.processS3Upload(req)
	case SyncOpDownload:
		err, size = ep.processS3Download(req)
	case SyncOpDelete:
		err = ep.processS3Delete(req)
	case SyncOpList:
		list, err, size = ep.processS3List(req)
		req.imgList = list
	case SyncOpGetObjectMetaData:
		contentLength, remoteFileMD5, err = ep.processS3ObjectMetaData(req)
		req.contentLength = contentLength
		req.remoteFileMD5 = remoteFileMD5
	case SysOpPutPart:
		etagID, uploadID, err := ep.processMultipartUpload(req)
		if err == nil {
			req.UploadID = uploadID
			req.EtagID = etagID
		}
	case SysOpCompleteParts:
		err = ep.completeMultipartUpload(req)
	case SyncOpGetURI:
		sasURL, err := ep.generateSignedURL(req)
		if err == nil {
			req.SasURI = sasURL
		}
	case SysOpDownloadByChunks:
		err = ep.processS3DownloadByChunks(req)
	default:
		err = fmt.Errorf("Unknown AWS S3 datastore operation")
	}

	req.asize = int64(size)
	if err != nil {
		req.status = fmt.Sprintf("%v", err)
	}

	return err
}

func (ep *AwsTransportMethod) Open() error {
	return nil
}

func (ep *AwsTransportMethod) Close() error {
	return ep.hClientWrap.close()
}

// WithSrcIP : use the specific IP as source address for this connection.
func (ep *AwsTransportMethod) WithSrcIP(localAddr net.IP) error {
	return ep.hClientWrap.withSrcIP(localAddr)
}

// WithProxy : connect via the provided proxy URL.
func (ep *AwsTransportMethod) WithProxy(proxy *url.URL) error {
	return ep.hClientWrap.withProxy(proxy)
}

// WithTrustedCerts : run requests with these certificates added as trusted.
func (ep *AwsTransportMethod) WithTrustedCerts(certs [][]byte) error {
	return ep.hClientWrap.withTrustedCerts(certs)
}

// WithBindIntf : bind to specific interface for this connection
func (ep *AwsTransportMethod) WithBindIntf(intf string) error {
	return ep.hClientWrap.withBindIntf(intf)
}

// WithLogging enables or disables logging.
func (ep *AwsTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// WithNetTracing enables network tracing.
func (ep *AwsTransportMethod) WithNetTracing(opts ...nettrace.TraceOpt) error {
	return ep.hClientWrap.withNetTracing(opts...)
}

// GetNetTrace returns collected network trace and packet captures.
func (ep *AwsTransportMethod) GetNetTrace(description string) (
	nettrace.AnyNetTrace, []nettrace.PacketCapture, error) {
	return ep.hClientWrap.getNetTrace(description)
}

// File upload to AWS S3 Datastore
func (ep *AwsTransportMethod) processS3Upload(req *DronaRequest) (error, int) {
	fInfo, err := os.Stat(req.objloc)
	if err != nil {
		return err, 0
	}
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err, 0
	}

	// FiXME: strings.TrimSuffix needs to go away once final soultion is done.
	// upload, always the compression file.
	sc := zedAWS.NewAwsCtx(ep.token, ep.apiKey, ep.region, hClient)
	if sc == nil {
		return fmt.Errorf("unable to create S3 context"), 0
	}
	if req.cancelContext != nil {
		sc = sc.WithContext(req.cancelContext)
	}
	if req.logger != nil {
		sc = sc.WithLogger(req.logger)
	}

	location, err := sc.UploadFile(req.objloc, ep.bucket, req.name, false, prgChan)
	if len(location) > 0 {
		req.objloc = location
	}

	return err, int(fInfo.Size())
}

// File download from AWS S3 Datastore
func (ep *AwsTransportMethod) processS3Download(req *DronaRequest) (error, int) {
	var csize int
	pwd := strings.TrimSuffix(ep.apiKey, "\n")
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err, 0
	}

	if req.ackback {
		s := zedAWS.NewAwsCtx(ep.token, pwd, ep.region, hClient)
		if req.cancelContext != nil {
			s = s.WithContext(req.cancelContext)
		}
		if req.logger != nil {
			s = s.WithLogger(req.logger)
		}
		if s != nil {
			err, length := s.GetObjectSize(ep.bucket, req.name)
			if err == nil {
				ep.ctx.postSize(req, length, 0)
			}
		}
		go statsUpdater(req, ep.ctx, prgChan)
	}

	sc := zedAWS.NewAwsCtx(ep.token, pwd, ep.region, hClient)
	if sc == nil {
		return fmt.Errorf("unable to create S3 context"), 0
	}
	if req.cancelContext != nil {
		sc = sc.WithContext(req.cancelContext)
	}
	if req.logger != nil {
		sc = sc.WithLogger(req.logger)
	}
	doneParts, err := sc.DownloadFile(req.objloc, ep.bucket, req.name, req.sizelimit, req.doneParts, prgChan)
	req.doneParts = doneParts
	if err != nil {
		return err, 0
	}
	// check for download complete
	st, err := os.Stat(req.objloc)
	if err != nil {
		return err, 0
	}
	csize = int(st.Size())

	return err, csize
}

func (ep *AwsTransportMethod) processS3DownloadByChunks(req *DronaRequest) error {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err
	}
	pwd := strings.TrimSuffix(ep.apiKey, "\n")
	sc := zedAWS.NewAwsCtx(ep.token, pwd, ep.region, hClient)
	if sc == nil {
		return fmt.Errorf("unable to create S3 context")
	}
	if req.cancelContext != nil {
		sc = sc.WithContext(req.cancelContext)
	}
	if req.logger != nil {
		sc = sc.WithLogger(req.logger)
	}
	readCloser, size, err := sc.DownloadFileByChunks(req.objloc, ep.bucket, req.name)
	if err != nil {
		return err
	}
	req.chunkInfoChan = make(chan ChunkData, 1)
	chunkChan := make(chan ChunkData)
	go func(chunkChan chan ChunkData) {
		for chunkData := range chunkChan {
			ep.ctx.postChunk(req, chunkData)
		}
	}(chunkChan)
	return processChunkByChunk(readCloser, size, chunkChan)
}

// File delete from AWS S3 Datastore
func (ep *AwsTransportMethod) processS3Delete(req *DronaRequest) error {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err
	}
	s3ctx := zedAWS.NewAwsCtx(ep.token, ep.apiKey, ep.region, hClient)
	if s3ctx != nil {
		if req.cancelContext != nil {
			s3ctx = s3ctx.WithContext(req.cancelContext)
		}
		if req.logger != nil {
			s3ctx = s3ctx.WithLogger(req.logger)
		}
		err = s3ctx.DeleteObject(ep.bucket, req.name)
	} else {
		return fmt.Errorf("no s3 context")
	}
	if err != nil {
		return err
	}
	//log.Printf("Successfully deleted file from %s, bucket:%s, %s", ep.token, ep.bucket, req.name)

	return err
}

// File list from AWS S3 Datastore
func (ep *AwsTransportMethod) processS3List(req *DronaRequest) ([]string, error, int) {
	var csize int
	var s []string
	pwd := strings.TrimSuffix(ep.apiKey, "\n")

	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}

	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return s, err, 0
	}
	sc := zedAWS.NewAwsCtx(ep.token, pwd, ep.region, hClient)
	if sc == nil {
		return s, fmt.Errorf("unable to create S3 context"), 0
	}
	if req.cancelContext != nil {
		sc = sc.WithContext(req.cancelContext)
	}
	if req.logger != nil {
		sc = sc.WithLogger(req.logger)
	}

	list, err := sc.ListImages(ep.bucket, prgChan)
	if err != nil {
		return s, err, 0
	}

	//log.Printf("S3 Image List: %v", list)
	//log.Printf("Successfully listed s3 images at %v", ep.bucket)
	return list, err, csize
}

// Verify Uploaded Object Size and MD5 sum
func (ep *AwsTransportMethod) processS3ObjectMetaData(req *DronaRequest) (int64, string, error) {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return 0, "", err
	}
	pwd := strings.TrimSuffix(ep.apiKey, "\n")
	sc := zedAWS.NewAwsCtx(ep.token, pwd, ep.region, hClient)
	if sc == nil {
		return 0, "", fmt.Errorf("unable to create S3 context")
	}
	if req.cancelContext != nil {
		sc = sc.WithContext(req.cancelContext)
	}
	if req.logger != nil {
		sc = sc.WithLogger(req.logger)
	}

	size, remoteFileMD5, err := sc.GetObjectMetaData(ep.bucket, req.name)
	if len(remoteFileMD5) > 0 && remoteFileMD5[0] == '"' {
		remoteFileMD5 = remoteFileMD5[1:]
	}
	if len(remoteFileMD5) > 0 && remoteFileMD5[len(remoteFileMD5)-1] == '"' {
		remoteFileMD5 = remoteFileMD5[:len(remoteFileMD5)-1]
	}
	return size, remoteFileMD5, err
}

func (ep *AwsTransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
	dR := &DronaRequest{}
	dR.syncEp = ep
	dR.operation = opType
	dR.name = objname
	dR.ackback = ackback

	// FIXME:...we need this later
	dR.localName = objname
	dR.objloc = objloc

	// limit for this download
	dR.sizelimit = sizelimit
	dR.result = reply

	return dR
}

func (ep *AwsTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

func (ep *AwsTransportMethod) processMultipartUpload(req *DronaRequest) (string, string, error) {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return "", "", err
	}
	s3ctx := zedAWS.NewAwsCtx(ep.token, ep.apiKey, ep.region, hClient)
	if req.cancelContext != nil {
		s3ctx = s3ctx.WithContext(req.cancelContext)
	}
	if req.logger != nil {
		s3ctx = s3ctx.WithLogger(req.logger)
	}
	return s3ctx.UploadPart(ep.bucket, req.localName, req.Adata, req.PartID, req.UploadID)

}

func (ep *AwsTransportMethod) completeMultipartUpload(req *DronaRequest) error {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err
	}
	s3ctx := zedAWS.NewAwsCtx(ep.token, ep.apiKey, ep.region, hClient)
	if req.cancelContext != nil {
		s3ctx = s3ctx.WithContext(req.cancelContext)
	}
	if req.logger != nil {
		s3ctx = s3ctx.WithLogger(req.logger)
	}
	return s3ctx.CompleteUploadedParts(ep.bucket, req.localName, req.UploadID, req.Blocks)
}

func (ep *AwsTransportMethod) generateSignedURL(req *DronaRequest) (string, error) {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return "", err
	}
	s3ctx := zedAWS.NewAwsCtx(ep.token, ep.apiKey, ep.region, hClient)
	if req.cancelContext != nil {
		s3ctx = s3ctx.WithContext(req.cancelContext)
	}
	if req.logger != nil {
		s3ctx = s3ctx.WithLogger(req.logger)
	}
	return s3ctx.GetSignedURL(ep.bucket, req.localName, req.Duration)
}

type AwsTransportMethod struct {
	transport SyncTransportType
	region    string
	bucket    string

	//Auth
	token  string
	apiKey string

	failPostTime time.Time
	ctx          *DronaCtx
	hClientWrap  *httpClientWrapper
}
