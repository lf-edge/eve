// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"bytes"
	"fmt"
	"net"
	"net/url"

	"time"

	"github.com/lf-edge/eve/libs/nettrace"
	azure "github.com/lf-edge/eve/libs/zedUpload/azureutil"
	"github.com/lf-edge/eve/libs/zedUpload/types"
)

// Action : execute selected action targeting Azure datastore.
func (ep *AzureTransportMethod) Action(req *DronaRequest) error {
	var err error
	var size int
	var loc string
	var list []string
	var contentLength int64
	var remoteFileMD5 string

	switch req.operation {
	case SyncOpDownload:
		err = ep.processAzureDownload(req)
	case SyncOpUpload:
		loc, err = ep.processAzureUpload(req)
		req.objloc = loc
	case SyncOpDelete:
		err = ep.processAzureBlobDelete(req)
	case SyncOpList:
		list, err, size = ep.processAzureBlobList(req)
		req.imgList = list
	case SyncOpGetObjectMetaData:
		contentLength, remoteFileMD5, err = ep.processAzureBlobMetaData(req)
		req.contentLength = contentLength
		req.remoteFileMD5 = remoteFileMD5
	case SysOpPutPart:
		err = ep.processAzureUploadByChunks(req)
	case SysOpCompleteParts:
		err = ep.processPutBlockListIntoBlob(req)
	case SyncOpGetURI:
		sasURI, err := ep.processGenerateBlobSasURI(req)
		if err == nil {
			req.SasURI = sasURI
		}
	case SysOpDownloadByChunks:
		err = ep.processAzureDownloadByChunks(req)
	default:
		err = fmt.Errorf("Unknown Azure Blob datastore operation")
	}

	req.asize = int64(size)
	if err != nil {
		req.status = fmt.Sprintf("%v", err)
	}
	return err
}

func (ep *AzureTransportMethod) Open() error {
	return nil
}

func (ep *AzureTransportMethod) Close() error {
	return ep.hClientWrap.close()
}

// WithSrcIP : use the specific IP as source address for this connection.
func (ep *AzureTransportMethod) WithSrcIP(localAddr net.IP) error {
	return ep.hClientWrap.withSrcIP(localAddr)
}

// WithProxy : connect via the provided proxy URL.
func (ep *AzureTransportMethod) WithProxy(proxy *url.URL) error {
	return ep.hClientWrap.withProxy(proxy)
}

// WithTrustedCerts : run requests with these certificates added as trusted.
func (ep *AzureTransportMethod) WithTrustedCerts(certs [][]byte) error {
	return ep.hClientWrap.withTrustedCerts(certs)
}

// WithBindIntf : bind to specific interface for this connection
func (ep *AzureTransportMethod) WithBindIntf(intf string) error {
	return ep.hClientWrap.withBindIntf(intf)
}

// WithLogging enables or disables logging.
func (ep *AzureTransportMethod) WithLogging(onoff bool) error {
	return nil
}

// WithNetTracing enables network tracing.
func (ep *AzureTransportMethod) WithNetTracing(opts ...nettrace.TraceOpt) error {
	return ep.hClientWrap.withNetTracing(opts...)
}

// GetNetTrace returns collected network trace and packet captures.
func (ep *AzureTransportMethod) GetNetTrace(description string) (
	nettrace.AnyNetTrace, []nettrace.PacketCapture, error) {
	return ep.hClientWrap.getNetTrace(description)
}

// File upload to Azure Blob Datastore
func (ep *AzureTransportMethod) processAzureUpload(req *DronaRequest) (string, error) {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return "", err
	}
	file := req.name
	loc, err := azure.UploadAzureBlob(ep.aurl, ep.acName, ep.acKey, ep.container, file, req.objloc, hClient)
	if err != nil {
		return loc, err
	}
	return loc, nil
}

// File download from Azure Blob Datastore
func (ep *AzureTransportMethod) processAzureDownload(req *DronaRequest) error {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err
	}
	file := req.name
	prgChan := make(types.StatsNotifChan)
	defer close(prgChan)
	if req.ackback {
		go statsUpdater(req, ep.ctx, prgChan)
	}
	doneParts, err := azure.DownloadAzureBlob(ep.aurl, ep.acName, ep.acKey, ep.container,
		file, req.objloc, req.sizelimit, hClient, req.doneParts, prgChan)
	req.doneParts = doneParts
	if err != nil {
		return err
	}
	return nil
}

// File delete from Azure Blob Datastore
func (ep *AzureTransportMethod) processAzureBlobDelete(req *DronaRequest) error {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err
	}
	err = azure.DeleteAzureBlob(ep.aurl, ep.acName, ep.acKey, ep.container, req.name, hClient)
	//log.Printf("Azure Blob delete status: %v", status)
	return err
}

// File list from Azure Blob Datastore
func (ep *AzureTransportMethod) processAzureBlobList(req *DronaRequest) ([]string, error, int) {
	var csize int
	var img []string
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return img, err, csize
	}
	img, err = azure.ListAzureBlob(ep.aurl, ep.acName, ep.acKey, ep.container, hClient)
	if err != nil {
		return img, err, csize
	}
	return img, nil, csize
}

func (ep *AzureTransportMethod) processAzureBlobMetaData(req *DronaRequest) (int64, string, error) {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return 0, "", err
	}
	size, md5, err := azure.GetAzureBlobMetaData(ep.aurl, ep.acName, ep.acKey, ep.container, req.name, hClient)
	if err != nil {
		return 0, "", err
	}
	return size, md5, nil
}

func (ep *AzureTransportMethod) getContext() *DronaCtx {
	return ep.ctx
}

func (ep *AzureTransportMethod) processAzureUploadByChunks(req *DronaRequest) error {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err
	}
	return azure.UploadPartByChunk(ep.aurl, ep.acName, ep.acKey, ep.container,
		req.localName, req.UploadID, hClient, bytes.NewReader(req.Adata))
}

func (ep *AzureTransportMethod) processAzureDownloadByChunks(req *DronaRequest) error {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err
	}
	readCloser, size, err := azure.DownloadAzureBlobByChunks(ep.aurl, ep.acName, ep.acKey,
		ep.container, req.name, req.objloc, hClient)
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

func (ep *AzureTransportMethod) processGenerateBlobSasURI(req *DronaRequest) (string, error) {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return "", err
	}
	return azure.GenerateBlobSasURI(ep.aurl, ep.acName, ep.acKey, ep.container,
		req.localName, hClient, req.Duration)
}

func (ep *AzureTransportMethod) processPutBlockListIntoBlob(req *DronaRequest) error {
	hClient, err := ep.hClientWrap.unwrap()
	if err != nil {
		return err
	}
	return azure.UploadBlockListToBlob(ep.aurl, ep.acName, ep.acKey, ep.container,
		req.localName, hClient, req.Blocks)
}

func (ep *AzureTransportMethod) NewRequest(opType SyncOpType, objname, objloc string, sizelimit int64, ackback bool, reply chan *DronaRequest) *DronaRequest {
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

type AzureTransportMethod struct {
	transport SyncTransportType
	aurl      string
	container string

	//Auth
	authType string
	acName   string
	acKey    string

	failPostTime time.Time
	ctx          *DronaCtx
	hClientWrap  *httpClientWrapper
}
